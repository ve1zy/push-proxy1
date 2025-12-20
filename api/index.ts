// api/fcm-handler.ts
import { SignJWT, importPKCS8 } from "jose";
import { buffer } from "micro";

// ---------- Logging ----------
const log = (msg: string, data?: unknown) => {
  const t = new Date().toISOString();
  console.log(`[${t}] ${msg}`, data ? JSON.stringify(data, null, 2) : "");
};

const logErr = (msg: string, err: unknown) => {
  const t = new Date().toISOString();
  console.error(
    `[${t}] ERROR: ${msg}`,
    err instanceof Error ? err.stack || err.message : JSON.stringify(err)
  );
};

// ---------- Config ----------
const SA = JSON.parse(process.env.SERVICE_ACCOUNT_JSON || "{}");
const { project_id: PROJECT_ID, client_email: CLIENT_EMAIL, private_key: PRIVATE_KEY } = SA;

if (!PRIVATE_KEY?.trim()) {
  throw new Error("Missing private_key in SERVICE_ACCOUNT_JSON");
}

log("Using client_email", { email: CLIENT_EMAIL });
const FCM_URL = `https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`;

// ---------- Auth ----------
async function getAccessToken(): Promise<string> {
  const privateKey = await importPKCS8(PRIVATE_KEY, "RS256");
  const jwt = await new SignJWT({
    iss: CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .sign(privateKey);

  log("Generated JWT", { jwt: jwt.substring(0, 100) + "..." });

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "<no response>");
    logErr("Auth failed", { response: text });
    throw new Error(`Auth failed: ${text}`);
  }

  return (await res.json()).access_token;
}

// ---------- FCM send (token only) ----------
async function sendFCMMessage(rawMessage: any, id: string): Promise<boolean> {
  const hasToken = "token" in rawMessage;
  const hasTopic = "topic" in rawMessage;

  if (hasTopic) {
    logErr(`[${id}] Topic messages are disabled`, rawMessage);
    return false;
  }
  if (!hasToken) {
    logErr(`[${id}] No token provided`, rawMessage);
    return false;
  }

  try {
    const token = await getAccessToken();
    const res = await fetch(FCM_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: rawMessage }),
    });

    const text = await res.text().catch(() => "<no response>");

    if (!res.ok) {
      logErr(`[${id}] FCM send failed`, { status: res.status, body: text });

      try {
        const json = JSON.parse(text);
        const isUnregistered = json?.error?.details?.some(
          (d: any) =>
            d?.["@type"] === "type.googleapis.com/google.firebase.fcm.v1.FcmError" &&
            d?.errorCode === "UNREGISTERED"
        );

        if (isUnregistered) {
          log(`[${id}] Token is UNREGISTERED — remove from DB`, {
            token: rawMessage.token?.substring(0, 20) + "...",
          });
        }
      } catch (e) {
        // ignore JSON parse errors
      }

      return false;
    } else {
      log(`[${id}] FCM sent successfully`);
      return true;
    }
  } catch (e) {
    logErr(`[${id}] Exception in sendFCMMessage`, e);
    return false;
  }
}

// ---------- Mattermost payload ----------
interface MattermostPayload {
  type: string;
  platform: string;
  device_id?: string;
  message?: string;
  channel_name?: string;
  sender_name?: string;
  ack_id?: string;
  server_id?: string;
  channel_id?: string;
  sender_id?: string;
  category?: string;
  badge?: string;
  post_id?: string;
  version?: string;
  [key: string]: unknown;
}

// ---------- Handle Mattermost Push ----------
async function handleMattermost(payload: MattermostPayload, id: string): Promise<{ status: number; message: string }> {
  const { type, platform, device_id: token } = payload;

  if (type === "test") {
    return { status: 200, message: "OK" };
  }

  if (type !== "message" && type !== "clear") {
    return { status: 400, message: "Bad type" };
  }

  if (type === "clear") {
    return { status: 200, message: "OK" };
  }

  let p = platform;
  if (p === "android_rn" || p === "android_rn-v2") p = "android";
  if (p !== "android") {
    return { status: 400, message: "Only Android supported" };
  }

  if (!token) {
    return { status: 400, message: "No device_id" };
  }

  const title = payload.channel_name || payload.sender_name || "Mattermost";
  const body = typeof payload.message === "string" ? payload.message : "";

  const data: Record<string, string> = {};
  for (const key of [
    "ack_id",
    "server_id",
    "channel_id",
    "channel_name",
    "sender_id",
    "sender_name",
    "category",
    "type",
    "badge",
    "post_id",
    "version",
  ]) {
    data[key] = String(payload[key as keyof typeof payload] ?? "");
  }

  log(`[${id}] Sending to token`, { token: token.substring(0, 10) + "..." });

  const success = await sendFCMMessage(
    {
      token,
      notification: { title, body },
      android: {
        notification: {
          channelId: "mattermost",
          sound: "default",
        },
      },
      data,
    },
    id
  );

  return { status: success ? 200 : 500, message: success ? "OK" : "Failed to send" };
}

// ---------- Next.js API Handler ----------
export default async function handler(req: any, res: any): Promise<void> {
  const id = crypto.randomUUID();

  if (req.method !== "POST") {
    res.status(405).send("Method Not Allowed");
    return;
  }

  let payload: any;
  try {
    const buf = await buffer(req);
    const body = buf.toString("utf8");
    payload = JSON.parse(body);
  } catch (e) {
    logErr(`[${id}] Invalid JSON`, e);
    res.status(400).send("Invalid JSON");
    return;
  }

  if (typeof payload !== "object" || payload === null) {
    res.status(400).send("Payload must be an object");
    return;
  }

  log(`[${id}] Mattermost request`, payload);

  const result = await handleMattermost(payload, id);
  res.status(result.status).send(result.message);
}

// ---------- Vercel Config ----------
export const config = {
  api: {
    bodyParser: false, // required for buffer()
  },
  runtime: "nodejs",
};

import { SignJWT, importPKCS8 } from "jose";

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
const SA = JSON.parse("{"type": "service_account","project_id": "devfest-d7fc2","private_key_id": "4e5ef5d908c6be621293f6faaf79230a219d0ab4","private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMb5gi2FvBJrmK\nBjcwRTHSUOkjnuK8OwajGqnl7nEskhePYixC6EJXaXXcw7Vc+CFEAtDafQbP2GTn\nfMse3C919djJfRAeLziXg/1EL3mXLeJmtyVsPThCqNrjfQrDzQzho2XmVEwjww/0\no6nG1vzaRYNIgMNVfnrTuovpEgk8hu/cRZXp/u8VagU7JaupffMhxGRsG3GdqD/N\neMl3KqnjwP/XDU7ajjEpBEqqIo2E+D3YcuSr2cGbbQfKO0B9TFnldq4VixsdGqPn\nTsV1MbuuuGkeNdEwpo7qQgGi8SkrPdjCtA9H2G43IgEVwTGnZnKFdFNoq3PEZXqW\nQYm5ZZgFAgMBAAECggEAEZCF9vp1WbFI0CvMCpTrXKlQepvAWdFNdu6HyeZUaXKs\n3QgfiukXKBj6xCq5dqEoBIakaJ1E3E84ji4J6p8a4czrYRZib+F5QIVZ2YWlsgBC\nezZBnBzfbFTDJ7f62ItRz8Ig82rrNshf4tI7+EZI570AtFZB0iLhjTbyJeaDjiRX\naxnjqRhUqu48N9DViSKcwqNbcCDoIRigLOv7EBdB9O3gCfX7ymVJBq88Eab9EEcZ\nTfTQ81FML6ful8vqyJsv1m/YuZRyM+kGs7VitlrZXY/Wc+R4GetT4ue42dkh84y9\ntdryAQsL9lR5309CE1o2tJMcVBpL9wMSZFE+v4S60QKBgQD0GgsNMCvym337pNf5\n98Jwx+T5gFmEzYPlWWHh6edZTXjmSiokc40GckC+G9F0tX5cvGVcx+GnAAnSnoju\n2lVwyadYQB/cpCsDsg8ZdYV0RuwW7VLIXzPIz/jiDKMB2ruISkrVP169F6gJWpMX\nlPfakRw50dTzTBBFVnjXKKBSsQKBgQDWZpeQyQJ/BwajjQDsJt2IaMHOK76jzt5n\nrnhnc7J/E9cCCoz0CDrmLWdBdBeqTtOWtEY6vgds44MFiT1VsXgUAqAf0EvfOBq7\niG8D+SVgFd971mSezLkmi5nvvmflSqKmjaLNfJ+zOE2NCRECe3ExnKDkq4esqLSe\nsrNzgWSnlQKBgCx/juIxlOFeHSJBk6ma09RRbFlbX3ZJLLEjkSdox2bNK6v3eyU3\n905kh47gbVd0OnvXUDcQrP8Pj7rYcafxH0A3Uo1Q6z4Co2DCFeSTOufOgf1P+BZU\n3JDP8NPsb87HvAYFXQzwx2l7JYPHAid7XY93goi7yrErfY/WSqMWYduRAoGBAMtX\nCbCbs+5d74H2HUXbpofVMtoiyu/5Jx4WbsNPC59SZbzd3MkldRcRQLjnLfqsQCjS\nWTklOU2giYcanj1Dz6rKwqrplsviHhh2UTPne/chR4/fyhaB+6f/BsRGRatFmfV0\np09UPvJvF74HN0avZK+06TN3K3oplwRcX63QrnHxAoGAS16JamO3eLpHWkwIzjsY\nmfMI67Mfdu84qb9g13elDR+tC0X9TTFVgUL+V6OyeppwYIRZ/J/4f7YBRGZML3eX\ni4x3ex95QfqjlF/YrHX4UEYgHDKFOxYlqFB7aB8G4K7dlDZWJsrqGITfDXFtEdb1\nPPZbD8/lmSCQxwMw7NhdrqU=\n-----END PRIVATE KEY-----\n","client_email": "firebase-adminsdk-fbsvc@devfest-d7fc2.iam.gserviceaccount.com","client_id": "102760452747836456723","auth_uri": "https://accounts.google.com/o/oauth2/auth","token_uri": "https://oauth2.googleapis.com/token","auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40devfest-d7fc2.iam.gserviceaccount.com","universe_domain": "googleapis.com"}" || "{}");
const {
  project_id: PROJECT_ID,
  client_email: CLIENT_EMAIL,
  private_key: PRIVATE_KEY,
} = SA;

if (!PRIVATE_KEY?.trim()) {
  throw new Error("Missing private_key in SERVICE_ACCOUNT_JSON");
}

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

// ---------- FCM send (strictly for topic or token) ----------
async function sendFCMMessage(rawMessage: any, id: string) {
  // 🔒 Убедимся, что не смешиваем token и topic
  const hasToken = "token" in rawMessage;
  const hasTopic = "topic" in rawMessage;

  if (hasToken && hasTopic) {
    logErr(`[${id}] FATAL: message contains both 'token' and 'topic'!`, rawMessage);
    throw new Error("Ambiguous FCM message: cannot have both token and topic");
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

      // Проверка на UNREGISTERED — только если был token
      if (hasToken) {
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
          // ignore
        }
      }

      return false;
    } else {
      log(`[${id}] FCM sent successfully`, { hasTopic, hasToken });
      return true;
    }
  } catch (e) {
    logErr(`[${id}] Exception in sendFCMMessage`, e);
    return false;
  }
}

// ---------- VIP broadcast: ONLY TOPIC, NO TOKEN ----------
async function broadcastVip() {
  const id = crypto.randomUUID();
  log(`[${id}] Sending VIP broadcast to topic 'devfest_vip'`);

  const message = {
    topic: "devfest_vip",
    notification: {
      title: "VIP-опыт на ДевФест",
      body: "Получите все привилегии: от мастер-классов и игр до личного общения со спикерами. Повысьте категорию билета!",
    },
    android: {
      notification: {
        sound: "default",
      },
    },
  };

  await sendFCMMessage(message, id);
}

// ---------- Mattermost payload ----------
interface MattermostPayload {
  type: string;
  platform: string;
  device_id?: string;
  message?: string;
  [key: string]: unknown;
}

// ---------- Mattermost push ----------
async function handleMattermost(payload: MattermostPayload, id: string) {
  const { type, platform, device_id: token } = payload;

  if (type === "test") return new Response("OK", { status: 200 });
  if (type !== "message" && type !== "clear") return new Response("Bad type", { status: 400 });
  if (type === "clear") return new Response("OK", { status: 200 });

  let p = platform;
  if (p === "android_rn" || p === "android_rn-v2") p = "android";
  if (p !== "android") return new Response("Only Android supported", { status: 400 });
  if (!token) return new Response("No device_id", { status: 400 });

  const title = payload.channel_name || payload.sender_name || "Mattermost";
  const body = typeof payload.message === "string" ? payload.message : "";

  const  Record<string, string> = {};
  for (const key of [
    "ack_id", "server_id", "channel_id", "channel_name", "sender_id",
    "sender_name", "category", "type", "badge", "post_id", "version"
  ]) {
    data[key] = String(payload[key] ?? "");
  }

  log(`[${id}] Sending to token`, { token: token.substring(0, 10) + "..." });

  await sendFCMMessage(
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

  return new Response("OK", { status: 200 });
}

// ---------- HTTP Handler ----------
export default async function handler(req: Request): Promise<Response> {
  const id = crypto.randomUUID();
  const url = new URL(req.url);

  // Manual trigger for VIP
  if (req.method === "POST" && url.pathname === "/broadcast-vip") {
    const auth = req.headers.get("Authorization");
    if (auth !== "Bearer sYne9ZHEflIFrFwHXKjie05rDSqoJOrKaqlAgL4QF/0=") {
      return new Response("Unauthorized", { status: 401 });
    }
    log(`[${id}] Manual VIP broadcast triggered`);
    broadcastVip(); // fire-and-forget
    return new Response("OK", { status: 202 });
  }

  // Mattermost push
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let payload;
  try {
    payload = await req.json();
  } catch (e) {
    logErr(`[${id}] Invalid JSON`, e);
    return new Response("Invalid JSON", { status: 400 });
  }

  if (typeof payload !== "object" || payload === null) {
    return new Response("Payload must be an object", { status: 400 });
  }

  log(`[${id}] Mattermost request`, payload);
  return handleMattermost(payload, id);
}

// ---------- Export for Vercel Node.js Runtime ----------
export const config = {
  runtime: "nodejs",
};

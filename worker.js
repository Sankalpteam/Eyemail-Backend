export default {
  async email(message, env, ctx) {
    try {
      const toAddress = (message.to || "").toLowerCase().trim();
      const fromAddress = (message.from || "").trim();
      const subject = message.headers.get("subject") || "(No Subject)";

      if (!toAddress.endsWith("@eyemail.in")) {
        message.setReject("Invalid domain");
        return;
      }

      const username = toAddress.split("@")[0].replace(/[^a-z0-9._-]/g, "");
      if (!username) {
        message.setReject("Invalid recipient");
        return;
      }

      const rawEmail = await new Response(message.raw).text();
      const bodyText = extractPlainText(rawEmail);
      const snippet = bodyText.replace(/\s+/g, " ").trim().slice(0, 120);

      const accessToken = await getGoogleAccessToken(
        env.FIREBASE_CLIENT_EMAIL,
        env.FIREBASE_PRIVATE_KEY
      );

      const projectId = env.FIREBASE_PROJECT_ID;
      const baseUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;

      const userLookupResp = await fetch(`${baseUrl}/usernames/${username}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!userLookupResp.ok) {
        message.setReject("Mailbox does not exist");
        return;
      }

      const userLookupData = await userLookupResp.json();
      const targetUid = userLookupData.fields?.uid?.stringValue;

      if (!targetUid) {
        message.setReject("User UID not found");
        return;
      }

      const nowIso = new Date().toISOString();
      const firestoreDoc = {
        fields: {
          from: { stringValue: fromAddress },
          fromName: { stringValue: fromAddress.split("@")[0] },
          to: { stringValue: toAddress },
          subject: { stringValue: subject },
          body: { stringValue: bodyText || "(Empty message body)" },
          snippet: { stringValue: snippet },
          folder: { stringValue: "inbox" },
          read: { booleanValue: false },
          starred: { booleanValue: false },
          timestamp: { timestampValue: nowIso },
          createdAt: { stringValue: nowIso },
        },
      };

      await fetch(`${baseUrl}/users/${targetUid}/emails`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(firestoreDoc),
      });
    } catch (err) {
      console.error("Email worker error:", err);
    }
  },
};

function extractPlainText(raw) {
  const parts = raw.split(/\r?\n\r?\n/);
  if (parts.length < 2) return raw.slice(0, 4000);
  let body = parts.slice(1).join("\n\n");

  const boundaryMatch = raw.match(/boundary="?([^"\r\n;]+)"?/i);
  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const sections = raw.split("--" + boundary);
    for (const sec of sections) {
      if (/Content-Type:\s*text\/plain/i.test(sec)) {
        const secParts = sec.split(/\r?\n\r?\n/);
        if (secParts.length > 1) {
          body = secParts.slice(1).join("\n\n");
          break;
        }
      }
    }
  }

  body = body.replace(/=\r?\n/g, "").replace(/=20/g, " ").replace(/=3D/g, "=");
  return body.trim().slice(0, 15000);
}

async function getGoogleAccessToken(clientEmail, privateKeyPem) {
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const encode = (obj) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const unsignedJwt = `${encode(header)}.${encode(claim)}`;
  const cleanPem = privateKeyPem
    .replace(/\\n/g, "\n")
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");

  const binaryKey = Uint8Array.from(atob(cleanPem), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedJwt)
  );

  const signedJwt = `${unsignedJwt}.${btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")}`;

  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${signedJwt}`,
  });

  const tokenData = await tokenResp.json();
  return tokenData.access_token;
}

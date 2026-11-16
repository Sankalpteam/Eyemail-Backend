// Eyemail inbound mail worker
// Receives mail from Cloudflare Email Routing and hands it to the backend,
// which owns the mailbox lookup, storage accounting and Firestore write.
//
// Required Cloudflare environment variable:
//   WEBHOOK_SECRET   must match WEBHOOK_SECRET in Render
// BACKEND_URL is optional - it defaults to the Render service below.
//
// Deployed by hand in the Cloudflare dashboard (Email Routing -> Email Workers).
// A merge to this repository does not publish it.

const MAX_BODY_CHARS = 15000;

export default {
  async email(message, env, ctx) {
    const toAddress = (message.to || "").toLowerCase().trim();
    const fromAddress = (message.from || "").trim();
    const subject = message.headers.get("subject") || "(No Subject)";

    if (!toAddress.endsWith("@eyemail.in")) {
      message.setReject("Invalid domain");
      return;
    }

    // BACKEND_URL is not a secret, so it has a safe default and you do not
    // have to type it in the dashboard.
    const backendUrl = (env.BACKEND_URL || "https://eyemail-backend.onrender.com").replace(/\/+$/, "");

    if (!env.WEBHOOK_SECRET) {
      // Misconfigured worker: defer the message instead of losing it.
      throw new Error("Worker is missing WEBHOOK_SECRET");
    }

    const rawEmail = await new Response(message.raw).text();
    const bodyText = extractPlainText(rawEmail);

    let resp;
    try {
      resp = await fetch(`${backendUrl}/webhook/inbound`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-webhook-secret": env.WEBHOOK_SECRET,
        },
        body: JSON.stringify({
          from: fromAddress,
          to: toAddress,
          subject: subject,
          text: bodyText,
        }),
      });
    } catch (err) {
      // Backend unreachable (cold start, network). Defer so Cloudflare retries.
      throw new Error(`Backend unreachable: ${err}`);
    }

    if (resp.ok) return;

    if (resp.status === 404) {
      // Mailbox really does not exist - bounce it so the sender knows.
      message.setReject("Mailbox does not exist");
      return;
    }

    const detail = await resp.text();
    throw new Error(`Backend rejected inbound mail (${resp.status}): ${detail}`);
  },
};

function extractPlainText(raw) {
  const parts = raw.split(/\r?\n\r?\n/);
  if (parts.length < 2) return raw.slice(0, MAX_BODY_CHARS);
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
  return body.trim().slice(0, MAX_BODY_CHARS);
}

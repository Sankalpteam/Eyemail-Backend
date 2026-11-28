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

/**
 * The words out of an HTML mail, keeping the shape: paragraphs, line breaks, list items,
 * and the addresses of links beside their words. Nothing is executed and nothing is kept
 * that a person cannot read.
 */
function htmlToText(html) {
  let text = String(html);
  text = text.replace(/<\s*(script|style|head|title)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, " ");
  text = text.replace(/<\s*br\s*\/?\s*>/gi, "\n");
  text = text.replace(/<\s*\/\s*(p|div|tr|h[1-6]|blockquote|li)\s*>/gi, "\n");
  text = text.replace(/<\s*li[^>]*>/gi, "\n• ");
  text = text.replace(/<\s*a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\s*\/\s*a\s*>/gi,
    (_m, href, label) => {
      const words = String(label).replace(/<[^>]+>/g, "").trim();
      const url = String(href).trim();
      if (!words) return url;
      return words === url ? url : `${words} (${url})`;
    });
  text = text.replace(/<[^>]+>/g, " ");
  const entities = {
    "&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
    "&#39;": "'", "&apos;": "'", "&mdash;": "—", "&ndash;": "–", "&hellip;": "…",
    "&rsquo;": "’", "&lsquo;": "‘", "&ldquo;": "“", "&rdquo;": "”",
  };
  text = text.replace(/&[a-zA-Z#0-9]+;/g, (m) => entities[m.toLowerCase()] ?? m);
  text = text.replace(/[ \t\u00a0]+/g, " ");
  // A space left on either side of a line break reads as a dent in the paragraph.
  text = text.replace(/[ \t]*\n[ \t]*/g, "\n");
  text = text.replace(/\n{3,}/g, "\n\n");
  return text.trim();
}

function extractPlainText(raw) {
  const parts = raw.split(/\r?\n\r?\n/);
  if (parts.length < 2) return raw.slice(0, MAX_BODY_CHARS);
  let body = parts.slice(1).join("\n\n");

  let isHtml = false;
  const boundaryMatch = raw.match(/boundary="?([^"\r\n;]+)"?/i);
  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const sections = raw.split("--" + boundary);
    let htmlBody = "";
    for (const sec of sections) {
      if (/Content-Type:\s*text\/plain/i.test(sec)) {
        const secParts = sec.split(/\r?\n\r?\n/);
        if (secParts.length > 1) {
          body = secParts.slice(1).join("\n\n");
          htmlBody = "";
          break;
        }
      }
      if (!htmlBody && /Content-Type:\s*text\/html/i.test(sec)) {
        const secParts = sec.split(/\r?\n\r?\n/);
        if (secParts.length > 1) htmlBody = secParts.slice(1).join("\n\n");
      }
    }
    // No plain part at all: the mail is HTML only, so turn it into words here rather than
    // showing tags to the person in the mailbox.
    if (htmlBody) {
      body = htmlBody;
      isHtml = true;
    }
  } else if (/Content-Type:\s*text\/html/i.test(raw.slice(0, 2000))) {
    isHtml = true;
  }

  body = body.replace(/=\r?\n/g, "").replace(/=20/g, " ").replace(/=3D/g, "=");
  return body.trim().slice(0, MAX_BODY_CHARS);
}

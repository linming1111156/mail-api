
import PostalMime from "postal-mime";

interface Env {
  DB: D1Database;
  API_TOKEN: string;
  ROUTE_ADDRESS: string;
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function extractUrls(text: string): string[] {
  const normalized = text
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

  const matches = normalized.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  return [...new Set(matches.map((url) => url.replace(/[),.;]+$/, "")))];
}

function extractVerificationCode(text: string): string | null {
  const patterns = [
    /(?:verification|verify|security|confirmation|one[- ]time|otp|验证码|校验码|验证代码)[^\d]{0,40}(\d{4,8})/i,
    /(\d{4,8})[^\w]{0,20}(?:is your|is the|verification|security|confirmation|one[- ]time|otp|验证码|校验码)/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) return match[1];
  }

  return null;
}

function authorized(request: Request, env: Env): boolean {
  const header = request.headers.get("Authorization") ?? "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match || !env.API_TOKEN) return false;

  const supplied = match[1];
  const expected = env.API_TOKEN;

  // Compare fixed-length digests to avoid leaking token length or contents.
  return false;
}

async function isAuthorized(
  request: Request,
  env: Env,
): Promise<boolean> {
  const header = request.headers.get("Authorization") ?? "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match || !env.API_TOKEN) return false;

  const encoder = new TextEncoder();
  const supplied = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(match[1]),
  );
  const expected = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(env.API_TOKEN),
  );

  const a = new Uint8Array(supplied);
  const b = new Uint8Array(expected);
  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

async function handleApi(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!(await isAuthorized(request, env))) {
    return json({ error: "Unauthorized" }, 401);
  }

  if (!env.DB) {
    return json({ error: "D1 database binding DB is missing" }, 500);
  }

  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  if (path === "/api/health") {
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      return json({ ok: true, database: "connected" });
    } catch {
      return json({ ok: false, database: "error" }, 500);
    }
  }

  if (path === "/api/emails") {
    const recipient = url.searchParams.get("to")?.trim();
    const sender = url.searchParams.get("from")?.trim();
    const since = url.searchParams.get("since");
    const until = url.searchParams.get("until");

    const limit = Math.min(
      Math.max(Number(url.searchParams.get("limit") ?? "20") || 20, 1),
      100,
    );
    const offset = Math.max(
      Number(url.searchParams.get("offset") ?? "0") || 0,
      0,
    );

    const conditions: string[] = [];
    const bindings: (string | number)[] = [];

    if (recipient) {
      conditions.push("lower(recipient) = ?");
      bindings.push(normalizeEmail(recipient));
    }

    if (sender) {
      conditions.push("lower(sender) = ?");
      bindings.push(normalizeEmail(sender));
    }

    if (since) {
      if (Number.isNaN(Date.parse(since))) {
        return json({ error: "Invalid since date" }, 400);
      }
      conditions.push("received_at >= ?");
      bindings.push(since);
    }

    if (until) {
      if (Number.isNaN(Date.parse(until))) {
        return json({ error: "Invalid until date" }, 400);
      }
      conditions.push("received_at <= ?");
      bindings.push(until);
    }

    const where = conditions.length
      ? `WHERE ${conditions.join(" AND ")}`
      : "";

    const count = await env.DB.prepare(
      `SELECT COUNT(*) AS total FROM emails ${where}`,
    )
      .bind(...bindings)
      .first<{ total: number }>();

    const results = await env.DB.prepare(
      `SELECT id, message_id, sender, recipient, subject,
              verification_url, verification_code, received_at
       FROM emails ${where}
       ORDER BY received_at DESC, id DESC
       LIMIT ? OFFSET ?`,
    )
      .bind(...bindings, limit, offset)
      .all();

    return json({
      total: count?.total ?? 0,
      limit,
      offset,
      emails: results.results,
    });
  }

  const detailMatch = path.match(/^\/api\/emails\/(\d+)$/);

  if (detailMatch) {
    const id = Number(detailMatch[1]);

    const email = await env.DB.prepare(
      `SELECT id, message_id, sender, recipient, subject,
              text_body, html_body, verification_url,
              verification_code, received_at
       FROM emails WHERE id = ?`,
    )
      .bind(id)
      .first();

    if (!email) {
      return json({ error: "Email not found" }, 404);
    }

    return json({ email });
  }

  return json({ error: "Not found" }, 404);
}

export async function handleEmail(
  message: ForwardableEmailMessage,
  env: Env,
): Promise<void> {
  try {
    if (!env.DB) {
      message.setReject("Email storage is not configured");
      return;
    }

    const parsed = await PostalMime.parse(message.raw);

    const sender =
      parsed.from?.address?.trim() ||
      message.from.trim();

    const recipient =
      Array.isArray(parsed.to)
        ? parsed.to.map((item) => item.address).filter(Boolean).join(", ")
        : parsed.to?.address || message.to;

    const textBody = parsed.text ?? "";
    const htmlBody = typeof parsed.html === "string" ? parsed.html : "";

    const combined = `${textBody}\n${htmlBody}`;
    const urls = extractUrls(combined);
    const verificationUrl =
      urls.find((item) =>
        /verify|verification|confirm|activate|token|auth|验证|确认/i.test(item),
      ) ?? urls[0] ?? null;

    const verificationCode = extractVerificationCode(
      `${parsed.subject ?? ""}\n${textBody}\n${htmlBody.replace(/<[^>]*>/g, " ")}`,
    );

    const messageId =
      parsed.messageId ??
      message.headers.get("message-id");

    await env.DB.prepare(
      `INSERT INTO emails (
        message_id, sender, recipient, subject,
        text_body, html_body, verification_url, verification_code
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        messageId ?? null,
        sender,
        recipient,
        parsed.subject ?? "",
        textBody,
        htmlBody,
        verificationUrl,
        verificationCode,
      )
      .run();
  } catch (error) {
    console.error("Failed to store incoming email", error);
    message.setReject("Failed to store incoming email");
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env);
    }

    if (url.pathname === "/") {
      return json({
        service: "mail-api",
        status: "running",
        endpoints: [
          "GET /api/health",
          "GET /api/emails",
          "GET /api/emails/:id",
        ],
      });
    }

    return json({ error: "Not found" }, 404);
  },

  email: handleEmail,
} satisfies ExportedHandler<Env>;

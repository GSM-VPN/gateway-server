import { createHmac, timingSafeEqual } from "node:crypto";

type SessionPayload = {
  deviceId: string;
  email: string;
  exp: number;
  iat: number;
  scope: "vpn";
};

function base64UrlEncode(value: string): string {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function sign(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createSessionToken(payload: SessionPayload, secret: string): string {
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = sign(secret, body);
  return `${body}.${signature}`;
}

export function verifySessionToken(token: string, secret: string): SessionPayload | null {
  const [body, signature] = token.split(".");
  if (!body || !signature) {
    return null;
  }

  const expected = Buffer.from(sign(secret, body), "utf8");
  const actual = Buffer.from(signature, "utf8");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(body)) as SessionPayload;
    if (payload.scope !== "vpn") {
      return null;
    }
    if (payload.exp < Date.now()) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export function createGatewayRequestSignature(secret: string, parts: string[]): string {
  return createHmac("sha256", secret).update(parts.join("|")).digest("base64url");
}

export function verifyGatewayRequestSignature(secret: string, parts: string[], signature: string): boolean {
  const expected = Buffer.from(createGatewayRequestSignature(secret, parts), "utf8");
  const actual = Buffer.from(signature, "utf8");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}


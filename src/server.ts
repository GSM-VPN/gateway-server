import Fastify from "fastify";
import type { IncomingHttpHeaders } from "node:http";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { config } from "./config.js";
import {
  createGatewayRequestSignature,
  createSessionToken,
  verifySessionToken,
} from "./auth.js";
import type {
  ConnectRequestBody,
  ConnectResponse,
  GatewayAuthContext,
  LoginResponse,
  LoginRequestBody,
  SelectServerResult,
  ServerStatus,
} from "./types.js";

const app = Fastify({ logger: true });

type ClientLease = {
  clientAddress: string;
  peerPublicKey: string;
  serverId: string;
};

const clientLeases = new Map<string, ClientLease>();
const persistedLeases = new Map<string, ClientLease>();
const stateFilePath = path.resolve(config.stateFilePath);

const servers: ReadonlyArray<ServerStatus> = [
  {
    id: "vpn-a",
    name: "VPN Server A",
    region: "primary",
    loadPercent: 32,
    online: true,
    endpoint: config.vpnServerAUrl || "http://127.0.0.1:8081",
    publicKey: "",
  },
  {
    id: "vpn-b",
    name: "VPN Server B",
    region: "backup",
    loadPercent: 18,
    online: true,
    endpoint: config.vpnServerBUrl || "http://127.0.0.1:8082",
    publicKey: "",
  },
];

async function refreshServerStatus(server: ServerStatus): Promise<ServerStatus> {
  try {
    const response = await fetch(`${server.endpoint}/status`);
    if (!response.ok) {
      return server;
    }

    const data = (await response.json()) as Partial<ServerStatus>;
    return {
      ...server,
      online: data.online ?? server.online,
      loadPercent: typeof data.loadPercent === "number" ? data.loadPercent : server.loadPercent,
      publicKey: typeof data.publicKey === "string" ? data.publicKey : server.publicKey,
    };
  } catch {
    return server;
  }
}

function selectBestServer(serverList: ReadonlyArray<ServerStatus>): ServerStatus | undefined {
  return [...serverList].filter((server) => server.online).sort((a, b) => a.loadPercent - b.loadPercent)[0];
}

function allocateClientAddress(): string {
  const usedAddresses = new Set([
    ...Array.from(clientLeases.values()).map((lease) => lease.clientAddress),
    ...Array.from(persistedLeases.values()).map((lease) => lease.clientAddress),
  ]);

  for (let host = 2; host < 255; host += 1) {
    const address = `10.10.0.${host}/32`;
    if (!usedAddresses.has(address)) {
      return address;
    }
  }

  throw new Error("No available client addresses");
}

async function loadPersistedLeases(): Promise<void> {
  try {
    const raw = await readFile(stateFilePath, "utf8");
    const parsed = JSON.parse(raw) as { leases?: Record<string, ClientLease> };
    for (const [deviceId, lease] of Object.entries(parsed.leases ?? {})) {
      if (lease?.clientAddress && lease?.peerPublicKey && lease?.serverId) {
        persistedLeases.set(deviceId, lease);
      }
    }
  } catch {
    // No saved lease file yet is fine.
  }
}

async function savePersistedLeases(): Promise<void> {
  await mkdir(path.dirname(stateFilePath), { recursive: true });
  const payload = Object.fromEntries(clientLeases);
  await writeFile(stateFilePath, JSON.stringify({ leases: { ...Object.fromEntries(persistedLeases), ...payload } }, null, 2), "utf8");
}

async function removePeerFromServer(server: ServerStatus, deviceId: string, peerPublicKey: string): Promise<void> {
  const timestamp = Date.now().toString();
  const gatewaySignature = createGatewayRequestSignature(config.gatewaySharedSecret, [
    timestamp,
    server.id,
    peerPublicKey,
    deviceId,
  ]);

  await fetch(`${server.endpoint}/peers/${encodeURIComponent(peerPublicKey)}`, {
    method: "DELETE",
    headers: {
      "x-gateway-timestamp": timestamp,
      "x-gateway-signature": gatewaySignature,
      "x-gateway-device-id": deviceId,
      "x-gateway-server-id": server.id,
    },
  });
}

async function registerPeerOnServer(
  server: ServerStatus,
  deviceId: string,
  peerPublicKey: string,
  clientAddress: string
): Promise<boolean> {
  const timestamp = Date.now().toString();
  const gatewaySignature = createGatewayRequestSignature(config.gatewaySharedSecret, [
    timestamp,
    server.id,
    peerPublicKey,
    deviceId,
  ]);

  const response = await fetch(`${server.endpoint}/peers/register`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-gateway-timestamp": timestamp,
      "x-gateway-signature": gatewaySignature,
      "x-gateway-device-id": deviceId,
      "x-gateway-server-id": server.id,
    },
    body: JSON.stringify({
      publicKey: peerPublicKey,
      allowedIps: [clientAddress],
      serverId: server.id,
      deviceId,
    }),
  });

  return response.ok;
}

function readHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

async function requireAuth(request: { headers: IncomingHttpHeaders }): Promise<GatewayAuthContext | null> {
  const authHeader = readHeader(request.headers, "authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.slice("Bearer ".length);
  const payload = verifySessionToken(token, config.authSecret);
  if (!payload) {
    return null;
  }

  return {
    email: payload.email,
    deviceId: payload.deviceId,
  };
}

app.get("/health", async (): Promise<{ ok: true; app: string }> => {
  return {
    ok: true,
    app: config.appName,
  };
});

app.post<{ Body: LoginRequestBody }>("/login", async (request, reply): Promise<LoginResponse | { ok: false; message: string }> => {
  const email = request.body.email?.trim().toLowerCase();
  const inviteCode = request.body.inviteCode?.trim();
  const deviceId = request.body.deviceId?.trim() || randomUUID();

  if (!email) {
    reply.code(400);
    return { ok: false, message: "email is required" };
  }

  if (config.inviteCode && inviteCode !== config.inviteCode.trim()) {
    reply.code(401);
    return { ok: false, message: "invalid invite code" };
  }

  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
  const accessToken = createSessionToken(
    {
      email,
      deviceId,
      iat: Date.now(),
      exp: Date.now() + 1000 * 60 * 60 * 24,
      scope: "vpn",
    },
    config.authSecret
  );

  return {
    ok: true,
    message: "Login successful",
    accessToken,
    expiresAt,
    user: {
      email,
      deviceId,
    },
  };
});

app.get("/servers", async (request, reply): Promise<{ servers: ServerStatus[] } | { ok: false; message: string }> => {
  const auth = await requireAuth(request);
  if (!auth) {
    reply.code(401);
    return { ok: false, message: "unauthorized" };
  }

  const refreshed = await Promise.all(servers.map((server) => refreshServerStatus(server)));
  return { servers: refreshed };
});

app.post<{ Body: ConnectRequestBody }>("/connect", async (request, reply) => {
  const auth = await requireAuth(request);
  if (!auth) {
    reply.code(401);
    return { ok: false, message: "unauthorized" };
  }

  const refreshed: ServerStatus[] = await Promise.all(servers.map((server) => refreshServerStatus(server)));
  const selected: ServerStatus | undefined = request.body.serverId
    ? refreshed.find((server) => server.id === request.body.serverId && server.online)
    : selectBestServer(refreshed);

  if (!selected) {
    return {
      ok: false,
      message: "No online VPN servers were available",
    };
  }

  const clientPublicKey = request.body.clientPublicKey?.trim();
  if (!clientPublicKey) {
    reply.code(400);
    return {
      ok: false,
      message: "clientPublicKey is required",
    };
  }

  if (!selected.publicKey) {
    reply.code(502);
    return {
      ok: false,
      message: "selected VPN server has no public key yet",
    };
  }

  const existingLease = clientLeases.get(auth.deviceId);
  const persistedLease = persistedLeases.get(auth.deviceId);
  const clientAddress = existingLease?.clientAddress ?? persistedLease?.clientAddress ?? allocateClientAddress();

  const leaseToCleanup = existingLease ?? persistedLease;
  if (leaseToCleanup) {
    const previousServer = refreshed.find((server) => server.id === leaseToCleanup.serverId);
    if (previousServer) {
      try {
        await removePeerFromServer(previousServer, auth.deviceId, leaseToCleanup.peerPublicKey);
      } catch {
        // If cleanup fails, continue so the new registration can still succeed.
      }
    }
    clientLeases.delete(auth.deviceId);
    persistedLeases.delete(auth.deviceId);
  }

  try {
    const registrationOk = await registerPeerOnServer(selected, auth.deviceId, clientPublicKey, clientAddress);
    if (!registrationOk) {
      reply.code(502);
      return {
        ok: false,
        message: "failed to register peer on VPN server",
      };
    }
  } catch {
    reply.code(502);
    return {
      ok: false,
      message: "failed to contact VPN server",
    };
  }

  clientLeases.set(auth.deviceId, {
    clientAddress,
    peerPublicKey: clientPublicKey,
    serverId: selected.id,
  });
  await savePersistedLeases();

  const response: ConnectResponse = {
    serverId: selected.id,
    endpoint: selected.endpoint,
    publicKey: selected.publicKey,
    allowedIps: ["0.0.0.0/0", "::/0"],
    clientPublicKey,
    clientAddress,
  };

  const result: SelectServerResult = {
    selectedServer: selected,
    connection: response,
  };

  return {
    ok: true,
    userId: request.body.userId ?? auth.email,
    ...result,
  };
});

app.post("/disconnect", async (request, reply): Promise<{ ok: true; message: string } | { ok: false; message: string }> => {
  const auth = await requireAuth(request);
  if (!auth) {
    reply.code(401);
    return { ok: false, message: "unauthorized" };
  }

  const lease = clientLeases.get(auth.deviceId);
  if (lease) {
    const refreshed = await Promise.all(servers.map((server) => refreshServerStatus(server)));
    const server = refreshed.find((candidate) => candidate.id === lease.serverId);
    if (server) {
      try {
        await removePeerFromServer(server, auth.deviceId, lease.peerPublicKey);
      } catch {
        // Disconnect should still complete even if peer cleanup fails.
      }
    }
    clientLeases.delete(auth.deviceId);
    persistedLeases.delete(auth.deviceId);
    await savePersistedLeases();
  }

  return {
    ok: true,
    message: "Disconnected",
  };
});

const start = async (): Promise<void> => {
  try {
    await loadPersistedLeases();
    await app.listen({ port: config.port, host: "0.0.0.0" });
  } catch (error) {
    app.log.error(error);
    process.exit(1);
  }
};

void start();

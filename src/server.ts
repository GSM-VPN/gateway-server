import websocket from "@fastify/websocket";
import Fastify from "fastify";
import type { FastifyRequest } from "fastify";
import type { IncomingHttpHeaders } from "node:http";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import WebSocket, { type RawData } from "ws";
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
  VpnServerInfoUpdate,
  VpnServerRegisterRequest,
  VpnServerRegisterResponse,
} from "./types.js";

type ClientLease = {
  clientAddress: string;
  peerPublicKey: string;
  serverId: string;
};

type VpnServerRecord = ServerStatus & {
  wsKey: string;
  socket: WebSocket | null;
};

type VpnServerInfoPayload = VpnServerInfoUpdate & {
  id?: string;
};

const app = Fastify({ logger: true });

const clientLeases = new Map<string, ClientLease>();
const persistedLeases = new Map<string, ClientLease>();
const vpnServersById = new Map<string, VpnServerRecord>();
const vpnServerIdsByWsKey = new Map<string, string>();
const stateFilePath = path.resolve(config.stateFilePath);

function normalizeName(baseName: string, existingNames: ReadonlySet<string>): string {
  const trimmed = baseName.trim() || "VPN Server";
  if (!existingNames.has(trimmed)) {
    return trimmed;
  }

  for (let suffix = 1; suffix < 1000; suffix += 1) {
    const candidate = `${trimmed}-${String(suffix).padStart(2, "0")}`;
    if (!existingNames.has(candidate)) {
      return candidate;
    }
  }

  throw new Error("No available server names");
}

function buildManagementUrl(ip: string, tcpPort: number): string {
  return `http://${ip}:${tcpPort}`;
}

function buildEndpoint(ip: string, udpPort: number): string {
  return `${ip}:${udpPort}`;
}

function toPublicServerStatus(server: VpnServerRecord): ServerStatus {
  return {
    id: server.id,
    name: server.name,
    ip: server.ip,
    internalUdpPort: server.internalUdpPort,
    externalUdpPort: server.externalUdpPort,
    httpPort: server.httpPort,
    externalHttpPort: server.externalHttpPort,
    managementUrl: server.managementUrl,
    endpoint: server.endpoint,
    loadPercent: server.loadPercent,
    online: server.online,
    publicKey: server.publicKey,
    lastSeenAt: server.lastSeenAt,
  };
}

function listServers(): ServerStatus[] {
  return [...vpnServersById.values()]
    .map(toPublicServerStatus)
    .sort((a, b) => a.name.localeCompare(b.name));
}

function selectBestServer(serverList: ReadonlyArray<ServerStatus>): ServerStatus | undefined {
  return [...serverList]
    .filter((server) => server.online)
    .sort((a, b) => a.loadPercent - b.loadPercent || a.name.localeCompare(b.name))[0];
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
  await writeFile(
    stateFilePath,
    JSON.stringify({ leases: { ...Object.fromEntries(persistedLeases), ...payload } }, null, 2),
    "utf8"
  );
}

function readHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function readGatewayAuthHeaders(request: { headers: IncomingHttpHeaders }): {
  signature: string;
  timestamp: string;
} | null {
  const signature = readHeader(request.headers, "x-gateway-signature");
  const timestamp = readHeader(request.headers, "x-gateway-timestamp");
  if (!signature || !timestamp) {
    return null;
  }

  const parsed = Number(timestamp);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  if (Math.abs(Date.now() - parsed) > 5 * 60 * 1000) {
    return null;
  }

  return { signature, timestamp };
}

function readPeerAuthHeaders(request: { headers: IncomingHttpHeaders }): {
  deviceId: string;
  signature: string;
  serverId: string;
  timestamp: string;
} | null {
  const deviceId = readHeader(request.headers, "x-gateway-device-id");
  const signature = readHeader(request.headers, "x-gateway-signature");
  const serverId = readHeader(request.headers, "x-gateway-server-id");
  const timestamp = readHeader(request.headers, "x-gateway-timestamp");
  if (!deviceId || !signature || !serverId || !timestamp) {
    return null;
  }

  const parsed = Number(timestamp);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  if (Math.abs(Date.now() - parsed) > 5 * 60 * 1000) {
    return null;
  }

  return { deviceId, signature, serverId, timestamp };
}

function pickExistingServer(request: VpnServerRegisterRequest): VpnServerRecord | undefined {
  const ip = request.ip?.trim();
  const internalUdpPort = request.internalUdpPort;
  const httpPort = request.httpPort;
  if (!ip || typeof internalUdpPort !== "number" || typeof httpPort !== "number") {
    return undefined;
  }

  return [...vpnServersById.values()].find(
    (server) => server.ip === ip && server.internalUdpPort === internalUdpPort && server.httpPort === httpPort
  );
}

function upsertVpnServer(request: VpnServerRegisterRequest, wsKey: string): VpnServerRecord {
  const ip = request.ip?.trim() || "127.0.0.1";
  const internalUdpPort = Number(request.internalUdpPort ?? 0);
  const externalUdpPort = Number(request.externalUdpPort ?? request.internalUdpPort ?? 0);
  const httpPort = Number(request.httpPort ?? 0);
  const externalHttpPort = Number(request.externalHttpPort ?? request.httpPort ?? 0);
  const existing = pickExistingServer(request);
  const existingNames = new Set(
    [...vpnServersById.values()]
      .filter((server) => server.id !== existing?.id)
      .map((server) => server.name)
  );
  const name = normalizeName(request.name?.trim() || existing?.name || "VPN Server", existingNames);
  const id = existing?.id ?? randomUUID();
  const baseRecord: VpnServerRecord = {
    id,
    wsKey,
    socket: existing?.socket ?? null,
    name,
    ip,
    internalUdpPort,
    externalUdpPort,
    httpPort,
    externalHttpPort,
    managementUrl: buildManagementUrl(ip, externalHttpPort),
    endpoint: buildEndpoint(ip, externalUdpPort),
    loadPercent: existing?.loadPercent ?? 0,
    online: existing?.online ?? false,
    publicKey: existing?.publicKey ?? "",
    lastSeenAt: existing?.lastSeenAt ?? null,
  };

  vpnServersById.set(id, baseRecord);
  vpnServerIdsByWsKey.set(wsKey, id);

  if (existing && existing.wsKey !== wsKey) {
    vpnServerIdsByWsKey.delete(existing.wsKey);
  }

  return baseRecord;
}

function mergeServerInfo(server: VpnServerRecord, update: VpnServerInfoPayload): VpnServerRecord {
  const nextIp = update.ip?.trim() || server.ip;
  const nextInternalUdpPort =
    typeof update.internalUdpPort === "number" ? update.internalUdpPort : server.internalUdpPort;
  const nextPublicUdpPort =
    typeof (update as VpnServerRegisterRequest).externalUdpPort === "number"
      ? (update as VpnServerRegisterRequest).externalUdpPort!
      : server.externalUdpPort;
  const nextHttpPort = typeof update.httpPort === "number" ? update.httpPort : server.httpPort;
  const nextPublicTcpPort =
    typeof (update as VpnServerRegisterRequest).externalHttpPort === "number"
      ? (update as VpnServerRegisterRequest).externalHttpPort!
      : server.externalHttpPort;
  const nextName = update.name?.trim() || server.name;
  const existingNames = new Set(
    [...vpnServersById.values()]
      .filter((candidate) => candidate.id !== server.id)
      .map((candidate) => candidate.name)
  );
  const normalizedName = normalizeName(nextName, existingNames);
  const merged: VpnServerRecord = {
    ...server,
    name: normalizedName,
    ip: nextIp,
    internalUdpPort: nextInternalUdpPort,
    externalUdpPort: nextPublicUdpPort,
    httpPort: nextHttpPort,
    externalHttpPort: nextPublicTcpPort,
    managementUrl: buildManagementUrl(nextIp, nextPublicTcpPort),
    endpoint: buildEndpoint(nextIp, nextPublicUdpPort),
    loadPercent: typeof update.loadPercent === "number" ? update.loadPercent : server.loadPercent,
    online: typeof update.online === "boolean" ? update.online : true,
    publicKey: typeof update.publicKey === "string" ? update.publicKey : server.publicKey,
    lastSeenAt: new Date().toISOString(),
  };

  vpnServersById.set(server.id, merged);
  return merged;
}

function readInfoPayload(raw: string): VpnServerInfoPayload | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") {
      return null;
    }

    if ("server" in parsed && parsed.server && typeof parsed.server === "object") {
      return parsed.server as VpnServerInfoPayload;
    }

    return parsed as VpnServerInfoPayload;
  } catch {
    return null;
  }
}

function rawDataToString(message: RawData): string {
  if (typeof message === "string") {
    return message;
  }

  if (Array.isArray(message)) {
    return Buffer.concat(message).toString("utf8");
  }

  return Buffer.isBuffer(message) ? message.toString("utf8") : Buffer.from(message).toString("utf8");
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

  const response = await fetch(`${server.managementUrl}/peers/register`, {
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

async function removePeerFromServer(server: ServerStatus, deviceId: string, peerPublicKey: string): Promise<void> {
  const timestamp = Date.now().toString();
  const gatewaySignature = createGatewayRequestSignature(config.gatewaySharedSecret, [
    timestamp,
    server.id,
    peerPublicKey,
    deviceId,
  ]);

  await fetch(`${server.managementUrl}/peers/${encodeURIComponent(peerPublicKey)}`, {
    method: "DELETE",
    headers: {
      "x-gateway-timestamp": timestamp,
      "x-gateway-signature": gatewaySignature,
      "x-gateway-device-id": deviceId,
      "x-gateway-server-id": server.id,
    },
  });
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

function getServerById(serverId: string | undefined): VpnServerRecord | undefined {
  if (!serverId) {
    return undefined;
  }

  return vpnServersById.get(serverId);
}

async function publishServerState(socket: WebSocket, server: VpnServerRecord): Promise<void> {
  if (socket.readyState !== WebSocket.OPEN) {
    return;
  }

  socket.send(JSON.stringify({ ok: true, server: toPublicServerStatus(server) }));
}

app.register(websocket);

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

  return { servers: listServers() };
});

app.post<{ Body: VpnServerRegisterRequest }>("/vpn/register", async (request, reply): Promise<VpnServerRegisterResponse> => {
  const auth = readGatewayAuthHeaders(request);
  if (!auth) {
    reply.code(401);
    return { ok: false, message: "unauthorized" };
  }

  const ip = request.body.ip?.trim();
  const internalUdpPort = request.body.internalUdpPort;
  const httpPort = request.body.httpPort;
  const name = request.body.name?.trim();

  if (!ip) {
    reply.code(400);
    return { ok: false, message: "ip is required" };
  }

  if (typeof internalUdpPort !== "number" || typeof httpPort !== "number") {
    reply.code(400);
    return { ok: false, message: "internalUdpPort and httpPort are required" };
  }

  if (!name) {
    reply.code(400);
    return { ok: false, message: "name is required" };
  }

  const externalUdpPort =
    typeof request.body.externalUdpPort === "number" ? request.body.externalUdpPort : internalUdpPort;
  const externalHttpPort = typeof request.body.externalHttpPort === "number" ? request.body.externalHttpPort : httpPort;

  const signatureOk = createGatewayRequestSignature(config.gatewaySharedSecret, [
    auth.timestamp,
    ip,
    String(internalUdpPort),
    String(externalUdpPort),
    String(httpPort),
    String(externalHttpPort),
    name,
  ]);

  const headerSignature = readHeader(request.headers, "x-gateway-signature") ?? "";
  if (signatureOk !== headerSignature) {
    reply.code(401);
    return { ok: false, message: "invalid gateway signature" };
  }

  const wsKey = randomUUID();
  const server = upsertVpnServer(
    { ip, internalUdpPort, externalUdpPort, httpPort, externalHttpPort, name },
    wsKey
  );

  return {
    ok: true,
    message: "VPN server registered",
    wsKey,
    server: toPublicServerStatus(server),
  };
});

app.get<{ Querystring: { wsKey?: string } }>(
  "/vpn/info",
  { websocket: true },
  (socket: WebSocket, request: FastifyRequest<{ Querystring: { wsKey?: string } }>) => {
    const wsKey = request.query.wsKey?.trim();
    const serverId = wsKey ? vpnServerIdsByWsKey.get(wsKey) : undefined;
    const server = getServerById(serverId);

    if (!server || server.wsKey !== wsKey) {
      socket.close(1008, "invalid wsKey");
      return;
    }

    if (server.socket && server.socket !== socket && server.socket.readyState === WebSocket.OPEN) {
      server.socket.close(1000, "replaced");
    }

    const nextServer: VpnServerRecord = {
      ...server,
      socket,
      online: true,
      lastSeenAt: new Date().toISOString(),
    };
    vpnServersById.set(server.id, nextServer);

    void publishServerState(socket, nextServer);

    socket.on("message", (message: RawData) => {
      const payload = readInfoPayload(rawDataToString(message));
      if (!payload) {
        return;
      }

      const current = vpnServersById.get(server.id);
      if (!current) {
        return;
      }

      const updated = mergeServerInfo(current, payload);
      void publishServerState(socket, updated);
    });

    socket.on("close", () => {
      const current = vpnServersById.get(server.id);
      if (!current || current.socket !== socket) {
        return;
      }

      vpnServersById.set(server.id, {
        ...current,
        socket: null,
        online: false,
        lastSeenAt: new Date().toISOString(),
      });
    });
  }
);

app.post<{ Body: ConnectRequestBody }>("/connect", async (request, reply) => {
  const auth = await requireAuth(request);
  if (!auth) {
    reply.code(401);
    return { ok: false, message: "unauthorized" };
  }

  const servers = listServers();
  const selected: ServerStatus | undefined = request.body.serverId
    ? servers.find((server) => server.id === request.body.serverId && server.online)
    : selectBestServer(servers);

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
    const previousServer = vpnServersById.get(leaseToCleanup.serverId);
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
    const server = vpnServersById.get(lease.serverId);
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
    await app.listen({ port: config.httpPort, host: "0.0.0.0" });
  } catch (error) {
    app.log.error(error);
    process.exit(1);
  }
};

void start();

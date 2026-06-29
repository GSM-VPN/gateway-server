export type ServerStatus = {
  id: string;
  name: string;
  ip: string;
  internalUdpPort: number;
  externalUdpPort: number;
  httpPort: number;
  externalHttpPort: number;
  managementUrl: string;
  endpoint: string;
  loadPercent: number;
  online: boolean;
  publicKey: string;
  lastSeenAt: string | null;
};

export type VpnServerRegisterRequest = {
  ip?: string;
  internalUdpPort?: number;
  externalUdpPort?: number;
  httpPort?: number;
  externalHttpPort?: number;
  name?: string;
};

export type VpnServerInfoUpdate = {
  ip?: string;
  internalUdpPort?: number;
  httpPort?: number;
  externalHttpPort?: number;
  name?: string;
  loadPercent?: number;
  online?: boolean;
  publicKey?: string;
  peers?: Array<{
    publicKey: string;
    allowedIps: string[];
    lastHandshakeAt: string | null;
    rxBytes: number;
    txBytes: number;
  }>;
};

export type VpnServerRegisterResponse =
  | { ok: true; message: string; wsKey: string; server: ServerStatus }
  | { ok: false; message: string };

export type ConnectResponse = {
  serverId: string;
  endpoint: string;
  publicKey: string;
  allowedIps: string[];
  clientPublicKey: string;
  clientAddress: string;
};

export type ConnectRequestBody = {
  userId?: string;
  clientPublicKey?: string;
  allowedIps?: string[];
  serverId?: string;
  deviceId?: string;
};

export type LoginRequestBody = {
  email?: string;
  inviteCode?: string;
  deviceId?: string;
};

export type LoginResponse = {
  ok: true;
  message: string;
  accessToken: string;
  expiresAt: string;
  user: {
    email: string;
    deviceId: string;
  };
};

export type SelectServerResult = {
  selectedServer: ServerStatus;
  connection: ConnectResponse;
};

export type GatewayAuthContext = {
  email: string;
  deviceId: string;
};

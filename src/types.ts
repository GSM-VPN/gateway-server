export type ServerStatus = {
  id: string;
  name: string;
  region: string;
  loadPercent: number;
  online: boolean;
  endpoint: string;
  publicKey: string;
};

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

type GatewayConfig = {
  port: number;
  appName: string;
  authSecret: string;
  inviteCode: string;
  gatewaySharedSecret: string;
  vpnServerAUrl: string;
  vpnServerBUrl: string;
  stateFilePath: string;
};

export const config: GatewayConfig = {
  port: Number(process.env.PORT ?? 8080),
  appName: process.env.APP_NAME ?? "GSM-VPN Gateway",
  authSecret: process.env.AUTH_SECRET ?? "dev-only-auth-secret-change-me",
  inviteCode: process.env.INVITE_CODE ?? "",
  gatewaySharedSecret: process.env.GATEWAY_SHARED_SECRET ?? "dev-only-gateway-secret-change-me",
  vpnServerAUrl: process.env.VPN_SERVER_A_URL ?? "",
  vpnServerBUrl: process.env.VPN_SERVER_B_URL ?? "",
  stateFilePath: process.env.GATEWAY_STATE_FILE ?? ".data/gateway-leases.json",
};

# Gateway Server

Handles login, VPN server registration, server selection, peer registration, and persisted lease state.

## Requirements

- Node.js
- TypeScript
- Fastify

## Setup

1. Run `npm install`
2. Copy `.env.example` to `.env`
3. Set the following values:

- `AUTH_SECRET`
- `INVITE_CODE`
- `GATEWAY_SHARED_SECRET`
- `GATEWAY_STATE_FILE` if you want a custom state path

## Run

```bash
npm run dev
```

## Build

```bash
npm run build
```

## Notes

- Registered VPN server data and lease state are stored in `.data/gateway-leases.json` by default.
- The gateway no longer uses static `VPN_SERVER_A_URL` / `VPN_SERVER_B_URL` entries. VPN servers register themselves through `/vpn/register`.

# Gateway Server

GSM-VPN의 제어부입니다. 로그인, 서버 선택, 세션 발급, VPN 서버 등록을 담당합니다.

## 역할

- 사용자 로그인
- 초대 코드 검증
- VPN 서버 상태 조회
- 가장 여유 있는 서버 선택
- 클라이언트 피어 등록/해제
- 세션과 lease 정보 저장

## 기술 스택

- Node.js
- TypeScript
- Fastify

## 실행 준비

1. `npm install`
2. `.env.example`을 `.env`로 복사
3. 아래 값을 채우기

필수 항목:

- `AUTH_SECRET`
- `INVITE_CODE`
- `GATEWAY_SHARED_SECRET`
- `VPN_SERVER_A_URL`
- `VPN_SERVER_B_URL`

## 개발 실행

```bash
npm run dev
```

## 빌드

```bash
npm run build
```

## 참고

- lease 상태는 기본적으로 `.data/gateway-leases.json`에 저장됩니다.
- 필요하면 `GATEWAY_STATE_FILE`로 경로를 바꿀 수 있습니다.


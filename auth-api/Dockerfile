# ==============================================================================
# 가상 2FA(안면인증) API 서버 Dockerfile (auth-api/Dockerfile)
#
# [서비스 역할]
# - 안면인증 성공/실패 상태를 시뮬레이션하고 Nginx `auth_request`에 응답하는 컨테이너
# [포트]
# - 컨테이너 내부 3000번 포트 노출 (호스트 3000:3000 매핑)
# ==============================================================================

FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]


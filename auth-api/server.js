/**
 * ==============================================================================
 * 가상 2FA(안면인증) 서버 (auth-api/server.js)
 *
 * [역할]
 * - 사용자의 안면인증 완료 여부를 쿠키(`poc_2fa_user`)로 관리하고 검증합니다.
 * - Nginx의 `/_auth/verify` 서브요청을 받아 인증 완료 시 HTTP 200과 함께
 *   `X-Authenticated-User` 헤더를 반환하며, 미인증 시 HTTP 401을 반환합니다.
 * ==============================================================================
 */

const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 요청 로깅 미들웨어 (컨테이너 로그에서 2FA 상태 추적용)
app.use((req, res, next) => {
  console.log(`[mock-auth-api] ${new Date().toISOString()} | ${req.method} ${req.originalUrl} | cookie_user=${req.cookies?.poc_2fa_user || 'none'}`);
  next();
});

// 1. 컨테이너 헬스체크 엔드포인트
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'mock-auth-api' });
});

// 2. Nginx auth_request 검증 엔드포인트
app.get('/auth/verify', (req, res) => {
  const verifiedUser = req.cookies?.poc_2fa_user;
  if (!verifiedUser) {
    return res.status(401).json({ authenticated: false, message: '2FA 안면인증이 필요합니다.' });
  }
  // 인증된 사용자 ID를 헤더에 담아 Nginx로 전달 -> Nginx가 es-security-runas-user로 변환
  res.setHeader('X-Authenticated-User', verifiedUser);
  return res.status(200).json({ authenticated: true, user: verifiedUser });
});

// 3. 브라우저 테스트용 가상 안면인증 로그인 페이지
app.get('/auth/login-page', (req, res) => {
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8" />
      <title>PoC 2FA 안면인증 시뮬레이터</title>
      <style>
        body { font-family: sans-serif; max-width: 480px; margin: 60px auto; padding: 24px; border: 1px solid #ddd; border-radius: 8px; }
        button { padding: 10px 16px; background: #0055cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
        input { padding: 8px; width: 100%; margin: 8px 0 16px; box-sizing: border-box; }
      </style>
    </head>
    <body>
      <h2>2FA 안면인증 (Mock)</h2>
      <p>안면인증을 완료하면 Nginx가 <code>es-security-runas-user</code> 헤더에 아래 계정을 담아 Kibana로 전달합니다.</p>
      <form method="POST" action="/auth/verify-face">
        <label>대리 로그인할 Elasticsearch 사용자 ID:</label>
        <input type="text" name="username" value="face_user1" required />
        <button type="submit">안면인증 성공 시뮬레이션 및 Kibana 접속</button>
      </form>
    </body>
    </html>
  `);
});

// 4. 가상 안면인증 승인 처리 (쿠키 발급 후 루트(/) 즉 Kibana로 이동)
app.post('/auth/verify-face', (req, res) => {
  const username = req.body.username || 'face_user1';
  res.cookie('poc_2fa_user', username, { httpOnly: true, path: '/' });
  console.log(`[mock-auth-api] 2FA 안면인증 승인 완료: user=${username}`);
  res.redirect('/');
});

// 5. 로그아웃 (2FA 세션 쿠키 삭제)
app.get('/auth/logout', (req, res) => {
  res.clearCookie('poc_2fa_user', { path: '/' });
  res.redirect('/auth/login-page');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[mock-auth-api] 가상 2FA 서버가 포트 ${PORT}에서 실행 중입니다.`);
});


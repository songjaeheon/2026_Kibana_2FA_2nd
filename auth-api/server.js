/**
 * ==============================================================================
 * 가상 2FA(안면인증) 검증 서버 (auth-api/server.js)
 * 구현 기술 스택: Node.js + Express
 *
 * [주요 역할]
 * 1. Nginx의 `auth_request` 모듈이 호출하는 `/auth` 엔드포인트를 제공합니다.
 * 2. 클라이언트가 전달한 `Authorization` 헤더(Bearer, Basic, Raw) 또는 쿠키를 파싱하여
 *    사전 등록된 가상 사용자('admin', 'user_a', 'user_b' 등)인지 검증합니다.
 * 3. 인증 성공 시 HTTP 200과 함께 `X-Authenticated-User: {사용자ID}` 응답 헤더를 반환하고,
 *    실패 시 HTTP 401 Unauthorized를 반환합니다.
 * 4. 모든 요청 인입, 헤더/쿠키 파싱 단계, 검증 결과, 최종 응답 헤더 및 상태 코드에 대해
 *    ISO-8601 타임스탬프가 포함된 디버그(DEBUG) 레벨 상세 로그를 콘솔에 출력합니다.
 * ==============================================================================
 */

const express = require('express');
const cookieParser = require('cookie-parser');

// Express 애플리케이션 인스턴스 생성
const app = express();

// 서버 리스닝 포트 설정 (환경변수 PORT가 없으면 기본값 3000 사용)
const PORT = process.env.PORT || 3000;

// JSON 및 URL-encoded 요청 본문 파싱 미들웨어 등록
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 요청의 Cookie 헤더를 파싱하여 req.cookies 객체로 변환하는 미들웨어 등록
app.use(cookieParser());

/**
 * 사전 정의된 가상 2FA(안면인증) 허용 사용자 목록 및 메타데이터 사전
 * - key: 사용자 ID ('admin', 'user_a', 'user_b' 등)
 * - value: 비밀번호/토큰 검증값, 권한 설명, 안면인증 등록 상태
 */
const VALID_USERS = {
  admin: {
    userId: 'admin',
    secret: 'admin123',
    token: 'token-admin-2fa',
    roleDescription: '전체 시스템 관리자 (Superuser)',
    faceVerified: true,
  },
  user_a: {
    userId: 'user_a',
    secret: 'usera123',
    token: 'token-user-a-2fa',
    roleDescription: '보안 분석가 A (Security Analyst A)',
    faceVerified: true,
  },
  user_b: {
    userId: 'user_b',
    secret: 'userb123',
    token: 'token-user-b-2fa',
    roleDescription: '일반 대시보드 열람자 B (Viewer B)',
    faceVerified: true,
  },
  face_user1: {
    userId: 'face_user1',
    secret: 'changeme123!',
    token: 'token-face-user1-2fa',
    roleDescription: '기본 2FA 테스트 계정',
    faceVerified: true,
  },
};

/**
 * [유틸리티 함수] 타임스탬프와 로그 레벨이 포함된 포맷팅 로그 출력 함수
 * @param {'DEBUG'|'INFO'|'WARN'|'ERROR'} level - 로그 레벨 문자열
 * @param {string} stage - 현재 처리 중인 단계 식별자 (예: 'REQ_IN', 'HEADER_PARSE', 'AUTH_RESULT', 'RES_OUT')
 * @param {string} message - 출력할 메인 로그 메시지
 * @param {object|null} details - 함께 출력할 상세 데이터 객체 (선택 사항)
 */
function logDebug(level, stage, message, details = null) {
  // 현재 시각을 ISO-8601 표준 타임스탬프 문자열로 생성
  const timestamp = new Date().toISOString();
  // 로그 헤더 포맷 구성: [타임스탬프] [레벨] [단계] 메시지
  const logPrefix = `[${timestamp}] [${level.padEnd(5, ' ')}] [${stage.padEnd(14, ' ')}] ${message}`;

  // 상세 객체(details)가 전달된 경우 가독성 좋게 한 줄 JSON 또는 멀티라인으로 함께 출력
  if (details !== null && details !== undefined) {
    console.log(`${logPrefix} | 상세데이터: ${JSON.stringify(details)}`);
  } else {
    console.log(logPrefix);
  }
}

/**
 * [공통 미들웨어] 모든 인입 요청의 메타데이터, 헤더, 쿠키를 디버그 레벨로 로깅
 * @param {express.Request} req - Express 요청 객체
 * @param {express.Response} res - Express 응답 객체
 * @param {express.NextFunction} next - 다음 미들웨어 호출 함수
 */
app.use((req, res, next) => {
  // 요청 처리 소요 시간 측정을 위해 시작 시각 기록
  req._startTime = Date.now();

  // 인입 요청의 주요 정보를 디버그 로그로 출력
  logDebug('DEBUG', 'REQ_IN', '새로운 HTTP 요청이 인입되었습니다.', {
    method: req.method,
    url: req.originalUrl,
    clientIp: req.ip || req.socket?.remoteAddress,
    originalUri: req.headers['x-original-uri'] || '(직접 호출)',
    hasAuthHeader: Boolean(req.headers['authorization']),
    rawAuthHeader: req.headers['authorization'] || null,
    cookies: req.cookies || {},
    userAgent: req.headers['user-agent'] || null,
  });

  // 다음 라우터 또는 미들웨어로 제어권 전달
  next();
});

/**
 * [핵심 파싱 함수] 요청의 Authorization 헤더 또는 쿠키에서 사용자 식별 정보를 추출하는 함수
 *
 * 지원 포맷:
 * 1) Authorization: Bearer <token 또는 userId> (예: "Bearer user_a", "Bearer token-user-a-2fa")
 * 2) Authorization: Basic <base64(userId:password)> (예: "Basic YWRtaW46YWRtaW4xMjM=")
 * 3) Authorization: <userId> (단순 사용자 ID 문자열 직접 전달)
 * 4) Cookie: poc_2fa_user=<userId> 또는 auth_user=<userId>
 * 5) X-2FA-User 헤더: <userId> (테스트 편의용 커스텀 헤더)
 *
 * @param {express.Request} req - Express 요청 객체
 * @returns {{ source: string, extractedUser: string|null, extractedSecret: string|null, rawValue: string|null }}
 */
function extractCredentialsFromRequest(req) {
  // 요청 헤더에서 authorization 값을 추출 (대소문자 무관하게 Express가 소문자로 정규화함)
  const authHeader = req.headers['authorization'];
  // 테스트 편의를 위한 커스텀 헤더(x-2fa-user) 확인
  const customUserHeader = req.headers['x-2fa-user'];
  // 요청 쿠키에서 사용자 식별 쿠키(poc_2fa_user 또는 auth_user) 확인
  const cookieUser = req.cookies?.poc_2fa_user || req.cookies?.auth_user;

  logDebug('DEBUG', 'HEADER_PARSE', '인증 정보 추출을 시작합니다.', {
    authorizationHeader: authHeader || '(없음)',
    x2faUserHeader: customUserHeader || '(없음)',
    cookieUser: cookieUser || '(없음)',
  });

  // 1순위: Authorization 헤더가 존재하는 경우 파싱 수행
  if (authHeader && typeof authHeader === 'string') {
    const trimmedHeader = authHeader.trim();

    // 1-A: "Basic <base64>" 포맷인 경우 Base64 디코딩 후 "사용자ID:비밀번호" 분리
    if (trimmedHeader.toLowerCase().startsWith('basic ')) {
      const base64Credentials = trimmedHeader.slice(6).trim();
      logDebug('DEBUG', 'HEADER_PARSE', 'Authorization Basic 헤더 감지 - Base64 디코딩을 시도합니다.', {
        base64Credentials,
      });

      try {
        // Base64 문자열을 UTF-8 평문으로 디코딩
        const decoded = Buffer.from(base64Credentials, 'base64').toString('utf-8');
        // 첫 번째 콜론(:)을 기준으로 사용자 ID와 비밀번호 분리
        const colonIndex = decoded.indexOf(':');
        const extractedUser = colonIndex !== -1 ? decoded.slice(0, colonIndex) : decoded;
        const extractedSecret = colonIndex !== -1 ? decoded.slice(colonIndex + 1) : '';

        logDebug('DEBUG', 'HEADER_PARSE', 'Basic 헤더 디코딩 완료', {
          extractedUser,
          hasSecret: Boolean(extractedSecret),
        });

        return {
          source: 'Authorization (Basic)',
          extractedUser,
          extractedSecret,
          rawValue: trimmedHeader,
        };
      } catch (err) {
        logDebug('WARN', 'HEADER_PARSE', 'Basic 헤더 Base64 디코딩 실패', { error: err.message });
        return { source: 'Authorization (Basic - Invalid)', extractedUser: null, extractedSecret: null, rawValue: trimmedHeader };
      }
    }

    // 1-B: "Bearer <token 또는 userId>" 포맷인 경우 토큰 값 추출
    if (trimmedHeader.toLowerCase().startsWith('bearer ')) {
      const bearerToken = trimmedHeader.slice(7).trim();
      logDebug('DEBUG', 'HEADER_PARSE', 'Authorization Bearer 헤더 감지 - 토큰/사용자 매핑을 확인합니다.', {
        bearerToken,
      });

      // 토큰 문자열이 사전 정의된 토큰(예: token-user-a-2fa)과 일치하는지 먼저 검색
      const matchedByToken = Object.values(VALID_USERS).find((u) => u.token === bearerToken);
      const resolvedUser = matchedByToken ? matchedByToken.userId : bearerToken;

      logDebug('DEBUG', 'HEADER_PARSE', 'Bearer 토큰 파싱 완료', {
        bearerToken,
        resolvedUser,
        matchedByTokenPreset: Boolean(matchedByToken),
      });

      return {
        source: 'Authorization (Bearer)',
        extractedUser: resolvedUser,
        extractedSecret: bearerToken,
        rawValue: trimmedHeader,
      };
    }

    // 1-C: 접두사 없이 사용자 ID가 Authorization 헤더에 직접 들어온 경우 (예: "Authorization: user_a")
    logDebug('DEBUG', 'HEADER_PARSE', 'Authorization 단일 문자열 헤더 감지', {
      extractedUser: trimmedHeader,
    });
    return {
      source: 'Authorization (Raw)',
      extractedUser: trimmedHeader,
      extractedSecret: null,
      rawValue: trimmedHeader,
    };
  }

  // 2순위: X-2FA-User 커스텀 헤더가 존재하는 경우
  if (customUserHeader && typeof customUserHeader === 'string') {
    const trimmedCustom = customUserHeader.trim();
    logDebug('DEBUG', 'HEADER_PARSE', 'X-2FA-User 커스텀 헤더에서 사용자 ID를 추출했습니다.', {
      extractedUser: trimmedCustom,
    });
    return {
      source: 'Header (X-2FA-User)',
      extractedUser: trimmedCustom,
      extractedSecret: null,
      rawValue: trimmedCustom,
    };
  }

  // 3순위: 브라우저 쿠키(poc_2fa_user 또는 auth_user)가 존재하는 경우
  if (cookieUser && typeof cookieUser === 'string') {
    const trimmedCookie = cookieUser.trim();
    logDebug('DEBUG', 'HEADER_PARSE', 'Cookie에서 2FA 사용자 ID를 추출했습니다.', {
      extractedUser: trimmedCookie,
    });
    return {
      source: 'Cookie (poc_2fa_user/auth_user)',
      extractedUser: trimmedCookie,
      extractedSecret: null,
      rawValue: trimmedCookie,
    };
  }

  // 어떠한 인증 수단도 발견되지 않은 경우
  logDebug('WARN', 'HEADER_PARSE', '요청에 Authorization 헤더나 2FA 인증 쿠키가 존재하지 않습니다.');
  return {
    source: 'NONE',
    extractedUser: null,
    extractedSecret: null,
    rawValue: null,
  };
}

/**
 * [핵심 검증 함수] 추출된 사용자 정보가 허용된 가상 사용자('admin', 'user_a', 'user_b' 등)인지 검증하는 함수
 *
 * @param {{ source: string, extractedUser: string|null, extractedSecret: string|null }} cred - 파싱된 인증 정보
 * @returns {{ isValid: boolean, userRecord: object|null, reason: string }}
 */
function verifyVirtualUser(cred) {
  // 추출된 사용자 ID가 없으면 즉시 인증 실패 처리
  if (!cred.extractedUser) {
    return {
      isValid: false,
      userRecord: null,
      reason: '인증 헤더(Authorization) 또는 쿠키에서 사용자 ID를 찾을 수 없습니다.',
    };
  }

  // 허용된 가상 사용자 목록(VALID_USERS)에 해당 사용자 ID가 존재하는지 조회
  const userRecord = VALID_USERS[cred.extractedUser];
  if (!userRecord) {
    return {
      isValid: false,
      userRecord: null,
      reason: `등록되지 않은 가상 사용자입니다: '${cred.extractedUser}' (허용 목록: ${Object.keys(VALID_USERS).join(', ')})`,
    };
  }

  // Basic 인증으로 비밀번호까지 전달된 경우, 비밀번호 일치 여부 확인 (단, 비밀번호가 비어있지 않을 때만 검증)
  if (cred.source === 'Authorization (Basic)' && cred.extractedSecret) {
    if (cred.extractedSecret !== userRecord.secret) {
      return {
        isValid: false,
        userRecord: null,
        reason: `사용자 '${cred.extractedUser}'의 Basic 인증 비밀번호가 일치하지 않습니다.`,
      };
    }
  }

  // 안면인증(2FA) 활성화 상태 확인
  if (!userRecord.faceVerified) {
    return {
      isValid: false,
      userRecord: null,
      reason: `사용자 '${cred.extractedUser}'의 2FA 안면인증 상태가 비활성화되어 있습니다.`,
    };
  }

  // 모든 검증 통과
  return {
    isValid: true,
    userRecord,
    reason: `가상 사용자 '${userRecord.userId}' (${userRecord.roleDescription}) 2FA 인증 검증 성공`,
  };
}

/**
 * [핵심 핸들러 함수] Nginx `auth_request`가 호출하는 2FA 인증 검증 핸들러
 * - `/auth` 및 하위 호환 경로 `/auth/verify` 모두에서 이 함수를 실행합니다.
 * - 인증 성공 시: HTTP 200 OK + `X-Authenticated-User: {사용자ID}` 헤더 반환
 * - 인증 실패 시: HTTP 401 Unauthorized 반환
 *
 * @param {express.Request} req - Express 요청 객체
 * @param {express.Response} res - Express 응답 객체
 */
function handleAuthRequest(req, res) {
  // 1단계: 요청 헤더 및 쿠키에서 사용자 인증 정보 파싱
  const credentials = extractCredentialsFromRequest(req);

  // 2단계: 추출된 사용자가 'admin', 'user_a', 'user_b' 등 유효한 가상 사용자인지 검증
  const verification = verifyVirtualUser(credentials);

  // 요청 처리 소요 시간(ms) 계산
  const elapsedMs = Date.now() - (req._startTime || Date.now());

  // 3단계: 검증 결과에 따른 분기 처리 및 응답 반환
  if (verification.isValid && verification.userRecord) {
    const authenticatedUserId = verification.userRecord.userId;

    // [요구사항 3] 인증 성공 시 응답 헤더에 `X-Authenticated-User: {사용자ID}` 설정
    res.setHeader('X-Authenticated-User', authenticatedUserId);

    // 인증 성공 상세 로그 출력
    logDebug('INFO', 'AUTH_SUCCESS', '2FA 사용자 인증에 성공했습니다.', {
      authenticatedUser: authenticatedUserId,
      authSource: credentials.source,
      roleDescription: verification.userRecord.roleDescription,
    });

    // 구성할 응답 본문 객체 생성
    const responseBody = {
      authenticated: true,
      user: authenticatedUserId,
      role: verification.userRecord.roleDescription,
      source: credentials.source,
      timestamp: new Date().toISOString(),
    };

    // 반환하는 응답 상태 코드, 응답 헤더, 응답 본문을 디버그 레벨로 상세 로깅
    logDebug('DEBUG', 'RES_OUT', '클라이언트(Nginx)로 HTTP 200 성공 응답을 반환합니다.', {
      statusCode: 200,
      responseHeaders: {
        'X-Authenticated-User': authenticatedUserId,
        'Content-Type': 'application/json',
      },
      responseBody,
      elapsedMs: `${elapsedMs}ms`,
    });

    // HTTP 200 상태 코드와 JSON 본문 반환
    return res.status(200).json(responseBody);
  }

  // 인증 실패 시 상세 로그 출력
  logDebug('WARN', 'AUTH_FAILURE', '2FA 사용자 인증에 실패했습니다.', {
    attemptedUser: credentials.extractedUser,
    authSource: credentials.source,
    reason: verification.reason,
  });

  // 실패 응답 본문 구성
  const errorResponseBody = {
    authenticated: false,
    error: 'Unauthorized',
    message: verification.reason,
    allowedUsers: Object.keys(VALID_USERS),
    timestamp: new Date().toISOString(),
  };

  // 반환하는 실패 응답(HTTP 401) 정보를 디버그 레벨로 상세 로깅
  logDebug('DEBUG', 'RES_OUT', '클라이언트(Nginx)로 HTTP 401 실패 응답을 반환합니다.', {
    statusCode: 401,
    responseHeaders: {
      'Content-Type': 'application/json',
    },
    responseBody: errorResponseBody,
    elapsedMs: `${elapsedMs}ms`,
  });

  // [요구사항 3] 인증 실패 시 HTTP 401 상태 코드 반환
  return res.status(401).json(errorResponseBody);
}

// ==============================================================================
// 라우트(Endpoint) 정의 영역
// ==============================================================================

/**
 * [요구사항 1] Nginx의 `auth_request`에서 호출할 메인 `/auth` 엔드포인트
 * - GET 및 POST 메서드를 모두 허용하여 Nginx 서브요청 및 직접 API 호출 테스트를 지원합니다.
 */
app.all('/auth', handleAuthRequest);

/**
 * 기존 설정과의 하위 호환성을 위한 `/auth/verify` 별칭(Alias) 엔드포인트
 */
app.all('/auth/verify', handleAuthRequest);

/**
 * 컨테이너 상태 확인(Healthcheck)을 위한 `/health` 엔드포인트
 */
app.get('/health', (req, res) => {
  const healthPayload = {
    status: 'ok',
    service: 'mock-auth-api',
    registeredUsers: Object.keys(VALID_USERS),
    timestamp: new Date().toISOString(),
  };

  logDebug('DEBUG', 'RES_OUT', '헬스체크 응답 반환', {
    statusCode: 200,
    responseBody: healthPayload,
  });

  res.status(200).json(healthPayload);
});

/**
 * 브라우저 기반 PoC 시연용 가상 2FA(안면인증) 로그인 화면 (`/auth/login-page`)
 * - 'admin', 'user_a', 'user_b' 중 원하는 계정을 선택하여 즉시 안면인증 완료 쿠키를 발급받을 수 있습니다.
 */
app.get('/auth/login-page', (req, res) => {
  logDebug('INFO', 'LOGIN_PAGE', '가상 2FA 안면인증 선택 페이지를 렌더링합니다.');

  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8" />
      <title>PoC 2FA 안면인증 시뮬레이터</title>
      <style>
        body { font-family: 'Malgun Gothic', sans-serif; max-width: 540px; margin: 50px auto; padding: 28px; border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }
        h2 { margin-top: 0; color: #1f2328; }
        label { font-weight: bold; display: block; margin-top: 14px; }
        select, button { width: 100%; padding: 10px 12px; margin-top: 8px; font-size: 15px; border-radius: 6px; box-sizing: border-box; }
        select { border: 1px solid #ccc; }
        button { background: #0969da; color: #fff; border: none; cursor: pointer; margin-top: 20px; font-weight: bold; }
        button:hover { background: #0550ae; }
        .hint { background: #f6f8fa; padding: 12px; border-radius: 6px; font-size: 13px; margin-top: 18px; line-height: 1.5; }
        code { background: #eaeef2; padding: 2px 5px; border-radius: 4px; }
      </style>
    </head>
    <body>
      <h2>2FA 안면인증 시뮬레이터 (mock-auth-api)</h2>
      <p>안면인증을 통과할 가상 사용자를 선택하면 <code>X-Authenticated-User</code> 헤더를 통해 Nginx가 Elasticsearch <code>run_as</code> 헤더를 주입합니다.</p>
      <form method="POST" action="/auth/verify-face">
        <label for="username">대리 로그인할 가상 사용자 선택:</label>
        <select name="username" id="username">
          <option value="admin">admin (전체 관리자 - Superuser)</option>
          <option value="user_a">user_a (보안 분석가 A)</option>
          <option value="user_b">user_b (대시보드 열람자 B)</option>
          <option value="face_user1">face_user1 (기본 테스트 계정)</option>
        </select>
        <button type="submit">안면인증 성공 시뮬레이션 및 Kibana 접속</button>
      </form>
      <div class="hint">
        <strong>CLI / cURL 직접 검증 예시:</strong><br/>
        <code>curl -i -H "Authorization: Bearer admin" http://localhost:3000/auth</code><br/>
        <code>curl -i -H "Authorization: Bearer user_a" http://localhost:3000/auth</code><br/>
        <code>curl -i -u user_b:userb123 http://localhost:3000/auth</code>
      </div>
    </body>
    </html>
  `);
});

/**
 * 브라우저 폼 제출 시 선택한 가상 사용자 쿠키(`poc_2fa_user`)를 발급하고 Kibana 메인(`/`)으로 리다이렉트
 */
app.post('/auth/verify-face', (req, res) => {
  // 폼 데이터에서 선택된 사용자 ID 추출 (기본값: 'admin')
  const selectedUser = (req.body.username || 'admin').trim();

  // 등록된 가상 사용자인지 확인
  if (!VALID_USERS[selectedUser]) {
    logDebug('WARN', 'FACE_VERIFY', '유효하지 않은 사용자 선택 시도', { selectedUser });
    return res.status(401).json({
      authenticated: false,
      message: `허용되지 않은 사용자입니다: ${selectedUser}`,
    });
  }

  // 브라우저에 2FA 인증 완료 쿠키 설정
  res.cookie('poc_2fa_user', selectedUser, { httpOnly: true, path: '/' });

  logDebug('INFO', 'FACE_VERIFY', '가상 안면인증 완료 - 쿠키 발급 후 Kibana(/)로 리다이렉트합니다.', {
    selectedUser,
    cookieSet: `poc_2fa_user=${selectedUser}`,
    redirectTo: '/',
  });

  // Nginx 루트(Kibana 프록시)로 리다이렉트
  return res.redirect('/');
});

/**
 * 2FA 인증 세션(쿠키) 초기화 및 로그아웃 처리 엔드포인트
 */
app.get('/auth/logout', (req, res) => {
  const prevUser = req.cookies?.poc_2fa_user || '(없음)';
  // 쿠키 제거
  res.clearCookie('poc_2fa_user', { path: '/' });
  res.clearCookie('auth_user', { path: '/' });

  logDebug('INFO', 'LOGOUT', '사용자 2FA 인증 쿠키를 삭제하고 로그인 페이지로 이동합니다.', {
    previousUser: prevUser,
  });

  return res.redirect('/auth/login-page');
});

// ==============================================================================
// 서버 기동
// ==============================================================================
app.listen(PORT, '0.0.0.0', () => {
  logDebug('INFO', 'SERVER_START', `가상 2FA 인증 서버(mock-auth-api)가 포트 ${PORT}에서 시작되었습니다.`, {
    port: PORT,
    endpoints: ['/auth', '/auth/verify', '/auth/login-page', '/auth/verify-face', '/auth/logout', '/health'],
    allowedUsers: Object.keys(VALID_USERS),
  });
});

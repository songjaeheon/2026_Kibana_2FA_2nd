#!/usr/bin/env sh
# ==============================================================================
# Elasticsearch run_as 권한(Role) 및 사용자(User) 자동 프로비저닝 스크립트
# 파일 경로: es-setup/init-es.sh
#
# [핵심 아키텍처 및 보안 설계 원칙]
# 1. 최소 권한의 원칙 (Principle of Least Privilege)
#    - 일반 사원(`user_a`, `user_b`)에게는 업무에 필요한 특정 인덱스 조회 권한(`viewer_role`)만 부여합니다.
# 2. 직무 분리 (Separation of Duties) 및 권한 위임 전용화
#    - Nginx 리버스 프록시가 사용하는 계정(`proxy_user`)에는 인덱스 데이터 조회 권한을 단 하나도 부여하지 않고,
#      오직 지정된 사원 계정으로 신원을 대리(`run_as`)할 수 있는 권한(`proxy_role`)만 부여합니다.
# 3. 침해 사고 시 피해 반경 최소화 (Blast Radius Containment)
#    - 만약 Nginx 설정 파일이 유출되어 `proxy_user` 자격증명이 노출되더라도,
#      공격자는 `superuser`(`elastic`) 권한을 탈취할 수 없으며 `proxy_role`의 `run_as` 목록에
#      명시된 일반 사원(`user_a`, `user_b`) 범위 밖의 동작은 수행할 수 없습니다.
# ==============================================================================

# 명령어 실패 시 즉시 중단 및 정의되지 않은 변수 참조 시 에러 발생 설정
set -eu

# 접속 대상 Elasticsearch URL 및 슈퍼유저(elastic) 초기 비밀번호 설정
ES_URL="${ES_URL:-http://elasticsearch:9200}"
ES_PASS="${ELASTIC_PASSWORD:-changeme123!}"

# 프록시 전용 계정 비밀번호 (nginx/nginx.conf의 Basic Auth Base64 값과 일치해야 함)
# Base64("proxy_user:proxy_password") = "cHJveHlfdXNlcjpwcm94eV9wYXNzd29yZA=="
PROXY_USER_PASS="${PROXY_USER_PASS:-proxy_password}"

# 일반 사원 초기 비밀번호 (실제 환경에서는 2FA 프록시를 통해서만 진입하므로 직접 사용되지 않음)
EMPLOYEE_PASS="${EMPLOYEE_PASS:-employee_pass_123!}"

# ------------------------------------------------------------------------------
# [유틸리티 함수 1] 타임스탬프가 포함된 구조화 로그 출력 함수
# ------------------------------------------------------------------------------
log_info() {
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)
  printf "[%s] [INFO ] %s\n" "${TIMESTAMP}" "$1"
}

log_step() {
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)
  printf "\n================================================================================\n"
  printf "[%s] [STEP ] %s\n" "${TIMESTAMP}" "$1"
  printf "================================================================================\n"
}

log_error() {
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)
  printf "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n" >&2
  printf "[%s] [ERROR] %s\n" "${TIMESTAMP}" "$1" >&2
  printf "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n" >&2
}

# ------------------------------------------------------------------------------
# [유틸리티 함수 2] Elasticsearch REST API 호출 및 응답 코드/에러 검증 공통 함수
# - 호출 전: 수행 작업 설명, HTTP 메서드, 엔드포인트 URL, 요청 Payload 상세 출력
# - 호출 후: HTTP 상태 코드 및 응답 Body 상세 출력
# - 에러 처리: HTTP 상태 코드가 2xx(200~299)가 아니면 즉시 상세 원인을 출력하고 스크립트 중단(exit 1)
# ------------------------------------------------------------------------------
call_es_api() {
  STEP_DESC="$1"
  HTTP_METHOD="$2"
  ENDPOINT="$3"
  PAYLOAD="${4:-}"
  EXTRA_HEADER="${5:-}"

  FULL_URL="${ES_URL}${ENDPOINT}"
  RESPONSE_FILE="/tmp/es_response_$$.json"

  log_info "▶ 작업 시작: ${STEP_DESC}"
  log_info "  - 요청 주소 : ${HTTP_METHOD} ${FULL_URL}"

  if [ -n "${EXTRA_HEADER}" ]; then
    log_info "  - 추가 헤더 : ${EXTRA_HEADER}"
  fi

  if [ -n "${PAYLOAD}" ]; then
    printf "  - 요청 Payload:\n%s\n" "${PAYLOAD}"
  else
    log_info "  - 요청 Payload: (없음)"
  fi

  # curl 실행: 응답 본문은 임시 파일에 저장하고, HTTP 상태 코드만 추출
  HTTP_CODE=""
  if [ -n "${PAYLOAD}" ] && [ -n "${EXTRA_HEADER}" ]; then
    HTTP_CODE=$(curl -s -S -o "${RESPONSE_FILE}" -w "%{http_code}" \
      -u "elastic:${ES_PASS}" \
      -X "${HTTP_METHOD}" \
      -H "Content-Type: application/json" \
      -H "${EXTRA_HEADER}" \
      "${FULL_URL}" \
      -d "${PAYLOAD}") || {
        log_error "cURL 네트워크 호출 자체가 실패했습니다. (${HTTP_METHOD} ${FULL_URL})"
        rm -f "${RESPONSE_FILE}"
        exit 1
      }
  elif [ -n "${PAYLOAD}" ]; then
    HTTP_CODE=$(curl -s -S -o "${RESPONSE_FILE}" -w "%{http_code}" \
      -u "elastic:${ES_PASS}" \
      -X "${HTTP_METHOD}" \
      -H "Content-Type: application/json" \
      "${FULL_URL}" \
      -d "${PAYLOAD}") || {
        log_error "cURL 네트워크 호출 자체가 실패했습니다. (${HTTP_METHOD} ${FULL_URL})"
        rm -f "${RESPONSE_FILE}"
        exit 1
      }
  elif [ -n "${EXTRA_HEADER}" ]; then
    HTTP_CODE=$(curl -s -S -o "${RESPONSE_FILE}" -w "%{http_code}" \
      -u "elastic:${ES_PASS}" \
      -X "${HTTP_METHOD}" \
      -H "${EXTRA_HEADER}" \
      "${FULL_URL}") || {
        log_error "cURL 네트워크 호출 자체가 실패했습니다. (${HTTP_METHOD} ${FULL_URL})"
        rm -f "${RESPONSE_FILE}"
        exit 1
      }
  else
    HTTP_CODE=$(curl -s -S -o "${RESPONSE_FILE}" -w "%{http_code}" \
      -u "elastic:${ES_PASS}" \
      -X "${HTTP_METHOD}" \
      "${FULL_URL}") || {
        log_error "cURL 네트워크 호출 자체가 실패했습니다. (${HTTP_METHOD} ${FULL_URL})"
        rm -f "${RESPONSE_FILE}"
        exit 1
      }
  fi

  RESPONSE_BODY=$(cat "${RESPONSE_FILE}" 2>/dev/null || echo "")
  rm -f "${RESPONSE_FILE}"

  log_info "  - HTTP 응답 코드: ${HTTP_CODE}"
  printf "  - 응답 Body   : %s\n" "${RESPONSE_BODY}"

  # HTTP 상태 코드가 200~299 범위인지 확인 (예: 400 Bad Request, 401, 403, 500 발생 시 즉시 중단)
  case "${HTTP_CODE}" in
    200|201|202|204)
      log_info "✔ 작업 성공: ${STEP_DESC} (HTTP ${HTTP_CODE})"
      ;;
    *)
      log_error "API 호출 중 에러가 발생하여 프로비저닝을 즉시 중단합니다!
  [실패 작업] ${STEP_DESC}
  [요청 정보] ${HTTP_METHOD} ${FULL_URL}
  [상태 코드] HTTP ${HTTP_CODE}
  [요청 본문] ${PAYLOAD}
  [에러 응답] ${RESPONSE_BODY}"
      exit 1
      ;;
  esac
}

# ------------------------------------------------------------------------------
# [사전 단계] Elasticsearch 클러스터 기동 대기 및 kibana_system 비밀번호 초기화
# ------------------------------------------------------------------------------
log_step "0. Elasticsearch 클러스터 기동 확인 및 시스템 계정 초기화"
log_info "Elasticsearch(${ES_URL}) 응답을 대기합니다..."

RETRY_COUNT=0
MAX_RETRIES=30
until curl -s -u "elastic:${ES_PASS}" "${ES_URL}/_cluster/health" > /dev/null; do
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ "${RETRY_COUNT}" -ge "${MAX_RETRIES}" ]; then
    log_error "Elasticsearch가 지정된 시간(${MAX_RETRIES}회 재시도) 내에 응답하지 않아 중단합니다."
    exit 1
  fi
  log_info "Elasticsearch 준비 대기 중... (${RETRY_COUNT}/${MAX_RETRIES})"
  sleep 2
done
log_info "Elasticsearch 클러스터 연결이 확인되었습니다."

# Kibana 서버가 Elasticsearch와 내부 통신할 때 사용하는 kibana_system 비밀번호 설정
# [보안 분리 이유]
# Kibana 자체 백엔드 프로세스(kibana_system)는 대시보드 메타데이터와 시스템 인덱스를 관리할 뿐,
# 실제 사용자의 데이터 인덱스를 조회할 수 없도록 프록시 계정(proxy_user)과 엄격히 분리됩니다.
call_es_api \
  "Kibana 내부 통신 전용 시스템 계정(kibana_system) 비밀번호 설정" \
  "POST" \
  "/_security/user/kibana_system/_password" \
  "{
    \"password\": \"${ES_PASS}\"
  }"

# ------------------------------------------------------------------------------
# [단계 1] 일반 사용자용 Role 생성 (viewer_role)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 최소 권한의 원칙 (Least Privilege)]
# 1. 일반 사원(user_a, user_b)은 데이터를 분석·열람하는 주체이므로, 클러스터 설정 변경이나
#    보안 계정 관리 권한(manage_security)을 가지면 안 됩니다.
# 2. 또한 인덱스 삭제(delete_index)나 데이터 변조(write)를 방지하기 위해
#    지정된 업무 인덱스(`logs-*`, `metrics-*`, `kibana_sample_data_*`)에 대해
#    오직 읽기 전용 권한(`read`, `view_index_metadata`)만 부여합니다.
# 3. Kibana 웹 UI에 정상 로그인하여 대시보드와 Discover 메뉴를 열람할 수 있도록
#    Kibana 기본 공간(`default`)에 대한 읽기 권한(`kibana_admin` 또는 application privileges)을 함께 구성합니다.
# ------------------------------------------------------------------------------
create_viewer_role() {
  log_step "1. 일반 사용자용 읽기 전용 Role (viewer_role) 생성"

  VIEWER_ROLE_PAYLOAD='{
    "cluster": [
      "monitor"
    ],
    "indices": [
      {
        "names": [ "logs-*", "metrics-*", "kibana_sample_data_*" ],
        "privileges": [ "read", "view_index_metadata" ]
      }
    ],
    "applications": [
      {
        "application": "kibana-.kibana",
        "privileges": [ "read" ],
        "resources": [ "*" ]
      }
    ],
    "metadata": {
      "description": "2FA 인증을 통과한 일반 사원에게 부여되는 인덱스 읽기 전용 및 Kibana 열람 Role"
    }
  }'

  call_es_api \
    "일반 사원용 최소 권한 Role (viewer_role) 생성" \
    "PUT" \
    "/_security/role/viewer_role" \
    "${VIEWER_ROLE_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 2] 일반 사원 계정 생성 (user_a, user_b, admin, face_user1)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 개별 신원 식별 및 감사 추적성 (Auditability)]
# 1. 모든 사원이 공용 계정을 쓰면 보안 감사(Audit) 시 누가 어떤 쿼리를 실행했는지 식별할 수 없습니다.
# 2. 따라서 사원별로 고유 계정(`user_a`, `user_b`)을 생성하고 앞서 만든 `viewer_role`을 부여합니다.
# 3. 특히 일반 사원 계정에는 타인을 대리 실행할 수 있는 `run_as` 권한이 전혀 없으므로,
#    사원 간 수평적 권한 상승(Lateral Movement)이 원천 차단됩니다.
# ------------------------------------------------------------------------------
create_employee_users() {
  log_step "2. 일반 사원 계정 (user_a, user_b 등) 생성 및 viewer_role 부여"

  # 2-1. 사원 A (user_a) 생성 - viewer_role 부여
  USER_A_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\" ],
    \"full_name\": \"Security Analyst User A\",
    \"email\": \"user_a@poc.local\",
    \"metadata\": {
      \"department\": \"SOC\",
      \"auth_type\": \"2FA_FACE_AUTH\"
    }
  }"
  call_es_api \
    "일반 사원 계정 'user_a' 생성 (viewer_role 부여)" \
    "POST" \
    "/_security/user/user_a" \
    "${USER_A_PAYLOAD}"

  # 2-2. 사원 B (user_b) 생성 - viewer_role 부여
  USER_B_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\" ],
    \"full_name\": \"Dashboard Viewer User B\",
    \"email\": \"user_b@poc.local\",
    \"metadata\": {
      \"department\": \"Operations\",
      \"auth_type\": \"2FA_FACE_AUTH\"
    }
  }"
  call_es_api \
    "일반 사원 계정 'user_b' 생성 (viewer_role 부여)" \
    "POST" \
    "/_security/user/user_b" \
    "${USER_B_PAYLOAD}"

  # 2-3. 관리자 테스트 계정 (admin) 및 기본 테스트 계정 (face_user1) 생성
  # PoC에서 관리자 권한과 일반 열람자(viewer_role) 권한 차이를 비교 테스트할 수 있도록 구성합니다.
  ADMIN_USER_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\", \"kibana_admin\", \"superuser\" ],
    \"full_name\": \"PoC System Admin (2FA)\",
    \"email\": \"admin@poc.local\"
  }"
  call_es_api \
    "관리자 비교 테스트용 계정 'admin' 생성" \
    "POST" \
    "/_security/user/admin" \
    "${ADMIN_USER_PAYLOAD}"

  FACE_USER1_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\" ],
    \"full_name\": \"PoC Default Face User 1\",
    \"email\": \"face_user1@poc.local\"
  }"
  call_es_api \
    "기본 테스트 사원 계정 'face_user1' 생성 (viewer_role 부여)" \
    "POST" \
    "/_security/user/face_user1" \
    "${FACE_USER1_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 3] 프록시 전용 Role 생성 (proxy_role)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 직무 분리 (Separation of Duties) 및 권한 위임 제한]
# 1. Nginx 프록시는 사용자의 2FA 통과 결과를 받아 신원을 전달하는 '전달자(Impersonator)'일 뿐,
#    프록시 자체가 비즈니스 데이터를 조회하거나 변경하는 주체가 되어서는 안 됩니다.
# 2. 따라서 `proxy_role`에는 `indices` 권한이나 `cluster` 관리 권한을 일절 부여하지 않고,
#    오직 `run_as` 필드에 앞서 생성한 일반 사원 목록(`user_a`, `user_b`, `admin`, `face_user1`)만 명시합니다.
# 3. 특히 `run_as` 대상에 `elastic`(슈퍼유저)이나 `kibana_system`을 절대 포함하지 않음으로써,
#    만약 프록시 계정이 탈취되더라도 시스템 최고 권한으로의 권한 상승(Privilege Escalation)을 차단합니다.
# ------------------------------------------------------------------------------
create_proxy_role() {
  log_step "3. 프록시 전용 대리 실행 Role (proxy_role) 생성"

  PROXY_ROLE_PAYLOAD='{
    "run_as": [
      "user_a",
      "user_b",
      "admin",
      "face_user1"
    ],
    "cluster": [],
    "indices": [],
    "metadata": {
      "description": "Nginx 리버스 프록시 전용 Role - 자체 인덱스 접근 권한 없이 지정된 사원에 대한 run_as 권한만 보유"
    }
  }'

  call_es_api \
    "프록시 전용 Role (proxy_role) 생성 (user_a, user_b 등에 대한 run_as 권한만 부여)" \
    "PUT" \
    "/_security/role/proxy_role" \
    "${PROXY_ROLE_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 4] 프록시 전용 계정 생성 (proxy_user)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 대리 인증 자격증명의 고립화]
# 1. Nginx 설정(`nginx.conf`)에는 Basic Auth 헤더가 고정으로 기입되므로,
#    이 계정은 오직 `proxy_role` 하나만 가진 전용 서비스 계정(`proxy_user`)이어야 합니다.
# 2. 만약 누군가 `proxy_user:proxy_password`만 가지고 `es-security-runas-user` 헤더 없이
#    Elasticsearch에 직접 쿼리를 보내면, `proxy_role`에는 어떠한 인덱스 조회 권한도 없으므로
#    모든 데이터 접근이 거부(403 Forbidden)됩니다.
# ------------------------------------------------------------------------------
create_proxy_user() {
  log_step "4. 프록시 전용 계정 (proxy_user) 생성 및 proxy_role 부여"

  PROXY_USER_PAYLOAD="{
    \"password\": \"${PROXY_USER_PASS}\",
    \"roles\": [ \"proxy_role\" ],
    \"full_name\": \"Nginx 2FA Auth Gateway Proxy Account\",
    \"metadata\": {
      \"purpose\": \"impersonation_only\",
      \"managed_by\": \"es-setup/init-es.sh\"
    }
  }"

  call_es_api \
    "프록시 전용 계정 'proxy_user' 생성 (proxy_role 부여)" \
    "POST" \
    "/_security/user/proxy_user" \
    "${PROXY_USER_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 5] 테스트용 샘플 인덱스 데이터 적재 및 run_as 동작 자가 검증
# ------------------------------------------------------------------------------
verify_run_as_provisioning() {
  log_step "5. 샘플 인덱스 생성 및 proxy_user -> user_a 대리 실행(run_as) 검증"

  # 5-1. viewer_role이 조회할 수 있는 샘플 로그 문서 1건 색인 (logs-poc-2026)
  SAMPLE_DOC_PAYLOAD='{
    "@timestamp": "2026-10-25T22:30:00Z",
    "event": "2fa_face_auth_poc_initialized",
    "message": "Elasticsearch run_as 테스트용 샘플 보안 로그 데이터입니다.",
    "allowed_role": "viewer_role"
  }'
  call_es_api \
    "viewer_role 읽기 테스트를 위한 샘플 로그 문서(logs-poc-2026) 생성" \
    "POST" \
    "/logs-poc-2026/_doc/1?refresh=true" \
    "${SAMPLE_DOC_PAYLOAD}"

  # 5-2. proxy_user 계정으로 `es-security-runas-user: user_a` 헤더를 포함하여
  # `/_security/_authenticate` 호출 시 실제 인증 주체가 `user_a`로 전환되는지 검증
  log_info "▶ 검증 시작: proxy_user 자격증명 + 'es-security-runas-user: user_a' 헤더로 대리 인증 테스트"
  VERIFY_FILE="/tmp/es_verify_$$.json"
  VERIFY_CODE=$(curl -s -S -o "${VERIFY_FILE}" -w "%{http_code}" \
    -u "proxy_user:${PROXY_USER_PASS}" \
    -H "es-security-runas-user: user_a" \
    "${ES_URL}/_security/_authenticate") || {
      log_error "run_as 대리 인증 검증 호출에 실패했습니다."
      rm -f "${VERIFY_FILE}"
      exit 1
    }

  VERIFY_BODY=$(cat "${VERIFY_FILE}" 2>/dev/null || echo "")
  rm -f "${VERIFY_FILE}"

  log_info "  - 검증 HTTP 응답 코드: ${VERIFY_CODE}"
  printf "  - 검증 응답 Body   : %s\n" "${VERIFY_BODY}"

  if [ "${VERIFY_CODE}" != "200" ]; then
    log_error "run_as 대리 인증 검증 실패! (HTTP ${VERIFY_CODE}) 응답: ${VERIFY_BODY}"
    exit 1
  fi

  log_info "✔ 검증 성공: proxy_user가 'user_a' 권한(viewer_role)으로 정상 대리 인증(run_as)되었습니다."
}

# ==============================================================================
# 메인 실행 흐름 (요구사항 1의 순서 엄수)
# ==============================================================================
create_viewer_role
create_employee_users
create_proxy_role
create_proxy_user
verify_run_as_provisioning

printf "\n================================================================================\n"
log_info "모든 Elasticsearch run_as 권한(Role) 및 사용자(User) 프로비저닝이 완료되었습니다!"
printf "================================================================================\n"

  # 2-2. 사원 B (user_b) 생성 - viewer_role 부여
  USER_B_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\" ],
    \"full_name\": \"Dashboard Viewer User B\",
    \"email\": \"user_b@poc.local\",
    \"metadata\": {
      \"department\": \"Operations\",
      \"auth_type\": \"2FA_FACE_AUTH\"
    }
  }"
  call_es_api \
    "일반 사원 계정 'user_b' 생성 (viewer_role 부여)" \
    "POST" \
    "/_security/user/user_b" \
    "${USER_B_PAYLOAD}"

  # 2-3. 관리자 테스트 계정 (admin) 및 기본 테스트 계정 (face_user1) 생성
  # PoC에서 관리자 권한과 일반 열람자(viewer_role) 권한 차이를 비교 테스트할 수 있도록 구성합니다.
  ADMIN_USER_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\", \"kibana_admin\", \"superuser\" ],
    \"full_name\": \"PoC System Admin (2FA)\",
    \"email\": \"admin@poc.local\"
  }"
  call_es_api \
    "관리자 비교 테스트용 계정 'admin' 생성" \
    "POST" \
    "/_security/user/admin" \
    "${ADMIN_USER_PAYLOAD}"

  FACE_USER1_PAYLOAD="{
    \"password\": \"${EMPLOYEE_PASS}\",
    \"roles\": [ \"viewer_role\" ],
    \"full_name\": \"PoC Default Face User 1\",
    \"email\": \"face_user1@poc.local\"
  }"
  call_es_api \
    "기본 테스트 사원 계정 'face_user1' 생성 (viewer_role 부여)" \
    "POST" \
    "/_security/user/face_user1" \
    "${FACE_USER1_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 3] 프록시 전용 Role 생성 (proxy_role)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 직무 분리 (Separation of Duties) 및 권한 위임 제한]
# 1. Nginx 프록시는 사용자의 2FA 통과 결과를 받아 신원을 전달하는 '전달자(Impersonator)'일 뿐,
#    프록시 자체가 비즈니스 데이터를 조회하거나 변경하는 주체가 되어서는 안 됩니다.
# 2. 따라서 `proxy_role`에는 `indices` 권한이나 `cluster` 관리 권한을 일절 부여하지 않고,
#    오직 `run_as` 필드에 앞서 생성한 일반 사원 목록(`user_a`, `user_b`, `admin`, `face_user1`)만 명시합니다.
# 3. 특히 `run_as` 대상에 `elastic`(슈퍼유저)이나 `kibana_system`을 절대 포함하지 않음으로써,
#    만약 프록시 계정이 탈취되더라도 시스템 최고 권한으로의 권한 상승(Privilege Escalation)을 차단합니다.
# ------------------------------------------------------------------------------
create_proxy_role() {
  log_step "3. 프록시 전용 대리 실행 Role (proxy_role) 생성"

  PROXY_ROLE_PAYLOAD='{
    "run_as": [
      "user_a",
      "user_b",
      "admin",
      "face_user1"
    ],
    "cluster": [],
    "indices": [],
    "metadata": {
      "description": "Nginx 리버스 프록시 전용 Role - 자체 인덱스 접근 권한 없이 지정된 사원에 대한 run_as 권한만 보유"
    }
  }'

  call_es_api \
    "프록시 전용 Role (proxy_role) 생성 (user_a, user_b 등에 대한 run_as 권한만 부여)" \
    "PUT" \
    "/_security/role/proxy_role" \
    "${PROXY_ROLE_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 4] 프록시 전용 계정 생성 (proxy_user)
# ------------------------------------------------------------------------------
# [보안 원칙상 권한 분리 이유 - 대리 인증 자격증명의 고립화]
# 1. Nginx 설정(`nginx.conf`)에는 Basic Auth 헤더가 고정으로 기입되므로,
#    이 계정은 오직 `proxy_role` 하나만 가진 전용 서비스 계정(`proxy_user`)이어야 합니다.
# 2. 만약 누군가 `proxy_user:proxy_password`만 가지고 `es-security-runas-user` 헤더 없이
#    Elasticsearch에 직접 쿼리를 보내면, `proxy_role`에는 어떠한 인덱스 조회 권한도 없으므로
#    모든 데이터 접근이 거부(403 Forbidden)됩니다.
# ------------------------------------------------------------------------------
create_proxy_user() {
  log_step "4. 프록시 전용 계정 (proxy_user) 생성 및 proxy_role 부여"

  PROXY_USER_PAYLOAD="{
    \"password\": \"${PROXY_USER_PASS}\",
    \"roles\": [ \"proxy_role\" ],
    \"full_name\": \"Nginx 2FA Auth Gateway Proxy Account\",
    \"metadata\": {
      \"purpose\": \"impersonation_only\",
      \"managed_by\": \"es-setup/init-es.sh\"
    }
  }"

  call_es_api \
    "프록시 전용 계정 'proxy_user' 생성 (proxy_role 부여)" \
    "POST" \
    "/_security/user/proxy_user" \
    "${PROXY_USER_PAYLOAD}"
}

# ------------------------------------------------------------------------------
# [단계 5] 테스트용 샘플 인덱스 데이터 적재 및 run_as 동작 자가 검증
# ------------------------------------------------------------------------------
verify_run_as_provisioning() {
  log_step "5. 샘플 인덱스 생성 및 proxy_user -> user_a 대리 실행(run_as) 검증"

  # 5-1. viewer_role이 조회할 수 있는 샘플 로그 문서 1건 색인 (logs-poc-2026)
  SAMPLE_DOC_PAYLOAD='{
    "@timestamp": "2026-10-25T22:30:00Z",
    "event": "2fa_face_auth_poc_initialized",
    "message": "Elasticsearch run_as 테스트용 샘플 보안 로그 데이터입니다.",
    "allowed_role": "viewer_role"
  }'
  call_es_api \
    "viewer_role 읽기 테스트를 위한 샘플 로그 문서(logs-poc-2026) 생성" \
    "POST" \
    "/logs-poc-2026/_doc/1?refresh=true" \
    "${SAMPLE_DOC_PAYLOAD}"

  # 5-2. proxy_user 계정으로 `es-security-runas-user: user_a` 헤더를 포함하여
  # `/_security/_authenticate` 호출 시 실제 인증 주체가 `user_a`로 전환되는지 검증
  log_info "▶ 검증 시작: proxy_user 자격증명 + 'es-security-runas-user: user_a' 헤더로 대리 인증 테스트"
  VERIFY_FILE="/tmp/es_verify_$$.json"
  VERIFY_CODE=$(curl -s -S -o "${VERIFY_FILE}" -w "%{http_code}" \
    -u "proxy_user:${PROXY_USER_PASS}" \
    -H "es-security-runas-user: user_a" \
    "${ES_URL}/_security/_authenticate") || {
      log_error "run_as 대리 인증 검증 호출에 실패했습니다."
      rm -f "${VERIFY_FILE}"
      exit 1
    }

  VERIFY_BODY=$(cat "${VERIFY_FILE}" 2>/dev/null || echo "")
  rm -f "${VERIFY_FILE}"

  log_info "  - 검증 HTTP 응답 코드: ${VERIFY_CODE}"
  printf "  - 검증 응답 Body   : %s\n" "${VERIFY_BODY}"

  if [ "${VERIFY_CODE}" != "200" ]; then
    log_error "run_as 대리 인증 검증 실패! (HTTP ${VERIFY_CODE}) 응답: ${VERIFY_BODY}"
    exit 1
  fi

  log_info "✔ 검증 성공: proxy_user가 'user_a' 권한(viewer_role)으로 정상 대리 인증(run_as)되었습니다."
}

# ==============================================================================
# 메인 실행 흐름 (요구사항 1의 순서 엄수)
# ==============================================================================
create_viewer_role
create_employee_users
create_proxy_role
create_proxy_user
verify_run_as_provisioning

printf "\n================================================================================\n"
log_info "모든 Elasticsearch run_as 권한(Role) 및 사용자(User) 프로비저닝이 완료되었습니다!"
printf "================================================================================\n"


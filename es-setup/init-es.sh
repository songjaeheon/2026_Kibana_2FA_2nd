#!/bin/sh
# ==============================================================================
# Elasticsearch run_as 초기 보안 설정 스크립트 (es-setup/init-es.sh)
#
# [역할]
# 1. Kibana 내부 통신용 시스템 계정(kibana_system) 비밀번호 설정
# 2. 2FA 통과 후 대리 실행(run_as)을 수행할 프록시 전용 Role 및 계정 생성
# 3. 실제 안면인증 사용자를 모사할 테스트 사용자(face_user1) 생성
# ==============================================================================

set -e

ES_URL="http://elasticsearch:9200"
ES_PASS="${ELASTIC_PASSWORD:-changeme123!}"

echo "[es-setup] Elasticsearch 응답 대기 중..."
until curl -s -u "elastic:${ES_PASS}" "${ES_URL}/_cluster/health" > /dev/null; do
  sleep 2
done

echo "[es-setup] 1. kibana_system 시스템 계정 비밀번호 설정..."
curl -s -X POST -u "elastic:${ES_PASS}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${ES_PASS}\"}" > /dev/null

echo "[es-setup] 2. run_as 대리 실행 권한을 가진 Role (proxy_runas_role) 생성..."
curl -s -X PUT -u "elastic:${ES_PASS}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/role/proxy_runas_role" \
  -d '{
    "run_as": [ "face_user1", "analyst_*" ],
    "cluster": [ "monitor" ]
  }' > /dev/null

echo "[es-setup] 3. Nginx 프록시가 사용할 대리 실행 계정 (proxy_admin) 생성..."
curl -s -X POST -u "elastic:${ES_PASS}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/proxy_admin" \
  -d "{
    \"password\" : \"${ES_PASS}\",
    \"roles\" : [ \"proxy_runas_role\" ],
    \"full_name\" : \"Nginx 2FA Proxy Impersonator\"
  }" > /dev/null

echo "[es-setup] 4. 2FA 인증 대상 테스트 사용자 (face_user1) 생성..."
curl -s -X POST -u "elastic:${ES_PASS}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/face_user1" \
  -d "{
    \"password\" : \"${ES_PASS}\",
    \"roles\" : [ \"kibana_admin\", \"superuser\" ],
    \"full_name\" : \"2FA Verified User 1\"
  }" > /dev/null

echo "[es-setup] 초기 Role 및 계정 구성이 완료되었습니다."


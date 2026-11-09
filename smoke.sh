#!/usr/bin/env bash
cd /home/operator24/web-port-scanner || exit 1
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 > /tmp/uv.log 2>&1 &
UV=$!; sleep 4
B=http://127.0.0.1:8000; U="smoke$RANDOM"; H='Content-Type: application/json'
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
echo "register         $(code -X POST $B/auth/register -H "$H" -d "{\"username\":\"$U\",\"password\":\"Correct-Horse-Battery-9\"}")  (want 201)"
TOKEN=$(curl -s -X POST $B/auth/login -H "$H" -d "{\"username\":\"$U\",\"password\":\"Correct-Horse-Battery-9\"}" | python -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')
A="Authorization: Bearer $TOKEN"
echo "me               $(code $B/auth/me -H "$A")  (want 200)"
echo "scan no auth     $(code -X POST $B/scans/ -H "$H" -d '{"target":"example.com","ports":[80]}')  (want 401)"
echo "scan bad port    $(code -X POST $B/scans/ -H "$A" -H "$H" -d '{"target":"example.com","ports":[0]}')  (want 422)"
echo "scan loopback    $(code -X POST $B/scans/ -H "$A" -H "$H" -d '{"target":"localhost","ports":[80]}')  (want 400)"
echo "scan public      $(curl -s -w ' -> %{http_code}' -X POST $B/scans/ -H "$A" -H "$H" -d '{"target":"example.com","ports":[80,443]}')  (want 202)"
kill $UV 2>/dev/null; wait $UV 2>/dev/null
echo "--- log tail"; tail -3 /tmp/uv.log

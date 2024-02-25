curl -X POST -H "Content-Type: application/json" -d '{"password": "admin", "newpassword": "admin2", "whitelist": ["127.0.0.1","192.168.1.22"]}' http://127.0.0.1:8080/setAdmin | jq .


curl http://127.0.0.1:8080/v1/testservice1 | jq .


curl -H "system: dev" http://127.0.0.1:8080/v1/testservice1 | jq .


app-1  | time="2024-02-25T16:21:16Z" level=error msg="IP not in whitelist"
app-1  | [GIN] 2024/02/25 - 16:21:16 | 404 |    5.406167ms |    192.168.65.1 | POST     "/setAdmin"



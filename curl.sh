curl -X POST -H "Content-Type: application/json" -d '{"password": "admin", "newpassword": "admin2", "whitelist": ["127.0.0.1","192.168.1.22"]}' http://127.0.0.1:8080/setAdmin | jq .


curl http://127.0.0.1:8080/v1/testservice1 | jq .


curl -H "system: dev" http://127.0.0.1:8080/v1/testservice1 | jq .


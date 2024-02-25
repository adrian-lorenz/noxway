curl -X POST -H "Content-Type: application/json" -d '{"password": "admin", "newpassword": "admin2", "whitelist": ["127.0.0.1","192.168.1.22"]}' http://127.0.0.1:8080/setAdmin

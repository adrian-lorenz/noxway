curl -X POST -H "Content-Type: application/json" -d '{"password": "admin", "newpassword": "admin2", "whitelist": ["127.0.0.1","192.168.1.22"]}' http://127.0.0.1:8080/setAdmin | jq .


curl http://127.0.0.1:8080/v1/testservice1 | jq .


curl -H "system: dev" http://127.0.0.1:8080/v1/testservice1 | jq .


curl -X POST -H "Content-Type: application/json" -d '{"password": "admin", "newpassword": "muha", "whitelist": ["127.0.0.1"]}' http://127.0.0.1:8080/setAdmin

curl --request POST \
  --url http://127.0.0.1:8080/retiveCert \
  --header 'Content-Type: application/json' \
  --data '{
	"domain": "api.noxway.org",
	"mail": "a.lorenz@noa-x.de"
}'


NOXWAY_DB_PASSWORD="trlud12333" docker-compose up --build


docker build -t noxway/noxway:0.0.3 .
docker login -u noxway     
docker push noxway/noxway:0.0.3



curl -H "system: dev"  https://api.noxway.org/v1/testservice1 | jq .
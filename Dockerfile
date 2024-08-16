FROM golang:1.23.0 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o main
FROM amd64/alpine:latest
WORKDIR /app
COPY --from=builder /app/main /app/main
RUN chmod +x /app/main
EXPOSE 8080 443 80
CMD ["./main"]

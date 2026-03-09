FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY test-ws/server/main.go ./main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o ws-test-server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/ws-test-server .
EXPOSE 8080
CMD ["./ws-test-server"]

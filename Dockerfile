FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o opencode-relay-server ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/opencode-relay-server .

# Persistent data directory - Azure App Service mounts /home as persistent storage
RUN mkdir -p /home/data
VOLUME /home/data

EXPOSE 8080
CMD ["./opencode-relay-server"]

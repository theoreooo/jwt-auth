FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auth ./cmd/auth

FROM alpine:3.18

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/auth ./auth
COPY config ./config

EXPOSE 8082

ENV CONFIG_PATH=/app/config/local.yaml

ENTRYPOINT ["/app/auth"] 
FROM golang:1.26.5-alpine3.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server .

FROM alpine:3.24

RUN apk --no-cache add ca-certificates tzdata openssl && \
    adduser -D -u 10001 appuser

WORKDIR /app

COPY --chown=appuser:appuser --from=builder /app/server .

USER appuser:appuser

EXPOSE 8080

CMD ["./server"]

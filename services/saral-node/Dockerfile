FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/saral-node ./cmd/main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /bin/saral-node /usr/local/bin/saral-node
ENV PORT=8001
ENV VAULT_DIR=/vault
VOLUME ["/vault"]
EXPOSE 8001
ENTRYPOINT ["/usr/local/bin/saral-node"]


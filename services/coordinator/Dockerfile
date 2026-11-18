FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/coordinator ./cmd/main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /bin/coordinator /usr/local/bin/coordinator
ENV PORT=9001
EXPOSE 9001
ENTRYPOINT ["/usr/local/bin/coordinator"]


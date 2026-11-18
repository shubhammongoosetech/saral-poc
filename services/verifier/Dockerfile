FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/verifier ./cmd/main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /bin/verifier /usr/local/bin/verifier
ENV PORT=9101
EXPOSE 9101
ENTRYPOINT ["/usr/local/bin/verifier"]


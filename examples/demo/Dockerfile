FROM golang:1.25.3-alpine3.22 AS builder
WORKDIR /app
COPY . /app
RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o /app/bin .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/bin /app/bin
ENTRYPOINT ["/app/bin"]

FROM golang:1.23.4 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

WORKDIR /app/cmd/scout
RUN CGO_ENABLED=0 GOOS=linux go build -o scout

FROM alpine:3.21

WORKDIR /scan

COPY --from=builder /app/cmd/scout/scout /usr/local/bin/scout

RUN chmod +x /usr/local/bin/scout

ENTRYPOINT ["scout"]
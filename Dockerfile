FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN apk --no-cache add build-base

ENV CGO_ENABLED=1
WORKDIR /app/cmd/scout

RUN go build -o scout

FROM alpine:3.21

RUN apk --no-cache add libgcc

WORKDIR /scan

COPY --from=builder /app/cmd/scout/scout /usr/local/bin/scout

# temp
COPY --from=builder /app/cmd/scout/scout.db /scout.db


RUN chmod +x /usr/local/bin/scout

ENTRYPOINT ["scout"]
FROM golang:1.23.0

WORKDIR /app

COPY *.go go.mod go.sum ./
# syntax=docker/dockerfile:1
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -buildvcs=false \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sws-lab \
    ./cmd/sws-lab

FROM scratch
COPY --from=build /out/sws-lab /sws-lab

USER 65532:65532
EXPOSE 8080
ENV ADDR=:8080

ENTRYPOINT ["/sws-lab"]

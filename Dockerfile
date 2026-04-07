FROM golang:1.25 AS build

ARG VERSION=dirty

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /broker ./cmd/broker

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /broker /broker
USER 65534
ENTRYPOINT ["/broker"]

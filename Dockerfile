FROM --platform=$BUILDPLATFORM golang:1.26.2 AS build

ARG VERSION=dirty
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w -X main.version=${VERSION}" -o /broker ./cmd/broker

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /broker /broker
USER 65534
ENTRYPOINT ["/broker"]

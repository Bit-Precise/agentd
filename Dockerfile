# syntax=docker/dockerfile:1
# Builds all three binaries; pick an image with --target agentserver |
# agentrelay | agentd. The web console is built from the OpenAPI document and
# embedded into agentserver.

FROM --platform=$BUILDPLATFORM node:24-alpine AS web
RUN npm install -g pnpm@12
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY docs/agentserver-openapi.yaml /src/docs/agentserver-openapi.yaml
COPY web/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
# Cross-compile on the build platform; no emulation for multi-arch images.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X agentd/internal/control.Version=${VERSION} -X agentd/internal/relay.Version=${VERSION} -X agentd/internal/agent.Version=${VERSION}" \
      -o /out/ ./cmd/agentserver ./cmd/agentrelay ./cmd/agentd

FROM gcr.io/distroless/static-debian12:nonroot AS agentserver
COPY --from=build /out/agentserver /usr/local/bin/agentserver
EXPOSE 8443 7800
ENTRYPOINT ["/usr/local/bin/agentserver"]
CMD ["run", "-c", "/etc/agentserver/config.yaml"]

FROM gcr.io/distroless/static-debian12:nonroot AS agentrelay
COPY --from=build /out/agentrelay /usr/local/bin/agentrelay
EXPOSE 8443 3478/udp
ENTRYPOINT ["/usr/local/bin/agentrelay"]
CMD ["run", "-c", "/etc/agentrelay/config.yaml"]

FROM gcr.io/distroless/static-debian12:nonroot AS agentd
COPY --from=build /out/agentd /usr/local/bin/agentd
ENV AGENTD_HOME=/var/lib/agentd
ENTRYPOINT ["/usr/local/bin/agentd"]
CMD ["run"]

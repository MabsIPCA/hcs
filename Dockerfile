# syntax=docker/dockerfile:1

# --- Build KICS (fork with --image-bom) ---
ARG KICS_REPO=https://github.com/MabsIPCA/kics
ARG KICS_REF=feat/image-bom
FROM golang:1.26-bookworm AS kics-build
ARG KICS_REPO
ARG KICS_REF
RUN git clone --depth 1 --branch "${KICS_REF}" "${KICS_REPO}" /kics
WORKDIR /kics
RUN CGO_ENABLED=0 go build -o /out/kics ./cmd/console
# KICS needs its query + library assets at runtime
RUN cp -r assets /out/assets

# --- Build hcs ---
FROM golang:1.26-bookworm AS hcs-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/hcs ./cmd/hcs

# --- Trivy binary ---
FROM aquasec/trivy:latest AS trivy

# --- Final image ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=kics-build /out/kics /usr/local/bin/kics
COPY --from=kics-build /out/assets /opt/kics/assets
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=hcs-build /out/hcs /usr/local/bin/hcs
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries
ENTRYPOINT ["hcs"]

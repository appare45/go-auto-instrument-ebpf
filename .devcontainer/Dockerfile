FROM mcr.microsoft.com/devcontainers/go:2-1.25-trixie

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt update && \
  apt install -y make clang libbpf-dev llvm clangd


#!/usr/bin/env bash
set -euo pipefail

# File Notes:
# - Builds eTraceGen kernel object: bpf/event_logger.bpf.o
# - Generates bpf/vmlinux.h from host BTF when missing.
# - Intended for Linux hosts with clang + bpftool installed (clang required for BPF).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_SRC="${ROOT_DIR}/bpf/event_logger.bpf.c"
BPF_OBJ="${ROOT_DIR}/bpf/event_logger.bpf.o"
VMLINUX_H="${ROOT_DIR}/bpf/vmlinux.h"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[error] bpf object build requires Linux"
  exit 1
fi

# Prefer an explicit CLANG override, otherwise pick the newest clang available.
CLANG_BIN="${CLANG:-}"
if [[ -z "${CLANG_BIN}" ]]; then
  for candidate in clang clang-18 clang-17 clang-16 clang-15 clang-14 clang-13; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      CLANG_BIN="${candidate}"
      break
    fi
  done
fi

if [[ -z "${CLANG_BIN}" ]]; then
  echo "[error] clang not found (required to build BPF object)"
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "[error] required tool not found: bpftool"
  exit 1
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "[error] kernel BTF not available at /sys/kernel/btf/vmlinux"
  exit 1
fi

case "$(uname -m)" in
  x86_64)
    target_arch="x86"
    ;;
  aarch64|arm64)
    target_arch="arm64"
    ;;
  armv7l)
    target_arch="arm"
    ;;
  riscv64)
    target_arch="riscv"
    ;;
  ppc64le)
    target_arch="powerpc"
    ;;
  s390x)
    target_arch="s390"
    ;;
  *)
    echo "[error] unsupported architecture for __TARGET_ARCH mapping: $(uname -m)"
    exit 1
    ;;
esac

# Generate CO-RE type header from running kernel BTF.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_H}"

"${CLANG_BIN}" \
  -g -O2 -target bpf \
  -D__TARGET_ARCH_${target_arch} \
  -I"${ROOT_DIR}/bpf" \
  -I"${ROOT_DIR}/include" \
  -c "${BPF_SRC}" \
  -o "${BPF_OBJ}"

echo "[pass] built ${BPF_OBJ} (clang=${CLANG_BIN})"

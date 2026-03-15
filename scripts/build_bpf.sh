#!/usr/bin/env bash
set -euo pipefail

# File Notes:
# - Builds eTraceGen kernel object: bpf/event_logger.bpf.o
# - Generates bpf/vmlinux.h from host BTF when missing.
# - Intended for Linux hosts with clang + bpftool installed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_SRC="${ROOT_DIR}/bpf/event_logger.bpf.c"
BPF_OBJ="${ROOT_DIR}/bpf/event_logger.bpf.o"
VMLINUX_H="${ROOT_DIR}/bpf/vmlinux.h"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[error] bpf object build requires Linux"
  exit 1
fi

for tool in clang bpftool; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "[error] required tool not found: ${tool}"
    exit 1
  fi
done

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

clang \
  -g -O2 -target bpf \
  -D__TARGET_ARCH_${target_arch} \
  -I"${ROOT_DIR}/bpf" \
  -I"${ROOT_DIR}/include" \
  -c "${BPF_SRC}" \
  -o "${BPF_OBJ}"

echo "[pass] built ${BPF_OBJ}"

#!/usr/bin/env bash
set -euo pipefail

# File Notes:
# - Single Linux entrypoint for build, preflight, test, and run workflows.
# - Uses capture-first defaults for sandbox telemetry collection.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/etracegen"
BPF_SRC="${ROOT_DIR}/bpf/event_logger.bpf.c"
BPF_OBJ="${ROOT_DIR}/bpf/event_logger.bpf.o"
VMLINUX_H="${ROOT_DIR}/bpf/vmlinux.h"

LOGGER_PID=""

pass() { echo "[pass] $1"; }
warn() { echo "[warn] $1"; }
fail() { echo "[fail] $1"; exit 1; }

cleanup_logger() {
  if [[ -n "${LOGGER_PID}" ]] && kill -0 "${LOGGER_PID}" 2>/dev/null; then
    kill -INT "${LOGGER_PID}" || true
    wait "${LOGGER_PID}" || true
  fi
  LOGGER_PID=""
}
trap cleanup_logger EXIT

ensure_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    fail "Linux host required (found $(uname -s))"
  fi
}

check_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "required tool missing: ${cmd}"
  fi
  pass "tool found: ${cmd}"
}

pick_clang() {
  local clang_bin="${CLANG:-}"
  if [[ -n "${clang_bin}" ]]; then
    echo "${clang_bin}"
    return 0
  fi

  local candidate
  for candidate in clang clang-18 clang-17 clang-16 clang-15 clang-14 clang-13; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

build_userspace() {
  ensure_linux
  cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/build"
  cmake --build "${ROOT_DIR}/build" -j
  pass "built userspace binary: ${BIN}"
}

build_bpf() {
  ensure_linux

  local clang_bin
  clang_bin="$(pick_clang)" || fail "clang not found (required for BPF object build)"

  check_cmd bpftool

  if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    fail "kernel BTF not available at /sys/kernel/btf/vmlinux"
  fi

  local target_arch
  case "$(uname -m)" in
    x86_64) target_arch="x86" ;;
    aarch64|arm64) target_arch="arm64" ;;
    armv7l) target_arch="arm" ;;
    riscv64) target_arch="riscv" ;;
    ppc64le) target_arch="powerpc" ;;
    s390x) target_arch="s390" ;;
    *) fail "unsupported architecture for __TARGET_ARCH mapping: $(uname -m)" ;;
  esac

  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_H}"

  # Ubuntu/Debian with clang --target=bpf may need explicit multiarch include path
  # so stdint.h can resolve bits/libc-header-start.h.
  local gcc_triplet=""
  local multiarch_include=""
  if command -v gcc >/dev/null 2>&1; then
    gcc_triplet="$(gcc -dumpmachine 2>/dev/null || true)"
  fi
  if [[ -n "${gcc_triplet}" && -d "/usr/include/${gcc_triplet}" ]]; then
    multiarch_include="/usr/include/${gcc_triplet}"
  fi

  local extra_include_flags=()
  if [[ -n "${multiarch_include}" ]]; then
    extra_include_flags+=("-I${multiarch_include}")
  fi

  "${clang_bin}" \
    -g -O2 -target bpf \
    -D__TARGET_ARCH_${target_arch} \
    -I"${ROOT_DIR}/bpf" \
    -I"${ROOT_DIR}/include" \
    "${extra_include_flags[@]}" \
    -c "${BPF_SRC}" \
    -o "${BPF_OBJ}"

  pass "built ${BPF_OBJ} (clang=${clang_bin}${multiarch_include:+, multiarch_include=${multiarch_include}})"
}


host_check() {
  ensure_linux

  echo "[info] kernel: $(uname -r)"
  echo "[info] arch: $(uname -m)"

  check_cmd gcc
  check_cmd g++
  check_cmd cmake
  check_cmd pkg-config
  check_cmd clang
  check_cmd llvm-strip
  check_cmd bpftool
  check_cmd pahole

  if [[ -r /sys/kernel/btf/vmlinux ]]; then
    pass "kernel BTF present: /sys/kernel/btf/vmlinux"
  else
    fail "kernel BTF missing: /sys/kernel/btf/vmlinux"
  fi

  if [[ -r /proc/config.gz ]]; then
    zgrep -q '^CONFIG_BPF=y' /proc/config.gz && pass 'CONFIG_BPF=y' || warn 'CONFIG_BPF not confirmed'
    zgrep -q '^CONFIG_BPF_SYSCALL=y' /proc/config.gz && pass 'CONFIG_BPF_SYSCALL=y' || warn 'CONFIG_BPF_SYSCALL not confirmed'
    zgrep -q '^CONFIG_BPF_JIT=y' /proc/config.gz && pass 'CONFIG_BPF_JIT=y' || warn 'CONFIG_BPF_JIT not confirmed'
  else
    warn '/proc/config.gz not readable; cannot validate kernel config flags directly'
  fi

  if [[ ${EUID} -eq 0 ]]; then
    pass 'running as root (simplest for initial validation)'
  else
    warn 'not running as root; initial attach/load may fail without capabilities'
  fi

  echo "[hint] Debian/Ubuntu packages: build-essential cmake ninja-build gcc g++ clang llvm pkg-config libelf-dev zlib1g-dev libbpf-dev bpftool pahole linux-headers-$(uname -r)"
  echo "[hint] Fedora/RHEL packages: gcc-c++ make cmake ninja-build clang llvm pkgconf-pkg-config elfutils-libelf-devel zlib-devel libbpf libbpf-devel bpftool dwarves kernel-devel kernel-headers"
  echo "[hint] Arch packages: base-devel cmake ninja clang llvm pkgconf libelf zlib libbpf bpftool pahole linux-headers"

  pass "host prerequisites checked"
}

preflight() {
  ensure_linux

  [[ -f "${ROOT_DIR}/README.md" ]] || fail "missing file: README.md"
  [[ -f "${ROOT_DIR}/CMakeLists.txt" ]] || fail "missing file: CMakeLists.txt"
  [[ -f "${ROOT_DIR}/config/default.yaml" ]] || fail "missing file: config/default.yaml"
  [[ -f "${ROOT_DIR}/include/event_schema.h" ]] || fail "missing file: include/event_schema.h"
  [[ -f "${ROOT_DIR}/src/main.cpp" ]] || fail "missing file: src/main.cpp"
  [[ -f "${ROOT_DIR}/bpf/event_logger.bpf.c" ]] || fail "missing file: bpf/event_logger.bpf.c"
  [[ -f "${ROOT_DIR}/docs/arch-exec-flow/linux-setup.md" ]] || fail "missing file: docs/arch-exec-flow/linux-setup.md"
  pass "repository structure sanity checks passed"

  rg -q "domains:" "${ROOT_DIR}/config/default.yaml" || fail "config missing domains section"
  rg -q "startup_report" "${ROOT_DIR}/src/main.cpp" || fail "startup report wiring missing"
  rg -q "on_raw_sys_enter" "${ROOT_DIR}/bpf/event_logger.bpf.c" || fail "raw syscall handler missing"
  pass "kernel and config sanity checks passed"

  [[ -x "${BIN}" ]] || fail "missing built binary: build/etracegen (run ./scripts/linux.sh build)"
  [[ -f "${BPF_OBJ}" ]] || fail "missing BPF object: bpf/event_logger.bpf.o (run ./scripts/linux.sh bpf)"

  host_check
  pass "release preflight passed"
}

start_logger() {
  local cfg_path="$1"
  local out_path="$2"
  local err_path="$3"

  ETRACEGEN_CONFIG="${cfg_path}" ETRACEGEN_BPF_OBJECT="${BPF_OBJ}" "${BIN}" >"${out_path}" 2>"${err_path}" &
  LOGGER_PID="$!"
  sleep 1

  if ! kill -0 "${LOGGER_PID}" 2>/dev/null; then
    fail "logger exited early for config ${cfg_path}"
  fi
}

stop_logger() {
  cleanup_logger
}

generate_general_activity() {
  local tag="$1"
  /bin/sh -c 'true' >/dev/null 2>&1 || true

  local tmp_a="/tmp/etracegen_${tag}_$$.a"
  local tmp_b="/tmp/etracegen_${tag}_$$.b"

  : >"${tmp_a}"
  cat "${tmp_a}" >/dev/null 2>&1 || true
  mv "${tmp_a}" "${tmp_b}"
  rm -f "${tmp_b}"
}

generate_network_activity() {
  (exec 3<>/dev/tcp/127.0.0.1/1) >/dev/null 2>&1 || true
  exec 3>&- 2>/dev/null || true
}

integration_smoke() {
  ensure_linux

  local out_file="${ROOT_DIR}/build/integration_smoke_output.ndjson"
  local stderr_file="${ROOT_DIR}/build/integration_smoke_stderr.log"

  [[ -x "${BIN}" ]] || fail "binary not found: ${BIN}"
  [[ -f "${BPF_OBJ}" ]] || fail "bpf object not found: ${BPF_OBJ}"

  rm -f "${out_file}" "${stderr_file}"
  start_logger "${ROOT_DIR}/config/default.yaml" "${out_file}" "${stderr_file}"

  generate_general_activity "smoke"
  generate_network_activity

  sleep 1
  stop_logger

  rg -q '"type":"process"' "${out_file}" || fail "no process events observed"
  rg -q '"type":"file"' "${out_file}" || fail "no file events observed"
  rg -q '"type":"syscall"' "${out_file}" || fail "no syscall events observed"

  if ! rg -q '"type":"network"' "${out_file}"; then
    warn "no network events observed in smoke run"
  fi

  pass "integration smoke test succeeded"
}

write_validate_config() {
  local cfg_path="$1"
  local syscall_enabled="$2"
  local network_enabled="$3"

  cat >"${cfg_path}" <<CFG
collector:
  poll_timeout_ms: 200

domains:
  process: true
  file: true
  syscall: ${syscall_enabled}

  network_socket: ${network_enabled}
  dns: false
  http: false
  https: false

file_probes:
  openat: true
  unlinkat: true
  renameat2: true

sink:
  type: stdout_json
CFG
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  rg -q "${pattern}" "${file}" || fail "${message}"
}

assert_not_contains() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  if rg -q "${pattern}" "${file}"; then
    fail "${message}"
  fi
}

run_validate_case() {
  local case_name="$1"
  local syscall_enabled="$2"
  local network_enabled="$3"

  local cfg="${ROOT_DIR}/build/validate_v1/${case_name}.yaml"
  local out="${ROOT_DIR}/build/validate_v1/${case_name}.ndjson"
  local err="${ROOT_DIR}/build/validate_v1/${case_name}.stderr.log"

  write_validate_config "${cfg}" "${syscall_enabled}" "${network_enabled}"
  start_logger "${cfg}" "${out}" "${err}"

  generate_general_activity "validate_${case_name}"
  if [[ "${network_enabled}" == "true" ]]; then
    generate_network_activity
  fi

  sleep 1
  stop_logger

  assert_contains '"type":"process"' "${out}" "${case_name} missing process events"
  assert_contains '"type":"file"' "${out}" "${case_name} missing file events"

  if [[ "${syscall_enabled}" == "true" ]]; then
    assert_contains '"type":"syscall"' "${out}" "${case_name} missing syscall events"
  else
    assert_not_contains '"type":"syscall"' "${out}" "${case_name} unexpectedly emitted syscall events"
  fi

  if [[ "${network_enabled}" == "true" ]] && ! rg -q '"type":"network"' "${out}"; then
    warn "${case_name} did not emit network events on this host"
  fi

  pass "validation case passed: ${case_name}"
}

validate_v1() {
  ensure_linux

  [[ -x "${BIN}" ]] || fail "binary not found: ${BIN}"
  [[ -f "${BPF_OBJ}" ]] || fail "bpf object not found: ${BPF_OBJ}"

  mkdir -p "${ROOT_DIR}/build/validate_v1"

  run_validate_case "baseline_all" "true" "true"
  run_validate_case "syscall_domain_off" "false" "true"

  pass "v1 validation suite passed"
}

run_binary() {
  ensure_linux
  [[ -x "${BIN}" ]] || fail "binary not found: ${BIN}"
  [[ -f "${BPF_OBJ}" ]] || fail "bpf object not found: ${BPF_OBJ}"
  ETRACEGEN_BPF_OBJECT="${BPF_OBJ}" "${BIN}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/linux.sh <command>

Commands:
  help       Show this help.
  build      Build userspace binary.
  bpf        Build BPF object.
  all        Build userspace + BPF object.
  check      Run Linux host prerequisite checks.
  preflight  Run release preflight checks.
  smoke      Run integration smoke test.
  validate   Run v1 validation suite.
  verify     Run build + preflight + smoke + validate.
  run        Run the collector binary.
USAGE
}

main() {
  local cmd="${1:-help}"

  case "${cmd}" in
    help|-h|--help) usage ;;
    build) build_userspace ;;
    bpf) build_bpf ;;
    all) build_userspace; build_bpf ;;
    check) host_check ;;
    preflight) preflight ;;
    smoke) integration_smoke ;;
    validate) validate_v1 ;;
    verify) build_userspace; build_bpf; preflight; integration_smoke; validate_v1 ;;
    run) run_binary ;;
    *) fail "unknown command: ${cmd}. Run ./scripts/linux.sh help" ;;
  esac
}

main "${1:-help}"

#!/usr/bin/env bash
set -euo pipefail

KAAMO_VERSION="2.0.0"
KAAMO_DIR="${HOME}/.kaamo"
MODEL_DIR="${KAAMO_DIR}/models"

echo "Kaamo Installer v${KAAMO_VERSION}"

check_deps() {
  local missing=()
  for cmd in docker cmake python3 pip3; do
    command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "Missing dependencies: ${missing[*]}"
    exit 1
  fi
}

build_native() {
  cmake -B build/native src/native -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O2 -march=native"
  cmake --build build/native --parallel "$(getconf _NPROCESSORS_ONLN)"
  mkdir -p "${KAAMO_DIR}/lib"
  cp build/native/libkaamo.so "${KAAMO_DIR}/lib/" || true
}

install_python() {
  pip3 install --quiet uv
  uv pip install -e ".[all]"
}

setup_dirs() {
  mkdir -p "${MODEL_DIR}" "${KAAMO_DIR}/agents" "${KAAMO_DIR}/logs"
  chmod 700 "${KAAMO_DIR}"
}

setup_daemon() {
  if command -v systemctl >/dev/null 2>&1; then
    sudo install -m644 scripts/kaamo-daemon.service /etc/systemd/system/kaamo-daemon.service
    sudo systemctl daemon-reload
    sudo systemctl enable kaamo-daemon
  fi
}

check_deps
setup_dirs
build_native
install_python
setup_daemon
echo "Kaamo installed. Populate Gemma SHA-256 values before using pull-model."


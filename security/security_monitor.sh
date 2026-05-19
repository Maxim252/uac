#!/bin/sh
# security/security_monitor.sh
# Security Monitor v1.2 — Кибериммунный компонент для UAC
# ВКР Мосейчук М.Л. 2026
# SPDX-License-Identifier: Apache-2.0

_sm_init() {
  __SM_VERSION="1.2-kiberimmune"
  __SM_ENABLED="${UAC_SECURITY_MONITOR:-1}"

  # Пытаемся сразу определить правильный путь
  if [ -n "${__UAC_TEMP_DATA_DIR:-}" ]; then
    __SM_LOG_FILE="${__UAC_TEMP_DATA_DIR}/uac_security_monitor_audit.log"
  else
    __SM_LOG_FILE="/tmp/uac_security_monitor_audit.log"
  fi

  if [ -n "${__UAC_DIR:-}" ]; then
    __SM_POLICY_DIR="${__UAC_DIR}/security/policies"
  else
    __SM_POLICY_DIR="./security/policies"
  fi

  mkdir -p "$(dirname "${__SM_LOG_FILE}")" 2>/dev/null || true

  if [ "${__SM_ENABLED}" != "1" ]; then
    return 0
  fi

  if [ ! -f "${__SM_LOG_FILE}" ]; then
    printf "timestamp|operation|details|decision|reason|user|hostname|pid\n" > "${__SM_LOG_FILE}"
  fi

  _sm_log_event "SM_INIT" "Security Monitor started" "ALLOW" "Active"
}

_sm_log_event() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf "%s|%s|%s|%s|%s|%s|%s|%s\n" "$ts" "$1" "$2" "$3" "$4" \
    "$(_get_current_user 2>/dev/null || echo unknown)" \
    "${__UAC_HOSTNAME:-$(hostname)}" "$$" >> "${__SM_LOG_FILE}"
}

_sm_check_binary_integrity() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local bin="$1"
  local wl="${__SM_POLICY_DIR}/bin_whitelist.txt"
  [ ! -f "$wl" ] && return 0
  [ ! -f "$bin" ] && { _sm_log_event "BINARY" "$bin" "BLOCK" "missing"; return 1; }
  local h=$(sha256sum "$bin" 2>/dev/null | awk '{print $1}')
  grep -q "^${bin}:${h}$" "$wl" && { _sm_log_event "BINARY" "$bin" "ALLOW" "ok"; return 0; }
  _sm_log_event "BINARY" "$bin" "BLOCK" "bad hash"; return 1
}

_sm_check_profile_integrity() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local p="$1"
  local al="${__SM_POLICY_DIR}/allowed_profiles.txt"
  [ ! -f "$p" ] && { _sm_log_event "PROFILE" "$p" "BLOCK" "missing"; return 1; }
  if [ -f "$al" ]; then
    local name=$(basename "$p" .yaml)
    grep -qE "^(${name}|${p})$" "$al" || { _sm_log_event "PROFILE" "$p" "BLOCK" "not allowed"; return 1; }
  fi
  _sm_log_event "PROFILE" "$p" "ALLOW" "ok"; return 0
}

_sm_authorize() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  case "$1" in
    load_profile)      _sm_check_profile_integrity "$2" || return 1 ;;
    execute_binary)    _sm_check_binary_integrity "$2" || return 1 ;;
    start_collection)  _sm_log_event "start_collection" "$2" "ALLOW" "ok" ;;
    before_manifest)   _sm_log_event "PRE_MANIFEST" "check" "ALLOW" "ok" ;;
    *)                 _sm_log_event "$1" "$*" "ALLOW" "default" ;;
  esac
  return 0
}

_sm_generate_bin_whitelist() {
  local dir="${__SM_POLICY_DIR:-./security/policies}"
  mkdir -p "$dir"
  local wl="$dir/bin_whitelist.txt"
  > "$wl"
  find "${__UAC_DIR:-.}/bin" -type f -executable 2>/dev/null | while read f; do
    echo "$f:$(sha256sum "$f" | awk '{print $1}')" >> "$wl"
  done
  echo "Whitelist создан: $wl"
}

if [ -n "${__UAC_DIR:-}" ] || [ -f "./uac" ]; then
  _sm_init
fi

# Перемещает лог монитора в uac-data.tmp, если он был создан в /tmp
_sm_move_log_to_output() {
  if [ -n "${__UAC_TEMP_DATA_DIR:-}" ] && [ -f "/tmp/uac_security_monitor_audit.log" ]; then
    mv "/tmp/uac_security_monitor_audit.log" "${__UAC_TEMP_DATA_DIR}/uac_security_monitor_audit.log" 2>/dev/null || true
    __SM_LOG_FILE="${__UAC_TEMP_DATA_DIR}/uac_security_monitor_audit.log"
  fi
}

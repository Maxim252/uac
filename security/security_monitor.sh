#!/bin/sh
# security/security_monitor.sh
# Security Monitor v1.8 — Кибериммунный слой для UAC
# ВКР: Мосейчук М.Л., ЮФУ, 2026

__SM_INITIALIZED=0
__SM_VERSION="1.8-kiberimmune"

_sm_init() {
  if [ "${__SM_INITIALIZED}" = "1" ]; then
    return 0
  fi

  __SM_ENABLED="${UAC_SECURITY_MONITOR:-1}"

  if [ -n "${__UAC_DIR:-}" ]; then
    __SM_POLICY_DIR="${__UAC_DIR}/security/policies"
  else
    __SM_POLICY_DIR="./security/policies"
  fi

  if [ -n "${__UAC_TEMP_DATA_DIR:-}" ]; then
    __SM_LOG_FILE="${__UAC_TEMP_DATA_DIR}/uac_security_monitor_audit.log"
  else
    __SM_LOG_FILE="/tmp/uac_security_monitor_audit.log"
  fi

  mkdir -p "${__SM_POLICY_DIR}" 2>/dev/null || true

  if [ "${__SM_ENABLED}" != "1" ]; then
    __SM_INITIALIZED=1
    return 0
  fi

  if [ ! -f "${__SM_LOG_FILE}" ]; then
    printf "timestamp|level|operation|details|decision|reason|user|hostname|pid|version\n" > "${__SM_LOG_FILE}"
  fi

  _sm_log_event "INFO" "SM_INIT" "Security Monitor started" "ALLOW" "Active" "${__SM_VERSION}"
  __SM_INITIALIZED=1
}

# Улучшенная функция логирования с уровнем
_sm_log_event() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local level="$1"
  local operation="$2"
  local details="$3"
  local decision="$4"
  local reason="$5"
  local version="${6:-${__SM_VERSION}}"
  local ts=$(date '+%Y-%m-%d %H:%M:%S')

  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
    "$ts" "$level" "$operation" "$details" "$decision" "$reason" \
    "$(_get_current_user 2>/dev/null || echo unknown)" \
    "${__UAC_HOSTNAME:-$(hostname)}" "$$" "$version" \
    >> "${__SM_LOG_FILE}"
}

_sm_check_binary_integrity() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local binary_path="$1"
  local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"

  if [ ! -f "$whitelist" ]; then
    _sm_log_event "INFO" "BINARY_CHECK" "$binary_path" "ALLOW" "No whitelist" ""
    return 0
  fi

  if [ ! -f "$binary_path" ]; then
    _sm_log_event "WARN" "BINARY_CHECK" "$binary_path" "BLOCK" "File missing" ""
    return 1
  fi

  local current_hash
  current_hash=$(sha256sum "$binary_path" 2>/dev/null | awk '{print $1}')

  if grep -q "^${binary_path}:${current_hash}$" "$whitelist" 2>/dev/null; then
    _sm_log_event "INFO" "BINARY_CHECK" "$binary_path" "ALLOW" "Hash verified" ""
    return 0
  else
    _sm_log_event "BLOCK" "BINARY_CHECK" "$binary_path" "BLOCK" "Integrity violation" ""
    return 1
  fi
}

_sm_check_profile_integrity() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local profile_path="$1"

  if [ ! -f "$profile_path" ]; then
    _sm_log_event "WARN" "PROFILE_CHECK" "$profile_path" "BLOCK" "Profile missing" ""
    return 1
  fi

  local allowed="${__SM_POLICY_DIR}/allowed_profiles.txt"
  if [ -f "$allowed" ]; then
    local pname=$(basename "$profile_path" .yaml)
    if ! grep -qE "^(${pname}|${profile_path})$" "$allowed" 2>/dev/null; then
      _sm_log_event "BLOCK" "PROFILE_CHECK" "$profile_path" "BLOCK" "Profile not allowed" ""
      return 1
    fi
  fi

  _sm_log_event "INFO" "PROFILE_CHECK" "$profile_path" "ALLOW" "Authorized" ""
  return 0
}

_sm_authorize() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local operation="$1"
  shift
  local details="$*"

  case "$operation" in
    load_profile)
      _sm_check_profile_integrity "$details" || return 1 ;;
    execute_binary)
      _sm_check_binary_integrity "$1" || return 1 ;;
    config_loaded|artifact_list_built|collection_phase_start|collection_phase_finished|output_preparation)
      _sm_log_event "INFO" "$operation" "$details" "ALLOW" "ok" "" ;;
    before_final_packaging)
      _sm_log_event "INFO" "before_final_packaging" "$details" "ALLOW" "Final check" "" ;;
    error_occurred)
      _sm_log_event "WARN" "error_occurred" "$details" "WARN" "Error detected" "" ;;
    *)
      _sm_log_event "INFO" "$operation" "$details" "ALLOW" "Default" "" ;;
  esac
  return 0
}

_sm_cleanup() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  _sm_log_event "INFO" "SM_CLEANUP" "Security Monitor session finished" "ALLOW" "Normal exit" ""
}

_sm_generate_bin_whitelist() {
  local dir="${__SM_POLICY_DIR:-./security/policies}"
  mkdir -p "$dir"
  local wl="$dir/bin_whitelist.txt"
  > "$wl"
  find "${__UAC_DIR:-.}/bin" -type f -executable 2>/dev/null | while read f; do
    echo "$f:$(sha256sum "$f" | awk '{print $1}')" >> "$wl"
  done
  _sm_log_event "INFO" "WHITELIST_GEN" "bin_whitelist.txt generated" "ALLOW" "Initial setup" ""
  echo "Whitelist создан: $wl"
}

if [ -n "${__UAC_DIR:-}" ] || [ -f "./uac" ]; then
  _sm_init
fi

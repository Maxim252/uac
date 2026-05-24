#!/bin/sh
# security/security_monitor.sh
# Security Monitor v1.12 — Кибериммунный слой для UAC
# Самопроверка при старте (бинарники + профиль)
# ВКР: Мосейчук М.Л., ЮФУ, 2026

__SM_INITIALIZED=0
__SM_VERSION="1.12-kiberimmune"

# ============================================================
# Portable SHA256 hash function (работает на Linux, macOS, FreeBSD, Solaris)
# ============================================================
_sm_get_sha256() {
    local file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 "$file" 2>/dev/null | awk '{print $1}'
    elif command -v digest >/dev/null 2>&1; then
        digest -a sha256 "$file" 2>/dev/null
    else
        echo "ERROR: No SHA256 tool found" >&2
        return 1
    fi
}

# ============================================================
# Проверка целостности бинарников (кросс-платформенная)
# ============================================================
_sm_check_binary_integrity() {
    [ "${__SM_ENABLED}" != "1" ] && return 0
    local binary_path="$1"
    local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"

    [ ! -f "$whitelist" ] && return 0
    [ ! -f "$binary_path" ] && { _sm_log_event "BLOCK" "BINARY_CHECK" "$binary_path" "BLOCK" "File missing" ""; return 1; }

    local bin_name current_hash
    bin_name=$(basename "$binary_path")
    current_hash=$(_sm_get_sha256 "$binary_path")

    if grep -qE "[:/]$bin_name:$current_hash$" "$whitelist" 2>/dev/null; then
        _sm_log_event "INFO" "BINARY_CHECK" "$bin_name" "ALLOW" "Hash verified" ""
        return 0
    else
        _sm_log_event "BLOCK" "BINARY_CHECK" "$bin_name" "BLOCK" "Integrity violation" ""
        return 1
    fi
}

# ============================================================
# Проверка целостности профиля
# ============================================================
_sm_check_profile_integrity() {
  [ "${__SM_ENABLED}" != "1" ] && return 0

  local profile_arg="$1"
     # === УМНОЕ АВТООПРЕДЕЛЕНИЕ ПРОФИЛЯ (чтобы не писать export) ===
  if [ -z "$profile_arg" ] || [ "$profile_arg" = "unknown" ]; then
    profile_arg="${__UAC_PROFILE:-${UAC_PROFILE:-${PROFILE:-}}}"

    if [ -z "$profile_arg" ] && [ -n "${__ua_command_line:-}" ]; then
      profile_arg=$(echo "$__ua_command_line" | grep -oE '(-p|--profile)[ =]+[^ ]+' | head -1 | sed 's/.*[ =]//')
    fi
  fi 
  local allowed="${__SM_POLICY_DIR}/allowed_profiles.txt"
  local pname
  pname=$(basename "$profile_arg" .yaml)

  [ ! -f "$allowed" ] && return 0

  local expected_line
  expected_line=$(grep -E "^${pname}(\.yaml)?:sha256:" "$allowed" 2>/dev/null | head -1)

  if [ -z "$expected_line" ]; then
    _sm_log_event "BLOCK" "PROFILE_CHECK" "$pname" "BLOCK" "Profile not in whitelist" ""
    return 1
  fi

  local profile_path=""
  for candidate in \
    "${__UAC_DIR}/profiles/${pname}.yaml" \
    "./profiles/${pname}.yaml" \
    "profiles/${pname}.yaml" \
    "${__SM_POLICY_DIR}/../profiles/${pname}.yaml"
  do
    [ -f "$candidate" ] && { profile_path="$candidate"; break; }
  done

  [ -z "$profile_path" ] && { _sm_log_event "BLOCK" "PROFILE_CHECK" "$pname" "BLOCK" "Profile file not found" ""; return 1; }

  local expected_hash current_hash
  expected_hash=$(echo "$expected_line" | cut -d: -f3)
  current_hash=$(sha256sum "$profile_path" 2>/dev/null | awk '{print $1}')

  if [ "$current_hash" != "$expected_hash" ]; then
    _sm_log_event "BLOCK" "PROFILE_CHECK" "$pname" "BLOCK" "Profile hash mismatch - possible tampering!" ""
    return 1
  fi

  _sm_log_event "INFO" "PROFILE_CHECK" "$pname" "ALLOW" "Hash verified" ""
  return 0
}

# ============================================================
# Автоматическая проверка профиля при старте монитора
# ============================================================
_sm_auto_check_active_profile() {
  [ "${__SM_ENABLED}" != "1" ] && return 0

  local profile="${__UAC_PROFILE:-}"

  if [ -z "$profile" ] && [ -n "${__ua_command_line:-}" ]; then
    profile=$(echo "$__ua_command_line" | grep -oE '\-p[ =]+[^ ]+' | head -1 | sed 's/^-p[ =]*//')
  fi

  [ -z "$profile" ] && return 0

  _sm_log_event "INFO" "AUTO_PROFILE_CHECK" "Auto-checking profile: $profile" "INFO" "Startup self-check" ""

  if ! _sm_check_profile_integrity "$profile"; then
    echo ""
    echo ">>> [SECURITY MONITOR] ПРОФИЛЬ ПОДМЕНЁН ИЛИ ПОВРЕЖДЁН — ЗАПУСК ОСТАНОВЛЕН <<<"
    echo ""
    _sm_log_event "BLOCK" "AUTO_PROFILE_CHECK" "$profile" "BLOCK" "Tampered profile detected at startup" ""
    exit 1
  fi

  _sm_log_event "INFO" "AUTO_PROFILE_CHECK" "$profile" "ALLOW" "Profile verified automatically" ""
}

# ============================================================
# Проверка всех бинарников при старте
# ============================================================
_sm_verify_critical_components() {
  [ "${__SM_ENABLED}" != "1" ] && return 0

  local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"

  if [ ! -f "$whitelist" ]; then
    _sm_log_event "WARN" "SELF_CHECK" "bin_whitelist.txt not found yet" "WARN" "First setup" ""
    return 0
  fi

  _sm_log_event "INFO" "SELF_CHECK" "Starting automatic binary integrity verification" "INFO" "Init phase" ""

  local checked=0 failed=0

  while IFS= read -r line || [ -n "$line" ]; do
    local bin_path
    bin_path=$(echo "$line" | cut -d: -f1)
    [ -z "$bin_path" ] && continue

    case "$bin_path" in
      /*) ;;
      *) [ -n "${__UAC_DIR:-}" ] && bin_path="${__UAC_DIR}/${bin_path}" ;;
    esac

    if [ -f "$bin_path" ]; then
      checked=$((checked + 1))
      _sm_check_binary_integrity "$bin_path" || failed=$((failed + 1))
    fi
  done < "$whitelist"

  if [ "$failed" -gt 0 ]; then
    _sm_log_event "BLOCK" "SELF_CHECK" "$failed binaries failed integrity check" "BLOCK" "Critical failure" ""
    echo "Security Monitor: Обнаружены повреждённые/подменённые бинарники ($failed). Работа остановлена." >&2
    exit 1
  fi

  _sm_log_event "INFO" "SELF_CHECK" "Startup check passed. Checked: $checked binaries" "ALLOW" "All good" ""
}

# ============================================================
# Логирование событий
# ============================================================
_sm_log_event() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local level="$1" operation="$2" details="$3" decision="$4" reason="$5"
  local version="${6:-${__SM_VERSION}}"
  local ts="$(date '+%Y-%m-%d %H:%M:%S')"

  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
    "$ts" "$level" "$operation" "$details" "$decision" "$reason" \
    "$(_get_current_user 2>/dev/null || echo unknown)" \
    "${__UAC_HOSTNAME:-$(hostname)}" "$$" "$version" \
    >> "${__SM_LOG_FILE}"
}

# ============================================================
# Централизованная авторизация (Default Deny)
# ============================================================
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
    config_loaded|artifact_list_built|collection_phase_start|collection_phase_finished|output_preparation|start_collection|before_manifest|before_final_packaging)
      _sm_log_event "INFO" "$operation" "$details" "ALLOW" "ok" "" ;;
    *)
      _sm_log_event "BLOCK" "$operation" "$details" "BLOCK" "Unknown operation - Default Deny" ""
      return 1 ;;
  esac
  return 0
}

# ============================================================
# Инициализация монитора (самопроверка)
# ============================================================
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

  _sm_log_event "INFO" "SM_INIT" "Security Monitor started (self-check mode)" "ALLOW" "Active" "${__SM_VERSION}"

  _sm_verify_critical_components
  _sm_auto_check_active_profile

  __SM_INITIALIZED=1
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

    find "${__UAC_DIR:-.}/bin" -type f 2>/dev/null | while read f; do
        local hash
        hash=$(_sm_get_sha256 "$f")
        echo "$f:$hash" >> "$wl"
    done
    echo "Whitelist создан: $wl"
}

# Автозапуск
if [ -n "${__UAC_DIR:-}" ] || [ -f "./uac" ]; then
  _sm_init
fi

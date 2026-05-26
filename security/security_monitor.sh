#!/bin/sh
# security/security_monitor.sh
# Security Monitor v1.13 — Cyber-immune integrity layer for UAC
# Self-check on startup (binaries + profiles)
# Improvements: fixed whitelist generator, consistent hashing, reduced duplication,
# better internationalization, UAC_REGENERATE_WHITELIST=1 support.
# Original concept: ВКР Мосейчук М.Л., ЮФУ, 2026

__SM_INITIALIZED=0
__SM_VERSION="1.13-improved"

# ============================================================
# Secret for signing whitelist files (tamper detection)
# This raises the bar against casual modification of the policy files.
# It is NOT a replacement for proper file permissions / package signing.
# ============================================================
__SM_WHITELIST_HMAC_SECRET="UAC-SM-2026-kiberimmune-v1.13"

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
# Tamper detection for whitelist files
# We compute a simple signature over the content using the embedded secret.
# This makes casual editing / substitution of the policy files detectable.
# ============================================================
_sm_compute_whitelist_signature() {
    local content="$1"
    # Simple HMAC-like construction using available SHA256
    printf "%s%s" "$content" "$__SM_WHITELIST_HMAC_SECRET" | _sm_get_sha256 /dev/stdin 2>/dev/null || echo "SIG-ERROR"
}

_sm_verify_whitelist_file() {
    local whitelist="$1"
    [ ! -f "$whitelist" ] && return 0

    # Read all lines except the last one
    local content sig_line expected_sig computed_sig

    content=$(sed '$d' "$whitelist" 2>/dev/null)
    sig_line=$(tail -1 "$whitelist" 2>/dev/null)

    case "$sig_line" in
        ___SM_WHITELIST_SIG___:sha256:*)
            expected_sig=$(echo "$sig_line" | cut -d: -f3)
            computed_sig=$(_sm_compute_whitelist_signature "$content")

            if [ "$computed_sig" = "$expected_sig" ]; then
                return 0
            else
                _sm_log_event "BLOCK" "WHITELIST" "$(basename "$whitelist")" "BLOCK" "Signature mismatch - possible tampering" ""
                return 1
            fi
            ;;
        *)
            # No signature present - for backward compatibility we allow it (with warning)
            # In future versions we can make signature mandatory
            _sm_log_event "WARN" "WHITELIST" "$(basename "$whitelist")" "WARN" "No signature found (legacy file?)" ""
            return 0
            ;;
    esac
}

# ============================================================
# Проверка целостности критически важных shell-скриптов UAC
# (включая сам Security Monitor, update_whitelists.sh и entrypoint uac)
# Решает проблему "курицы и яйца" — монитор теперь может проверять сам себя
# после того, как он загружен, а bootstrap-проверка в uac защищает до загрузки.
# ============================================================
_sm_verify_core_scripts_whitelist() {
    local wl="${__SM_POLICY_DIR}/core_scripts_whitelist.txt"
    _sm_verify_whitelist_file "$wl"
}

_sm_check_core_script_integrity() {
    [ "${__SM_ENABLED}" != "1" ] && return 0

    local rel_path="$1"
    local wl="${__SM_POLICY_DIR}/core_scripts_whitelist.txt"

    if ! _sm_verify_core_scripts_whitelist; then
        _sm_log_event "BLOCK" "CORE_SCRIPT_CHECK" "$rel_path" "BLOCK" "Core scripts whitelist is tampered" ""
        return 1
    fi

    [ ! -f "$wl" ] && return 0

    local expected_line expected_hash current_hash full_path
    # Support both "uac" and "./uac" forms
    expected_line=$(grep -E "^(\./)?${rel_path}:sha256:" "$wl" 2>/dev/null | head -1)

    if [ -z "$expected_line" ]; then
        _sm_log_event "BLOCK" "CORE_SCRIPT_CHECK" "$rel_path" "BLOCK" "Script not in core whitelist" ""
        return 1
    fi

    expected_hash=$(echo "$expected_line" | cut -d: -f3)

    # Resolve full filesystem path
    case "$rel_path" in
        /*) full_path="$rel_path" ;;
        *)  full_path="${__UAC_DIR}/${rel_path}" ;;
    esac

    [ ! -f "$full_path" ] && {
        _sm_log_event "BLOCK" "CORE_SCRIPT_CHECK" "$rel_path" "BLOCK" "File missing" ""
        return 1
    }

    current_hash=$(_sm_get_sha256 "$full_path")

    if [ "$current_hash" != "$expected_hash" ]; then
        _sm_log_event "BLOCK" "CORE_SCRIPT_CHECK" "$rel_path" "BLOCK" "Core script hash mismatch - possible tampering!" ""
        return 1
    fi

    _sm_log_event "INFO" "CORE_SCRIPT_CHECK" "$rel_path" "ALLOW" "Hash verified" ""
    return 0
}

# ============================================================
# Проверка целостности бинарников (кросс-платформенная)
# ============================================================
_sm_check_binary_integrity() {
    [ "${__SM_ENABLED}" != "1" ] && return 0
    local binary_path="$1"
    local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"

    if ! _sm_verify_whitelist_file "$whitelist"; then
        _sm_log_event "BLOCK" "BINARY_CHECK" "$binary_path" "BLOCK" "Whitelist file is tampered" ""
        return 1
    fi

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

  local profile_arg
  profile_arg=$(_sm_resolve_profile_arg "$1")

  local allowed="${__SM_POLICY_DIR}/allowed_profiles.txt"
  local pname
  pname=$(basename "$profile_arg" .yaml)

  # No active profile context (common in unit tests / direct _sm_authorize calls).
  # Treat as non-fatal for continuous checks — the init-time self-checks already covered startup.
  # We still want command execution to be logged for audit visibility.
  if [ -z "$pname" ] || [ "$pname" = "." ] || [ "$pname" = "unknown" ]; then
    return 0
  fi

  if ! _sm_verify_whitelist_file "$allowed"; then
      _sm_log_event "BLOCK" "PROFILE_CHECK" "$pname" "BLOCK" "Profile whitelist is tampered" ""
      return 1
  fi

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
  current_hash=$(_sm_get_sha256 "$profile_path")

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

  local profile
  profile=$(_sm_resolve_profile_arg "${__UAC_PROFILE:-}")

  [ -z "$profile" ] && return 0

  _sm_log_event "INFO" "AUTO_PROFILE_CHECK" "Auto-checking profile: $profile" "INFO" "Startup self-check" ""

  if ! _sm_check_profile_integrity "$profile"; then
    echo ""
    echo ">>> [SECURITY MONITOR] PROFILE TAMPERED OR DAMAGED — ABORTING <<<"
    echo ""
    _sm_log_event "BLOCK" "AUTO_PROFILE_CHECK" "$profile" "BLOCK" "Tampered profile detected at startup" ""
    exit 1
  fi

  _sm_log_event "INFO" "AUTO_PROFILE_CHECK" "$profile" "ALLOW" "Profile verified automatically" ""
}

# Helper: resolve profile name from argument or command line (reduces duplication)
_sm_resolve_profile_arg() {
    local arg="$1"

    if [ -z "$arg" ] || [ "$arg" = "unknown" ]; then
        arg="${__UAC_PROFILE:-${UAC_PROFILE:-${PROFILE:-}}}"

        if [ -z "$arg" ] && [ -n "${__ua_command_line:-}" ]; then
            # Try --profile first, then -p
            arg=$(echo "$__ua_command_line" | grep -oE '(--profile|-p)[ =]+[^ ]+' | head -1 | sed -E 's/.*[ =]//')
        fi
    fi

    echo "$arg" | sed 's/\.yaml$//'
}

# ============================================================
# Проверка всех бинарников при старте
# ============================================================
_sm_verify_critical_components() {
  [ "${__SM_ENABLED}" != "1" ] && return 0

  local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"

  if ! _sm_verify_whitelist_file "$whitelist"; then
      echo "Security Monitor: bin_whitelist.txt signature verification failed!" >&2
      _sm_log_event "BLOCK" "SELF_CHECK" "bin_whitelist" "BLOCK" "Tampered whitelist at startup" ""
      return 1
  fi

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
    echo "Security Monitor: $failed binary file(s) failed integrity check. Aborting." >&2
    exit 1
  fi

  _sm_log_event "INFO" "SELF_CHECK" "Startup check passed. Checked: $checked binaries" "ALLOW" "All good" ""

  # === NEW: Check core UAC scripts (uac entrypoint + Security Monitor + critical libs) ===
  local core_wl="${__SM_POLICY_DIR}/core_scripts_whitelist.txt"
  if [ -f "$core_wl" ]; then
    if ! _sm_verify_core_scripts_whitelist; then
      echo "Security Monitor: core_scripts_whitelist.txt signature verification failed!" >&2
      _sm_log_event "BLOCK" "SELF_CHECK" "core_scripts_whitelist" "BLOCK" "Tampered core scripts whitelist at startup" ""
      return 1
    fi

    _sm_log_event "INFO" "SELF_CHECK" "Starting core scripts integrity verification (uac + security layer)" "INFO" "Init phase" ""

    local core_checked=0
    local core_failed=0

    while IFS= read -r line || [ -n "$line" ]; do
      local script_rel
      script_rel=$(echo "$line" | cut -d: -f1)
      [ -z "$script_rel" ] && continue
      case "$script_rel" in
        ___SM_WHITELIST_SIG___*) break ;;
        *)
          script_rel=$(echo "$script_rel" | sed 's|^./||')
          if [ -f "${__UAC_DIR}/${script_rel}" ]; then
            core_checked=$((core_checked + 1))
            _sm_check_core_script_integrity "$script_rel" || core_failed=$((core_failed + 1))
          fi
          ;;
      esac
    done < "$core_wl"

    if [ "$core_failed" -gt 0 ]; then
      _sm_log_event "BLOCK" "SELF_CHECK" "$core_failed core script(s) failed integrity check" "BLOCK" "Critical failure (core scripts)" ""
      echo "Security Monitor: $core_failed core script file(s) failed integrity check. Aborting." >&2
      exit 1
    fi

    _sm_log_event "INFO" "SELF_CHECK" "Core scripts OK. Checked: $core_checked files (uac + monitor + libs)" "ALLOW" "All good" ""
  fi
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
# Непрерывный контроль целостности (Continuous Integrity Monitoring)
# ============================================================
_sm_continuous_integrity_check() {
  [ "${__SM_ENABLED}" != "1" ] && return 0

  # Re-verify the active profile
  if ! _sm_check_profile_integrity ""; then
    _sm_log_event "BLOCK" "CONTINUOUS_CHECK" "profile" "BLOCK" "Profile integrity failed during continuous check" ""
    return 1
  fi

  # Re-verify critical binaries (only if whitelist exists)
  local whitelist="${__SM_POLICY_DIR}/bin_whitelist.txt"
  if [ -f "$whitelist" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      local bin_path
      bin_path=$(echo "$line" | cut -d: -f1)
      [ -z "$bin_path" ] && continue

      case "$bin_path" in
        /*) ;;
        *) [ -n "${__UAC_DIR:-}" ] && bin_path="${__UAC_DIR}/${bin_path}" ;;
      esac

      if [ -f "$bin_path" ]; then
        if ! _sm_check_binary_integrity "$bin_path"; then
          _sm_log_event "BLOCK" "CONTINUOUS_CHECK" "$bin_path" "BLOCK" "Binary integrity failed during continuous check" ""
          return 1
        fi
      fi
    done < "$whitelist"
  fi

  # Re-verify core UAC scripts (uac + security_monitor + critical libs)
  local core_wl="${__SM_POLICY_DIR}/core_scripts_whitelist.txt"
  if [ -f "$core_wl" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      local script_rel
      script_rel=$(echo "$line" | cut -d: -f1)
      [ -z "$script_rel" ] && continue
      case "$script_rel" in
        ___SM_WHITELIST_SIG___*) break ;;
        *)
          script_rel=$(echo "$script_rel" | sed 's|^./||')
          if [ -f "${__UAC_DIR}/${script_rel}" ]; then
            if ! _sm_check_core_script_integrity "$script_rel"; then
              _sm_log_event "BLOCK" "CONTINUOUS_CHECK" "$script_rel" "BLOCK" "Core script integrity failed during continuous check" ""
              return 1
            fi
          fi
          ;;
      esac
    done < "$core_wl"
  fi

  return 0
}

# ============================================================
# Централизованная авторизация (Default Deny)
# ============================================================
_sm_authorize() {
  [ "${__SM_ENABLED}" != "1" ] && return 0
  local operation="$1"
  shift
  local details="$*"

  # Perform continuous integrity check before high-risk operations
  case "$operation" in
    execute_binary|before_final_packaging|collection_phase_start)
      # Heavy operations: full profile + binary re-check
      if ! _sm_continuous_integrity_check; then
        _sm_log_event "BLOCK" "$operation" "$details" "BLOCK" "Continuous integrity check failed" ""
        return 1
      fi
      ;;
    execute_artifact_command)
      # High-frequency path (every artifact command): light check only (profile)
      # Full binary re-scan is too expensive to do on every single command
      if ! _sm_check_profile_integrity ""; then
        _sm_log_event "BLOCK" "CONTINUOUS_CHECK" "profile" "BLOCK" "Profile integrity failed during command execution" ""
        return 1
      fi
      ;;
  esac

  case "$operation" in
    load_profile)
      _sm_check_profile_integrity "$details" || return 1 ;;
    execute_binary)
      _sm_check_binary_integrity "$1" || return 1 ;;
    execute_artifact_command)
      # Log every command that comes from profiles/artifacts (high visibility)
      # Future: could add command allow-listing or dangerous pattern detection here
      _sm_log_event "INFO" "$operation" "$details" "ALLOW" "profile command execution" "" ;;
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

  # Optional: regenerate whitelist on demand (very useful after UAC updates or adding custom tools)
  if [ "${UAC_REGENERATE_WHITELIST:-0}" = "1" ]; then
      _sm_generate_bin_whitelist
  fi

  _sm_verify_critical_components
  _sm_auto_check_active_profile

  _sm_log_event "INFO" "SM_INIT" "Audit log: ${__SM_LOG_FILE}" "ALLOW" "Initialized" ""

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

    # Use a temporary file + atomic move to avoid subshell redirection issues
    local tmp_wl="${wl}.tmp.$$"
    > "$tmp_wl"

    find "${__UAC_DIR:-.}/bin" -type f 2>/dev/null | while IFS= read -r f; do
        [ -f "$f" ] || continue
        local hash
        hash=$(_sm_get_sha256 "$f")
        if [ -n "$hash" ] && [ "$hash" != "ERROR: No SHA256 tool found" ]; then
            echo "$f:$hash" >> "$tmp_wl"
        fi
    done

    # Sort for determinism
    sort -o "$tmp_wl" "$tmp_wl" 2>/dev/null || true

    # Append tamper-evident signature
    local content sig
    content=$(cat "$tmp_wl")
    sig=$(_sm_compute_whitelist_signature "$content")
    echo "___SM_WHITELIST_SIG___:sha256:${sig}" >> "$tmp_wl"

    mv "$tmp_wl" "$wl" 2>/dev/null || cp "$tmp_wl" "$wl"
    rm -f "$tmp_wl" 2>/dev/null || true

    echo "Binary whitelist regenerated: $wl"
    _sm_log_event "INFO" "WHITELIST_GEN" "$wl" "ALLOW" "Whitelist updated" ""
}

# Автозапуск
if [ -n "${__UAC_DIR:-}" ] || [ -f "./uac" ]; then
  _sm_init
fi

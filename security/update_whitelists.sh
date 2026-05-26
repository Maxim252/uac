#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# security/update_whitelists.sh
#
# Convenient maintenance script for Security Monitor whitelists.
#
# Usage:
#   ./security/update_whitelists.sh [options]
#
# Options:
#   --profiles     Update profiles whitelist (allowed_profiles.txt)
#   --binaries     Update binaries whitelist (bin_whitelist.txt)
#   --all          Update both (default behavior if no option is given)
#   --dry-run      Show changes that would be made without writing files
#   --help         Show this help
#
# This script creates timestamped backups before modifying files.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
UAC_ROOT=$(dirname "$SCRIPT_DIR")
POLICIES_DIR="${UAC_ROOT}/security/policies"
PROFILES_DIR="${UAC_ROOT}/profiles"

# Colors (if supported)
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    RED=$(tput setaf 1)
    RESET=$(tput sgr0)
else
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi

log_info()    { printf "%s[INFO]%s    %s\n"    "$GREEN"  "$RESET" "$*"; }
log_warn()    { printf "%s[WARN]%s    %s\n"    "$YELLOW" "$RESET" "$*"; }
log_error()   { printf "%s[ERROR]%s   %s\n"    "$RED"    "$RESET" "$*" >&2; }
log_success() { printf "%s[SUCCESS]%s %s\n"    "$GREEN"  "$RESET" "$*"; }

print_help() {
    cat << EOF
Security Monitor Whitelist Update Script

Usage:
  $(basename "$0") [options]

Options:
  --profiles     Update allowed_profiles.txt with current profile hashes
  --binaries     Regenerate bin_whitelist.txt from current bin/ directory
  --all          Update both profiles and binaries (default)
  --dry-run      Show what would be changed without modifying any files
  --help         Show this help message

The script always creates a timestamped backup of the files it is about to modify.
EOF
}

get_sha256() {
    file="$1"

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

backup_file() {
    file="$1"
    if [ -f "$file" ]; then
        ts=$(date +%Y%m%d-%H%M%S)
        backup="${file}.bak-${ts}"
        cp "$file" "$backup"
        log_info "Backup created: $backup"
    fi
}

update_profiles() {
    dry_run="$1"
    output_file="${POLICIES_DIR}/allowed_profiles.txt"

    log_info "Scanning profiles in: $PROFILES_DIR"

    if [ ! -d "$PROFILES_DIR" ]; then
        log_error "Profiles directory not found: $PROFILES_DIR"
        return 1
    fi

    tmpfile=$(mktemp)
    count=0

    for profile in "$PROFILES_DIR"/*.yaml; do
        [ -f "$profile" ] || continue

        name=$(basename "$profile" .yaml)
        hash=$(get_sha256 "$profile")

        if [ -z "$hash" ] || [ "$hash" = "ERROR: No SHA256 tool found" ]; then
            log_warn "Failed to hash: $profile"
            continue
        fi

        echo "${name}:sha256:${hash}" >> "$tmpfile"
        count=$((count + 1))
        log_info "  ${name} -> ${hash}"
    done

    if [ "$count" -eq 0 ]; then
        log_error "No profiles found or hashed."
        rm -f "$tmpfile"
        return 1
    fi

    # Sort for consistency
    sort -o "$tmpfile" "$tmpfile"

    # Append tamper-evident signature (same logic as security_monitor.sh)
    local secret="UAC-SM-2026-kiberimmune-v1.13"
    local content sig
    content=$(cat "$tmpfile")
    # Portable signature using available sha256 tool
    if command -v sha256sum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | sha256sum 2>/dev/null | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | shasum -a 256 2>/dev/null | awk '{print $1}')
    else
        sig=$(printf "%s%s" "$content" "$secret" | sha256 2>/dev/null | awk '{print $1}')
    fi

    echo "___SM_WHITELIST_SIG___:sha256:${sig}" >> "$tmpfile"

    if [ "$dry_run" = "yes" ]; then
        log_warn "DRY-RUN: Would write the following to ${output_file}:"
        cat "$tmpfile"
        rm -f "$tmpfile"
        return 0
    fi

    backup_file "$output_file"
    mv "$tmpfile" "$output_file"
    chmod 644 "$output_file"

    log_success "Updated ${output_file} with ${count} profile(s)."
}

update_binaries() {
    dry_run="$1"
    output_file="${POLICIES_DIR}/bin_whitelist.txt"

    log_info "Scanning binaries in: ${UAC_ROOT}/bin"

    if [ ! -d "${UAC_ROOT}/bin" ]; then
        log_error "bin/ directory not found"
        return 1
    fi

    tmpfile=$(mktemp)
    count=0

    # Use find + portable hash (same logic as security_monitor.sh)
    find "${UAC_ROOT}/bin" -type f 2>/dev/null | while IFS= read -r f; do
        [ -f "$f" ] || continue
        hash=$(get_sha256 "$f")

        if [ -n "$hash" ] && [ "$hash" != "ERROR: No SHA256 tool found" ]; then
            # Store relative path for consistency with existing behavior
            rel_path=$(echo "$f" | sed "s|^${UAC_ROOT}/|./|")
            echo "${rel_path}:${hash}" >> "$tmpfile"
            count=$((count + 1))
        fi
    done

    # Count lines after the loop (the while loop runs in subshell)
    total=$(wc -l < "$tmpfile" 2>/dev/null || echo 0)

    if [ "$total" -eq 0 ]; then
        log_error "No binaries were hashed."
        rm -f "$tmpfile"
        return 1
    fi

    sort -o "$tmpfile" "$tmpfile"

    # Append tamper-evident signature
    local secret="UAC-SM-2026-kiberimmune-v1.13"
    local content sig
    content=$(cat "$tmpfile")
    if command -v sha256sum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | sha256sum 2>/dev/null | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | shasum -a 256 2>/dev/null | awk '{print $1}')
    else
        sig=$(printf "%s%s" "$content" "$secret" | sha256 2>/dev/null | awk '{print $1}')
    fi
    echo "___SM_WHITELIST_SIG___:sha256:${sig}" >> "$tmpfile"

    if [ "$dry_run" = "yes" ]; then
        log_warn "DRY-RUN: Would write ${total} entries to ${output_file}"
        head -10 "$tmpfile"
        [ "$total" -gt 10 ] && echo "..."
        rm -f "$tmpfile"
        return 0
    fi

    backup_file "$output_file"
    mv "$tmpfile" "$output_file"
    chmod 644 "$output_file"

    log_success "Regenerated ${output_file} with ${total} entries."
}

update_core_scripts() {
    dry_run="$1"
    output_file="${POLICIES_DIR}/core_scripts_whitelist.txt"

    log_info "Scanning core UAC scripts (entrypoint + security layer + critical libs)"

    tmpfile=$(mktemp)
    count=0

    # Explicit list of critical scripts that must be protected (same set as in security_monitor.sh)
    local core_scripts="
uac
security/security_monitor.sh
security/update_whitelists.sh
lib/exit_fatal.sh
lib/load_libraries.sh
lib/log_msg.sh
lib/parse_command_line_arguments.sh
lib/parse_profile.sh
lib/validate_profile.sh
"

    for rel in $core_scripts; do
        local full="${UAC_ROOT}/${rel}"
        [ -f "$full" ] || { log_warn "Core script not found, skipping: $rel"; continue; }

        local hash
        hash=$(get_sha256 "$full")
        if [ -z "$hash" ] || [ "$hash" = "ERROR: No SHA256 tool found" ]; then
            log_warn "Failed to hash core script: $rel"
            continue
        fi

        echo "${rel}:sha256:${hash}" >> "$tmpfile"
        count=$((count + 1))
        log_info "  ${rel} -> ${hash}"
    done

    if [ "$count" -eq 0 ]; then
        log_error "No core scripts were hashed."
        rm -f "$tmpfile"
        return 1
    fi

    # Sort for determinism (consistent with other whitelists)
    sort -o "$tmpfile" "$tmpfile"

    # Append tamper-evident signature (identical algorithm)
    local secret="UAC-SM-2026-kiberimmune-v1.13"
    local content sig
    content=$(cat "$tmpfile")
    if command -v sha256sum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | sha256sum 2>/dev/null | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        sig=$(printf "%s%s" "$content" "$secret" | shasum -a 256 2>/dev/null | awk '{print $1}')
    else
        sig=$(printf "%s%s" "$content" "$secret" | sha256 2>/dev/null | awk '{print $1}')
    fi
    echo "___SM_WHITELIST_SIG___:sha256:${sig}" >> "$tmpfile"

    if [ "$dry_run" = "yes" ]; then
        log_warn "DRY-RUN: Would write the following to ${output_file}:"
        cat "$tmpfile"
        rm -f "$tmpfile"
        return 0
    fi

    backup_file "$output_file"
    mv "$tmpfile" "$output_file"
    chmod 644 "$output_file"

    log_success "Regenerated ${output_file} with ${count} core script(s)."
}

# ====================== Main ======================

DRY_RUN="no"
DO_PROFILES="no"
DO_BINARIES="no"
DO_CORE="no"

if [ $# -eq 0 ]; then
    DO_PROFILES="yes"
    DO_BINARIES="yes"
    DO_CORE="yes"
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --profiles)
            DO_PROFILES="yes"
            ;;
        --binaries)
            DO_BINARIES="yes"
            ;;
        --core-scripts)
            DO_CORE="yes"
            ;;
        --all)
            DO_PROFILES="yes"
            DO_BINARIES="yes"
            DO_CORE="yes"
            ;;
        --dry-run)
            DRY_RUN="yes"
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
    shift
done

echo "Security Monitor Whitelist Updater"
echo "UAC root: $UAC_ROOT"
echo

mkdir -p "$POLICIES_DIR"

if [ "$DO_PROFILES" = "yes" ]; then
    echo "=== Updating Profiles Whitelist ==="
    update_profiles "$DRY_RUN"
    echo
fi

if [ "$DO_BINARIES" = "yes" ]; then
    echo "=== Updating Binaries Whitelist ==="
    update_binaries "$DRY_RUN"
    echo
fi

if [ "$DO_CORE" = "yes" ]; then
    echo "=== Updating Core Scripts Whitelist ==="
    update_core_scripts "$DRY_RUN"
    echo
fi

if [ "$DRY_RUN" = "yes" ]; then
    log_warn "DRY-RUN completed. No files were modified."
else
    log_success "Whitelist update completed."
    log_info "You can verify the changes with:"
    log_info "  cat security/policies/allowed_profiles.txt"
    log_info "  head -20 security/policies/bin_whitelist.txt"
    log_info "  cat security/policies/core_scripts_whitelist.txt"
fi

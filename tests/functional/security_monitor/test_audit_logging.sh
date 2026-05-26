#!/bin/sh
# Тесты поведения журналирования аудита Монитора безопасности
# Требования:
# - Журнал аудита создаётся
# - Важные события журналируются (SM_INIT, execute_artifact_command, PROFILE_CHECK и др.)
# - Формат журнала согласован

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
TEST_TMP=$(mktemp -d /tmp/uac-test-audit-XXXXXX)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[УСПЕХ]${NC} $1"; }
fail() { echo -e "${RED}[ПРОВАЛ]${NC} $1"; FAILED=1; }

FAILED=0
cleanup() { rm -rf "$TEST_TMP"; }
trap cleanup EXIT

echo "=== Монитор безопасности — Тесты журналирования аудита ==="

export __UAC_DIR="$PROJECT_ROOT"
export __UAC_TEMP_DATA_DIR="$TEST_TMP"

. "$PROJECT_ROOT/security/security_monitor.sh" 2>/dev/null || true
_sm_init >/dev/null 2>&1 || true

# Use real signed policy files + active profile so the full verification path is exercised
export __UAC_PROFILE="full"
# Do not override __SM_POLICY_DIR — let it default to $PROJECT_ROOT/security/policies (real signed data)

LOG_FILE="${__SM_LOG_FILE:-$TEST_TMP/uac_security_monitor_audit.log}"

# Force some events
_sm_log_event "INFO" "TEST_EVENT" "test details" "ALLOW" "unit test" 2>/dev/null || true
_sm_authorize "execute_artifact_command" "cat /etc/passwd" 2>/dev/null || true
_sm_authorize "PROFILE_CHECK" "full" 2>/dev/null || true

echo ""
echo "[Тест 1] Файл журнала аудита создаётся после работы монитора"

if [ -f "$LOG_FILE" ]; then
    pass "Файл журнала аудита создан"
    LOG_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    echo "  В журнале $LOG_LINES строк"
else
    fail "Файл журнала аудита не создан"
fi

echo ""
echo "[Тест 2] В журнале присутствуют важные события"

if [ -f "$LOG_FILE" ]; then
    if grep -q "SM_INIT" "$LOG_FILE"; then
        pass "Событие SM_INIT зафиксировано в журнале"
    else
        fail "Событие SM_INIT отсутствует в журнале аудита"
    fi

    if grep -q "execute_artifact_command" "$LOG_FILE"; then
        pass "События execute_artifact_command журналируются"
    else
        fail "Записи execute_artifact_command не найдены"
    fi
else
    fail "Невозможно проверить события — файл журнала отсутствует"
fi

echo ""
echo "[Тест 3] Формат журнала содержит ожидаемые поля"

if [ -f "$LOG_FILE" ]; then
    HEADER=$(head -1 "$LOG_FILE")
    if echo "$HEADER" | grep -q "timestamp|level|operation|details|decision"; then
        pass "Заголовок журнала аудита имеет ожидаемый формат с разделителем |"
    else
        fail "Формат заголовка журнала аудита некорректен"
    fi
else
    fail "Файл журнала отсутствует для проверки формата"
fi

echo ""
echo "[Тест 4] Журнал дописывается (не перезаписывается)"

if [ -f "$LOG_FILE" ]; then
    BEFORE=$(wc -l < "$LOG_FILE")
    _sm_log_event "INFO" "APPEND_TEST" "append check" "ALLOW" "test" 2>/dev/null || true
    AFTER=$(wc -l < "$LOG_FILE")

    if [ "$AFTER" -gt "$BEFORE" ]; then
        pass "Журнал дописывается (увеличился с $BEFORE до $AFTER строк)"
    else
        fail "Журнал не дописывается корректно"
    fi
fi

if [ "$FAILED" -eq 0 ]; then
    echo ""
    echo "=== Все тесты журналирования аудита пройдены ==="
else
    echo ""
    echo "=== Некоторые тесты журналирования аудита провалены ==="
    exit 1
fi
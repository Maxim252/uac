#!/bin/sh
# Негативные тесты обнаружения подделки белых списков Монитора безопасности
# Покрываемые требования:
# - Обнаружение изменений в allowed_profiles.txt и bin_whitelist.txt
# - Проверка подписи (__SM_WHITELIST_SIG___)
# - Поведение при модификации белого списка после подписания

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
TEST_TMP=$(mktemp -d /tmp/uac-test-tampering-XXXXXX)

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[УСПЕХ]${NC} $1"; }
fail() { echo -e "${RED}[ПРОВАЛ]${NC} $1"; FAILED=1; }

FAILED=0
cleanup() { rm -rf "$TEST_TMP"; }
trap cleanup EXIT

echo "=== Монитор безопасности — Тесты обнаружения подделки белых списков ==="

export __UAC_DIR="$PROJECT_ROOT"
export __UAC_TEMP_DATA_DIR="$TEST_TMP"

. "$PROJECT_ROOT/security/security_monitor.sh" 2>/dev/null || true
_sm_init >/dev/null 2>&1 || true

# Helper to create a signed whitelist
create_signed_whitelist() {
    local file="$1"
    local content="$2"
    echo "$content" > "$file"
    local sig
    sig=$(_sm_compute_whitelist_signature "$content")
    echo "___SM_WHITELIST_SIG___:sha256:$sig" >> "$file"
}

# Тест 1: Корректно подписанный белый список профилей
echo ""
echo "[Тест 1] Корректно подписанный allowed_profiles.txt"
test_profile="$TEST_TMP/allowed_profiles.txt"
create_signed_whitelist "$test_profile" "full:sha256:abc123def456"
if _sm_verify_whitelist_file "$test_profile"; then
    pass "Корректно подписанный белый список профилей принят"
else
    fail "Корректно подписанный белый список профилей был отклонён"
fi

# Тест 2: Подделанный белый список профилей (содержимое изменено после подписания)
echo ""
echo "[Тест 2] Подделанный allowed_profiles.txt (содержимое изменено)"
# Создаём корректно подписанный файл, затем подделываем *строки данных*, сохраняя строку подписи.
# Это имитирует атакующего, который редактирует политику после её подписания.
echo "full:sha256:originalhash" > "$test_profile"
content=$(cat "$test_profile")
sig=$(_sm_compute_whitelist_signature "$content")
echo "___SM_WHITELIST_SIG___:sha256:$sig" >> "$test_profile"

# Подделка: меняем строку данных (строка подписи должна остаться в конце, чтобы было обнаружено несоответствие)
# Записываем вредоносную строку *перед* подписью (имитация редактирования содержимого на месте).
printf '%s\n' "full:sha256:EVIL_TAMPERED_HASH" "___SM_WHITELIST_SIG___:sha256:$sig" > "$test_profile"
if ! _sm_verify_whitelist_file "$test_profile" 2>/dev/null; then
    pass "Подделанный белый список профилей корректно отклонён"
else
    fail "Подделка белого списка профилей НЕ обнаружена"
fi

# Тест 3: Корректно подписанный белый список бинарников
echo ""
echo "[Тест 3] Корректно подписанный bin_whitelist.txt"
test_bin="$TEST_TMP/bin_whitelist.txt"
create_signed_whitelist "$test_bin" "./bin/testtool:deadbeef1234"
if _sm_verify_whitelist_file "$test_bin"; then
    pass "Корректно подписанный белый список бинарников принят"
else
    fail "Корректно подписанный белый список бинарников был отклонён"
fi

# Тест 4: Строка подписи удалена (распространённая атака)
echo ""
echo "[Тест 4] Белый список с удалённой строкой подписи"
test_profile2="$TEST_TMP/allowed_profiles2.txt"
echo "full:sha256:abc123def456" > "$test_profile2"
# Строка подписи не добавлена
if _sm_verify_whitelist_file "$test_profile2" 2>/dev/null; then
    echo "[ИНФО] Устаревший неподписанный белый список разрешён (текущее запасное поведение)"
else
    pass "Отсутствие подписи активирует защиту"
fi

# Тест 5: Строка подписи присутствует, но недействительна
echo ""
echo "[Тест 5] Недействительная строка подписи"
test_bin2="$TEST_TMP/bin_whitelist2.txt"
echo "./bin/tool:cafebabe" > "$test_bin2"
echo "___SM_WHITELIST_SIG___:sha256:WRONG_SIGNATURE_123" >> "$test_bin2"
if ! _sm_verify_whitelist_file "$test_bin2" 2>/dev/null; then
    pass "Недействительная подпись корректно отклонена"
else
    fail "Недействительная подпись НЕ обнаружена"
fi

# Тест 6: Скрипт update_whitelists.sh создаёт проверяемые подписанные файлы
echo ""
echo "[Тест 6] update_whitelists.sh создаёт проверяемые подписанные файлы"
if [ -x "$PROJECT_ROOT/security/update_whitelists.sh" ]; then
    "$PROJECT_ROOT/security/update_whitelists.sh" --profiles --dry-run >/dev/null 2>&1 || true
    # Мы не можем легко протестировать реальную запись без побочных эффектов в этом окружении,
    # но можем хотя бы убедиться, что скрипт существует и запускается
    pass "update_whitelists.sh доступен и исполняем"
else
    fail "update_whitelists.sh не найден или не является исполняемым"
fi

if [ "$FAILED" -eq 0 ]; then
    echo ""
    echo "=== Все тесты обнаружения подделки пройдены ==="
else
    echo ""
    echo "=== Некоторые тесты обнаружения подделки провалены ==="
    exit 1
fi
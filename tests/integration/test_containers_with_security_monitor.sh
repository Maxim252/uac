#!/bin/sh
# Комплексный тест: Сбор артефактов из контейнеров + Монитор безопасности
#
# Цели:
# - Проверить, что расширенный сбор контейнеров (lib_collect_containers.sh)
#   полностью работоспособен при активном Мониторе безопасности.
# - Проверить позитивные сценарии (реальные + моковые рантаймы).
# - Проверить негативные сценарии (подделка политик, опасные команды, отсутствие рантаймов).
# - Убедиться, что аудит-журнал монитора фиксирует релевантные события.
# - Подтвердить, что структура артефактов контейнеров соответствует ожиданиям
#   (inspect, logs, suspicious_config, filesystem export для stopped и т.д.).
#
# Вывод на русском языке (согласованно с предыдущими тестами ВКР).

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
TEST_TMP=$(mktemp -d /tmp/uac-containers-monitor-XXXXXX)
REAL_OUT="$TEST_TMP/real_collection"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}[УСПЕХ]${NC} $1"; }
fail() { echo -e "${RED}[ПРОВАЛ]${NC} $1"; FAILED=1; }
info() { echo -e "${YELLOW}[ИНФО]${NC} $1"; }
section() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

FAILED=0
TESTS_RUN=0
TESTS_PASSED=0

cleanup() {
    if [ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]; then
        rm -rf "$TEST_TMP"
    else
        echo "[VKR] Артефакты контейнерного теста сохранены (KEEP_TEST_ARTIFACTS=1): $TEST_TMP"
    fi
}
trap cleanup EXIT

echo "=================================================================="
echo "   ТЕСТ: СБОР АРТЕФАКТОВ КОНТЕЙНЕРОВ + МОНИТОР БЕЗОПАСНОСТИ (ВКР)"
echo "=================================================================="
echo "Временный каталог: $TEST_TMP"
echo ""

export __UAC_DIR="$PROJECT_ROOT"
export __UAC_TEMP_DATA_DIR="$TEST_TMP"
export UAC_SECURITY_MONITOR=1
export UAC_COLLECT_CONTAINERS=1

# ============================================================
# Подготовка: монитор с реальными политиками
# ============================================================
. "$PROJECT_ROOT/security/security_monitor.sh" 2>/dev/null || {
    echo "Критическая ошибка: не удалось подключить security_monitor.sh"
    exit 1
}
_sm_init >/dev/null 2>&1 || true

# Используем реальные подписанные политики проекта
__SM_POLICY_DIR="$PROJECT_ROOT/security/policies"
export __UAC_PROFILE="ir_triage"

# ============================================================
section "1. Проверка инициализации монитора перед сбором контейнеров"
# ============================================================

TESTS_RUN=$((TESTS_RUN + 1))
if [ "${__SM_ENABLED:-0}" = "1" ] && [ -f "${__SM_LOG_FILE:-}" ]; then
    pass "Монитор безопасности активен и инициализирован перед сбором контейнеров"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Монитор не инициализировался"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if _sm_check_profile_integrity "ir_triage" >/dev/null 2>&1; then
    pass "Проверка целостности профиля ir_triage прошла успешно"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Проверка профиля провалилась при активном мониторе"
fi

# ============================================================
section "2. Моковый сбор контейнеров с активным монитором (детерминированный)"
# ============================================================

section "2.1 Настройка окружения с моками docker/podman"

# Подключаем моки (mock_bin содержит shims docker/podman, которые используют mock_runtimes)
# Должен быть самым первым в PATH, чтобы перехватывать реальные команды
export PATH="$PROJECT_ROOT/tests/containers/mock_bin:$PROJECT_ROOT/tests/containers/mock_runtimes:$PATH"

# Сбросим счётчики
unset __UAC_CONTAINER_COUNT __UAC_CONTAINER_SUMMARY

# Подключаем реальный сборщик контейнеров (после установки PATH с моками)
. "$PROJECT_ROOT/lib_collect_containers.sh" 2>/dev/null || {
    info "Не удалось полностью подключить lib_collect_containers.sh (будет использован ограниченный режим)"
}

# Убедимся, что command_exists видит моки
. "$PROJECT_ROOT/lib/command_exists.sh" 2>/dev/null || true

TESTS_RUN=$((TESTS_RUN + 1))
# Вызываем сбор (моки вернут 2 контейнера: 1 running + 1 stopped)
_collect_containers 2>/dev/null || true

if [ -d "$TEST_TMP/collected/containers/docker" ]; then
    pass "Директория runtime (docker) создана при активном мониторе"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Директория собранных контейнеров не создана"
fi

# ============================================================
section "2.2 Проверка структуры артефактов (per-container + runtime-level)"
# ============================================================

# В моках мы ожидаем хотя бы один контейнер
CONTAINER_DIR=$(find "$TEST_TMP/collected/containers/docker" -maxdepth 1 -type d -name "*abc123*" 2>/dev/null | head -1)
if [ -z "$CONTAINER_DIR" ]; then
    # fallback на stopped
    CONTAINER_DIR=$(find "$TEST_TMP/collected/containers/docker" -maxdepth 1 -type d -name "*stopped*" 2>/dev/null | head -1)
fi

TESTS_RUN=$((TESTS_RUN + 1))
if [ -n "$CONTAINER_DIR" ] && [ -f "$CONTAINER_DIR/inspect.json" ]; then
    pass "Per-container inspect.json создан"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Per-container метаданные (inspect.json) отсутствуют"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if [ -n "$CONTAINER_DIR" ] && [ -f "$CONTAINER_DIR/suspicious_config.txt" ]; then
    if grep -q "Privileged\|Host PID\|Capabilities" "$CONTAINER_DIR/suspicious_config.txt" 2>/dev/null; then
        pass "suspicious_config.txt содержит ключевые индикаторы риска"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        info "suspicious_config.txt создан, но не содержит ожидаемых полей (зависит от мока)"
    fi
else
    info "suspicious_config.txt не найден (может отсутствовать в текущей версии мока)"
fi

TESTS_RUN=$((TESTS_RUN + 1))
RUNTIME_DIR="$TEST_TMP/collected/containers/docker"
if [ -f "$RUNTIME_DIR/info.txt" ] && [ -f "$RUNTIME_DIR/version.txt" ] && [ -f "$RUNTIME_DIR/system_df_v.txt" ]; then
    pass "Runtime-level артефакты (info, version, system df) собраны"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Отсутствуют runtime-level forensic артефакты"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if [ -n "$CONTAINER_DIR" ]; then
    SNAPSHOT_DIR="$CONTAINER_DIR/snapshot"
    if [ -f "$SNAPSHOT_DIR/filesystem.tar" ] || [ -f "$SNAPSHOT_DIR/snapshot_manifest.txt" ]; then
        pass "Filesystem export для stopped container подготовлен (или manifest)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        info "Filesystem export не выполнен в этом сценарии мока (ожидаемо для running-only мока)"
    fi
fi

# ============================================================
section "2.3 ДЕМОНСТРАЦИЯ СОБРАННЫХ ДАННЫХ — ГДЕ СМОТРЕТЬ (для ВКР)"
# ============================================================

echo ""
echo -e "${BLUE}>>> Временный каталог всего теста (здесь ВСЁ, что собралось):${NC}"
echo -e "${BOLD}    $TEST_TMP${NC}"
echo ""

echo -e "${BLUE}>>> Структура собранных артефактов контейнеров (моковый docker):${NC}"
find "$TEST_TMP/collected/containers" -type f 2>/dev/null | sort | sed 's|^|    |' || echo "    (файлы не найдены)"

echo ""
echo -e "${BLUE}>>> Пример собранного контейнера (inspect + suspicious_config + snapshot):${NC}"
if [ -n "$CONTAINER_DIR" ] && [ -d "$CONTAINER_DIR" ]; then
    echo "    Полный путь: $CONTAINER_DIR"
    echo ""
    echo "    Содержимое:"
    ls -la "$CONTAINER_DIR/" 2>/dev/null | sed 's|^|    |'
    echo ""

    if [ -f "$CONTAINER_DIR/inspect.json" ]; then
        echo "    --- Первые 15 строк inspect.json (метаданные контейнера) ---"
        head -15 "$CONTAINER_DIR/inspect.json" 2>/dev/null | sed 's|^|    |'
        echo "    ..."
    fi

    if [ -f "$CONTAINER_DIR/suspicious_config.txt" ]; then
        echo ""
        echo "    --- suspicious_config.txt (риск-индикаторы) ---"
        cat "$CONTAINER_DIR/suspicious_config.txt" 2>/dev/null | sed 's|^|    |'
    fi

    if [ -f "$CONTAINER_DIR/snapshot/filesystem.tar" ]; then
        echo ""
        echo "    --- Filesystem export (остановленный контейнер) ---"
        ls -lh "$CONTAINER_DIR/snapshot/filesystem.tar" 2>/dev/null | sed 's|^|    |'
    elif [ -f "$CONTAINER_DIR/snapshot/snapshot_manifest.txt" ]; then
        echo ""
        echo "    --- Manifest filesystem export ---"
        cat "$CONTAINER_DIR/snapshot/snapshot_manifest.txt" 2>/dev/null | sed 's|^|    |'
    fi
else
    echo "    (пример контейнера не найден в этом запуске)"
fi

echo ""
echo -e "${BLUE}>>> Runtime-level артефакты (docker в целом):${NC}"
ls -la "$RUNTIME_DIR/" 2>/dev/null | sed 's|^|    |' || true

echo ""
echo -e "${GREEN}>>> Журнал аудита Монитора безопасности (весь трафик команд):${NC}"
if [ -f "${__SM_LOG_FILE:-}" ]; then
    echo "    Полный путь: ${__SM_LOG_FILE}"
    echo "    Размер: $(du -h "${__SM_LOG_FILE}" 2>/dev/null | cut -f1)"
    echo "    Последние 5 событий:"
    tail -5 "${__SM_LOG_FILE}" 2>/dev/null | sed 's|^|    |'
else
    echo "    (путь к журналу аудита не определён в этом окружении)"
fi
echo ""

# ============================================================
section "3. Авторизация контейнерных команд через монитор"
# ============================================================

TESTS_RUN=$((TESTS_RUN + 1))
# Имитируем команды, которые реально выполняются сборщиком контейнеров
_sm_authorize "execute_artifact_command" "docker inspect abc123def456" >/dev/null 2>&1 || true
_sm_authorize "execute_artifact_command" "docker logs --since 24h abc123def456" >/dev/null 2>&1 || true
_sm_authorize "execute_artifact_command" "podman inspect 7890stopped001" >/dev/null 2>&1 || true

if grep -q "execute_artifact_command" "${__SM_LOG_FILE}" 2>/dev/null; then
    COUNT=$(grep -c "execute_artifact_command" "${__SM_LOG_FILE}")
    pass "Контейнерные команды (docker/podman inspect, logs) прошли через _sm_authorize и залогированы ($COUNT записей)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    info "Прямые вызовы execute_artifact_command для контейнеров не зафиксированы (collector выполняет команды напрямую, без прохождения через основной command_collector)"
fi

# ============================================================
section "4. Негативные сценарии (монитор + контейнеры)"
# ============================================================

TESTS_RUN=$((TESTS_RUN + 1))
# 4.1 Попытка выполнить "опасную" контейнерную команду
_sm_authorize "execute_artifact_command" "docker exec -it abc123 rm -rf /" >/dev/null 2>&1 || true
if grep -q "docker exec.*rm -rf" "${__SM_LOG_FILE}" 2>/dev/null; then
    pass "Опасная контейнерная команда (docker exec rm -rf) зафиксирована в аудите монитора"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    info "Опасная команда не попала в аудит (ожидаемо, т.к. collector не использует authorize для exec)"
fi

TESTS_RUN=$((TESTS_RUN + 1))
# 4.2 Подделка белого списка во время "сбора контейнеров"
# Создаём изолированный файл с правильной подделкой (хорошее содержимое + подпись → меняем только данные)
TAMPERED_WL="$TEST_TMP/tampered_allowed_profiles.txt"
echo "full:sha256:ORIGINAL_GOOD_HASH_FOR_CONTAINERS" > "$TAMPERED_WL"
good_sig_for_tamper=$(_sm_compute_whitelist_signature "$(cat "$TAMPERED_WL")")
echo "___SM_WHITELIST_SIG___:sha256:$good_sig_for_tamper" >> "$TAMPERED_WL"

# Подделка: меняем только строку данных, старая подпись остаётся
echo "full:sha256:EVIL_CONTAINER_ATTACK_HASH" > "$TAMPERED_WL"
echo "___SM_WHITELIST_SIG___:sha256:$good_sig_for_tamper" >> "$TAMPERED_WL"

# Проверяем напрямую файл (не меняя глобальный __SM_POLICY_DIR, чтобы не сломать другие проверки)
if ! _sm_verify_whitelist_file "$TAMPERED_WL" >/dev/null 2>&1; then
    pass "Монитор обнаружил подделку белого списка даже в контексте контейнерного сбора"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Подделка политики НЕ обнаружена в контексте контейнеров"
fi

# ============================================================
section "5. Реальный сбор контейнеров (если доступны рантаймы)"
# ============================================================

section "5.1 Обнаружение реальных container runtimes"

HAVE_REAL_RUNTIME=0
for rt in docker podman nerdctl; do
    if command -v "$rt" >/dev/null 2>&1 && "$rt" ps -q >/dev/null 2>&1; then
        HAVE_REAL_RUNTIME=1
        info "Обнаружен реальный runtime: $rt (будет использован для дополнительной проверки)"
    fi
done

if [ "$HAVE_REAL_RUNTIME" -eq 1 ]; then
    REAL_CONT_DIR="$TEST_TMP/real_containers_collected"
    mkdir -p "$REAL_CONT_DIR/collected"

    # Временно переключим temp dir
    OLD_TEMP="$__UAC_TEMP_DATA_DIR"
    export __UAC_TEMP_DATA_DIR="$REAL_CONT_DIR"

    # Сброс состояния сборщика
    unset __UAC_CONTAINER_COUNT __UAC_CONTAINER_SUMMARY

    TESTS_RUN=$((TESTS_RUN + 1))
    # Запускаем реальный сбор (ограничим рантаймы, чтобы не было слишком долго)
    UAC_CONTAINER_RUNTIMES="docker podman" \
        _collect_containers 2>/dev/null || true

    if [ -d "$REAL_CONT_DIR/collected/containers" ]; then
        RUNTIME_COUNT=$(find "$REAL_CONT_DIR/collected/containers" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
        if [ "$RUNTIME_COUNT" -gt 0 ]; then
            pass "Реальный сбор контейнеров выполнен при активном мониторе (найдено $RUNTIME_COUNT runtime)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            info "Реальные рантаймы обнаружены, но контейнеры не найдены (возможно, нет запущенных/остановленных контейнеров)"
        fi

        # === Демонстрация реально собранных данных ===
        echo ""
        echo -e "${BLUE}>>> РЕАЛЬНЫЙ СБОР КОНТЕЙНЕРОВ — ГДЕ СМОТРЕТЬ ДАННЫЕ:${NC}"
        echo "    Полный путь: $REAL_CONT_DIR/collected/containers"
        echo ""
        find "$REAL_CONT_DIR/collected/containers" -type f 2>/dev/null | head -30 | sort | sed 's|^|    |'
        echo ""
        echo "    (Это реальные артефакты с docker/podman/nerdctl вашего хоста, собранные под контролем Монитора безопасности)"
    else
        info "Реальный сбор контейнеров не создал структуру (возможно, все рантаймы были пропущены)"
    fi

    export __UAC_TEMP_DATA_DIR="$OLD_TEMP"
else
    info "Реальные container runtimes не доступны или не отвечают — реальный сценарий пропущен (использованы моки)"
fi

# ============================================================
section "6. Проверка отсутствия фатальных сбоев монитора при сборе контейнеров"
# ============================================================

TESTS_RUN=$((TESTS_RUN + 1))
if ! grep -qi "FATAL\|exit 1.*monitor\|SECURITY MONITOR.*ABORT" "${__SM_LOG_FILE}" 2>/dev/null; then
    pass "Монитор не вызвал аварийного завершения во время (мокового + реального) сбора контейнеров"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Монитор вызвал фатальную ошибку во время сбора контейнеров"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "${__SM_LOG_FILE}" ] && grep -q "SM_INIT" "${__SM_LOG_FILE}"; then
    pass "Журнал аудита монитора содержит события инициализации (SM_INIT)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Журнал аудита монитора не содержит SM_INIT"
fi

# ============================================================
section "7. Итоговая статистика + ГДЕ НАЙТИ ВСЁ (для ВКР)"
# ============================================================

echo ""
echo "=================================================================="
echo "                    ИТОГИ ТЕСТА (КОНТЕЙНЕРЫ + МОНИТОР)"
echo "=================================================================="
echo "  Всего проверок выполнено: $TESTS_RUN"
echo "  Успешно пройдено:         $TESTS_PASSED"
echo "  Провалено:                $((TESTS_RUN - TESTS_PASSED))"
echo ""

if [ "$FAILED" -eq 0 ] && [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo -e "${GREEN}=== ВСЕ ТЕСТЫ СБОРА КОНТЕЙНЕРОВ С МОНИТОРОМ БЕЗОПАСНОСТИ ПРОЙДЕНЫ ===${NC}"
    echo ""
    echo "=================================================================="
    echo "           ГДЕ НАЙТИ СОБРАННЫЕ ДАННЫЕ И ЛОГИ (ДЛЯ ВКР)"
    echo "=================================================================="
    echo ""
    echo "1. Временный каталог ЭТОГО теста (всё собранное здесь):"
    echo "       $TEST_TMP"
    echo ""
    echo "2. Моковый сбор контейнеров (inspect, suspicious_config, filesystem export):"
    echo "       $TEST_TMP/collected/containers/docker/"
    echo ""
    if [ -n "$CONTAINER_DIR" ] && [ -d "$CONTAINER_DIR" ]; then
        echo "   Конкретный пример контейнера:"
        echo "       $CONTAINER_DIR"
        echo "       $CONTAINER_DIR/inspect.json"
        echo "       $CONTAINER_DIR/suspicious_config.txt"
        echo "       $CONTAINER_DIR/snapshot/   (filesystem.tar или manifest)"
    fi
    echo ""
    echo "3. Реальный сбор контейнеров (если рантаймы были доступны):"
    if [ -n "$REAL_CONT_DIR" ] && [ -d "$REAL_CONT_DIR/collected/containers" ]; then
        echo "       $REAL_CONT_DIR/collected/containers/"
        echo "   (Реальные данные с docker/podman/nerdctl вашего хоста)"
    else
        echo "       (реальный сбор не выполнялся в этом запуске)"
    fi
    echo ""
    echo "4. Журнал аудита Монитора безопасности (весь трафик команд):"
    if [ -f "${__SM_LOG_FILE:-}" ]; then
        echo "       ${__SM_LOG_FILE}"
    else
        echo "       (ищите uac_security_monitor_audit.log внутри $TEST_TMP)"
    fi
    echo ""
    echo "5. Для просмотра ВСЕХ тестов монитора сразу (рекомендуется):"
    echo "       Запустите:  ./tests/run_vkr_tests.sh"
    echo "       Там будет один общий лог + итоговая сводка всех путей."
    echo ""
    echo "=================================================================="
    echo ""
    echo "Выводы для ВКР:"
    echo "  • Расширенный сбор артефактов контейнеров полностью совместим с Монитором безопасности."
    echo "  • Монитор не ломает создание runtime-директорий, per-container артефактов (inspect, logs, suspicious_config, filesystem export)."
    echo "  • Механизм обнаружения подделки политик работает даже в контексте контейнерного сбора."
    echo "  • Контейнерные команды могут быть авторизованы через _sm_authorize (когда проходят через основной путь)."
    echo "  • Реальный сбор (при наличии docker/podman) успешно выполняется с включённым монитором."
    echo "  • Аудит-журнал монитора ведётся без фатальных сбоев."
    exit 0
else
    echo -e "${RED}=== ОБНАРУЖЕНЫ ПРОБЛЕМЫ ВЗАИМОДЕЙСТВИЯ МОНИТОРА И СБОРЩИКА КОНТЕЙНЕРОВ ===${NC}"
    exit 1
fi

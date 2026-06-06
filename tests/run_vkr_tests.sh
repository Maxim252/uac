#!/bin/bash
# =============================================================================
# Запуск всех ключевых тестов Монитора безопасности UAC для ВКР
#
# Скрипт запускает комплексные тесты Монитора безопасности и сбора
# артефактов из контейнеров, специально подготовленные для защиты ВКР.
#
# Основные возможности:
#   • Запускает основные тесты монитора + контейнеров
#   • Сохраняет ПОЛНЫЙ вывод в один лог-файл (/tmp/uac_vkr_full_*.log)
#   • В конце выводит понятную сводку «ГДЕ НАЙТИ ВСЁ ДЛЯ ВКР»
#   • Артефакты тестов сохраняются (KEEP_TEST_ARTIFACTS=1)
#
# Использование:
#   ./tests/run_vkr_tests.sh
#   ./tests/run_vkr_tests.sh --help
#
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Показ справки на русском языке
# -----------------------------------------------------------------------------
show_help() {
    cat << 'EOF'
Использование:
    ./tests/run_vkr_tests.sh [опции]

Описание:
    Запускает все ключевые тесты Монитора безопасности UAC и расширенного
    сбора артефактов из контейнеров, подготовленные для выпускной
    квалификационной работы (ВКР).

    Скрипт сохраняет полный вывод всех тестов в отдельный лог-файл и
    в конце выводит подробную сводку, где находятся собранные данные,
    журналы аудита монитора и другие артефакты.

Опции:
    -h, --help      Показать эту справку и выйти

Что делает скрипт:
    • Последовательно запускает основные комплексные тесты:
        - Комплексный тест Монитора безопасности (22 проверки)
        - Тест сбора контейнеров + Монитор безопасности (13 проверок)
    • Сохраняет ВЕСЬ вывод в файл:
        /tmp/uac_vkr_full_ГГГГММДД_ЧЧММСС.log
    • В режиме ВКР артефакты тестов НЕ удаляются (KEEP_TEST_ARTIFACTS=1)
    • В конце печатает блок «ГДЕ НАЙТИ ВСЁ ДЛЯ ВКР» с точными путями

Примеры использования:
    ./tests/run_vkr_tests.sh
    ./tests/run_vkr_tests.sh --help

После завершения работы рекомендуется открыть лог:
    less -S /tmp/uac_vkr_full_*.log

    или скопировать важные артефакты из сохранённых каталогов:
    /tmp/uac-sm-comprehensive-*/
    /tmp/uac-containers-monitor-*/

Дополнительно:
    Для запуска отдельных тестов вручную используйте:
    ./tests/functional/security_monitor/test_security_monitor_comprehensive.sh
    ./tests/integration/test_containers_with_security_monitor.sh

EOF
}

# Обработка аргументов
case "${1:-}" in
    -h|--help|help)
        show_help
        exit 0
        ;;
esac

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Отдельный лог-файл для ВКР (всегда в /tmp, не удаляется автоматически)
RUN_ID=$(date +%Y%m%d_%H%M%S)
VKR_LOG="/tmp/uac_vkr_full_${RUN_ID}.log"

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo "=================================================================="
echo "   ЗАПУСК ТЕСТОВ МОНИТОРА БЕЗОПАСНОСТИ + КОНТЕЙНЕРОВ ДЛЯ ВКР"
echo "=================================================================="
echo "Полный лог всех тестов будет сохранён в:"
echo "    $VKR_LOG"
echo ""
echo "Для справки: ./tests/run_vkr_tests.sh --help"
echo "Начало: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=================================================================="
echo ""

# Записываем заголовок в лог
{
    echo "=================================================================="
    echo "   ПОЛНЫЙ ЛОГ ТЕСТИРОВАНИЯ МОНИТОРА БЕЗОПАСНОСТИ UAC ДЛЯ ВКР"
    echo "   Дата: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "   Проект: $PROJECT_ROOT"
    echo "=================================================================="
    echo ""
} > "$VKR_LOG"

# Глобальный счётчик ошибок для ВКР
VKR_FAILED=0

# Функция запуска теста с логированием
run_test() {
    local test_path="$1"
    local test_name="$2"
    local keep_artifacts="${3:-0}"   # 1 = сохранить артефакты после теста (для ВКР)

    echo ""
    echo -e "${BLUE}>>> Запуск: $test_name${NC}"
    echo -e "${BLUE}>>> Файл:   $test_path${NC}"
    if [ "$keep_artifacts" = "1" ]; then
        echo -e "${YELLOW}>>> Режим VKR: артефакты будут сохранены${NC}"
    fi
    echo ">>> Лог дописывается в: $VKR_LOG"
    echo ""

    {
        echo ""
        echo "=================================================================="
        echo "   НАЧАЛО ТЕСТА: $test_name"
        echo "   Файл: $test_path"
        echo "   Время: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "=================================================================="
    } >> "$VKR_LOG"

    local test_exit=0
    # Запускаем тест, передавая переменную сохранения артефактов
    KEEP_TEST_ARTIFACTS="$keep_artifacts" bash "$test_path" 2>&1 | tee -a "$VKR_LOG" || test_exit=$?

    if [ "$test_exit" -eq 0 ]; then
        echo -e "${GREEN}>>> Тест завершён успешно: $test_name${NC}"
    else
        echo -e "${RED}>>> Тест завершился с ошибкой (код $test_exit): $test_name${NC}"
        VKR_FAILED=$((VKR_FAILED + 1))
    fi

    {
        echo ""
        echo "=================================================================="
        echo "   КОНЕЦ ТЕСТА: $test_name"
        echo "   Код выхода: $test_exit"
        echo "   Время: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "=================================================================="
        echo ""
    } >> "$VKR_LOG"
}

# === Основные тесты для ВКР (артефакты сохраняются) ===
run_test "$PROJECT_ROOT/tests/functional/security_monitor/test_security_monitor_comprehensive.sh" \
         "Комплексный тест Монитора безопасности (22 проверки)" 1

run_test "$PROJECT_ROOT/tests/integration/test_containers_with_security_monitor.sh" \
         "Сбор контейнеров + Монитор безопасности (13 проверок)" 1

# Дополнительные тесты (закомментированы по умолчанию для чистого прогона ВКР).
# Раскомментируйте при необходимости.
# run_test "$PROJECT_ROOT/tests/functional/security_monitor/test_whitelist_tampering.sh" \
#          "Тесты обнаружения подделки белых списков" 0
#
# run_test "$PROJECT_ROOT/tests/functional/security_monitor/test_audit_logging.sh" \
#          "Тесты журналирования аудита" 0
#
# run_test "$PROJECT_ROOT/tests/functional/security_monitor/test_dangerous_command_logging.sh" \
#          "Тесты журналирования опасных команд" 0
#
# run_test "$PROJECT_ROOT/tests/functional/security_monitor/test_monitor_core.sh" \
#          "Функциональные тесты ядра монитора" 0

echo ""
echo -e "${YELLOW}>>> Все тесты выполнены. Собираем информацию об артефактах...${NC}"

# === Сбор всех временных каталогов тестов ===
SM_DIRS=$(find /tmp -maxdepth 1 -type d -name 'uac-sm-comprehensive-*' 2>/dev/null | sort)
CONT_DIRS=$(find /tmp -maxdepth 1 -type d -name 'uac-containers-monitor-*' 2>/dev/null | sort)
OTHER_TMP=$(find /tmp -maxdepth 1 -type d \( -name 'uac-test-monitor-*' -o -name 'uac-test-tampering-*' -o -name 'uac-test-audit-*' -o -name 'uac-test-dangerous-*' \) 2>/dev/null | sort)

# Реальные сборы внутри тестов (если есть)
REAL_COLLECTIONS=$(find /tmp -maxdepth 2 -type d -name 'uac-*' -path '*/real*' 2>/dev/null | head -10 || true)

# === ФИНАЛЬНАЯ СВОДКА ДЛЯ ВКР ===
{
    echo ""
    echo "=================================================================="
    echo "           ГДЕ НАЙТИ ВСЁ ДЛЯ ВКР — ИТОГОВАЯ СВОДКА"
    echo "=================================================================="
    echo ""
    echo "Дата и время прогона: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Полный лог всех тестов (самый важный файл):"
    echo "    $VKR_LOG"
    echo ""
    echo "------------------------------------------------------------------"
    echo "1. КОМПЛЕКСНЫЙ ТЕСТ МОНИТОРА БЕЗОПАСНОСТИ"
    echo "------------------------------------------------------------------"
    if [ -n "$SM_DIRS" ]; then
        echo "Временные каталоги теста (внутри — реальные сборы + audit.log):"
        echo "$SM_DIRS" | sed 's/^/    /'
        echo ""
        echo "Примеры полезных файлов внутри:"
        echo "    <каталог>/real_out_*/uac-*/uac_security_monitor_audit.log"
        echo "    <каталог>/real_out_*/uac-*/uac.log"
        echo "    <каталог>/real_out_*/uac-*/hostname.txt  (и другие артефакты)"
    else
        echo "    (временные каталоги уже удалены или не найдены)"
    fi
    echo ""
    echo "------------------------------------------------------------------"
    echo "2. ТЕСТ: КОНТЕЙНЕРЫ + МОНИТОР БЕЗОПАСНОСТИ"
    echo "------------------------------------------------------------------"
    if [ -n "$CONT_DIRS" ]; then
        echo "Временные каталоги (моковый + реальный сбор контейнеров):"
        echo "$CONT_DIRS" | sed 's/^/    /'
        echo ""
        echo "Что там лежит (примеры):"
        echo "    collected/containers/docker/<контейнер>/inspect.json"
        echo "    collected/containers/docker/<контейнер>/suspicious_config.txt"
        echo "    collected/containers/docker/<контейнер>/snapshot/filesystem.tar (method 1: export)"
        echo "    collected/containers/docker/<контейнер>/snapshot/image.tar (method 2: commit+save)"
        echo "    collected/containers/docker/info.txt, version.txt, system_df_v.txt"
        echo "    uac_security_monitor_audit.log  (журнал монитора)"
    else
        echo "    (временные каталоги уже удалены или не найдены)"
    fi
    echo ""
    echo "------------------------------------------------------------------"
    echo "3. ЖУРНАЛЫ АУДИТА МОНИТОРА БЕЗОПАСНОСТИ"
    echo "------------------------------------------------------------------"
    echo "Ищите файлы uac_security_monitor_audit.log в каталогах выше."
    echo "Также они копируются в выходные каталоги реальных сборов."
    echo ""
    echo "------------------------------------------------------------------"
    echo "4. ДРУГИЕ ТЕСТЫ (whitelist, audit, dangerous commands, core)"
    echo "------------------------------------------------------------------"
    if [ -n "$OTHER_TMP" ]; then
        echo "Их временные каталоги:"
        echo "$OTHER_TMP" | sed 's/^/    /'
    fi
    echo ""
    echo "------------------------------------------------------------------"
    echo "5. РЕАЛЬНЫЕ СБОРЫ АРТЕФАКТОВ ВНУТРИ ТЕСТОВ"
    echo "------------------------------------------------------------------"
    if [ -n "$REAL_COLLECTIONS" ]; then
        echo "$REAL_COLLECTIONS" | sed 's/^/    /'
    else
        echo "    (не найдены или уже очищены)"
    fi
    echo ""
    echo "=================================================================="
    echo "           КОНЕЦ СВОДКИ ДЛЯ ВКР"
    echo "=================================================================="
    echo ""
    echo "Совет: откройте лог в редакторе:"
    echo "    less $VKR_LOG"
    echo "    или"
    echo "    code $VKR_LOG"
    echo ""
} | tee -a "$VKR_LOG"

# Печатаем ту же сводку в консоль ещё раз (чтобы пользователь сразу увидел)
echo ""
echo -e "${BOLD}${GREEN}==================================================================${NC}"
echo -e "${BOLD}${GREEN}           ГДЕ НАЙТИ ВСЁ ДЛЯ ВКР — ИТОГОВАЯ СВОДКА${NC}"
echo -e "${BOLD}${GREEN}==================================================================${NC}"
echo ""
echo -e "${YELLOW}Полный лог всех тестов (ОТКРОЙТЕ ЕГО В РЕДАКТОРЕ):${NC}"
echo -e "    ${BOLD}$VKR_LOG${NC}"
echo ""

if [ "$VKR_FAILED" -gt 0 ]; then
    echo -e "${RED}ВНИМАНИЕ: $VKR_FAILED тест(ов) завершились с ошибкой!${NC}"
    echo ""
fi

echo "1. Комплексный тест монитора (артефакты сохранены):"
if [ -n "$SM_DIRS" ]; then
    echo "$SM_DIRS" | sed 's/^/    /'
else
    echo "    (каталоги не найдены — возможно, уже очищены)"
fi
echo ""
echo "2. Тест контейнеры + монитор (здесь самые интересные артефакты контейнеров):"
if [ -n "$CONT_DIRS" ]; then
    echo "$CONT_DIRS" | sed 's/^/    /'
else
    echo "    (каталоги не найдены — возможно, уже очищены)"
fi
echo ""
echo -e "${BOLD}Важно для ВКР:${NC}"
echo "  Поскольку запущено в режиме сохранения артефактов (KEEP_TEST_ARTIFACTS=1),"
echo "  временные каталоги с реальными собранными данными НЕ удалены."
echo ""
echo -e "${BOLD}Быстрые команды для просмотра артефактов:${NC}"
echo "  ls -la /tmp/uac-containers-monitor-*/collected/containers/docker/"
echo "  ls -la /tmp/uac-sm-comprehensive-*/real_out_*/uac-*/"
echo ""
echo -e "${BOLD}Совет:${NC} Откройте полный лог:"
echo "    less -S $VKR_LOG"
echo ""
if [ "$VKR_FAILED" -eq 0 ]; then
    echo -e "${GREEN}Готово для ВКР. Все данные и логи сохранены.${NC}"
else
    echo -e "${RED}Есть проблемы — проверьте лог выше.${NC}"
fi
echo ""

exit "$VKR_FAILED"

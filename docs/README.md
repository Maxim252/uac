# Документация UAC — Расширения для ВКР

Этот каталог содержит документацию по ключевым расширениям UAC, разработанным в рамках выпускной квалификационной работы.

## Основные документы

| Документ | Назначение |
|----------|----------|
| [SECURITY_MONITOR.md](SECURITY_MONITOR.md) | Полное описание Монитора безопасности (архитектура, подписи, авторизация, аудит, интеграция) |
| [CONTAINER_COLLECTION.md](CONTAINER_COLLECTION.md) | Описание расширенного сборщика артефактов из контейнеров (docker, podman, nerdctl и др.) |
| [VKR_Security_Monitor_Testing_Report.md](VKR_Security_Monitor_Testing_Report.md) | Отчёт о комплексном тестировании Монитора + контейнеров для защиты ВКР |

## Быстрый старт для ВКР

```bash
# Запуск всех релевантных тестов + сохранение артефактов
./tests/run_vkr_tests.sh

# Просмотр итоговой сводки и путей
less /tmp/uac_vkr_full_*.log
```

## Связанные файлы проекта

- `security/security_monitor.sh`
- `lib_collect_containers.sh`
- `tests/run_vkr_tests.sh`
- `security/policies/`

---

*Актуально на 2026 год.*
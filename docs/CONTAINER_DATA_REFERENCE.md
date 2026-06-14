# Справочник артефактов контейнерного сбора (collected/containers/*)

**Назначение:** 
- Полный список **всех** артефактов, которые собирает UAC для контейнерных сред (все рантаймы).
- **Подробное описание того, что именно находится внутри каждого файла** (структура, типичные поля, примеры содержимого).
- Forensic-ценность и различия между механизмами сбора.

**Механизмы сбора:**

1. **Глубокий сбор** (`lib_collect_containers.sh`) → `collected/containers/<runtime>/...`
   - Метаданные + CRIU checkpoint (только для running) + `/proc` хоста.
   - Автоматически при `UAC_COLLECT_CONTAINERS=1`.
   - Legacy `export`/`commit`/`save` запрещены.

2. **Декларативный сбор** (YAML `artifacts/live_response/containers/`) → `collected/live_response/containers/...`
   - Сырой вывод команд (включается профилем).

> Пример пути пользователя: `/tmp/uac_v24_nerdct/uac-kali-linux-20260606193016/containers/*` — это директория глубокого сбора для nerdctl.

---

## ЧАСТЬ 1. СВОДНЫЕ ТАБЛИЦЫ ВСЕХ АРТЕФАКТОВ (что собирается)

### 1.1 Глубокий сбор — Runtime-level артефакты (`collected/containers/<runtime>/`)

| Артефакт (файл)                              | Рантаймы                          | Краткое описание источника                          | Что находится внутри (кратко) | Ценность |
|----------------------------------------------|-----------------------------------|-----------------------------------------------------|-------------------------------|----------|
| `info.txt`                                   | docker, podman, nerdctl, crictl   | `<runtime> info`                                    | Конфигурация демона, storage driver, security options, ресурсы | Высокая |
| `version.txt`                                | docker, podman, nerdctl, crictl   | `<runtime> version`                                 | Версии клиента и сервера      | Средняя |
| `criu_version.txt`                           | все (когда criu присутствует в PATH) | `criu --version` или маркер "not found"             | Версия CRIU (или доказательство его отсутствия) | Высокая (для аудита checkpoint механизма) |
| `system_df_v.txt`                            | docker, podman, nerdctl           | `<runtime> system df -v`                            | Подробная статистика места (images, containers, volumes, build cache) | Высокая |
| `journal_docker.log` / `journal_podman.log` / `journal_containerd.log` / `journal_buildkit.log` | все | `journalctl -u <unit>` (последние N строк) | События systemd unit: запуск, остановка, ошибки, сообщения от демона | Очень высокая (timeline) |
| `docker.log`, `containerd.log` и др.         | все                               | Копии из `/var/log/`                                | Логи демонов в текстовом виде | Высокая |
| `docker_container_<id>.log`                  | docker                            | Логи из `/var/lib/docker/containers/<id>/*-json.log` | Исторические stdout/stderr контейнеров (json-lines) | Очень высокая |
| `ctr_*.txt` (containers, images, snapshots, content, leases) | containerd + ctr | `ctr --namespace k8s.io ... list` | Списки контейнеров, образов, снепшотов, контента, leases в containerd | Высокая (K8s) |
| `overlay2_listing.txt` / `overlay2_layers.txt` | docker | `ls` и `find` по `/var/lib/docker/overlay2` | Список слоёв overlay2 (ID директорий) | Высокая |
| `podman_overlay_listing.txt`                 | podman                            | Аналог для podman storage overlay                   | Слои podman                   | Высокая |
| `containerd_overlayfs_listing.txt`           | containerd                        | Листинг snapshotter overlayfs                       | Слои containerd               | Высокая |
| `runtime_sockets.txt`                        | все                               | `ls -l` + `stat` сокетов docker.sock / containerd.sock / podman.sock | Права, владелец, тип сокетов  | Высокая (escape risk) |
| `docker_buildx_du.txt`, `docker_buildkit_files.txt`, `podman_build_files.txt`, `build_cache_structure.txt` | docker/podman | `buildx du`, find по buildkit/storage/build         | Build cache, слои сборок, метаданные | Высокая (supply chain) |
| `daemon.json`, `storage.conf`                | docker / podman                   | Копии конфигов демона и storage                     | Настройки хранения, insecure registries и т.д. | Высокая |
| `registry_config_*.json`, `podman_auth_*.json` | docker/podman | `~/.docker/config.json` и `~/.config/containers/auth.json` | Credentials, registry mirrors, auth helpers | Очень высокая |

### 1.2 Глубокий сбор — Per-container артефакты (`collected/containers/<runtime>/<name>_<cid>/`)

| Артефакт                              | Рантаймы (deep)              | Краткое описание | Что находится внутри (кратко) | Ценность |
|---------------------------------------|------------------------------|------------------|-------------------------------|----------|
| `inspect.json`                        | docker/podman/nerdctl/crictl | Полный inspect   | Большой JSON со State, Config, HostConfig, NetworkSettings, Mounts, GraphDriver | **Критическая** |
| `config.json`                         | docker/podman/nerdctl        | `.Config`        | Env, Cmd, Entrypoint, Image, Labels, WorkingDir, Volumes, User и т.д. | Высокая |
| `hostconfig.json`                     | docker/podman/nerdctl        | `.HostConfig`    | Privileged, Binds, PidMode, NetworkMode, CapAdd/Drop, Devices, SecurityOpt, RestartPolicy, ReadonlyRootfs и др. | **Критическая** |
| `networksettings.json`                | docker/podman/nerdctl        | Сетевые настройки| IP, Gateway, Ports, Networks{}, MacAddress, SandboxKey и т.д. | Высокая |
| `image_inspect.json` + `image_history.txt` | docker/podman/nerdctl     | Инфо + история образа | Полный inspect образа + команды слоёв (FROM, RUN, COPY...) | Высокая |
| `securityopt.json` / `capabilities.txt` | docker/podman/nerdctl      | SecurityOpt, CapAdd/CapDrop | Списки seccomp, apparmor, capabilities | Высокая |
| `suspicious_config.txt`               | docker/podman/nerdctl        | Специальный отчёт | Ключевые риск-флаги в удобном текстовом виде (см. ниже подробный разбор) | **Очень высокая** |
| `logs.txt`                            | все                          | Последние 24ч логов контейнера | Текстовый вывод stdout/stderr приложения | Высокая |
| `snapshot/checkpoint.tar.gz`          | running (кроме очень больших) | CRIU (podman native / ctr / direct / docker exp) | Архив checkpoint'а (память + FS diff). Для podman — восстановимый tar.gz | **Очень высокая** (состояние памяти!) |
| `snapshot/checkpoint_info.txt`        | running                      | Метаданные       | Метод, флаги, статус, предупреждения (для docker — обязательно "EXPERIMENTAL") | Высокая |
| `snapshot/checkpoint_manifest.txt`    | все                          | Список           | Что реально создано (checkpoint.tar.gz + ...) | Низкая (мета) |
| `snapshot/checkpoint_skipped.txt`     | stopped / disabled           | Маркер           | Причина (не running / CRIU недоступен / лимит размера / UAC_CONTAINER_CHECKPOINT=0) | Средняя |
| `ps.txt`, `env.txt`, `network.txt`, `mounts.txt` | docker/podman/nerdctl | Внутриконтейнерные команды или nsenter | Вывод ps, env, ss/netstat, mounts | Высокая (running) |
| `cgroup.txt`, `namespaces.txt`        | docker/podman/nerdctl        | Host /proc/<pid> | Содержимое cgroup и список namespaces (cgroup, pid, net, mnt, ipc, uts...) | Высокая |
| `proc_cmdline.txt`, `proc_environ*.txt`, `proc_status.txt`, `proc_exe.txt`, `proc_fd.txt`, `proc_maps.txt` и др. (всего ~12 файлов) | docker/podman/nerdctl | Прямые файлы из `/proc/<pid>/` хоста | См. подробный разбор ниже | Очень высокая |
| `uid_map.txt` / `gid_map.txt`         | docker/podman/nerdctl        | User namespace mapping | Диапазоны uid/gid (0 100000 65536 и т.п.) | **Критическая** для rootless |
| `rootless_hint.txt`, `inside_skipped.txt`, `nsenter_used.txt`, `*_failed.txt` | все | Маркеры и ошибки | Текстовые заметки о режиме и проблемах сбора | Средняя |

### 1.3 Декларативный сбор — `collected/live_response/containers/`

Полный список см. в таблицах ниже (в Части 3). Основное отличие — это **сырой вывод команд** (текст, таблицы или JSON), без дополнительной обработки и без снимков ФС.

---

## ЧАСТЬ 2. ПОДРОБНЫЙ РАЗБОР: ЧТО ИМЕННО НАХОДИТСЯ ВНУТРИ КАЖДОГО АРТЕФАКТА

### 2.1 Runtime-level файлы (глубокий сбор)

#### info.txt
**Что находится внутри:**
Полный вывод команды `<runtime> info` (обычно в JSON-формате для современных версий, иногда текст).

Ключевые полезные поля (Docker/Podman/nerdctl):
- `ServerVersion`, `ClientInfo`
- `Storage Driver`: `overlay2` (или `fuse-overlayfs`, `btrfs` и т.д.)
- `Driver Status` / `Backing Filesystem`
- `Logging Driver` (json-file, journald и др.)
- `Cgroup Driver` (cgroupfs / systemd), `Cgroup Version` (1 или 2)
- `Security Options`: `seccomp`, `apparmor`, `selinux`, `userns`, `rootless`
- `Kernel Version`, `Operating System`, `OSType`, `Architecture`
- `CPUs`, `Total Memory`, `Docker Root Dir`
- `Plugins`, `Swarm`, `LiveRestoreEnabled`, `Experimental`
- Для rootless: `Security Options: rootless`

**Ценность:** Быстро понять, в каком режиме работает рантайм, какой storage driver (важно для анализа слоёв), включены ли опасные security options глобально.

#### system_df_v.txt
**Содержимое:** Расширенный `system df -v` — несколько секций:
- Images (с SIZE, CREATED, CONTAINERS)
- Containers (ID, IMAGE, COMMAND, CREATED, STATUS, PORTS, NAMES, SIZE)
- Local Volumes
- Build Cache (с ID, TYPE, SIZE, CREATED, LAST USED, USAGE, SHARED)

**Ценность:** Видно dangling images, stopped containers, которые занимают место, объём build cache. Полезно для понимания, что "мусора" на хосте и какие образы реально используются.

#### journal_*.log (journal_docker.log, journal_containerd.log и т.д.)
**Что внутри:** Вывод `journalctl -u <unit> --no-pager -n N` — строки в формате systemd journal:
```
Jun 06 19:30:15 hostname dockerd[1234]: time="2026-06-06T19:30:15.123456789Z" level=info msg="API listen on /var/run/docker.sock"
Jun 06 19:31:22 hostname containerd[567]: ... containerd successfully booted in ...
```

**Ценность:** Хронология событий демона — запуск/перезапуск контейнеров, ошибки pull, проблемы с overlay, OOM, restart policy срабатывания. Часто содержит точные timestamp'ы, которых нет в других логах.

#### runtime_sockets.txt
**Содержимое:** 
```
srw-rw---- 1 root docker 0 Jun  6 12:00 /var/run/docker.sock
  File: /var/run/docker.sock
  Size: 0          Blocks: 0          IO Block: 4096   socket
...
```

**Ценность:** Показывает, кто имеет доступ к сокету (группа docker = практически root на хосте). Критично для оценки риска container escape.

#### overlay2_layers.txt / podman_overlay_listing.txt и т.п.
**Содержимое:** Просто листинги директорий слоёв, например:
```
/var/lib/docker/overlay2
drwx------  5 root root  4096 ...  0a1b2c3d4e5f...
drwx------  5 root root  4096 ...  f1e2d3c4b5a6...
...
/var/lib/docker/overlay2/0a1b2c3d4e5f.../
link
diff/
merged/
work/
```

**Ценность:** Позволяет понять структуру слоёв на диске, найти orphaned layers (когда контейнер/образ удалён, но слой остался), иногда увидеть имена через `link` файлы.

#### registry_config_*.json и podman_auth_*.json
**Содержимое:** Стандартные файлы Docker/Podman auth:
```json
{
  "auths": {
    "https://index.docker.io/v1/": { "auth": "base64user:pass" },
    "myregistry.local": { "username": "...", "password": "..." }
  },
  "credHelpers": { "gcr.io": "gcloud" }
}
```

**Ценность:** Украденные или оставленные credentials к registry. Можно использовать для pull вредоносных образов или понять, откуда тянули образы.

### 2.2 Per-container метаданные (глубокий сбор)

#### inspect.json (самый важный файл)
**Что находится внутри:** Полный JSON-объект от `<runtime> inspect <cid>`.

Основные топ-уровневые разделы:
- `Id`, `Created`, `Path`, `Args[]`
- `State`: `Running`, `Paused`, `Restarting`, `Pid`, `ExitCode`, `StartedAt`, `FinishedAt`, `Health`, `OOMKilled` и т.д.
- `Config`: почти всё, что было в Dockerfile / --env / --entrypoint / --cmd / Labels / ExposedPorts
- `HostConfig`: **самый критичный для безопасности** раздел (см. ниже)
- `GraphDriver`: `Name: "overlay2"`, `Data: { "LowerDir", "MergedDir", "UpperDir", "WorkDir" }` — реальные пути на хосте к слоям этого контейнера
- `Mounts[]`: все volume и bind mounts (Source, Destination, Mode, RW, Type, Propagation)
- `NetworkSettings`: IP, Mac, Ports, Networks (с деталями каждого network)
- `Image`, `ResolvConfPath`, `HostnamePath`, `HostsPath`, `LogPath` и др.

**Особенно ценные подсекции** (они же выносятся в отдельные файлы):
- `.HostConfig` → `hostconfig.json`
- `.Config` → `config.json`
- `.NetworkSettings` → `networksettings.json`

#### hostconfig.json
**Что находится внутри (ключевые опасные поля):**
```json
{
  "Binds": ["/host/path:/container/path:rw", ...],
  "Privileged": true,
  "PidMode": "host",
  "NetworkMode": "host",
  "IpcMode": "host",
  "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
  "CapDrop": [],
  "Devices": [{"PathOnHost": "/dev/sda", ...}],
  "SecurityOpt": ["seccomp=unconfined", "apparmor=unconfined"],
  "ReadonlyRootfs": false,
  "UsernsMode": "",
  ...
}
```

**Ценность:** Прямые индикаторы возможного побега из контейнера.

#### suspicious_config.txt (лучший файл для быстрого просмотра)
**Точное содержимое** (генерируется по шаблону из кода):

```
Container: /web
Image: nginx:latest
Privileged: true
Host PID: host
Host Network: host
Host IPC: 
Host Userns: 
ReadOnly Rootfs: false
Capabilities Add: ["SYS_ADMIN","NET_ADMIN"]
Devices: [{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]
Binds: ["/:/host:rw"]
SecurityOpt: ["seccomp=unconfined"]
```

**Что там находится:** Специально выбранные поля из HostConfig + Config, которые чаще всего используются при атаках / побегах. Очень удобно для triage — не нужно читать огромный inspect.json.

#### image_history.txt
**Содержимое:** Вывод `image history --no-trunc` — история слоёв образа:
```
IMAGE          CREATED       CREATED BY                                      SIZE      COMMENT
<sha>          3 weeks ago   /bin/sh -c #(nop)  CMD ["nginx" "-g" "daemon...   0B        
<sha>          3 weeks ago   /bin/sh -c #(nop)  EXPOSE 80                     0B        
<sha>          3 weeks ago   /bin/sh -c #(nop)  STOPSIGNAL SIGQUIT            0B        
<sha>          3 weeks ago   /bin/sh -c #(nop)  ADD file:... in /             55.3MB    
...
```

**Ценность:** Видно, какие команды выполнялись при сборке образа (часто там остаются секреты в RUN, или видно, что образ собран злоумышленником).

### 2.3 Снимки состояния (CRIU hot copy)

**Жёсткое правило:** Legacy `export`/`commit`/`save` запрещены. Единственный механизм — CRIU checkpoint (live, `--leave-running`).

**Артефакты (только для running):**
- `snapshot/checkpoint.tar.gz` — архив (podman — restorable).
- `snapshot/checkpoint_info.txt` — метод, статус, предупреждения (для docker — "EXPERIMENTAL").
- `snapshot/checkpoint_manifest.txt`

**Для stopped:** `snapshot/checkpoint_skipped.txt` + host overlay listings (runtime-level).

**Поддержка:**
- podman: полная (нативный, приоритет №1).
- containerd/nerdctl/crictl: хорошая (ctr + criu dump).
- docker: базовая (experimental, с предупреждением).

### 2.4 Данные изнутри контейнера и с хоста (/proc + nsenter)

#### ps.txt, env.txt, network.txt, mounts.txt (running)
**Обычный вывод** команд, выполненных через `docker exec` или `nsenter --target <pid> ...`:
- `ps auxww` или `ps -ef` — процессы внутри контейнера (PID, USER, COMMAND и т.д.)
- `env` — все переменные окружения (часто содержат пароли, ключи, endpoint'ы)
- `ss -tuln` / `netstat` — слушающие сокеты
- `cat /proc/mounts` или `mount` — какие файловые системы и bind-маунты примонтированы

#### cgroup.txt
Содержимое `/proc/<pid>/cgroup`:
```
12:memory:/docker/abc123...
11:cpu,cpuacct:/docker/abc123...
...
0::/
```

Показывает, в каких cgroup находится процесс (полезно для идентификации и понимания ограничений).

#### namespaces.txt
`ls -l /proc/<pid>/ns/`:
```
lrwxrwxrwx 1 root root 0 ... cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx 1 root root 0 ... net -> 'net:[4026531992]'
...
```

Если значения namespace inode совпадают с хостовыми — контейнер использует host namespace (опасно).

#### proc_*.txt (самые мощные forensic артефакты при ограниченном образе)

- **proc_cmdline.txt**: Аргументы командной строки процесса, разделённые \0. Первое слово — обычно исполняемый файл.
- **proc_environ.txt** / **proc_environ_readable.txt**: Переменные окружения процесса (сырой и с \0→\n). Часто более полные, чем `env` внутри.
- **proc_status.txt**: 
  ```
  Name:   nginx
  State:  S (sleeping)
  Pid:    12345
  PPid:   1
  Uid:    101     101     101     101
  Gid:    101     101     101     101
  CapInh: 0000000000000000
  CapPrm: 00000000a80425fb
  CapEff: 00000000a80425fb
  CapBnd: 00000000a80425fb
  CapAmb: 0000000000000000
  ...
  ```
  Показывает реальные capabilities процесса, uid/gid маппинг, состояние.
- **proc_exe.txt**: Куда указывает `/proc/<pid>/exe` (полный путь к исполняемому файлу внутри контейнера или на хосте).
- **proc_fd.txt**: Содержимое директории fd (номера → symlink'ы на файлы/сокеты/устройства). Показывает, какие файлы/сети открыты процессом.
- **proc_maps.txt**: Memory mappings процесса (библиотеки, стек, heap, загруженные .so).
- **proc_cwd.txt**: Текущая рабочая директория процесса.

**proc_dir_listing.txt** — просто `ls -la /proc/<pid>/` — обзор всех доступных псевдофайлов.

#### uid_map.txt / gid_map.txt (rootless)
Типичное содержимое:
```
         0      100000      65536
```
(в контейнере uid 0 отображается в uid 100000 на хосте, и т.д. на 65536 записей).

**Ценность:** Позволяет понять, как user namespace настроен, и искать возможности escape через неправильные маппинги или доступ к файлам хоста с неправильными uid.

### 2.5 Декларативные артефакты (live_response/containers)

**Общее правило:**
- Файлы вида `docker_xxx_<cid>.txt` или `podman_xxx_<cid>.txt` — это **сырой вывод** соответствующей команды для каждого контейнера.
- Пример: `docker_inspect_<cid>.txt` содержит примерно то же, что и `inspect.json` из глубокого сбора, но в **человеческом текстовом формате** (не чистый JSON), плюс некоторые команды (top, logs, diff, stats) дают данные, которых в глубоком сборе может не быть или они собираются иначе.
- `docker_container_ls_--all_--size.txt` — таблица всех контейнеров (включая stopped).
- `docker_diff_<cid>.txt` — список изменённых/добавленных/удалённых файлов в контейнере относительно образа (очень полезно, но не полный FS snapshot).
- `docker_top_<cid>.txt` — процессы, которые видит `docker top` (через API, не всегда совпадает с ps внутри).
- Аналогично для podman (полностью зеркальный набор).
- Для LXC/pct/jls/zone — это в основном списки и `config show` / `info` в текстовом виде.

**Сравнение с глубоким сбором:**
- Декларативный: больше "классических" команд (volume ls, network ls, diff, top, stats).
- Глубокий: структурированные JSON + CRIU checkpoint (hot copy только для running) + данные ядра хоста (/proc) + build cache + auth + suspicious summary + host overlay listings + criu_version.txt.

---

## ЧАСТЬ 3. ДЕКЛАРАТИВНЫЕ АРТЕФАКТЫ — ПОЛНЫЕ СПИСКИ ПО РАНТАЙМАМ

(таблицы с точными output_file из YAML — см. предыдущую версию документа; они не изменились).

**Docker (декларативно)** — см. оригинальные 16 артефактов в docker.yaml (ls, inspect, logs, top, diff, stats, volumes, networks и т.д.).

Аналогично для podman (полный зеркальный набор).

containerd: только `containerd_config_dump.txt`.

LXC, pct, jls, zoneadm — списки и per-instance конфиги (см. таблицы в предыдущих разделах).

---

## СВОДКА: ГДЕ ИСКАТЬ ЧТО

- Хочешь быстро увидеть опасные контейнеры → `suspicious_config.txt` во всех поддиректориях `containers/*/`
- Хочешь состояние памяти + FS diff running контейнера (лучший forensic snapshot) → `snapshot/checkpoint.tar.gz` + `checkpoint_info.txt` (CRIU hot copy). Для stopped — host overlay layers + metadata.
- Хочешь процессы/сеть/окружение изнутри → `ps.txt`, `env.txt`, `network.txt` + `proc_environ_readable.txt`
- Хочешь понять, как контейнер "вырвался" в host namespaces → `hostconfig.json` + `namespaces.txt` + `uid_map.txt`
- Timeline событий демона → `journal_containerd.log` / `journal_docker.log`
- Credentials и registry → `registry_config_*.json` и `podman_auth_*.json`
- Для LXC/Proxmox/Jails/Solaris — только `live_response/containers/`

---

*Документ содержит полный перечень всех артефактов + детальный разбор того, что находится внутри каждого файла (2026).*
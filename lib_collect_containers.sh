#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2006,SC1091
#
# lib/collect_containers.sh
#
# Enhanced container collection for UAC.
# Performs deep forensic acquisition from container runtimes
# (docker, podman, nerdctl, crictl), including stopped containers.
#
# This module augments (does not replace) the declarative artifacts
# located in artifacts/live_response/containers/.
#
# Environment variables (all optional):
#   UAC_COLLECT_CONTAINERS=0|1                 Enable/disable collection (default: 1)
#   UAC_CONTAINER_RUNTIMES="docker podman ..." Override list of runtimes to check
#   UAC_CONTAINER_EXEC_TIMEOUT=5               Timeout (seconds) for exec inside containers
#   UAC_CONTAINER_EXPORT_MAX_SIZE_MB=0         Skip export if container > this size in MB (0 = no limit)
#
# Functions provided:
#   _collect_containers   - Main function (recommended)
#   collect_containers    - Backwards-compatible wrapper
#
# Sets on completion:
#   __UAC_CONTAINER_COUNT   (integer)
#   __UAC_CONTAINER_SUMMARY (string)
#

_collect_containers() {
    __cc_total=0
    __cc_runtimes_used=""

    # Allow full override of which runtimes to attempt
    if [ -n "${UAC_CONTAINER_RUNTIMES:-}" ]; then
        __cc_runtimes="${UAC_CONTAINER_RUNTIMES}"
    else
        __cc_runtimes="docker podman nerdctl crictl"
    fi

    __cc_exec_timeout="${UAC_CONTAINER_EXEC_TIMEOUT:-5}"
    __cc_export_max_mb="${UAC_CONTAINER_EXPORT_MAX_SIZE_MB:-0}"

    _verbose_msg "Starting enhanced container collection (runtimes: ${__cc_runtimes})"

    for __cc_runtime in $__cc_runtimes; do
        if ! command_exists "${__cc_runtime}"; then
            continue
        fi

        # More reliable than simple command -v: check if the daemon actually responds
        if ! "${__cc_runtime}" ps -q >/dev/null 2>&1; then
            _log_msg WRN "Container runtime '${__cc_runtime}' found but daemon not responding"
            continue
        fi

        _log_msg INF "Container runtime active: ${__cc_runtime}"
        printf "[+] Container runtime detected: %s\n" "${__cc_runtime}" >&2

        __cc_containers=$("${__cc_runtime}" ps -aq 2>/dev/null || true)

        # Create directory early for runtime-level artifacts
        __cc_runtime_dir="${__UAC_TEMP_DATA_DIR}/collected/containers/${__cc_runtime}"
        mkdir -p "${__cc_runtime_dir}" 2>/dev/null || true

        # === Runtime-level forensic artifacts (very valuable) ===
        "${__cc_runtime}" system df -v 2>/dev/null > "${__cc_runtime_dir}/system_df_v.txt" || true
        "${__cc_runtime}" info 2>/dev/null > "${__cc_runtime_dir}/info.txt" || true
        "${__cc_runtime}" version 2>/dev/null > "${__cc_runtime_dir}/version.txt" || true

        # === Systematic Runtime Logs Collection ===
        # Journald logs for main runtimes
        journalctl -u docker --no-pager -n 2000 2>/dev/null > "${__cc_runtime_dir}/journal_docker.log" || true
        journalctl -u podman --no-pager -n 1000 2>/dev/null > "${__cc_runtime_dir}/journal_podman.log" || true
        journalctl -u containerd --no-pager -n 2000 2>/dev/null > "${__cc_runtime_dir}/journal_containerd.log" || true
        journalctl -u buildkit --no-pager -n 500 2>/dev/null > "${__cc_runtime_dir}/journal_buildkit.log" || true

        # File-based logs (common locations)
        for logfile in \
            /var/log/docker.log \
            /var/log/docker/docker.log \
            /var/log/containerd.log \
            /var/log/podman.log \
            /var/log/containers/*.log; do
            if [ -f "$logfile" ]; then
                cp "$logfile" "${__cc_runtime_dir}/$(basename $logfile)" 2>/dev/null || true
            fi
        done

        # Docker/Podman specific log locations
        if [ -d "/var/lib/docker/containers" ]; then
            find /var/lib/docker/containers -name "*.log" -type f 2>/dev/null | head -20 | while read f; do
                cp "$f" "${__cc_runtime_dir}/docker_container_$(basename $(dirname $f)).log" 2>/dev/null || true
            done
        fi

        # containerd-specific rich collection via ctr (currently underused)
        if [ "${__cc_runtime}" = "containerd" ] || command_exists ctr; then
            ctr --namespace k8s.io containers list 2>/dev/null > "${__cc_runtime_dir}/ctr_containers.txt" || true
            ctr --namespace k8s.io images list 2>/dev/null > "${__cc_runtime_dir}/ctr_images.txt" || true
            ctr --namespace k8s.io snapshots list 2>/dev/null > "${__cc_runtime_dir}/ctr_snapshots.txt" || true
            ctr --namespace k8s.io content list 2>/dev/null | head -100 > "${__cc_runtime_dir}/ctr_content.txt" || true
            ctr --namespace k8s.io leases list 2>/dev/null > "${__cc_runtime_dir}/ctr_leases.txt" || true
        fi

        # Storage driver / overlay2 metadata (high value, metadata only)
        if [ -d "/var/lib/docker/overlay2" ]; then
            ls -la /var/lib/docker/overlay2 2>/dev/null | head -50 > "${__cc_runtime_dir}/overlay2_listing.txt" || true
            find /var/lib/docker/overlay2 -maxdepth 2 -type d 2>/dev/null | head -30 > "${__cc_runtime_dir}/overlay2_layers.txt" || true
        fi
        if [ -d "/var/lib/containers/storage/overlay" ]; then
            ls -la /var/lib/containers/storage/overlay 2>/dev/null | head -50 > "${__cc_runtime_dir}/podman_overlay_listing.txt" || true
        fi
        if [ -d "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs" ]; then
            ls -la /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs 2>/dev/null | head -50 > "${__cc_runtime_dir}/containerd_overlayfs_listing.txt" || true
        fi

        # === Runtime socket permissions and exposure (important for risk assessment) ===
        for sock in \
            /var/run/docker.sock \
            /var/run/docker/docker.sock \
            /run/docker.sock \
            /run/containerd/containerd.sock \
            /var/run/containerd/containerd.sock \
            /run/user/*/podman/podman.sock \
            /run/podman/podman.sock; do
            if [ -S "$sock" ] || [ -e "$sock" ]; then
                ls -l "$sock" 2>/dev/null >> "${__cc_runtime_dir}/runtime_sockets.txt"
                stat "$sock" 2>/dev/null >> "${__cc_runtime_dir}/runtime_sockets.txt"
                echo "---" >> "${__cc_runtime_dir}/runtime_sockets.txt"
            fi
        done
        # Also check common containerd CRI socket
        if [ -S "/var/run/containerd/containerd.sock" ]; then
            ls -l /var/run/containerd/containerd.sock >> "${__cc_runtime_dir}/runtime_sockets.txt" 2>/dev/null || true
        fi

        # === Build Artifacts Collection (Docker BuildKit + Podman + containerd) ===
        # Docker / BuildKit build cache (read-only inspection)
        if command_exists docker; then
            docker buildx du 2>/dev/null > "${__cc_runtime_dir}/docker_buildx_du.txt" || true
            docker system df -v 2>/dev/null > "${__cc_runtime_dir}/docker_system_df_full.txt" || true
            # List build cache without deleting
            find /var/lib/docker/buildkit -type f 2>/dev/null | head -100 > "${__cc_runtime_dir}/docker_buildkit_files.txt" || true
        fi

        # Podman build cache (read-only)
        if command_exists podman; then
            podman system df -v 2>/dev/null > "${__cc_runtime_dir}/podman_system_df_full.txt" || true
            find /var/lib/containers/storage -path '*build*' -type f 2>/dev/null | head -50 > "${__cc_runtime_dir}/podman_build_files.txt" || true
        fi

        # containerd content store (often contains build artifacts)
        if command_exists ctr; then
            ctr --namespace k8s.io content list 2>/dev/null | grep -i -E 'build|layer' > "${__cc_runtime_dir}/containerd_build_related_content.txt" || true
            ctr --namespace k8s.io leases list 2>/dev/null > "${__cc_runtime_dir}/containerd_leases.txt" || true
        fi

        # Common build cache / buildkit directories (metadata only, safe)
        for build_dir in \
            /var/lib/docker/buildkit \
            /var/lib/containers/storage/build \
            /root/.local/share/containers/build \
            /var/lib/containerd/io.containerd.content.v1.content; do
            if [ -d "$build_dir" ]; then
                echo "=== $build_dir ===" >> "${__cc_runtime_dir}/build_cache_structure.txt"
                du -sh "$build_dir" 2>/dev/null >> "${__cc_runtime_dir}/build_cache_structure.txt" || true
                find "$build_dir" -maxdepth 3 -type f \( -name "*.json" -o -name "*.toml" -o -name "*.db" \) 2>/dev/null | head -30 >> "${__cc_runtime_dir}/build_cache_structure.txt" || true
                echo "" >> "${__cc_runtime_dir}/build_cache_structure.txt"
            fi
        done

        # Try to get daemon config if accessible
        if [ -f "/etc/docker/daemon.json" ]; then
            cp "/etc/docker/daemon.json" "${__cc_runtime_dir}/daemon.json" 2>/dev/null || true
        fi
        if [ -f "/etc/containers/storage.conf" ]; then
            cp "/etc/containers/storage.conf" "${__cc_runtime_dir}/storage.conf" 2>/dev/null || true
        fi

        # === Registry authentication and image pull history (medium priority) ===
        # Docker
        for user_home in /root /home/*; do
            if [ -f "$user_home/.docker/config.json" ]; then
                cp "$user_home/.docker/config.json" "${__cc_runtime_dir}/registry_config_$(basename $user_home).json" 2>/dev/null || true
            fi
        done
        # Podman
        for user_home in /root /home/*; do
            if [ -f "$user_home/.config/containers/auth.json" ]; then
                cp "$user_home/.config/containers/auth.json" "${__cc_runtime_dir}/podman_auth_$(basename $user_home).json" 2>/dev/null || true
            fi
        done
        # System-wide (less common but possible)
        if [ -f "/etc/docker/config.json" ]; then
            cp "/etc/docker/config.json" "${__cc_runtime_dir}/system_docker_config.json" 2>/dev/null || true
        fi
        if [ -z "${__cc_containers}" ]; then
            continue
        fi

        __cc_runtime_count=0

        for __cc_cid in ${__cc_containers}; do
            __cc_name=$("${__cc_runtime}" inspect --format '{{.Name}}' "${__cc_cid}" 2>/dev/null | sed 's|^/||')
            [ -z "${__cc_name}" ] && __cc_name="${__cc_cid}"

            # Sanitize directory name
            __cc_safe_name=$(echo "${__cc_name}" | tr -c '[:alnum:]._-' '_')
            __cc_cdir="${__cc_runtime_dir}/${__cc_safe_name}_${__cc_cid}"
            mkdir -p "${__cc_cdir}" 2>/dev/null || true

            _log_msg INF "Collecting container (${__cc_runtime}): ${__cc_name} (${__cc_cid})"

            # === Metadata ===
            "${__cc_runtime}" inspect "${__cc_cid}" > "${__cc_cdir}/inspect.json" 2>/dev/null || true
            "${__cc_runtime}" logs --since 24h "${__cc_cid}" > "${__cc_cdir}/logs.txt" 2>/dev/null || true

            # Additional high-value forensic metadata
            "${__cc_runtime}" inspect --format '{{json .Config}}' "${__cc_cid}" > "${__cc_cdir}/config.json" 2>/dev/null || true
            "${__cc_runtime}" inspect --format '{{json .HostConfig}}' "${__cc_cid}" > "${__cc_cdir}/hostconfig.json" 2>/dev/null || true
            "${__cc_runtime}" inspect --format '{{json .NetworkSettings}}' "${__cc_cid}" > "${__cc_cdir}/networksettings.json" 2>/dev/null || true

            # Image and security context (very useful for forensics)
            image_id=$("${__cc_runtime}" inspect --format '{{.Image}}' "${__cc_cid}" 2>/dev/null || echo "")
            if [ -n "$image_id" ]; then
                "${__cc_runtime}" image inspect "$image_id" > "${__cc_cdir}/image_inspect.json" 2>/dev/null || true
                "${__cc_runtime}" history --no-trunc "$image_id" > "${__cc_cdir}/image_history.txt" 2>/dev/null || true
            fi

            # Security options (capabilities, seccomp, apparmor, etc.)
            "${__cc_runtime}" inspect --format '{{json .HostConfig.SecurityOpt}}' "${__cc_cid}" > "${__cc_cdir}/securityopt.json" 2>/dev/null || true
            "${__cc_runtime}" inspect --format '{{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}}' "${__cc_cid}" > "${__cc_cdir}/capabilities.txt" 2>/dev/null || true

            # === Suspicious / high-risk configuration summary (excellent for triage) ===
            "${__cc_runtime}" inspect --format '
Container: {{.Name}}
Image: {{.Config.Image}}
Privileged: {{.HostConfig.Privileged}}
Host PID: {{.HostConfig.PidMode}}
Host Network: {{.HostConfig.NetworkMode}}
Host IPC: {{.HostConfig.IpcMode}}
Host Userns: {{.HostConfig.UsernsMode}}
ReadOnly Rootfs: {{.HostConfig.ReadonlyRootfs}}
Capabilities Add: {{json .HostConfig.CapAdd}}
Devices: {{json .HostConfig.Devices}}
Binds: {{json .HostConfig.Binds}}
SecurityOpt: {{json .HostConfig.SecurityOpt}}
' "${__cc_cid}" 2>/dev/null > "${__cc_cdir}/suspicious_config.txt" || true

            # Rootless container hints (very relevant for Docker rootless and Podman rootless)
            if echo "${__cc_name}" | grep -qi rootless || [ -n "${XDG_RUNTIME_DIR:-}" ]; then
                echo "Possible rootless container detected" > "${__cc_cdir}/rootless_hint.txt"
                # Try to collect user namespace mapping info from host
                cat "/proc/${__cc_pid}/uid_map" 2>/dev/null > "${__cc_cdir}/uid_map.txt" || true
                cat "/proc/${__cc_pid}/gid_map" 2>/dev/null > "${__cc_cdir}/gid_map.txt" || true
            fi

            # === Full filesystem export (works on stopped containers) ===
            __cc_snapshot_dir="${__cc_cdir}/snapshot"
            mkdir -p "${__cc_snapshot_dir}" 2>/dev/null || true

            __cc_skip_export=false
            if [ "${__cc_export_max_mb}" -gt 0 ] 2>/dev/null; then
                __cc_size=$("${__cc_runtime}" inspect --format '{{.SizeRootFs}}' "${__cc_cid}" 2>/dev/null || echo 0)
                __cc_size_mb=$(( __cc_size / 1024 / 1024 2>/dev/null || echo 0 ))
                if [ "${__cc_size_mb}" -gt "${__cc_export_max_mb}" ]; then
                    echo "Export skipped: estimated size ${__cc_size_mb}MB exceeds limit ${__cc_export_max_mb}MB" \
                        > "${__cc_snapshot_dir}/export_skipped.txt"
                    __cc_skip_export=true
                    _log_msg WRN "Export skipped for large container ${__cc_name} (${__cc_size_mb}MB)"
                fi
            fi

            if [ "${__cc_skip_export}" = false ]; then
                if "${__cc_runtime}" export "${__cc_cid}" > "${__cc_snapshot_dir}/filesystem.tar" 2>/dev/null; then
                    echo "filesystem.tar" > "${__cc_snapshot_dir}/snapshot_manifest.txt"
                else
                    echo "export failed" > "${__cc_snapshot_dir}/export_failed.txt"
                    _log_msg ERR "Filesystem export failed for container ${__cc_name}"
                fi
            fi

            # === Inside-container collection (only for running containers) ===
            __cc_running=$("${__cc_runtime}" inspect --format '{{.State.Running}}' "${__cc_cid}" 2>/dev/null || echo "false")

            if [ "${__cc_running}" = "true" ]; then
                # Prefer modern 'ss' over legacy 'netstat'
                _collect_container_exec "${__cc_runtime}" "${__cc_cid}" "${__cc_exec_timeout}" \
                    'ps auxww 2>/dev/null || ps -ef 2>/dev/null || echo "ps unavailable"' \
                    "${__cc_cdir}/ps.txt"

                _collect_container_exec "${__cc_runtime}" "${__cc_cid}" "${__cc_exec_timeout}" \
                    'env 2>/dev/null || printenv 2>/dev/null || echo "env unavailable"' \
                    "${__cc_cdir}/env.txt"

                _collect_container_exec "${__cc_runtime}" "${__cc_cid}" "${__cc_exec_timeout}" \
                    'ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "network tools unavailable"' \
                    "${__cc_cdir}/network.txt"

                _collect_container_exec "${__cc_runtime}" "${__cc_cid}" "${__cc_exec_timeout}" \
                    'cat /proc/mounts 2>/dev/null || mount 2>/dev/null || echo "mount info unavailable"' \
                    "${__cc_cdir}/mounts.txt"
            else
                echo "Container not running - inside collection skipped" > "${__cc_cdir}/inside_skipped.txt"
            fi

            # === nsenter fallback (extremely valuable for deep forensics) ===
            __cc_pid=$("${__cc_runtime}" inspect --format '{{.State.Pid}}' "${__cc_cid}" 2>/dev/null || echo 0)

            if [ "${__cc_pid}" -gt 0 ] 2>/dev/null; then
                # Always useful forensic artifacts
                cat "/proc/${__cc_pid}/cgroup" 2>/dev/null > "${__cc_cdir}/cgroup.txt" || true
                ls -l "/proc/${__cc_pid}/ns/" 2>/dev/null > "${__cc_cdir}/namespaces.txt" || true

                # Enhanced host-side process artifacts for the container PID (high forensic value)
                for f in cmdline environ status limits stat maps fd cwd exe comm; do
                    cat "/proc/${__cc_pid}/${f}" 2>/dev/null > "${__cc_cdir}/proc_${f}.txt" || true
                done
                ls -la "/proc/${__cc_pid}/" 2>/dev/null > "${__cc_cdir}/proc_dir_listing.txt" || true
                # Readable environment
                cat "/proc/${__cc_pid}/environ" 2>/dev/null | tr '\0' '\n' > "${__cc_cdir}/proc_environ_readable.txt" || true

                # Use nsenter only if we didn't get useful data from exec
                if [ ! -s "${__cc_cdir}/ps.txt" ] || \
                   grep -qi "unavailable\|skipped\|failed" "${__cc_cdir}/ps.txt" 2>/dev/null; then

                    if command_exists nsenter; then
                        _log_msg INF "Using nsenter fallback for PID ${__cc_pid} (${__cc_name})"
                        nsenter --target "${__cc_pid}" --mount --uts --ipc --net --pid \
                            ps auxww 2>/dev/null > "${__cc_cdir}/ps.txt" || true
                        nsenter --target "${__cc_pid}" --mount \
                            env 2>/dev/null > "${__cc_cdir}/env.txt" || true
                        nsenter --target "${__cc_pid}" --net \
                            'ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "no network info"' \
                            2>/dev/null > "${__cc_cdir}/network.txt" || true
                        echo "nsenter fallback used (PID ${__cc_pid})" > "${__cc_cdir}/nsenter_used.txt"
                    fi
                fi
            fi

            __cc_runtime_count=$(( __cc_runtime_count + 1 ))
        done

        if [ "${__cc_runtime_count}" -gt 0 ]; then
            __cc_total=$(( __cc_total + __cc_runtime_count ))
            __cc_runtimes_used="${__cc_runtimes_used} ${__cc_runtime}"
            _log_msg INF "Container collection completed for ${__cc_runtime}: ${__cc_runtime_count} containers"
        fi
    done

    __UAC_CONTAINER_COUNT=${__cc_total}

    if [ "${__cc_total}" -gt 0 ]; then
        __UAC_CONTAINER_SUMMARY="Runtimes:${__cc_runtimes_used} | Total: ${__cc_total} (incl. stopped)"
        printf "[+] Collected from %d containers across runtimes:%s\n" "${__cc_total}" "${__cc_runtimes_used}" >&2
    else
        __UAC_CONTAINER_SUMMARY="No containers found"
    fi

    _log_msg INF "Container collection finished. Total containers: ${__cc_total}"
}

# Internal helper: execute command inside container with optional timeout
_collect_container_exec() {
    __cce_runtime="$1"
    __cce_cid="$2"
    __cce_timeout="$3"
    __cce_cmd="$4"
    __cce_outfile="$5"

    if command_exists timeout; then
        timeout "${__cce_timeout}" \
            "${__cce_runtime}" exec "${__cce_cid}" sh -c "${__cce_cmd}" \
            > "${__cce_outfile}" 2>/dev/null || echo "exec failed or timed out" > "${__cce_outfile}"
    else
        "${__cce_runtime}" exec "${__cce_cid}" sh -c "${__cce_cmd}" \
            > "${__cce_outfile}" 2>/dev/null || echo "exec failed" > "${__cce_outfile}"
    fi
}

# Backwards compatibility wrapper (the main uac script still calls collect_containers)
collect_containers() {
    _collect_containers
}

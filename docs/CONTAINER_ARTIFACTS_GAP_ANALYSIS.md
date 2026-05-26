# Container Artifact Collection Gap Analysis - UAC
# Focused on: Docker, Podman, containerd only

**Date:** 2026-05-26  
**Scope:** Docker, Podman, containerd (no Kubernetes/CRI-O/LXC)

## Current Strengths

- Strong per-container metadata (inspect, logs, top, diff, security options, capabilities, image history).
- Full filesystem export for stopped containers.
- Excellent deep inside-container view via nsenter fallback.
- Good runtime-level collection (system df, info, some configs).
- Solid declarative coverage via YAML for Docker and Podman.

## Remaining Gaps (Prioritized for Docker / Podman / containerd)

### High Priority Improvements (Recommended)

| # | Gap | Why Valuable | Current Coverage | Effort | Priority for Docker/Podman/containerd |
|---|-----|--------------|------------------|--------|---------------------------------------|
| 1 | **Storage driver deep metadata** (overlay2 layers, whiteouts, deleted files info) | Shows what was deleted/changed at filesystem level without full export | Only `system df -v` | Medium | **Very High** |
| 2 | **Runtime daemon logs** (journal + file logs) | Critical for timeline, errors, container lifecycle events | Partial (just added journalctl for docker/containerd) | Low | **Very High** |
| 3 | **Rootless container specifics** | User namespaces, subuid/subgid mappings, XDG_RUNTIME_DIR content | Almost none | Medium | **High** |
| 4 | **Registry auth & pull history** | `.docker/config.json`, image pull events, auth tokens | Weak | Low-Medium | High |
| 5 | **Build artifacts** (build cache, buildkit, secrets) | Important for supply-chain / malicious image builds | None | Medium | High |
| 6 | **Better containerd coverage via `ctr`** | containerd has rich `ctr` tooling that is underused | Weak (mostly crictl) | Medium | **Very High** (containerd is lagging) |
| 7 | **Host PID deep mapping + full /proc data** | Full forensic view of container processes from host side | Partial (recently improved) | Medium | High |
| 8 | **Runtime socket + permission details** | Ownership, permissions, and exposure of docker.sock / containerd.sock | None | Low | Medium-High |
| 9 | **Structured "suspicious config" summary** per container | Quick detection of privileged, hostPID, hostNetwork, dangerous mounts/devices | None (raw inspect only) | Low | High (triage value) |

### Medium Priority

- More complete recursive listing of runtime directories (`/var/lib/docker`, `/var/lib/containers`, containerd content/snapshot store) — metadata only.
- CNI configuration (even without full Kubernetes).
- Plugin / extension state.
- More detailed volume mount analysis (bind mounts from host).

### Things We Should Probably NOT Collect (or collect very carefully)

- Full layer contents / full container filesystems without strict size limits.
- All environment variables and secrets from every container by default.
- Full content of image layers.

## Recommendations (Docker + Podman + containerd focus)

1. **Prioritize containerd improvements** — it currently has the weakest coverage among the three.
2. Add dedicated storage driver inspection modules (especially overlayfs).
3. Add rootless mode detection and specific collection paths.
4. Create a "suspicious container" summary artifact.
5. Systematically collect runtime logs (both journald and traditional files).
6. Consider adding a `container_forensics` profile that enables deep collection + all container YAMLs.

## Suggested Profile Idea

Create a new profile or artifact list focused purely on containers:
- All Docker/Podman/containerd YAMLs
- Deep `collect_containers`
- Runtime logs
- Storage metadata
- Suspicious config detection

## Update: Medium Priority Items Implementation Status (Docker/Podman/containerd only)

**Recently completed (this session):**

- **Registry auth and image history** → Added collection of `~/.docker/config.json` and Podman `auth.json` for all users.
- **Runtime logs (systematic)** → Added comprehensive journalctl collection (docker, podman, containerd, buildkit) + common log file locations.
- **Build artifacts** → Added BuildKit cache inspection (`docker buildx du`), build cache structure scanning, containerd content/leases related to builds.
- **Socket permissions** → Added collection of docker.sock / containerd.sock / podman.sock with ownership and permissions.
- **Host PID artifacts (/proc)** → Expanded collection (cmdline, environ, maps, fd, cwd, exe, comm + readable environment).
- **/var/lib structure (metadata)** → Improved recursive listings for overlay2, containers/storage, and containerd snapshotter.

**Still recommended for future work:**
- Deeper overlay2 layer analysis (whiteouts, layer sizes without full export)
- Stronger rootless container support
- Runtime-level "suspicious containers" summary report
- More extensive use of `ctr` for containerd


## Security Monitor Update (Continuous Integrity)

**Implemented (2026-05-26):**
- Added `_sm_continuous_integrity_check()` function.
- Integrated continuous checks into `_sm_authorize()` for high-risk operations (`execute_artifact_command`, `execute_binary`, `before_final_packaging`, `collection_phase_start`).
- Added explicit continuous integrity check right before the main artifact collection loop in `uac`.
- This partially addresses the previous gap of "no runtime integrity monitoring".

This brings the Security Monitor closer to a cyber-immune design by performing integrity re-verification at critical points during execution, not only at startup.

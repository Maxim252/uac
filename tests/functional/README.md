# Functional and Non-Functional Tests for UAC

## Purpose
This directory contains tests validating the key requirements implemented for:

- Enhanced Container Collection (docker, podman, nerdctl, etc.)
- Security Monitor (full integration, authorization, tamper protection, auditing)

## Negative Test Cases (Important)
We specifically added negative tests for:
- Tampering of `allowed_profiles.txt` and `bin_whitelist.txt` (signature verification)
- Dangerous command patterns reaching the authorization layer
- Monitor behavior when policy files are corrupted
- Audit log integrity and append-only behavior
- Combination of monitor + container collection under stress

## Test Categories

### Container Collection
- `test_container_collection.sh` — Basic structure and key artifacts
- `test_deep_container_artifacts.sh` — suspicious_config, filesystem export, nsenter, runtime forensics

### Security Monitor
- `test_monitor_core.sh` — Core authorization and initialization
- `test_whitelist_tampering.sh` — Signature validation and tampering detection (negative)
- `test_audit_logging.sh` — Audit log creation and content
- `test_dangerous_command_logging.sh` — Dangerous commands are at least logged

### Integration
- `test_monitor_with_containers.sh` — Monitor + containers together
- `test_monitor_containers_with_mocks.sh` — Full integration using existing mock runtimes + many negative cases

## Requirements Coverage
See the main `tests/README.md` for the full list of functional and non-functional requirements being validated.

## Running

```bash
chmod +x tests/functional/**/*.sh tests/integration/*.sh

# Run everything (recommended)
bash tests/functional/containers/test_container_collection.sh
bash tests/functional/containers/test_deep_container_artifacts.sh
bash tests/functional/security_monitor/test_monitor_core.sh
bash tests/functional/security_monitor/test_whitelist_tampering.sh
bash tests/functional/security_monitor/test_audit_logging.sh
bash tests/functional/security_monitor/test_dangerous_command_logging.sh
bash tests/integration/test_monitor_with_containers.sh
bash tests/integration/test_monitor_containers_with_mocks.sh
```
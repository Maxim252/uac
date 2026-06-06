#!/bin/sh
# Minimal mock for Podman (similar structure to mock_docker)

set -e

CMD="$1"
shift || true

case "$CMD" in
    ps)
        if [ "$*" = "-aq" ]; then
            echo "pod123container"
        else
            echo "CONTAINER ID  IMAGE  STATUS"
            echo "pod123container  alpine  Up"
        fi
        ;;
    inspect)
        cat <<'JSON'
{
  "Id": "pod123container",
  "Name": "/podman-test",
  "State": { "Running": true, "Pid": 9876 },
  "SizeRootFs": 8000000
}
JSON
        ;;
    logs)
        echo "podman mock log"
        ;;
    export)
        OUT="$1"
        echo "podman-mock-fs" | tar -cf "$OUT" -T -
        ;;
    commit)
        # podman commit ...
        ;;
    save)
        while [ $# -gt 0 ]; do
            case "$1" in
                -o)
                    OUT="$2"
                    shift 2
                    if [ -n "$OUT" ]; then
                        echo "podman-layered-via-commit-save" | tar -cf "$OUT" -T -
                    fi
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        ;;
    rmi)
        ;;
    *)
        echo "mock-podman: $CMD $*" >&2
        exit 0
        ;;
esac

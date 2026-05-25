#!/bin/sh
# Mock Docker CLI for testing collect_containers()
#
# Usage:
#   PATH="/path/to/mock_runtimes:$PATH" docker ps -aq
#
# Simulates:
#   - One running container (with PID)
#   - One stopped container
#   - Realistic inspect output
#   - export that creates a small tar

set -e

CMD="$1"
shift || true

case "$CMD" in
    ps)
        case "$*" in
            -aq)
                echo "abc123def456"
                echo "7890stopped001"
                ;;
            -q)
                echo "abc123def456"   # only running
                ;;
            *)
                echo "CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS         PORTS   NAMES"
                echo "abc123def456   nginx     \"nginx\"   2 days ago   Up 2 days   80/tcp   web"
                echo "7890stopped001 busybox   \"sh\"      5 days ago   Exited (0)           stopped-box"
                ;;
        esac
        ;;

    inspect)
        CID="$1"
        case "$CID" in
            abc123def456)
                # Running container
                cat <<'JSON'
{
  "Id": "abc123def4567890",
  "Name": "/web",
  "State": {
    "Running": true,
    "Pid": 12345,
    "Status": "running"
  },
  "SizeRootFs": 45000000,
  "Config": {
    "Image": "nginx:latest"
  }
}
JSON
                ;;
            7890stopped001)
                # Stopped container
                cat <<'JSON'
{
  "Id": "7890stopped0012345",
  "Name": "/stopped-box",
  "State": {
    "Running": false,
    "Pid": 0,
    "Status": "exited"
  },
  "SizeRootFs": 12000000,
  "Config": {
    "Image": "busybox:latest"
  }
}
JSON
                ;;
            *)
                echo '{"Id":"'$CID'","Name":"/unknown","State":{"Running":false,"Pid":0}}'
                ;;
        esac
        ;;

    logs)
        echo "Mock log line 1 for container $1"
        echo "Mock log line 2 - $(date)"
        ;;

    export)
        # Simulate filesystem export - create a tiny valid tar
        OUTFILE="$1"
        if [ -n "$OUTFILE" ]; then
            # Create a minimal tar with one file
            echo "mock filesystem content from container" | tar -cf "$OUTFILE" -T -
            echo "Mock export completed: $OUTFILE" >&2
        fi
        ;;

    info)
        echo '{"ServerVersion":"24.0.0-mock"}'
        ;;

    version)
        echo 'Docker version 24.0.0-mock, build mock'
        ;;

    *)
        echo "mock-docker: unsupported command: $CMD $*" >&2
        exit 1
        ;;
esac

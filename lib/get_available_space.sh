#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Get available space (in kilobytes) on the filesystem containing the given path.
# Arguments:
#   string path: any path on the target filesystem (defaults to /)
# Returns:
#   string: available kilobytes (numeric, may be 0 on error), or empty on total failure
_get_available_space()
{
  __gas_path="${1:-/}"

  # Prefer POSIX -P output for stable column layout.
  # Column order with -P is typically: Filesystem, 1024-blocks, Used, Available, Capacity, Mounted on
  # So Available is $4.
  __gas_avail=$(df -kP "${__gas_path}" 2>/dev/null | awk 'NR==2 {print $4+0}')

  if [ -z "${__gas_avail}" ]; then
    # Fallback for older df without -P (some busybox/minimal systems)
    __gas_avail=$(df -k "${__gas_path}" 2>/dev/null | awk 'NR==2 {print $4+0}')
  fi

  # If still empty, try to at least return 0 so callers can compare
  if [ -z "${__gas_avail}" ]; then
    __gas_avail=0
  fi

  printf "%s\n" "${__gas_avail}"
}

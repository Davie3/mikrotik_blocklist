#!/bin/sh
# Run the generator in CI and record its exit code as the step output "rc".
#
# Exit 2 means the lists were written but stale feeds were left out. It is
# treated as success here so the lists are still validated and published;
# the workflow's last step then fails the run so GitHub sends a notification.
set -u

rc=0
# -u: unbuffered, so progress (stdout) and errors (stderr) stay in order in the log.
python3 -u generate.py || rc=$?
echo "rc=$rc" >>"$GITHUB_OUTPUT"
[ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]

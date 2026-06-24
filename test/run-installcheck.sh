#!/bin/sh
# Run the regression suite against a throwaway cluster of the major version that
# was baked into this image.  Executed as the container's default command; not
# meant to be run directly on a developer machine (see run-tests.sh for that).
set -eu

cd "$(dirname "$0")/.."

echo "=== regression test for PostgreSQL ${PG_MAJOR} ==="

if pg_virtualenv -v "${PG_MAJOR}" make installcheck; then
    echo "PostgreSQL ${PG_MAJOR}: PASS"
else
    status=$?
    echo "PostgreSQL ${PG_MAJOR}: FAIL"
    if [ -f regression.diffs ]; then
        echo "--- regression.diffs ---"
        cat regression.diffs
    fi
    exit "$status"
fi

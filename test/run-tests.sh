#!/bin/sh
# Build a container for each requested PostgreSQL major version and run the
# regression suite inside it.  With no arguments every supported version is
# tested; otherwise the arguments are taken as the list of versions, e.g.
#
#     test/run-tests.sh            # 12 13 14 15 16 17 18 19
#     test/run-tests.sh 17 18 19   # only these
#
# Must be run from a checkout with Docker available.
set -eu

VERSIONS="${*:-12 13 14 15 16 17 18 19}"

# Resolve the repository root so the script works from anywhere.
cd "$(CDPATH= cd "$(dirname "$0")/.." && pwd)"

passed=""
failed=""

for v in $VERSIONS; do
    echo
    echo "########## PostgreSQL $v ##########"
    if docker build --build-arg "PG_MAJOR=$v" -f test/Dockerfile -t "pg_permissions-test:$v" . \
        && docker run --rm "pg_permissions-test:$v"; then
        passed="$passed $v"
    else
        failed="$failed $v"
    fi
done

echo
echo "########## summary ##########"
echo "passed:${passed:- none}"
echo "failed:${failed:- none}"

[ -z "$failed" ]

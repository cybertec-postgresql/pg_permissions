Containerised regression tests
==============================

These files run the regression suite (`make installcheck`) against every
supported PostgreSQL major version inside throwaway Docker containers, so you
do not need a local PostgreSQL installation of each version.

Requirements
------------

- Docker (with the daemon running and reachable by the current user)

Usage
-----

Run all supported versions (currently 12 through 19) from the repository root:

    test/run-tests.sh

Or test only specific versions:

    test/run-tests.sh 17 18 19

The script builds one image per version and runs the suite in it, then prints a
summary of which versions passed and which failed.  The exit status is non-zero
if any version failed.

How it works
------------

`Dockerfile` takes a `PG_MAJOR` build argument and installs that major version
from the PostgreSQL APT repository (apt.postgresql.org), including the
`-pgdg-snapshot` repository so that not-yet-released versions (currently 19)
can be tested.  The extension is built and installed during the image build;
the container then uses `pg_virtualenv` to spin up a temporary cluster and runs
`make installcheck` against it.

To build and test a single version by hand:

    docker build --build-arg PG_MAJOR=17 -f test/Dockerfile -t pg_permissions-test:17 .
    docker run --rm pg_permissions-test:17

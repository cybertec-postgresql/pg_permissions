# Build and regression-test pg_permissions against a single PostgreSQL major
# version.  The version is selected with the PG_MAJOR build argument, e.g.
#
#     docker build --build-arg PG_MAJOR=17 -f test/Dockerfile -t pg_permissions-test:17 .
#
# Packages are taken from the PostgreSQL APT repository (apt.postgresql.org).
# Versions that have not been released yet (currently 19) are pulled from the
# additional "-pgdg-snapshot" repository.
FROM debian:bookworm-slim

ARG PG_MAJOR=16
ENV PG_MAJOR=${PG_MAJOR}
ENV DEBIAN_FRONTEND=noninteractive

# PostgreSQL APT repository plus the build tool chain.  The snapshot repository
# is added unconditionally but only carries packages for not-yet-released major
# versions, so it does no harm for released ones.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates gnupg lsb-release wget make gcc; \
    install -d /usr/share/postgresql-common/pgdg; \
    wget -qO /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    codename="$(lsb_release -cs)"; \
    printf 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg main %s\n' \
        "$codename" "$PG_MAJOR" > /etc/apt/sources.list.d/pgdg.list; \
    printf 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg-snapshot main %s\n' \
        "$codename" "$PG_MAJOR" > /etc/apt/sources.list.d/pgdg-snapshot.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        "postgresql-${PG_MAJOR}" "postgresql-server-dev-${PG_MAJOR}"; \
    rm -rf /var/lib/apt/lists/*

ENV PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:$PATH

WORKDIR /work
COPY . /work

# Install the extension into the server packages (needs root).
RUN make install PG_CONFIG="/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config"

# The regression test must not run as root; pg_virtualenv spins up a throwaway
# cluster owned by this user for the duration of the test.
RUN chown -R postgres:postgres /work
USER postgres

CMD ["test/run-installcheck.sh"]

EXTENSION = pg_permissions
DATA = pg_permissions--*.sql
DOCS = README.pg_permissions
REGRESS = sample

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

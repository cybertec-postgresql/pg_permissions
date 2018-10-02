EXTENSION = pg_permissions
DATA = pg_permissions--1.0.sql
DOCS = README.pg_permissions
REGRESS = sample

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

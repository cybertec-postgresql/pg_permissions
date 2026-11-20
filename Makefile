EXTENSION = pg_permissions
DATA = pg_permissions--*.sql
REGRESS = sample upgrade public inheritance constraints default_acl usability role_drop

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

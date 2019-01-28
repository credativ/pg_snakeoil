# pg_snakeoil/Makefile

MODULE_big = pg_snakeoil
OBJS = pg_snakeoil.o

EXTENSION = pg_snakeoil
DATA = pg_snakeoil--0.4--1.sql \
       pg_snakeoil--1.sql
PGFILEDESC = "pg_snakeoil - clamav antivirus integration"

REGRESS = pg_snakeoil

# Only works when using pgxs
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
PG_LIBS=-lclamav
SHLIB_LINK=-lclamav

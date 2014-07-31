FNAME=macgeiger

CFLAGS_OWN=-Wall -D_GNU_SOURCE
CFLAGS_DBG=-g3
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${CFLAGS}

all:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force $(RCBFLAGS) $(FNAME).c

clean:
	rm -f *.o
	rm -f $(PROGS)
	rm -f *.rcb

.PHONY: all clean optimized debug

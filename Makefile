FNAME=macgeiger

CFLAGS_OWN=-Wall -D_GNU_SOURCE
CFLAGS_DBG=-g3
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} ${CFLAGS}

SRCS=$(FNAME).c audio-backend.c channel-switch.c netgui.c

all: $(FNAME).out

$(FNAME).rcb: config.mak
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force --new $(RCBFLAGS) $(FNAME).c

$(FNAME).out: $(SRCS) $(FNAME).rcb
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force $(RCBFLAGS) $(FNAME).c

clean:
	rm -f *.o
	rm -f $(FNAME).out
	rm -f *.rcb

.PHONY: all clean optimized debug

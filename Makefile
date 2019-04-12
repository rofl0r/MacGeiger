FNAME=macgeiger

CFLAGS_OWN=-Wall -D_GNU_SOURCE
CFLAGS_DBG=-g3
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} ${CFLAGS}

SRCS=$(FNAME).c audio-backend.c channel-switch.c netgui.c

all: $(FNAME)

$(FNAME): $(SRCS)
	CFLAGS="${CFLAGS_RCB_DBG} ${CFLAGS}" rcb2 $(RCBFLAGS) $(FNAME).c

clean:
	rm -f *.o
	rm -f $(FNAME).out
	rm -f $(FNAME)
	rm -f *.rcb

.PHONY: all clean optimized debug

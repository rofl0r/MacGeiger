#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stropts.h>
#include <unistd.h>
#include "wireless-lite.h"

/* returns 0 on success. */
int set_channel(const char* iface, int channel) {
	int s;
	if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	struct iwreq req = {.u.freq.m = channel, .u.freq.flags = IW_FREQ_FIXED};
	snprintf(req.ifr_name, IFNAMSIZ, "%s", iface);

	int ret;
	if((ret = ioctl(s, SIOCSIWFREQ, &req) < 0)) perror("ioctl");
	close(s);
	return ret;
}

#ifndef LIBRARY_CODE
static int usage(char* argv0) {
	dprintf(2, "usage: %s interface channel\n", argv0);
	return 1;
}

int main(int argc, char** argv) {
	if(argc != 3) return usage(argv[0]);
	return set_channel(argv[1], atoi(argv[2]));
}
#endif


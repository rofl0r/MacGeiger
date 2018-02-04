#include "server.h"
#include "../lib/include/sblist.h"
#include "../lib/include/strlib.h"
#include <pthread.h>

static volatile int server_done = 0;

struct thread {
	long long last_update;
	pthread_t pt;
	struct client client;
	volatile int done;
};

static void dump_json_str(int fd, char *key, char *val) {
	dprintf(fd, "\"%s\" : \"%s\", ", key, val);
}
static void dump_json_int(int fd, char *key, int val) {
	dprintf(fd, "\"%s\" : %d, ", key, val);
}

static void dump_wlan_json(int fd, size_t wlanid) {
	struct wlaninfo* w = &wlans[wlanid];
	char buf[256+8];
	assert(sizeof buf >= WPS_MAX_STR_LEN*4);
	assert(sizeof buf >= sizeof(wlans[0].essid)*4);
	dprintf(fd, "{");
	dump_json_str(fd, "bssid", mac2str(w->mac, buf));
	dump_json_str(fd, "essid", sanitize_string(w->essid, buf));
	dump_json_int(fd, "channel", w->channel);
	dump_json_int(fd, "rssi", w->last_rssi);

	if(!w->wps) goto wps_done;

	//if(w->wps->vendor[0]) drintf(fd, "\"vendor_oui\" : \"%02X%02X%02X\", ", vendor[0], vendor[1], vendor[2]);
	if(w->wps->version) dump_json_int(fd, "wps_version", w->wps->version);
	if(w->wps->state) dump_json_int(fd, "wps_state", w->wps->state);
	if(w->wps->locked) dump_json_int(fd, "wps_locked", w->wps->locked);

	if(w->wps->manufacturer[0]) dump_json_str(fd, "wps_manufacturer", sanitize_string(w->wps->manufacturer, buf));
	if(w->wps->model_name[0]) dump_json_str(fd, "wps_model_name", sanitize_string(w->wps->model_name, buf));
	if(w->wps->model_number[0]) dump_json_str(fd, "wps_model_number", sanitize_string(w->wps->model_number, buf));
	if(w->wps->device_name[0]) dump_json_str(fd, "wps_device_name", sanitize_string(w->wps->device_name, buf));
	if(w->wps->ssid[0]) dump_json_str(fd, "wps_ssid", sanitize_string(w->wps->ssid, buf));
	if(w->wps->serial[0]) dump_json_str(fd, "wps_serial", sanitize_string(w->wps->serial, buf));
	if(w->wps->os_version[0]) dump_json_str(fd, "wps_os_version", sanitize_string(w->wps->os_version, buf));
	if(w->wps->uuid[0]) dump_json_str(fd, "wps_uuid", sanitize_string(w->wps->uuid, buf));
	if(w->wps->selected_registrar[0]) dump_json_str(fd, "wps_selected_registrar", sanitize_string(w->wps->selected_registrar, buf));
	if(w->wps->response_type[0]) dump_json_str(fd, "wps_response_type", sanitize_string(w->wps->response_type, buf));
	if(w->wps->primary_device_type[0]) dump_json_str(fd, "wps_primary_device_type", sanitize_string(w->wps->primary_device_type, buf));
	if(w->wps->config_methods[0]) dump_json_str(fd, "wps_config_methods", sanitize_string(w->wps->config_methods, buf));
	if(w->wps->rf_bands[0]) dump_json_str(fd, "wps_rf_bands", sanitize_string(w->wps->rf_bands, buf));

wps_done:
	dprintf(fd, "\"dummy\": 0}\n");
}

static void* clientthread(void *data) {
	struct thread *t = data;
	char buf[32];
	ssize_t n;
	size_t i;
	while(!server_done) {
		n = recv(t->client.fd, buf, sizeof buf, 0);
		if(n <= 0) break;
		if(!strcmp(buf, "LIST\n")) {
			lock();
			for(i=0; i<wlan_count; i++) {
				if(wlans[i].last_seen > t->last_update)
					dump_wlan_json(t->client.fd, i);
			}
			t->last_update = getutime64();
			unlock();
			dprintf(t->client.fd, "END\n");
		} else if (!strcmp(buf, "QUIT\n")) {
			server_done = 1;
		} else if(!strcmp(buf, "UNSELECT\n")) {
			set_selection(0);
		} else if((!strncmp(buf, "SELECT ", 7))
			  && strlen(buf) == 7 + 6*2 + 5 + 1
			  && buf[7 + 6*2 + 5] == '\n'
			) {
			unsigned char mac[6], *m = mac;
			char *p = buf + 7;
			for(i=0;i<6;i++) {
				*m = hexval(p);
				p++;
				*m = *m << 4 | hexval(p);
				m++;
				p+=2;
			}
			lock();
			for(i=0;i<wlan_count; i++) {
				if(!memcmp(wlans[i].mac, mac, 6)) {
					selection = i;
					set_selection(1);
					break;
				}
			}
			unlock();
		}
	}
	return 0;
}

static void collect(sblist *threads) {
	size_t i;
	for(i=0;i<sblist_getsize(threads);) {
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if(thread->done) {
			pthread_join(thread->pt, 0);
			sblist_delete(threads, i);
			free(thread);
		} else
			i++;
	}
}

struct netgui_config {
	int port;
	const char *listenaddr;
	pthread_t thr;
};

static void* netgui_thread(void *args) {
	struct netgui_config *cfg = args;
	signal(SIGPIPE, SIG_IGN);
	struct server s;
	sblist *threads = sblist_new(sizeof (struct thread*), 8);

	if(server_setup(&s, cfg->listenaddr, cfg->port)) {
		perror("server_setup");
		server_done = 1;
	}
	while(!server_done) {
		collect(threads);
		struct client c;
		struct thread *curr = malloc(sizeof (struct thread));
		if(!curr) goto oom;
		curr->done = 0;
		if(server_waitclient(&s, &c)) continue;
		curr->client = c;
		if(!sblist_add(threads, &curr)) {
			close(curr->client.fd);
			free(curr);
			oom:
			//dolog("rejecting connection due to OOM\n");
			usleep(16); /* prevent 100% CPU usage in OOM situation */
			continue;
		}
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
			pthread_attr_setstacksize(a, 64*1024);
		}
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0) {
			//dolog("pthread_create failed. OOM?\n");
		}
		if(a) pthread_attr_destroy(&attr);
	}
	size_t i;
	for(i=0;i<sblist_getsize(threads);i++) {
		struct thread* thread =
			*((struct thread**)sblist_get(threads, i));
		close(thread->client.fd);
	}
	collect(threads);

	return 0;
}

void netgui_start(struct netgui_config *cfg, const char *listenaddr, int port) {
	cfg->port = port;
	cfg->listenaddr = listenaddr,
	pthread_create(&cfg->thr, 0, netgui_thread, cfg);
}

void netgui_stop(struct netgui_config *cfg) {
	server_done = 1;

	/* connect to the listener so it returns from server_waitclient() */
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if(fd == -1) goto skip;

	struct addrinfo *ainfo = 0;
	const char *dst = "127.0.0.1";
	if(strcmp(cfg->listenaddr, "0.0.0.0"))
		dst = cfg->listenaddr;
	if(resolve(dst, cfg->port, &ainfo)) goto skip;

	connect(fd, ainfo->ai_addr, ainfo->ai_addrlen);
	freeaddrinfo(ainfo);

skip:
	pthread_join(cfg->thr, 0);
}

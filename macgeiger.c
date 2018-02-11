
/*
    MacGeiger WIFI AP detector
    Copyright (C) 2014 rofl0r

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pcap/pcap.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <fcntl.h>

#define GUI_FPS 40

//RcB: DEP "audio-backend.c"
#include "audio-backend.c"

#define LIBRARY_CODE
#include "channel-switch.c"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

//RcB: LINK "-lpcap"
//RcB: LINK "-lpthread"

#include "../concol/console.h"
#include "../concol/console_keys.h"
#include "../concol/fonts/allfonts.h"

#ifdef NO_COLOR
#define console_setcolor(A, B, C) do {} while(0)
#endif

static int outfd;

static int usage(const char *argv0) {
	dprintf(2, "%s network-interface\n"
		   "i.e.: %s wlan0\n", argv0, argv0
		);
	return 1;
}

/* originally 256, but that would make the struct too big for the stack */
#define WPS_MAX_STR_LEN 64
struct wps_data
{
	uint8_t version;
	uint8_t state;
	uint8_t locked;
	char manufacturer[WPS_MAX_STR_LEN];
	char model_name[WPS_MAX_STR_LEN];
	char model_number[WPS_MAX_STR_LEN];
	char device_name[WPS_MAX_STR_LEN];
	char ssid[WPS_MAX_STR_LEN];
	char uuid[WPS_MAX_STR_LEN];
	char serial[WPS_MAX_STR_LEN];
	char selected_registrar[WPS_MAX_STR_LEN];
	char response_type[WPS_MAX_STR_LEN];
	char primary_device_type[WPS_MAX_STR_LEN];
	char config_methods[WPS_MAX_STR_LEN];
	char rf_bands[WPS_MAX_STR_LEN];
	char os_version[WPS_MAX_STR_LEN];
};

static void init_wps_data(struct wps_data* wps) {
	wps->version = 0;
	wps->state = 0;
	wps->locked = 0;
	wps->manufacturer[0] = 0;
	wps->model_name[0] = 0;
	wps->model_number[0] = 0;
	wps->device_name[0] = 0;
	wps->ssid[0] = 0;
	wps->uuid[0] = 0;
	wps->serial[0] = 0;
	wps->selected_registrar[0] = 0;
	wps->response_type[0] = 0;
	wps->primary_device_type[0] = 0;
	wps->config_methods[0] = 0;
	wps->rf_bands[0] = 0;
	wps->os_version[0] = 0;
}

enum enctype {
	ET_OPEN = 0,
	ET_WEP,
	ET_WPA,
	ET_WPA2,
	ET_MAX = ET_WPA2
};

static struct wlaninfo {
	struct wps_data *wps;
	long long total_rssi;
	long long last_seen;
	uint64_t timestamp;
	unsigned long count;
	uint16_t beaconinterval;
	char essid[32];
	unsigned char mac[6];
	unsigned char channel;
	signed char last_rssi;
	signed char min_rssi;
	signed char max_rssi;
	char enctype;
} wlans[128];
static unsigned wlan_count;

static pthread_mutex_t wlan_lock = PTHREAD_MUTEX_INITIALIZER;
#define lock() pthread_mutex_lock(&wlan_lock)
#define unlock() pthread_mutex_unlock(&wlan_lock)

static signed char min, max;
static unsigned char selection, selected;
static Console co, *t = &co;
static int colorcount;

static int get_wlan_by_essid(char* essid) {
	unsigned i;
	for(i=0;i<wlan_count;i++)
		if(!strcmp(essid, wlans[i].essid)) return i;
	return -1;
}

static int get_wlan_by_mac(unsigned char mac[6]) {
	unsigned i;
	for(i=0;i<wlan_count;i++)
		if(!memcmp(mac, wlans[i].mac, 6)) return i;
	return -1;
}

static int get_new_wlan(void) {
	if(wlan_count+1<sizeof(wlans)/sizeof(wlans[0])) {
		wlans[wlan_count].min_rssi = 127;
		wlans[wlan_count].max_rssi = -127;
		return wlan_count++;
	}
	return -1;
}

static int set_rssi(struct wlaninfo *w, struct wps_data* wps) {
	int i = -1;
//	if(w->essid[0]) i = get_wlan_by_essid(w->essid);
	lock();
	if(i == -1) i = get_wlan_by_mac(w->mac);
	if(i == -1) i = get_new_wlan();
	if(i != -1) {
		struct wlaninfo *d = &wlans[i];
		if(w->essid[0]) strcpy(d->essid, w->essid);
		memcpy(d->mac, w->mac, 6);
		d->total_rssi += w->last_rssi;
		d->count++;
		d->last_rssi = w->last_rssi;
		d->channel = w->channel;
		d->timestamp = w->timestamp;
		d->beaconinterval = w->beaconinterval;
		d->min_rssi = MIN(d->min_rssi, d->last_rssi);
		d->max_rssi = MAX(d->max_rssi, d->last_rssi);
		d->enctype = w->enctype;
		if(wps->version) {
			if(!d->wps) {
				d->wps = malloc(sizeof *wps);
				if(d->wps) init_wps_data(d->wps);
			}
			if(d->wps) {
				if(!wps->manufacturer[0]) {
					d->wps->version = wps->version;
					d->wps->state = wps->state;
					d->wps->locked = wps->locked;
				} else
					memcpy(d->wps, wps, sizeof(*wps));
			}
		}
	}
	unlock();
	return i;
}

volatile int stop;
void sigh(int x) {
	stop = 1;
}

#include "radiotap_flags.h"

static unsigned get_dbm_off(unsigned flags, unsigned start_off) {
	return rt_get_flag_offset(flags, IEEE80211_RADIOTAP_DBM_ANTSIGNAL, start_off);
}

static unsigned get_chan_off(unsigned flags, unsigned start_off) {
	return rt_get_flag_offset(flags, IEEE80211_RADIOTAP_CHANNEL, start_off);
}

static unsigned channel_from_freq(unsigned freq) {
	return freq==2484?14:(freq-2407)/5;
}

struct beaconframe {
	uint16_t framecontrol;
	uint16_t duration;
	unsigned char receiver[6];
	unsigned char source[6];
	unsigned char bssid[6];
	uint16_t sequence_no;
};

static unsigned char* find_tag(unsigned const char *tagdata, unsigned tag, unsigned bytes_left) {
	while(bytes_left) {
		if(*tagdata == tag) return (unsigned char*)tagdata;
		unsigned tagsize = tagdata[1];
		tagdata+=2+tagsize;
		if(bytes_left < 2+tagsize) return 0;
		bytes_left-=2+tagsize;
	}
	return 0;
}

static long long timeval2utime(struct timeval*t) {
	return (t->tv_sec * 1000LL * 1000LL) + t->tv_usec;
}

static long long getutime64(void) {
	struct timeval t;
	gettimeofday(&t, NULL);
	return timeval2utime(&t);
}


static int filebased;

static const unsigned char* pcap_next_wrapper(pcap_t *foo, struct pcap_pkthdr *h_out) {
	if(!filebased) {
		const unsigned char* ret = 0;
		struct pcap_pkthdr *hdr_temp;
		int err = pcap_next_ex(foo, &hdr_temp, &ret);
		if(err == 1) {
			*h_out = *hdr_temp;
		} else ret = 0;
		if(ret && outfd != -1){
			struct pcap_file_pkthdr {
				unsigned sec_epoch;
				unsigned ms_sec;
				unsigned caplen;
				unsigned len;
			} hdr_out = {
				.sec_epoch = h_out->ts.tv_sec,
				.ms_sec = h_out->ts.tv_usec,
				.caplen = h_out->caplen,
				.len = h_out->len,
			};
			write(outfd, &hdr_out, sizeof hdr_out);
			write(outfd, ret, h_out->len);
		}
		return ret;
	}
	static long long pcap_file_start_time, start_time;
	static unsigned char buf[2][2048];
	static struct pcap_pkthdr h[2];
	static int actbuf;
	const unsigned char* ret;
	if(start_time == 0 || getutime64() - start_time >= timeval2utime(&h[!actbuf].ts) - pcap_file_start_time) {
		ret = pcap_next(foo, h_out);
		if(ret) {
			h[actbuf] = *h_out;
			assert(h[actbuf].len <= sizeof buf[actbuf]);
			memcpy(buf[actbuf], ret, h[actbuf].len);
			actbuf = !actbuf;
		}
		if(!start_time) {
			start_time = getutime64();
			assert(ret);
			pcap_file_start_time = timeval2utime(&h_out->ts);
			return 0;
		}
		if(ret) {
			*h_out = h[actbuf];
			return buf[actbuf];
		} else return 0;
	} else
		return 0;
}

static inline int myisascii(int x) {
	return x >= ' ' && x < 127;
}

static void dump_packet(const unsigned char* data, size_t len) {
	static const char atab[] = "0123456789abcdef";
	char hex[24*2+1], ascii[24+1];
	unsigned h = 0, a = 0;
	int fill = ' ';

	while(len) {
		len--;
		hex[h++] = atab[*data >> 4];
		hex[h++] = atab[*data & 0xf];
		ascii[a++] = myisascii(*data) ? *data : '.';
		if(a == 24) {
	dump:
			hex[h] = 0;
			ascii[a] = 0;
			printf("%s\t%s\n", hex, ascii);

			if(fill == '_') return; /* jump from filler */

			a = 0;
			h = 0;
		}
		data++;
	}
	if(a) {
	filler:
		while(a<24) {
			hex[h++] = fill;
			hex[h++] = fill;
			ascii[a++] = fill;
		}
		goto dump;
	}
	a = 0;
	fill = '_';
	goto filler;
}

void setminmax(int val) {
	min = MIN(min, val);
	max = MAX(max, val);
	char mmbuf[128];
	snprintf(mmbuf, sizeof mmbuf, "min: %d, max: %d", min, max);
	console_settitle(t, mmbuf);
}

static int get_next_ie(const unsigned char *data, size_t len, size_t *currpos) {
	if(*currpos + 2 >= len) return 0;
	*currpos = *currpos + 2 + data[*currpos + 1];
	if(*currpos >= len) return 0;
	return 1;
}

static int get_next_wps_el(const unsigned char *data, size_t len, size_t *currpos) {
	if(*currpos + 4 >= len) return 0;
	uint16_t el_len;
	memcpy(&el_len, data + 2 + *currpos, 2);
	el_len = end_be16toh(el_len);
	*currpos = *currpos + 4 + el_len;
	if(*currpos >= len) return 0;
	return 1;
}

static void process_wps_tag(const unsigned char* tag, size_t len, struct wps_data *wps) {
	unsigned const char *el;
	char *str;
	size_t el_iterator = 0, wfa_iterator, remain;
	uint16_t el_id, el_len;
	int hex;

	do {
		el = tag + el_iterator;
		remain = len - el_iterator;
		memcpy(&el_id, el, 2);
		el_id = end_be16toh(el_id);
		memcpy(&el_len, el+2, 2);
		el_len = end_be16toh(el_len);
		el += 4;
		str = 0, hex = 0;
		switch(el_id) {
			case 0x104A: /* WPS_VERSION */
				wps->version = *el;
				break;
			case 0x1044: /* WPS_STATE */
				wps->state = *el;
				break;
			case 0x1057: /* WPS_LOCKED */
				wps->locked = *el;
				break;
			case 0x1021: /* WPS_MANUFACTURER */
				str = wps->manufacturer;
				break;
			case 0x1023: /*WPS_MODEL_NAME */
				str = wps->model_name;
				break;
			case 0x1024:
				str = wps->model_number;
				break;
			case 0x1011:
				str = wps->device_name;
				break;
			case 0x1045:
				str = wps->ssid;
				break;
			case 0x1047:
				str = wps->uuid;
				hex = 1;
				break;
			case 0x1042:
				str = wps->serial;
				break;
			case 0x1041:
				str = wps->selected_registrar;
				hex = 1;
				break;
			case 0x103B:
				str = wps->response_type;
				hex = 1;
				break;
			case 0x1054:
				str = wps->primary_device_type;
				hex = 1;
				break;
			case 0x1008:
				str = wps->config_methods;
				hex = 1;
				break;
			case 0x103C:
				str = wps->rf_bands;
				hex = 1;
			case 0x102D:
				str = wps->os_version;
				break;
			case 0x1049: /* WPS_VENDOR_EXTENSION */
				if(el_len >= 5 && !memcmp(el, "\x00\x37\x2A", 3)) { /* WFA_EXTENSION */
					el_len -= 3;
					el += 3;
					wfa_iterator = 0;
					do {
						if(wfa_iterator+2 <= el_len && el[wfa_iterator] == 0 /* WPS_VERSION2_ID */) {
							wps->version = el[2];
						}
					} while(get_next_ie(el, el_len, &wfa_iterator));
				}
				break;
		}
		if(str) {
			size_t max;
			if(hex) {
				max = el_len >= WPS_MAX_STR_LEN/2 ? WPS_MAX_STR_LEN/2 - 1 : el_len;
				while(max--) {
					sprintf(str, "%02x", *el);
					el++;
					str += 2;
				}
				*str = 0;
			} else {
				max = el_len + 1 >= WPS_MAX_STR_LEN ? WPS_MAX_STR_LEN  : el_len + 1;
				snprintf(str, max, "%s", el);
			}
		}

	} while(get_next_wps_el(tag, len, &el_iterator));

}

static void process_tags(const unsigned char* tagdata, size_t tagdata_len, struct wlaninfo *temp, struct wps_data *wps) {
	unsigned const char *tag;

	/* iterate through tags */
	size_t ie_iterator = 0, remain;
	do {
		tag = tagdata + ie_iterator;
		remain = tagdata_len - ie_iterator;
		switch(tag[0]) {
		case 0: /* essid tag */
			if(tag[1] <= remain) {
				memcpy(temp->essid, tag+2, tag[1]);
				temp->essid[tag[1]] = 0;
			}
			break;
		case 3: /* chan nr */
			assert(tag[1] == 1);
			temp->channel = tag[2];
			break;
		case 0x30: /* RSN_TAG_NUMBER */
			temp->enctype = ET_WPA2;
			break;
		case 0xDD: /* VENDOR_SPECIFIC_TAG*/
			if(tag[1] >= remain) break;
			if(tag[1] >= 8 &&
			   !memcmp(tag+2, "\x00\x50\xF2\x01\x01\x00", 6))
				temp->enctype = ET_WPA;
			if(tag[1] > 4 && !memcmp(tag+2, "\x00\x50\xf2" /*micro$oft*/ "\x04" /*type WPS*/, 4))
				process_wps_tag(tag+2+4, tag[1]-4, wps);
			break;
		}

	} while(get_next_ie(tagdata, tagdata_len, &ie_iterator));
}

static int process_frame(pcap_t *foo) {
	struct pcap_pkthdr h;
	const unsigned char* data = pcap_next_wrapper(foo, &h);
	if(data) {
		if(console_getbackendtype(t) == cb_sdl && getenv("DEBUG")) dump_packet(data, h.len);

		uint32_t flags, offset;
		if(!rt_get_presentflags(data, h.len, &flags, &offset))
			return -1;

		struct ieee80211_radiotap_header *rh = (void*) data;

		unsigned rtap_data = offset;

		struct wlaninfo temp = {0};
		{
			if(!(flags & (1U << IEEE80211_RADIOTAP_DBM_ANTSIGNAL))) return -1;
			unsigned dbmoff = get_dbm_off(flags, rtap_data);
			temp.last_rssi = ((signed char*)data)[dbmoff];
		}
		{
//			if(!(flags & (1U << IEEE80211_RADIOTAP_CHANNEL))) return -1;
			short freq;
			unsigned chanoff = get_chan_off(flags, rtap_data);
			memcpy(&freq, data+ chanoff, 2);
			temp.channel = channel_from_freq(freq);
		}
		uint16_t framectl;
		offset = rh->it_len;
		memcpy(&framectl, data+offset, 2);
		framectl = end_le16toh(framectl);
		struct beaconframe* beacon;
		unsigned const char* tagdata;
		unsigned pos;
		uint16_t caps;
		size_t tagdata_len;
		struct wps_data wps;

		switch(framectl) {
			/* IEEE 802.11 packet type */
			case 0x0080: /* beacon */
			case 0x0050: /* probe response */
				beacon = (void*)(data+offset);
				memcpy(&temp.mac,beacon->source,6);
				offset += sizeof(struct beaconframe);
				memcpy(&temp.timestamp,data+offset,8);
				temp.timestamp = end_le64toh(temp.timestamp);
				offset += 8;
				memcpy(&temp.beaconinterval, data+offset,2);
				temp.beaconinterval = end_le16toh(temp.beaconinterval);
				offset += 2;
				memcpy(&caps, data+offset, 2);
				caps = end_le16toh(caps);
				if(caps & 0x10 /* CAPABILITY_WEP */)
					temp.enctype = ET_WEP;
				offset += 2;
				pos = offset;
				tagdata = data+pos;
				tagdata_len = h.len-pos;
				init_wps_data(&wps);
				process_tags(tagdata, tagdata_len, &temp, &wps);
				setminmax(temp.last_rssi);
				return set_rssi(&temp, &wps);

				break;
			case 0x00d4: /*ack*/
			case 0x4288: /*QOS */
			case 0x0040: /* probe request */
			default:
				return -1;
		}
		//while(htonl(*(flags++)) & (1U << IEEE80211_RADIOTAP_EXT)) next_chunk+=4;
		//dprintf(2, "got data\n");
		//dump();
	} else usleep(1);
	return -1;
}

#if 0
static int next_chan(int chan) {
	if(++chan > 11) chan = 1;
	return chan;
}
#elif 1
static int next_chan(int chan) {
	static char chanlist[]={1,5,9,13,2,6,10,14,3,7,11,4,8,12};
	int i = 0;
	for(i = 0; i < sizeof chanlist && chanlist[i] != chan; i++);
	if(i >=13) return chanlist[0];
	return chanlist[++i];
}
#else
static int next_chan(int chan) {
	switch (chan) {
		case 1: case 2: case 3: case 4: case 5:
			return 6;
		case 6: case 7: case 8: case 9: case 10:
			return 11;
		case 11: case 12: case 13:
			/* uncomment next line if you leave in a country using chan 14 */
			//return 14;
		case 14:
			return 1;
		default:
			assert(0);
			return 0;
	}
}
#endif

static struct {int w, h;} dim;

#define BGCOL RGB(33, 66, 133)
#define COL_BLACK RGB(0,0,0)
#define COL_WHITE RGB(255,255,255)
#define COL_YELLOW RGB(255,255,0)

static void draw_bg() {
	unsigned x, y;
	console_setcolor(t, 0, BGCOL);
	for(y=0; y < dim.h; y++) {
		console_goto(t, 0, y);
		for(x = 0; x < dim.w; x++)
			console_printchar(t, ' ', 0);
	}
}

#if 0
static void dump_wlan(unsigned idx) {
	struct wlaninfo *w = &wlans[idx];
	dprintf(1, "%.2d %-24s %02x:%02x:%02x:%02x:%02x:%02x %.2f - %d\n", w->channel, w->essid,
	            w->mac[0], w->mac[1],
	            w->mac[2], w->mac[3], w->mac[4], w->mac[5],
	            (double)w->total_rssi/(double)w->count, w->last_rssi);
}
#else
static unsigned reduce_color(unsigned val) {
	unsigned a = val;
	if (colorcount <= 8) {
		a /= 85;
		if(a > 2) a = 2;
		static const unsigned tbl[] = {0, 127, 255};
		a = tbl[a];
	}
	return a;

}
static int get_r(unsigned percent) {
	return reduce_color((50 - percent/2) * 5);
}
static int get_g(unsigned percent) {
	return reduce_color(percent/2 * 5);
}
static int get_a(unsigned age) {
	return reduce_color(5+((50 - age)*5));
}
#define LINES_PER_NET 1
static void selection_move(int dir) {
	if((int)selection+dir < 0) dir=0;
	if((int)selection+dir >= wlan_count ||
	   ((int)selection+dir)*LINES_PER_NET+1 >= dim.h) dir=0;
	selection += dir;
}

static volatile unsigned bms;
static void set_bms(float percent) {
	float max = 800, min=50;
	float range=max-min;
	float rpercent = range/100.f;
	bms = min + (100 - percent) * rpercent;
}

char *mac2str(unsigned char mac[static 6], char buf[static 18]) {
	unsigned m, x;
	char hextab[16] = "0123456789abcdef";
	for(m = 0, x=0 ; m<6; m++, x+=3) {
		buf[x] = hextab[mac[m]>>4];
		buf[x+1] = hextab[mac[m]&15];
		buf[x+2] = ':';
	}
	buf[17]=0;
	return buf;
}

static char* format_timestamp(uint64_t timestamp, char *ts) {
#define TSTP_SEC 1000000ULL /* 1 MHz clock -> 1 million ticks/sec */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)
	uint64_t rem;
	unsigned days, hours, mins, secs;
	days = timestamp / TSTP_DAY;
	rem = timestamp % TSTP_DAY;
	hours = rem / TSTP_HOUR;
	rem %= TSTP_HOUR;
	mins = rem / TSTP_MIN;
	rem %= TSTP_MIN;
	secs = rem / TSTP_SEC;
	sprintf(ts, "%ud %02u:%02u:%02u", days, hours, mins, secs);
	return ts;
}

static const char* enctype_str(enum enctype et) {
	static const char enc_name[][5] = {
		[ET_OPEN]= "OPEN",
		[ET_WEP] = "WEP",
		[ET_WPA] = "WPA",
		[ET_WPA2]= "WPA2",
	};
	if(et > ET_MAX) abort();
	return enc_name[et];
}

static char* sanitize_string(char *s, char *new) {
	size_t i,j, l = strlen(s), ls=l;
	for(i=0,j=0;i<ls;i++) {
		if(s[i] < ' ' || s[i] > 127) {
			sprintf(new + j, "\\x%02x", s[i] & 0xff);
			j  += 3;
		} else new[j] = s[i];
		j++;
	}
	new[j] = 0;
	return new;
}

#define ESSID_PRINT_START 1
#define ESSID_PRINT_END 32+ESSID_PRINT_START
#define ESSID_PRINT_LEN (ESSID_PRINT_END - ESSID_PRINT_START)

static void dump_wlan_info(unsigned wlanidx) {
	struct wlaninfo *w = &wlans[wlanidx];
	lock();
	unsigned line = 3, x, col1, col2, col3, col4;
	console_setcolor(t, 0, BGCOL);
	console_setcolor(t, 1, COL_WHITE);

	col1 = x = 2;
	console_goto(t, ++x, line);
	char macbuf[18];
	console_printf(t, "MAC %s", mac2str(w->mac, macbuf));
	x += 25;
	col2 = x;

	console_goto(t, ++x, line);
	console_printf(t, "CHAN %d", (int) w->channel);
	x += 9 + 5;
	col3 = x;

	console_goto(t, ++x, line);
	char ts[64];
	format_timestamp(w->timestamp, ts);
	console_printf(t, "UP: %s", ts);
	x += strlen(ts) +5;
	col4 = x;

	console_goto(t, ++x, line);
	console_printf(t, "BI %d ms", (int) w->beaconinterval);

	line++;
	x = col1;

	console_goto(t, ++x, line);
	console_printf(t, "AVG %.2f dBm", (double)w->total_rssi/(double)w->count);
	//x += 14 + 5;
	x = col2;

	console_goto(t, ++x, line);
	console_printf(t, "CURR %d dBm", w->last_rssi);
	//x += 10 + 5;
	x = col3;

	console_goto(t, ++x, line);
	console_printf(t, "MIN %d dBm", w->min_rssi);
	//x += 9 + 5;
	x = col4;

	console_goto(t, ++x, line);
	console_printf(t, "MAX %d dBm", w->max_rssi);
	x += 9 + 5;

	line++;
	x = col1;
	console_goto(t, ++x, line);
	console_printf(t, "%4s", enctype_str(w->enctype));

	x = col2;
	console_goto(t, ++x, line);
	if(w->wps) console_printf(t, "WPS %d.%d", w->wps->version >> 4, w->wps->version & 15);

	x = col3;
	console_goto(t, ++x, line);
	if(w->wps) console_printf(t, w->wps->locked == 1 ? "LOCKED" : "-");

	char sanbuf[WPS_MAX_STR_LEN*4+1];

	x = col4;
	console_goto(t, ++x, line);
	if(w->wps && w->wps->manufacturer[0]) {
		sanitize_string(w->wps->manufacturer, sanbuf);
		console_printf(t, "%s", sanbuf);
	}

	line++;

	x = col1;
	console_goto(t, ++x, line);
	if(w->wps && w->wps->model_name[0]) {
		sanitize_string(w->wps->model_name, sanbuf);
		console_printf(t, "%s", sanbuf);
	}

	x = col2;
	console_goto(t, ++x, line);
	if(w->wps && w->wps->model_number[0]) {
		sanitize_string(w->wps->model_number, sanbuf);
		console_printf(t, "%s", sanbuf);
	}

	x = col3;
	console_goto(t, ++x, line);
	if(w->wps && w->wps->device_name[0]) {
		sanitize_string(w->wps->device_name, sanbuf);
		console_printf(t, "%s", sanbuf);
	}

	x = col4;
	console_goto(t, ++x, line);
	if(w->wps && w->wps->serial[0]) {
		sanitize_string(w->wps->serial, sanbuf);
		console_printf(t, "%s", sanbuf);
	}

	unlock();
}

static void dump_wlan_at(unsigned wlanidx, unsigned line) {
	console_goto(t, 0, line);
	console_setcolor(t, 0, BGCOL);

	console_setcolor(t, 1, COL_YELLOW);

	if(wlanidx == selection) {
		console_printchar(t, '>', 0);
	} else {
		console_printchar(t, ' ', 0);
	}

	struct wlaninfo *w = &wlans[wlanidx];

	lock();

	long long now = getutime64();
	long long age_ms = (now - w->last_seen)/1000;
	age_ms=MIN(5000, age_ms)/100; /* seems we end up with a range 0-50 */
	unsigned a = get_a(age_ms);

	console_setcolor(t, 1, RGB(a,a,a));
	console_goto(t, ESSID_PRINT_START, line);

	char macbuf[18];

	if(*w->essid) {
		char essid_san[32*4+1];
		sanitize_string(w->essid, essid_san);
		console_printf(t, "%*s", ESSID_PRINT_LEN, essid_san);
	} else
		console_printf(t, "<hidden> %*s", ESSID_PRINT_LEN-9, mac2str(w->mac, macbuf));

	console_goto(t, ESSID_PRINT_END, line);
	console_printchar(t, ' ', 0);

	int scale = max - min;
	int width = dim.w - (ESSID_PRINT_LEN+2);
	unsigned x;
	float widthpercent = (float)width/100.f;
	float scalepercent = (float)scale/100.f;
	float scaleup = (float)width / (float)scale;
	double avg = (double)w->total_rssi/(double)w->count;
	float avg_percent = (avg - (float)min) / scalepercent;
	float curr_percent = ((float)w->last_rssi - (float)min) / scalepercent;
	int avg_marker = (avg - (float)min) * scaleup;
	int curr_marker = ((float)w->last_rssi - (float)min) * scaleup;

	unlock();

	for(x = 0; x < width; x++) {
		rgb_t step_color;
		if(wlanidx == selection) step_color = RGB(get_r(x/widthpercent),get_g(x/widthpercent),0);
		else step_color = RGB(get_r(x/widthpercent),get_r(x/widthpercent),get_r(x/widthpercent));
		console_setcolor(t, 0, step_color);
		if(x != curr_marker) console_setcolor(t, 1, COL_BLACK);
		else console_setcolor(t, 1, COL_WHITE);
		if(x == avg_marker) console_printchar(t, 'I', 0);
		else if (x == curr_marker) console_printchar(t, '|', 0);
		else if(x == 0) console_printchar(t, '[', 0);
		else if(x == width-1) console_printchar(t, ']', 0);
		else console_printchar(t, ' ', 0);
	}
}

static void dump_wlan(unsigned idx) {
	if(idx * LINES_PER_NET + 1 > dim.h || (selected && selection != idx)) return;
	dump_wlan_at(idx, selected ? 1 : idx * LINES_PER_NET);
	if(selected) dump_wlan_info(idx);
}
#endif

static void calc_bms(unsigned wlanidx) {
	long long now = getutime64();
	struct wlaninfo *w = &wlans[wlanidx];
	lock();
	long long age_ms = (now - w->last_seen)/1000;
	unlock();
	age_ms=MIN(5000, age_ms)/100; /* seems we end up with a range 0-50 */
	int scale = max - min;
	float scalepercent = (float)scale/100.f;
	float curr_percent = ((float)w->last_rssi - (float)min) / scalepercent;
	if(age_ms < 15) set_bms(curr_percent);
	else bms = 0;
}

static void dump(void) {
	unsigned i;
	//dprintf(1, "********************\n");
	//draw_bg();
	for(i=0;i<wlan_count;i++)
		dump_wlan(i);
	console_refresh(t);
}

static void initconcol() {
	console_init(t);
	char *p;
	int rw=1024,rh=768;
	if((p = getenv("RES"))) {
		char *q = strchr(p, 'x');
		if(q) {
			unsigned l = q-p;
			char b[64];
			memcpy(b,p,l);
			b[l] = 0;
			rw=atoi(b);
			strcpy(b,++q);
			rh=atoi(b);
		}
	}
	point reso = {rw, rh};
	console_init_graphics(&co, reso, FONT);
        console_getbounds(t, &dim.w, &dim.h);
	colorcount = console_getcolorcount(t);
#ifdef NO_COLOR
	(*console_setcolor)(t, 0, COL_WHITE);
	(*console_setcolor)(t, 1, COL_BLACK);
#endif
	draw_bg();
}

static unsigned char blip[] = {0x52, 0x51, 0x51, 0x51, 0xC4, 0x4C, 0xF4, 0xF4, 0xF3,0xEF};
static unsigned blip_frame(int idx) {
	idx = idx % (2*sizeof(blip));
	if(idx>=sizeof(blip)) idx=(2*sizeof(blip))-idx;
	return blip[idx];
}

static volatile float volume = .5;

static void generate_blip(unsigned char* data, size_t bufsize) {
        int i;
        for(i=0;i<bufsize;i++) {
		float f = blip_frame(i) * volume;
		data[i] = f;
	}
}

static void volume_change(int dir) {
	volume += dir * 0.1;
	if(volume < 0) volume = 0;
	if(volume > 1) volume = 1;
}

static void* blip_thread(void* arg) {
	struct AudioCTX ao;
	audio_init(&ao);
	unsigned char buf[100], silence[1000];
	generate_blip(buf, sizeof(buf));
	memset(silence, buf[99], sizeof silence);
	long long t = getutime64();
	unsigned passed = 0;
	float myvol = volume;
	while(selected) {
		if(myvol != volume) {
			generate_blip(buf, sizeof(buf));
			myvol = volume;
		}
		if(bms && (getutime64() - t)/1000 >= bms) {
			audio_write(&ao, buf, sizeof buf);
			t = getutime64();
		}
		audio_write(&ao, silence, sizeof silence);
		usleep(1);
	}
	audio_close(&ao);
	return 0;
}

static void* chanwalker_thread(void* arg) {
	char* itf = arg;
	int channel = 1, delay = 800;
	long long tm = 0;
	if(filebased) return 0;
	while(!selected) {
		if((getutime64() - tm)/1000 >= delay) {
			int ret = set_channel(itf, channel = next_chan(channel));
			if(ret == -1) {
				if(console_getbackendtype(t) == cb_sdl)
					dprintf(2, "oops couldnt switch to chan %d\n", channel);
			}
			tm = getutime64();
		}
		usleep(1000);
	}
	return 0;
}
#include <sys/ioctl.h>
#include <sys/socket.h>
/* set an interface up or down, depending on whether up is set.
   if checkonly is true, no change will be made and the result
   of the function can be interpreted as "isdownup".
   if the interface was already up/down, 2 is returned.
   if the interface was successfully upped/downed, 1 is returned.
   0 is only returned if checkonly is set and the interface was not
   in the queried state.
   -1 is returned on error. */
static int ifdownup(const char *dev, int up, int checkonly) {
	int fd, ret = -1;
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;
	struct ifreq ifr = {0};
	strcpy(ifr.ifr_name, dev);
	if(ioctl(fd, SIOCGIFFLAGS, &ifr) <0) goto done;
	int isup = ifr.ifr_flags & IFF_UP;
	if((up && isup) || (!up && !isup)) ret = 2;
	else if (checkonly) ret = 0;
	else {
		if(up) ifr.ifr_flags |= IFF_UP;
		else   ifr.ifr_flags &= ~(IFF_UP);
		ret = (ioctl(fd, SIOCSIFFLAGS, &ifr) >= 0);
	}
	done:
	close(fd);
	return ret;
}

#include "wireless-lite.h"
static int getiwmode(const char *dev) {
	int fd, ret = -1;
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;
	struct iwreq iwr = {0};
	strcpy(iwr.ifr_name, dev);
	if(ioctl(fd, SIOCGIWMODE, &iwr) >=0) ret = iwr.u.mode;
	close(fd);
	return ret;
}

static int setiwmode(const char *dev, int mode) {
	int fd, ret = -1;
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;
	struct iwreq iwr = {.u.mode = mode};
	strcpy(iwr.ifr_name, dev);
	ret = ioctl(fd, SIOCSIWMODE, &iwr);
	close(fd);
	return ret;
}

static void* capture_thread(void*arg) {
	pcap_t *foo = arg;
	while(!stop) {
		int ret = process_frame(foo);
		long long tmp = getutime64();
		if(ret >= 0) {
			lock();
			wlans[ret].last_seen = tmp;
			unlock();
		}
	}
	return 0;
}

static pthread_t bt, wt;
static const char *itf;

static void set_selection(int on) {
	selected = on;
	if(selected) {
		pthread_join(wt, 0);
		draw_bg();
		pthread_create(&bt, 0, blip_thread, 0);
		if(!filebased) set_channel(itf, wlans[selection].channel);
	} else {
		pthread_create(&wt, 0, chanwalker_thread, (void*)itf);
		pthread_join(bt, 0);
	}
}


//RcB: DEP "server.c"
//RcB: DEP "../lib/src/sblist/*.c"
//RcB: DEP "../lib/src/strlib/hexval.c"
#include "netgui.c"

int main(int argc,char**argv) {
	if(argc == 1) return usage(argv[0]);
	itf = argv[1];
	min = 127;
	max = -60;
	outfd = -1;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *foo;
	if(strchr(argv[1], '.') && access(argv[1], R_OK) == 0) {
		filebased = 1;
		foo = pcap_open_offline(argv[1], errbuf);
	} else {
		foo = pcap_create(argv[1], errbuf);
		outfd= open("tmp.pcap", O_WRONLY|O_CREAT|O_TRUNC,0660);
		if(outfd != -1)
			write(outfd, "\xD4\xC3\xB2\xA1" "\x02\x00\x04\x00"
			             "\x00\x00\x00\x00" "\x00\x00\x00\x00"
			             "\x00\x00\x04\x00" "\x7F\x00\x00\x00", 24);
	}
	if(!foo) { dprintf(2, "%s\n", errbuf); return 1; }

	int ret, wasdown, orgmode;

	if(filebased) goto skip;

	if((orgmode = getiwmode(argv[1])) != IW_MODE_MONITOR) {
		if((ret = ifdownup(argv[1], 0, 0)) == -1) {
			iferr:;
			perror("error setting up interface - maybe need to run as root.");
		}
		wasdown = (ret == 2);
		if(setiwmode(argv[1], IW_MODE_MONITOR) == -1) goto iferr;
	} else {
		wasdown = (ifdownup(argv[1], 0, 1) == 2);
	}
	if(ifdownup(argv[1], 1, 0) == -1) goto iferr;

	if(pcap_activate(foo)) {
		dprintf(2, "pcap_activate failed: %s\n", pcap_geterr(foo));
		return 1;
	}

	skip:;

	initconcol();

	signal(SIGINT, sigh);

	int channel = 1;
	long long tm = 0;
	pthread_t ct, nt;
	pthread_create(&wt, 0, chanwalker_thread, argv[1]);
	pthread_create(&ct, 0, capture_thread, foo);

	struct netgui_config netgui_cfg;
	if(getenv("NETGUI")) {
		netgui_start(&netgui_cfg, "0.0.0.0", 9876);
	}

	while(!stop) {
		long long tmp = getutime64();
		if((tmp-tm) >= (1000000 / GUI_FPS)) {
			tm = tmp;
			dump();
		}

		if(selected) calc_bms(selection);
		int k = console_getkey_nb(t);

		switch(k) {
			case '+': case '0': volume_change(+1); break;
			case '-': case '9': volume_change(-1); break;
			case CK_CURSOR_DOWN: selection_move(1);break;
			case CK_CURSOR_UP: selection_move(-1);break;
			case CK_RETURN:
				//selected = !selected;
				set_selection(!selected);
				break;
			case CK_QUIT:
			case CK_ESCAPE: stop = 1; break;
		}
		usleep(1000);
	}

	pcap_breakloop(foo); // this doesn't actually seem to work

	if(getenv("NETGUI")) {
		netgui_stop(&netgui_cfg);
	}

	if(selected) {
		selected = 0;
		pthread_join(bt, 0);
	} else {
		selected = 1;
		pthread_join(wt, 0);
	}

	// since our capture_thread uses blocking reads in order to keep CPU usage
	// minimal, we need to get the current read cancelled - and if no packets
	// arrive, this can take a *long* time. since pcap_breakloop() doesn't actually
	// seem to work, the only way i found to break out of the read is to actually
	// bring down the interface - so this must happen before we join the thread
	// and close the pcap handle.
	if(!filebased) {
		if(wasdown || orgmode != IW_MODE_MONITOR) ifdownup(argv[1], 0, 0);
		if(orgmode != IW_MODE_MONITOR) setiwmode(argv[1], orgmode);
		if(!wasdown && orgmode != IW_MODE_MONITOR) ifdownup(argv[1], 1, 0);
	}

	pthread_join(ct, 0);

	pcap_close(foo);
	console_cleanup(t);
	if(outfd != -1) close(outfd);
	return 0;
}

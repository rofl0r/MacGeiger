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

static struct wlaninfo {
	char essid[32];
	unsigned char mac[6];
	unsigned char channel;
	long long total_rssi;
	long long last_seen;
	unsigned long count;
	int last_rssi;
} wlans[128];
static unsigned wlan_count;

static pthread_mutex_t wlan_lock = PTHREAD_MUTEX_INITIALIZER;
#define lock() pthread_mutex_lock(&wlan_lock)
#define unlock() pthread_mutex_unlock(&wlan_lock)

static signed char min, max;
static unsigned char selection, selected;
static Console co, *t = &co;

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
	if(wlan_count+1<sizeof(wlans)/sizeof(wlans[0]))
		return wlan_count++;
	return -1;
}

static int set_rssi(struct wlaninfo *w) {
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
	}
	unlock();
	return i;
}

volatile int stop;
void sigh(int x) {
	stop = 1;
}

struct ieee80211_radiotap_header {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};

enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

static const unsigned char ieee80211_radiotap_type_size[] = {
	[IEEE80211_RADIOTAP_TSFT] = 8,
	[IEEE80211_RADIOTAP_FLAGS] = 1,
	[IEEE80211_RADIOTAP_RATE] = 1,
	[IEEE80211_RADIOTAP_CHANNEL] = 2*2,
	[IEEE80211_RADIOTAP_FHSS] = 2,
	[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 1,
	[IEEE80211_RADIOTAP_DBM_ANTNOISE] = 1,
	[IEEE80211_RADIOTAP_LOCK_QUALITY] = 2,
	[IEEE80211_RADIOTAP_TX_ATTENUATION] = 2,
	[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 2,
	[IEEE80211_RADIOTAP_DBM_TX_POWER] = 1,
	[IEEE80211_RADIOTAP_ANTENNA] = 1,
	[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 1,
	[IEEE80211_RADIOTAP_DB_ANTNOISE] = 1,
	[IEEE80211_RADIOTAP_RX_FLAGS] = 2,
	[IEEE80211_RADIOTAP_TX_FLAGS] = 2,
	[IEEE80211_RADIOTAP_RTS_RETRIES] = 1,
	[IEEE80211_RADIOTAP_DATA_RETRIES] = 1,
	[IEEE80211_RADIOTAP_MCS] = 1+1+1,
	[IEEE80211_RADIOTAP_AMPDU_STATUS] = 4+2+1+1,
	[IEEE80211_RADIOTAP_VHT] = 12,
	[IEEE80211_RADIOTAP_TIMESTAMP] = 12,
};

static const unsigned char ieee80211_radiotap_type_align[] = {
	[IEEE80211_RADIOTAP_TSFT] = 8,
	[IEEE80211_RADIOTAP_FLAGS] = 1,
	[IEEE80211_RADIOTAP_RATE] = 1,
	[IEEE80211_RADIOTAP_CHANNEL] = 2,
	[IEEE80211_RADIOTAP_FHSS] = 2,
	[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 1,
	[IEEE80211_RADIOTAP_DBM_ANTNOISE] = 1,
	[IEEE80211_RADIOTAP_LOCK_QUALITY] = 2,
	[IEEE80211_RADIOTAP_TX_ATTENUATION] = 2,
	[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 2,
	[IEEE80211_RADIOTAP_DBM_TX_POWER] = 1,
	[IEEE80211_RADIOTAP_ANTENNA] = 1,
	[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 1,
	[IEEE80211_RADIOTAP_DB_ANTNOISE] = 1,
	[IEEE80211_RADIOTAP_RX_FLAGS] = 2,
	[IEEE80211_RADIOTAP_TX_FLAGS] = 2,
	[IEEE80211_RADIOTAP_RTS_RETRIES] = 1,
	[IEEE80211_RADIOTAP_DATA_RETRIES] = 1,
	[IEEE80211_RADIOTAP_MCS] = 1,
	[IEEE80211_RADIOTAP_AMPDU_STATUS] = 4,
	[IEEE80211_RADIOTAP_VHT] = 2,
	[IEEE80211_RADIOTAP_TIMESTAMP] = 8,
};

static unsigned get_flag_off(unsigned flags, unsigned which, unsigned start_off) {
	unsigned i,c=start_off;
	for(i=0;i<which;i++) if(flags & (1U << i)) {
		c+= c & (ieee80211_radiotap_type_align[i]-1);
		c+= ieee80211_radiotap_type_size[i];
	}
	return c;
}

static unsigned get_dbm_off(unsigned flags, unsigned start_off) {
	return get_flag_off(flags, IEEE80211_RADIOTAP_DBM_ANTSIGNAL, start_off);
}

static unsigned get_chan_off(unsigned flags, unsigned start_off) {
	return get_flag_off(flags, IEEE80211_RADIOTAP_CHANNEL, start_off);
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

static int process_frame(pcap_t *foo) {
	struct pcap_pkthdr h;
	const unsigned char* data = pcap_next_wrapper(foo, &h);
	if(data) {
		if(console_getbackendtype(t) == cb_sdl && getenv("DEBUG")) dump_packet(data, h.len);
		struct ieee80211_radiotap_header *rh = (void*) data;
		//size_t next_chunk = sizeof(*rh);
		uint32_t flags = rh->it_present, flags_copy = flags;
		unsigned ext_bytes = 0;
		while(flags_copy & (1U << IEEE80211_RADIOTAP_EXT)) {
			memcpy(&flags_copy, data+sizeof(*rh)+ext_bytes, 4);
			ext_bytes += 4;
		}
		unsigned rtap_data = sizeof(*rh) + ext_bytes;

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
		memcpy(&framectl, data+rh->it_len, 2);
		struct beaconframe* beacon;
		unsigned const char* tagdata, *curr_tag;
		unsigned pos;
		switch(htons(framectl)) {
			/* IEEE 802.11 packet type */
			case 0xd400: /*ack*/
				//memcpy(&temp.mac,data+rh->it_len+4, 6);
				//set_rssi(&temp, dbm);
				//break;
				return -1;
			case 0x8000: /*beacon */
				beacon = (void*)(data+rh->it_len);
				memcpy(&temp.mac,beacon->source,6);
				pos = rh->it_len+sizeof(*beacon)+12;
				tagdata = data+pos;
				curr_tag = find_tag(tagdata, 0, h.len-pos); /* find essid tag */
				if(curr_tag) {
					memcpy(temp.essid, curr_tag+2, curr_tag[1]);
					temp.essid[curr_tag[1]] = 0;
				} else {
					/* dubious beacon without essid */
					dprintf(2, "XXX\n");
					if(console_getbackendtype(t) == cb_sdl && getenv("DEBUG")) dump_packet(data, h.len);
				}
				curr_tag = find_tag(tagdata, 3, h.len-pos); /* find channel nr tag */
				if(curr_tag) {
					assert(curr_tag[1] == 1);
					temp.channel = curr_tag[2];
				}
				setminmax(temp.last_rssi);

				return set_rssi(&temp);

				break;
			case 0x8842: /*QOS */
			case 0x4000: /* probe request */
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
static int get_r(unsigned percent) {
	return (50 - percent/2) * 5;
}
static int get_g(unsigned percent) {
	return percent/2 * 5;
}
static int get_a(unsigned age) {
	return 5+((50 - age)*5);
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

#define ESSID_PRINT_START 1
#define ESSID_PRINT_END 32+ESSID_PRINT_START
#define ESSID_PRINT_LEN (ESSID_PRINT_END - ESSID_PRINT_START)

static void dump_wlan_info(unsigned wlanidx) {
	struct wlaninfo *w = &wlans[wlanidx];
	lock();
	unsigned line = 3;
	console_setcolor(t, 0, BGCOL);
	console_setcolor(t, 1, RGB(0xff,0xff,0xff));

	console_goto(t, ESSID_PRINT_END +1, line);
	char macbuf[18];
	console_printf(t, "MAC %s", mac2str(w->mac, macbuf));

	console_goto(t, ESSID_PRINT_END +1+25, line);
	console_printf(t, "CHAN %d", (int) w->channel);

	line++;

	console_goto(t, ESSID_PRINT_END +1, line);
	console_printf(t, "AVG %.2f dBm", (double)w->total_rssi/(double)w->count);

	console_goto(t, ESSID_PRINT_END +1+25, line);
	console_printf(t, "CURR %d dBm", w->last_rssi);
	unlock();
}

static void sanitize_string(char *s, char *new) {
	size_t i,j, l = strlen(s), ls=l;
	for(i=0,j=0;i<ls;i++) {
		if(s[i] < ' ' || s[i] > 127) {
			sprintf(new + j, "\\x%02x", s[i] & 0xff);
			j  += 3;
		} else new[j] = s[i];
		j++;
	}
	new[j] = 0;
}


static void dump_wlan_at(unsigned wlanidx, unsigned line) {
	console_goto(t, 0, line);
	console_setcolor(t, 0, BGCOL);

	console_setcolor(t, 1, RGB(255,255,0));
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

	console_goto(t, ESSID_PRINT_END +1, line);

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
		if(x != curr_marker) console_setcolor(t, 1, RGB(0,0,0));
		else console_setcolor(t, 1, RGB(255,255,255));
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
#ifdef NO_COLOR
	(*console_setcolor)(t, 0, RGB(255,255,255));
	(*console_setcolor)(t, 1, RGB(0,0,0));
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

int main(int argc,char**argv) {
	if(argc == 1) return usage(argv[0]);
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
	pthread_t bt, wt, ct;
	pthread_create(&wt, 0, chanwalker_thread, argv[1]);
	pthread_create(&ct, 0, capture_thread, foo);

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
				selected = !selected;
				if(selected) {
					pthread_join(wt, 0);
					draw_bg();
					pthread_create(&bt, 0, blip_thread, 0);
					if(!filebased) set_channel(argv[1], wlans[selection].channel);
				} else {
					pthread_create(&wt, 0, chanwalker_thread, argv[1]);
					pthread_join(bt, 0);
				}
				break;
			case CK_QUIT:
			case CK_ESCAPE: stop = 1; break;
		}
		usleep(1000);
	}

	pcap_breakloop(foo); // this doesn't actually seem to work

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

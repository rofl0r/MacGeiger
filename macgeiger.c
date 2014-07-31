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
#define LIBRARY_CODE
#include "channel-switch.c"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

//RcB: LINK "-lpcap"
//RcB: LINK "-lao"
//RcB: LINK "-lpthread"
#include <ao/ao.h>

#include "../concol/console.h"
#include "../concol/console_keys.h"
#define CONSOLE_FONT TESTFONT
#include "../concol/fonts/allfonts.h"

#ifdef NO_COLOR
#define console_setcolor(A, B, C) do {} while(0)
#endif

static int usage(void) {
	dprintf(2, "prog network-if\n");
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
} wlans[32];

static signed char min, max;
static unsigned char selection, selected;

static int get_wlan_by_essid(char* essid) {
	unsigned i;
	for(i=0;i<sizeof(wlans)/sizeof(wlans[0]);i++)
		if(!strcmp(essid, wlans[i].essid)) return i;
	return -1;
}

static int get_wlan_by_mac(unsigned char mac[6]) {
	unsigned i;
	for(i=0;i<sizeof(wlans)/sizeof(wlans[0]);i++)
		if(!memcmp(mac, wlans[i].mac, 6)) return i;
	return -1;
}

static int get_new_wlan(void) {
	unsigned i;
	for(i=0;i<sizeof(wlans)/sizeof(wlans[0]);i++)
		if(!wlans[i].essid[0] && !memcmp(wlans[i].mac, "\0\0\0\0\0\0", 6)) return i;
	return -1;
}

static int set_rssi(struct wlaninfo *w) {
	int i = -1;
	if(w->essid[0]) i = get_wlan_by_essid(w->essid);
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
	return i;
}

int stop;
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
};

static unsigned get_flag_off(unsigned flags, unsigned which) {
	unsigned i,c=0;
	for(i=0;i<which;i++) if(flags & (1U << i)) c+= ieee80211_radiotap_type_size[i];
	return c;
}

static unsigned get_dbm_off(unsigned flags) {
	return get_flag_off(flags, IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
}

static unsigned get_chan_off(unsigned flags) {
	return get_flag_off(flags, IEEE80211_RADIOTAP_CHANNEL);
}

static unsigned channel_from_freq(unsigned freq) {
	static const short chan_freqs[] = {
		[1] = 2412, [2] = 2417, [3] = 2422, [4] = 2427, [5] = 2432, [6] = 2437,
		[7] = 2442, [8] = 2447, [9] = 2452, [10] = 2457, [11] = 2462, [12] = 2467,
		[13] = 2472, [14] = 2484 /* chan 14 only used in japan */
	};
	unsigned i;
	for(i = 1; i < sizeof(chan_freqs)/sizeof(chan_freqs[0]); i++)
		if(chan_freqs[i] == freq) return i;
	return 0;
}

struct beaconframe {
	uint16_t framecontrol;
	uint16_t duration;
	unsigned char receiver[6];
	unsigned char source[6];
	unsigned char bssid[6];
	uint16_t sequence_no;
};

static unsigned const char* find_tag(unsigned const char *tagdata, unsigned tag, unsigned bytes_left) {
	while(bytes_left) {
		if(*tagdata == tag) return tagdata;
		unsigned tagsize = tagdata[1];
		tagdata+=2+tagsize;
		bytes_left-=2+tagsize;
	}
	return 0;
}

static int process_frame(pcap_t *foo) {
	struct pcap_pkthdr h;
	const unsigned char* data = pcap_next(foo, &h);
	if(data) {
		struct ieee80211_radiotap_header *rh = (void*) data;
		//size_t next_chunk = sizeof(*rh);
		uint32_t flags = rh->it_present;
		//assert(!(flags & (1U << IEEE80211_RADIOTAP_EXT)));
		if(flags & (1U << IEEE80211_RADIOTAP_EXT)) return -1;

		struct wlaninfo temp = {0};
		{
			assert(flags & (1U << IEEE80211_RADIOTAP_DBM_ANTSIGNAL));
			unsigned dbmoff = get_dbm_off(flags);
			temp.last_rssi = ((signed char*)data)[sizeof(*rh) + dbmoff];
			min = MIN(min, temp.last_rssi);
			max = MAX(max, temp.last_rssi);
		}
		{
			assert(flags & (1U << IEEE80211_RADIOTAP_CHANNEL));
			short freq;
			unsigned chanoff = get_chan_off(flags);
			memcpy(&freq, data+sizeof(*rh) + chanoff, 2);
			temp.channel = channel_from_freq(freq);
		}
		uint16_t framectl;
		memcpy(&framectl, data+rh->it_len, 2);
		struct beaconframe* beacon;
		unsigned char* tagdata, *curr_tag;
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
				}
				curr_tag = find_tag(tagdata, 3, h.len-pos); /* find channel nr tag */
				if(curr_tag) {
					assert(curr_tag[1] == 1);
					temp.channel = curr_tag[2];
				}

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
#endif
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

static long long getutime64(void) {
	struct timeval t;
	gettimeofday(&t, NULL);
	return (t.tv_sec * 1000LL * 1000LL) + t.tv_usec;
}

static Console co, *t = &co;
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
static void selection_move(int dir) {
	if((int)selection+dir < 0) dir=0;
	if(((int)selection+dir)*3+1 > dim.h) dir=0;
	selection += dir;
}

static volatile unsigned bms;
static void set_bms(float percent) {
	float max = 800, min=50;
	float range=max-min;
	float rpercent = range/100.f;
	bms = min + (100 - percent) * rpercent;
}

static void dump_wlan(unsigned idx) {
	struct wlaninfo *w = &wlans[idx];
	if(idx * 3 + 1 > dim.h || (selected && selection != idx)) return;
	long long now = getutime64();
	long long age_ms = (now - w->last_seen)/1000;
	age_ms=MIN(5000, age_ms)/100;
	console_goto(t, 1, idx*3);
	console_setcolor(t, 0, BGCOL);

	unsigned a = get_a(age_ms);
	console_setcolor(t, 1, RGB(a,a,a));
	console_printf(t, "%.2d %02x:%02x:%02x:%02x:%02x:%02x %-24s %.2f %d",
	                  w->channel, w->mac[0], w->mac[1],  w->mac[2], w->mac[3], w->mac[4], w->mac[5], w->essid,
	                  (double)w->total_rssi/(double)w->count, w->last_rssi);

	console_goto(t, 0, idx*3+1);
	console_setcolor(t, 1, RGB(255,255,0));
	if(idx == selection) {
		console_printchar(t, '>', 0);
	} else {
		console_printchar(t, ' ', 0);
	}

	console_goto(t, 1, idx*3+1);
	int scale = max - min;
	int width = dim.w - 2;
	unsigned x;
	float widthpercent = (float)width/100.f;
	float scalepercent = (float)scale/100.f;
	float scaleup = (float)width / (float)scale;
	double avg = (double)w->total_rssi/(double)w->count;
	float avg_percent = (avg - (float)min) / scalepercent;
	float curr_percent = ((float)w->last_rssi - (float)min) / scalepercent;
	set_bms(curr_percent);
	int avg_marker = (avg - (float)min) * scaleup;
	int curr_marker = ((float)w->last_rssi - (float)min) * scaleup;
	for(x = 0; x < width; x++) {
		rgb_t step_color = RGB(get_r(x/widthpercent),get_g(x/widthpercent),0);
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
#endif

static void dump(void) {
	unsigned i;
	//dprintf(1, "********************\n");
	//draw_bg();
	for(i=0;i<sizeof(wlans)/sizeof(wlans[0])&&(wlans[i].essid[0]||memcmp(wlans[i].mac, "\0\0\0\0\0\0", 6));i++)
		dump_wlan(i);
	console_refresh(t);
}

static void initconcol() {
	console_init(t);
	point reso = {800, 600};
//	point reso = {1280, 600};
	console_init_graphics(&co, reso, FONT);
        console_getbounds(t, &dim.w, &dim.h);
#ifdef NO_COLOR
	(*console_setcolor)(t, 0, RGB(255,255,255));
	(*console_setcolor)(t, 1, RGB(0,0,0));
#endif
	draw_bg();
}

struct AoWriter {
	ao_device *device;
	ao_sample_format format;
	int aodriver;
};

int AoWriter_init(struct AoWriter *self) {
	ao_initialize();
	memset(self, 0, sizeof(*self));
	self->format.bits = 8;
	self->format.channels = 1;
	self->format.rate = 11025;
	self->format.byte_format = AO_FMT_LITTLE;
	self->aodriver = ao_default_driver_id();
	self->device = ao_open_live(self->aodriver, &self->format, NULL);
	return self->device != NULL;
}

int AoWriter_write(struct AoWriter *self, void* buffer, size_t bufsize) {
	return ao_play(self->device, buffer, bufsize);
}

int AoWriter_close(struct AoWriter *self) {
	return ao_close(self->device);
}

static unsigned char blip[] = {0x52, 0x51, 0x51, 0x51, 0xC4, 0x4C, 0xF4, 0xF4, 0xF3,0xEF};
static int blip_frame(int idx) {
	idx = idx % (2*sizeof(blip));
	if(idx>=sizeof(blip)) idx=(2*sizeof(blip))-idx;
	return blip[idx];
}

static void generate_blip(unsigned char* data, size_t bufsize, double volume) {
        int i;
        for(i=0;i<bufsize;i++)
#if 1
		data[i] = (blip_frame(i)-128)*volume+127;
#else
		data[i] = blip_frame(i)*volume;
#endif
}

#define DEFAULT_VOLUME 0.02

static void* blip_thread(void* arg) {
	struct AoWriter ao;
	AoWriter_init(&ao);
	unsigned char buf[100], silence[1000];
	generate_blip(buf, sizeof(buf), DEFAULT_VOLUME);
	memset(silence, buf[99], sizeof silence);
	long long t = getutime64();
	unsigned passed = 0;
	while(selected) {
		if((getutime64() - t)/1000 >= bms) {
			AoWriter_write(&ao, buf, sizeof buf);
			t = getutime64();
		}
		AoWriter_write(&ao, silence, sizeof silence);
		usleep(1);
	}
	AoWriter_close(&ao);
	return 0;
}

static void* chanwalker_thread(void* arg) {
	char* itf = arg;
	int channel = 1, delay = 800;
	long long t = 0;
	while(!selected) {
		if((getutime64() - t)/1000 >= delay) {
			set_channel(itf, channel = next_chan(channel));
			t = getutime64();
		}
		usleep(1000);
	}
	return 0;
}

int main(int argc,char**argv) {
	if(argc == 1) return usage();
	min = 127;
	max = -127;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *foo = pcap_create(argv[1], errbuf);
	if(!foo) { dprintf(2, "%s\n", errbuf); return 1; }

	int ret;

	if((ret = pcap_can_set_rfmon(foo)) == 1) {
		ret = pcap_set_rfmon(foo, 1);
		if(ret != 0) {
			dprintf(2, "pcap_set_rfmon failed\n");
			return 1;
		}
	} else {
		dprintf(2, "warning: cannot set rfmon %d\n", ret);
		return 1;
	}

	if(pcap_activate(foo)) {
		dprintf(2, "%s\n", pcap_geterr(foo));
		return 1;
	}

	initconcol();

	signal(SIGINT, sigh);

	unsigned ms_passed = 1000;
	int channel = 1;
	long long now = 0;
	pthread_t bt, wt;
	pthread_create(&wt, 0, chanwalker_thread, argv[1]);

	while(!stop) {
		if(ms_passed > 20) { /* 50 FPS */
			if(!selected) {
				//set_channel(argv[1], channel = next_chan(channel));
				//ms_passed = (getutime64()-now)/1000;
				//dprintf(2, "set_channel took %u ms\n", ms_passed);
			}
			ms_passed = 0;
			now = getutime64();
			dump();
		}
		int ret = process_frame(foo);
		long long tmp = getutime64();
		ms_passed += (tmp-now)/1000;
		now = tmp;
		if(ret >= 0) wlans[ret].last_seen = now;
		int k = console_getkey_nb(t);
		switch(k) {
			case CK_CURSOR_DOWN: selection_move(1);break;
			case CK_CURSOR_UP: selection_move(-1);break;
			case CK_RETURN:
				selected = !selected;
				if(selected) {
					pthread_join(wt, 0);
					draw_bg();
					pthread_create(&bt, 0, blip_thread, 0);
					set_channel(argv[1], wlans[selection].channel);
				} else {
					pthread_create(&wt, 0, chanwalker_thread, argv[1]);
					pthread_join(bt, 0);
				}
				break;
			case CK_ESCAPE: stop = 1; break;
		}
	}
	if(selected) {
		selected = 0;
		pthread_join(bt, 0);
	} else {
		selected = 1;
		pthread_join(wt, 0);
	}
	pcap_close(foo);
	console_cleanup(t);
	return 0;
}

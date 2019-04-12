#define AUDIO_BACKEND_AO 1
#define AUDIO_BACKEND_SDL 2
#define AUDIO_BACKEND_NOP 3

#ifndef AUDIO_BACKEND
#define AUDIO_BACKEND AUDIO_BACKEND_AO
#endif

#if AUDIO_BACKEND == AUDIO_BACKEND_AO
#pragma RcB2 LINK "-lao"
#elif AUDIO_BACKEND == AUDIO_BACKEND_SDL
#pragma RcB2 LINK "-lSDL_sound" "-lSDL"
#endif

#include <unistd.h>

#if AUDIO_BACKEND == AUDIO_BACKEND_NOP

struct NopAudio {
	int dummy;
};

#define audio_init(X) do {} while(0)
#define audio_write(X, Y, Z) do {} while(0)
#define audio_close(X) do {} while(0)

#define AudioCTX NopAudio

#elif AUDIO_BACKEND == AUDIO_BACKEND_SDL

#include <pthread.h>
#include <SDL/SDL.h>
#include <SDL/SDL_audio.h>

struct SdlWriter {
	pthread_mutex_t cb_lock;
	char* buffer;
	size_t buffer_used;
	size_t buffer_size;
	SDL_AudioSpec fmt;
};

#define alock() pthread_mutex_lock(&self->cb_lock)
#define aunlock() pthread_mutex_unlock(&self->cb_lock)

static void sdl_callback(void *user, Uint8 *stream, int len) {
	struct SdlWriter *self = user;
	do {
		alock();
		if((size_t) len <= self->buffer_used) {
			memcpy(stream, self->buffer, len);
			size_t diff = self->buffer_used - len;
			memmove(self->buffer, (char*)self->buffer + len, diff);
			self->buffer_used = diff;
			aunlock();
			return;
		} else {
			aunlock();
			usleep(1000);
		}

	} while(1);
}

int SdlWriter_write(struct SdlWriter *self, void* buffer, size_t bufsize) {
	do {
		alock();
		if(self->buffer_used + bufsize > self->buffer_size) {
			aunlock();
			usleep(1000);
		} else {
			memcpy((char*)self->buffer + self->buffer_used, buffer, bufsize);
			self->buffer_used += bufsize;
			aunlock();
			break;
		}
	} while(1);
	return 1;
}

#undef alock
#undef aunlock

#define NUM_CHANNELS 2
int SdlWriter_init(struct SdlWriter *self) {
	SDL_Init(SDL_INIT_AUDIO);
	SDL_AudioSpec obtained;
	self->fmt.freq = 11025; //44100;
	self->fmt.format = AUDIO_U8; //AUDIO_S16;
	self->fmt.channels = 1; //NUM_CHANNELS;
	self->fmt.samples = 768; //COREMIXER_MAX_BUFFER;
	self->fmt.callback = sdl_callback;
	self->fmt.userdata = self;
	pthread_mutex_init(&self->cb_lock, 0);
	if(SDL_OpenAudio(&self->fmt, &obtained) < 0) {
		printf("sdl_openaudio: %s\n", SDL_GetError());
		return 0;
	}
	size_t max = obtained.samples > self->fmt.samples ? obtained.samples : self->fmt.samples;
	self->fmt = obtained;
	/* the buffer must be twice as big as the biggest number of samples processed/consumed */
	self->buffer_size = max * sizeof(int16_t) * NUM_CHANNELS * 2;
	if(!(self->buffer = malloc(self->buffer_size))) return 0;
	self->buffer_used = 0;
	SDL_PauseAudio(0);
	return 1;
}

int SdlWriter_close(struct SdlWriter *self) {
	SDL_CloseAudio();
	free(self->buffer);
	self->buffer = 0;
	self->buffer_size = 0;
	pthread_mutex_destroy(&self->cb_lock);
	SDL_QuitSubSystem(SDL_INIT_AUDIO);
	return 1;
}

#define audio_init(X) SdlWriter_init(X)
#define audio_write(X, Y, Z) SdlWriter_write(X, Y, Z)
#define audio_close(X) SdlWriter_close(X)

#define AudioCTX SdlWriter

#elif AUDIO_BACKEND == AUDIO_BACKEND_AO

#include <ao/ao.h>

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

#define audio_init(X) AoWriter_init(X)
#define audio_write(X, Y, Z) AoWriter_write(X, Y, Z)
#define audio_close(X) AoWriter_close(X)

#define AudioCTX AoWriter


#else
#error unknown AUDIO_BACKEND
#endif


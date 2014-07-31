MacGeiger - a WIFI AP locator utility
=====================================

3rd party dependencies (install them including headers, i.e. -dev package)
- libpcap :packet capturing library
- libao   :audio output library

1st party dependencies
- rcb     :build tool
  - depends on perl
- concol  :terminal library with ncurses,termbox and SDL backends
  - depends on either SDL or ncurses devel package installed

how to build:
paste this into your shell

    mkdir /tmp/macgeiger-build
    cd /tmp/macgeiger-build
    for i in rcb concol macgeiger ; do git clone git://github.com/rofl0r/$i ; done
    ln -s rcb.pl rcb/rcb
    cd macgeiger/
    printf "%s\n%s\n" "CFLAGS+=-DCONSOLE_BACKEND=SDL_CONSOLE" "CFLAGS+=-DCONSOLE_FONT=INT10FONT14" > config.mak
    PATH="$PATH:../rcb" make

if you want to use the ncurses backend (which is much harder to debug using gdb),
replace SDL_CONSOLE with NCURSES console in the above printf command

how to use:
./macgeiger wlan0mon
let the program gather network info for some seconds, then select an AP from the list
with cursor-up, cursor-down, then hit ENTER to track it with audio feedback.

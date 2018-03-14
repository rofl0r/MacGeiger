MacGeiger - a WIFI AP locator utility
=====================================

this tool puts your wireless card into monitor mode, then processes beacon
frames from APs to create a list, in which you can navigate with the cursor
keys, then select one AP with `ENTER`. the AP will open in detail view and
start to beep. the faster it beeps, the better is the signal of the AP.

this is quite handy to adjust directional antennas for the perfect signal
without having to stare at a screen, which may be impractical.

it can also be used on a mobile linux device (think netbook) to move through
the streets and find the physical location of APs. you probably should wear
headphones to do so...

the keys `+`/`-` and `0`/`9` can be used to adjust the audio volume.

Dependencies
------------

3rd party dependencies (install them including headers, i.e. -dev package)
- libpcap :packet capturing library
- libao   :audio output library

1st party dependencies
- rcb     :build tool
  - depends on perl
- concol  :terminal library with ncurses,termbox and SDL backends
  - depends on either SDL or ncurses devel package installed

how to build from release tarball:
----------------------------------

just run `make`. if you need to change variables, CFLAGS, etc, do so by
creating a file called `config.mak` and override the settings there.
you may also use it to change `BACKEND` to `SDL`.
by default the ncurses version will be built since it is assumed it is more
widely available.

Note: you may find release tarballs attached to git tags in the github repo.

how to build from git:
----------------------

paste this into your shell

    mkdir /tmp/macgeiger-build
    cd /tmp/macgeiger-build
    for i in rcb concol macgeiger libulz ; do git clone git://github.com/rofl0r/$i ; done
    mv libulz lib
    ln -s rcb.pl rcb/rcb
    cd macgeiger/
    printf "%s\n%s\n" "CFLAGS+=-DCONSOLE_BACKEND=SDL_CONSOLE" "CFLAGS+=-DCONSOLE_FONT=INT10FONT14" > config.mak
    PATH="$PATH:../rcb" make

if you want to use the ncurses backend (which is much harder to debug using gdb),
replace SDL_CONSOLE with NCURSES_CONSOLE in the above printf command

alternatively you may use the `create-dist` script to create a source tarball
that does not require the rcb build tool.

rebuilding with a different console backend:
-------------------------------------------
if you decided to try another backend (not the previously used one), run

    PATH="$PATH:../rcb" RCBFLAGS=--new make

how to use:
-----------

    ./macgeiger.out wlan0mon

let the program gather network info for some seconds, then select an AP from the list
with cursor-up, cursor-down, then hit ENTER to track it with audio feedback.

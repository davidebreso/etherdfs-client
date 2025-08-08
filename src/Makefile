#
# Makefile for mapdrive, requires Open Watcom v2
# Based on EtherDFS by Mateusz Viste and Davide Bresolin
#
# http://etherdfs.sourceforge.net
#

# Compiler settings
CFLAGS=-0 -s -d0 -ms -wx -ot

# -0      generate code for 8086
# -s      disable stack overflow checks
# -d0     don't include debugging information
# -ms     small memory model
# -wx     set warning level to max
# -ot     optimize for execution time

all: mapdrive.exe

etherdfs.obj: etherdfs.c dosstruc.h globals.h version.h
	wcc $CFLAGS etherdfs.c -fo=etherdfs.obj

mapdrive.exe: etherdfs.obj
	wlink system dos file etherdfs.obj option map=mapdrive name mapdrive
	upx -9 --8086 mapdrive.exe

clean: .symbolic
	rm -f mapdrive.exe
	rm -f mapdrive.map
	rm *.obj
	rm *.err

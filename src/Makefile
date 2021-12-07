#
# Makefile for etherdfs, requires Open Watcom v1.9
# Copyright (C) 2017 Mateusz Viste
#
# http://etherdfs.sourceforge.net
#

all: etherdfs.exe

#genmsg.exe: genmsg.c version.h
#	wcl -y -0 -s -d0 -lr -ms -we -wx -os genmsg.c -fe=genmsg.exe

genmsg: genmsg.c version.h
	gcc -o genmsg genmsg.c

chint.obj: chint086.asm
	wasm -0 chint086.asm -fo=chint.obj -mc
	
resident.obj: resident.c chint.h dosstruc.h globals.h
	wcc -0 -s -d0 -ms -wx resident.c -fo=resident.obj
	
etherdfs.obj: genmsg etherdfs.c chint.h dosstruc.h globals.h version.h
	./genmsg
	wcc -0 -s -d0 -ms -wx etherdfs.c -fo=etherdfs.obj

etherdfs.com: genmsg etherdfs.c chint.obj dosstruc.h globals.h version.h
	./genmsg
	wcl -y -0 -s -d0 -lr -mt -wx -k1024 -fm=etherdfs.map -os chint.obj -os etherdfs.c -fe=etherdfs.com

etherdfs.exe: genmsg etherdfs.obj chint.obj resident.obj
	wlink system dos file resident.obj,chint.obj,etherdfs.obj option map=etherdfs name etherdfs order clname rdata clname code segment begtext segment _text clname far_data clname begdata
	# upx -9 --8086 etherdfs.exe

begtext.obj: begtext.c begtext.h
	wcc -0 -s -d0 -ms -wx begtext.c -fo=begtext.obj	

begtext.exe: begmain.c begtext.obj begtext.h
	wcl -y -0 -s -d0 -lr -ms -wx -k1024 -fm=begtext.map -os begtext.obj begmain.c -fe=begtext.exe

# -y      ignore the WCL env. variable, if any
# -0      generate code for 8086
# -s      disable stack overflow checks
# -d0     don't include debugging information
# -lr     compile to a DOS real-mode application
# -ms     small memory model
# -we     treat all warnings as errors
# -wx     set warning level to max
# -k1024  set stack size to 1024 bytes (for the non-resident part)
# -fm=    generate a map file
# -os     optimize for size
# -fe     set output file name

clean: .symbolic
	if exist etherdfs.exe rm etherdfs.exe
	if exist genmsg rm genmsg
	rm *.obj

pkg: .symbolic etherdfs.exe
	if exist etherdfs.zip del etherdfs.zip
	zip -9 -k etherdfs.zip etherdfs.exe etherdfs.txt history.txt
	if exist ethersrc.zip del ethersrc.zip
	zip -9 -k ethersrc.zip *.h *.c *.asm *.txt makefile

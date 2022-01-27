
                === Improving the EtherDFS DOS client === 
                            Davide Bresolin

EtherDFS is a client/server filesystem that allows a modern host (the server) to
easily share files with an old PC running DOS. The original client TSR was
written by Mateusz Viste in 2017 and 2018. In 2020, Michael Ortmann added some
patches to the code to fix a few bugs and reduce the memory footprint.

The source code can be compiled with OpenWatcom v1.9 on a DOS machine, or a DOS
emulator. To write the EhterDFS TSR in C, Mateusz Viste had to use a few tricks 
to limit the memory footprint as much as possible, that are described in 
memnotes.txt.

This document describes the changes I made to the original source code for two
reasons: to compile the TSR with OpenWatcom v2 in a modern OSX machine, and to
remove some of the tricks used by Mateusz while keeping the memory footprint
small.

*** License ***

  MIT License
  Copyright (C) 2017, 2018 Mateusz Viste
  Copyright (c) 2020 Michael Ortmann
  Copyright (c) 2021 Davide Bresolin

*** Websites ***

  https://github.com/davidebreso/etherdfs-client
  https://gitlab.com/mortmann/etherdfs
  http://etherdfs.sourceforge.net


*** Compile the code on a modern machine ***

This was easy, and required only a few changes to the code:

    - modify the Makefile to work on a unix environment 
    - change path separators to unix forward slashes '/' 
    - compile genmsg.c with Apple's clang, since Open Watcom cannot generate 
      OSX executables

*** Keeping the memory footprint small ***

EtherDFS uses the INT 21h,31h DOS call to go resident. This call also allows to
trim any excess memory that won't be needed by the application any more. To
minimize the memory footprint it is necessary to place all resident code and
data, and also the stack before the transient part of the application.

You can instruct OpenWatcom to place the resident code in the segment BEGTEXT,
that is always the first segment of the memory map. Placing the resident data
and the stack before the transient code is much more complicated. The trick used
in the original code is to allocate a separate segment through an INT 21h,48h
call, and force EtherDFS to use THAT as its DATA & STACK segment by "patching"
portions of the code at runtime.

To remove the separate data and stack segment and the self-modifying code, I
forced OpenWatcom to place the resident data in the segment RESDATA of custom
class RDATA, and instructed the linker to place RESDATA at the start of the
memory map with the ORDER directive.

Still, the stack remained at the top of the memory. Forcing the linker to place
the stack before the code segments caused a lot of problems. I solved the
problem by allocating 1024 bytes in the resident data
segment to be used as stack space when the progam go resident. The interrupt
handler routine takes care of pointing the SS and SP registers to the top of
this 'resident stack space' before processing the int 2F call.

A change in the source code of the Open Watcom compiler of October 17, 2021 
introduced another pitfall: the preamble of interrupt functions now calls 
the function __GETDS to set the data segment. This function is part of the Open 
Watcom library, and it resides in the transient part of the code that gets 
trimmed when the program go resident. To solve this issue I added the code of
__GETDS to the resident code segment, so that it can be called by the interrupt
handler. The linker 

*** Trimming the excess memory ***

The DOS "go resident" call expects the amount of memory that needs to be kept in
16-bytes units (paragraphs). To know how many paragraphs the resident code and
data really takes, I used two little tricks to figure it out at compile time.

The linker places the various code and data segments of the program in the following
order: 

    RESDATA     (resident data and stack) 
    BEGTEXT     (resident code) 
    _TEXT       (transient code)
    ....        (transient data and other stuff)
    STACK       (transient stack)

Only the RESDATA and BEGTEXT segments need to be kept when going resident,
everything else can be discarded. The code uses the small memory model, where
the DS register points to the start of RESDATA (the first data portion of the
map) and the CS register points to the start of BEGTEXT (the first data portion
of the map). Hence, the size of RESDATA (in paragraphs) is given by the
difference between CS and DS.

To get the size of the resident code I used the trick already used by Mateusz
Viste: insert a code symbol (of an empty function) to the start of the transient
code. The offset of this simbol is the size of the resident code.

Finally, add the size of the PSP (256 bytes) to get the total amount of resident
memory.

*** Loading high ***

EtherDFS can be loaded high with the help of the LOADHIGH command of Dos 5+.
However, LOADHIGH needs a continuous block of upper memory large enough for
the whole program, not only for the resident portion. This requirement may
prevent EtherDFS to be loaded high even if there is enough free upper memory for
the resident part of the program. My version of EtherDFS uses a better
solution: the program is loaded in conventional memory, it allocates only the
required memory in the upper area, and moves the resident part there before going
resident. Thanks to this technique it can be loaded high in cases where LOADHIGH
fails.

The code for loading the TSR high is based on the 'Skeleton of TSR self-loading
to upper memory' at http://vitsoft.info/tsrup.htm. Allocating a separate memory
block reintroduced some of the problems that Mateusz Viste faced: the resident
code copied in the upper memory block should be able to access the data and
stack in the upper memory block. Instead of using self-modifying code, I opted
for a cleaner solution: I allocated a global variable into the resident _CODE_
segment to store the new data segment in upper memory. Then a little assembly
code at the top of the interrupt and packet driver handlers loads DS and SS with
the new segment.

Using this apporach, EtherDFS requires only a little more than 7K of contiguous
free upper memory to be loaded high.


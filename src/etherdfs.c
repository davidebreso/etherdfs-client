/*
 * EtherDFS - a network drive for DOS running over raw ethernet
 * http://etherdfs.sourceforge.net
 *
 * Copyright (C) 2017, 2018 Mateusz Viste
 * Copyright (c) 2020 Michael Ortmann
 * Copyright (C) 2021 Davide Bresolin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <i86.h>     /* union INTPACK */
// #include <stdio.h>   /* for printf */
#include "version.h" /* program & protocol version */

#include "dosstruc.h" /* definitions of structures used by DOS */
#include "globals.h"  /* global variables used by etherdfs */
#include "chint.h"    /* store_newds(newds) */

/* this function obviously does nothing - but I need it because it is a
 * 'low-water' mark for the end of my resident code (so I know how much memory
 * exactly I can trim when going TSR) */
static void begtextend(void) {
}

unsigned short residentcs;   /* segment of resident code */

/* registers a packet driver handle to use on subsequent calls */
static int pktdrv_accesstype(void) {
  unsigned char cflag = 0;
  _asm {
    mov ax, 201h        /* AH=subfunction access_type(), AL=if_class=1(eth) */
    mov bx, 0ffffh      /* if_type = 0xffff means 'all' */
    mov dl, 0           /* if_number: 0 (first interface) */
    /* ES:DI points to the receiving routine */
    mov es, residentcs   /* write segment of pktdrv_recv into es */
    mov di, offset pktdrv_recv
    /* DS:SI should point to the ethertype value in network byte order */
    push ds             /* save DS */
    mov ds, cs:glob_newds    /* Set DS to resident data area */
    mov si, offset glob_pktdrv_sndbuff + 12 /* DS:SI points to packet type specification */
    mov cx, 2            /* typelen (ethertype is 16 bits) */
    mov cflag, 1        /* pre-set the cflag variable to failure */
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
    /* get CF state - reset cflag if CF clear, and get pkthandle from AX */
    jc badluck   /* Jump if Carry */
    mov word ptr [glob_data + GLOB_DATOFF_PKTHANDLE], ax /* Pkt handle should be in AX */
    mov cflag, 0
    badluck:
    pop ds              /* restore DS */
  }

  if (cflag != 0) return(-1);
  return(0);
}

/* get my own MAC addr. target MUST point to a space of at least 6 chars */
static void pktdrv_getaddr(unsigned char *dst) {
  _asm {
    mov ah, 6                       /* subfunction: get_addr() */
    mov bx, word ptr [glob_data + GLOB_DATOFF_PKTHANDLE];  /* handle */
    push ds                         /* write segment of dst into es */
    pop es
    mov di, dst                     /* offset of dst (in small mem model dst IS an offset) */
    mov cx, 6                       /* expected length (ethernet = 6 bytes) */
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
  }
}


static int pktdrv_init(unsigned short pktintparam, int nocksum) {
  unsigned short far *intvect = (unsigned short far *)MK_FP(0, pktintparam << 2);
  unsigned short pktdrvfuncoffs = *intvect;
  unsigned short pktdrvfuncseg = *(intvect+1);
  unsigned short rseg = 0, roff = 0;
  char far *pktdrvfunc = (char far *)MK_FP(pktdrvfuncseg, pktdrvfuncoffs);
  int i;
  char sig[8];
  /* preload sig with "PKT DRVR" -- I could it just as well with
   * char sig[] = "PKT DRVR", but I want to avoid this landing in
   * my DATA segment so it doesn't pollute the TSR memory space. */
  sig[0] = 'P';
  sig[1] = 'K';
  sig[2] = 'T';
  sig[3] = ' ';
  sig[4] = 'D';
  sig[5] = 'R';
  sig[6] = 'V';
  sig[7] = 'R';

  /* set my ethertype to 0xF5ED (EDF5 in network byte order) */
  glob_pktdrv_sndbuff[12] = 0xED;
  glob_pktdrv_sndbuff[13] = 0xF5;
  /* set protover and CKSUM flag in send buffer (I won't touch it again) */
  if (nocksum == 0) {
    glob_pktdrv_sndbuff[56] = PROTOVER | 128; /* protocol version */
  } else {
    glob_pktdrv_sndbuff[56] = PROTOVER;       /* protocol version */
  }

  pktdrvfunc += 3; /* skip three bytes of executable code */
  for (i = 0; i < 8; i++) if (sig[i] != pktdrvfunc[i]) return(-1);

  glob_data.pktint = pktintparam;

  /* fetch the vector of the pktdrv interrupt and save it for later */
  _asm {
    mov ah, 35h /* AH=GetVect */
    mov al, byte ptr [glob_data] + GLOB_DATOFF_PKTINT; /* AL=int number */
    push es /* save ES and BX (will be overwritten) */
    push bx
    int 21h
    mov rseg, es
    mov roff, bx
    pop bx
    pop es
  }
  glob_pktdrv_pktcall = rseg;
  glob_pktdrv_pktcall <<= 16;
  glob_pktdrv_pktcall |= roff;

  return(pktdrv_accesstype());
}


static void pktdrv_free() {
  _asm {
    mov ah, 3
    mov bx, word ptr [glob_data + GLOB_DATOFF_PKTHANDLE]
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
  }
  /* if (regs.x.cflag != 0) return(-1);
  return(0);*/
}

static struct sdastruct far *getsda(void) {
  /* DOS 3.0+ - GET ADDRESS OF SDA (Swappable Data Area)
   * AX = 5D06h
   *
   * CF set on error (AX=error code)
   * DS:SI -> sda pointer
   */
  unsigned short rds = 0, rsi = 0;
  _asm {
    mov ax, 5d06h
    push ds
    push si
    int 21h
    mov bx, ds
    mov cx, si
    pop si
    pop ds
    mov rds, bx
    mov rsi, cx
  }
  return(MK_FP(rds, rsi));
}

/* returns the CDS struct for drive. requires DOS 4+ */
static struct cdsstruct far *getcds(unsigned int drive) {
  /* static to preserve state: only do init once */
  static unsigned char far *dir;
  static int ok = -1;
  static unsigned char lastdrv;
  /* init of never inited yet */
  if (ok == -1) {
    /* DOS 3.x+ required - no CDS in earlier versions */
    ok = 1;
    /* offsets of CDS and lastdrv in the List of Lists depends on the DOS version:
     * DOS < 3   no CDS at all
     * DOS 3.0   lastdrv at 1Bh, CDS pointer at 17h
     * DOS 3.1+  lastdrv at 21h, CDS pointer at 16h */
    /* fetch lastdrv and CDS through a little bit of inline assembly */
    _asm {
      push si /* SI needs to be preserved */
      /* get the List of Lists into ES:BX */
      mov ah, 52h
      int 21h
      /* get the LASTDRIVE value */
      mov si, 21h /* 21h for DOS 3.1+, 1Bh on DOS 3.0 */
      mov ah, byte ptr es:[bx+si]
      mov lastdrv, ah
      /* get the CDS */
      mov si, 16h /* 16h for DOS 3.1+, 17h on DOS 3.0 */
      les bx, es:[bx+si]
      mov word ptr dir+2, es
      mov word ptr dir, bx
      /* restore the original SI value*/
      pop si
    }
    /* some OSes (at least OS/2) set the CDS pointer to FFFF:FFFF */
    if (dir == (unsigned char far *) -1l) ok = 0;
  } /* end of static initialization */
  if (ok == 0) return(NULL);
  if (drive > lastdrv) return(NULL);
  /* return the CDS array entry for drive - note that currdir_size depends on
   * DOS version: 0x51 on DOS 3.x, and 0x58 on DOS 4+ */
  return((struct cdsstruct __far *)((unsigned char __far *)dir + (drive * 0x58 /*currdir_size*/)));
}
/******* end of CDS-related stuff *******/

/* primitive message output used instead of printf() to limit memory usage
 * and binary size */
static void outmsg(char *s);
#pragma aux outmsg =                                                         \
  "mov ah, 9h" /* DOS 1+ - WRITE STRING TO STANDARD OUTPUT                   \
                * DS:DX -> '$'-terminated string                             \
                * small memory model: no need to set DS, 's' is an offset */ \
  "int 21h"                                                                  \
parm [dx] modify exact [ah] nomemory;

/* zero out an object of l bytes */
static void zerobytes(void *obj, unsigned short l) {
  unsigned char *o = obj;
  while (l-- != 0) {
    *o = 0;
    o++;
  }
}

/* expects a hex string of exactly two chars "XX" and returns its value, or -1
 * if invalid */
static int hexpair2int(char *hx) {
  unsigned char h[2];
  unsigned short i;
  /* translate hx[] to numeric values and validate */
  for (i = 0; i < 2; i++) {
    if ((hx[i] >= 'A') && (hx[i] <= 'F')) {
      h[i] = hx[i] - ('A' - 10);
    } else if ((hx[i] >= 'a') && (hx[i] <= 'f')) {
      h[i] = hx[i] - ('a' - 10);
    } else if ((hx[i] >= '0') && (hx[i] <= '9')) {
      h[i] = hx[i] - '0';
    } else { /* invalid */
      return(-1);
    }
  }
  /* compute the end result and return it */
  i = h[0];
  i <<= 4;
  i |= h[1];
  return(i);
}

/* translates an ASCII MAC address into a 6-bytes binary string */
static int string2mac(unsigned char *d, char *mac) {
  int i, v;
  /* is it exactly 17 chars long? */
  for (i = 0; mac[i] != 0; i++);
  if (i != 17) return(-1);
  /* are nibble pairs separated by colons? */
  for (i = 2; i < 16; i += 3) if (mac[i] != ':') return(-1);
  /* translate each byte to its numeric value */
  for (i = 0; i < 16; i += 3) {
    v = hexpair2int(mac + i);
    if (v < 0) return(-1);
    *d = v;
    d++;
  }
  return(0);
}


#define ARGFL_QUIET 1
#define ARGFL_AUTO 2
#define ARGFL_UNLOAD 4
#define ARGFL_NOCKSUM 8
#define ARGFL_LOADHIGH 16

/* a structure used to pass and decode arguments between main() and parseargv() */
struct argstruct {
  int argc;    /* original argc */
  char **argv; /* original argv */
  unsigned short pktint; /* custom packet driver interrupt */
  unsigned char flags; /* ARGFL_QUIET, ARGFL_AUTO, ARGFL_UNLOAD, ARGFL_CKSUM, ARGFL_LOADHIGH */
};


/* parses (and applies) command-line arguments. returns 0 on success,
 * non-zero otherwise */
static int parseargv(struct argstruct *args) {
  int i, drivemapflag = 0, gotmac = 0;

  /* iterate through arguments, if any */
  for (i = 1; i < args->argc; i++) {
    char opt;
    char *arg;
    /* is it a drive mapping, like "c-x"? */
    if ((args->argv[i][0] >= 'A') && (args->argv[i][1] == '-') && (args->argv[i][2] >= 'A') && (args->argv[i][3] == 0)) {
      unsigned char ldrv, rdrv;
      rdrv = DRIVETONUM(args->argv[i][0]);
      ldrv = DRIVETONUM(args->argv[i][2]);
      if ((ldrv > 25) || (rdrv > 25)) return(-2);
      if (glob_data.ldrv[ldrv] != 0xff) return(-2);
      glob_data.ldrv[ldrv] = rdrv;
      drivemapflag = 1;
      continue;
    }
    /* not a drive mapping -> is it an option? */
    if (args->argv[i][0] == '/') {
      if (args->argv[i][1] == 0) return(-3);
      opt = args->argv[i][1];
      /* fetch option's argument, if any */
      if (args->argv[i][2] == 0) { /* single option */
        arg = NULL;
      } else if (args->argv[i][2] == '=') { /* trailing argument */
        arg = args->argv[i] + 3;
      } else {
        return(-3);
      }
      /* normalize the option char to lower case */
      if ((opt >= 'A') && (opt <= 'Z')) opt += ('a' - 'A');
      /* what is the option about? */
      switch (opt) {
        case 'q':
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_QUIET;
          break;
        case 'p':
          if (arg == NULL) return(-4);
          /* I expect an exactly 2-characters string */
          if ((arg[0] == 0) || (arg[1] == 0) || (arg[2] != 0)) return(-1);
          if ((args->pktint = hexpair2int(arg)) < 1) return(-4);
          break;
        case 'n':  /* disable CKSUM */
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_NOCKSUM;
          break;
        case 'u':  /* unload EtherDFS */
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_UNLOAD;
          break;
        case 'h': /* load TSR high */
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_LOADHIGH;
          break;
        default: /* invalid parameter */
          return(-5);
      }
      continue;
    }
    /* not a drive mapping nor an option -> so it's a MAC addr perhaps? */
    if (gotmac != 0) return(-1);  /* fail if got a MAC already */
    /* read the srv mac address, unless it's "::" (auto) */
    if ((args->argv[i][0] == ':') && (args->argv[i][1] == ':') && (args->argv[i][2] == 0)) {
      args->flags |= ARGFL_AUTO;
    } else {
      if (string2mac(GLOB_RMAC, args->argv[i]) != 0) return(-1);
    }
    gotmac = 1;
  }

  /* fail if MAC+unload or mapping+unload */
  if (args->flags & ARGFL_UNLOAD) {
    if ((gotmac != 0) || (drivemapflag != 0)) return(-1);
    return(0);
  }

  /* did I get at least one drive mapping? and a MAC? */
  if ((drivemapflag == 0) || (gotmac == 0)) return(-6);

  return(0);
}

/* translates an unsigned byte into a 2-characters string containing its hex
 * representation. s needs to be at least 3 bytes long. */
static void byte2hex(char *s, unsigned char b) {
  char h[16];
  unsigned short i;
  /* pre-compute h[] with a string 0..F -- I could do the same thing easily
   * with h[] = "0123456789ABCDEF", but then this would land inside the DATA
   * segment, while I want to keep it in stack to avoid polluting the TSR's
   * memory space */
  for (i = 0; i < 10; i++) h[i] = '0' + i;
  for (; i < 16; i++) h[i] = ('A' - 10) + i;
  /* */
  s[0] = h[b >> 4];
  s[1] = h[b & 15];
  s[2] = 0;
}

/* allocates sz paragraphs in upper memory and returns the segment to allocated memory 
 * or 0 on error. */
__declspec(naked) static unsigned short allocseg(unsigned short sz) {
  /* ask DOS for memory */
  _asm {
    /* set strategy to 'last fit' */
    mov ax, 5800h /* DOS 2.11+ - GET OR SET MEMORY ALLOCATION STRATEGY
                   * al = 0 means 'get allocation strategy' */
    int 21h       /* now current strategy is in ax */
    push ax       /* push current strategy to stack */
    mov ax, 5802h /* al = 2 means 'get UMB Link Status'*/ 
    int 21h       /* now current link status is in ax */
    push ax       /* push UMB Link Status to stack */
    mov ax, 5803h /* al = 3 means 'Set UMB Link Status' */
    mov bx, 1     /* 1 means 'include upper memory' */
    int 21h
    mov ax, 5801h /* al = 1 means 'set strategy' */
    mov bx, 0041h   /* 41h means 'upper best fit' */
    int 21h
    /* do the allocation now */
    mov ah, 48h     /* alloc memory (DOS 2+) */
    mov bx, dx      /* number of paragraphs to allocate */
    mov dx, 0       /* pre-set res to failure (0) */
    int 21h         /* returns allocated segment in AX */
    /* check CF */
    jc failed
    mov dx, ax    /* set res to actual result */
    failed:
    /* set link status back to its initial setting */
    mov ax, 5803h
    pop bx    /* pop UMB Link Status from stack */
    int 21h
    /* set strategy back to its initial setting */
    mov ax, 5801h
    pop bx        /* pop current strategy from stack */ 
    int 21h
    ret
  }
}
#pragma aux allocseg parm [dx] value [dx] modify exact [ax bx cl dx] nomemory;

/* free segment previously allocated through allocseg() */
static void freeseg(unsigned short segm) {
  _asm {
    mov ah, 49h   /* free memory (DOS 2+) */
    mov es, segm  /* put segment to free into ES */
    int 21h
  }
}

/* scans the 2Fh interrupt for some available 'multiplex id' in the range
 * C0..FF. also checks for EtherDFS presence at the same time. returns:
 *  - the available id if found
 *  - the id of the already-present etherdfs instance
 *  - 0 if no available id found
 * presentflag set to 0 if no etherdfs found loaded, non-zero otherwise. */
static unsigned char findfreemultiplex(unsigned char *presentflag) {
  unsigned char id = 0, freeid = 0, pflag = 0;
  _asm {
    mov id, 0C0h /* start scanning at C0h */
    checkid:
    xor al, al   /* subfunction is 'installation check' (00h) */
    mov ah, id
    int 2Fh
    /* is it free? (AL == 0) */
    test al, al
    jnz notfree    /* not free - is it me perhaps? */
    mov freeid, ah /* it's free - remember it, I may use it myself soon */
    jmp checknextid
    notfree:
    /* is it me? (AL=FF + BX=4D86 CX=7E1 [MV 2017]) */
    cmp al, 0ffh
    jne checknextid
    cmp bx, 4d86h
    jne checknextid
    cmp cx, 7e1h
    jne checknextid
    /* if here, then it's me... */
    mov ah, id
    mov freeid, ah
    mov pflag, 1
    jmp gameover
    checknextid:
    /* if not me, then check next id */
    inc id
    jnz checkid /* if id is zero, then all range has been covered (C0..FF) */
    gameover:
  }
  *presentflag = pflag;
  return(freeid);
}

/* Compute the size of resident memory needed by the program, in 16 btyes
 * paragraphs. How to compute the number of paragraphs? Simple: look at 
 * the memory map and note down the size of the RESDATA segment (that's 
 * where I store all TSR data) and of the BEGTEXT segment (that's where I 
 * store all TSR routines).
 * Then: (sizeof(RESDATA) + sizeof(BEGTEXT) + sizeof(PSP) + 15) / 16
 * PSP is 256 bytes of course. And +15 is needed to avoid truncating the
 * last (partially used) paragraph. */
static unsigned short get_residentsize() {
  unsigned short res = 0;
  _asm {
    push ax        /* save AX                                         */
    mov ax, offset begtextend /* AX = offset of resident code end     */
    add ax, 256    /* add size of PSP (256 bytes)                     */
    add ax, 15     /* add 15 to avoid truncating last paragraph       */
    mov cl, 4      /* convert bytes to number of 16-bytes paragraphs  */
    shr ax, cl     /* the 8086/8088 CPU supports only a 1-bit version
                    * of SHR so I use the reg,CL method               */
    /* Add size of RESDATA (in paragraphs) by subtracting CS and DS   */
    add ax, seg begtextend    /* add code segment                     */
    sub ax, seg glob_data     /* subtract data segment                */
    mov res, ax     /* set res to actual result */
    pop ax          /* restore AX                                     */   
  }
  return(res);
}

/* Compute the segment of the upper memory code */
static unsigned short get_upperds(unsigned short upperseg) {
  unsigned short res = 0;
  _asm {
    push ax        /* save AX                                         */
    /* Compute size of RESDATA (in paragraphs) by subtracting CS and DS   */
    mov ax, seg begtextend    /* AX is code segment                   */
    sub ax, seg glob_data     /* subtract data segment                */
    add ax, 16      /* add size of PSP (256 bytes, 16 paragraphs)     */
    add ax, upperseg    /* Add the upper base segment (points at PSP) */
    mov res, ax     /* set res to actual result */
    pop ax          /* restore AX                                     */     
  }
  return(res);
}

static unsigned char umb_ident[8] = "ETHERDFS";

int main(int argc, char **argv) {
  struct argstruct args;
  struct cdsstruct far *cds;
  unsigned char tmpflag = 0;
  int i;
  unsigned short upperseg;     /* segment of upper memory block to load high */
  unsigned short residentsize = get_residentsize();
  unsigned short old_pspseg;    /* PSP of low memory portion of the program */
  char buff[20];
  unsigned char far *mcbfptr;
  
  /* set all drive mappings as 'unused' */
  for (i = 0; i < 26; i++) glob_data.ldrv[i] = 0xff;

  /* parse command-line arguments */
  zerobytes(&args, sizeof(args));
  args.argc = argc;
  args.argv = argv;
  if (parseargv(&args) != 0) {
    #include "msg/help.c"
    return(1);
  }

  /* check DOS version - I require DOS 5.0+ */
  _asm {
    mov ax, 3306h
    int 21h
    mov tmpflag, bl
    inc al /* if AL was 0xFF ("unsupported function"), it is 0 now */
    jnz done
    mov tmpflag, 0 /* if AL is 0 (hence was 0xFF), set dosver to 0 */
    done:
  }
  if (tmpflag < 5) { /* tmpflag contains DOS version or 0 for 'unknown' */
    #include "msg/unsupdos.c"
    return(1);
  }

  /* look whether or not it's ok to install a network redirector at int 2F */
  _asm {
    mov tmpflag, 0
    mov ax, 1100h
    int 2Fh
    dec ax /* if AX was set to 1 (ie. "not ok to install"), it's zero now */
    jnz goodtogo
    mov tmpflag, 1
    goodtogo:
  }
  if (tmpflag != 0) {
    #include "msg/noredir.c"
    return(1);
  }

  /* is it all about unloading myself? */
  if ((args.flags & ARGFL_UNLOAD) != 0) {
    unsigned char etherdfsid, pktint;
    unsigned short myseg, myoff, myhandle;
    unsigned long pktdrvcall;
    struct tsrshareddata far *tsrdata;
    unsigned char far *int2fptr;

    /* am I loaded at all? */
    etherdfsid = findfreemultiplex(&tmpflag);
    if (tmpflag == 0) { /* not loaded, cannot unload */
      #include "msg/notload.c"
      return(1);
    }
    /* am I still at the top of the int 2Fh chain? */
    _asm {
      /* save BX and ES */
      push bx
      push es
      /* fetch int vector */
      mov ax, 352Fh  /* AH=35h 'GetVect' for int 2Fh */
      int 21h
      mov myseg, es
      mov myoff, bx
      /* restore BX and ES */
      pop es
      pop bx
    }
    /* the interrupt handler's signature appears at offset 26 
       (this might change at each source code modification) */
    int2fptr = (unsigned char far *)MK_FP(myseg, myoff) + 26; 
    /* look for the "MVet" signature */
    /* DEBUG: print signature */
    /* 
    for(i=0; i < 4; ++i) {
       buff[i] = int2fptr[i];
    }
    buff[4] = '\r';
    buff[5] = '\n';
    buff[6] = '$';
    outmsg(buff);
    */

    if ((int2fptr[0] != 'M') || (int2fptr[1] != 'V') || (int2fptr[2] != 'e') || (int2fptr[3] != 't')) {
      #include "msg/othertsr.c";
      return(1);
    }
    /* get the ptr to TSR's data */
    _asm {
      push bx
      pushf
      mov ah, etherdfsid
      mov al, 1
      mov cx, 4D86h
      mov myseg, 0ffffh
      int 2Fh /* AX should be 0, and BX:CX contains the address */
      test ax, ax
      jnz fail
      mov myseg, bx
      mov myoff, cx
      fail:
      popf
      pop bx
    }
    if (myseg == 0xffffu) {
      #include "msg/tsrcomfa.c"
      return(1);
    }
    // printf("TSR shared data at %04X:%04X\n", myseg, myoff);
    tsrdata = MK_FP(myseg, myoff);
    /* restore previous int 2f handler (under DS:DX, AH=25h, INT 21h)*/
    myseg = tsrdata->prev_2f_handler_seg;
    myoff = tsrdata->prev_2f_handler_off;
    _asm {
      /* save DS */
      push ds
      /* set DS:DX */
      mov ax, myseg
      push ax
      pop ds
      mov dx, myoff
      /* call INT 21h,25h for int 2Fh */
      mov ax, 252Fh
      int 21h
      /* restore DS */
      pop ds
    }
    /* get the address of the packet driver routine */
    pktint = tsrdata->pktint;
    _asm {
      /* save BX and ES */
      push bx
      push es
      /* fetch int vector */
      mov ah, 35h  /* AH=35h 'GetVect' */
      mov al, pktint /* interrupt */
      int 21h
      mov myseg, es
      mov myoff, bx
      /* restore BX and ES */
      pop es
      pop bx
    }
    pktdrvcall = myseg;
    pktdrvcall <<= 16;
    pktdrvcall |= myoff;
    /* unregister packet driver */
    myhandle = tsrdata->pkthandle;
    _asm {
      /* save AX */
      push ax
      /* prepare the release_type() call */
      mov ah, 3 /* release_type() */
      mov bx, myhandle
      /* call the pktdrv int */
      /* int to variable vector is a mess, so I have fetched its vector myself
       * and pushf + cli + call far it now to simulate a regular int */
      pushf
      cli
      call dword ptr pktdrvcall
      /* restore AX */
      pop ax
    }
    /* set all mapped drives as 'not available' */
    for (i = 0; i < 26; i++) {
      if (tsrdata->ldrv[i] == 0xff) continue;
      cds = getcds(i);
      if (cds != NULL) cds->flags = 0;
    }
    /* free TSR's resident seg and its PSP */
    // printf("Free TSR's resident memory at %04X\n", tsrdata->pspseg);
    freeseg(tsrdata->pspseg);
    /* all done */
    if ((args.flags & ARGFL_QUIET) == 0) {
      #include "msg/unloaded.c"
    }
    return(0);
  }

  /* remember current int 2f handler, we might over-write it soon (also I
   * use it to see if I'm already loaded) */
  _asm {
    mov ax, 352fh; /* AH=GetVect AL=2F */
    push es /* save ES and BX (will be overwritten) */
    push bx
    int 21h
    mov word ptr [glob_data + GLOB_DATOFF_PREV2FHANDLERSEG], es
    mov word ptr [glob_data + GLOB_DATOFF_PREV2FHANDLEROFF], bx
    pop bx
    pop es
  }

  /* is the TSR installed already? */
  glob_multiplexid = findfreemultiplex(&tmpflag);
  if (tmpflag != 0) { /* already loaded */
    #include "msg/alrload.c"
    return(1);
  } else if (glob_multiplexid == 0) { /* no free multiplex id found */
    #include "msg/nomultpx.c"
    return(1);
  }

  /* if any of the to-be-mapped drives is already active, fail */
  for (i = 0; i < 26; i++) {
    if (glob_data.ldrv[i] == 0xff) continue;
    cds = getcds(i);
    if (cds == NULL) {
      #include "msg/mapfail.c"
      return(1);
    }
    if (cds->flags != 0) {
      #include "msg/drvactiv.c"
      return(1);
    }
  }

  /* remember the SDA address (will be useful later) */
  glob_sdaptr = getsda();

  /* Save resident data segment inside resident code segment. */
  glob_newds = (FP_SEG((void far *)&glob_data));
  // printf("Saved resident data segment at %04X\n", glob_newds);

  /* Save resident code segment. */
  residentcs = (FP_SEG((void far *)&inthandler));
  // printf("Saved resident code segment at %04X\n", residentcs);

  /* init the packet driver interface */
  glob_data.pktint = 0;
  if (args.pktint == 0) { /* detect first packet driver within int 60h..80h */
    for (i = 0x60; i <= 0x80; i++) {
      if (pktdrv_init(i, args.flags & ARGFL_NOCKSUM) == 0) break;
    }
  } else { /* use the pktdrvr interrupt passed through command line */
    pktdrv_init(args.pktint, args.flags & ARGFL_NOCKSUM);
  }
  /* has it succeeded? */
  if (glob_data.pktint == 0) {
    #include "msg/pktdfail.c"
    return(1);
  }
  pktdrv_getaddr(GLOB_LMAC);

  /* should I auto-discover the server? */
  if ((args.flags & ARGFL_AUTO) != 0) {
    unsigned short *ax;
    unsigned char *answer;
    /* set (temporarily) glob_rmac to broadcast */
    for (i = 0; i < 6; i++) GLOB_RMAC[i] = 0xff;
    for (i = 0; glob_data.ldrv[i] == 0xff; i++); /* find first mapped disk */
    /* send a discovery frame that will update glob_rmac */
    if (sendquery(AL_DISKSPACE, i, 0, &answer, &ax, 1) != 6) {
      #include "msg/nosrvfnd.c"
      pktdrv_free(); /* free the pkt drv and quit */
      return(1);
    }
  }

  /* set all drives as being 'network' drives (also add the PHYSICAL bit,
   * otherwise MS-DOS 6.0 will ignore the drive) */
  for (i = 0; i < 26; i++) {
    if (glob_data.ldrv[i] == 0xff) continue;
    cds = getcds(i);
    cds->flags = CDSFLAG_NET | CDSFLAG_PHY;
    /* set 'current path' to root, to avoid inheriting any garbage */
    cds->current_path[0] = 'A' + i;
    cds->current_path[1] = ':';
    cds->current_path[2] = '\\';
    cds->current_path[3] = 0;
  }

  /* get the segment of the PSP (might come handy later) */
  _asm {
    mov ah, 62h          /* get current PSP address */
    int 21h              /* returns the segment of PSP in BX */
    mov word ptr [glob_data + GLOB_DATOFF_PSPSEG], bx  /* copy PSP segment to glob_pspseg */
  }
  // printf("PSP segment at %04X\n", glob_data.pspseg);
  // printf("RESDATA segment at %04X\n", FP_SEG((void far *)&glob_data));
  // printf("BEGTEXT segment at %04X\n", FP_SEG((void far *)inthandler));

  /* do I have to load myself high? */
  if ((args.flags & ARGFL_LOADHIGH) != 0) {
    /* allocate a new segment in the upper memory area to use for resident code and data */
    upperseg = allocseg(residentsize);
    if (upperseg == 0) {
      #include "msg/memfail.c"
      return(1);
    }
    // printf("Upper segment at %04X\n", upperseg);
    /* New resident data segment is upperseg + sizeof(PSP) in paragraphs 
     * PSP is 256 bytes (16 paragraphs). */
    glob_newds = upperseg + 16;
    // printf("Upper resident data segment at %04X\n", glob_newds);
    /* Get upper resident code segment */
    residentcs = get_upperds(upperseg);
    // printf("Upper resident code segment at %04X\n", residentcs);

    /* Set name of the block owner in the MCB
     * The Memory Control Block is 1 paragraph below upperseg
     * At offset 8 in MCB should be the name of block owner. */
    mcbfptr = (unsigned char far *)MK_FP(upperseg -1, 8); 
    // printf("Upper MCB signature at %04X:%04X\n", FP_SEG(mcbfptr), FP_OFF(mcbfptr));  
    for(i = 0; i < 8; i++) {
      mcbfptr[i] = umb_ident[i];
    }
  
    /* Set saved PSP segment to the upper memory block */
    old_pspseg = glob_data.pspseg;
    glob_data.pspseg = upperseg;
    // printf("Upper PSP segment at %04X\n", glob_data.pspseg);
    /* copy resident code and data into the upper memory segment */
    _asm {
      /* save registers on the stack */
      push ds
      push es
      push ax
      push cx
      push si
      push di
      pushf
      /* copy the memory block */
      mov ax, residentsize  /* ax is number of paragraphs to copy             */
      mov cl, 3           /* convert paragraphs to number of words            */
      shl ax, cl          /* the 8086/8088 CPU supports only a 1-bit version  */
                          /* of SHR so I use the reg,CL method                */
      mov cx, ax          /* CX is number of words to copy                    */    
      xor si, si          /* si = 0*/
      xor di, di          /* di = 0 */
      cld                 /* clear direction flag (increment si/di) */
      mov ax, old_pspseg  /* load ds with low memory PSP segment */           
      mov ds, ax          
      mov es, upperseg    /* load es with upperseg */
      rep movsw           /* execute copy DS:SI -> ES:DI */
      /* restore registers */
      popf
      pop di
      pop si
      pop cx
      pop ax
      pop es
      pop ds
    }
    /* Free the packet driver */
    pktdrv_free();
    /* Set new packet driver handle to upper memory */
    if(pktdrv_accesstype() != 0) {
      /* Relocation of packet driver failed.
       * Set all mapped drives as 'not available' */
      for (i = 0; i < 26; i++) {
        if (glob_data.ldrv[i] == 0xff) continue;
        cds = getcds(i);
        if (cds != NULL) cds->flags = 0;
      }
      /* Release upper memory block */
      freeseg(upperseg);
      #include "msg/relfail.c"
      return(1);
    }
  }

  if ((args.flags & ARGFL_QUIET) == 0) {
    #include "msg/instlled.c"
    for (i = 0; i < 6; i++) {
      byte2hex(buff + i + i + i, GLOB_LMAC[i]);
    }
    for (i = 2; i < 16; i += 3) buff[i] = ':';
    buff[17] = '$';
    outmsg(buff);
    #include "msg/pktdrvat.c"
    byte2hex(buff, glob_data.pktint);
    buff[2] = ')';
    buff[3] = '\r';
    buff[4] = '\n';
    buff[5] = '$';
    outmsg(buff);
    for (i = 0; i < 26; i++) {
      int z;
      if (glob_data.ldrv[i] == 0xff) continue;
      buff[0] = ' ';
      buff[1] = 'A' + i;
      buff[2] = ':';
      buff[3] = ' ';
      buff[4] = '-';
      buff[5] = '>';
      buff[6] = ' ';
      buff[7] = '[';
      buff[8] = 'A' + glob_data.ldrv[i];
      buff[9] = ':';
      buff[10] = ']';
      buff[11] = ' ';
      buff[12] = 'o';
      buff[13] = 'n';
      buff[14] = ' ';
      buff[15] = '$';
      outmsg(buff);
      for (z = 0; z < 6; z++) {
        byte2hex(buff + z + z + z, GLOB_RMAC[z]);
      }
      for (z = 2; z < 16; z += 3) buff[z] = ':';
      buff[17] = '\r';
      buff[18] = '\n';
      buff[19] = '$';
      outmsg(buff);
    }
  }

  /* free the environment (env segment is at offset 2C of the PSP) */
  // printf("Free the environment.\n");
  _asm {
    mov es, word ptr [glob_data + GLOB_DATOFF_PSPSEG] /* load ES with PSP's segment */
    mov es, es:[2Ch]    /* get segment of the env block */
    mov ah, 49h         /* free memory (DOS 2+) */
    int 21h
  }

  /* set up the TSR (INT 2F catching) */
  // printf("Set up the TSR at %04X:%04X\n", residentcs, inthandler);
  _asm {
    cli
    mov ax, 252fh /* AH=set interrupt vector  AL=2F */
    push ds /* preserve DS */
    push residentcs   /* set DS to the resident code segment, */
    pop ds      /* that is provide the int handler's segment  */
    mov dx, offset inthandler /* int handler's offset */
    int 21h
    pop ds /* restore DS to previous value */
    sti
  }

  // printf("Turn self into a TSR keeping %d paragraphs of memory\n", residentsize);
  /* If the TSR is loaded high, set the PSP to upper memory and deallocate low memory */
  if ((args.flags & ARGFL_LOADHIGH) != 0) {
    /* Set new PSP to upper memory */
    _asm {
      mov bx, upperseg    /* BX = new process PSP segment address */
      mov ah, 50h         /* INT 21,50 - Set Current Process ID */
      int 21h
    }
    /* Deallocate the whole low memory of the program */
    freeseg(old_pspseg);
  }
  /* When loading the TSR high, the following code actually run in deallocated memory
   * but luckily it is not overwritten yet by DOS. */
   
  /* Turn self into a TSR and free memory I won't need any more. That is, I
   * free all the libc startup code and my init functions by passing the
   * number of paragraphs to keep resident to INT 21h, AH=31h. How to compute
   * the number of paragraphs? Simple: look at the memory map and note down
   * the size of the RESDATA segment (that's where I store all TSR data) and of
   * the BEGTEXT segment (that's where I store all TSR routines).
   * Then: (sizeof(RESDATA) + sizeof(BEGTEXT) + sizeof(PSP) + 15) / 16
   * PSP is 256 bytes of course. And +15 is needed to avoid truncating the
   * last (partially used) paragraph. */
  _asm {
    mov ax, 3100h     /* AH=31 'terminate+stay resident', AL=0 exit code */
    mov dx, residentsize /* DX = size of resident memory (in paragraphs) */
    int 21h
  }

  return(0); /* never reached, but compiler complains if not present */
}

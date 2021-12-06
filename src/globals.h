/*
 * This file is part of the etherdfs project.
 * http://etherdfs.sourceforge.net
 *
 * Copyright (C) 2017 Mateusz Viste
 *
 * Contains all global variables used by etherdfs.
 */

#ifndef GLOBALS_SENTINEL
#define GLOBALS_SENTINEL

/* set DEBUGLEVEL to 0, 1 or 2 to turn on debug mode with desired verbosity */
#define DEBUGLEVEL 0

/* define the maximum size of a frame, as sent or received by etherdfs.
 * example: value 1084 accomodates payloads up to 1024 bytes +all headers */
#define FRAMESIZE 1090

/* define NULL, for readability of the code */
#ifndef NULL
  #define NULL (void *)0
#endif

/* required size (in bytes) of the data segment - this must be bigh enough as
 * to accomodate all "DATA" segments AND the stack, which will be located at
 * the very end of the data segment. packet drivers tend to require a stack
 * of several hundreds bytes at least - 1K should be safe... It is important
 * that DATASEGSZ can contain a stack of AT LEAST the size of the stack used
 * by the transient code, since the transient part of the program will switch
 * to it and expects the stack to not become corrupted in the process */
#define DATASEGSZ 3500

/* a few globals useful only for debug messages */
#if DEBUGLEVEL > 0
static unsigned short dbg_xpos = 0;
static unsigned short far *dbg_VGA = (unsigned short far *)(0xB8000000l);
static unsigned char dbg_hexc[16] = "0123456789ABCDEF";
#define dbg_startoffset 80*16
#endif

/* translates a drive letter (either upper- or lower-case) into a number (A=0,
 * B=1, C=2, etc) */
#define DRIVETONUM(x) (((x) >= 'a') && ((x) <= 'z')?x-'a':x-'A')

/* all the calls I support are in the range AL=0..2Eh - the list below serves
 * as a convenience to compare AL (subfunction) values */
enum AL_SUBFUNCTIONS {
  AL_INSTALLCHK = 0x00,
  AL_RMDIR      = 0x01,
  AL_MKDIR      = 0x03,
  AL_CHDIR      = 0x05,
  AL_CLSFIL     = 0x06,
  AL_CMMTFIL    = 0x07,
  AL_READFIL    = 0x08,
  AL_WRITEFIL   = 0x09,
  AL_LOCKFIL    = 0x0A,
  AL_UNLOCKFIL  = 0x0B,
  AL_DISKSPACE  = 0x0C,
  AL_SETATTR    = 0x0E,
  AL_GETATTR    = 0x0F,
  AL_RENAME     = 0x11,
  AL_DELETE     = 0x13,
  AL_OPEN       = 0x16,
  AL_CREATE     = 0x17,
  AL_FINDFIRST  = 0x1B,
  AL_FINDNEXT   = 0x1C,
  AL_SKFMEND    = 0x21,
  AL_UNKNOWN_2D = 0x2D,
  AL_SPOPNFIL   = 0x2E,
  AL_UNKNOWN    = 0xFF
};

/* whenever the tsrshareddata structure changes, offsets below MUST be
 * adjusted (these are required by assembly routines) */
#define GLOB_DATOFF_PREV2FHANDLERSEG 0
#define GLOB_DATOFF_PREV2FHANDLEROFF 2
#define GLOB_DATOFF_PSPSEG 4
#define GLOB_DATOFF_PKTHANDLE 6
#define GLOB_DATOFF_PKTINT 8

struct tsrshareddata {
/*offs*/
/*  0 */ unsigned short prev_2f_handler_seg; /* seg:off of the previous 2F handler */
/*  2 */ unsigned short prev_2f_handler_off; /* (so I can call it for all queries  */
                                            /* that do not relate to my drive     */
/*  4 */ unsigned short pspseg;    /* segment of the program's PSP block */
/*  6 */ unsigned short pkthandle; /* handler returned by the packet driver */
/*  8 */ unsigned char pktint;     /* software interrupt of the packet driver */

         unsigned char ldrv[26]; /* local to remote drives mappings (0=A:, 1=B, etc */
};

extern struct tsrshareddata glob_data;

/* global variables related to packet driver management and handling frames */
extern unsigned char glob_pktdrv_sndbuff[FRAMESIZE]; /* this not only is my send-frame buffer, but I also use it to store permanently lmac, rmac, ethertype and PROTOVER at proper places */
extern unsigned long glob_pktdrv_pktcall;     /* vector address of the pktdrv interrupt */

/* a few definitions for data that points to my sending buffer */
#define GLOB_LMAC (glob_pktdrv_sndbuff + 6) /* local MAC address */
#define GLOB_RMAC (glob_pktdrv_sndbuff)     /* remote MAC address */

extern struct sdastruct far *glob_sdaptr; /* pointer to DOS SDA (set by main() at *
                                           * startup, used later by process2f()   */

/* the INT 2F "multiplex id" registerd by EtherDFS */
extern unsigned char glob_multiplexid;


//*************//
//* Functions *//
//*************//

extern void __declspec(naked) far pktdrv_recv(void);
extern unsigned short sendquery(unsigned char query, unsigned char drive, unsigned short bufflen, unsigned char **replyptr, unsigned short **replyax, unsigned int updatermac);
extern void __interrupt __far inthandler(union INTPACK r);
extern void begtextend(void);
extern void outmsg(char *s);

#endif

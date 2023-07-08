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

/* all the resident code goes to segment 'BEGTEXT' */
#pragma code_seg(BEGTEXT, CODE)

/* all the resident data goes to segment 'RESDATA' of special class 'RDATA' */
#pragma data_seg(RESDATA, RDATA)

#include "dosstruc.h" /* definitions of structures used by DOS */
#include "globals.h"  /* global variables used by etherdfs */
#include "chint.h"   /* _mvchain_intr() */

struct tsrshareddata glob_data;

/* global variables related to packet driver management and handling frames */
unsigned char glob_pktdrv_recvbuff[FRAMESIZE];
signed short volatile glob_pktdrv_recvbufflen; /* length of the frame in buffer, 0 means "free", and neg value means "awaiting" */
unsigned char glob_pktdrv_sndbuff[FRAMESIZE]; /* this not only is my send-frame buffer, but I also use it to store permanently lmac, rmac, ethertype and PROTOVER at proper places */
unsigned long glob_pktdrv_pktcall;     /* vector address of the pktdrv interrupt */

unsigned char glob_reqdrv;  /* the requested drive, set by the INT 2F *
                                    * handler and read by process2f()        */

unsigned short glob_reqstkword; /* WORD saved from the stack (used by SETATTR) */
struct sdastruct far *glob_sdaptr; /* pointer to DOS SDA (set by main() at *
                                           * startup, used later by process2f()   */

/* seg:off addresses of the old (DOS) stack */
unsigned short glob_oldstack_seg;
unsigned short glob_oldstack_off;

/* the INT 2F "multiplex id" registerd by EtherDFS */
unsigned char glob_multiplexid;

/* an INTPACK structure used to store registers as set when INT2F is called */
union INTPACK glob_intregs;

/* copies len bytes from *src to *dst */
static void __declspec(naked) copybytes(void far *dst, void far *src, unsigned int len) {
  _asm {
    /* Save registers and flags into the stack */
    push ds
    pushf
    cld                /* clear direction flag (increment si/di) */
    mov ds, dx         /* load segment of source */
    shr cx, 1          /* number of words to copy */
    rep movsw          /* copy CX words from DS:SI -> ES:DI */
    adc cx, cx         /* see if 1 more byte to copy */
    rep movsb          /* do repeat copy */
    /* restore flags and registers */
    popf
    pop ds
    ret
  }   
}
#pragma aux copybytes parm [es di] [dx si] [cx] modify exact [cx di si] nomemory;

static unsigned short __declspec(naked) mystrlen(void far *s) {
  _asm {
    /* Save registers and flags into the stack */
    pushf
    cld                /* clear direction flag (increment si/di) */
    mov al, 0          /* Zero terminator */
    mov cx, 0xFFFF     /* CX count string length */
    repne scasb        /* scan string to find zero terminator */
    neg cx             /* string length is (-CX - 2) */
    dec cx
    dec cx
    /* restore flags and registers */
    popf
    ret
  }  
}
#pragma aux mystrlen parm [es di] value [cx] modify exact [ax cx di] nomemory;

/* returns -1 if the NULL-terminated s string contains any wildcard (?, *)
 * character. otherwise returns the length of the string. */
static int __declspec(naked) len_if_no_wildcards(char far *s) {
  _asm {
    /* Save registers and flags into the stack */
    push ds
    pushf
    cld               /* clear direction flag (increment si/di) */
    mov ds, cx        /* load segment of string */
    xor cx, cx        /* CX = 0 */
  next:
    lodsb             /* load byte at DS:SI into AL */
    test  al,al       /* is zero? */
    jz end            /* return string length */
    inc cx            /* it is a character, increment cx */
    cmp al,'?'        /* is '?' ? */
    je wildcard
    cmp al, '*'       /* is '*' ? */
    jne next          /* if not, continue with next char */
  wildcard:
    mov cx, -1
  end:
    /* restore flags and registers */
    popf
    pop ds 
    ret   
  }
}
#pragma aux len_if_no_wildcards parm [cx si] value [cx] modify exact [al cx si] nomemory;

/* computes a BSD checksum of l bytes at dataptr location */
__declspec(naked) static unsigned short bsdsum(unsigned char *dataptr, unsigned short l) {
  _asm {
    cld           /* clear direction flag */
    xor bx, bx    /* bx will hold the result */
    xor ax, ax
    iterate:
    lodsb         /* load a byte from DS:SI into AL and INC SI */
    ror bx, 1
    add bx, ax
    dec cx        /* DEC CX + JNZ could be replaced by a single LOOP */
    jnz iterate   /* instruction, but DEC+JNZ is 3x faster (on 8086) */
    ret
  }
}
/* Must be [si] [cx] and NOT [si cx] */
#pragma aux bsdsum parm [si] [cx] value [bx] modify exact [ax bx cx si] nomemory;

/* this function is called two times by the packet driver. One time for
 * telling that a packet is incoming, and how big it is, so the application
 * can prepare a buffer for it and hand it back to the packet driver. the
 * second call is just to let know that the frame has been copied into the
 * buffer. This is a naked function - I don't need the compiler to get into
 * the way when dealing with packet driver callbacks.
 * IMPORTANT: this function must take care to modify ONLY the registers
 * ES and DI - packet drivers can be easily confused should anything else
 * be modified. */
void __declspec(naked) far pktdrv_recv(void) {
  _asm {
    // jmp skip
    // SIG db 'pktr'
    // skip:
    /* save DS and flags to stack */
    push ds  /* save old ds (I will change it) */
    push bx  /* save bx (I use it as a temporary register) */
    pushf    /* save flags */
    /* set my custom DS (saved in CS:glob_newds) */
    mov bx, cs:glob_newds
    mov ds, bx
    /* handle the call */
    cmp ax, 0
    jne secondcall /* if ax != 0, then packet driver just filled my buffer */
    /* first call: the packet driver needs a buffer of CX bytes */
    cmp cx, FRAMESIZE /* is cx > FRAMESIZE ? (unsigned) */
    ja nobufferavail  /* it is too small (that's what she said!) */
    /* see if buffer not filled already... */
    cmp glob_pktdrv_recvbufflen, 0 /* is bufflen > 0 ? (signed) */
    jg nobufferavail  /* if signed > 0, then we are busy already */

    /* buffer is available, set its seg:off in es:di */
    mov es,bx /* set es:di to recvbuff */
    mov di, offset glob_pktdrv_recvbuff
    /* set bufferlen to expected len and switch it to neg until data comes */
    mov glob_pktdrv_recvbufflen, cx
    neg glob_pktdrv_recvbufflen
    /* restore flags, bx and ds, then return */
    jmp restoreandret

  nobufferavail: /* no buffer available, or it's too small -> fail */
    /* zero out es and di - this tells the packet driver 'sorry no can do' */
    xor di,di
    push di
    pop es
    /* restore flags, bx and ds, then return */
    jmp restoreandret

  secondcall: /* second call: I've just got data in buff */
    /* I switch back bufflen to positive so the app can see that something is there now */
    neg glob_pktdrv_recvbufflen
    /* restore flags, bx and ds, then return */
  restoreandret:
    popf   /* restore flags */
    pop bx /* restore bx */
    pop ds /* restore ds */
    retf
  }
}

/* this table makes it easy to figure out if I want a subfunction or not */
unsigned char supportedfunctions[0x2F] = {
  AL_INSTALLCHK,  /* 0x00 */
  AL_RMDIR,       /* 0x01 */
  AL_UNKNOWN,     /* 0x02 */
  AL_MKDIR,       /* 0x03 */
  AL_UNKNOWN,     /* 0x04 */
  AL_CHDIR,       /* 0x05 */
  AL_CLSFIL,      /* 0x06 */
  AL_CMMTFIL,     /* 0x07 */
  AL_READFIL,     /* 0x08 */
  AL_WRITEFIL,    /* 0x09 */
  AL_LOCKFIL,     /* 0x0A */
  AL_UNLOCKFIL,   /* 0x0B */
  AL_DISKSPACE,   /* 0x0C */
  AL_UNKNOWN,     /* 0x0D */
  AL_SETATTR,     /* 0x0E */
  AL_GETATTR,     /* 0x0F */
  AL_UNKNOWN,     /* 0x10 */
  AL_RENAME,      /* 0x11 */
  AL_UNKNOWN,     /* 0x12 */
  AL_DELETE,      /* 0x13 */
  AL_UNKNOWN,     /* 0x14 */
  AL_UNKNOWN,     /* 0x15 */
  AL_OPEN,        /* 0x16 */
  AL_CREATE,      /* 0x17 */
  AL_UNKNOWN,     /* 0x18 */
  AL_UNKNOWN,     /* 0x19 */
  AL_UNKNOWN,     /* 0x1A */
  AL_FINDFIRST,   /* 0x1B */
  AL_FINDNEXT,    /* 0x1C */
  AL_UNKNOWN,     /* 0x1D */
  AL_UNKNOWN,     /* 0x1E */
  AL_UNKNOWN,     /* 0x1F */
  AL_UNKNOWN,     /* 0x20 */
  AL_SKFMEND,     /* 0x21 */
  AL_UNKNOWN,     /* 0x22 */
  AL_UNKNOWN,     /* 0x23 */
  AL_UNKNOWN,     /* 0x24 */
  AL_UNKNOWN,     /* 0x25 */
  AL_UNKNOWN,     /* 0x26 */
  AL_UNKNOWN,     /* 0x27 */
  AL_UNKNOWN,     /* 0x28 */
  AL_UNKNOWN,     /* 0x29 */
  AL_UNKNOWN,     /* 0x2A */
  AL_UNKNOWN,     /* 0x2B */
  AL_UNKNOWN,     /* 0x2C */
  AL_UNKNOWN_2D,  /* 0x2D */
  AL_SPOPNFIL     /* 0x2E */
};

/*
an INTPACK struct contains following items:
regs.w.gs
regs.w.fs
regs.w.es
regs.w.ds
regs.w.di
regs.w.si
regs.w.bp
regs.w.sp
regs.w.bx
regs.w.dx
regs.w.cx
regs.w.ax
regs.w.ip
regs.w.cs
regs.w.flags (AND with INTR_CF to fetch the CF flag - INTR_CF is defined as 0x0001)

regs.h.bl
regs.h.bh
regs.h.dl
regs.h.dh
regs.h.cl
regs.h.ch
regs.h.al
regs.h.ah
*/


/* sends query out, as found in glob_pktdrv_sndbuff, and awaits for an answer.
 * this function returns the length of replyptr, or 0xFFFF on error. */
unsigned short sendquery(unsigned char query, unsigned char drive, unsigned short bufflen, unsigned char **replyptr, unsigned short **replyax, unsigned int updatermac) {
  static unsigned char seq;
  unsigned short count;
  unsigned char t;
  unsigned char volatile far *rtc = (unsigned char far *)0x46C; /* this points to a char, while the rtc timer is a word - but I care only about the lowest 8 bits. Be warned that this location won't increment while interrupts are disabled! */
  
  /* resolve remote drive - no need to validate it, it has been validated
   * already by inthandler() */
  drive = glob_data.ldrv[drive];

  /* bufflen provides payload's length, but I prefer knowing the frame's len */
  bufflen += 60;

  /* if query too long then quit */
  if (bufflen > sizeof(glob_pktdrv_sndbuff)) {
      return(0);
  }
  /* inc seq */
  seq++;
  /* I do not fill in ethernet headers (src mac, dst mac, ethertype), nor
   * PROTOVER, since all these have been inited already at transient time */
  /* padding (38 bytes) */
  ((unsigned short *)glob_pktdrv_sndbuff)[26] = bufflen; /* total frame len */
  glob_pktdrv_sndbuff[57] = seq;   /* seq number */
  glob_pktdrv_sndbuff[58] = drive;
  glob_pktdrv_sndbuff[59] = query; /* AL value (query) */
  if (glob_pktdrv_sndbuff[56] & 128) { /* if CKSUM enabled, compute it */
    /* fill in the BSD checksum at offset 54 */
    ((unsigned short *)glob_pktdrv_sndbuff)[27] = bsdsum(glob_pktdrv_sndbuff + 56, bufflen - 56);
  }
  /* I do not copy anything more into glob_pktdrv_sndbuff - the caller is
   * expected to have already copied all relevant data into glob_pktdrv_sndbuff+60
   * copybytes((unsigned char far *)glob_pktdrv_sndbuff + 60, (unsigned char far *)buff, bufflen);
   */

  /* send the query frame and wait for an answer for about 100ms. then, resend
   * the query again and again, up to 5 times. the RTC clock at 0x46C is used
   * as a timing reference. */
  glob_pktdrv_recvbufflen = 0; /* mark the receiving buffer empty */
  for (count = 5; count != 0; count--) { /* faster than count=0; count<5; count++ */
    /* send the query frame out */
    _asm {
      /* save registers */
      push ax
      push cx
      push dx /* may be changed by the packet driver (set to errno) */
      push si
      pushf /* must be last register pushed (expected by 'call') */
      /* */
      mov ah, 4h   /* SendPkt */
      mov cx, bufflen
      mov si, offset glob_pktdrv_sndbuff /* DS:SI points to buff, I do not
                                 modify DS because the buffer should already
                                 be in my data segment (small memory model) */
      /* int to variable vector is a mess, so I have fetched its vector myself
       * and pushf + cli + call far it now to simulate a regular int */
      /* pushf -- already on the stack */
      cli
      call dword ptr glob_pktdrv_pktcall
      /* restore registers (but not pushf, already restored by call) */
      pop si
      pop dx
      pop cx
      pop ax
    }

    /* wait for (and validate) the answer frame */
    t = *rtc;
    for (;;) {
      int i;
      if ((t != *rtc) && (t+1 != *rtc) && (*rtc != 0)) {
          break; /* timeout, retry */
      }
      if (glob_pktdrv_recvbufflen < 1) continue;
      /* I've got something! */
      /* is the frame long enough for me to care? */
      if (glob_pktdrv_recvbufflen < 60) goto ignoreframe;
      /* is it for me? (correct src mac & dst mac) */
      for (i = 0; i < 6; i++) {
        if (glob_pktdrv_recvbuff[i] != GLOB_LMAC[i]) goto ignoreframe;
        if ((updatermac == 0) && (glob_pktdrv_recvbuff[i+6] != GLOB_RMAC[i])) goto ignoreframe;
      }
      /* is the ethertype and seq what I expect? */
      if ((((unsigned short *)glob_pktdrv_recvbuff)[6] != 0xF5EDu) || (glob_pktdrv_recvbuff[57] != seq)) goto ignoreframe;

      /* validate frame length (if provided) */
      if (((unsigned short *)glob_pktdrv_recvbuff)[26] > glob_pktdrv_recvbufflen) {
        /* frame appears to be truncated */
        goto ignoreframe;
      }
      if (((unsigned short *)glob_pktdrv_recvbuff)[26] < 60) {
        /* malformed frame */
        goto ignoreframe;
      }
      glob_pktdrv_recvbufflen = ((unsigned short *)glob_pktdrv_recvbuff)[26];

      /* if CKSUM enabled, check it on received frame */
      if (glob_pktdrv_sndbuff[56] & 128) {
        /* is the cksum ok? */
        if (bsdsum(glob_pktdrv_recvbuff + 56, glob_pktdrv_recvbufflen - 56) != (((unsigned short *)glob_pktdrv_recvbuff)[27])) {
          /* DEBUG - prints a '!' on screen on cksum error */ /*{
            unsigned short far *v = (unsigned short far *)0xB8000000l;
            v[0] = 0x4000 | '!';
          }*/
          goto ignoreframe;
        }
      }

      /* return buffer (without headers and seq) */
      *replyptr = glob_pktdrv_recvbuff + 60;
      *replyax = (unsigned short *)(glob_pktdrv_recvbuff + 58);
      /* update glob_rmac if needed, then return */
      if (updatermac != 0) copybytes(GLOB_RMAC, glob_pktdrv_recvbuff + 6, 6);
      return(glob_pktdrv_recvbufflen - 60);
      ignoreframe: /* ignore this frame and wait for the next one */
      glob_pktdrv_recvbufflen = 0; /* mark the buffer empty */
    }
  }

  return(0xFFFFu); /* return error */
}


/* reset CF (set on error only) and AX (expected to contain the error code,
 * I might set it later) - I assume a success */
#define SUCCESSFLAG glob_intregs.w.ax = 0; glob_intregs.w.flags &= ~(INTR_CF);
#define FAILFLAG(x) {glob_intregs.w.ax = x; glob_intregs.w.flags |= INTR_CF;}

/* this function contains the logic behind INT 2F processing */
void process2f(void) {
#if DEBUGLEVEL > 0
  char far *dbg_msg = NULL;
#endif
  short i;
  unsigned char *answer;
  unsigned char *buff; /* pointer to the "query arguments" part of glob_pktdrv_sndbuff */
  unsigned char subfunction;
  unsigned short *ax; /* used to collect the resulting value of AX */
  buff = glob_pktdrv_sndbuff + 60;

  /* DEBUG output (RED) */
#if DEBUGLEVEL > 0
  dbg_xpos &= 511;
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | ' ';
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | (dbg_hexc[(glob_intregs.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | (dbg_hexc[glob_intregs.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | ' ';
#endif

  /* remember the AL register (0x2F subfunction id) */
  subfunction = glob_intregs.h.al;

  /* if we got here, then the call is definitely for us. set AX and CF to */
  /* 'success' (being a natural optimist I assume success) */
  SUCCESSFLAG;

  /* look what function is called exactly and process it */
  switch (subfunction) {
    case AL_RMDIR: /*** 01h: RMDIR ******************************************/
      /* RMDIR is like MKDIR, but I need to check if dir is not current first */
      for (i = 0; glob_sdaptr->fn1[i] != 0; i++) {
        if (glob_sdaptr->fn1[i] != glob_sdaptr->drive_cdsptr[i]) goto proceedasmkdir;
      }
      FAILFLAG(16); /* err 16 = "attempted to remove current directory" */
      break;
      proceedasmkdir:
    case AL_MKDIR: /*** 03h: MKDIR ******************************************/
      i = mystrlen(glob_sdaptr->fn1);
      /* fn1 must be at least 2 bytes long */
      if (i < 2) {
        FAILFLAG(3); /* "path not found" */
        break;
      }
      /* copy fn1 to buff (but skip drive part) */
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query providing fn1 */
      if (sendquery(subfunction, glob_reqdrv, i, &answer, &ax, 0) == 0) {
        glob_intregs.w.ax = *ax;
        if (*ax != 0) glob_intregs.w.flags |= INTR_CF;
      } else {
        FAILFLAG(2);
      }
      break;
    case AL_CHDIR: /*** 05h: CHDIR ******************************************/
      /* The INT 2Fh/1105h redirector callback is executed by DOS when
       * changing directories. The Phantom authors (and RBIL contributors)
       * clearly thought that it was the redirector's job to update the CDS,
       * but in fact the callback is only meant to validate that the target
       * directory exists; DOS subsequently updates the CDS. */
      /* fn1 must be at least 2 bytes long */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(3); /* "path not found" */
        break;
      }
      /* copy fn1 to buff (but skip the drive: part) */
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query providing fn1 */
      if (sendquery(AL_CHDIR, glob_reqdrv, i, &answer, &ax, 0) == 0) {
        glob_intregs.w.ax = *ax;
        if (*ax != 0) glob_intregs.w.flags |= INTR_CF;
      } else {
        FAILFLAG(3); /* "path not found" */
      }
      break;
    case AL_CLSFIL: /*** 06h: CLSFIL ****************************************/
      /* my only job is to decrement the SFT's handle count (which I didn't
       * have to increment during OPENFILE since DOS does it... talk about
       * consistency. I also inform the server about this, just so it knows */
      /* ES:DI points to the SFT */
      {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      if (sftptr->handle_count > 0) sftptr->handle_count--;
      ((unsigned short *)buff)[0] = sftptr->start_sector;
      if (sendquery(AL_CLSFIL, glob_reqdrv, 2, &answer, &ax, 0) == 0) {
        if (*ax != 0) FAILFLAG(*ax);
      }
      }
      break;
    case AL_CMMTFIL: /*** 07h: CMMTFIL **************************************/
      /* I have nothing to do here */
      break;
    case AL_READFIL: /*** 08h: READFIL **************************************/
      { /* ES:DI points to the SFT (whose file_pos needs to be updated) */
        /* CX = number of bytes to read (to be updated with number of bytes actually read) */
        /* SDA DTA = read buffer */
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      unsigned short totreadlen;
      /* is the file open for write-only? */
      if (sftptr->open_mode & 1) {
        FAILFLAG(5); /* "access denied" */
        break;
      }
      /* return immediately if the caller wants to read 0 bytes */
      if (glob_intregs.x.cx == 0) break;
      /* do multiple read operations so chunks can fit in my eth frames */
      totreadlen = 0;
      for (;;) {
        int chunklen, len;
        if ((glob_intregs.x.cx - totreadlen) < (FRAMESIZE - 60)) {
          chunklen = glob_intregs.x.cx - totreadlen;
        } else {
          chunklen = FRAMESIZE - 60;
        }
        /* query is OOOOSSLL (offset, start sector, length to read) */
        ((unsigned long *)buff)[0] = sftptr->file_pos + totreadlen;
        ((unsigned short *)buff)[2] = sftptr->start_sector;
        ((unsigned short *)buff)[3] = chunklen;
        len = sendquery(AL_READFIL, glob_reqdrv, 8, &answer, &ax, 0);
        if (len == 0xFFFFu) { /* network error */
          FAILFLAG(2);
          break;
        } else if (*ax != 0) { /* backend error */
          FAILFLAG(*ax);
          break;
        } else { /* success */
          copybytes(glob_sdaptr->curr_dta + totreadlen, answer, len);
          totreadlen += len;
          if ((len < chunklen) || (totreadlen == glob_intregs.x.cx)) { /* EOF - update SFT and break out */
            sftptr->file_pos += totreadlen;
            glob_intregs.x.cx = totreadlen;
            break;
          }
        }
      }
      }
      break;
    case AL_WRITEFIL: /*** 09h: WRITEFIL ************************************/
      { /* ES:DI points to the SFT (whose file_pos needs to be updated) */
        /* CX = number of bytes to write (to be updated with number of bytes actually written) */
        /* SDA DTA = read buffer */
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      unsigned short bytesleft, chunklen, written = 0;
      /* is the file open for read-only? */
      if ((sftptr->open_mode & 3) == 0) {
        FAILFLAG(5); /* "access denied" */
        break;
      }
      /* TODO FIXME I should update the file's time in the SFT here */
      /* do multiple write operations so chunks can fit in my eth frames */
      bytesleft = glob_intregs.x.cx;

      do { /* MUST do at least one loop so 0-bytes write calls are sent to ethersrv, */
           /* this is required because a 0-bytes write means "truncate"              */
        unsigned short len;
        chunklen = bytesleft;
        if (chunklen > FRAMESIZE - 66) chunklen = FRAMESIZE - 66;
        /* query is OOOOSS (file offset, start sector/fileid) */
        ((unsigned long *)buff)[0] = sftptr->file_pos;
        ((unsigned short *)buff)[2] = sftptr->start_sector;
        copybytes(buff + 6, glob_sdaptr->curr_dta + written, chunklen);
        len = sendquery(AL_WRITEFIL, glob_reqdrv, chunklen + 6, &answer, &ax, 0);
        if (len == 0xFFFFu) { /* network error */
          FAILFLAG(2);
          break;
        } else if ((*ax != 0) || (len != 2)) { /* backend error */
          FAILFLAG(*ax);
          break;
        } else { /* success - write amount of bytes written into CX and update SFT */
          len = ((unsigned short *)answer)[0];
          written += len;
          bytesleft -= len;
          glob_intregs.x.cx = written;
          sftptr->file_pos += len;
          if (sftptr->file_pos > sftptr->file_size) sftptr->file_size = sftptr->file_pos;
          if (len != chunklen) break; /* something bad happened on the other side */
        }
      } while (bytesleft > 0);
      }
      break;
    case AL_LOCKFIL: /*** 0Ah: LOCKFIL **************************************/
      {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      ((unsigned short *)buff)[0] = glob_intregs.x.cx;
      ((unsigned short *)buff)[1] = sftptr->start_sector;
      if (glob_intregs.h.bl > 1) FAILFLAG(2); /* BL should be either 0 (lock) or 1 (unlock) */
      /* copy 8*CX bytes from DS:DX to buff+4 (parameters block) */
      copybytes(buff + 4, MK_FP(glob_intregs.x.ds, glob_intregs.x.dx), glob_intregs.x.cx << 3);
      if (sendquery(AL_LOCKFIL + glob_intregs.h.bl, glob_reqdrv, (glob_intregs.x.cx << 3) + 4, &answer, &ax, 0) != 0) {
        FAILFLAG(2);
      }
      }
      break;
    case AL_UNLOCKFIL: /*** 0Bh: UNLOCKFIL **********************************/
      /* Nothing here - this isn't supposed to be used by DOS 4+ */
      FAILFLAG(2);
      break;
    case AL_DISKSPACE: /*** 0Ch: get disk information ***********************/
      if (sendquery(AL_DISKSPACE, glob_reqdrv, 0, &answer, &ax, 0) == 6) {
        glob_intregs.w.ax = *ax; /* sectors per cluster */
        glob_intregs.w.bx = ((unsigned short *)answer)[0]; /* total clusters */
        glob_intregs.w.cx = ((unsigned short *)answer)[1]; /* bytes per sector */
        glob_intregs.w.dx = ((unsigned short *)answer)[2]; /* num of available clusters */
      } else {
        FAILFLAG(2);
      }
      break;
    case AL_SETATTR: /*** 0Eh: SETATTR **************************************/
      /* sdaptr->fn1 -> file to set attributes for
         stack word -> new attributes (stack must not be changed!) */
      /* fn1 must be at least 2 characters long */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      /* */
      buff[0] = glob_reqstkword;
      /* copy fn1 to buff (but without the drive part) */
      copybytes(buff + 1, glob_sdaptr->fn1 + 2, i - 2);
    #if DEBUGLEVEL > 0
      dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1000 | dbg_hexc[(glob_reqstkword >> 4) & 15];
      dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1000 | dbg_hexc[glob_reqstkword & 15];
    #endif
      i = sendquery(AL_SETATTR, glob_reqdrv, i - 1, &answer, &ax, 0);
      if (i != 0) {
        FAILFLAG(2);
      } else if (*ax != 0) {
        FAILFLAG(*ax);
      }
      break;
    case AL_GETATTR: /*** 0Fh: GETATTR **************************************/
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      i = sendquery(AL_GETATTR, glob_reqdrv, i, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 9) || (*ax != 0)) {
        FAILFLAG(*ax);
      } else { /* all good */
        /* CX = timestamp
         * DX = datestamp
         * BX:DI = fsize
         * AX = attr
         * NOTE: Undocumented DOS talks only about setting AX, no fsize, time
         *       and date, these are documented in RBIL and used by SHSUCDX */
        glob_intregs.w.cx = ((unsigned short *)answer)[0]; /* time */
        glob_intregs.w.dx = ((unsigned short *)answer)[1]; /* date */
        glob_intregs.w.bx = ((unsigned short *)answer)[3]; /* fsize hi word */
        glob_intregs.w.di = ((unsigned short *)answer)[2]; /* fsize lo word */
        glob_intregs.w.ax = answer[8];                     /* file attribs */
      }
      break;
    case AL_RENAME: /*** 11h: RENAME ****************************************/
      /* sdaptr->fn1 = old name
       * sdaptr->fn2 = new name */
      /* is the operation for the SAME drive? */
      if (glob_sdaptr->fn1[0] != glob_sdaptr->fn2[0]) {
        FAILFLAG(2);
        break;
      }
      /* prepare the query (LSSS...DDD...) */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2; /* trim out the drive: part (C:\FILE --> \FILE) */
      buff[0] = i;
      copybytes(buff + 1, glob_sdaptr->fn1 + 2, i);
      i = len_if_no_wildcards(glob_sdaptr->fn2);
      if (i < 2) {
        FAILFLAG(3);
        break;
      }
      i -= 2; /* trim out the drive: part (C:\FILE --> \FILE) */
      copybytes(buff + 1 + buff[0], glob_sdaptr->fn2 + 2, i);
      /* send the query out */
      i = sendquery(AL_RENAME, glob_reqdrv, 1 + buff[0] + i, &answer, &ax, 0);
      if (i != 0) {
        FAILFLAG(2);
      } else if (*ax != 0) {
        FAILFLAG(*ax);
      }
      break;
    case AL_DELETE: /*** 13h: DELETE ****************************************/
    #if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
    #endif
      /* compute length of fn1 and copy it to buff (w/o the 'drive:' part) */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query */
      i = sendquery(AL_DELETE, glob_reqdrv, i, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 0) || (*ax != 0)) {
        FAILFLAG(*ax);
      }
      break;
    case AL_OPEN: /*** 16h: OPEN ********************************************/
    case AL_CREATE: /*** 17h: CREATE ****************************************/
    case AL_SPOPNFIL: /*** 2Eh: SPOPNFIL ************************************/
    #if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
    #endif
      /* fail if fn1 contains any wildcard, otherwise get len of fn1 */
      i = len_if_no_wildcards(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(3);
        break;
      }
      i -= 2;
      /* prepare and send query (SSCCMMfff...) */
      ((unsigned short *)buff)[0] = glob_reqstkword; /* WORD from the stack */
      ((unsigned short *)buff)[1] = glob_sdaptr->spop_act; /* action code (SPOP only) */
      ((unsigned short *)buff)[2] = glob_sdaptr->spop_mode; /* open mode (SPOP only) */
      copybytes(buff + 6, glob_sdaptr->fn1 + 2, i);
      i = sendquery(subfunction, glob_reqdrv, i + 6, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 25) || (*ax != 0)) {
        FAILFLAG(*ax);
      } else {
        /* ES:DI contains an uninitialized SFT */
        struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
        /* special treatment for SPOP, (set open_mode and return CX, too) */
        if (subfunction == AL_SPOPNFIL) {
          glob_intregs.w.cx = ((unsigned short *)answer)[11];
        }
        if (sftptr->open_mode & 0x8000) { /* if bit 15 is set, then it's a "FCB open", and requires the internal DOS "Set FCB Owner" function to be called */
          /* TODO FIXME set_sft_owner() */
        #if DEBUGLEVEL > 0
          dbg_VGA[25*80] = 0x1700 | '$';
        #endif
        }
        sftptr->file_attr = answer[0];
        sftptr->dev_info_word = 0x8040 | glob_reqdrv; /* mark device as network & unwritten drive */
        sftptr->dev_drvr_ptr = NULL;
        sftptr->start_sector = ((unsigned short *)answer)[10];
        sftptr->file_time = ((unsigned long *)answer)[3];
        sftptr->file_size = ((unsigned long *)answer)[4];
        sftptr->file_pos = 0;
        sftptr->open_mode &= 0xff00u;
        sftptr->open_mode |= answer[24];
        sftptr->rel_sector = 0xffff;
        sftptr->abs_sector = 0xffff;
        sftptr->dir_sector = 0;
        sftptr->dir_entry_no = 0xff; /* why such value? no idea, PHANTOM.C uses that, too */
        copybytes(sftptr->file_name, answer + 1, 11);
      }
      break;
    case AL_FINDFIRST: /*** 1Bh: FINDFIRST **********************************/
    case AL_FINDNEXT:  /*** 1Ch: FINDNEXT ***********************************/
      {
      /* AX = 111Bh
      SS = DS = DOS DS
      [DTA] = uninitialized 21-byte findfirst search data
      (see #01626 at INT 21/AH=4Eh)
      SDA first filename pointer (FN1, 9Eh) -> fully-qualified search template
      SDA CDS pointer -> current directory structure for drive with file
      SDA search attribute = attribute mask for search

      Return:
      CF set on error
      AX = DOS error code (see #01680 at INT 21/AH=59h/BX=0000h)
           -> http://www.ctyme.com/intr/rb-3012.htm
      CF clear if successful
      [DTA] = updated findfirst search data
      (bit 7 of first byte must be set)
      [DTA+15h] = standard directory entry for file (see #01352)

      FindNext is the same, but only DTA should be used to fetch search params
      */
      struct sdbstruct far *dta;

#if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
#endif
      /* prepare the query buffer (i must provide query's length) */
      if (subfunction == AL_FINDFIRST) {
        dta = (struct sdbstruct far *)(glob_sdaptr->curr_dta);
        /* FindFirst needs to fetch search arguments from SDA */
        buff[0] = glob_sdaptr->srch_attr; /* file attributes to look for */
        /* copy fn1 (w/o drive) to buff */
        for (i = 2; glob_sdaptr->fn1[i] != 0; i++) buff[i-1] = glob_sdaptr->fn1[i];
        i--; /* adjust i because its one too much otherwise */
      } else { /* FindNext needs to fetch search arguments from DTA (es:di) */
        dta = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
        ((unsigned short *)buff)[0] = dta->par_clstr;
        ((unsigned short *)buff)[1] = dta->dir_entry;
        buff[4] = dta->srch_attr;
        /* copy search template to buff */
        for (i = 0; i < 11; i++) buff[i+5] = dta->srch_tmpl[i];
        i += 5; /* i must provide the exact query's length */
      }
      /* send query to remote peer and wait for answer */
      i = sendquery(subfunction, glob_reqdrv, i, &answer, &ax, 0);
      if (i == 0xffffu) {
        if (subfunction == AL_FINDFIRST) {
          FAILFLAG(2); /* a failed findfirst returns error 2 (file not found) */
        } else {
          FAILFLAG(18); /* a failed findnext returns error 18 (no more files) */
        }
        break;
      } else if ((*ax != 0) || (i != 24)) {
        FAILFLAG(*ax);
        break;
      }
      /* fill in the directory entry 'found_file' (32 bytes)
       * 00h unsigned char fname[11]
       * 0Bh unsigned char fattr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 0Ch unsigned char f1[10]
       * 16h unsigned short time_lstupd
       * 18h unsigned short date_lstupd
       * 1Ah unsigned short start_clstr  *optional*
       * 1Ch unsigned long fsize
       */
      copybytes(glob_sdaptr->found_file.fname, answer+1, 11); /* found file name */
      glob_sdaptr->found_file.fattr = answer[0]; /* found file attributes */
      glob_sdaptr->found_file.time_lstupd = ((unsigned short *)answer)[6]; /* time (word) */
      glob_sdaptr->found_file.date_lstupd = ((unsigned short *)answer)[7]; /* date (word) */
      glob_sdaptr->found_file.start_clstr = 0; /* start cluster (I don't care) */
      glob_sdaptr->found_file.fsize = ((unsigned long *)answer)[4]; /* fsize (word) */

      /* put things into DTA so I can understand where I left should FindNext
       * be called - this shall be a valid FindFirst structure (21 bytes):
       * 00h unsigned char drive letter (7bits, MSB must be set for remote drives)
       * 01h unsigned char search_tmpl[11]
       * 0Ch unsigned char search_attr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 0Dh unsigned short entry_count_within_directory
       * 0Fh unsigned short cluster number of start of parent directory
       * 11h unsigned char reserved[4]
       * -- RBIL says: [DTA+15h] = standard directory entry for file
       * 15h 11-bytes (FCB-style) filename+ext ("FILE0000TXT")
       * 20h unsigned char attr. of file found (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 21h 10-bytes reserved
       * 2Bh unsigned short file time
       * 2Dh unsigned short file date
       * 2Fh unsigned short cluster
       * 31h unsigned long file size
       */
      /* init some stuff only on FindFirst (FindNext contains valid values already) */
      if (subfunction == AL_FINDFIRST) {
        dta->drv_lett = glob_reqdrv | 128; /* bit 7 set means 'network drive' */
        copybytes(dta->srch_tmpl, glob_sdaptr->fcb_fn1, 11);
        dta->srch_attr = glob_sdaptr->srch_attr;
      }
      dta->par_clstr = ((unsigned short *)answer)[10];
      dta->dir_entry = ((unsigned short *)answer)[11];
      /* then 32 bytes as in the found_file record */
      copybytes(dta + 0x15, &(glob_sdaptr->found_file), 32);
      }
      break;
    case AL_SKFMEND: /*** 21h: SKFMEND **************************************/
    {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      ((unsigned short *)buff)[0] = glob_intregs.x.dx;
      ((unsigned short *)buff)[1] = glob_intregs.x.cx;
      ((unsigned short *)buff)[2] = sftptr->start_sector;
      /* send query to remote peer and wait for answer */
      i = sendquery(AL_SKFMEND, glob_reqdrv, 6, &answer, &ax, 0);
      if (i == 0xffffu) {
        FAILFLAG(2);
      } else if ((*ax != 0) || (i != 4)) {
        FAILFLAG(*ax);
      } else { /* put new position into DX:AX */
        glob_intregs.w.ax = ((unsigned short *)answer)[0];
        glob_intregs.w.dx = ((unsigned short *)answer)[1];
      }
      break;
    }
    case AL_UNKNOWN_2D: /*** 2Dh: UNKNOWN_2D ********************************/
      /* this is only called in MS-DOS v4.01, its purpose is unknown. MSCDEX
       * returns AX=2 there, and so do I. */
      glob_intregs.w.ax = 2;
      break;
  }

  /* DEBUG */
#if DEBUGLEVEL > 0
  while ((dbg_msg != NULL) && (*dbg_msg != 0)) dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4f00 | *(dbg_msg++);
#endif
}

/**** Allocate space for the Interrupt handler stack */
static unsigned char newstack[NEWSTACKSZ];

/* this function is hooked on INT 2Fh */
void __interrupt __far inthandler(union INTPACK r) {
  /* insert a static code signature so I can reliably patch myself later,
   * this will also contain the DS segment to use and actually set it */
  _asm {
    jmp SKIPTSRSIG
    TSRSIG db 'MVet'
    SKIPTSRSIG:
    /* save AX */
    push ax
    /* set my custom DS (saved in CS:glob_newds) */
    mov ax, cs:glob_newds
    mov ds, ax
    /* save one word from the stack (might be used by SETATTR later)
     * The original stack should be at SS:BP+30 */
    mov ax, ss:[BP+30]
    mov glob_reqstkword, ax

    /* uncomment the debug code below to insert a stack's dump into snd eth
     * frame - debugging ONLY! */
    /*
    mov ax, ss:[BP]
    mov word ptr [glob_pktdrv_sndbuff+16], ax
    mov ax, ss:[BP+2]
    mov word ptr [glob_pktdrv_sndbuff+18], ax
    mov ax, ss:[BP+4]
    mov word ptr [glob_pktdrv_sndbuff+20], ax
    mov ax, ss:[BP+6]
    mov word ptr [glob_pktdrv_sndbuff+22], ax
    mov ax, ss:[BP+8]
    mov word ptr [glob_pktdrv_sndbuff+24], ax
    mov ax, ss:[BP+10]
    mov word ptr [glob_pktdrv_sndbuff+26], ax
    mov ax, ss:[BP+12]
    mov word ptr [glob_pktdrv_sndbuff+28], ax
    mov ax, ss:[BP+14]
    mov word ptr [glob_pktdrv_sndbuff+30], ax
    mov ax, ss:[BP+16]
    mov word ptr [glob_pktdrv_sndbuff+32], ax
    mov ax, ss:[BP+18]
    mov word ptr [glob_pktdrv_sndbuff+34], ax
    mov ax, ss:[BP+20]
    mov word ptr [glob_pktdrv_sndbuff+36], ax
    mov ax, ss:[BP+22]
    mov word ptr [glob_pktdrv_sndbuff+38], ax
    */
    /* restore AX */
    pop ax
  }

  /* DEBUG output (BLUE) */
#if DEBUGLEVEL > 1
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[(r.h.ah >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[r.h.ah & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[(r.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[r.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0;
#endif

  /* is it a multiplex call for me? */
  if (r.h.ah == glob_multiplexid) {
    if (r.h.al == 0) { /* install check */
      r.h.al = 0xff;    /* 'installed' */
      r.w.bx = 0x4d86;  /* MV          */
      r.w.cx = 0x7e1;   /* 2017        */
      return;
    }
    if ((r.h.al == 1) && (r.x.cx == 0x4d86)) { /* get shared data ptr (AX=0, ptr under BX:CX) */
      _asm {
        push ds
        pop glob_reqstkword
      }
      r.w.ax = 0; /* zero out AX */
      r.w.bx = glob_reqstkword; /* ptr returned at BX:CX */
      r.w.cx = FP_OFF(&glob_data);
      return;
    }
  }

  /* if not related to a redirector function (AH=11h), or the function is
   * an 'install check' (0), or the function is over our scope (2Eh), or it's
   * an otherwise unsupported function (as pointed out by supportedfunctions),
   * then call the previous INT 2F handler immediately */
  if ((r.h.ah != 0x11) || (r.h.al == AL_INSTALLCHK) || (r.h.al > 0x2E) || (supportedfunctions[r.h.al] == AL_UNKNOWN)) goto CHAINTOPREVHANDLER;

  /* DEBUG output (GREEN) */
#if DEBUGLEVEL > 0
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x2e00 | (dbg_hexc[(r.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x2e00 | (dbg_hexc[r.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0;
#endif

  /* determine whether or not the query is meant for a drive I control,
   * and if not - chain to the previous INT 2F handler */
  if (((r.h.al >= AL_CLSFIL) && (r.h.al <= AL_UNLOCKFIL)) || (r.h.al == AL_SKFMEND) || (r.h.al == AL_UNKNOWN_2D)) {
  /* ES:DI points to the SFT: if the bottom 6 bits of the device information
   * word in the SFT are > last drive, then it relates to files not associated
   * with drives, such as LAN Manager named pipes. */
    struct sftstruct far *sft = MK_FP(r.w.es, r.w.di);
    glob_reqdrv = sft->dev_info_word & 0x3F;
  } else {
    switch (r.h.al) {
      case AL_FINDNEXT:
        glob_reqdrv = glob_sdaptr->sdb.drv_lett & 0x1F;
        break;
      case AL_SETATTR:
      case AL_GETATTR:
      case AL_DELETE:
      case AL_OPEN:
      case AL_CREATE:
      case AL_SPOPNFIL:
      case AL_MKDIR:
      case AL_RMDIR:
      case AL_CHDIR:
      case AL_RENAME: /* check sda.fn1 for drive */
        glob_reqdrv = DRIVETONUM(glob_sdaptr->fn1[0]);
        break;
      default: /* otherwise check out the CDS (at ES:DI) */
        {
        struct cdsstruct far *cds = MK_FP(r.w.es, r.w.di);
        glob_reqdrv = DRIVETONUM(cds->current_path[0]);
      #if DEBUGLEVEL > 0 /* DEBUG output (ORANGE) */
        dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x6e00 | ('A' + glob_reqdrv);
        dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x6e00 | ':';
      #endif
        }
        break;
    }
  }
  /* validate drive */
  if ((glob_reqdrv > 25) || (glob_data.ldrv[glob_reqdrv] == 0xff)) {
    goto CHAINTOPREVHANDLER;
  }

  /* This should not be necessary. DOS usually generates an FCB-style name in
   * the appropriate SDA area. However, in the case of user input such as
   * 'CD ..' or 'DIR ..' it leaves the fcb area all spaces, hence the need to
   * normalize the fcb area every time. */
  if (r.h.al != AL_DISKSPACE) {
    unsigned short i;
    unsigned char far *path = glob_sdaptr->fn1;

    /* fast forward 'path' to first character of the filename */
    for (i = 0;; i++) {
      if (glob_sdaptr->fn1[i] == '\\') path = glob_sdaptr->fn1 + i + 1;
      if (glob_sdaptr->fn1[i] == 0) break;
    }

    /* clear out fcb_fn1 by filling it with spaces */
    for (i = 0; i < 11; i++) glob_sdaptr->fcb_fn1[i] = ' ';

    /* copy 'path' into fcb_name using the fcb syntax ("FILE    TXT") */
    for (i = 0; *path != 0; path++) {
      if (*path == '.') {
        i = 8;
      } else {
        glob_sdaptr->fcb_fn1[i++] = *path;
      }
    }
  }

  /* copy interrupt registers into glob_intregs so the int handler can access them without using any stack */
  copybytes(&glob_intregs, &r, sizeof(union INTPACK));
  /* set stack to my custom memory */
  _asm {
    cli /* make sure to disable interrupts, so nobody gets in the way while I'm fiddling with the stack */
    mov glob_oldstack_seg, SS
    mov glob_oldstack_off, SP
    /* set SS to DS */
    mov ax, ds
    mov ss, ax
    /* set SP to the end of the new stack (-2) */
    mov sp, offset newstack + NEWSTACKSZ - 2 
    sti
  }
  /* call the actual INT 2F processing function */
  process2f();
  /* switch stack back */
  _asm {
    cli
    mov SS, glob_oldstack_seg
    mov SP, glob_oldstack_off
    sti
  }
  /* copy all registers back so watcom will set them as required 'for real' */
  copybytes(&r, &glob_intregs, sizeof(union INTPACK));
  return;

  /* hand control to the previous INT 2F handler */
  CHAINTOPREVHANDLER:
  _mvchain_intr(MK_FP(glob_data.prev_2f_handler_seg, glob_data.prev_2f_handler_off));
}

/*********************** HERE ENDS THE RESIDENT PART ***********************/


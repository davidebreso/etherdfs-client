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

#include <i86.h>
#include <stdio.h>
#include "version.h"
#include "dosstruc.h"
#include "globals.h"

/* returns the CDS struct for drive. requires DOS 4+ */
static struct cdsstruct far *getcds(unsigned int drive) {
  /* static to preserve state: only do init once */
  static unsigned char far *dir;
  static int ok = -1;
  static unsigned char lastdrv;

  /* init if never inited yet */
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

int main(int argc, char **argv) {
  struct cdsstruct far *cds;
  int i;
  unsigned char drive_letter;
  unsigned int drive_num;

  printf("MAPDRIVE v" PVER " - Based on EtherDFS\n");

  if (argc != 2) {
    printf("Usage: mapdrive D:\n");
    printf("Maps a drive letter to a network resource.\n");
    return(1);
  }

  /* Validate argument */
  if (argv[1][1] != ':' || argv[1][2] != 0) {
    printf("Invalid drive format. Use a single letter followed by a colon (e.g., D:).\n");
    return(1);
  }

  drive_letter = argv[1][0];
  if ((drive_letter >= 'a') && (drive_letter <= 'z')) {
      drive_letter -= ('a' - 'A');
  }

  if (drive_letter < 'A' || drive_letter > 'Z') {
      printf("Invalid drive letter.\n");
      return 1;
  }

  drive_num = DRIVETONUM(drive_letter);

  /* Get the CDS for the specified drive */
  cds = getcds(drive_num);

  if (cds == NULL) {
    printf("Error: Could not get CDS for drive %c:.\n", drive_letter);
    printf("Your LASTDRIVE setting in CONFIG.SYS might be too low.\n");
    return(1);
  }

  /* Check if the drive is already in use */
  if (cds->flags != 0) {
    printf("Error: Drive %c: is already in use.\n", drive_letter);
    return(1);
  }

  /* Set the drive as a network drive */
  cds->flags = CDSFLAG_NET | CDSFLAG_PHY;
  cds->current_path[0] = drive_letter;
  cds->current_path[1] = ':';
  cds->current_path[2] = '\\';
  cds->current_path[3] = 0;

  printf("Drive %c: successfully mapped as a network drive.\n", drive_letter);

  return(0);
}

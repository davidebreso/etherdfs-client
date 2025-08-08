/*
 * This file is part of the etherdfs project.
 * http://etherdfs.sourceforge.net
 *
 * Copyright (C) 2017 Mateusz Viste
 *
 * Contains definitions of DOS structures used by etherdfs.
 */

#ifndef DOSSTRUCTS_SENTINEL
#define DOSSTRUCTS_SENTINEL


/* make sure structs are packed tightly (required since that's how DOS packs its CDS) */
#pragma pack(1)


/* CDS (current directory structure), as used by DOS 4+ */
#define CDSFLAG_SUB 0x1000u  /* SUBST drive */
#define CDSFLAG_JOI 0x2000u  /* JOINed drive */
#define CDSFLAG_PHY 0x4000u  /* Physical drive */
#define CDSFLAG_NET 0x8000u  /* Network drive */
struct cdsstruct {
  unsigned char current_path[67]; /* current path */
  unsigned short flags; /* indicates whether the drive is physical, networked, substed or joined*/
  unsigned char far *dpb; /* a pointer to the Drive Parameter Block */
  union {
    struct { /* used for local disks */
      unsigned short start_cluster;
      unsigned long unknown;
    } LOCAL;
    struct { /* used for network disks */
      unsigned long redirifs_record_ptr;
      unsigned short parameter;
    } NET;
  } u;
  unsigned short backslash_offset; /* offset in current_path of '\' (always 2, unless it's a SUBST drive) */
  /* DOS 4 and newer have 7 extra bytes here */
  unsigned char f2[7];
}; /* 88 bytes total */

#endif

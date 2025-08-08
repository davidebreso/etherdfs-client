/*
 * This file is part of the etherdfs project.
 * http://etherdfs.sourceforge.net
 *
 * Copyright (C) 2017 Mateusz Viste
 * Copyright (C) 2021 Davide Bresolin
 *
 * Contains all global variables used by etherdfs.
 */

#ifndef GLOBALS_SENTINEL
#define GLOBALS_SENTINEL

/* define NULL, for readability of the code */
#ifndef NULL
  #define NULL (void *)0
#endif

/* translates a drive letter (either upper- or lower-case) into a number (A=0,
 * B=1, C=2, etc) */
#define DRIVETONUM(x) (((x) >= 'a') && ((x) <= 'z')?x-'a':x-'A')

#endif

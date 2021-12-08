
/* allocates sz bytes of memory and returns the segment to allocated memory or
 * 0 on error. the allocation strategy is 'highest possible' (last fit) to
 * avoid memory fragmentation */
__declspec(naked) static unsigned short allocseg(unsigned short sz) {
  /* ask DOS for memory */
  _asm {
    /* set strategy to 'last fit' */
    mov ax, 5800h /* DOS 2.11+ - GET OR SET MEMORY ALLOCATION STRATEGY
                   * al = 0 means 'get allocation strategy' */
    int 21h       /* now current strategy is in ax */
    push ax       /* push current strategy to stack */
    mov ax, 5801h /* al = 1 means 'set allocation strategy' */
    mov bl, 2     /* 2 or greater means 'last fit' */
    int 21h
    /* do the allocation now */
    mov ah, 48h   /* DOS 2+ - ALLOCATE MEMORY */
    mov bx, dx    /* number of paragraphs to allocate */
    /* bx should contains number of 16-byte paragraphs instead of bytes */
    add bx, 15    /* make sure to allocate enough paragraphs */
    mov cl, 4     /* convert bytes to number of 16-bytes paragraphs  */
    shr bx, cl    /* the 8086/8088 CPU supports only a 1-bit version
                   * of SHR so I use the reg,CL method               */
    mov dx, 0     /* pre-set res to failure (0) */
    int 21h       /* returns allocated segment in AX */
    /* check CF */
    jc failed
    mov dx, ax    /* set res to actual result */
    failed:
    /* set strategy back to its initial setting */
    mov ax, 5801h
    pop bx        /* pop current strategy from stack */ 
    int 21h
    ret
  }
}
#pragma aux allocseg parm [dx] value [dx] modify exact [ax bx cl dx] nomemory;

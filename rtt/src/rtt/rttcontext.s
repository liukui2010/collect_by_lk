
/*
 * int
 * savecontext(f, savearea, sp)
 * void (*f)();
 * void *savearea;
 * void *sp;
 *
 * If F == 0, save enough of the current state in SAVEAREA so that
 * control can later be returned to the caller of the function calling
 * savecontext().  Savecontext() behaves like setjmp(3) in that 0 is
 * returned when the context is saved but a non-zero value is returned
 * when returnto() resumes execution of the saved context.
 *
 * If F != 0, switch to the stack pointed to by SP and call F.  There is
 * no return from F.
 *
 * void
 * returnto(savearea)
 * void *savearea;
 *
 * Restore the state previously stored in SAVEAREA and continue execution
 * based on that saved state.  This resumes a suspended thread, making
 * it look like a call to savecontext() with F == 0 is now returning.
 *
 * bjb/mwg Dec/89 and Jul/90
 */
/********************************************


note: unless the predecrement addressing mode is used, the register mask can
be interpreted as follows:

------------------------------------------------------------------------------
Mask:  MostSigBit  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0  LeastSigBit
Register:          a7 a6 a5 a4 a3 a2 a1 a0 d7 d6 d5 d4 d3 d2 d1 d0
------------------------------------------------------------------------------

 if the predecrement addressing mode is used, the mask becomes:
------------------------------------------------------------------------------
Mask:  MostSigBit  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0  LeastSigBit
Register:          d0 d1 d2 d3 d4 d5 d6 d7 a0 a1 a2 a3 a4 a5 a6 a7

*********************************************/

#ifdef sun3
.text
.globl _saveThreadContext

_saveThreadContext:
	movl	sp@(0x4), a0		/* get save area (1st param) */
        movl    sp@, a0@                /* save ret address, it gets trashed*/
	moveml	#0xfefe, a0@(4)		/* save regs to save area    */
					/* this includes a6 (frame pointer) */
					/* and a7 (stack pointer)    */
        moveq   #17, d0
	rts


.text
.globl _startNewThread

_startNewThread:
        movl    sp@(0x4), a0            /* get function addr from stack   */
        movl    sp@(0x8), sp            /* set stack pointer to new stack */
        jmp     a0@


.text
.globl _returnToThread

_returnToThread:
	movl	sp@(0x4), a0		/* get save area (only param) */
	moveml	a0@(4), #0xfefe    	/* this restores the regs     */
        movl    a0@, sp@
        moveq   #0, d0
        rts

#endif /* sun3 */




#if defined(sun4) || defined(sun4sol)
#ifdef sun4
#include    <sun4/asm_linkage.h>
#include    <sun4/trap.h>
#endif

#ifdef sun4sol
#define _ASM
#include <sys/trap.h>
#include <sys/stack.h>

#endif
	
topstack =  0
globals  = 12

.text
#ifdef sun4
.global _saveThreadContext
_saveThreadContext:
#else
.global saveThreadContext
saveThreadContext:
#endif
    st  %g1, [%o0 + globals +  0]        ! Save all globals just in case
    st  %g2, [%o0 + globals +  4]
    st  %g3, [%o0 + globals +  8]
    st  %g4, [%o0 + globals + 12]
    st  %g5, [%o0 + globals + 16]
    st  %g6, [%o0 + globals + 20]
    st  %g7, [%o0 + globals + 24]
    mov %y, %g1
    st  %g1, [%o0 + globals + 28]

    st  %sp, [%o0 + topstack + 0]
    st  %o7, [%o0 + topstack + 4]

    jmp  %o7 + 0x8
    add %g0, 17, %o0

.text
#ifdef sun4
.global _startNewThread
_startNewThread:
#else
.global startNewThread
startNewThread:
#endif
    ta  ST_FLUSH_WINDOWS                ! Flush all other active windows

    add  %o1, STACK_ALIGN - 1, %o1      ! SPARC requires stricter alignment
    and  %o1, ~(STACK_ALIGN - 1), %o1   ! than malloc gives so force alignment
    sub  %o1, SA(MINFRAME), %fp
    sub  %fp, SA(MINFRAME), %sp

    jmpl %o0, %g0
    nop

.text
#ifdef sun4	
.globl _returnToThread
_returnToThread:
#else
.globl returnToThread
returnToThread:
#endif
    ta  ST_FLUSH_WINDOWS                ! Flush all other active windows

    ld  [%o0 + globals + 28], %g1       ! Restore global regs
    mov %g1, %y
    ld  [%o0 + globals +  0], %g1
    ld  [%o0 + globals +  4], %g2
    ld  [%o0 + globals +  8], %g3
    ld  [%o0 + globals + 12], %g4
    ld  [%o0 + globals + 16], %g5
    ld  [%o0 + globals + 20], %g6
    ld  [%o0 + globals + 24], %g7

    ld  [%o0 + topstack + 0], %fp
    sub %fp, SA(MINFRAME), %sp
    ld  [%o0 + topstack + 4], %o7

    clr  %o0
    retl
    restore %o0, 0x0, %o0

#endif /* sun4 */

#ifdef hp700

	.CODE
	.SUBSPA $CODE$
	.EXPORT saveThreadContext,ENTRY
	.PROC
	.CALLINFO
saveThreadContext .ENTER
	STWM    %rp, 4(%arg0)         /* store return address */
	STWM    3, 4(%arg0)           /* store general purpose registers */
	STWM    4, 4(%arg0)
	STWM    5, 4(%arg0)
	STWM    6, 4(%arg0)
	STWM    7, 4(%arg0)
	STWM    8, 4(%arg0)
	STWM    9, 4(%arg0)
	STWM    10, 4(%arg0)
	STWM    11, 4(%arg0)
	STWM    12, 4(%arg0)
	STWM    13, 4(%arg0)
	STWM    14, 4(%arg0)
	STWM    15, 4(%arg0)
	STWM    16, 4(%arg0)
	STWM    17, 4(%arg0)
	STWM    18, 4(%arg0)
	STWM    19, 4(%arg0)
	STWM    20, 4(%arg0)
	STWM    21, 4(%arg0)
	STWM    22, 4(%arg0)
	STWM    %sl, 4(%arg0)       /* store static link (necessray?) */
	STWM    %sp, 4(%arg0)       /* store stack pointer            */

	LDIL	17,%ret0            /* return the perfect number      */
	.LEAVE
	.PROCEND


	.EXPORT startNewThread,ENTRY
	.PROC
	.CALLINFO
startNewThread  .ENTER
	LDIL    0, 3         /* clear register 3                   */
	LDH     0(%arg0), 3  /* dereference value supplied as addr */

	BV	0(3)         /* branch to that location    
			      * - note: this is peculiar to cc on hpux. gcc on
			      * this architecture (and others I've seen) pass
			      * the address directly rather than a reference to
			      * where it is located!
			      */

	COPY	%arg1,%sp    /* set stack pointer to new stack */
	.LEAVE 
	.PROCEND


	.EXPORT returnToThread,ENTRY
	.PROC
	.CALLINFO
returnToThread .ENTER
	LDWM    4(%arg0), %rp         /* load return address */
	LDWM    4(%arg0), 3           /* load general purpose registers */
	LDWM    4(%arg0), 4
	LDWM    4(%arg0), 5
	LDWM    4(%arg0), 6
	LDWM    4(%arg0), 7
	LDWM    4(%arg0), 8
	LDWM    4(%arg0), 9
	LDWM    4(%arg0), 10
	LDWM    4(%arg0), 11
	LDWM    4(%arg0), 12
	LDWM    4(%arg0), 13
	LDWM    4(%arg0), 14
	LDWM    4(%arg0), 15
	LDWM    4(%arg0), 16
	LDWM    4(%arg0), 17
	LDWM    4(%arg0), 18
	LDWM    4(%arg0), 19
	LDWM    4(%arg0), 20
	LDWM    4(%arg0), 21
	LDWM    4(%arg0), 22
	LDWM    4(%arg0), %sl       /* load static link (necessray?) */
	LDWM    4(%arg0), %sp       /* load stack pointer            */
	LDIL	0, %ret0            /* return zero */
	.LEAVE
	.PROCEND
        .END
#endif /* hp700 */


#ifdef mips
/* mips stuff has yet to be tested */

.text
.globl saveThreadContext
.ent saveThreadContext

saveThreadContext:
        sw      $16,  0($4)             /* save regs to save area */
        sw      $17,  4($4)
        sw      $18,  8($4)
        sw      $19, 12($4)
        sw      $20, 16($4)
        sw      $21, 20($4)
        sw      $22, 24($4)
        sw      $23, 28($4)
        sw      $fp, 32($4)
        sw      $sp, 36($4)
        sw      $31, 40($4)
        /* Don't know if gp needs to be saved... */

        li      $2, 17
        j       $31
.end saveThreadContext

.text
.globl startNewThread
.ent startNewThread
startNewThread:
        addu    $sp, $0, $5             /* set stack pointer to new stack */
        j       $4
.end startNewThread


.text
.globl returnToThread
.ent returnToThread

returnToThread:
        lw      $16,  0($4)
        lw      $17,  4($4)
        lw      $18,  8($4)
        lw      $19, 12($4)
        lw      $20, 16($4)
        lw      $21, 20($4)
        lw      $22, 24($4)
        lw      $23, 28($4)
        lw      $fp, 32($4)
        lw      $sp, 36($4)

        lw      $31, 40($4)
        li      $2, 0
        j       $31
.end returnToThread

#endif /* mips */


#ifdef ibm

/* RS6000 */
.align 2
.extern .saveThreadContext
.globl .saveThreadContext
.csect [PR]

.saveThreadContext:
	mflr	0
	st	0, 0(3)		/* save link */
	st	1, 4(3)		/* save sp */
	stm	13, 8(3)	/* save regs to save area */

	lil	3, 17
	br

.align 2
.extern .startNewThread
.globl .startNewThread
.csect [PR]

.startNewThread:

/*
  We need to create a link area for this procedure.  This is because
  the function we call is allowed to write into our link area to save
  the CR and LR.  The link area also includes space reserved for the
  compiler and for saving the TOC.  It's currently 6 words (24 bytes)
  long; this code will need to be changed if the value changes.

  The POWER architecture specifies that the stack pointer must be
  quad-word aligned (16 bytes), so we take the next multiple up from
  24 as the space we need to reserve.  This assumes that the sp passed
  in is already quad-word aligned.
*/

	.set	linkarea, 32
	ai	1, 4, -linkarea
	l	0, 0(3)
	mtlr	0
	brl



.align 2
.extern .returnToThread
.globl .returnToThread
.csect [PR]

.returnToThread:
	lm	13, 8(3)
	l	1, 4(3)
	l	0, 0(3)
	mtlr	0
	lil	3, 0

	br

.align 2
.extern .stackPointer
.globl .stackPointer
.csect [PR]

.set SP,1; .set BO_ALWAYS,20; .set r0,0; .set r3,3; .set CR0_LT,0

.stackPointer:
	stu	SP,-64(SP)
	l	r3,0(SP)
	st	r3,56(SP)
	ai	SP,SP,64
	bcr	BO_ALWAYS,CR0_LT


#endif

#if defined(i386) || defined(i486) || defined(i686)

#ifdef i86pc
.globl saveThreadContext
.align 4

saveThreadContext:
#else
.globl saveThreadContext
.align 4

saveThreadContext:
#endif /* i86pc */
	mov %ebx, %eax      /* first thing we do is save EBX into EAX       */
	mov 4(%esp), %ebx   /* now we get the save area into EBX            */	
	mov %eax, 32(%ebx)  /* get old value of EBX from EAX into save area */
	mov (%esp), %eax    /* now we get the return address into save area */
	mov %eax, (%ebx)
	mov %edi, 4(%ebx)   /* save registers in save area */
	mov %esi, 8(%ebx)
	mov %edx, 16(%ebx)
	mov %ecx, 20(%ebx)
	mov %ebp, 24(%ebx)
	mov %esp, 28(%ebx)
	mov %eax, %ebx      /* restore EBX */
	mov $11, %eax       /* return value of 17 (decimal) :) */
	ret

#ifdef i86pc
.globl startNewThread
.align 4

startNewThread:
#else
.globl startNewThread
.align 4

startNewThread:
#endif /* i86pc */
	mov 4(%esp),%eax    /* we get the function pointer from the stack */
	mov 8(%esp),%esp    /* restore the stack pointer for the new thread */
	jmp *%eax
	

#ifdef i86pc
.globl returnToThread
.align 4

returnToThread:
#else
.globl returnToThread
.align 4

returnToThread:
#endif /* i86pc */
	mov 4(%esp), %ebx    /* get the save area pointer into EBX */
	mov 4(%ebx), %edi   /* restore registers from save area */
	mov 8(%ebx), %esi
	mov 16(%ebx), %edx
	mov 20(%ebx), %ecx
	mov 24(%ebx), %ebp
	mov 28(%ebx), %esp
	mov (%ebx), %eax   /* restore the return address */
	mov %eax,(%esp)
	mov 32(%ebx), %eax  /* get old value of EBX from EAX into save area */
	mov %eax, %ebx      /* restore EBX */
	mov $0, %eax        /* return value of zero */
        ret

#endif /* i386 || i486  || i686 */


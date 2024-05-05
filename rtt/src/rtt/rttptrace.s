.set r0,0; .set SP,1; .set RTOC,2; .set r3,3; .set r4,4
.set r5,5; .set r6,6; .set r7,7; .set r8,8; .set r9,9
.set r10,10; .set r11,11; .set r12,12; .set r13,13; .set r14,14
.set r15,15; .set r16,16; .set r17,17; .set r18,18; .set r19,19
.set r20,20; .set r21,21; .set r22,22; .set r23,23; .set r24,24
.set r25,25; .set r26,26; .set r27,27; .set r28,28; .set r29,29
.set r30,30; .set r31,31
.set fp0,0; .set fp1,1; .set fp2,2; .set fp3,3; .set fp4,4
.set fp5,5; .set fp6,6; .set fp7,7; .set fp8,8; .set fp9,9
.set fp10,10; .set fp11,11; .set fp12,12; .set fp13,13; .set fp14,14
.set fp15,15; .set fp16,16; .set fp17,17; .set fp18,18; .set fp19,19
.set fp20,20; .set fp21,21; .set fp22,22; .set fp23,23; .set fp24,24
.set fp25,25; .set fp26,26; .set fp27,27; .set fp28,28; .set fp29,29
.set fp30,30; .set fp31,31
.set MQ,0; .set XER,1; .set FROM_RTCU,4; .set FROM_RTCL,5; .set FROM_DEC,6
.set LR,8; .set CTR,9; .set TID,17; .set DSISR,18; .set DAR,19; .set TO_RTCU,20
.set TO_RTCL,21; .set TO_DEC,22; .set SDR_0,24; .set SDR_1,25; .set SRR_0,26
.set SRR_1,27
.set BO_dCTR_NZERO_AND_NOT,0; .set BO_dCTR_NZERO_AND_NOT_1,1
.set BO_dCTR_ZERO_AND_NOT,2; .set BO_dCTR_ZERO_AND_NOT_1,3
.set BO_IF_NOT,4; .set BO_IF_NOT_1,5; .set BO_IF_NOT_2,6
.set BO_IF_NOT_3,7; .set BO_dCTR_NZERO_AND,8; .set BO_dCTR_NZERO_AND_1,9
.set BO_dCTR_ZERO_AND,10; .set BO_dCTR_ZERO_AND_1,11; .set BO_IF,12
.set BO_IF_1,13; .set BO_IF_2,14; .set BO_IF_3,15; .set BO_dCTR_NZERO,16
.set BO_dCTR_NZERO_1,17; .set BO_dCTR_ZERO,18; .set BO_dCTR_ZERO_1,19
.set BO_ALWAYS,20; .set BO_ALWAYS_1,21; .set BO_ALWAYS_2,22
.set BO_ALWAYS_3,23; .set BO_dCTR_NZERO_8,24; .set BO_dCTR_NZERO_9,25
.set BO_dCTR_ZERO_8,26; .set BO_dCTR_ZERO_9,27; .set BO_ALWAYS_8,28
.set BO_ALWAYS_9,29; .set BO_ALWAYS_10,30; .set BO_ALWAYS_11,31
.set CR0_LT,0; .set CR0_GT,1; .set CR0_EQ,2; .set CR0_SO,3
.set CR1_FX,4; .set CR1_FEX,5; .set CR1_VX,6; .set CR1_OX,7
.set CR2_LT,8; .set CR2_GT,9; .set CR2_EQ,10; .set CR2_SO,11
.set CR3_LT,12; .set CR3_GT,13; .set CR3_EQ,14; .set CR3_SO,15
.set CR4_LT,16; .set CR4_GT,17; .set CR4_EQ,18; .set CR4_SO,19
.set CR5_LT,20; .set CR5_GT,21; .set CR5_EQ,22; .set CR5_SO,23
.set CR6_LT,24; .set CR6_GT,25; .set CR6_EQ,26; .set CR6_SO,27
.set CR7_LT,28; .set CR7_GT,29; .set CR7_EQ,30; .set CR7_SO,31
.set TO_LT,16; .set TO_GT,8; .set TO_EQ,4; .set TO_LLT,2; .set TO_LGT,1

	.rename	H.314.NO_SYMBOL{PR},""
	.rename	H.355.NO_SYMBOL{TC},""
	.rename	H.357.NO_SYMBOL{RO},""
	.rename	E.361._ptrace_c_{RW},"_ptrace$c$"
	.rename	H.366._ptrace_c_{TC},"_ptrace$c$"
	.rename	E.368._ptrace_c_,"_ptrace@c@"
	.rename	H.373._ptrace_c_{TC},"_ptrace@c@"
	.rename	H.377.PTraceInit_{TC},"PTraceInit_"
	.rename	H.382.traceFD_{TC},"traceFD_"
	.rename	H.386.errno{TC},"errno"
	.rename	H.390._iob{TC},"_iob"
	.rename	H.395.PtraceBasePtr{TC},"PtraceBasePtr"
	.rename	H.400.PtraceEndPtr{TC},"PtraceEndPtr"
	.rename	H.405.PtraceCurPtr{TC},"PtraceCurPtr"
	.rename	H.409.PTraceSync_{TC},"PTraceSync_"
	.rename	H.413.PTraceEnd_{TC},"PTraceEnd_"
	.rename	H.417.stackCheck{TC},"stackCheck"

	.lglobl	H.314.NO_SYMBOL{PR}     
	.globl	.PTraceInit_            
	.globl	.PTraceSync_            
	.globl	.PTraceEnd_             
	.globl	.stackCheck             
	.lglobl	H.357.NO_SYMBOL{RO}     
	.lglobl	E.361._ptrace_c_{RW}    
	.lglobl	E.368._ptrace_c_{RW}    
	.globl	PTraceInit_{DS}         
	.globl	traceFD_{RW}            
	.extern	errno{UA}               
	.extern	_iob{UA}                
	.globl	PtraceBasePtr{RW}       
	.globl	PtraceEndPtr{RW}        
	.globl	PtraceCurPtr{RW}        
	.globl	PTraceSync_{DS}         
	.globl	PTraceEnd_{DS}          
	.globl	stackCheck{DS}          
	.extern	.getpid{PR}             
	.extern	.sprintf{PR}            
	.extern	.open{PR}               
	.extern	.printf{PR}             
	.extern	.RttBeginCritical{PR}   
	.extern	.fflush{PR}             
	.extern	.exit{PR}               
	.extern	.shmat{PR}              
	.extern	.fprintf{PR}            
	.extern	.fsync{PR}              
	.extern	.RttEndCritical{PR}     
	.extern	.close{PR}              


# .text section


	.csect	H.314.NO_SYMBOL{PR}     
	.function	.PTraceInit_{PR},.PTraceInit_,2,0
.PTraceInit_:                           # 0x00000000 (H.314.NO_SYMBOL)
	.file	"ptrace.c"              
	mfspr	r0,LR
	stm	r29,-12(SP)
	st	r0,8(SP)
	stu	SP,-80(SP)
	l	r31,T.366._ptrace_c_(RTOC)
	l	r30,T.355.NO_SYMBOL(RTOC)
	st	r3,104(SP)
	.bf	33
	.line	1
	bl	.getpid{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	st	r3,56(SP)
	.line	3
	l	r29,T.373._ptrace_c_(RTOC)
	cal	r3,0(r29)
	l	r5,0(r31)
	l	r6,56(SP)
	ai	r4,r30,12
	bl	.sprintf{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r3,0(r29)
	.line	5
	cal	r4,8962(r0)
	cal	r5,436(r0)
	bl	.open{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r4,0(r3)
	l	r3,T.382.traceFD_(RTOC)
	st	r4,0(r3)
	.line	9
	l	r3,0(r3)
	cmpi	1,r3,0
	bc	BO_IF_NOT,CR1_FX,__Lb0
	.line	11
	l	r4,T.373._ptrace_c_(RTOC)
	l	r3,T.386.errno(RTOC)
	l	r5,0(r3)
	ai	r3,r30,18
	bl	.printf{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	12
	bl	.PTraceEnd_
	bl	.RttBeginCritical{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	l	r3,T.390._iob(RTOC)
	ai	r3,r3,32
	bl	.fflush{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r3,1(r0)
	bl	.exit{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
__Lb0:                                  # 0x000000b0 (H.314.NO_SYMBOL+0xb0)
	.line	14
	l	r3,T.382.traceFD_(RTOC)
	l	r3,0(r3)
	cal	r4,0(r0)
	cal	r5,2048(r0)
	bl	.shmat{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r4,0(r3)
	l	r3,T.395.PtraceBasePtr(RTOC)
	st	r4,0(r3)
	.line	15
	l	r3,0(r3)
	cmpi	1,r3,-1
	bc	BO_IF_NOT,CR1_VX,__L11c
	.line	17
	l	r3,T.386.errno(RTOC)
	l	r4,0(r3)
	ai	r3,r30,58
	bl	.printf{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	18
	bl	.PTraceEnd_
	bl	.RttBeginCritical{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	l	r3,T.390._iob(RTOC)
	ai	r3,r3,32
	bl	.fflush{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r3,1(r0)
	bl	.exit{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
__L11c:                                 # 0x0000011c (H.314.NO_SYMBOL+0x11c)
	.line	20
	l	r5,T.400.PtraceEndPtr(RTOC)
	l	r3,T.395.PtraceBasePtr(RTOC)
	l	r4,0(r3)
	cau	r4,r4,0x0010
	st	r4,0(r5)
	.line	21
	l	r4,T.405.PtraceCurPtr(RTOC)
	l	r3,0(r3)
	st	r3,0(r4)
	.line	22
	l	r29,T.390._iob(RTOC)
	ai	r3,r29,64
	l	r5,T.373._ptrace_c_(RTOC)
	ai	r4,r30,104
	bl	.fprintf{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	cal	r3,0(r29)
	.line	23
	ai	r3,r3,64
	bl	.fflush{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	24
	l	r0,88(SP)
	mtspr	LR,r0
	ai	SP,SP,80
	lm	r29,-12(SP)
	bcr	BO_ALWAYS,CR0_LT
	.ef	56
# traceback table
	.long	0x00000000
	.byte	0x00			# VERSION=0
	.byte	0x00			# LANG=TB_C
	.byte	0x20			# IS_GL=0,IS_EPROL=0,HAS_TBOFF=1
					# INT_PROC=0,HAS_CTL=0,TOCLESS=0
					# FP_PRESENT=0,LOG_ABORT=0
	.byte	0x41			# INT_HNDL=0,NAME_PRESENT=1
					# USES_ALLOCA=0,CL_DIS_INV=WALK_ONCOND
					# SAVES_CR=0,SAVES_LR=1
	.byte	0x80			# STORES_BC=1,FPR_SAVED=0
	.byte	0x03			# GPR_SAVED=3
	.byte	0x01			# FIXEDPARMS=1
	.byte	0x01			# FLOATPARMS=0,PARMSONSTK=1
	.long	0x00000000		# 
	.long	0x00000178		# TB_OFFSET
	.short	11			# NAME_LEN
	.byte	"PTraceInit_"
	.byte	0			# padding
	.byte	0			# padding
	.byte	0			# padding
# End of traceback table
	.function	.PTraceSync_{PR},.PTraceSync_,2,0
.PTraceSync_:                           # 0x0000019c (H.314.NO_SYMBOL+0x19c)
	mfspr	r0,LR
	stu	SP,-64(SP)
	st	r0,72(SP)
	.bf	60
	.line	1
	bl	.RttBeginCritical{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	2
	l	r3,T.382.traceFD_(RTOC)
	l	r3,0(r3)
	bl	.fsync{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	3
	bl	.RttEndCritical{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	4
	l	r0,72(SP)
	mtspr	LR,r0
	ai	SP,SP,64
	bcr	BO_ALWAYS,CR0_LT
	.ef	63
# traceback table
	.long	0x00000000
	.byte	0x00			# VERSION=0
	.byte	0x00			# LANG=TB_C
	.byte	0x20			# IS_GL=0,IS_EPROL=0,HAS_TBOFF=1
					# INT_PROC=0,HAS_CTL=0,TOCLESS=0
					# FP_PRESENT=0,LOG_ABORT=0
	.byte	0x41			# INT_HNDL=0,NAME_PRESENT=1
					# USES_ALLOCA=0,CL_DIS_INV=WALK_ONCOND
					# SAVES_CR=0,SAVES_LR=1
	.byte	0x80			# STORES_BC=1,FPR_SAVED=0
	.byte	0x00			# GPR_SAVED=0
	.byte	0x00			# FIXEDPARMS=0
	.byte	0x01			# FLOATPARMS=0,PARMSONSTK=1
	.long	0x0000003c		# TB_OFFSET
	.short	11			# NAME_LEN
	.byte	"PTraceSync_"
	.byte	0			# padding
	.byte	0			# padding
	.byte	0			# padding
# End of traceback table
	.function	.PTraceEnd_{PR},.PTraceEnd_,2,0
.PTraceEnd_:                            # 0x000001f8 (H.314.NO_SYMBOL+0x1f8)
	mfspr	r0,LR
	stu	SP,-64(SP)
	st	r0,72(SP)
	.bf	67
	.line	1
	bl	.PTraceSync_
	.line	2
	l	r3,T.382.traceFD_(RTOC)
	l	r3,0(r3)
	bl	.close{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	3
	l	r0,72(SP)
	mtspr	LR,r0
	ai	SP,SP,64
	bcr	BO_ALWAYS,CR0_LT
	.ef	69
# traceback table
	.long	0x00000000
	.byte	0x00			# VERSION=0
	.byte	0x00			# LANG=TB_C
	.byte	0x20			# IS_GL=0,IS_EPROL=0,HAS_TBOFF=1
					# INT_PROC=0,HAS_CTL=0,TOCLESS=0
					# FP_PRESENT=0,LOG_ABORT=0
	.byte	0x41			# INT_HNDL=0,NAME_PRESENT=1
					# USES_ALLOCA=0,CL_DIS_INV=WALK_ONCOND
					# SAVES_CR=0,SAVES_LR=1
	.byte	0x80			# STORES_BC=1,FPR_SAVED=0
	.byte	0x00			# GPR_SAVED=0
	.byte	0x00			# FIXEDPARMS=0
	.byte	0x01			# FLOATPARMS=0,PARMSONSTK=1
	.long	0x00000030		# TB_OFFSET
	.short	10			# NAME_LEN
	.byte	"PTraceEnd_"
# End of traceback table
	.function	.stackCheck{PR},.stackCheck,2,0
.stackCheck:                            # 0x00000244 (H.314.NO_SYMBOL+0x244)
	mfspr	r0,LR
	st	r31,-4(SP)
	st	r0,8(SP)
	stu	SP,-80(SP)
	l	r31,T.355.NO_SYMBOL(RTOC)
	st	r3,104(SP)
	st	r4,108(SP)
	.bf	73
	.line	1
	cal	r3,0(r0)
	st	r3,56(SP)
	.line	2
	l	r3,108(SP)
	l	r4,104(SP)
	cmpl	1,1,3
	bc	BO_IF_NOT,CR1_FX,__L29c
	.line	4
	bl	.RttBeginCritical{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	5
	ai	r3,r31,128
	bl	.printf{PR}
	cror	CR3_SO,CR3_SO,CR3_SO
	.line	6
	l	r4,56(SP)
	cau	r3,r0,0x0001
	ai	r3,r3,-8531
	st	r3,0(r4)
__L29c:                                 # 0x0000029c (H.314.NO_SYMBOL+0x29c)
	.line	8
	l	r31,76(SP)
	l	r0,88(SP)
	mtspr	LR,r0
	ai	SP,SP,80
	bcr	BO_ALWAYS,CR0_LT
	.ef	80
# traceback table
	.long	0x00000000
	.byte	0x00			# VERSION=0
	.byte	0x00			# LANG=TB_C
	.byte	0x20			# IS_GL=0,IS_EPROL=0,HAS_TBOFF=1
					# INT_PROC=0,HAS_CTL=0,TOCLESS=0
					# FP_PRESENT=0,LOG_ABORT=0
	.byte	0x41			# INT_HNDL=0,NAME_PRESENT=1
					# USES_ALLOCA=0,CL_DIS_INV=WALK_ONCOND
					# SAVES_CR=0,SAVES_LR=1
	.byte	0x80			# STORES_BC=1,FPR_SAVED=0
	.byte	0x01			# GPR_SAVED=1
	.byte	0x02			# FIXEDPARMS=2
	.byte	0x01			# FLOATPARMS=0,PARMSONSTK=1
	.long	0x00000000		# 
	.long	0x0000006c		# TB_OFFSET
	.short	10			# NAME_LEN
	.byte	"stackCheck"
# End of traceback table
# End	csect	H.314.NO_SYMBOL{PR}

# .data section


	.toc	                        # 0x000002d0 
T.377.PTraceInit_:
	.tc	H.377.PTraceInit_{TC},PTraceInit_{DS}
T.366._ptrace_c_:
	.tc	H.366._ptrace_c_{TC},E.361._ptrace_c_{RW}
T.355.NO_SYMBOL:
	.tc	H.355.NO_SYMBOL{TC},H.357.NO_SYMBOL{RO}
T.373._ptrace_c_:
	.tc	H.373._ptrace_c_{TC},E.368._ptrace_c_
T.382.traceFD_:
	.tc	H.382.traceFD_{TC},traceFD_
T.386.errno:
	.tc	H.386.errno{TC},errno{UA}
T.390._iob:
	.tc	H.390._iob{TC},_iob{UA} 
T.395.PtraceBasePtr:
	.tc	H.395.PtraceBasePtr{TC},PtraceBasePtr
T.400.PtraceEndPtr:
	.tc	H.400.PtraceEndPtr{TC},PtraceEndPtr
T.405.PtraceCurPtr:
	.tc	H.405.PtraceCurPtr{TC},PtraceCurPtr
T.409.PTraceSync_:
	.tc	H.409.PTraceSync_{TC},PTraceSync_{DS}
T.413.PTraceEnd_:
	.tc	H.413.PTraceEnd_{TC},PTraceEnd_{DS}
T.417.stackCheck:
	.tc	H.417.stackCheck{TC},stackCheck{DS}


	.csect	PTraceInit_{DS}         
	.long	.PTraceInit_            # "\0\0\0\0"
	.long	TOC{TC0}                # "\0\0\002\320"
	.long	0x00000000              # "\0\0\0\0"
# End	csect	PTraceInit_{DS}


	.csect	PTraceSync_{DS}         
	.long	.PTraceSync_            # "\0\0\001\234"
	.long	TOC{TC0}                # "\0\0\002\320"
	.long	0x00000000              # "\0\0\0\0"
# End	csect	PTraceSync_{DS}


	.csect	PTraceEnd_{DS}          
	.long	.PTraceEnd_             # "\0\0\001\370"
	.long	TOC{TC0}                # "\0\0\002\320"
	.long	0x00000000              # "\0\0\0\0"
# End	csect	PTraceEnd_{DS}


	.csect	stackCheck{DS}          
	.long	.stackCheck             # "\0\0\002D"
	.long	TOC{TC0}                # "\0\0\002\320"
	.long	0x00000000              # "\0\0\0\0"
# End	csect	stackCheck{DS}


	.csect	E.361._ptrace_c_{RW}, 3 
	.long	H.357.NO_SYMBOL{RO}     # "\0\0\0038"
# End	csect	E.361._ptrace_c_{RW}


	.csect	H.357.NO_SYMBOL{RO}, 3  
	.long	0x2f746d70              # "/tmp"
	.long	0x2f707472              # "/ptr"
	.long	0x61636500              # "ace\0"
	.long	0x25732e25              # "%s.%"
	.long	0x64004361              # "d\0Ca"
	.long	0x6e277420              # "n't "
	.long	0x6f70656e              # "open"
	.long	0x20747261              # " tra"
	.long	0x63652066              # "ce f"
	.long	0x696c6520              # "ile "
	.long	0x25732c20              # "%s, "
	.long	0x6572726e              # "errn"
	.long	0x6f207761              # "o wa"
	.long	0x73202564              # "s %d"
	.long	0x0a004361              # "\n\0Ca"
	.long	0x6e277420              # "n't "
	.long	0x6d617020              # "map "
	.long	0x74726163              # "trac"
	.long	0x65206669              # "e fi"
	.long	0x6c652074              # "le t"
	.long	0x6f206d65              # "o me"
	.long	0x6d6f7279              # "mory"
	.long	0x2c206572              # ", er"
	.long	0x726f7220              # "ror "
	.long	0x77617320              # "was "
	.long	0x25640a00              # "%d\n\0"
	.long	0x50545241              # "PTRA"
	.long	0x43453a20              # "CE: "
	.long	0x20547261              # " Tra"
	.long	0x63652066              # "ce f"
	.long	0x696c6520              # "ile "
	.long	0x25730a00              # "%s\n\0"
	.long	0x42616420              # "Bad "
	.long	0x7468696e              # "thin"
	.long	0x67732c20              # "gs, "
	.long	0x70616c2e              # "pal."
# End	csect	H.357.NO_SYMBOL{RO}
	.long	0x0a000000              # "\n\0\0\0"



# .bss section
	.lcomm	L.E.368._ptrace_c_, 256, E.368._ptrace_c_
	.comm	traceFD_, 4, 3          # 0x000004cc 
	.comm	PtraceBasePtr, 4, 3     # 0x000004d0 
	.comm	PtraceEndPtr, 4, 3      # 0x000004d4 
	.comm	PtraceCurPtr, 4, 3      # 0x000004d8 

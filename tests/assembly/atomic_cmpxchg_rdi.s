	.file	"temp.c"
	.text
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"%d\n"
	.text
	.globl	addValue
	.type	addValue, @function
addValue:
.LFB13:
	.cfi_startproc
	endbr64
	movq	globalValue@GOTPCREL(%rip), %rdx
	xorl	%eax, %eax
	lock cmpxchgl	%edi, (%rdx)
	leaq	.LC0(%rip), %rsi
	movl	$1, %edi
	xorl	%eax, %eax
	movl	(%rdx), %edx
	jmp	__printf_chk@PLT
	.cfi_endproc
.LFE13:
	.size	addValue, .-addValue
	.section	.text.startup,"ax",@progbits
	.globl	main
	.type	main, @function
main:
.LFB14:
	.cfi_startproc
	endbr64
	pushq	%rax
	.cfi_def_cfa_offset 16
	movl	$5, %edi
	call	addValue@PLT
	xorl	%eax, %eax
	popq	%rdx
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE14:
	.size	main, .-main
	.globl	globalValue
	.bss
	.align 4
	.type	globalValue, @object
	.size	globalValue, 4
globalValue:
	.zero	4
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 8
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 8
4:

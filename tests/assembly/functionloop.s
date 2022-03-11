	.text
	.file	"functionloop.cpp"
	.globl	_Z12functionLoopi       # -- Begin function _Z12functionLoopi
	.p2align	4, 0x90
	.type	_Z12functionLoopi,@function
_Z12functionLoopi:                      # @_Z12functionLoopi
	.cfi_startproc
# %bb.0:
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	.p2align	4, 0x90
.LBB0_2:                                # =>This Inner Loop Header: Depth=1
	addl	$-1, %edi
	cmpl	$1, %edi
	jg	.LBB0_2
.LBB0_3:
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end0:
	.size	_Z12functionLoopi, .Lfunc_end0-_Z12functionLoopi
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	pushq	%rax
	.cfi_def_cfa_offset 16
	movl	$10, %edi
	callq	_Z12functionLoopi
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
                                        # -- End function
	.type	.Lstr,@object           # @str
	.section	.rodata.str1.1,"aMS",@progbits,1
.Lstr:
	.asciz	"test"
	.size	.Lstr, 5

	.ident	"clang version 10.0.0-4ubuntu1 "
	.section	".note.GNU-stack","",@progbits
	.addrsig

/*
 * $Id: antidup.S, this makes tracing of binary a bit harder. We're
 *	achieving this by simple technique -- we're tracing it first,
 *	linux won't allow ptrace() at one pid twice.
 */

.globl	antidump
.globl	antidump_end

antidump:
	xor	%eax, %eax
	mov	$190, %al
	int	$0x80
	test	%eax, %eax
	jz	traced_child
wait_loop:
	xor	%edx, %edx
	push	%ecx
	or	$-1, %ebx
	mov	%esp, %ecx
	push	$7
	pop	%eax
	int	$0x80
	pop	%ebx
	cmp	$0x7f, %bl
	mov	%bh, %bl
	jne	go_exit
/* child got signal, deliver it */
	and	$63, %ebx
	mov	%ebx, %esi
	xchg	%ecx, %eax
	push	$7
	pop	%ebx
	push	$26
	pop	%eax
	int	$0x80
	jmp	wait_loop
go_exit:
	push	$1
	pop	%eax
	int	$0x80
traced_child:
	xor	%ebx, %ebx
	push	$26
	pop	%eax
	int	$0x80
	test	%eax, %eax
	js	go_exit
entidump_end:

/*
 * $Id: decompress.S, NRV2E decompressor,
 *	111 bytes - optimized for size, not speed ;)
 */

.data
.align 0
.p2align 0
.globl	decompress
.globl	decompress_end
.globl	decompress_src
.globl	decompress_dest
decompress:
	cld
	.byte	0xbe	/* mov decompress_src, %esi */
decompress_src:	.long	0
	lodsl
	xchg	%eax, %edi
	push	%edi
decompr_start:
	or	$-1, %ebp
	xor	%ecx, %ecx
	xor	%ebx, %ebx
	call	ggetbit
getbit:
	add	%bl, %bl
	jne	gotbit
	mov	(%esi), %bl
	inc	%esi
	stc
	adc	%bl, %bl
gotbit:	ret
decompr_literal:
	movsb
	.byte	0xb0	/* jmp decompr_loop ;) */
ggetbit:
	pop	%edx
decompr_loop:
	call	*%edx
	jc	decompr_literal
decompr_match:
	xor	%eax, %eax
	inc	%eax
loop:
	call	*%edx
	adc	%eax, %eax
	call	*%edx
	jc	break
	dec	%eax
	call	*%edx
	adc	%eax, %eax
	jmp	loop
break:	sub	$3, %eax
	jc	decompr_same_off
	shl	$8, %eax
	lodsb
	xor	$0xffffffff, %eax
	jz	decompr_end
	sar	%eax
	xchg	%eax, %ebp
	jae	decompr_got_off
decompr_mlen1:
	call	*%edx
	adc	%ecx, %ecx
	jmp	decompr_got_len
	# not reached ?!
decompr_same_off:
	call	*%edx
	jc	decompr_mlen1
decompr_got_off:
	inc	%ecx
	call	*%edx
	jc	decompr_mlen1
loop1:
	call	*%edx
	adc	%ecx, %ecx
	call	*%edx
	jae	loop1
	inc	%ecx
	inc	%ecx
decompr_got_len:
	cmp	$-0x500, %ebp
	adc	$2, %ecx
	xchg	%esi, %eax
	lea	(%edi, %ebp, 1), %esi
	repz;	movsb
	xchg	%esi, %eax
	jmp	decompr_loop
decompr_end:
/* just execute decompressed code */
	ret
decompress_dest:
	.long	0
decompress_end:

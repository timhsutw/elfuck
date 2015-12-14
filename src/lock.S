/*
 * $Id: lock.S, file locking, sha1 & rc4 (~400 & ~80 bytes)
 */

#define __ASSEMBLY__
#include "getpw.h"

.globl	elf_lock
.globl	lock_start
.globl	lock_testkey
.globl	elf_lock_end
.globl	rc4_asm
.globl	sha1_asm
.globl	locked_len

	.data
	.align	0
	.p2align 0

elf_lock:
	.byte	0xbd			/* mov lock_start, %ebp */
lock_start:	.long 0			/* ptr to encrypted data */
	mov	%esp, %esi
	sub	$(64+MAXPASS), %esp	/* 60 bytes - password, 64 bytes - terminfo */
	cld
	lodsl
	lea	4(%esi, %eax, 4), %esi
/* walk thru env and look for 'EPW=' */
find_env:
	lodsl
	test	%eax, %eax
	jz	find_env_end

	cmpl	$0x3d575045, (%eax)	/* cmp 'EPW=', (%eax) */
	jne	find_env
	lea	4(%eax), %esi
	jmp	have_pass
find_env_end:
get_pass:
	push	$4
	pop	%eax
	xor	%ebx, %ebx
	inc	%ebx
	mov	-4(%ebp), %edx		/* size of banner (negative!) */
	lea	-4(%ebp, %edx), %ecx
	neg	%edx
	int	$0x80
	/* we'must explicitly read password from stdin
	 * ioctl(TCGETS ... */
	pushl	$54
	popl	%eax		/* ioctl */
	xor	%ebx, %ebx	/* stdin */
	mov	$0x5401, %ecx	/* TCGETS */
	mov	%esp, %edx
	int	$0x80
	test	%eax, %eax
	jnz	err_out
ioctl_ok:
	pushl	12(%edx)
	andb	$0xf7, 12(%edx)	/* &= ~(ECHO) */
	inc	%ecx		/* 0x5402 - TCSETS */
	mov	$54, %al
	push	%eax
	int	$0x80

	push	%ecx
	push	%edx
	mov	$3, %al
	lea	64(%esp), %ecx
	mov	%ecx, %esi
	push	$MAXPASS
	pop	%edx		/* maximal password - 60 chrs */
	int	$0x80
	dec	%eax
	jns	1f
err_out:
	xchg	%eax, %ebx
	xor	%eax, %eax
	inc	%eax
	int	$0x80
1:
	movb	%ah, (%ecx, %eax) /* terminate string (yah, including \n) */

	pop	%edx		/* restore original terminfo */
	pop	%ecx
	pop	%eax
	popl	12(%edx)
	int	$0x80

	/* write newline */
	mov	$4, %al
	inc	%ebx
	push	$0xa
	mov	%esp, %ecx
	push	$1
	pop	%edx
	int	$0x80
	pop	%eax
have_pass:
	xor	%ecx, %ecx
	push	%esi
	.byte	0xb0
1:	inc	%ecx
	lodsb
	test	%al, %al
	jnz	1b
	pop	%esi
	mov	%esp, %edi
	call	sha1		/* and compute hash of password! */
	/* well, now use the password hash value as decryption key */
	.byte	0xb9		/* mov locked_len, %ecx */
locked_len:	.long	0
	mov	%ebp, %esi
/*
 * edi - key (hashed)
 * esi - input data
 * ecx - length
 */
	call	rc4		/* decrypt */
	push	%edi
	add	$20, %edi
	call	sha1		/* compute sha1 of result */
	.byte	0x81, 0x3f	/* cmp $lock_testkey, (%edi) */
lock_testkey:.long	0
	pop	%edi
	je	decrypt_ok
	call	rc4		/* repair back ;) */
	call	1f
	.ascii	"bad password\n"
1:	pop	%ecx
	push	$4
	pop	%eax
	push	$2
	pop	%ebx
	pushl	$13
	pop	%edx
	int	$0x80
	jmp	get_pass	/* try again ;) */
decrypt_ok:
	add	$(64+MAXPASS), %esp
	jmp	*%ebp		/* jump to decrypted proggie */

/*
 * RC4 implementation, 20 byte key assumed
 * edi - key
 * esi - data
 * ecx - datalen
 */
rc4:
	pushal
	mov	%esp, %ebp
	xor	%eax, %eax
1:	dec	%esp
	inc	%al
	jnz	1b
1:	movb	%al, (%esp, %eax)
	inc	%al
	jnz	1b		/* eax = 0 index2 */
	cdq			/* edx = 0, counter */
	xor	%ebx, %ebx	/* ebx = 0 index1 */
2:	addb	(%edi, %ebx), %al
	addb	(%esp, %edx), %al
	movb	(%esp, %edx), %bh
	xchgb	%bh, (%esp, %eax)
	movb	%bh, (%esp, %edx)
	xor	%bh, %bh
	inc	%ebx
	cmp	$20, %bl	/* <-- put key len there! */
	jc	1f
	and	%bh, %bl
1:	inc	%dl
	jnz	2b
	cdq			/* edx = 0, x */
	xor	%ebx, %ebx	/* ebx = 0, y */
1:	inc	%dl
	addb	(%esp, %edx), %bl
	movb	(%esp, %edx), %al
	xchgb	%al, (%esp, %ebx)
	movb	%al, (%esp, %edx)
	addb	(%esp, %ebx), %al
	mov	(%esp, %eax), %al
	xor	%al, (%esi)
	inc	%esi
	loop	1b
	mov	%ebp, %esp
	popa
	ret
rc4_end:

/*
 * minimalistic implementation of sha1 in x86 asm, ~400 bytes
 * esi - input bytes
 * ecx - number of input bytes
 * edi - 20 bytes of digest
 */
sha1:
	pusha
	push	%edi
	pushl	$0x67452301	/* state[0] */
	pushl	$0xEFCDAB89	/* state[1] */
	pushl	$0x98BADCFE	/* state[2] */
	pushl	$0x10325476	/* state[3] */
	pushl	$0xC3D2E1F0	/* state[4] */
	mov	%ecx, %eax
	mov	%ecx, %ebp
	shl	$3, %eax
	bswap	%eax		/* sha1 works with big endian only ;( */
	push	%eax		/* count[0] */
	sub	$128, %esp	/* for padding stuff */
trans_loop:
	cmp	$64, %ecx
	jc	gopad1
	call	transform
	add	$64, %esi
	sub	$64, %ecx
	jmp	trans_loop
gopad1:
	mov	%esp, %edi
	push	%ecx
	repz;	movsb
	movb	$0x80, %al	/* padding mark */
	stosb
	pop	%ebx
	mov	$127, %cl
	sub	%ebx, %ecx
	xor	%eax, %eax
	repz;	stosb
	mov	%esp, %esi	/* start to esi */
	inc	%ecx
	mov	127(%esi,%ecx), %eax	/* size to eax */
	cmp	$56, %ebx
	jc	single_align
double_align:
	mov	%eax, 124(%esi)
	call	transform
	add	$64, %esi
	.byte	0xba
single_align:
	mov	%eax, 60(%esp)
	call	transform
	add	$128+4, %esp
	
	mov	$5, %cl
	mov	20(%esp), %edi
1:	mov	-4(%esp, %ecx, 4), %eax
	bswap	%eax
	stosl
	loop	1b
	add	$24, %esp
	popa
ret

/*
 * well, this is the main SHA1 function
 * it must preserve all registers
 * 0(%esp) - count - unused
 * 4(%esp) - state[4]
 * 8(%esp) - state[3]
 * 12(%esp) - state[2]
 * 16(%esp) - state[1]
 * 20(%esp) - state[0]
 */
transform:
	pusha
	/* create private copy of processed data */
	pushl	$64
	popl	%ecx
	sub	%ecx, %esp
	mov	%esp, %edi
	repz;	movsb
	mov	%esp, %esi

	add	$128+36+4, %edi

	mov	16(%edi), %ebp
	mov	12(%edi), %eax
	mov	8(%edi), %ebx
	mov	4(%edi), %edx
	mov	(%edi), %edi

	/*
	 * e = a
	 * a = b
	 * b = c
	 * c = d
	 * d = e
	 */
	xor	%ecx, %ecx
aloop:
	# rotate a,b,c,d,e
	push	%eax
	push	%ebx
	push	%edx
	push	%edi
	push	%ebp
	pop	%eax
	pop	%ebp
	pop	%edi
	pop	%edx
	pop	%ebx

#!#
	push	%edx
	call	rop
	push	%eax
	rol	$5, %eax
	add	%eax, %edx
	pop	%eax
	add	%edx, %ebp
	rol	$30, %ebx
	pop	%edx

	inc	%ecx
	cmp	$80, %cl
	jc	aloop
	add	$64, %esp

	lea	128+36+4(%esp), %ecx

	add	%ebp, 16(%ecx)
	add	%eax, 12(%ecx)
	add	%ebx, 8(%ecx)
	add	%edx, 4(%ecx)
	add	%edi, (%ecx)

	popa
ret

rop:
	cmp	$20, %cl
	jae	r2
/*
 * R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
 * R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
 */
r0:
	xor	%edi, %edx	/* x = x^y */
	and	%ebx, %edx	/* x = x&w */
	xor	%edi, %edx	/* x = x^y */

	cmp	$20, %cl
	jae	r2
	cmp	$16, %cl
	jae	r1
r0_:
	push	%eax
	mov	(%esi, %ecx, 4), %eax /* x += blk0(i) */
	bswap	%eax
	mov	%eax, (%esi, %ecx, 4)
	add	%eax, %edx
	pop	%eax
	jmp	rx
r1:
	call	blk
rx:	add	$0x5A827999, %edx
rall:	ret

/*
 * R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
 * R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);
 */

r2:
	cmp	$40, %cl
	jae	mayber3
r2r4:
	xor	%ebx, %edx	/* x^w */
	xor	%edi, %edx	/* ^y */
	call	blk
	add	$0x6ED9EBA1, %edx
	cmp	$60, %cl
	jc	rall
	/* alternatively R4 */
	add	$(0xCA62C1D6-0x6ED9EBA1), %edx
	ret
mayber3:
	cmp	$60, %cl
	jae	r2r4
r3:
/* R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30); */
	push	%edx
	or	%ebx, %edx	/* x|w */
	and	%edi, %edx	/* &y */
	and	%ebx, (%esp)
	or	(%esp), %edx
	add	$4, %esp
	call	blk
	add	$0x8F1BBCDC, %edx
	ret

/*
 * this performs block expand function
 * blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
 *         ^block->l[(i+2)&15]^block->l[i&15],1))
 * i => ecx
 * result will be added to X (%edx), block itself is in esi
 */
blk:
	pusha
	lea	13(%ecx), %eax
	and	$15, %al	/* block->l[(i+13)&15] = ebx */
	lea	8(%ecx), %ebx
	and	$15, %bl	/* block->l[(i+8)&15] = ebx */
	lea	2(%ecx), %edx
	and	$15, %dl	/* block->l[(i+2)&15] = edx */
	and	$15, %cl	/* block->l[i&15] = ecx */

	mov	(%esi, %eax, 4), %edi /* block->l[i&15] */
	xor	(%esi, %ebx, 4), %edi /* ^block->l[(i+8)&15] */
	xor	(%esi, %edx, 4), %edi /* ^block->l[(i+2)&15] */
	xor	(%esi, %ecx, 4), %edi /* ^block->l[i&15] */
	rol	$1, %edi	/* rol 1 */
	mov	%edi, (%esi, %ecx, 4) /* result to block->l[i&15] */
	add	%edi, 20(%esp)	/* add to pushed %edx */
	popa
ret
sha1_end:
elf_lock_end:

/* just a C interfaces */

/* sha1_asm(char *digest, char *input, int len) */
sha1_asm:
	pushal
	mov	32+4(%esp), %edi
	mov	32+8(%esp), %esi
	mov	32+12(%esp), %ecx
	call	sha1
	popal
ret

/* rc4_asm(char *key, char *input, int len) */
rc4_asm:
	pushal
	mov	32+4(%esp), %edi
	mov	32+8(%esp), %esi
	mov	32+12(%esp), %ecx
	call	rc4
	popal
ret

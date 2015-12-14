/*
 * $Id: execelf.S, executing any ELF file from memory - ~400 bytes ;)
 */

.data
.align 0
.p2align 0
.globl	execelf
.globl	execelf_end
.globl	execelf_interp
.globl	e_skip_interp
.globl	e_no_interp

#define DEBUG 0
GRANT=512

#if DEBUG
#define PAUSE \
	pushal; \
	pushl	$3; \
	pop	%eax; \
	push	$1; \
	pop	%edx; \
	push	%eax; \
	mov	%esp, %ecx; \
	xor	%ebx, %ebx; \
	int	$0x80; \
	pop	%eax; \
	popal;
#else
#define PAUSE
#endif

execelf:
//#include "antidump.S"
	call	e_getdelta
elf_error:
	call	e_getstrings
e_err1:
	.ascii	"ELF execution failed\n"
e_err2:
e_getstrings:
	movl	$4, %eax
	movl	$2, %ebx
	popl	%ecx
	movl	$(e_err2-e_err1), %edx
	int	$0x80
	mov	$1, %eax
	mov	$127, %ebx
	int	$0x80
e_getdelta:
	pop	%edi
	add	$(execelf_end-elf_error), %edi
	mov	%edi, %ebx
	xor	%ebp, %ebp	/* interpreter base, none at this time */
	xor	%eax, %eax
	scasb
	jz	e_no_interp
e_skip_interp:
	scasb
	jnz	e_skip_interp
e_load_interp:
	/* well, try open interpreter file */
	push	%esi
	mov	$5, %eax
	xor	%ecx, %ecx
	int	$0x80
	test	%eax, %eax
	js	elf_error
	mov	$4096, %edx
	sub	%edx, %esp	/* one page for headers */
	xchg	%eax, %ebx	/* handle to %ebx */
	mov	$3, %eax	/* read() */
	mov	%esp, %ecx
	int	$0x80
	
	mov	28(%esp), %edx	/* phdrs offset */
	push	$0		/* last_bss */
	push	$0		/* elf_bss */
e_load_findseg:
	cmpl	$1, 8(%esp, %edx)
	jne	e_load_nextseg
	/* this will mmap one segment */
e_load_mapseg:
	mov	8+8(%esp, %edx), %eax /* vaddr offset */
	mov	%eax, %edi
	and	$~4095, %edi
	and	$4095, %eax

	mov	8+4(%esp, %edx), %ecx /* offset in file */
	sub	%eax, %ecx

	mov	8+16(%esp, %edx), %esi /* filesz */
	add	%eax, %esi

	push	%ecx		/* offset */
	push	%ebx		/* fd */
	push	$0x12		/* MAP_FIXED | MAP_PRIVATE */
	push	$0x7		/* rwx */
	push	%esi		/* filesize */

	cmpw	$3, 8+5*4+16(%esp) /* ET_DYN ?! */
	jne	e_load_fixed
	add	%ebp, %edi	/* relocate */
	test	%ebp, %ebp	/* huh, base not known yet ? */
	jne	e_load_fixed
	andb	$~0x10, 8(%esp)	/* remove MAP_FIXED */
	push	$0
	.byte	0xb0		/* addr = 0, i.e. get random */
e_load_fixed:
	push	%edi		/* addr */
	mov	%esp, %ebx
	mov	$90, %eax
	int	$0x80		/* try mmap */
	cmp	$0xfffff000, %eax
1:	jae	elf_error	/* failed ? */

	testb	$0x10, 12(%esp)	/* was fixed ? */
	jnz	e_load_wasfixed
	sub	%edi, %eax	/* it's first dynamic - set base */
	xchg	%eax, %ebp	/* to the ebp */
e_load_wasfixed:
	add	$16, %esp
	pop	%ebx		/* restore fd */
	pop	%eax		/* offset - blah */

	mov	8+8(%esp, %edx), %ecx /* vaddr unaligned */
	add	%ebp, %ecx
	
	mov	8+16(%esp, %edx), %edi
	add	%ecx, %edi	/* k = load_addr + p_vaddr + p_filesz */
	pop	%eax		/* elf_bss */
	cmp	%edi, %eax	/* if (k > elf_bss) */
	jae	elf_bss_g
	xchg	%edi, %eax	/* elf_bss = k */
elf_bss_g:

	mov	4+20(%esp, %edx), %edi
	add	%ecx, %edi	/* k = load_addr + p_vaddr + p_memsz */
	pop	%esi		/* last_bss */
	cmp	%edi, %esi
	jae	last_bss_g
	mov	%edi, %esi
last_bss_g:
	pushl	%esi
	pushl	%eax

e_load_nextseg:
	add	$32, %edx
	decw	8+44(%esp)
	jnz	e_load_findseg

	mov	$6, %eax	/* close that sucker */
	int	$0x80

/* well, ladies and gantlemans, now pad zero the bss and mmap the rest of it */
	pop	%edi		/* elf_bss */
	pop	%ecx		/* last_bss */
	lea	4095(%edi), %eax /* where we'll start mmaping to */
	and	$~4095, %eax
	sub	%eax, %ecx	/* size */
	add	$4095, %ecx	/* pagealigned */
	and	$~4095, %ecx
	jecxz	no_bss

	push	$0
	push	$0
	push	$0x32
	push	$0x7
	push	%ecx
	push	%eax
	mov	%esp, %ebx
	mov	$90, %eax
	int	$0x80
	cmp	$0xfffff000, %eax
	jae	1b		/* failed ? */
	add	$24, %esp

	/* and also zero it */
	xor	%eax, %eax
	repz;	stosb
no_bss:

	mov	24(%esp), %eax	/* yep, we need new entrypoint */
	add	%ebp, %eax
	add	$4096, %esp
	pop	%esi
e_no_interp:
	mov	%esi, %edi
	test	%eax, %eax
	jnz	have_ep
	mov	8(%edi), %eax
have_ep:
	xchg	%eax, %ebx	/* entrypoint in ebx */
	mov	%edi, %edx	/* saved-aux in edx */

/* now go count stuff */
	mov	%esp, %esi
	lea	(%esp), %esi
	lodsl
	lea	4(%esi,%eax,4), %esi
skip_env:
	lodsl
	test	%eax, %eax
	jnz	skip_env

	push	%esi		/* save start of aux table */
skip_aux:
	lodsl
	test	%eax, %eax
	lodsl
	jnz	skip_aux

	pop	%eax

	sub	%esp, %esi	/* in esi is now size of block to be moved */
	mov	%esi, %ecx
	mov	%esp, %esi
	sub	$GRANT, %esp
	mov	%esp, %edi
	repz;	movsb

	push	%ebx		/* save entrypoint */
	lea	-512(%eax), %esi

	PAUSE

/*	push	$4
	pop	%ecx
	push	$22
	pop	%ebx
	call	set_aux_ent
	
	push	$6
	pop	%ecx
	push	$4096
	pop	%ebx
	call	set_aux_ent
	
	push	$8
	pop	%ecx
	push	$0
	pop	%ebx
	call	set_aux_ent

	push	$11
	pop	%ecx
	push	$0
	pop	%ebx
	call	set_aux_ent

	push	$12
	pop	%ecx
	push	$0
	pop	%ebx
	call	set_aux_ent

	push	$13
	pop	%ecx
	push	$0
	pop	%ebx
	call	set_aux_ent

	push	$14
	pop	%ecx
	push	$0
	pop	%ebx
	call	set_aux_ent */


	push	$3
	pop	%ecx		/* AT_PHDR */
	mov	(%edx), %ebx
	call	set_aux_ent
	mov	$5, %cl		/* AT_PHNUM */
	mov	4(%edx), %ebx
	call	set_aux_ent
	mov	$7, %cl		/* AT_BASE */
	mov	%ebp, %ebx
	call	set_aux_ent
	mov	$9, %cl		/* AT_ENTRY */
	mov	8(%edx), %ebx
	call	set_aux_ent

	/* now, free our unused pages and fire that sucker up */
	push	$91
	pop	%eax
	movl	12(%edx), %ebx
	movl	16(%edx), %ecx
	int	$0x80
	xor	%eax, %eax
	xor	%ebx, %ebx
	xor	%ecx, %ecx
	xor	%edx, %edx
	xor	%esi, %esi
	xor	%edi, %edi
	xor	%ebp, %ebp
	ret	/* voila! */

/* this will setup new/modify existing aux entry, well on buggy
   < 2.2.17 kernels we're going to overwrite envp, but heck, it
   seem to work fine -sd */
set_aux_ent:
	push	%esi
set_aux_find:
	lodsl
	test	%eax, %eax
	jz	set_aux_new
	cmp	%ecx, %eax
	lodsl
	jne	set_aux_find
	mov	%ebx, -4(%esi)
set_aux_done:
	pop	%esi
	ret
set_aux_new:
	mov	%ecx, -4(%esi)
	mov	%ebx, (%esi)
	and	$0, 4(%esi)
	jmp	set_aux_done

execelf_end:
execelf_interp:	.zero	256




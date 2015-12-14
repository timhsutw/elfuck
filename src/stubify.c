/*
 * $Id: stubify.c, well, this is what actually screws up any ELF file.
 *
 * Produced SFX executable looks like:
 *
 * <segment>
 *	<optional polymorphic descrambler>
 *	<optional locking code>
 * 	120	decompressor [entrypoint]
 *	4	ptr to dest (needed by decompressor)
 *	x1	packed elf body
 *	4096-x2 <padding>
 *	x2	ELF loader <-- from this point decompressor stores output
 *	---- there begins original ELF base
 *	two segments of original elf, merged to one
 */

/* you can put anything there */
#define PWDPROMPT "password:"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/elf.h>
#include <string.h>
#include <sys/mman.h>
#include "nrv2e.h"
#include "elfuck.h"
#include "decompress.h"
#include "execelf.h"
#include "stubify.h"
#include "poly.h"
#include "getpw.h"
#include "lock.h"

static	int olen;
void	pack_callback(int ts, int cs, void *d)
{
	static int c = 0;
	register int k = ts * 100 / olen;

	if (c != k) {
		fprintf(stderr, "\r%d %%", k);
		c = k;
	}
}

#define OFFSET(x) ((x) & 4095)
int	stubify_elf(uchar *src, uchar *dest, int size, int level, int flags)
{
	struct	elf32_hdr *e = (void *) src;
	struct	stub *o = (void *) dest;
	struct	elf32_phdr *p;
	ulong	lo = -1, hi = 0, memhi = 0, start = 0;
	uchar	*pa, *ka;
	int	i, d = 0;
	ucl_callback cb;
	struct	elf_aux *aux;
	int	bsize = sizeof(ELF_BANNER)-1, esize = EXECELF_SIZE + 1;
	int	have_interp = 0;
	poly_key	pk;
	uchar	*poly = NULL;
	uchar	phash[20];
	ulong	testhash[5];
	int	lsize = 0;
	uchar	*lock = NULL;

	if (strncmp(e->e_ident, "\177ELF", 4)) {
		eprintf("ERROR: Input file not in ELF format\n");
		return -1;
	}

	memset(&pk, 0, sizeof(pk));

	if (flags & FLAG_NOBANNER)
		bsize = 0;

	if (flags & FLAG_SCRAMBLE) {
		poly = poly_gen(&pk);
	}

	if (flags & FLAG_LOCK) {
		int lp = sizeof(PWDPROMPT)-1;
		int lpn = -lp;
		getpassw(phash);
		lock = malloc(LOCK_SIZE + lp + sizeof(lpn));
		memcpy(lock + LOCK_SIZE, PWDPROMPT, lp);
		memcpy(lock + LOCK_SIZE + lp, &lpn, sizeof(lpn));
		lsize = LOCK_SIZE + lp + sizeof(lpn);
	}

	/* find code and data segments */
	for (i = 0, p = (void *) (src + e->e_phoff); i < e->e_phnum; i++, p++) {
		if (p->p_type == PT_LOAD) {
			if (p->p_vaddr < lo) lo = p->p_vaddr;
			if ((p->p_vaddr+p->p_filesz) > hi)
				hi = p->p_vaddr + p->p_filesz;
			if ((p->p_vaddr+p->p_memsz) > memhi)
				memhi = p->p_vaddr + p->p_memsz;
		}
		if (p->p_type == PT_INTERP) {
			strcpy(execelf_interp, src + p->p_offset);
			esize += strlen(execelf_interp);
			have_interp = 1;
		}
	}

	if (!have_interp) {
		/* huh. this is really hackish, ELF haven't interpreter,
		   so zero interpreter loader code for better compression,
		   as it will be never used anyway */
		memset(e_skip_interp, 0, e_no_interp-e_skip_interp);
	}

	lo = ALIGNDOWN(lo);
	hi = ALIGNUP(hi);
	memhi = ALIGNUP(memhi);
	printf("size in file: %ld, size in memory: %ld\n", hi-lo, memhi-lo);

	/* allocate source buffer we'll be compressing */
	ka = pa = malloc((hi-lo) + esize);
	if (!pa) {
		perror("ERROR: malloc failed");
		return -1;
	}
	memcpy(ka, execelf, esize); pa += esize;
	memset(pa, 0, (hi-lo));

	/* copy file data to it */
	for (i = 0, p = (void *) (src + e->e_phoff); i < e->e_phnum; i++, p++) {
		if (p->p_type == PT_LOAD) {
			memcpy(	pa + ALIGNDOWN(p->p_vaddr - lo),
				src + p->p_offset - OFFSET(p->p_vaddr),
				p->p_filesz + OFFSET(p->p_vaddr));
			memcpy(	pa + p->p_vaddr - lo,
				src + p->p_offset,
				p->p_filesz);
		}
	}

	/* ok, now compress that sucker */
	printf("Compressing ...\n");
	cb.callback = (void *) pack_callback;
	olen = (hi-lo) + esize;
	d = bsize + DECOMPRESS_SIZE + pk.len + lsize;
	ucl_nrv2e_99_compress(ka, olen, o->data + d, &i, &cb, level, NULL, NULL);
	aux = (void *) (o->data + d + i);
	i += sizeof(*aux);

	start = ALIGNDOWN(lo - (sizeof(struct stub) + d + i + 4096));
	if (start > 0x7fffffff) {
		printf("FATAL: There is not enough space for us!\n");
		free(ka);
		return -1;
	}

	/* ok, it's time to setup headers */
	memcpy(o->elf.e_ident, "\177ELF", 4);
	o->elf.e_type = ET_EXEC;
	o->elf.e_machine = EM_386;
	o->elf.e_version = 1;
	o->elf.e_entry = start + bsize + sizeof(o->elf) + sizeof(o->phdr);
	o->elf.e_phoff = sizeof(o->elf);
	o->elf.e_shoff = o->elf.e_flags = 0;
	o->elf.e_ehsize = sizeof(o->elf);
	o->elf.e_phentsize = sizeof(o->phdr);
	o->elf.e_phnum = 1;
	o->elf.e_shentsize = o->elf.e_shnum = o->elf.e_shstrndx = 0;

	/* we'have only one segment */
	o->phdr.p_type = PT_LOAD;
	o->phdr.p_offset = 0;
	o->phdr.p_vaddr = o->phdr.p_paddr = start;
	o->phdr.p_filesz = sizeof(o->elf) + sizeof(o->phdr) + d + i;
	o->phdr.p_memsz = memhi - start;
	o->phdr.p_flags = PF_R | PF_W | PF_X;
	o->phdr.p_align = 4096;

	/* copy the decompressor */
	memcpy(o->data, ELF_BANNER, bsize);
	decompress_src = o->elf.e_entry + pk.len + lsize + DECOMPRESS_SIZE - 4;
	decompress_dest = lo - esize;
	memcpy(o->data + bsize + pk.len + lsize, decompress, DECOMPRESS_SIZE);

	/* setup aux variables for execelf */
	aux->phdr = e->e_phoff + lo;
	aux->phnum = e->e_phnum;
	aux->entry = e->e_entry;
	aux->freestart = start;
	aux->freelen = lo - start - 4096;

	/* lock the result if requiered */
	if (lock) {
		uchar *data = o->data + bsize + pk.len + lsize;
		int llen = (DECOMPRESS_SIZE + i);
		sha1_asm((char *) testhash, data, llen);
		lock_testkey = testhash[0];
		lock_start = o->elf.e_entry + pk.len + lsize;
		locked_len = llen;
		memcpy(lock, elf_lock, LOCK_SIZE);
		memcpy(o->data + bsize + pk.len, lock, lsize);
		rc4_asm(phash, data, llen);
	}

	/* scramble the result if requiered */
	if (pk.len) {
		ulong slen = (DECOMPRESS_SIZE + i + lsize);
		poly_encrypt(o->data + bsize + pk.len,
			slen, &pk);

		/* setup the descrambler */
		*((ulong *)(&poly[pk.plen])) = (slen+3) >> 2;
		*((ulong *)(&poly[pk.paddr])) = o->elf.e_entry + pk.len;
		o->elf.e_entry += pk.start;

		/* and copy the polymorphic descrambler */
		memcpy(o->data + bsize, poly, pk.len);
	}

	free(ka);
	free(poly);
	free(lock);
	return o->phdr.p_filesz;
}

/* this will pack arbitrary ELF in 'src' to 'dest' with 'evel' */
int	pack_elf(char *src, char *dest, int level, int flags)
{
	int	in, out, size, t;
	uchar	*i, *o;

	printf("Packing%s%s%s '%s' to '%s'\n", 
		flags & FLAG_SCRAMBLE ? ", scrambling" : "",
		flags & FLAG_LOCK ? ", locking" : "",
		flags & FLAG_NOBANNER ? " without banner" : "",
		src, dest);

	/* open input/output streams */
	in = open(src, O_RDONLY);
	if (in < 0) {
		perror(src);
		return 1;
	}

	out = open(dest, O_CREAT | O_RDWR | O_TRUNC, 0744);
	if (out < 0) {
		perror(dest);
		return 1;
	}

	size = lseek(in, 0, SEEK_END);
	ftruncate(out, ALIGNDOWN(size*2) + 4096);

	/* mmap them */
	i = mmap(NULL, ALIGNUP(size), PROT_READ, MAP_SHARED, in, 0);
	if (i == MAP_FAILED) {
		perror("mmap");
		close(in); close(out);
		return 1;
	}

	o = mmap(NULL, ALIGNDOWN(size*2) + 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
		out, 0);
	if (o == MAP_FAILED) {
		perror("mmap");
		close(in); close(out); munmap(i, ALIGNUP(size));
		return 1;
	}
	t = stubify_elf(i, o, size, level, flags);
	munmap(i, ALIGNUP(size));
	munmap(o, ALIGNDOWN(size*2) + 4096);
	if (t >= 0) {
		printf("\rOk, compressed to %.2f%% (%d => %d)\n", t * 100.0 / size, size, t);
		ftruncate(out, t);
		close(out);
	} else {
		printf("\rCompression failed!\n");
		close(out);
		unlink(dest);
	}
	close(in);
	return t<0?-1:0;
}

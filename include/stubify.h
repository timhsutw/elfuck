#ifndef STUBIFY_H
#define STUBIFY_H
#include <linux/elf.h>
extern int	pack_elf(char *, char *, int, int);

typedef struct {
	void    (*callback) (int, uint, int, void * user);
	void	*user;
} ucl_callback;

struct stub {
	struct elf32_hdr	elf;
	struct elf32_phdr	phdr;
	uchar  data[1];
} __attribute__ ((packed));

struct elf_aux {
	ulong	phdr;
	ulong	phnum;
	ulong	entry;
	ulong	freestart;
	ulong	freelen;
}  __attribute__ ((packed));

#endif

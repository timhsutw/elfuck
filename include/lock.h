#ifndef LOCK_H
#define LOCK_H

extern	void elf_lock();
extern	ulong lock_start;
extern	ulong lock_testkey;
extern	ulong locked_len;
extern	void elf_lock_end();
extern	void sha1_asm(uchar *, char *, int);
extern	void rc4_asm(uchar *, char *, int);

#define LOCK_SIZE ((ulong) elf_lock_end - (ulong) elf_lock)

#endif

#ifndef DECOMPRESS_H
#define DECOMPRESS_H
extern	void decompress(void);
extern	void decompress_end(void);
extern	ulong decompress_src;
extern	ulong decompress_dest;
#define DECOMPRESS_SIZE ((unsigned) decompress_end - (unsigned) decompress)
#endif

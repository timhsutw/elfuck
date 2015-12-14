#ifndef ELFUCK_H
#define ELFUCK_H

#define ELF_BANNER "\nELFuck 0.1 compressed (c) 2002 by sd <http://sd.g-art.nl>\n"
#define BANNER	"ELFuck 0.1, real-time ELF executables compression/encryption\n" \
		"(c) Copyright 2002 by sd <http://sd.g-art.nl>\n"

#ifndef ulong
#define ulong unsigned long
#endif
#ifndef uchar
#define uchar unsigned char
#endif
#ifndef uint
#define uint unsigned int
#endif

#define eprintf(fmt...) fprintf(stderr, fmt)
#define ALIGNDOWN(x) ((x)&(~4095))
#define ALIGNUP(x) ALIGNDOWN((x)+4095)

#define FLAG_NOBANNER	1
#define FLAG_SCRAMBLE	2
#define FLAG_LOCK	4

#endif

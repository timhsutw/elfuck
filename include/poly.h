#ifndef POLY_H
#define POLY_H

typedef struct {
	unsigned long a,b;
	unsigned paddr, plen;
	unsigned len;
	unsigned start;
} poly_key;

#define MAXGAPLEN	16
#define MINGAPLEN	8
#define MAXJUNK		3

//#define NOPGAP

char	*poly_gen(poly_key *key);
void	poly_encrypt(unsigned char *data, int len, poly_key *key);

#endif

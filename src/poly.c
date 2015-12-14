/*
 * $Id: poly.c, kinda lame polymorphic engine
 *
 * The decryptor will look like
 *
 * 0: mov $key1, %reg1   \
 * 1: mov $key2, %reg2    \ these may be randomly exchanged
 * 2: mov $length, %reg3  /
 * 3: mov $addr, %reg4   /
 *
 * 4: xor %reg1, (%reg4)
 * 5: sub %reg2, (%reg4) \ exchangable
 * 6: add %reg2, %reg1   /
 * 7: lea x(%reg4), %reg4 / add x, %reg4 \ exchangable
 * 8: lea x(%reg4), %reg4 / add x, %reg4 /
 * 9: dec %reg3
 *    jz loopout
 *
 *
 * each instruction statement has before and after some one-byte junk
 * (cli, nop ..), following a jump to randomly placed next statement,
 * a`la Onehalf.
 *
 * virii folks will know -- kinda lame ;p
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "elfuck.h"
#include "poly.h"

typedef struct {
	int	pos;
	int	len;
} poly_state;

static void	blewgap(unsigned char **p)
{
	int gaplen = (rand() % (MAXGAPLEN-MINGAPLEN)) + MINGAPLEN;
	unsigned char *buf = *p;
	(*p) += gaplen;
	while (gaplen--)
#ifdef NOPGAP
		*buf++ = 0x90;
#else
		*buf++ = rand() & 0xff;
#endif
}

static int freeregs[3];

static void	blewnop(unsigned char **p)
{
	unsigned char *b = *p;
	static char tab[] = "\xf8\xfc\xf5\xf9\xfd\x90";
	(*p)++;
	switch (rand() % 3) {
		case 0: /* dec */
			*b = 0x48 + freeregs[rand() % 3];
			break;
		case 1: /* inc */
			*b = 0x40 + freeregs[rand() % 3];
			break;
		case 2: /* some one-byte */
			*b = tab[rand() % (sizeof(tab)-1)];
			break;
	}
}

static void	blewnops(unsigned char **p) {
	int i = (rand() % MAXJUNK)+1;
	while (i--) {
		blewnop(p);
	}
}

static void	blewadd(unsigned char **p, unsigned num, int reg)
{
	unsigned char *buf = *p;
	switch (rand() % 3) {
		/* classic add */
		case 0:
			buf[0] = 0x81;
			buf[1] = 0xc0 + reg;
			*((unsigned *)(&buf[2])) = num;
			break;
		/* sub -number */
		case 1:
			buf[0] = 0x81;
			buf[1] = 0xe8 + reg;
			*((unsigned *)(&buf[2])) = 0-num;
			break;
		/* lea num(%reg), reg */
		case 2:
			buf[0] = 0x8d;
			buf[1] = 0x80 + reg + reg*8;
			*((unsigned *)(&buf[2])) = num;
			break;
	}
	(*p) += 6;
}

void	mix_jump(int *tab, int count)
{
	int i, j, k, s;
	for (i = 0; i < count*count; i++) {
		j = rand() % count;
		k = (j+1) % count;
		s = tab[j];
		tab[j] = tab[k];
		tab[k] = s;
	}
}

char	*poly_gen(poly_key *key)
{
	poly_state st[10];
	unsigned char *ret, *before, *outjump = NULL;
	unsigned char *p = ret = malloc((MAXGAPLEN+64)*10);
	int	regs[4];
	int	ii, i, j, k;
	unsigned koef1, koef2;
	int	jtab[10];

	memset(st, 0, sizeof(st));
	memset(regs, 0, sizeof(regs));

	/* generate keys */
	srand(time(NULL));
	key->a = rand() ^ (rand() << 16);
	key->b = rand() ^ (rand() << 16);
	koef1 = rand() ^ (rand() << 16);
	koef2 = (0-koef1) + 4;

	/* generate registers */
	for (i = 0; i < 4; i++) {
		int a;
		a = (rand() % 8)-1;
	again:
		a = (a+1) % 8;
		if (a == 4) goto again;
		for (j = 0; j < i; j++) {
			if (regs[j] == a)
				goto again;
		}
		regs[i] = a;
	}

	/* pick the rest */
	for (i = 0, k = 0; i < 8; i++) {
		if (i == 4) continue;
		for (j = 0; j < 4; j++) {
			if (i == regs[j])
				goto next;
		}
		for (j = 0; j < k; j++) {
			if (i == freeregs[j])
				goto next;
		}
		freeregs[k++] = i;
	next:
		;	
	}

	for (ii = 0; ii < 10; ii++) {
		int state;
		
		/* introduce us by real shit ;p */
		blewgap(&p);

		/* find free state */
		for (state = rand() % 10; st[state].len; state = (state+1) % 10);


		/* put few nops */
		before = p;
		blewnops(&p);
		switch (state) {
			case 0:
				*p++ = 0xb8 + regs[0];
				*((ulong *) p) = key->a;
				p += 4;
				break;
			case 1:
				*p++ = 0xb8 + regs[1];
				*((ulong *) p) = key->b;
				p += 4;
				break;
			case 2:
				*p++ = 0xb8 + regs[2];
				key->plen = p-ret;
				p += 4;
				break;
			case 3:
				*p++ = 0xb8 + regs[3];
				key->paddr = p-ret;
				p += 4;
				break;
			case 4:
				*p++ = 0x31;
				*p++ = 0x40 + regs[3] + regs[0] * 8;
				*p++ = 0;
				break;
			case 5:
				*p++ = 0x29;
				*p++ = 0x40 + regs[3] + regs[1] * 8;
				*p++ = 0;
				break;
			case 6:
				*p++ = 1;
				*p++ = 0xc0 + regs[0] + regs[1] * 8;
				break;
			case 7:
				blewadd(&p, koef1, regs[3]);
				break;
			case 8:
				blewadd(&p, koef2, regs[3]);
				break;
			case 9:
				*p++ = 0x48 + regs[2];
				outjump = p;
				/* space for jump code */
				for (i = 0; i < 6; i++)
					blewnop(&p);
				break;
		}
		blewnops(&p);
		st[state].pos = before - ret;
		st[state].len = p - before;
	}
	/* ok, we have our states */
	blewgap(&p);

	/* now compute jumps */
	for (i = 0; i < 9; i++) {
		jtab[i] = i+1;
	}
	jtab[9] = 4;

/*	XXX-TODO: Not implemented yet
	mix_jump(&jtab[0], 4);
	mix_jump(&jtab[5], 2);
	mix_jump(&jtab[7], 2); */

	key->start = st[0].pos;

	/* place jump instruction after each label */
	for (i = 0; i < 10; i++) {
		long from = st[i].pos + st[i].len;
		long to = st[jtab[i]].pos;
		long rel = to-from-2;
		if ((rel > 127) || (rel < -127)) {
			/* near jump */
			ret[from] = 0xe9;
			*((long *)(&ret[from+1])) = rel-3;
		} else {
			/* short jump */
			ret[from] = 0xeb;
			ret[from+1] = ((unsigned long) rel) & 0xff;
		}
	}

	/* and finally, setup the jump-out instruction */
	i = p-outjump-2;
	if (i > 127) {
		/* near 'jz' */
		outjump[0] = 0x0f;
		outjump[1] = 0x84;
		*((long *)(&outjump[2])) = i-4;
	} else {
		/* short 'jz' */
		outjump[0] = 0x74;
		outjump[1] = i;
	}
	key->len = p-ret;
	return ret;
}

void	poly_encrypt(unsigned char *data, int len, poly_key *key)
{
	unsigned *p = (void *) data;
	unsigned a,b;

	len = (len+3) >> 2;
	a = key->a;
	b = key->b;

	while (len--) {
		*p += b;
		*p ^= a;
		a += b;
		p++;
	}
}

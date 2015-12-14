/*
 * $Id: getpw.c, password input
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>

#include "elfuck.h"
#include "lock.h"
#include "getpw.h"

/* this will return a 20byte hash of entered password */
void	getpassw(uchar *hash)
{
        struct  termios old, new;
	char	p1[MAXPASS], p2[MAXPASS];
	int	len1, len2;

	/* get old term settings */
        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ECHO);
        tcsetattr(0, TCSAFLUSH, &new);
	while (1) {
		printf("Password: "); fflush(stdout);
		len1 = read(0, p1, sizeof(p1)-1);
		if (--len1 < 0) goto bad;
		p1[len1] = 0;
		putchar('\n');
		printf("Retype password:"); fflush(stdout);
		len2 = read(0, p2, sizeof(p2)-1);
		if (--len2 < 0) goto bad;
		p2[len2] = 0;
		putchar('\n');
		if ((len1 != len2) || (strcmp(p1, p2))) {
		bad:
			printf("Sorry, passwords do not match\n");
			continue;
		}
		break;
	}
        tcsetattr(0, TCSAFLUSH, &old);
	sha1_asm(hash, p1, len1);
}

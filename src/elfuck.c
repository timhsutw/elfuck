/*
 * $Id: elfuck.c, the main program, args parsing etc
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "elfuck.h"
#include "stubify.h"

void __stack_chk_fail(void) {}


int	usage(char *s)
{
	eprintf("%s [-bsl0123456789] input <output>\n"
		"\tb\tdon't include banner in header\n"
		"\ts\tscramble the file with polymorphic decryptor\n"
		"\tl\tlock the file by password\n"
		"\t1-9\tcompression level\n", s);
	return 1;
}

int	main(int argc, char *argv[])
{
	int	level = 9;
	char	*input;
	char	output[1024] = "output";
	int	i = 1;
	int	flags = 0;

	printf("%s\n", BANNER);

	/* parse args */
	if (argc < 2)
		return usage(argv[0]);

	/* arguments ? */
	if (argv[1][0] == '-') {
		int q;
		char *s = argv[1];

		i++;
		for (q = 1; q < strlen(s); q++) {
			if ((s[q] >= '1') && (s[q] <= '9')) {
				level = s[q] - '0';
				continue;
			}
			switch (s[q] & 0xdf) {
				case 'B':
					flags |= FLAG_NOBANNER;
					break;
				case 'S':
					flags |= FLAG_SCRAMBLE;
					break;
				case 'L':
					flags |= FLAG_LOCK;
					break;
				default:
					return usage(argv[0]);
			}
		}
	}

	if (argc <= i)
		return usage(argv[0]);
	input = argv[i];
	i++;
	if (i < argc) {
		strncpy(output, argv[i], sizeof(output)-1);
		output[sizeof(output)-1] = 0;
	}
	return pack_elf(input, output, abs(level), flags);
}

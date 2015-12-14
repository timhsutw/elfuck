#ifndef EXECELF_H
#define EXECELF_H
extern void execelf(void);
extern void execelf_end(void);
extern void e_skip_interp(void);
extern void e_no_interp(void);
extern char execelf_interp[256];
#define EXECELF_SIZE ((unsigned) execelf_end - (unsigned) execelf)
#endif

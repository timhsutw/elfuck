/* nrv2e -- implementation of the NRV2E-99 compression algorithm

   This file was part of the UCL data compression library.

   Copyright (C) 1996-2002 Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   The UCL library is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   The UCL library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with the UCL library; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer
   <markus@oberhumer.com>
   http://www.oberhumer.com/opensource/ucl/
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/elf.h>
#include <string.h>
#include <sys/mman.h>

#include <limits.h>

//#include <assert.h>
#define assert(x)


#define ucl_memcpy memcpy
#define ucl_malloc malloc
#define ucl_alloc(x,y) malloc(x*y)
#define ucl_free free
#define ucl_memcmp memcmp
#define ucl_memset memset
#define ucl_sizeof(x) (sizeof(x))
#define UCL_PUBLIC(x) x

#define NRV2E
//#define __UCL_CHECKER

#define UCL_BYTE(x)       ((unsigned char) (x))
#define UCL_USHORT(x)     ((unsigned short) ((x) & 0xffff))
#define UCL_MAX(a,b)        ((a) >= (b) ? (a) : (b))
#define UCL_MIN(a,b)        ((a) <= (b) ? (a) : (b))
#define UCL_MAX3(a,b,c)     ((a) >= (b) ? UCL_MAX(a,c) : UCL_MAX(b,c))
#define UCL_MIN3(a,b,c)     ((a) <= (b) ? UCL_MIN(a,c) : UCL_MIN(b,c))


#define UCL_E_OK                    0
#define UCL_E_ERROR                 (-1)
#define UCL_E_INVALID_ARGUMENT      (-2)
#define UCL_E_OUT_OF_MEMORY         (-3)
/* compression errors */
#define UCL_E_NOT_COMPRESSIBLE      (-101)
/* decompression errors */
#define UCL_E_INPUT_OVERRUN         (-201)
#define UCL_E_OUTPUT_OVERRUN        (-202)
#define UCL_E_LOOKBEHIND_OVERRUN    (-203)
#define UCL_E_EOF_NOT_FOUND         (-204)
#define UCL_E_INPUT_NOT_CONSUMED    (-205)
#define UCL_E_OVERLAP_OVERRUN       (-206)

typedef unsigned int ucl_uint32;
typedef int ucl_int32;
#define UCL_UINT32_MAX      0xffffffffUL
#define UCL_INT32_MAX       INT_MAX
#define UCL_INT32_MIN       INT_MIN
typedef unsigned int ucl_uint;
typedef int ucl_int;
#define UCL_UINT_MAX        UINT_MAX
#define UCL_INT_MAX         INT_MAX
#define UCL_INT_MIN         INT_MIN
#define UCL_UINT32_C(c)     c ## UL
#define UCL_UNUSED(x)	    x = x


struct ucl_compress_config_t {
	int     bb_endian;
	int     bb_size;
	ucl_uint max_offset;
	ucl_uint max_match;
	int     s_level;
	int     h_level;
	int     p_level;
	int     c_flags;
	ucl_uint m_size;
};
#define ucl_compress_config_p   ucl_compress_config_t *

#define ucl_byte                unsigned char
#define ucl_bytep               unsigned char *
#define ucl_charp               char *
#define ucl_voidp               void *
#define ucl_shortp              short *
#define ucl_ushortp             unsigned short *
#define ucl_uint32p             ucl_uint32 *
#define ucl_int32p              ucl_int32 *
#define ucl_uintp               ucl_uint *
#define ucl_intp                ucl_int *
#define ucl_voidpp              ucl_voidp *
#define ucl_bytepp              ucl_bytep *
#define ucl_bool		int

/* a progress indicator callback function */
typedef struct {
	void    (*callback) (ucl_uint, ucl_uint, int, ucl_voidp user);
	ucl_voidp user;
} ucl_progress_callback_t;
#define ucl_progress_callback_p ucl_progress_callback_t *


#define N       (1024*1024ul)	/* size of ring buffer */
//#define SWD_USE_MALLOC
#define SWD_HSIZE   65536ul

#if 1
#define THRESHOLD       1	/* lower limit for match length */
#define F            16384	/* upper limit for match length */
#else
#define THRESHOLD       1	/* lower limit for match length */
#define F            2048	/* upper limit for match length */
#endif

#define UCL_COMPRESS_T          ucl_nrv2e_t
#define ucl_swd_t               ucl_nrv2e_swd_t
#define ucl_nrv_99_compress     ucl_nrv2e_99_compress
#define M2_MAX_OFFSET           0x500
#define ucl_swd_p		ucl_swd_t *

typedef struct {
	int     init;

	ucl_uint look;		/* bytes in lookahead buffer */

	ucl_uint m_len;
	ucl_uint m_off;

	ucl_uint last_m_len;
	ucl_uint last_m_off;

	const ucl_byte *bp;
	const ucl_byte *ip;
	const ucl_byte *in;
	const ucl_byte *in_end;
	ucl_byte *out;

	ucl_uint32 bb_b;
	unsigned bb_k;
	unsigned bb_c_endian;
	unsigned bb_c_s;
	unsigned bb_c_s8;
	ucl_byte *bb_p;
	ucl_byte *bb_op;

	struct ucl_compress_config_t conf;
	ucl_uintp result;

	ucl_progress_callback_p cb;

	ucl_uint textsize;	/* text size counter */
	ucl_uint codesize;	/* code size counter */
	ucl_uint printcount;	/* counter for reporting progress every 1K bytes */

	/* some stats */
	unsigned long lit_bytes;
	unsigned long match_bytes;
	unsigned long rep_bytes;
	unsigned long lazy;
} UCL_COMPRESS_T;

#define getbyte(c)  ((c).ip < (c).in_end ? *((c).ip)++ : (-1))

#ifndef SWD_N
#  define SWD_N             N
#endif
#ifndef SWD_F
#  define SWD_F             F
#endif
#ifndef SWD_THRESHOLD
#  define SWD_THRESHOLD     THRESHOLD
#endif

/* unsigned type for dictionary access - don't waste memory here */
#if (SWD_N + SWD_F + SWD_F < USHRT_MAX)
typedef unsigned short swd_uint;
#  define SWD_UINT_MAX      USHRT_MAX
#else
typedef ucl_uint swd_uint;
#  define SWD_UINT_MAX      UCL_UINT_MAX
#endif
#define SWD_UINT(x)         ((swd_uint)(x))


#ifndef SWD_HSIZE
#  define SWD_HSIZE         16384
#endif
#ifndef SWD_MAX_CHAIN
#  define SWD_MAX_CHAIN     2048
#endif

#if !defined(HEAD3)
#if 1
#  define HEAD3(b,p) \
    (((0x9f5f*(((((ucl_uint32)b[p]<<5)^b[p+1])<<5)^b[p+2]))>>5) & (SWD_HSIZE-1))
#else
#  define HEAD3(b,p) \
    (((0x9f5f*(((((ucl_uint32)b[p+2]<<5)^b[p+1])<<5)^b[p]))>>5) & (SWD_HSIZE-1))
#endif
#endif

#if (SWD_THRESHOLD == 1) && !defined(HEAD2)
#  if 1 && defined(UCL_UNALIGNED_OK_2)
#    define HEAD2(b,p)      (* (const ucl_ushortp) &(b[p]))
#  else
#    define HEAD2(b,p)      (b[p] ^ ((unsigned)b[p+1]<<8))
#  endif
#  define NIL2              SWD_UINT_MAX
#endif


#if defined(__UCL_CHECKER)
   /* malloc arrays of the exact size to detect any overrun */
#  ifndef SWD_USE_MALLOC
#    define SWD_USE_MALLOC
#  endif
#endif


typedef struct {
/* public - "built-in" */
	ucl_uint n;
	ucl_uint f;
	ucl_uint threshold;

/* public - configuration */
	ucl_uint max_chain;
	ucl_uint nice_length;
	ucl_bool use_best_off;
	ucl_uint lazy_insert;

/* public - output */
	ucl_uint m_len;
	ucl_uint m_off;
	ucl_uint look;
	int     b_char;
#if defined(SWD_BEST_OFF)
	ucl_uint best_off[SWD_BEST_OFF];
#endif

/* semi public */
	UCL_COMPRESS_T *c;
	ucl_uint m_pos;
#if defined(SWD_BEST_OFF)
	ucl_uint best_pos[SWD_BEST_OFF];
#endif

/* private */
	const ucl_byte *dict;
	const ucl_byte *dict_end;
	ucl_uint dict_len;

/* private */
	ucl_uint ip;		/* input pointer (lookahead) */
	ucl_uint bp;		/* buffer pointer */
	ucl_uint rp;		/* remove pointer */
	ucl_uint b_size;

	unsigned char *b_wrap;

	ucl_uint node_count;
	ucl_uint first_rp;

#if defined(SWD_USE_MALLOC)
	unsigned char *b;
	swd_uint *head3;
	swd_uint *succ3;
	swd_uint *best3;
	swd_uint *llen3;
#ifdef HEAD2
	swd_uint *head2;
#endif
#else
	unsigned char b[SWD_N + SWD_F + SWD_F];
	swd_uint head3[SWD_HSIZE];
	swd_uint succ3[SWD_N + SWD_F];
	swd_uint best3[SWD_N + SWD_F];
	swd_uint llen3[SWD_HSIZE];
#ifdef HEAD2
	swd_uint head2[UCL_UINT32_C(65536)];
#endif
#endif
} ucl_swd_t;


/* Access macro for head3.
 * head3[key] may be uninitialized if the list is emtpy,
 * but then its value will never be used.
 */
#if defined(__UCL_CHECKER)
#  define s_head3(s,key) \
        ((s->llen3[key] == 0) ? SWD_UINT_MAX : s->head3[key])
#else
#  define s_head3(s,key)        s->head3[key]
#endif


/***********************************************************************
//
************************************************************************/

static
void    swd_initdict(ucl_swd_t * s, const ucl_byte * dict,
		     ucl_uint dict_len)
{
	s->dict = s->dict_end = NULL;
	s->dict_len = 0;

	if (!dict || dict_len <= 0)
		return;
	if (dict_len > s->n) {
		dict += dict_len - s->n;
		dict_len = s->n;
	}

	s->dict = dict;
	s->dict_len = dict_len;
	s->dict_end = dict + dict_len;
	ucl_memcpy(s->b, dict, dict_len);
	s->ip = dict_len;
}


static
void    swd_insertdict(ucl_swd_t * s, ucl_uint node, ucl_uint len)
{
	ucl_uint key;

	s->node_count = s->n - len;
	s->first_rp = node;

	while (len-- > 0) {
		key = HEAD3(s->b, node);
		s->succ3[node] = s_head3(s, key);
		s->head3[key] = SWD_UINT(node);
		s->best3[node] = SWD_UINT(s->f + 1);
		s->llen3[key]++;
		assert(s->llen3[key] <= s->n);

#ifdef HEAD2
		key = HEAD2(s->b, node);
		s->head2[key] = SWD_UINT(node);
#endif

		node++;
	}
}


/***********************************************************************
//
************************************************************************/

static
int     swd_init(ucl_swd_t * s, const ucl_byte * dict, ucl_uint dict_len)
{
	ucl_uint i = 0;
	int     c = 0;

	if (s->n == 0)
		s->n = SWD_N;
	if (s->f == 0)
		s->f = SWD_F;
	s->threshold = SWD_THRESHOLD;
	if (s->n > SWD_N || s->f > SWD_F)
		return UCL_E_INVALID_ARGUMENT;

#if defined(SWD_USE_MALLOC)
	s->b = (unsigned char *) ucl_alloc(s->n + s->f + s->f, 1);
	s->head3 = (swd_uint *) ucl_alloc(SWD_HSIZE, sizeof(*s->head3));
	s->succ3 = (swd_uint *) ucl_alloc(s->n + s->f, sizeof(*s->succ3));
	s->best3 = (swd_uint *) ucl_alloc(s->n + s->f, sizeof(*s->best3));
	s->llen3 = (swd_uint *) ucl_alloc(SWD_HSIZE, sizeof(*s->llen3));
	if (!s->b || !s->head3 || !s->succ3 || !s->best3 || !s->llen3)
		return UCL_E_OUT_OF_MEMORY;
#ifdef HEAD2
	s->head2 =
	    (swd_uint *) ucl_alloc(UCL_UINT32_C(65536), sizeof(*s->head2));
	if (!s->head2)
		return UCL_E_OUT_OF_MEMORY;
#endif
#endif

	/* defaults */
	s->max_chain = SWD_MAX_CHAIN;
	s->nice_length = s->f;
	s->use_best_off = 0;
	s->lazy_insert = 0;

	s->b_size = s->n + s->f;
	if (s->b_size + s->f >= SWD_UINT_MAX)
		return UCL_E_ERROR;
	s->b_wrap = s->b + s->b_size;
	s->node_count = s->n;

	ucl_memset(s->llen3, 0, sizeof(s->llen3[0]) * SWD_HSIZE);
#ifdef HEAD2
#if 1
	ucl_memset(s->head2, 0xff,
		   sizeof(s->head2[0]) * UCL_UINT32_C(65536));
	assert(s->head2[0] == NIL2);
#else
	for (i = 0; i < UCL_UINT32_C(65536); i++)
		s->head2[i] = NIL2;
#endif
#endif

	s->ip = 0;
	swd_initdict(s, dict, dict_len);
	s->bp = s->ip;
	s->first_rp = s->ip;

	assert(s->ip + s->f <= s->b_size);
#if 1
	s->look = (ucl_uint) (s->c->in_end - s->c->ip);
	if (s->look > 0) {
		if (s->look > s->f)
			s->look = s->f;
		ucl_memcpy(&s->b[s->ip], s->c->ip, s->look);
		s->c->ip += s->look;
		s->ip += s->look;
	}
#else
	s->look = 0;
	while (s->look < s->f) {
		if ((c = getbyte(*(s->c))) < 0)
			break;
		s->b[s->ip] = UCL_BYTE(c);
		s->ip++;
		s->look++;
	}
#endif
	if (s->ip == s->b_size)
		s->ip = 0;

	if (s->look >= 2 && s->dict_len > 0)
		swd_insertdict(s, 0, s->dict_len);

	s->rp = s->first_rp;
	if (s->rp >= s->node_count)
		s->rp -= s->node_count;
	else
		s->rp += s->b_size - s->node_count;

#if defined(__UCL_CHECKER)
	/* initialize memory for the first few HEAD3 (if s->ip is not far
	 * enough ahead to do this job for us). The value doesn't matter. */
	if (s->look < 3)
		ucl_memset(&s->b[s->bp + s->look], 0, 3);
#endif

	UCL_UNUSED(i);
	UCL_UNUSED(c);
	return UCL_E_OK;
}


static
void    swd_exit(ucl_swd_t * s)
{
#if defined(SWD_USE_MALLOC)
	/* free in reverse order of allocations */
#ifdef HEAD2
	ucl_free(s->head2);
	s->head2 = NULL;
#endif
	ucl_free(s->llen3);
	s->llen3 = NULL;
	ucl_free(s->best3);
	s->best3 = NULL;
	ucl_free(s->succ3);
	s->succ3 = NULL;
	ucl_free(s->head3);
	s->head3 = NULL;
	ucl_free(s->b);
	s->b = NULL;
#else
	UCL_UNUSED(s);
#endif
}


#define swd_pos2off(s,pos) \
    (s->bp > (pos) ? s->bp - (pos) : s->b_size - ((pos) - s->bp))


/***********************************************************************
//
************************************************************************/

static __inline__ void swd_getbyte(ucl_swd_t * s)
{
	int     c;

	if ((c = getbyte(*(s->c))) < 0) {
		if (s->look > 0)
			--s->look;
#if defined(__UCL_CHECKER)
		/* initialize memory - value doesn't matter */
		s->b[s->ip] = 0;
		if (s->ip < s->f)
			s->b_wrap[s->ip] = 0;
#endif
	} else {
		s->b[s->ip] = UCL_BYTE(c);
		if (s->ip < s->f)
			s->b_wrap[s->ip] = UCL_BYTE(c);
	}
	if (++s->ip == s->b_size)
		s->ip = 0;
	if (++s->bp == s->b_size)
		s->bp = 0;
	if (++s->rp == s->b_size)
		s->rp = 0;
}


/***********************************************************************
// remove node from lists
************************************************************************/

static __inline__ void swd_remove_node(ucl_swd_t * s, ucl_uint node)
{
	if (s->node_count == 0) {
		ucl_uint key;

#ifdef UCL_DEBUG
		if (s->first_rp != UCL_UINT_MAX) {
			if (node != s->first_rp)
				printf
				    ("Remove %5d: %5d %5d %5d %5d  %6d %6d\n",
				     node, s->rp, s->ip, s->bp,
				     s->first_rp, s->ip - node,
				     s->ip - s->bp);
			assert(node == s->first_rp);
			s->first_rp = UCL_UINT_MAX;
		}
#endif

		key = HEAD3(s->b, node);
		assert(s->llen3[key] > 0);
		--s->llen3[key];

#ifdef HEAD2
		key = HEAD2(s->b, node);
		assert(s->head2[key] != NIL2);
		if ((ucl_uint) s->head2[key] == node)
			s->head2[key] = NIL2;
#endif
	} else
		--s->node_count;
}


/***********************************************************************
//
************************************************************************/

static
void    swd_accept(ucl_swd_t * s, ucl_uint n)
{
	assert(n <= s->look);

	if (n > 0)
		do {
			ucl_uint key;

			swd_remove_node(s, s->rp);

			/* add bp into HEAD3 */
			key = HEAD3(s->b, s->bp);
			s->succ3[s->bp] = s_head3(s, key);
			s->head3[key] = SWD_UINT(s->bp);
			s->best3[s->bp] = SWD_UINT(s->f + 1);
			s->llen3[key]++;
			assert(s->llen3[key] <= s->n);

#ifdef HEAD2
			/* add bp into HEAD2 */
			key = HEAD2(s->b, s->bp);
			s->head2[key] = SWD_UINT(s->bp);
#endif

			swd_getbyte(s);
		} while (--n > 0);
}


/***********************************************************************
//
************************************************************************/

static
void    swd_search(ucl_swd_t * s, ucl_uint node, ucl_uint cnt)
{
#if 0 && defined(__GNUC__) && defined(__i386__)
	register const unsigned char *p1 __asm__("%edi");
	register const unsigned char *p2 __asm__("%esi");
	register const unsigned char *px __asm__("%edx");
#else
	const unsigned char *p1;
	const unsigned char *p2;
	const unsigned char *px;
#endif
	ucl_uint m_len = s->m_len;
	const unsigned char *b = s->b;
	const unsigned char *bp = s->b + s->bp;
	const unsigned char *bx = s->b + s->bp + s->look;
	unsigned char scan_end1;

	assert(s->m_len > 0);

	scan_end1 = bp[m_len - 1];
	for (; cnt-- > 0; node = s->succ3[node]) {
		p1 = bp;
		p2 = b + node;
		px = bx;

		assert(m_len < s->look);

		if (
#if 1
			   p2[m_len - 1] == scan_end1 &&
			   p2[m_len] == p1[m_len] &&
#endif
			   p2[0] == p1[0] && p2[1] == p1[1]) {
			ucl_uint i;
			assert(ucl_memcmp(bp, &b[node], 3) == 0);

#if 0 && defined(UCL_UNALIGNED_OK_4)
			p1 += 3;
			p2 += 3;
			while (p1 < px
			       && *(const ucl_uint32p) p1 ==
			       *(const ucl_uint32p) p2)
				p1 += 4, p2 += 4;
			while (p1 < px && *p1 == *p2)
				p1 += 1, p2 += 1;
#else
			p1 += 2;
			p2 += 2;
			do {
			} while (++p1 < px && *p1 == *++p2);
#endif
			i = p1 - bp;

#ifdef UCL_DEBUG
			if (ucl_memcmp(bp, &b[node], i) != 0)
				printf("%5ld %5ld %02x%02x %02x%02x\n",
				       (long) s->bp, (long) node,
				       bp[0], bp[1], b[node], b[node + 1]);
#endif
			assert(ucl_memcmp(bp, &b[node], i) == 0);

#if defined(SWD_BEST_OFF)
			if (i < SWD_BEST_OFF) {
				if (s->best_pos[i] == 0)
					s->best_pos[i] = node + 1;
			}
#endif
			if (i > m_len) {
				s->m_len = m_len = i;
				s->m_pos = node;
				if (m_len == s->look)
					return;
				if (m_len >= s->nice_length)
					return;
				if (m_len > (ucl_uint) s->best3[node])
					return;
				scan_end1 = bp[m_len - 1];
			}
		}
	}
}


/***********************************************************************
//
************************************************************************/

#ifdef HEAD2

static
ucl_bool swd_search2(ucl_swd_t * s)
{
	ucl_uint key;

	assert(s->look >= 2);
	assert(s->m_len > 0);

	key = s->head2[HEAD2(s->b, s->bp)];
	if (key == NIL2)
		return 0;
#ifdef UCL_DEBUG
	if (ucl_memcmp(&s->b[s->bp], &s->b[key], 2) != 0)
		printf("%5ld %5ld %02x%02x %02x%02x\n", (long) s->bp,
		       (long) key, s->b[s->bp], s->b[s->bp + 1], s->b[key],
		       s->b[key + 1]);
#endif
	assert(ucl_memcmp(&s->b[s->bp], &s->b[key], 2) == 0);
#if defined(SWD_BEST_OFF)
	if (s->best_pos[2] == 0)
		s->best_pos[2] = key + 1;
#endif

	if (s->m_len < 2) {
		s->m_len = 2;
		s->m_pos = key;
	}
	return 1;
}

#endif


/***********************************************************************
//
************************************************************************/

static
void    swd_findbest(ucl_swd_t * s)
{
	ucl_uint key;
	ucl_uint cnt, node;
	ucl_uint len;

	assert(s->m_len > 0);

	/* get current head, add bp into HEAD3 */
	key = HEAD3(s->b, s->bp);
	node = s->succ3[s->bp] = s_head3(s, key);
	cnt = s->llen3[key]++;
	assert(s->llen3[key] <= s->n + s->f);
	if (cnt > s->max_chain && s->max_chain > 0)
		cnt = s->max_chain;
	s->head3[key] = SWD_UINT(s->bp);

	s->b_char = s->b[s->bp];
	len = s->m_len;
	if (s->m_len >= s->look) {
		if (s->look == 0)
			s->b_char = -1;
		s->m_off = 0;
		s->best3[s->bp] = SWD_UINT(s->f + 1);
	} else {
#ifdef HEAD2
		if (swd_search2(s))
#endif
			if (s->look >= 3)
				swd_search(s, node, cnt);
		if (s->m_len > len)
			s->m_off = swd_pos2off(s, s->m_pos);
		s->best3[s->bp] = SWD_UINT(s->m_len);

#if defined(SWD_BEST_OFF)
		if (s->use_best_off) {
			int     i;
			for (i = 2; i < SWD_BEST_OFF; i++)
				if (s->best_pos[i] > 0)
					s->best_off[i] =
					    swd_pos2off(s,
							s->best_pos[i] -
							1);
				else
					s->best_off[i] = 0;
		}
#endif
	}

	swd_remove_node(s, s->rp);

#ifdef HEAD2
	/* add bp into HEAD2 */
	key = HEAD2(s->b, s->bp);
	s->head2[key] = SWD_UINT(s->bp);
#endif
}


#undef HEAD3
#undef HEAD2
#undef s_head3


/***********************************************************************
//
************************************************************************/

static int
init_match(UCL_COMPRESS_T * c, ucl_swd_t * s,
	   const ucl_byte * dict, ucl_uint dict_len, ucl_uint32 flags)
{
	int     r;

	assert(!c->init);
	c->init = 1;

	s->c = c;

	c->last_m_len = c->last_m_off = 0;

	c->textsize = c->codesize = c->printcount = 0;
	c->lit_bytes = c->match_bytes = c->rep_bytes = 0;
	c->lazy = 0;

	r = swd_init(s, dict, dict_len);
	if (r != UCL_E_OK) {
		swd_exit(s);
		return r;
	}

	s->use_best_off = (flags & 1) ? 1 : 0;
	return UCL_E_OK;
}


/***********************************************************************
//
************************************************************************/

static int
find_match(UCL_COMPRESS_T * c, ucl_swd_t * s,
	   ucl_uint this_len, ucl_uint skip)
{
	assert(c->init);

	if (skip > 0) {
		assert(this_len >= skip);
		swd_accept(s, this_len - skip);
		c->textsize += this_len - skip + 1;
	} else {
		assert(this_len <= 1);
		c->textsize += this_len - skip;
	}

	s->m_len = THRESHOLD;
#ifdef SWD_BEST_OFF
	if (s->use_best_off)
		memset(s->best_pos, 0, sizeof(s->best_pos));
#endif
	swd_findbest(s);
	c->m_len = s->m_len;
#if defined(__UCL_CHECKER)
	/* s->m_off may be uninitialized if we didn't find a match,
	 * but then its value will never be used.
	 */
	c->m_off = (s->m_len == THRESHOLD) ? 0 : s->m_off;
#else
	c->m_off = s->m_off;
#endif

	swd_getbyte(s);

	if (s->b_char < 0) {
		c->look = 0;
		c->m_len = 0;
		swd_exit(s);
	} else {
		c->look = s->look + 1;
	}
	c->bp = c->ip - c->look;

#if 0
	/* brute force match search */
	if (c->m_len > THRESHOLD && c->m_len + 1 <= c->look) {
		const ucl_byte *ip = c->bp;
		const ucl_byte *m = c->bp - c->m_off;
		const ucl_byte *in = c->in;

		if (ip - in > N)
			in = ip - N;
		for (;;) {
			while (*in != *ip)
				in++;
			if (in == ip)
				break;
			if (in != m)
				if (memcmp(in, ip, c->m_len + 1) == 0)
					printf("%p %p %p %5d\n", in, ip, m,
					       c->m_len);
			in++;
		}
	}
#endif

	if (c->cb && c->textsize > c->printcount) {
		(*c->cb->callback) (c->textsize, c->codesize, 3, c->cb->user);
		c->printcount += 1024;
	}

	return UCL_E_OK;
}


/***********************************************************************
// bit buffer
************************************************************************/

static int bbConfig(UCL_COMPRESS_T * c, int endian, int bitsize)
{
	if (endian != -1) {
		if (endian != 0)
			return UCL_E_ERROR;
		c->bb_c_endian = endian;
	}
	if (bitsize != -1) {
		if (bitsize != 8 && bitsize != 16 && bitsize != 32)
			return UCL_E_ERROR;
		c->bb_c_s = bitsize;
		c->bb_c_s8 = bitsize / 8;
	}
	c->bb_b = 0;
	c->bb_k = 0;
	c->bb_p = NULL;
	c->bb_op = NULL;
	return UCL_E_OK;
}


static void bbWriteBits(UCL_COMPRESS_T * c)
{
	ucl_byte *p = c->bb_p;
	ucl_uint32 b = c->bb_b;

	p[0] = UCL_BYTE(b >> 0);
	if (c->bb_c_s >= 16) {
		p[1] = UCL_BYTE(b >> 8);
		if (c->bb_c_s == 32) {
			p[2] = UCL_BYTE(b >> 16);
			p[3] = UCL_BYTE(b >> 24);
		}
	}
}


static void bbPutBit(UCL_COMPRESS_T * c, unsigned bit)
{
	assert(bit == 0 || bit == 1);
	assert(c->bb_k <= c->bb_c_s);

	if (c->bb_k < c->bb_c_s) {
		if (c->bb_k == 0) {
			assert(c->bb_p == NULL);
			c->bb_p = c->bb_op;
			c->bb_op += c->bb_c_s8;
		}
		assert(c->bb_p != NULL);
		assert(c->bb_p + c->bb_c_s8 <= c->bb_op);

		c->bb_b = (c->bb_b << 1) + bit;
		c->bb_k++;
	} else {
		assert(c->bb_p != NULL);
		assert(c->bb_p + c->bb_c_s8 <= c->bb_op);

		bbWriteBits(c);
		c->bb_p = c->bb_op;
		c->bb_op += c->bb_c_s8;
		c->bb_b = bit;
		c->bb_k = 1;
	}
}


static void bbPutByte(UCL_COMPRESS_T * c, unsigned b)
{
    /**printf("putbyte %p %p %x  (%d)\n", op, bb_p, x, bb_k);*/
	assert(c->bb_p == NULL || c->bb_p + c->bb_c_s8 <= c->bb_op);
	*c->bb_op++ = UCL_BYTE(b);
}


static void bbFlushBits(UCL_COMPRESS_T * c, unsigned filler_bit)
{
	if (c->bb_k > 0) {
		assert(c->bb_k <= c->bb_c_s);
		while (c->bb_k != c->bb_c_s)
			bbPutBit(c, filler_bit);
		bbWriteBits(c);
		c->bb_k = 0;
	}
	c->bb_p = NULL;
}



/***********************************************************************
//
************************************************************************/

static void code_prefix_ss11(UCL_COMPRESS_T * c, ucl_uint32 i)
{
	if (i >= 2) {
		ucl_uint32 t = 4;
		i += 2;
		do {
			t <<= 1;
		} while (i >= t);
		t >>= 1;
		do {
			t >>= 1;
			bbPutBit(c, (i & t) ? 1 : 0);
			bbPutBit(c, 0);
		} while (t > 2);
	}
	bbPutBit(c, (unsigned) i & 1);
	bbPutBit(c, 1);
}


#if defined(NRV2D) || defined(NRV2E)
static void code_prefix_ss12(UCL_COMPRESS_T * c, ucl_uint32 i)
{
	if (i >= 2) {
		ucl_uint32 t = 2;
		do {
			i -= t;
			t <<= 2;
		} while (i >= t);
		do {
			t >>= 1;
			bbPutBit(c, (i & t) ? 1 : 0);
			bbPutBit(c, 0);
			t >>= 1;
			bbPutBit(c, (i & t) ? 1 : 0);
		} while (t > 2);
	}
	bbPutBit(c, (unsigned) i & 1);
	bbPutBit(c, 1);
}
#endif


static void
code_match(UCL_COMPRESS_T * c, ucl_uint m_len, const ucl_uint m_off)
{
	unsigned m_low = 0;

	while (m_len > c->conf.max_match) {
		code_match(c, c->conf.max_match - 3, m_off);
		m_len -= c->conf.max_match - 3;
	}

	c->match_bytes += m_len;
	if (m_len > c->result[3])
		c->result[3] = m_len;
	if (m_off > c->result[1])
		c->result[1] = m_off;

	bbPutBit(c, 0);

#if defined(NRV2B)
	if (m_off == c->last_m_off) {
		bbPutBit(c, 0);
		bbPutBit(c, 1);
	} else {
		code_prefix_ss11(c, 1 + ((m_off - 1) >> 8));
		bbPutByte(c, (unsigned) m_off - 1);
	}
	m_len = m_len - 1 - (m_off > M2_MAX_OFFSET);
	if (m_len >= 4) {
		bbPutBit(c, 0);
		bbPutBit(c, 0);
		code_prefix_ss11(c, m_len - 4);
	} else {
		bbPutBit(c, m_len > 1);
		bbPutBit(c, (unsigned) m_len & 1);
	}
#elif defined(NRV2D)
	m_len = m_len - 1 - (m_off > M2_MAX_OFFSET);
	assert(m_len > 0);
	m_low = (m_len >= 4) ? 0u : (unsigned) m_len;
	if (m_off == c->last_m_off) {
		bbPutBit(c, 0);
		bbPutBit(c, 1);
		bbPutBit(c, m_low > 1);
		bbPutBit(c, m_low & 1);
	} else {
		code_prefix_ss12(c, 1 + ((m_off - 1) >> 7));
		bbPutByte(c,
			  ((((unsigned) m_off - 1) & 0x7f) << 1) |
			  ((m_low > 1) ? 0 : 1));
		bbPutBit(c, m_low & 1);
	}
	if (m_len >= 4)
		code_prefix_ss11(c, m_len - 4);
#elif defined(NRV2E)
	m_len = m_len - 1 - (m_off > M2_MAX_OFFSET);
	assert(m_len > 0);
	m_low = (m_len <= 2);
	if (m_off == c->last_m_off) {
		bbPutBit(c, 0);
		bbPutBit(c, 1);
		bbPutBit(c, m_low);
	} else {
		code_prefix_ss12(c, 1 + ((m_off - 1) >> 7));
		bbPutByte(c,
			  ((((unsigned) m_off - 1) & 0x7f) << 1) | (m_low ^
								    1));
	}
	if (m_low)
		bbPutBit(c, (unsigned) m_len - 1);
	else if (m_len <= 4) {
		bbPutBit(c, 1);
		bbPutBit(c, (unsigned) m_len - 3);
	} else {
		bbPutBit(c, 0);
		code_prefix_ss11(c, m_len - 5);
	}
#else
#  error
#endif

	c->last_m_off = m_off;
	UCL_UNUSED(m_low);
}


static void code_run(UCL_COMPRESS_T * c, const ucl_byte * ii, ucl_uint lit)
{
	if (lit == 0)
		return;
	c->lit_bytes += lit;
	if (lit > c->result[5])
		c->result[5] = lit;
	do {
		bbPutBit(c, 1);
		bbPutByte(c, *ii++);
	} while (--lit > 0);
}


/***********************************************************************
//
************************************************************************/

static int
len_of_coded_match(UCL_COMPRESS_T * c, ucl_uint m_len, ucl_uint m_off)
{
	int     b;
	if (m_len < 2 || (m_len == 2 && (m_off > M2_MAX_OFFSET))
	    || m_off > c->conf.max_offset)
		return -1;
	assert(m_off > 0);

	m_len = m_len - 2 - (m_off > M2_MAX_OFFSET);

	if (m_off == c->last_m_off)
		b = 1 + 2;
	else {
#if defined(NRV2B)
		b = 1 + 10;
		m_off = (m_off - 1) >> 8;
		while (m_off > 0) {
			b += 2;
			m_off >>= 1;
		}
#elif defined(NRV2D) || defined(NRV2E)
		b = 1 + 9;
		m_off = (m_off - 1) >> 7;
		while (m_off > 0) {
			b += 3;
			m_off >>= 2;
		}
#else
#  error
#endif
	}

#if defined(NRV2B) || defined(NRV2D)
	b += 2;
	if (m_len < 3)
		return b;
	m_len -= 3;
#elif defined(NRV2E)
	b += 2;
	if (m_len < 2)
		return b;
	if (m_len < 4)
		return b + 1;
	m_len -= 4;
#else
#  error
#endif
	do {
		b += 2;
		m_len >>= 1;
	} while (m_len > 0);

	return b;
}


/***********************************************************************
//
************************************************************************/

#if !defined(NDEBUG)
static
void    assert_match(const ucl_swd_p swd, ucl_uint m_len, ucl_uint m_off)
{
	const UCL_COMPRESS_T *c = swd->c;
	ucl_uint d_off;

	assert(m_len >= 2);
	if (m_off <= (ucl_uint) (c->bp - c->in)) {
		assert(c->bp - m_off + m_len < c->ip);
		assert(ucl_memcmp(c->bp, c->bp - m_off, m_len) == 0);
	} else {
		assert(swd->dict != NULL);
		d_off = m_off - (ucl_uint) (c->bp - c->in);
		assert(d_off <= swd->dict_len);
		if (m_len > d_off) {
			assert(ucl_memcmp
			       (c->bp, swd->dict_end - d_off, d_off) == 0);
			assert(c->in + m_len - d_off < c->ip);
			assert(ucl_memcmp
			       (c->bp + d_off, c->in, m_len - d_off) == 0);
		} else {
			assert(ucl_memcmp
			       (c->bp, swd->dict_end - d_off, m_len) == 0);
		}
	}
}
#else
#  define assert_match(a,b,c)   ((void)0)
#endif


#if defined(SWD_BEST_OFF)

static void
better_match(const ucl_swd_p swd, ucl_uint * m_len, ucl_uint * m_off)
{
}

#endif


/***********************************************************************
//
************************************************************************/

UCL_PUBLIC(int)
ucl_nrv_99_compress(const ucl_bytep in, ucl_uint in_len,
		    ucl_bytep out, ucl_uintp out_len,
		    ucl_progress_callback_p cb,
		    int level,
		    const struct ucl_compress_config_p conf,
		    ucl_uintp result)
{
	const ucl_byte *ii;
	ucl_uint lit;
	ucl_uint m_len, m_off;
	UCL_COMPRESS_T c_buffer;
	UCL_COMPRESS_T *const c = &c_buffer;
#undef swd
#if 1 && defined(SWD_USE_MALLOC)
	ucl_swd_t the_swd;
#   define swd (&the_swd)
#else
	ucl_swd_p swd;
#endif
	ucl_uint result_buffer[16];
	int     r;

	struct swd_config_t {
		unsigned try_lazy;
		ucl_uint good_length;
		ucl_uint max_lazy;
		ucl_uint nice_length;
		ucl_uint max_chain;
		ucl_uint32 flags;
		ucl_uint32 max_offset;
	};
	const struct swd_config_t *sc;
	static const struct swd_config_t swd_config[10] = {
		/* faster compression */
		{0, 0, 0, 8, 4, 0, 48 * 1024L},
		{0, 0, 0, 16, 8, 0, 48 * 1024L},
		{0, 0, 0, 32, 16, 0, 48 * 1024L},
		{1, 4, 4, 16, 16, 0, 48 * 1024L},
		{1, 8, 16, 32, 32, 0, 48 * 1024L},
		{1, 8, 16, 128, 128, 0, 48 * 1024L},
		{2, 8, 32, 128, 256, 0, 128 * 1024L},
		{2, 32, 128, F, 2048, 1, 128 * 1024L},
		{2, 32, 128, F, 2048, 1, 256 * 1024L},
		{2, F, F, F, 4096, 1, N}
		/* max. compression */
	};

	if (level < 1 || level > 10)
		return UCL_E_INVALID_ARGUMENT;
	sc = &swd_config[level - 1];

	memset(c, 0, sizeof(*c));
	c->ip = c->in = in;
	c->in_end = in + in_len;
	c->out = out;
	if (cb && cb->callback)
		c->cb = cb;
	cb = NULL;
	c->result = result ? result : (ucl_uintp) result_buffer;
	memset(c->result, 0, 16 * sizeof(*c->result));
	c->result[0] = c->result[2] = c->result[4] = UCL_UINT_MAX;
	result = NULL;
	memset(&c->conf, 0xff, sizeof(c->conf));
	if (conf)
		memcpy(&c->conf, conf, sizeof(c->conf));
	conf = NULL;
	r = bbConfig(c, 0, 8);
	if (r == 0)
		r = bbConfig(c, c->conf.bb_endian, c->conf.bb_size);
	if (r != 0)
		return UCL_E_INVALID_ARGUMENT;
	c->bb_op = out;

	ii = c->ip;	/* point to start of literal run */
	lit = 0;

#if !defined(swd)
	swd = (ucl_swd_p) ucl_alloc(1, ucl_sizeof(*swd));
	if (!swd)
		return UCL_E_OUT_OF_MEMORY;
#endif
	swd->f = UCL_MIN(F, c->conf.max_match);
	swd->n = UCL_MIN(N, sc->max_offset);
	if (c->conf.max_offset != UCL_UINT_MAX)
		swd->n = UCL_MIN(N, c->conf.max_offset);
	if (in_len >= 256 && in_len < swd->n)
		swd->n = in_len;
	if (swd->f < 8 || swd->n < 256)
		return UCL_E_INVALID_ARGUMENT;
	r = init_match(c, swd, NULL, 0, sc->flags);
	if (r != UCL_E_OK) {
#if !defined(swd)
		ucl_free(swd);
#endif
		return r;
	}
	if (sc->max_chain > 0)
		swd->max_chain = sc->max_chain;
	if (sc->nice_length > 0)
		swd->nice_length = sc->nice_length;
	if (c->conf.max_match < swd->nice_length)
		swd->nice_length = c->conf.max_match;

	if (c->cb)
		(*c->cb->callback) (0, 0, -1, c->cb->user);

	c->last_m_off = 1;
	r = find_match(c, swd, 0, 0);
	if (r != UCL_E_OK)
		return r;
	while (c->look > 0) {
		ucl_uint ahead;
		ucl_uint max_ahead;
		int     l1, l2;

		c->codesize = c->bb_op - out;

		m_len = c->m_len;
		m_off = c->m_off;

		assert(c->bp == c->ip - c->look);
		assert(c->bp >= in);
		if (lit == 0)
			ii = c->bp;
		assert(ii + lit == c->bp);
		assert(swd->b_char == *(c->bp));

		if (m_len < 2 || (m_len == 2 && (m_off > M2_MAX_OFFSET))
		    || m_off > c->conf.max_offset) {
			/* a literal */
			lit++;
			swd->max_chain = sc->max_chain;
			r = find_match(c, swd, 1, 0);
			assert(r == 0);
			continue;
		}

		/* a match */
#if defined(SWD_BEST_OFF)
		if (swd->use_best_off)
			better_match(swd, &m_len, &m_off);
#endif
		assert_match(swd, m_len, m_off);

		/* shall we try a lazy match ? */
		ahead = 0;
		if (sc->try_lazy <= 0 || m_len >= sc->max_lazy
		    || m_off == c->last_m_off) {
			/* no */
			l1 = 0;
			max_ahead = 0;
		} else {
			/* yes, try a lazy match */
			l1 = len_of_coded_match(c, m_len, m_off);
			assert(l1 > 0);
			max_ahead = UCL_MIN(sc->try_lazy, m_len - 1);
		}

		while (ahead < max_ahead && c->look > m_len) {
			if (m_len >= sc->good_length)
				swd->max_chain = sc->max_chain >> 2;
			else
				swd->max_chain = sc->max_chain;
			r = find_match(c, swd, 1, 0);
			ahead++;

			assert(r == 0);
			assert(c->look > 0);
			assert(ii + lit + ahead == c->bp);

			if (c->m_len < 2)
				continue;
#if defined(SWD_BEST_OFF)
			if (swd->use_best_off)
				better_match(swd, &c->m_len, &c->m_off);
#endif
			l2 = len_of_coded_match(c, c->m_len, c->m_off);
			if (l2 < 0)
				continue;
#if 1
			if (l1 + (int) (ahead + c->m_len - m_len) * 5 >
			    l2 + (int) (ahead) * 9)
#else
			if (l1 > l2)
#endif
			{
				c->lazy++;
				assert_match(swd, c->m_len, c->m_off);

#if 0
				if (l3 > 0) {
					/* code previous run */
					code_run(c, ii, lit);
					lit = 0;
					/* code shortened match */
					code_match(c, ahead, m_off);
				} else
#endif
				{
					lit += ahead;
					assert(ii + lit == c->bp);
				}
				goto lazy_match_done;
			}
		}

		assert(ii + lit + ahead == c->bp);

		/* 1 - code run */
		code_run(c, ii, lit);
		lit = 0;

		/* 2 - code match */
		code_match(c, m_len, m_off);
		swd->max_chain = sc->max_chain;
		r = find_match(c, swd, m_len, 1 + ahead);
		assert(r == 0);

	      lazy_match_done:;
	}

	/* store final run */
	code_run(c, ii, lit);

	/* EOF */
	bbPutBit(c, 0);
#if defined(NRV2B)
	code_prefix_ss11(c, UCL_UINT32_C(0x1000000));
	bbPutByte(c, 0xff);
#elif defined(NRV2D) || defined(NRV2E)
	code_prefix_ss12(c, UCL_UINT32_C(0x1000000));
	bbPutByte(c, 0xff);
#else
#  error
#endif
	bbFlushBits(c, 0);

	assert(c->textsize == in_len);
	c->codesize = c->bb_op - out;
	*out_len = c->bb_op - out;
	if (c->cb)
		(*c->cb->callback) (c->textsize, c->codesize, 4, c->cb->user);

#if 0
	printf("%7ld %7ld -> %7ld   %7ld %7ld   %ld  (max: %d %d %d)\n",
	       (long) c->textsize, (long) in_len, (long) c->codesize,
	       c->match_bytes, c->lit_bytes, c->lazy,
	       c->result[1], c->result[3], c->result[5]);
#endif
	assert(c->lit_bytes + c->match_bytes == in_len);

	swd_exit(swd);
#if !defined(swd)
	ucl_free(swd);
#endif
	return UCL_E_OK;
#undef swd
}


/*
vi:ts=4:et
*/

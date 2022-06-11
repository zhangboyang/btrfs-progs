/*
 * Copied from the kernel source code, include/linux/rslib.h and
 *     lib/reed_solomon/{reed_solomon.c, encode_rs.c, decode_rs.c}
 *
 * Removed unused code, while keeping modifications as few as possible.
 *
 */

// SPDX-License-Identifier: GPL-2.0
/*
 * Generic Reed Solomon encoder / decoder library
 *
 * Copyright (C) 2004 Thomas Gleixner (tglx@linutronix.de)
 *
 * Reed Solomon code lifted from reed solomon library written by Phil Karn
 * Copyright 2002 Phil Karn, KA9Q
 *
 * Description:
 *
 * The generic Reed Solomon library provides runtime configurable
 * encoding / decoding of RS codes.
 *
 * Each user must call init_rs to get a pointer to a rs_control structure
 * for the given rs parameters. The control struct is unique per instance.
 * It points to a codec which can be shared by multiple control structures.
 * If a codec is newly allocated then the polynomial arrays for fast
 * encoding / decoding are built. This can take some time so make sure not
 * to call this function from a time critical path.  Usually a module /
 * driver should initialize the necessary rs_control structure on module /
 * driver init and release it on exit.
 *
 * The encoding puts the calculated syndrome into a given syndrome buffer.
 *
 * The decoding is a two step process. The first step calculates the
 * syndrome over the received (data + syndrome) and calls the second stage,
 * which does the decoding / error correction itself.  Many hw encoders
 * provide a syndrome calculation over the received data + syndrome and can
 * call the second stage directly.
 */
#include "common/internal.h"
#include "kernel-lib/list.h"

/**
 * struct rs_codec - rs codec data
 *
 * @mm:		Bits per symbol
 * @nn:		Symbols per block (= (1<<mm)-1)
 * @alpha_to:	log lookup table
 * @index_of:	Antilog lookup table
 * @genpoly:	Generator polynomial
 * @nroots:	Number of generator roots = number of parity symbols
 * @fcr:	First consecutive root, index form
 * @prim:	Primitive element, index form
 * @iprim:	prim-th root of 1, index form
 * @gfpoly:	The primitive generator polynominal
 * @gffunc:	Function to generate the field, if non-canonical representation
 * @gfswab:	Treat symbols as foreign endian, may be true only if mm = 16
 * @users:	Users of this structure
 * @list:	List entry for the rs codec list
*/
struct rs_codec {
	int		mm;
	int		nn;
	uint16_t	*alpha_to;
	uint16_t	*index_of;
	uint16_t	*genpoly;
	int		nroots;
	int		fcr;
	int		prim;
	int		iprim;
	int		gfpoly;
	int		(*gffunc)(int);
	bool		gfswab;
	int		users;
	struct list_head list;
};

/**
 * struct rs_control - rs control structure per instance
 * @codec:	The codec used for this instance
 * @buffers:	Internal scratch buffers used in calls to decode_rs()
 */
struct rs_control {
	struct rs_codec	*codec;
	uint16_t	buffers[];
};

/** modulo replacement for galois field arithmetics
 *
 *  @rs:	Pointer to the RS codec
 *  @x:		the value to reduce
 *
 *  where
 *  rs->mm = number of bits per symbol
 *  rs->nn = (2^rs->mm) - 1
 *
 *  Simple arithmetic modulo would return a wrong result for values
 *  >= 3 * rs->nn
*/
static inline int rs_modnn(struct rs_codec *rs, int x)
{
	while (x >= rs->nn) {
		x -= rs->nn;
		x = (x >> rs->mm) + (x & rs->nn);
	}
	return x;
}

enum {
	RS_DECODE_LAMBDA,
	RS_DECODE_SYN,
	RS_DECODE_B,
	RS_DECODE_T,
	RS_DECODE_OMEGA,
	RS_DECODE_ROOT,
	RS_DECODE_REG,
	RS_DECODE_LOC,
	RS_DECODE_NUM_BUFFERS
};

/* This list holds all currently allocated rs codec structures */
static LIST_HEAD(codec_list);
/* Protection for the list */
static DEFINE_MUTEX(rslistlock);

/**
 * codec_init - Initialize a Reed-Solomon codec
 * @symsize:	the symbol size (number of bits)
 * @gfpoly:	Field generator polynomial coefficients
 * @gffunc:	Field generator function
 * @gfswab:	Treat symbols as foreign endian, may be true only if symsize=16
 * @fcr:	first root of RS code generator polynomial, index form
 * @prim:	primitive element to generate polynomial roots
 * @nroots:	RS code generator polynomial degree (number of roots)
 * @gfp:	GFP_ flags for allocations
 *
 * Allocate a codec structure and the polynom arrays for faster
 * en/decoding. Fill the arrays according to the given parameters.
 */
static struct rs_codec *codec_init(int symsize,
				   int gfpoly, int (*gffunc)(int), bool gfswab,
				   int fcr, int prim, int nroots, gfp_t gfp)
{
	int i, j, sr, root, iprim;
	struct rs_codec *rs;

	rs = kzalloc(sizeof(*rs), gfp);
	if (!rs)
		return NULL;

	INIT_LIST_HEAD(&rs->list);

	rs->mm = symsize;
	rs->nn = (1 << symsize) - 1;
	rs->fcr = fcr;
	rs->prim = prim;
	rs->nroots = nroots;
	rs->gfpoly = gfpoly;
	rs->gffunc = gffunc;
	rs->gfswab = gfswab;

	/* Allocate the arrays */
	rs->alpha_to = kmalloc_array(rs->nn + 1, sizeof(uint16_t), gfp);
	if (rs->alpha_to == NULL)
		goto err;

	rs->index_of = kmalloc_array(rs->nn + 1, sizeof(uint16_t), gfp);
	if (rs->index_of == NULL)
		goto err;

	rs->genpoly = kmalloc_array(rs->nroots + 1, sizeof(uint16_t), gfp);
	if(rs->genpoly == NULL)
		goto err;

	/* Generate Galois field lookup tables */
	rs->index_of[0] = rs->nn;	/* log(zero) = -inf */
	rs->alpha_to[rs->nn] = 0;	/* alpha**-inf = 0 */
	if (gfpoly) {
		sr = 1;
		sr = gfswab ? swab16(sr) : sr;
		for (i = 0; i < rs->nn; i++) {
			rs->index_of[sr] = i;
			rs->alpha_to[i] = sr;
			sr = gfswab ? swab16(sr) : sr;
			sr <<= 1;
			if (sr & (1 << symsize))
				sr ^= gfpoly;
			sr &= rs->nn;
			sr = gfswab ? swab16(sr) : sr;
		}
	} else {
		sr = gffunc(0);
		for (i = 0; i < rs->nn; i++) {
			rs->index_of[sr] = i;
			rs->alpha_to[i] = sr;
			sr = gffunc(sr);
		}
	}
	/* If it's not primitive, exit */
	if(sr != rs->alpha_to[0])
		goto err;

	/* Find prim-th root of 1, used in decoding */
	for(iprim = 1; (iprim % prim) != 0; iprim += rs->nn);
	/* prim-th root of 1, index form */
	rs->iprim = iprim / prim;

	/* Form RS code generator polynomial from its roots */
	rs->genpoly[0] = rs->alpha_to[0];
	for (i = 0, root = fcr * prim; i < nroots; i++, root += prim) {
		rs->genpoly[i + 1] = rs->alpha_to[0];
		/* Multiply rs->genpoly[] by  @**(root + x) */
		for (j = i; j > 0; j--) {
			if (rs->genpoly[j] != 0) {
				rs->genpoly[j] = rs->genpoly[j -1] ^
					rs->alpha_to[rs_modnn(rs,
					rs->index_of[rs->genpoly[j]] + root)];
			} else
				rs->genpoly[j] = rs->genpoly[j - 1];
		}
		/* rs->genpoly[0] can never be zero */
		rs->genpoly[0] =
			rs->alpha_to[rs_modnn(rs,
				rs->index_of[rs->genpoly[0]] + root)];
	}
	/* convert rs->genpoly[] to index form for quicker encoding */
	for (i = 0; i <= nroots; i++)
		rs->genpoly[i] = rs->index_of[rs->genpoly[i]];

	rs->users = 1;
	list_add(&rs->list, &codec_list);
	return rs;

err:
	kfree(rs->genpoly);
	kfree(rs->index_of);
	kfree(rs->alpha_to);
	kfree(rs);
	return NULL;
}


/**
 *  free_rs - Free the rs control structure
 *  @rs:	The control structure which is not longer used by the
 *		caller
 *
 * Free the control structure. If @rs is the last user of the associated
 * codec, free the codec as well.
 */
void free_rs(struct rs_control *rs)
{
	struct rs_codec *cd;

	if (!rs)
		return;

	cd = rs->codec;
	mutex_lock(&rslistlock);
	cd->users--;
	if(!cd->users) {
		list_del(&cd->list);
		kfree(cd->alpha_to);
		kfree(cd->index_of);
		kfree(cd->genpoly);
		kfree(cd);
	}
	mutex_unlock(&rslistlock);
	kfree(rs);
}

/**
 * init_rs_internal - Allocate rs control, find a matching codec or allocate a new one
 *  @symsize:	the symbol size (number of bits)
 *  @gfpoly:	the extended Galois field generator polynomial coefficients,
 *		with the 0th coefficient in the low order bit. The polynomial
 *		must be primitive;
 *  @gffunc:	pointer to function to generate the next field element,
 *		or the multiplicative identity element if given 0.  Used
 *		instead of gfpoly if gfpoly is 0
 *  @gfswab:	Treat symbols as foreign endian, may be true only if symsize=16
 *  @fcr:	the first consecutive root of the rs code generator polynomial
 *		in index form
 *  @prim:	primitive element to generate polynomial roots
 *  @nroots:	RS code generator polynomial degree (number of roots)
 *  @gfp:	GFP_ flags for allocations
 */
static struct rs_control *init_rs_internal(int symsize, int gfpoly,
					   int (*gffunc)(int), bool gfswab,
					   int fcr, int prim, int nroots,
					   gfp_t gfp)
{
	struct list_head *tmp;
	struct rs_control *rs;
	unsigned int bsize;

	/* Sanity checks */
	if (symsize < 1)
		return NULL;
	if (fcr < 0 || fcr >= (1<<symsize))
		return NULL;
	if (prim <= 0 || prim >= (1<<symsize))
		return NULL;
	if (nroots < 0 || nroots >= (1<<symsize))
		return NULL;
	if (gfswab && symsize != 16)
		return NULL;

	/*
	 * The decoder needs buffers in each control struct instance to
	 * avoid variable size or large fixed size allocations on
	 * stack. Size the buffers to arrays of [nroots + 1].
	 */
	bsize = sizeof(uint16_t) * RS_DECODE_NUM_BUFFERS * (nroots + 1);
	rs = kzalloc(sizeof(*rs) + bsize, gfp);
	if (!rs)
		return NULL;

	mutex_lock(&rslistlock);

	/* Walk through the list and look for a matching entry */
	list_for_each(tmp, &codec_list) {
		struct rs_codec *cd = list_entry(tmp, struct rs_codec, list);

		if (symsize != cd->mm)
			continue;
		if (gfpoly != cd->gfpoly)
			continue;
		if (gffunc != cd->gffunc)
			continue;
		if (gfswab != cd->gfswab)
			continue;
		if (fcr != cd->fcr)
			continue;
		if (prim != cd->prim)
			continue;
		if (nroots != cd->nroots)
			continue;
		/* We have a matching one already */
		cd->users++;
		rs->codec = cd;
		goto out;
	}

	/* Create a new one */
	rs->codec = codec_init(symsize, gfpoly, gffunc, gfswab,
			       fcr, prim, nroots, gfp);
	if (!rs->codec) {
		kfree(rs);
		rs = NULL;
	}
out:
	mutex_unlock(&rslistlock);
	return rs;
}

/**
 * init_rs16_gfp - Allocate rs control struct for 16 bit symbols
 *  @gfpoly:	the extended Galois field generator polynomial coefficients,
 *		with the 0th coefficient in the low order bit. The polynomial
 *		must be primitive;
 *  @gfswab:	Treat symbols as foreign endian
 *  @fcr:	the first consecutive root of the rs code generator polynomial
 *		in index form
 *  @prim:	primitive element to generate polynomial roots
 *  @nroots:	RS code generator polynomial degree (number of roots)
 *  @gfp:	Memory allocation flags.
 */
struct rs_control *init_rs16_gfp(int gfpoly, bool gfswab, int fcr, int prim,
				 int nroots, gfp_t gfp)
{
	return init_rs_internal(16, gfpoly, NULL, gfswab,
				fcr, prim, nroots, gfp);
}

/**
 *  encode_rs16 - Calculate the parity for data values (16bit data width)
 *  @rsc:	the rs control structure
 *  @data:	data field of a given type
 *  @len:	data length
 *  @par:	parity data, must be initialized by caller (usually all 0)
 *  @invmsk:	invert data mask (will be xored on data, not on parity!)
 *
 *  Each field in the data array contains up to symbol size bits of valid data.
 */
int encode_rs16(struct rs_control *rsc, uint16_t *data, int len, uint16_t *par,
	uint16_t invmsk)
{
	struct rs_codec *rs = rsc->codec;
	int i, j, pad;
	int nn = rs->nn;
	int nroots = rs->nroots;
	uint16_t *alpha_to = rs->alpha_to;
	uint16_t *index_of = rs->index_of;
	uint16_t *genpoly = rs->genpoly;
	uint16_t fb;
	uint16_t msk = (uint16_t) rs->nn;

	/* Check length parameter for validity */
	pad = nn - nroots - len;
	if (pad < 0 || pad >= nn)
		return -ERANGE;

	for (i = 0; i < len; i++) {
		fb = index_of[((((uint16_t) data[i])^invmsk) & msk) ^ par[0]];
		/* feedback term is non-zero */
		if (fb != nn) {
			for (j = 1; j < nroots; j++) {
				par[j] ^= alpha_to[rs_modnn(rs, fb +
							 genpoly[nroots - j])];
			}
		}
		/* Shift */
		memmove(&par[0], &par[1], sizeof(uint16_t) * (nroots - 1));
		if (fb != nn) {
			par[nroots - 1] = alpha_to[rs_modnn(rs,
							    fb + genpoly[0])];
		} else {
			par[nroots - 1] = 0;
		}
	}
	return 0;
}

/**
 *  decode_rs16 - Decode codeword (16bit data width)
 *  @rsc:	the rs control structure
 *  @data:	data field of a given type
 *  @par:	received parity data field
 *  @len:	data length
 *  @s: 	syndrome data field, must be in index form
 *		(if NULL, syndrome is calculated)
 *  @no_eras:	number of erasures
 *  @eras_pos:	position of erasures, can be NULL
 *  @invmsk:	invert data mask (will be xored on data, not on parity!)
 *  @corr:	buffer to store correction bitmask on eras_pos
 *
 *  Each field in the data array contains up to symbol size bits of valid data.
 *
 *  Note: The rc_control struct @rsc contains buffers which are used for
 *  decoding, so the caller has to ensure that decoder invocations are
 *  serialized.
 *
 *  Returns the number of corrected symbols or -EBADMSG for uncorrectable
 *  errors. The count includes errors in the parity.
 */
int decode_rs16(struct rs_control *rsc, uint16_t *data, uint16_t *par, int len,
		uint16_t *s, int no_eras, int *eras_pos, uint16_t invmsk,
		uint16_t *corr)
{
	struct rs_codec *rs = rsc->codec;
	int deg_lambda, el, deg_omega;
	int i, j, r, k, pad;
	int nn = rs->nn;
	int nroots = rs->nroots;
	int fcr = rs->fcr;
	int prim = rs->prim;
	int iprim = rs->iprim;
	uint16_t *alpha_to = rs->alpha_to;
	uint16_t *index_of = rs->index_of;
	uint16_t u, q, tmp, num1, num2, den, discr_r, syn_error;
	int count = 0;
	int num_corrected;
	uint16_t msk = (uint16_t) rs->nn;

	/*
	 * The decoder buffers are in the rs control struct. They are
	 * arrays sized [nroots + 1]
	 */
	uint16_t *lambda = rsc->buffers + RS_DECODE_LAMBDA * (nroots + 1);
	uint16_t *syn = rsc->buffers + RS_DECODE_SYN * (nroots + 1);
	uint16_t *b = rsc->buffers + RS_DECODE_B * (nroots + 1);
	uint16_t *t = rsc->buffers + RS_DECODE_T * (nroots + 1);
	uint16_t *omega = rsc->buffers + RS_DECODE_OMEGA * (nroots + 1);
	uint16_t *root = rsc->buffers + RS_DECODE_ROOT * (nroots + 1);
	uint16_t *reg = rsc->buffers + RS_DECODE_REG * (nroots + 1);
	uint16_t *loc = rsc->buffers + RS_DECODE_LOC * (nroots + 1);

	/* Check length parameter for validity */
	pad = nn - nroots - len;
	BUG_ON(pad < 0 || pad >= nn - nroots);

	/* Does the caller provide the syndrome ? */
	if (s != NULL) {
		for (i = 0; i < nroots; i++) {
			/* The syndrome is in index form,
			 * so nn represents zero
			 */
			if (s[i] != nn)
				goto decode;
		}

		/* syndrome is zero, no errors to correct  */
		return 0;
	}

	/* form the syndromes; i.e., evaluate data(x) at roots of
	 * g(x) */
	for (i = 0; i < nroots; i++)
		syn[i] = (((uint16_t) data[0]) ^ invmsk) & msk;

	for (j = 1; j < len; j++) {
		for (i = 0; i < nroots; i++) {
			if (syn[i] == 0) {
				syn[i] = (((uint16_t) data[j]) ^
					  invmsk) & msk;
			} else {
				syn[i] = ((((uint16_t) data[j]) ^
					   invmsk) & msk) ^
					alpha_to[rs_modnn(rs, index_of[syn[i]] +
						       (fcr + i) * prim)];
			}
		}
	}

	for (j = 0; j < nroots; j++) {
		for (i = 0; i < nroots; i++) {
			if (syn[i] == 0) {
				syn[i] = ((uint16_t) par[j]) & msk;
			} else {
				syn[i] = (((uint16_t) par[j]) & msk) ^
					alpha_to[rs_modnn(rs, index_of[syn[i]] +
						       (fcr+i)*prim)];
			}
		}
	}
	s = syn;

	/* Convert syndromes to index form, checking for nonzero condition */
	syn_error = 0;
	for (i = 0; i < nroots; i++) {
		syn_error |= s[i];
		s[i] = index_of[s[i]];
	}

	if (!syn_error) {
		/* if syndrome is zero, data[] is a codeword and there are no
		 * errors to correct. So return data[] unmodified
		 */
		return 0;
	}

 decode:
	memset(&lambda[1], 0, nroots * sizeof(lambda[0]));
	lambda[0] = alpha_to[0];

	if (no_eras > 0) {
		/* Init lambda to be the erasure locator polynomial */
		lambda[1] = alpha_to[rs_modnn(rs,
					prim * (nn - 1 - (eras_pos[0] + pad)))];
		for (i = 1; i < no_eras; i++) {
			u = rs_modnn(rs, prim * (nn - 1 - (eras_pos[i] + pad)));
			for (j = i + 1; j > 0; j--) {
				tmp = index_of[lambda[j - 1]];
				if (tmp != nn) {
					lambda[j] ^=
						alpha_to[rs_modnn(rs, u + tmp)];
				}
			}
		}
	}

	for (i = 0; i < nroots + 1; i++)
		b[i] = index_of[lambda[i]];

	/*
	 * Begin Berlekamp-Massey algorithm to determine error+erasure
	 * locator polynomial
	 */
	r = no_eras;
	el = no_eras;
	while (++r <= nroots) {	/* r is the step number */
		/* Compute discrepancy at the r-th step in poly-form */
		discr_r = 0;
		for (i = 0; i < r; i++) {
			if ((lambda[i] != 0) && (s[r - i - 1] != nn)) {
				discr_r ^=
					alpha_to[rs_modnn(rs,
							  index_of[lambda[i]] +
							  s[r - i - 1])];
			}
		}
		discr_r = index_of[discr_r];	/* Index form */
		if (discr_r == nn) {
			/* 2 lines below: B(x) <-- x*B(x) */
			memmove (&b[1], b, nroots * sizeof (b[0]));
			b[0] = nn;
		} else {
			/* 7 lines below: T(x) <-- lambda(x)-discr_r*x*b(x) */
			t[0] = lambda[0];
			for (i = 0; i < nroots; i++) {
				if (b[i] != nn) {
					t[i + 1] = lambda[i + 1] ^
						alpha_to[rs_modnn(rs, discr_r +
								  b[i])];
				} else
					t[i + 1] = lambda[i + 1];
			}
			if (2 * el <= r + no_eras - 1) {
				el = r + no_eras - el;
				/*
				 * 2 lines below: B(x) <-- inv(discr_r) *
				 * lambda(x)
				 */
				for (i = 0; i <= nroots; i++) {
					b[i] = (lambda[i] == 0) ? nn :
						rs_modnn(rs, index_of[lambda[i]]
							 - discr_r + nn);
				}
			} else {
				/* 2 lines below: B(x) <-- x*B(x) */
				memmove(&b[1], b, nroots * sizeof(b[0]));
				b[0] = nn;
			}
			memcpy(lambda, t, (nroots + 1) * sizeof(t[0]));
		}
	}

	/* Convert lambda to index form and compute deg(lambda(x)) */
	deg_lambda = 0;
	for (i = 0; i < nroots + 1; i++) {
		lambda[i] = index_of[lambda[i]];
		if (lambda[i] != nn)
			deg_lambda = i;
	}

	if (deg_lambda == 0) {
		/*
		 * deg(lambda) is zero even though the syndrome is non-zero
		 * => uncorrectable error detected
		 */
		return -EBADMSG;
	}

	/* Find roots of error+erasure locator polynomial by Chien search */
	memcpy(&reg[1], &lambda[1], nroots * sizeof(reg[0]));
	count = 0;		/* Number of roots of lambda(x) */
	for (i = 1, k = iprim - 1; i <= nn; i++, k = rs_modnn(rs, k + iprim)) {
		q = alpha_to[0];	/* lambda[0] is always 0 */
		for (j = deg_lambda; j > 0; j--) {
			if (reg[j] != nn) {
				reg[j] = rs_modnn(rs, reg[j] + j);
				q ^= alpha_to[reg[j]];
			}
		}
		if (q != 0)
			continue;	/* Not a root */

		if (k < pad) {
			/* Impossible error location. Uncorrectable error. */
			return -EBADMSG;
		}

		/* store root (index-form) and error location number */
		root[count] = i;
		loc[count] = k;
		/* If we've already found max possible roots,
		 * abort the search to save time
		 */
		if (++count == deg_lambda)
			break;
	}
	if (deg_lambda != count) {
		/*
		 * deg(lambda) unequal to number of roots => uncorrectable
		 * error detected
		 */
		return -EBADMSG;
	}
	/*
	 * Compute err+eras evaluator poly omega(x) = s(x)*lambda(x) (modulo
	 * x**nroots). in index form. Also find deg(omega).
	 */
	deg_omega = deg_lambda - 1;
	for (i = 0; i <= deg_omega; i++) {
		tmp = 0;
		for (j = i; j >= 0; j--) {
			if ((s[i - j] != nn) && (lambda[j] != nn))
				tmp ^=
				    alpha_to[rs_modnn(rs, s[i - j] + lambda[j])];
		}
		omega[i] = index_of[tmp];
	}

	/*
	 * Compute error values in poly-form. num1 = omega(inv(X(l))), num2 =
	 * inv(X(l))**(fcr-1) and den = lambda_pr(inv(X(l))) all in poly-form
	 * Note: we reuse the buffer for b to store the correction pattern
	 */
	num_corrected = 0;
	for (j = count - 1; j >= 0; j--) {
		num1 = 0;
		for (i = deg_omega; i >= 0; i--) {
			if (omega[i] != nn)
				num1 ^= alpha_to[rs_modnn(rs, omega[i] +
							i * root[j])];
		}

		if (num1 == 0) {
			/* Nothing to correct at this position */
			b[j] = 0;
			continue;
		}

		num2 = alpha_to[rs_modnn(rs, root[j] * (fcr - 1) + nn)];
		den = 0;

		/* lambda[i+1] for i even is the formal derivative
		 * lambda_pr of lambda[i] */
		for (i = min(deg_lambda, nroots - 1) & ~1; i >= 0; i -= 2) {
			if (lambda[i + 1] != nn) {
				den ^= alpha_to[rs_modnn(rs, lambda[i + 1] +
						       i * root[j])];
			}
		}

		b[j] = alpha_to[rs_modnn(rs, index_of[num1] +
					       index_of[num2] +
					       nn - index_of[den])];
		num_corrected++;
	}

	/*
	 * We compute the syndrome of the 'error' and check that it matches
	 * the syndrome of the received word
	 */
	for (i = 0; i < nroots; i++) {
		tmp = 0;
		for (j = 0; j < count; j++) {
			if (b[j] == 0)
				continue;

			k = (fcr + i) * prim * (nn-loc[j]-1);
			tmp ^= alpha_to[rs_modnn(rs, index_of[b[j]] + k)];
		}

		if (tmp != alpha_to[s[i]])
			return -EBADMSG;
	}

	/*
	 * Store the error correction pattern, if a
	 * correction buffer is available
	 */
	if (corr && eras_pos) {
		j = 0;
		for (i = 0; i < count; i++) {
			if (b[i]) {
				corr[j] = b[i];
				eras_pos[j++] = loc[i] - pad;
			}
		}
	} else if (data && par) {
		/* Apply error to data and parity */
		for (i = 0; i < count; i++) {
			if (loc[i] < (nn - nroots))
				data[loc[i] - pad] ^= b[i];
			else
				par[loc[i] - pad - len] ^= b[i];
		}
	}

	return  num_corrected;
}

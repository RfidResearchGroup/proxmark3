/* model.c
 * Greg Cook, 26/Jul/2016
 */

/* CRC RevEng: arbitrary-precision CRC calculator and algorithm finder
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016  Gregory Cook
 *
 * This file is part of CRC RevEng.
 *
 * CRC RevEng is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CRC RevEng is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CRC RevEng.  If not, see <https://www.gnu.org/licenses/>.
 */

/* 2016-02-22: split off preset.c
 * 2012-03-03: single-line Williams model string conversion
 * 2011-09-03: added mrev(), mnovel()
 * 2011-01-17: fixed ANSI C warnings (except preset models)
 * 2010-12-26: renamed CRC RevEng
 * 2010-12-18: minor change to mtostr() output format
 * 2010-12-15: added mcmp()
 * 2010-12-14: finished mtostr()
 * 2010-12-12: started models.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reveng.h"

/* Private declarations */

static const poly_t pzero = PZERO;

/* Definitions */

void
mcpy(model_t *dest, const model_t *src) {
	/* Copies the parameters of src to dest.
	 * dest must be an initialised model.
	 */
	if(!dest || !src) return;
	pcpy(&dest->spoly, src->spoly);
	pcpy(&dest->init, src->init);
	pcpy(&dest->xorout, src->xorout);
	pcpy(&dest->check, src->check);
	dest->flags = src->flags;
	/* link to the name as it is static */
	dest->name = src->name;
}

void
mfree(model_t *model) {
	/* Frees the parameters of model. */
	if(!model) return;
	pfree(&model->spoly);
	pfree(&model->init);
	pfree(&model->xorout);
	pfree(&model->check);
	/* not name as it is static */
	/* not model either, it might point to an array! */
}

int
mcmp(const model_t *a, const model_t *b) {
	/* Compares a and b for identical effect, i.e. disregarding
	 * trailing zeroes in parameter polys.
	 * Intended for bsearch().
	 */
	int result;
	if(!a || !b) return(!b - !a);
	if((result = psncmp(&a->spoly, &b->spoly))) return(result);
	if((result = psncmp(&a->init, &b->init))) return(result);
	if((a->flags & P_REFIN) && (~b->flags & P_REFIN)) return(1);
	if((~a->flags & P_REFIN) && (b->flags & P_REFIN)) return(-1);
	if((a->flags & P_REFOUT) && (~b->flags & P_REFOUT)) return(1);
	if((~a->flags & P_REFOUT) && (b->flags & P_REFOUT)) return(-1);
	return(psncmp(&a->xorout, &b->xorout));
}

char *
mtostr(const model_t *model) {
	/* Returns a malloc()-ed string containing a Williams model
	 * record representing the input model.
	 * mcanon() should be called on the argument before printing.
	 */
	size_t size;
	char *polystr, *initstr, *xorotstr, *checkstr, strbuf[512], *string = NULL;

	if(!model) return(NULL);
	polystr = ptostr(model->spoly, P_RTJUST, 4);
	initstr = ptostr(model->init, P_RTJUST, 4);
	xorotstr = ptostr(model->xorout, P_RTJUST, 4);
	checkstr = ptostr(model->check, P_RTJUST, 4);

	sprintf(strbuf, "%lu", plen(model->spoly));
	size =
		70
		+ (model->name && *model->name ? 2 + strlen(model->name) : 6)
		+ strlen(strbuf)
		+ (polystr && *polystr ? strlen(polystr) : 6)
		+ (initstr && *initstr ? strlen(initstr) : 6)
		+ (model->flags & P_REFIN ? 4 : 5)
		+ (model->flags & P_REFOUT ? 4 : 5)
		+ (xorotstr && *xorotstr ? strlen(xorotstr) : 6)
		+ (checkstr && *checkstr ? strlen(checkstr) : 6);
	if((string = malloc(size))) {
		sprintf(strbuf, "\"%s\"", model->name);
		sprintf(string,
				"width=%lu  "
				"poly=0x%s  "
				"init=0x%s  "
				"refin=%s  "
				"refout=%s  "
				"xorout=0x%s  "
				"check=0x%s  "
				"name=%s",
				plen(model->spoly),
				polystr && *polystr ? polystr : "(none)",
				initstr && *initstr ? initstr :  "(none)",
				(model->flags & P_REFIN) ? "true" : "false",
				(model->flags & P_REFOUT) ? "true" : "false",
				xorotstr && *xorotstr ? xorotstr : "(none)",
				checkstr && *checkstr ? checkstr : "(none)",
				(model->name && *model->name) ? strbuf : "(none)");
	}
	free(polystr);
	free(initstr);
	free(xorotstr);
	free(checkstr);
	if(!string)
		uerror("cannot allocate memory for model description");
	return(string);
}

void
mcanon(model_t *model) {
	/* canonicalise a model */
	unsigned long dlen;

	if(!model) return;

	/* extending on the right here. This preserves the functionality
	 * of a presumed working model.
	 */
	psnorm(&model->spoly);
	dlen = plen(model->spoly);
	praloc(&model->init, dlen);
	praloc(&model->xorout, dlen);

	/* only calculate Check if missing.  Relying on all functions
	 * changing parameters to call mnovel().  This is to ensure that
	 * the Check value stored in the preset table is printed when
	 * the model is dumped.  If something goes wrong with the
	 * calculator then the discrepancy with the stored Check value
	 * might be noticed.  Storing the Check value with each preset
	 * is highly preferred.
	 */
	if(!plen(model->check))
		mcheck(model);
}

void
mcheck(model_t *model) {
	/* calculate a check for the model */
	poly_t checkstr, check;

	/* generate the check string with the correct bit order */
	checkstr = strtop("313233343536373839", model->flags, 8);
	check = pcrc(checkstr, model->spoly, model->init, pzero, model->flags);
	if(model->flags & P_REFOUT)
		prev(&check);
	psum(&check, model->xorout, 0UL);
	model->check = check;
	pfree(&checkstr);
}

void
mrev(model_t *model) {
	/* reverse the model to calculate reversed CRCs */
	/* Here we invert RefIn and RefOut so that the user need only
	 * reverse the order of characters in the arguments, not the
	 * characters themselves.  If RefOut=True, the mirror image of
	 * Init seen through RefOut becomes XorOut, and as RefOut
	 * becomes false, the XorOut value moved to Init stays upright.
	 * If RefOut=False, Init transfers to XorOut without reflection
	 * but the new Init must be reflected to present the same image,
	 * as RefOut becomes true.
	 */
	poly_t temp;

	prcp(&model->spoly);
	if(model->flags & P_REFOUT)
		prev(&model->init);
	else
		prev(&model->xorout);

	/* exchange init and xorout */
	temp = model->init;
	model->init = model->xorout;
	model->xorout = temp;

	/* invert refin and refout */
	model->flags ^= P_REFIN | P_REFOUT;

	mnovel(model);
}

void
mnovel(model_t *model) {
	/* remove name and check string from modified model */
	model->name = NULL;
	pfree(&model->check);
}

/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#ifdef DEBUG
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef PKIM_H
#include "pkim.h"
#endif /* PKIM_H */

#define HIDIGIT(v) (((v) / 10) + '0')
#define LODIGIT(v) (((v) % 10) + '0')

#define C_SINGLE_QUOTE '\047'

#define DIGITHI(dig) (((dig) - '0') * 10)
#define DIGITLO(dig) ((dig) - '0')
#define ISDIGIT(dig) (((dig) >= '0') && ((dig) <= '9'))
#define CAPTURE(var,p,label)				  \
{							  \
    if (!ISDIGIT((p)[0]) || !ISDIGIT((p)[1])) goto label; \
    (var) = ((p)[0] - '0') * 10 + ((p)[1] - '0');	  \
}

#define PKIXMIN ((time_t) 60L)
#define PKIXHOUR (60L*PKIXMIN)
#define PKIXDAY (24L*PKIXHOUR)
#define PKIXYEAR (365L*PKIXDAY)

static long monthToDayInYear[12] = {
    0,
    31,
    31+28,
    31+28+31,
    31+28+31+30,
    31+28+31+30+31,
    31+28+31+30+31+30,
    31+28+31+30+31+30+31,
    31+28+31+30+31+30+31+31,
    31+28+31+30+31+30+31+31+30,
    31+28+31+30+31+30+31+31+30+31,
    31+28+31+30+31+30+31+31+30+31+30,
};

/* gmtTime must contain UTC time in micro-seconds unit */
NSS_IMPLEMENT NSSUTF8 *
nssTime_GetUTCTime
(
  NSSTime time,
  NSSArena *arenaOpt
)
{
    PRExplodedTime printableTime;
    unsigned char utc[14];

    /* Convert an int64 time to a printable format.  */
    PR_ExplodeTime(time, PR_GMTParameters, &printableTime);

    /* The month in UTC time is base one */
    printableTime.tm_month++;

    /* UTC time does not handle the years before 1950 */
    if (printableTime.tm_year < 1950)
	return (NSSUTF8 *)NULL;

    /* remove the century since it's added to the tm_year by the 
       PR_ExplodeTime routine, but is not needed for UTC time */
    printableTime.tm_year %= 100; 

    utc[0] = HIDIGIT(printableTime.tm_year);
    utc[1] = LODIGIT(printableTime.tm_year);
    utc[2] = HIDIGIT(printableTime.tm_month);
    utc[3] = LODIGIT(printableTime.tm_month);
    utc[4] = HIDIGIT(printableTime.tm_mday);
    utc[5] = LODIGIT(printableTime.tm_mday);
    utc[6] = HIDIGIT(printableTime.tm_hour);
    utc[7] = LODIGIT(printableTime.tm_hour);
    utc[8] = HIDIGIT(printableTime.tm_min);
    utc[9] = LODIGIT(printableTime.tm_min);
    utc[10] = HIDIGIT(printableTime.tm_sec);
    utc[11] = LODIGIT(printableTime.tm_sec);
    utc[12] = 'Z';
    utc[13] = '\0';

    return nssUTF8_Duplicate(utc, arenaOpt);
}

NSS_IMPLEMENT NSSTime
nssTime_CreateFromUTCTime
(
  NSSUTF8 *utcTime,
  PRStatus *statusOpt
)
{
    long year, month, mday, hour, minute, second, hourOff, minOff, days;
    PRTime result, tmp1, tmp2;
    
    /* Verify time is formatted properly and capture information */
    second = 0;
    hourOff = 0;
    minOff = 0;
    CAPTURE(year,utcTime+0,loser);
    if (year < 50) {
	/* ASSUME that year # is in the 2000's, not the 1900's */
	year += 100;
    }
    CAPTURE(month,utcTime+2,loser);
    if ((month == 0) || (month > 12)) goto loser;
    CAPTURE(mday,utcTime+4,loser);
    if ((mday == 0) || (mday > 31)) goto loser;
    CAPTURE(hour,utcTime+6,loser);
    if (hour > 23) goto loser;
    CAPTURE(minute,utcTime+8,loser);
    if (minute > 59) goto loser;
    if (ISDIGIT(utcTime[10])) {
	CAPTURE(second,utcTime+10,loser);
	if (second > 59) goto loser;
	utcTime += 2;
    }
    if (utcTime[10] == '+') {
	CAPTURE(hourOff,utcTime+11,loser);
	if (hourOff > 23) goto loser;
	CAPTURE(minOff,utcTime+13,loser);
	if (minOff > 59) goto loser;
    } else if (utcTime[10] == '-') {
	CAPTURE(hourOff,utcTime+11,loser);
	if (hourOff > 23) goto loser;
	hourOff = -hourOff;
	CAPTURE(minOff,utcTime+13,loser);
	if (minOff > 59) goto loser;
	minOff = -minOff;
    } else if (utcTime[10] != 'Z') {
	goto loser;
    }
    
    
    /* Convert pieces back into a single value year  */
    LL_I2L(tmp1, (year-70L));
    LL_I2L(tmp2, PKIXYEAR);
    LL_MUL(result, tmp1, tmp2);
    
    LL_I2L(tmp1, ( (mday-1L)*PKIXDAY + hour*PKIXHOUR + minute*PKIXMIN -
		  hourOff*PKIXHOUR - minOff*PKIXMIN + second ) );
    LL_ADD(result, result, tmp1);

    /*
    ** Have to specially handle the day in the month and the year, to
    ** take into account leap days. The return time value is in
    ** seconds since January 1st, 12:00am 1970, so start examining
    ** the time after that. We can't represent a time before that.
    */

    /* Using two digit years, we can only represent dates from 1970
       to 2069. As a result, we cannot run into the leap year rule
       that states that 1700, 2100, etc. are not leap years (but 2000
       is). In other words, there are no years in the span of time
       that we can represent that are == 0 mod 4 but are not leap
       years. Whew.
       */

    days = monthToDayInYear[month-1];
    days += (year - 68)/4;

    if (((year % 4) == 0) && (month < 3)) {
	days--;
    }
   
    LL_I2L(tmp1, (days * PKIXDAY) );
    LL_ADD(result, result, tmp1 );

    /* convert to micro seconds */
    LL_I2L(tmp1, PR_USEC_PER_SEC);
    LL_MUL(result, result, tmp1);

    if (statusOpt) *statusOpt = PR_SUCCESS;
    return result;

loser:
#if 0
    PORT_SetError(SEC_ERROR_INVALID_TIME);
#endif
    if (statusOpt) *statusOpt = PR_FAILURE;
    return -1; /* XXX guess so */
}

/*
   gmttime must contains UTC time in micro-seconds unit.
   Note: the caller should make sure that Generalized time
   should only be used for certifiate validities after the
   year 2049.  Otherwise, UTC time should be used.  This routine
   does not check this case, since it can be used to encode
   certificate extension, which does not have this restriction. 
 */
NSS_IMPLEMENT NSSUTF8 *
nssTime_GetGeneralizedTime
(
  NSSTime time,
  NSSArena *arenaOpt
)
{
    PRExplodedTime printableTime;
    unsigned char gen[16];

    /*Convert a int64 time to a printable format. This is a temporary call
	  until we change to NSPR 2.0
     */
    PR_ExplodeTime(time, PR_GMTParameters, &printableTime);

    /* The month in Generalized time is base one */
    printableTime.tm_month++;

    gen[0] = (printableTime.tm_year /1000) + '0';
    gen[1] = ((printableTime.tm_year % 1000) / 100) + '0';
    gen[2] = ((printableTime.tm_year % 100) / 10) + '0';
    gen[3] = (printableTime.tm_year % 10) + '0';
    gen[4] = HIDIGIT(printableTime.tm_month);
    gen[5] = LODIGIT(printableTime.tm_month);
    gen[6] = HIDIGIT(printableTime.tm_mday);
    gen[7] = LODIGIT(printableTime.tm_mday);
    gen[8] = HIDIGIT(printableTime.tm_hour);
    gen[9] = LODIGIT(printableTime.tm_hour);
    gen[10] = HIDIGIT(printableTime.tm_min);
    gen[11] = LODIGIT(printableTime.tm_min);
    gen[12] = HIDIGIT(printableTime.tm_sec);
    gen[13] = LODIGIT(printableTime.tm_sec);
    gen[14] = 'Z';
    gen[15] = '\0';

    return nssUTF8_Duplicate(gen, arenaOpt);
}

/*
    The caller should make sure that the generalized time should only
    be used for the certificate validity after the year 2051; otherwise,
    the certificate should be consider invalid!?
 */
NSS_IMPLEMENT NSSTime
nssTime_CreateFromGeneralizedTime
(
  NSSUTF8 *generalizedTime,
  PRStatus *statusOpt
)
{
    PRExplodedTime genTime;
    NSSUTF8 *gt = generalizedTime;
    long hourOff, minOff;
    uint16 century;

    nsslibc_memset(&genTime, 0, sizeof (genTime));

    /* Verify time is formatted properly and capture information */
    hourOff = 0;
    minOff = 0;

    CAPTURE(century, gt+0, loser);
    century *= 100;
    CAPTURE(genTime.tm_year,gt+2,loser);
    genTime.tm_year += century;

    CAPTURE(genTime.tm_month,gt+4,loser);
    if ((genTime.tm_month == 0) || (genTime.tm_month > 12)) goto loser;

    /* NSPR month base is 0 */
    --genTime.tm_month;
    
    CAPTURE(genTime.tm_mday,gt+6,loser);
    if ((genTime.tm_mday == 0) || (genTime.tm_mday > 31)) goto loser;
    
    CAPTURE(genTime.tm_hour,gt+8,loser);
    if (genTime.tm_hour > 23) goto loser;
    
    CAPTURE(genTime.tm_min,gt+10,loser);
    if (genTime.tm_min > 59) goto loser;
    
    if (ISDIGIT(gt[12])) {
	CAPTURE(genTime.tm_sec,gt+12,loser);
	if (genTime.tm_sec > 59) goto loser;
	gt += 2;
    }
    if (gt[12] == '+') {
	CAPTURE(hourOff,gt+13,loser);
	if (hourOff > 23) goto loser;
	CAPTURE(minOff,gt+15,loser);
	if (minOff > 59) goto loser;
    } else if (gt[12] == '-') {
	CAPTURE(hourOff,gt+13,loser);
	if (hourOff > 23) goto loser;
	hourOff = -hourOff;
	CAPTURE(minOff,gt+15,loser);
	if (minOff > 59) goto loser;
	minOff = -minOff;
    } else if (gt[12] != 'Z') {
	goto loser;
    }

    /* Since the values of hourOff and minOff are small, there will
       be no loss of data by the conversion to int8 */
    /* Convert the GMT offset to seconds and save it it genTime
       for the implode time process */
    genTime.tm_params.tp_gmt_offset = (PRInt32)((hourOff * 60L + minOff) * 60L);

    if (statusOpt) *statusOpt = PR_SUCCESS;
    return PR_ImplodeTime(&genTime);

loser:
#if 0
    PORT_SetError(SEC_ERROR_INVALID_TIME);
#endif
    if (statusOpt) *statusOpt = PR_FAILURE;
    return -1; /* XXX guess so */
}

NSS_IMPLEMENT NSSTime
NSSTime_Now
(
  void
)
{
    return (NSSTime)PR_Now();
}

NSS_IMPLEMENT PRBool
nssTime_WithinRange
(
  NSSTime time,
  NSSTime start,
  NSSTime finish
)
{
    return (LL_CMP(start, <, time) && LL_CMP(time, <, finish));
}

NSS_IMPLEMENT PRBool
nssTime_IsBefore
(
  NSSTime time,
  NSSTime compareTime
)
{
    return (LL_CMP(time, <, compareTime));
}

NSS_IMPLEMENT PRBool
nssTime_IsAfter
(
  NSSTime time,
  NSSTime compareTime
)
{
    return (LL_CMP(compareTime, <, time));
}

NSS_IMPLEMENT NSSTime
NSSTime_CreateFromUTCTime
(
  NSSUTF8 *utcTime,
  PRStatus *statusOpt
)
{
    return nssTime_CreateFromUTCTime(utcTime, statusOpt);
}


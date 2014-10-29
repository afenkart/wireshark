/*
 This file is part of the digitalSTROM ds485-core library.

 Copyright (C) 2010 digitalSTROM.org, Schlieren, Switzerland

 digitalSTROM ds485-core library is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation version 2
 of the License.

 digitalSTROM ds485-core library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with digitalSTROM ds485-core library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _dsid_h
#define _dsid_h

#if defined(__GNUC__)
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#elif defined(__MSVC__)
#endif

#define DSUID_SIZE      17
#define DSUID_STR_LEN   ((2 * DSUID_SIZE) + 1)

/**
 * 136-Bit dSUID
 */
typedef struct {
    unsigned char id[DSUID_SIZE];
#ifdef SWIG
} dsuid_t;
#else
} __attribute__ ((packed)) dsuid_t;
#endif

/**
 * 96-Bit dSID
 */
typedef struct dsid {
    unsigned char id[12];
} dsid_t;

#define __BROADCAST_DSUID "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
#define __NULL_DSUID "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

/*
 * lean man type checking, only type containing field id will pass
 * we still the check the whole dsuid_t struct for equality
 */

#define IsBroadcastDsuid(dsuid) \
    (memcmp(__BROADCAST_DSUID, (dsuid).id, sizeof(dsuid_t)) == 0)

#define IsEqualDsuid(dsuid1, dsuid2) \
    (memcmp((dsuid1).id, (dsuid2).id, sizeof(dsuid_t)) == 0)

#define SetBroadcastDsuid(dsuid) \
    memcpy((dsuid).id, __BROADCAST_DSUID, sizeof(dsuid_t))

#define SetNullDsuid(dsuid) \
    memcpy((dsuid).id, __NULL_DSUID, sizeof(dsuid_t))

#define IsNullDsuid(dsuid) \
    (memcmp(__NULL_DSUID, (dsuid).id, sizeof(dsuid_t)) == 0)

/*
 * Bus member and application types
 */
typedef enum {
	BusMember_Unknown = 0,
	BusMember_ds485d = 1,
	BusMember_ds485p = 2,
	BusMember_dSM11 = 16,
	BusMember_dSM12 = 17,
	BusMember_vDSM = 32,
	BusMember_vDC = 33,
	BusMember_dSS = 128,
	BusMember_dSA = 129,
	BusMember_dSG = 130
} BusMemberDevice_t;

#endif

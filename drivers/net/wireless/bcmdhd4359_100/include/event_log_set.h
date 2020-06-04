/*
 * EVENT_LOG system definitions
 *
 * Copyright (C) 1999-2019, Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: event_log_set.h 744920 2018-02-06 06:25:40Z $
 */

#ifndef _EVENT_LOG_SET_H_
#define _EVENT_LOG_SET_H_

#ifndef NUM_EVENT_LOG_SETS
/* Set a maximum number of sets here.  It is not dynamic for
 * efficiency of the EVENT_LOG calls. Old branches could define
 * this to an appropriat enumber in their makefiles to reduce
 * ROM invalidation
 */
#define NUM_EVENT_LOG_SETS 11
#endif // endif

/* Legacy implementation does not have these sets. So make them 0. */
#if (NUM_EVENT_LOG_SETS <= 8)
#define NUM_EVENT_LOG_DBG_SETS	0
#elif (NUM_EVENT_LOG_SETS == 9)
#define NUM_EVENT_LOG_DBG_SETS	1
#else
#define NUM_EVENT_LOG_DBG_SETS	2
#endif // endif

/* Debug log sets start from this log set and are always the last few ones */
/* Note that these log sets are not reserved for debug builds. They can be used
 * for other purpose as well. If used for other purpose, the debug log set
 * allocation code will check if there is a free one available out of
 * NUM_EVENT_LOG_DBG_SETS starting from EVENT_LOG_DBG_START_SET
 */
#define EVENT_LOG_DBG_START_SET	(NUM_EVENT_LOG_SETS - NUM_EVENT_LOG_DBG_SETS)

/* Define new event log sets here */
#define EVENT_LOG_SET_BUS	0
#define EVENT_LOG_SET_WL	1
#define EVENT_LOG_SET_PSM	2
#define EVENT_LOG_SET_ERROR	3
#define EVENT_LOG_SET_MEM_API	4
/* Share the set with MEM_API for now to limit ROM invalidation.
 * The above set is used in dingo only
 * On trunk, MSCH should move to a different set.
 */
#define EVENT_LOG_SET_MSCH_PROFILER	4
#define EVENT_LOG_SET_ECOUNTERS 5	/* Host to instantiate this for ecounters. */
#define EVENT_LOG_SET_6	6	/* Instantiated by host for channel switch logs */
#define EVENT_LOG_SET_7	7	/* Instantiated by host for AMPDU stats */

/* The following ones could be used for debug builds. Always the last few ones */
#define EVENT_LOG_SET_8 8
#define EVENT_LOG_SET_9	9

#define EVENT_LOG_SET_PRSRV    7 /* The logtag set flushed only on error. Share with 7 to avoid
				    * abandons.
				    */

#define EVENT_LOG_SET_PRSRV_BUS	10

/* send delayed logs when >= 50% of buffer is full */
#ifndef ECOUNTERS_DELAYED_FLUSH_PERCENTAGE
#define ECOUNTERS_DELAYED_FLUSH_PERCENTAGE	(50)
#endif // endif

#endif /* _EVENT_LOG_SET_H_ */

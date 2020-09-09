/*
 * Wifi dongle status Filter and Report
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
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: dhd_event_log_filter.h 726962 2017-10-17 10:14:12Z $
 */

#ifndef dhd_event_log_filter_h
#define dhd_event_log_filter_h
#include <dhd.h>
#include <event_log_tag.h>
int dhd_event_log_filter_init(dhd_pub_t *dhdp, uint8 *buf, uint32 buf_size);
void dhd_event_log_filter_deinit(dhd_pub_t *dhdp);
void dhd_event_log_filter_event_handler(
	dhd_pub_t *dhdp, event_log_hdr_t *log_hdr, uint32 *data);

void dhd_event_log_filter_notify_connect_request(dhd_pub_t *dhdp, uint8 *bssid, int channel);
void dhd_event_log_filter_notify_connect_done(dhd_pub_t *dhdp, uint8 *bssid, int roam);

#endif /* dhd_event_log_filter_h */

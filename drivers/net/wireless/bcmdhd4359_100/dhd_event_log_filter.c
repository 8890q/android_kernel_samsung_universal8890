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
 * $Id: dhd_event_log_filter.c 765264 2018-06-01 05:38:52Z $
 */

/*
 * Filter MODULE and Report MODULE
 */

#include <typedefs.h>
#include <osl.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_dbg.h>
#include <dhd_debug.h>
#include <event_log.h>
#include <event_trace.h>
#include <bcmtlv.h>
#include <bcmwifi_channels.h>
#include <dhd_event_log_filter.h>
#include <wl_cfg80211.h>

#define htod32(i) (i)
#define htod16(i) (i)
#define dtoh32(i) (i)
#define dtoh16(i) (i)
#define htodchanspec(i) (i)
#define dtohchanspec(i) (i)

#define DHD_FILTER_ERR_INTERNAL(fmt, ...) DHD_ERROR(("EWPF-" fmt, ##__VA_ARGS__))
#define DHD_FILTER_TRACE_INTERNAL(fmt, ...) DHD_INFO(("EWPF-" fmt, ##__VA_ARGS__))

#define DHD_FILTER_ERR(x) DHD_FILTER_ERR_INTERNAL x
#define DHD_FILTER_TRACE(x) DHD_FILTER_TRACE_INTERNAL x

/* ========= EWP Filter functions ============= */
//#define EWPF_DEBUG
#define EWPF_DEBUG_BUF_LEN	512
#define EWPF_VAL_CNT_PLINE	16

#define EWPF_REPORT_MAX_DATA	32	/* MAX record per slice */

#define EWPF_INVALID	(-1)
#define EWPF_XTLV_INVALID		0

#define EWPF_MAX_IDX_TYPE		2
#define EWPF_IDX_TYPE_SLICE		1
#define EWPF_IDX_TYPE_IFACE		2

#define EWPF_MAX_SLICE			2	/* MAX slice in dongle */
#define EWPF_SLICE_MAIN			0	/* SLICE ID for 5GHZ */
#define EWPF_SLICE_AUX			1	/* SLICE ID for 2GHZ */

#define EWPF_MAX_IFACE			2	/* MAX IFACE supported, 0: STA */

#define EWPF_ARM_TO_MSEC		1
#define EWPF_MSEC_TO_SEC		1000
#define EWPF_EPOCH				1000
#define EWPF_NONSEC_TO_SEC		1000000000
#define EWPF_REPORT_YEAR_MUL	10000
#define EWPF_REPORT_MON_MUL		100
#define EWPF_REPORT_HOUR_MUL	10000
#define EWPF_REPORT_MIN_MUL		100
#define EWPF_REPORT_MINUTES		60
#define EWPF_REPORT_YEAR_BASE	1900

/* EWPF element of slice type */
typedef struct {
	uint32 armcycle; /* dongle arm cycle for this record */
	union {
		wl_periodic_compact_cntrs_v1_t compact_cntr_v1;
		wl_periodic_compact_cntrs_v2_t compact_cntr_v2;
	};
} EWPF_slc_elem_t;

/* EWPF element for interface type */
typedef struct {
	uint32 armcycle; /* dongle arm cycle for this record */
	wl_if_stats_t if_stat;
	wl_lqm_t lqm;
	wl_if_infra_stats_t infra;
	wl_if_mgt_stats_t mgmt_stat;
	wl_if_state_compact_t if_comp_stat;
} EWPF_ifc_elem_t;

typedef struct {
	int enabled;			/* enabled/disabled */
	dhd_pub_t *dhdp;
	uint32 tmp_armcycle;	/* global ARM CYCLE for TAG */
	int idx_type;			/* 0 : SLICE, 1: IFACE */
	int xtlv_idx;			/* Slice/Interface index : global for TAG */
	void *s_ring[EWPF_MAX_SLICE];
	void *i_ring[EWPF_MAX_IFACE];

	/* used by Report module */
	uint8 last_bssid[ETHER_ADDR_LEN];	/* BSSID of last conencted/request */
	int last_channel;
	uint32 last_armcycle;	/* ARM CYCLE prior last connection */
} EWP_filter_t;

/* status gathering functions : XTLV callback functions */
typedef int (*EWPF_filter_cb)(void *ctx, const uint8 *data, uint16 type, uint16 len);
static int evt_xtlv_print_cb(void *ctx, const uint8 *data, uint16 type, uint16 len);
static int evt_xtlv_copy_cb(void *ctx, const uint8 *data, uint16 type, uint16 len);
static int evt_xtlv_idx_cb(void *ctx, const uint8 *data, uint16 type, uint16 len);
static int evt_xtlv_type_cb(void *ctx, const uint8 *data, uint16 type, uint16 len);
static int filter_main_cb(void *ctx, const uint8 *data, uint16 type, uint16 len);

/* ========= Module functions : exposed to others ============= */
int
dhd_event_log_filter_init(dhd_pub_t *dhdp, uint8 *buf, uint32 buf_size)
{

	EWP_filter_t *filter;
	int idx;
	uint32 req_size;
	uint32 s_ring_size; /* slice ring */
	uint32 i_ring_size; /* interface ring */
	uint8 *buf_ptr = buf;
	DHD_FILTER_ERR(("STARTED\n"));

	if (!dhdp || !buf) {
		DHD_FILTER_ERR(("INVALID PTR: dhdp:%p buf:%p\n", dhdp, buf));
		return BCME_ERROR;
	}

	i_ring_size = s_ring_size = dhd_ring_get_hdr_size();
	s_ring_size += ((uint32)sizeof(EWPF_slc_elem_t)) * EWPF_REPORT_MAX_DATA;
	i_ring_size += ((uint32)sizeof(EWPF_ifc_elem_t)) * EWPF_REPORT_MAX_DATA;

	req_size = s_ring_size * EWPF_MAX_SLICE + i_ring_size * EWPF_MAX_IFACE;
	req_size += (uint32)sizeof(EWP_filter_t);

	if (buf_size < req_size) {
		DHD_FILTER_ERR(("BUF SIZE IS TO SHORT: req:%d buf_size:%d\n",
			req_size, buf_size));
		return BCME_ERROR;
	}

	BCM_REFERENCE(dhdp);
	filter = (EWP_filter_t *)buf;
	buf_ptr += sizeof(EWP_filter_t);

	/* initialize control block */
	memset(filter, 0, sizeof(EWP_filter_t));

	filter->idx_type = EWPF_INVALID;
	filter->xtlv_idx = EWPF_INVALID;
	filter->tmp_armcycle = 0;

	for (idx = 0; idx < EWPF_MAX_SLICE; idx++) {
		filter->s_ring[idx] = dhd_ring_init(buf_ptr, s_ring_size,
			sizeof(EWPF_slc_elem_t), EWPF_REPORT_MAX_DATA);
		if (!filter->s_ring[idx]) {
			DHD_FILTER_ERR(("FAIL TO INIT SLICE RING: %d\n", idx));
			return BCME_ERROR;
		}
		buf_ptr += s_ring_size;
	}

	for (idx = 0; idx < EWPF_MAX_IFACE; idx++) {
		filter->i_ring[idx] = dhd_ring_init(buf_ptr, i_ring_size,
			sizeof(EWPF_ifc_elem_t), EWPF_REPORT_MAX_DATA);
		if (!filter->i_ring[idx]) {
			DHD_FILTER_ERR(("FAIL TO INIT INTERFACE RING: %d\n", idx));
			return BCME_ERROR;
		}
		buf_ptr += i_ring_size;
	}

	dhdp->event_log_filter = filter;
	filter->dhdp = dhdp;
	filter->enabled = TRUE;
	return BCME_OK;
}

void
dhd_event_log_filter_deinit(dhd_pub_t *dhdp)
{
	EWP_filter_t *filter;
	int idx;

	if (!dhdp) {
		return;
	}

	if (dhdp->event_log_filter) {
		filter = (EWP_filter_t *)dhdp->event_log_filter;
		for (idx = 0; idx < EWPF_MAX_SLICE; idx ++) {
			dhd_ring_deinit(filter->s_ring[idx]);
		}
		for (idx = 0; idx < EWPF_MAX_IFACE; idx ++) {
			dhd_ring_deinit(filter->i_ring[idx]);
		}
		dhdp->event_log_filter = NULL;
	}
}

void
dhd_event_log_filter_notify_connect_request(dhd_pub_t *dhdp, uint8 *bssid, int channel)
{
	EWP_filter_t *filter;
	void *last_elem;

	if (!dhdp || !dhdp->event_log_filter) {
		return;
	}

	filter = (EWP_filter_t *)dhdp->event_log_filter;
	if (filter->enabled != TRUE) {
		DHD_FILTER_ERR(("EWP Filter is not enabled\n"));
		return;
	}

	memcpy(filter->last_bssid, bssid, ETHER_ADDR_LEN);
	filter->last_channel = channel;

	/* Refer STA interface */
	last_elem = dhd_ring_get_last(filter->i_ring[0]);
	if (last_elem == NULL) {
		filter->last_armcycle = 0;
	} else {
		/* EXCLUDE before connect start */
		filter->last_armcycle = *(uint32 *)last_elem + EWPF_EPOCH + 1;
	}
}

void
dhd_event_log_filter_notify_connect_done(dhd_pub_t *dhdp, uint8 *bssid, int roam)
{
	EWP_filter_t *filter;
	void *last_elem;
	int channel;
	char buf[EWPF_DEBUG_BUF_LEN];
	int ret;
	uint32 armcycle;
	struct channel_info *ci;

	if (!dhdp || !dhdp->event_log_filter) {
		return;
	}

	filter = (EWP_filter_t *)dhdp->event_log_filter;
	if (filter->enabled != TRUE) {
		DHD_FILTER_ERR(("EWP Filter is not enabled\n"));
		return;
	}

	/* GET CHANNEL */
	*(uint32 *)buf = htod32(EWPF_DEBUG_BUF_LEN);
	ret = dhd_wl_ioctl_cmd(dhdp, WLC_GET_CHANNEL, buf, EWPF_DEBUG_BUF_LEN, FALSE, 0);
	if (ret != BCME_OK) {
		DHD_FILTER_ERR(("FAIL TO GET BSS INFO: %d\n", ret));
		return;
	}

	ci = (struct channel_info *)(buf + sizeof(uint32));
	channel = dtoh32(ci->hw_channel);
	DHD_FILTER_TRACE(("CHANNEL:prev %d new:%d\n", filter->last_channel, channel));

	memcpy(filter->last_bssid, bssid, ETHER_ADDR_LEN);
	filter->last_channel = channel;
	if (roam == FALSE) {
		return;
	}

	/* update connect time for roam */
	/* Refer STA interface */
	last_elem = dhd_ring_get_last(filter->i_ring[0]);
	if (last_elem == NULL) {
		armcycle = 0;
	} else {
		/* EXCLUDE before roam done */
		armcycle = *(uint32 *)last_elem + EWPF_EPOCH + 1;
	}

	filter->last_armcycle = armcycle;
}

/* ========= Event Handler functions and its callbacks: ============= */
typedef struct _EWPF_tbl {
	uint16 xtlv_id; /* XTLV ID, to handle */
	EWPF_filter_cb cb_func; /* specific call back function, usually for structre */
	int idx_type;			/* structure specific info: belonged type */
	int	max_idx;			/* structure specific info: ALLOWED MAX IDX */
	uint32 offset; /* offset of structure in EWPF_elem-t, valid if cb is not null */
	uint32 member_length;	/* MAX length of reserved for this structure */
	struct _EWPF_tbl *tbl; /* sub table if XTLV map to XLTV */
} EWPF_tbl_t;

/* Context structre for XTLV callback */
typedef struct {
	dhd_pub_t *dhdp;
	EWPF_tbl_t *tbl;
} EWPF_ctx_t;

#define SLICE_INFO(a) EWPF_IDX_TYPE_SLICE, EWPF_MAX_SLICE, OFFSETOF(EWPF_slc_elem_t, a), \
	sizeof(((EWPF_slc_elem_t *)NULL)->a)
#define IFACE_INFO(a) EWPF_IDX_TYPE_IFACE, EWPF_MAX_IFACE, OFFSETOF(EWPF_ifc_elem_t, a), \
	sizeof(((EWPF_ifc_elem_t *)NULL)->a)

#define SLICE_U_SIZE(a) sizeof(((EWPF_slc_elem_t *)NULL)->a)
#define SLICE_INFO_UNION(a) EWPF_IDX_TYPE_SLICE, EWPF_MAX_SLICE, OFFSETOF(EWPF_slc_elem_t, a)
#define NONE_INFO(a) 0, 0, a, 0
/* XTLV TBL for WL_SLICESTATS_XTLV_PERIODIC_STATE */
static EWPF_tbl_t EWPF_periodic[] =
{
	{
		WL_STATE_COMPACT_COUNTERS,
		evt_xtlv_copy_cb,
		SLICE_INFO_UNION(compact_cntr_v1),
		MAX(SLICE_U_SIZE(compact_cntr_v1), SLICE_U_SIZE(compact_cntr_v2)),
		NULL
	},
	{EWPF_XTLV_INVALID, NULL, NONE_INFO(0), NULL}
};

static EWPF_tbl_t EWPF_if_periodic[] =
{
	{
		WL_STATE_IF_COMPACT_STATE,
		evt_xtlv_copy_cb,
		IFACE_INFO(if_comp_stat),
		NULL
	},
	{EWPF_XTLV_INVALID, NULL, NONE_INFO(0), NULL}
};

/* XTLV TBL for EVENT_LOG_TAG_STATS */
static EWPF_tbl_t EWPF_main[] =
{
	/* MAIN XTLV */
	{
		WL_IFSTATS_XTLV_WL_SLICE,
		evt_xtlv_type_cb,
		NONE_INFO(0),
		EWPF_main
	},
	{
		WL_IFSTATS_XTLV_IF,
		evt_xtlv_type_cb,
		NONE_INFO(0),
		EWPF_main
	},
	/* ID XTLVs */
	{
		WL_IFSTATS_XTLV_SLICE_INDEX,
		evt_xtlv_idx_cb,
		NONE_INFO(0),
		NULL
	},
	{
		WL_IFSTATS_XTLV_IF_INDEX,
		evt_xtlv_idx_cb,
		NONE_INFO(0),
		NULL
	},
	/* NORMAL XTLVS */
	{
		WL_SLICESTATS_XTLV_PERIODIC_STATE,
		NULL,
		NONE_INFO(0),
		EWPF_periodic
	},
	{
		WL_IFSTATS_XTLV_IF_LQM,
		evt_xtlv_copy_cb,
		IFACE_INFO(lqm),
		NULL
	},
	{
		WL_IFSTATS_XTLV_GENERIC,
		evt_xtlv_copy_cb,
		IFACE_INFO(if_stat),
		NULL
	},
	{
		WL_IFSTATS_XTLV_MGT_CNT,
		evt_xtlv_copy_cb,
		IFACE_INFO(mgmt_stat),
		NULL
	},
	{
		WL_IFSTATS_XTLV_IF_PERIODIC_STATE,
		NULL,
		NONE_INFO(0),
		EWPF_if_periodic
	},
	{
		WL_IFSTATS_XTLV_INFRA_SPECIFIC,
		evt_xtlv_copy_cb,
		IFACE_INFO(infra),
		NULL
	},
	{
		WL_IFSTATS_XTLV_IF_EVENT_STATS,
		evt_xtlv_print_cb,
		NONE_INFO(0),
		NULL
	},

	{EWPF_XTLV_INVALID, NULL, NONE_INFO(0), NULL}
};

static int
evt_xtlv_print_cb(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	uint8 bssid[ETHER_ADDR_LEN];
	wl_event_based_statistics_v1_t *elem;

	DHD_FILTER_TRACE(("%s type:%d %x len:%d %x\n", __FUNCTION__, type, type, len, len));

	if (type == WL_IFSTATS_XTLV_IF_EVENT_STATS) {
		elem = (wl_event_based_statistics_v1_t *)(uintptr_t)data;
		if (elem->txdeauthivalclass > 0) {
			memcpy(bssid, &elem->BSSID, ETHER_ADDR_LEN);
			DHD_ERROR(("DHD STA sent DEAUTH frame with invalid class : %d times"
				", BSSID("MACDBG")\n", elem->txdeauthivalclass, MAC2STRDBG(bssid)));
		}
	} else {
		DHD_FILTER_ERR(("%s TYPE(%d) IS NOT SUPPORTED TO PRINT\n",
			__FUNCTION__, type));
		return BCME_ERROR;
	}

	return BCME_OK;
}

static int
evt_xtlv_copy_cb(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	EWPF_ctx_t *cur_ctx = (EWPF_ctx_t *)ctx;
	EWP_filter_t *filter = (EWP_filter_t *)cur_ctx->dhdp->event_log_filter;
	uint32 *armcycle;
	EWPF_tbl_t *tbl;
	void *ring;
	void *target;
	uint8 *ptr;
	int tbl_idx;
	uint32 elem_size;

	DHD_FILTER_TRACE(("%s type:%d %x len:%d %x\n", __FUNCTION__, type, type, len, len));

	for (tbl_idx = 0; ; tbl_idx++) {
		if (cur_ctx->tbl[tbl_idx].xtlv_id == EWPF_XTLV_INVALID) {
			DHD_FILTER_ERR(("%s NOT SUPPORTED TYPE(%d)\n", __FUNCTION__, type));
			return BCME_OK;
		}
		if (cur_ctx->tbl[tbl_idx].xtlv_id == type) {
			tbl = &cur_ctx->tbl[tbl_idx];
			break;
		}
	}

	/* Check Validation */
	if (filter->idx_type == EWPF_INVALID ||
		filter->xtlv_idx == EWPF_INVALID ||
		filter->idx_type != tbl->idx_type ||
		filter->xtlv_idx >= tbl->max_idx) {
		DHD_FILTER_ERR(("XTLV VALIDATION FAILED: type:%x xtlv:%x idx:%d\n",
			filter->idx_type, tbl->xtlv_id, filter->xtlv_idx));
		return BCME_OK;
	}

	/* SET RING INFO */
	if (filter->idx_type == EWPF_IDX_TYPE_SLICE) {
		ring = filter->s_ring[filter->xtlv_idx];
		elem_size = sizeof(EWPF_slc_elem_t);
	} else {
		ring = filter->i_ring[filter->xtlv_idx];
		elem_size = sizeof(EWPF_ifc_elem_t);
	}

	/* Check armcycle epoch is changed */
	target = dhd_ring_get_last(ring);
	if (target != NULL) {
		armcycle = (uint32 *)target;
		if (*armcycle + EWPF_EPOCH <= filter->tmp_armcycle) {
			/* EPOCH is changed (longer than 1sec) */
			target = NULL;
		} else if (*armcycle - EWPF_EPOCH >= filter->tmp_armcycle) {
			/* dongle is rebooted */
			target = NULL;
		}
	}

	if (target == NULL) {
		/* Get new idx */
		target = dhd_ring_get_empty(ring);
		if (target == NULL) {
			/* no available slot due to oldest slot is locked */
			DHD_FILTER_ERR(("SKIP to logging xltv(%x) due to locking\n", type));
			return BCME_OK;
		}

		/* clean up target */
		armcycle = (uint32 *)target;
		memset(target, 0, elem_size);
		memcpy(armcycle, &filter->tmp_armcycle, sizeof(*armcycle));
	}

#ifdef EWPF_DEBUG
	DHD_FILTER_ERR(("idx:%d write_:%p %d %d\n",
		filter->xtlv_idx, target, *armcycle, filter->tmp_armcycle));
#endif // endif

	if (len > cur_ctx->tbl[tbl_idx].member_length) {
		DHD_FILTER_ERR(("data Length is too big to save: (alloc = %d), (data = %d)\n",
			cur_ctx->tbl[tbl_idx].member_length, len));
		return BCME_ERROR;
	}

	ptr = (uint8 *)target;
	memcpy(ptr + cur_ctx->tbl[tbl_idx].offset, data, len);
	return BCME_OK;
}

static int
evt_xtlv_idx_cb(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	EWPF_ctx_t *cur_ctx = (EWPF_ctx_t *)ctx;
	EWP_filter_t *filter = (EWP_filter_t *)cur_ctx->dhdp->event_log_filter;

	filter->xtlv_idx = data[0];

	if (filter->idx_type == EWPF_IDX_TYPE_SLICE) {
		if (type != WL_IFSTATS_XTLV_SLICE_INDEX ||
			filter->xtlv_idx >= EWPF_MAX_SLICE) {
			goto idx_fail;
		}
	} else if (filter->idx_type == EWPF_IDX_TYPE_IFACE) {
		if (type != WL_IFSTATS_XTLV_IF_INDEX ||
			filter->xtlv_idx >= EWPF_MAX_IFACE) {
			DHD_FILTER_ERR(("CHANGE IFACE TO 0 in FORCE\n"));
			return BCME_OK;
		}
	} else {
		goto idx_fail;
	}
	return BCME_OK;

idx_fail:
	DHD_FILTER_ERR(("UNEXPECTED IDX XTLV: filter_type:%d input_type%x idx:%d\n",
		filter->idx_type, type, filter->xtlv_idx));
	filter->idx_type = EWPF_INVALID;
	filter->xtlv_idx = EWPF_INVALID;
	return BCME_OK;
}

static int
evt_xtlv_type_cb(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	EWPF_ctx_t *cur_ctx = (EWPF_ctx_t *)ctx;
	EWP_filter_t *filter = (EWP_filter_t *)cur_ctx->dhdp->event_log_filter;

	if (type == WL_IFSTATS_XTLV_WL_SLICE) {
		filter->idx_type = EWPF_IDX_TYPE_SLICE;
		DHD_FILTER_TRACE(("SLICE XTLV\n"));
	} else if (type == WL_IFSTATS_XTLV_IF) {
		filter->idx_type = EWPF_IDX_TYPE_IFACE;
		DHD_FILTER_TRACE(("IFACE XTLV\n"));
	}
	bcm_unpack_xtlv_buf(ctx, data, len,
		BCM_XTLV_OPTION_ALIGN32, filter_main_cb);
	return BCME_OK;
}

static int
filter_main_cb(void *ctx, const uint8 *data, uint16 type, uint16 len)
{
	EWPF_ctx_t *cur_ctx = (EWPF_ctx_t *)ctx;
	EWPF_ctx_t sub_ctx;
	int idx;
	int err;

	DHD_FILTER_TRACE(("%s type:%x len:%d\n", __FUNCTION__, type, len));

	sub_ctx.dhdp = cur_ctx->dhdp;
	for (idx = 0; ; idx++) {
		if (cur_ctx->tbl[idx].xtlv_id == EWPF_XTLV_INVALID) {
			DHD_FILTER_TRACE(("%s NOT SUPPORTED TYPE(%d)\n", __FUNCTION__, type));
			return BCME_OK;
		}
		if (cur_ctx->tbl[idx].xtlv_id == type) {
			break;
		}
	}

	/* parse sub xtlv */
	if (cur_ctx->tbl[idx].cb_func == NULL) {
		sub_ctx.tbl = cur_ctx->tbl[idx].tbl;
		err = bcm_unpack_xtlv_buf(&sub_ctx, data, len,
			BCM_XTLV_OPTION_ALIGN32, filter_main_cb);
		return err;
	}

	/* handle for structure/variable */
	return cur_ctx->tbl[idx].cb_func(ctx, data, type, len);
}

void
dhd_event_log_filter_event_handler(dhd_pub_t *dhdp, event_log_hdr_t *log_hdr, uint32 *data)
{
	int err;
	EWP_filter_t *filter;
	EWPF_ctx_t ctx;

	if (!dhdp->event_log_filter) {
		DHD_FILTER_ERR(("NO FILTER MODULE\n"));
		return;
	}

	if (!log_hdr || !data) {
		DHD_FILTER_ERR(("INVALID PARAMETER\n"));
		return;
	}

	filter = (EWP_filter_t *)dhdp->event_log_filter;
	if (filter->enabled != TRUE) {
		DHD_FILTER_ERR(("FITLER IS NOT STARTED\n"));
		return;
	}

	/* get ARMCYCLE */
	filter->tmp_armcycle = data[log_hdr->count - 1];
	filter->idx_type = EWPF_INVALID;
	filter->xtlv_idx = EWPF_INVALID;

#ifdef EWPF_DEBUG
	{
		char buf[EWPF_DEBUG_BUF_LEN];
		int idx;

		memset(buf, 0, sizeof(buf));
		DHD_FILTER_ERR(("tag %d(%x) count %d(%x)\n",
			log_hdr->tag, log_hdr->tag, log_hdr->count, log_hdr->count));
		for (idx = 0; idx < log_hdr->count; idx++) {
			sprintf(&buf[strlen(buf)], "%08x ", data[idx]);
			if ((idx + 1) % EWPF_VAL_CNT_PLINE == 0) {
				DHD_FILTER_ERR(("%s\n", buf));
				memset(buf, 0, sizeof(buf));
			}
		}
		if (strlen(buf) > 0) {
			DHD_FILTER_ERR(("%s\n", buf));
		}
	}
#endif /* EWPF_DEBUG */

	ctx.dhdp = dhdp;
	ctx.tbl = EWPF_main;
	if ((err = bcm_unpack_xtlv_buf(
		&ctx,
		(const uint8 *)data,
		(log_hdr->count - 1) * sizeof(uint32),
		BCM_XTLV_OPTION_ALIGN32,
		filter_main_cb))) {
		DHD_FILTER_ERR(("FAIL TO UNPACK XTLV: err(%d)\n", err));
	}
}
/* ========= Private Command(Serialize) ============= */
//#define EWPR_DEBUG
#ifdef EWPR_DEBUG
#undef DHD_FILTER_TRACE
#define DHD_FILTER_TRACE DHD_FILTER_ERR
#endif /* EWPR_DEBUG */
#define EWPR_DEBUG_BUF_LEN	512

#define EWP_REPORT_VERSION	0x20170905
#define EWP_REPORT_ELEM_PRINT_BUF	256
#define EWP_REPORT_NAME_MAX	64

#define EWPR_CSDCLIENT_DIFF	4
#define EWPR_DELTA3_POS		3
#define EWPR_DELTA2_POS		2
#define EWPR_DELTA1_POS		1
#define EWPR_NOW_POS		0

#define EWPR_INTERVAL	3
#define EWPR_DELTA1_CNT	2	/* 6 seconds before */
#define EWPR_DELTA2_CNT	5	/* 15 seconds before */
#define EWPR_DELTA3_CNT	9	/* 27 seconds before */
#define EWPR_ARRAY_CNT	10	/* INTERVAL * ARRAY total 30 seconds to lock */

#define EWPR_CNT_PER_LINE	5

/* EWP Reporter display format */
#define EWP_DEC	1
#define EWP_HEX	2

/* EWP Filter Data type */
/* BASIC : signed + length */
#define EWP_UINT8	2
#define EWP_UINT16	4
#define EWP_UINT32	8
#define EWP_UINT64	16
#define EWP_INT8	102
#define EWP_INT16	104
#define EWP_INT32	108

/* NON BAISC : need special handling */
#define EWP_NON_BASIC	200
#define EWP_DATE		201
#define EWP_TIME		202
#define EWP_BSSID		203
#define EWP_OUI			204

/* Delimiter between values */
#define KEY_DEL	' '
#define RAW_DEL '_'

/* IOVAR BUF SIZE */
#define EWPR_IOV_BUF_LEN	64

typedef struct {
	void *ring;				/* INPUT ring to lock */
	void **elem_list;		/* OUTPUT elem ptr list for each delta */
	uint32 max_armcycle;	/* IN/OUT arm cycle should be less than this */
	uint32 min_armcycle;	/* IN/OUT arm cycle should be bigger than this */
	uint32 max_period;		/* IN allowed time diff between first and last */
	uint32 delta_cnt;		/* IN finding delta count */
	uint32 *delta_list;		/* IN delta values to find */
} ewpr_lock_param_t;

#define MAX_MULTI_VER	2
typedef struct {
	uint32	version;		/* VERSION for multiple version struct */
	uint32	offset;			/* offset of the member at the version */
} ewpr_MVT_offset_elem_t;	/* elem for multi version type */

typedef struct {
	uint32	version_offset;		/* offset of version */
	ewpr_MVT_offset_elem_t opv[MAX_MULTI_VER];	/* offset per version */
} ewpr_MVT_offset_t;			/* multi_version type */

typedef struct {
	char name[EWP_REPORT_NAME_MAX];
	int ring_type;		/* Ring Type : EWPF_IDX_TYPE_SLICE, EWPF_IDX_TYPE_IFACE */
	int	is_multi_version;		/* is multi version */
	union {
		uint32 offset;			/* Offset from start of element structure */
		ewpr_MVT_offset_t v_info;
	};
	int data_type;				/* Data type : one of EWP Filter Data Type */
	int display_format;			/* Display format : one of EWP Reporter display */
	int display_type;			/* MAX display BYTE: valid for HEX FORM */
} ewpr_serial_info_t;

/* offset defines */
#define EWPR_CNT_VERSION_OFFSET \
	OFFSETOF(EWPF_slc_elem_t, compact_cntr_v1)

#define EWPR_CNT_V1_OFFSET(a) \
	WL_PERIODIC_COMPACT_CNTRS_VER_1, \
	(OFFSETOF(EWPF_slc_elem_t, compact_cntr_v1) + OFFSETOF(wl_periodic_compact_cntrs_v1_t, a))
#define EWPR_CNT_V2_OFFSET(a) \
	WL_PERIODIC_COMPACT_CNTRS_VER_2, \
	(OFFSETOF(EWPF_slc_elem_t, compact_cntr_v2) + OFFSETOF(wl_periodic_compact_cntrs_v2_t, a))
#define EWPR_STAT_OFFSET(a) \
	(OFFSETOF(EWPF_ifc_elem_t, if_stat) + OFFSETOF(wl_if_stats_t, a))
#define EWPR_INFRA_OFFSET(a) \
	(OFFSETOF(EWPF_ifc_elem_t, infra) + OFFSETOF(wl_if_infra_stats_t, a))
#define EWPR_MGMT_OFFSET(a) \
	(OFFSETOF(EWPF_ifc_elem_t, mgmt_stat) + OFFSETOF(wl_if_mgt_stats_t, a))
#define EWPR_LQM_OFFSET(a) \
	(OFFSETOF(EWPF_ifc_elem_t, lqm) + OFFSETOF(wl_lqm_t, a))
#define EWPR_SIGNAL_OFFSET(a) \
	(EWPR_LQM_OFFSET(current_bss) + OFFSETOF(wl_rx_signal_metric_t, a))
#define EWPR_IF_COMP_OFFSET(a) \
	(OFFSETOF(EWPF_ifc_elem_t, if_comp_stat) + OFFSETOF(wl_if_state_compact_t, a))

/* serail info type define */
#define EWPR_SERIAL_CNT(a) {\
	#a, EWPF_IDX_TYPE_SLICE, TRUE, \
	.v_info = { EWPR_CNT_VERSION_OFFSET, \
		{{EWPR_CNT_V1_OFFSET(a)}, \
		{EWPR_CNT_V2_OFFSET(a)}}}, \
	EWP_UINT32, EWP_HEX, EWP_UINT32}
#define EWPR_SERIAL_CNT_16(a) {\
	#a, EWPF_IDX_TYPE_SLICE, TRUE, \
	.v_info = { EWPR_CNT_VERSION_OFFSET, \
		{{EWPR_CNT_V1_OFFSET(a)}, \
		{EWPR_CNT_V2_OFFSET(a)}}}, \
	EWP_UINT32, EWP_HEX, EWP_UINT16}
#define EWPR_SERIAL_STAT(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_STAT_OFFSET(a), \
	EWP_UINT64, EWP_HEX, EWP_UINT32}
#define EWPR_SERIAL_INFRA(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_INFRA_OFFSET(a), \
	EWP_UINT32, EWP_HEX, EWP_UINT16}
#define EWPR_SERIAL_MGMT(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_MGMT_OFFSET(a), \
	EWP_UINT32, EWP_HEX, EWP_UINT16}
#define EWPR_SERIAL_LQM(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_LQM_OFFSET(a), \
	EWP_INT32, EWP_DEC, EWP_INT8}
#define EWPR_SERIAL_SIGNAL(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_SIGNAL_OFFSET(a), \
	EWP_INT32, EWP_DEC, EWP_INT8}
#define EWPR_SERIAL_IFCOMP_8(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_IF_COMP_OFFSET(a), \
	EWP_INT8, EWP_DEC, EWP_INT8}
#define EWPR_SERIAL_IFCOMP_16(a) {\
	#a, EWPF_IDX_TYPE_IFACE, FALSE, .offset = EWPR_IF_COMP_OFFSET(a), \
	EWP_UINT16, EWP_DEC, EWP_UINT16}
#define EWPR_SERIAL_ARM(a) {\
	"armcycle:" #a, EWPF_IDX_TYPE_##a, FALSE, {0, }, \
	EWP_UINT32, EWP_DEC, EWP_UINT32}
#define EWPR_SERIAL_NONE {"", EWPF_INVALID, FALSE, {0, }, 0, 0, 0}

ewpr_serial_info_t
ewpr_serial_CSDCLIENT_key_tbl[] = {
	EWPR_SERIAL_STAT(txframe),
	EWPR_SERIAL_STAT(txerror),
	EWPR_SERIAL_STAT(rxframe),
	EWPR_SERIAL_STAT(rxerror),
	EWPR_SERIAL_STAT(txretrans),
	EWPR_SERIAL_INFRA(rxbeaconmbss),
	EWPR_SERIAL_CNT(txallfrm),
	EWPR_SERIAL_CNT(rxrsptmout),
	EWPR_SERIAL_CNT(rxbadplcp),
	EWPR_SERIAL_CNT(rxcrsglitch),
	EWPR_SERIAL_CNT(rxbadfcs),
	EWPR_SERIAL_CNT_16(rxbeaconmbss),
	EWPR_SERIAL_CNT_16(rxbeaconobss),
	EWPR_SERIAL_NONE
};

ewpr_serial_info_t
ewpr_serial_CSDCLIENT_diff_tbl[] = {
	EWPR_SERIAL_STAT(txframe),
	EWPR_SERIAL_STAT(txerror),
	EWPR_SERIAL_STAT(rxframe),
	EWPR_SERIAL_STAT(rxerror),
	EWPR_SERIAL_STAT(txretrans),
	EWPR_SERIAL_INFRA(rxbeaconmbss),
	EWPR_SERIAL_MGMT(txassocreq),
	EWPR_SERIAL_MGMT(txreassocreq),
	EWPR_SERIAL_MGMT(txdisassoc),
	EWPR_SERIAL_MGMT(rxdisassoc),
	EWPR_SERIAL_MGMT(rxassocrsp),
	EWPR_SERIAL_MGMT(rxreassocrsp),
	EWPR_SERIAL_MGMT(txauth),
	EWPR_SERIAL_MGMT(rxauth),
	EWPR_SERIAL_MGMT(txdeauth),
	EWPR_SERIAL_MGMT(rxdeauth),
	EWPR_SERIAL_MGMT(txaction),
	EWPR_SERIAL_MGMT(rxaction),
	EWPR_SERIAL_CNT(txallfrm),
	EWPR_SERIAL_CNT(rxrsptmout),
	EWPR_SERIAL_CNT(rxbadplcp),
	EWPR_SERIAL_CNT(rxcrsglitch),
	EWPR_SERIAL_CNT(rxbadfcs),
	EWPR_SERIAL_CNT_16(rxbeaconmbss),
	EWPR_SERIAL_CNT_16(rxbeaconobss),
	EWPR_SERIAL_NONE
};

ewpr_serial_info_t
ewpr_serial_CSDCLIENT_array_tbl[] = {
	EWPR_SERIAL_IFCOMP_8(rssi_sum),
	EWPR_SERIAL_IFCOMP_8(snr),
	EWPR_SERIAL_IFCOMP_8(noise_level),
	EWPR_SERIAL_NONE
};

#ifdef EWPR_DEBUG
ewpr_serial_info_t
ewpr_serial_dbg_tbl[] = {
	EWPR_SERIAL_ARM(IFACE),
	EWPR_SERIAL_ARM(SLICE),
	EWPR_SERIAL_NONE
};
#endif /* EWPR_DEBUG */

int ewpr_set_period_lock(ewpr_lock_param_t *param);
int ewpr_diff_serial(ewpr_serial_info_t *info, char *buf,
	int buf_len, void *_f_op, void *_s_op, char del);
int ewpr_single_serial(ewpr_serial_info_t *info, char *buf, int buf_len, void *ptr, char del);

int
ewpr_serial_basic(char *buf, int buf_len, uint32 data, int format, int display_type, char del)
{
	if (format == EWP_HEX) {
		switch (display_type) {
			case EWP_INT8:
			case EWP_UINT8:
				return scnprintf(buf, buf_len, "%c%02x", del, data & 0xff);
			case EWP_INT16:
			case EWP_UINT16:
				return scnprintf(buf, buf_len, "%c%04x", del, data & 0xffff);
			case EWP_INT32:
			case EWP_UINT32:
				return scnprintf(buf, buf_len, "%c%08x", del, data & 0xffffffff);
			default:
				DHD_FILTER_ERR(("INVALID TYPE for Serial:%d", display_type));
				return 0;
		}
	}

	if (format == EWP_DEC) {
		int32 sdata = (int32) data;
		switch (display_type) {
			case EWP_INT8:
			case EWP_UINT8:
				return scnprintf(buf, buf_len, "%c%04d", del, sdata);
			case EWP_INT16:
			case EWP_UINT16:
				return scnprintf(buf, buf_len, "%c%06d", del, sdata);
			case EWP_INT32:
			case EWP_UINT32:
				return scnprintf(buf, buf_len, "%c%011d", del, sdata);
			default:
				DHD_FILTER_ERR(("INVALID TYPE for Serial:%d", display_type));
				return 0;
		}
	}

	DHD_FILTER_ERR(("INVALID FORMAT for Serial:%d", format));
	return 0;
}

static int
ewpr_get_multi_offset(uint16 looking_version, ewpr_serial_info_t *info)
{
	int idx;
	ewpr_MVT_offset_elem_t *opv;

	DHD_FILTER_TRACE(("FINDING MULTI OFFSET: type = %s version = %d\n",
		info->name, looking_version));
	for (idx = 0; idx < MAX_MULTI_VER; idx ++) {
		opv = &(info->v_info.opv[idx]);

		/* END OF MULTI VERSION */
		if (opv->version == 0) {
			DHD_FILTER_ERR(("NO VERSION of finding(%d) type = %s\n",
				looking_version, info->name));
			return EWPF_INVALID;
		}
		if (looking_version == opv->version) {
			return opv->offset;
		}
	}
	DHD_FILTER_ERR(("NO VERSION of finding(%d) type = %s\n",
		looking_version, info->name));
	return EWPF_INVALID;
}
int
ewpr_single_serial(ewpr_serial_info_t *info, char *buf, int buf_len, void *_ptr, char del)
{
	uint32 sval = 0;
	char *ptr = (char *)_ptr;
	uint32 offset = EWPF_INVALID;
	uint16	version;

	if (info->is_multi_version == TRUE) {
		version = *(uint16 *)((char *)_ptr + info->v_info.version_offset);
		offset = ewpr_get_multi_offset(version, info);
	} else {
		offset = info->offset;
	}

	if (offset == EWPF_INVALID) {
		DHD_FILTER_ERR(("INVALID TYPE to OFFSET:%s\n", info->name));
		return 0;
	}

	ptr += offset;

	switch (info->data_type) {
		case EWP_INT8:
			sval = *(int8 *)ptr;
			break;
		case EWP_UINT8:
			sval = *(uint8 *)ptr;
			break;
		case EWP_INT16:
			sval = *(int16 *)ptr;
			break;
		case EWP_UINT16:
			sval = *(uint16 *)ptr;
			break;
		case EWP_INT32:
			sval = *(int32 *)ptr;
			break;
		case EWP_UINT32:
			sval = *(uint32 *)ptr;
			break;
#ifdef EWPR_DEBUG
		case EWP_UINT64:
			sval = (uint32)(*(uint64 *)ptr);
			break;
#endif /* EWPR_DEBUG */
		default:
			DHD_FILTER_ERR(("INVALID TYPE for Single Serial:%d", info->data_type));
			return 0;
	}

	return ewpr_serial_basic(buf, buf_len, sval, info->display_format, info->display_type, del);
}

int
ewpr_diff_serial(ewpr_serial_info_t *info,
	char *buf, int buf_len, void *_f_op, void *_s_op, char del)
{
	char *f_op = (char *)_f_op;
	char *s_op = (char *)_s_op;
	uint32 diff;
	uint32 offset = EWPF_INVALID;
	uint16	version;

	if (info->is_multi_version == TRUE) {
		version = *(uint16 *)(f_op + info->v_info.version_offset);
		offset = ewpr_get_multi_offset(version, info);
	} else {
		offset = info->offset;
	}

	if (offset == EWPF_INVALID) {
		DHD_FILTER_ERR(("INVALID TYPE to OFFSET:%s\n", info->name));
		return 0;
	}

	f_op = f_op + offset;
	s_op = s_op + offset;

	switch (info->data_type) {
		case EWP_INT8:
		case EWP_UINT8:
			diff = *(uint8 *)f_op - *(uint8 *)s_op;
			break;
		case EWP_INT16:
		case EWP_UINT16:
			diff = *(uint16 *)f_op - *(uint16 *)s_op;
			break;
		case EWP_INT32:
		case EWP_UINT32:
			diff = *(uint32 *)f_op - *(uint32 *)s_op;
			break;
		case EWP_UINT64:
			diff = (uint32)(*(uint64 *)f_op - *(uint64 *)s_op);
			break;
		default:
			DHD_FILTER_ERR(("INVALID TYPE to DIFF:%d", info->data_type));
			return 0;
	}

	return ewpr_serial_basic(buf, buf_len, diff, info->display_format, info->display_type, del);
}

#ifdef EWPR_DEBUG
void
ewpr_debug_dump(ewpr_serial_info_t *tbl, void **ring)
{
	void *elem;
	int idx, idx2;
	ewpr_serial_info_t *info;
	char buf[EWPR_DEBUG_BUF_LEN];
	uint32 bytes_written;
	int lock_cnt;

	for (idx = 0; strlen(tbl[idx].name) != 0; idx++) {
		info = &tbl[idx];
		memset(buf, 0, sizeof(buf));
		lock_cnt = dhd_ring_lock_get_count(ring[info->ring_type - 1]);
		elem = dhd_ring_lock_get_first(ring[info->ring_type - 1]);
		bytes_written = scnprintf(buf, EWPR_DEBUG_BUF_LEN, "%s:", info->name);
		for (idx2 = 0; elem && (idx2 < lock_cnt); idx2++) {
			bytes_written += ewpr_single_serial(info, &buf[bytes_written],
				EWPR_DEBUG_BUF_LEN - bytes_written, elem, KEY_DEL);
			elem = dhd_ring_get_next(ring[info->ring_type - 1], elem);
		}
		DHD_FILTER_ERR(("%s\n", buf));
	}
}
#endif /* EWPR_DEBUG */

uint32
dhd_event_log_filter_serialize(dhd_pub_t *dhdp, char *in_buf, uint32 tot_len, int type)
{
	EWP_filter_t *filter = (EWP_filter_t *)dhdp->event_log_filter;
	void *ring[EWPF_MAX_IDX_TYPE];
	char *ret_buf = in_buf;
	int slice_id;
	int iface_id;
	int idx, idx2;
	uint32 bytes_written = 0;
	void *elem[EWPF_MAX_IDX_TYPE][EWPR_CSDCLIENT_DIFF];
	void **elem_list;
	int lock_cnt, lock_cnt2;
	char *last_print;
	void *arr_elem;
	uint32 delta_list[EWPR_CSDCLIENT_DIFF];
	ewpr_lock_param_t lock_param;
	int print_name = FALSE;
	char cookie_str[DEBUG_DUMP_TIME_BUF_LEN];
	char iov_buf[EWPR_IOV_BUF_LEN];

	if (type != 0) {
		DHD_FILTER_ERR(("NOT SUPPORTED TYPE: %d\n", type));
		return 0;
	}

	iface_id = 0; /* STA INTERFACE ONLY */
	if (filter->last_channel <= CH_MAX_2G_CHANNEL) {
		slice_id = EWPF_SLICE_AUX;
	} else {
		slice_id = EWPF_SLICE_MAIN;
	}
	ring[EWPF_IDX_TYPE_SLICE - 1] = filter->s_ring[slice_id];
	ring[EWPF_IDX_TYPE_IFACE - 1] = filter->i_ring[iface_id];

	/* Configure common LOCK parameter */
	lock_param.max_armcycle = (uint32)EWPF_INVALID;
	lock_param.min_armcycle = filter->last_armcycle;
	lock_param.max_period = (EWPR_ARRAY_CNT - 1)* EWPR_INTERVAL;
	lock_param.max_period *= EWPF_MSEC_TO_SEC * EWPF_ARM_TO_MSEC;
	lock_param.delta_cnt = ARRAYSIZE(delta_list);
	lock_param.delta_list = delta_list;

	delta_list[EWPR_DELTA3_POS] = EWPR_DELTA3_CNT;
	delta_list[EWPR_DELTA2_POS] = EWPR_DELTA2_CNT;
	delta_list[EWPR_DELTA1_POS] = EWPR_DELTA1_CNT;
	delta_list[EWPR_NOW_POS] = 0;
	lock_param.ring = ring[EWPF_IDX_TYPE_IFACE -1];
	lock_param.elem_list = elem[EWPF_IDX_TYPE_IFACE -1];
	lock_cnt = ewpr_set_period_lock(&lock_param);
	if (lock_cnt <= 0) {
		DHD_FILTER_ERR(("FAIL TO GET IFACE LOCK: %d\n", iface_id));
		bytes_written = 0;
		goto finished;
	}

	delta_list[EWPR_DELTA3_POS] = EWPR_DELTA3_CNT;
	delta_list[EWPR_DELTA2_POS] = EWPR_DELTA2_CNT;
	delta_list[EWPR_DELTA1_POS] = EWPR_DELTA1_CNT;
	delta_list[EWPR_NOW_POS] = 0;
	lock_param.ring = ring[EWPF_IDX_TYPE_SLICE -1];
	lock_param.elem_list = elem[EWPF_IDX_TYPE_SLICE -1];
	lock_cnt2 = ewpr_set_period_lock(&lock_param);
	if (lock_cnt2 <= 0) {
		DHD_FILTER_ERR(("FAIL TO GET SLICE LOCK: %d\n", slice_id));
		goto finished;
	}

	if (lock_cnt != lock_cnt2) {
		DHD_FILTER_ERR(("Lock Count is Diff: iface:%d slice:%d\n", lock_cnt, lock_cnt2));
		lock_cnt = MIN(lock_cnt, lock_cnt2);
	}

#ifdef EWPR_DEBUG
	print_name = TRUE;
	ewpr_debug_dump(ewpr_serial_dbg_tbl, ring);
	ewpr_debug_dump(ewpr_serial_CSDCLIENT_diff_tbl, ring);
	ewpr_debug_dump(ewpr_serial_CSDCLIENT_array_tbl, ring);
#endif /* EWPR_DEBUG */

	memset(ret_buf, 0, tot_len);
	memset(cookie_str, 0, DEBUG_DUMP_TIME_BUF_LEN);
	bytes_written = 0;
	last_print = ret_buf;

	get_debug_dump_time(cookie_str);
#ifdef DHD_LOG_DUMP
	dhd_logdump_cookie_save(dhdp, cookie_str, "ECNT");
#endif // endif

	/* KEY DATA */
	bytes_written += scnprintf(&ret_buf[bytes_written],
		tot_len - bytes_written, "%08x", EWP_REPORT_VERSION);
	bytes_written += scnprintf(&ret_buf[bytes_written],
		tot_len - bytes_written, "%c%s", KEY_DEL, cookie_str);
	DHD_FILTER_ERR(("%d: %s\n", bytes_written, last_print));
	last_print = &ret_buf[bytes_written];

	for (idx = 0; strlen(ewpr_serial_CSDCLIENT_key_tbl[idx].name) != 0; idx++) {
		ewpr_serial_info_t *info = &ewpr_serial_CSDCLIENT_key_tbl[idx];
		elem_list = elem[info->ring_type - 1];
		if (print_name) {
			bytes_written += scnprintf(&ret_buf[bytes_written],
				tot_len - bytes_written, " %s:", info->name);
		}
		bytes_written += ewpr_diff_serial(info, &ret_buf[bytes_written],
			tot_len - bytes_written,
			elem_list[EWPR_NOW_POS],
			elem_list[EWPR_DELTA1_POS],
			KEY_DEL);
		if ((idx + 1) % EWPR_CNT_PER_LINE == 0) {
			DHD_FILTER_ERR(("%d:%s\n", bytes_written, last_print));
			last_print = &ret_buf[bytes_written];
		}
	}

	/* RAW DATA */
	bytes_written += scnprintf(&ret_buf[bytes_written],
		tot_len - bytes_written, "%c%08x", KEY_DEL, EWP_REPORT_VERSION);
	bytes_written += scnprintf(&ret_buf[bytes_written],
		tot_len - bytes_written, "%c%s", RAW_DEL, cookie_str);

	for (idx = 0; strlen(ewpr_serial_CSDCLIENT_diff_tbl[idx].name) != 0; idx++) {
		ewpr_serial_info_t *info = &ewpr_serial_CSDCLIENT_diff_tbl[idx];
		elem_list = elem[info->ring_type - 1];
		if (print_name) {
			bytes_written += scnprintf(&ret_buf[bytes_written],
				tot_len - bytes_written, " %s:", info->name);
		}
		bytes_written += ewpr_diff_serial(info, &ret_buf[bytes_written],
			tot_len - bytes_written,
			elem_list[EWPR_NOW_POS],
			elem_list[EWPR_DELTA1_POS],
			RAW_DEL);
		bytes_written += ewpr_diff_serial(info, &ret_buf[bytes_written],
			tot_len - bytes_written,
			elem_list[EWPR_DELTA1_POS],
			elem_list[EWPR_DELTA2_POS],
			RAW_DEL);
		if ((idx + 1) % EWPR_CNT_PER_LINE == 0) {
			DHD_FILTER_ERR(("%d:%s\n", bytes_written, last_print));
			last_print = &ret_buf[bytes_written];
		}
	}

	/* FILL BSS SPECIFIC DATA LATER */
	if (dhd_iovar(dhdp, 0, "auth", NULL, 0, iov_buf, ARRAYSIZE(iov_buf), FALSE) < 0) {
		DHD_FILTER_ERR(("fail to get auth\n"));
		*(uint32 *)iov_buf = EWPF_INVALID;

	}
	bytes_written += scnprintf(&ret_buf[bytes_written],
			tot_len - bytes_written, "%c%08x", RAW_DEL, *(uint32 *)iov_buf);

	if (dhd_iovar(dhdp, 0, "wsec", NULL, 0, iov_buf, ARRAYSIZE(iov_buf), FALSE) < 0) {
		DHD_FILTER_ERR(("fail to get wsec\n"));
		*(uint32 *)iov_buf = EWPF_INVALID;

	}
	bytes_written += scnprintf(&ret_buf[bytes_written],
			tot_len - bytes_written, "%c%08x", RAW_DEL, *(uint32 *)iov_buf);

	if (dhd_iovar(dhdp, 0, "mfp", NULL, 0, iov_buf, ARRAYSIZE(iov_buf), FALSE) < 0) {
		DHD_FILTER_ERR(("fail to get mfp\n"));
		*(uint8 *)iov_buf = EWPF_INVALID;

	}
	bytes_written += scnprintf(&ret_buf[bytes_written],
			tot_len - bytes_written, "%c%02x", RAW_DEL, *(uint8 *)iov_buf);

	if (dhd_iovar(dhdp, 0, "bip", NULL, 0, iov_buf, ARRAYSIZE(iov_buf), FALSE) < 0) {
		DHD_FILTER_ERR(("fail to get bip\n"));
		*(uint8 *)iov_buf = EWPF_INVALID;
	}
	bytes_written += scnprintf(&ret_buf[bytes_written],
			tot_len - bytes_written, "%c%02x", RAW_DEL, *(uint8 *)iov_buf);

	for (idx = 0; strlen(ewpr_serial_CSDCLIENT_array_tbl[idx].name) != 0; idx++) {
		ewpr_serial_info_t *info = &ewpr_serial_CSDCLIENT_array_tbl[idx];
		if (print_name) {
			bytes_written += scnprintf(&ret_buf[bytes_written],
				tot_len - bytes_written, " %s:", info->name);
		}
		for (idx2 = 0; idx2 < EWPR_ARRAY_CNT - lock_cnt; idx2++) {
			bytes_written += ewpr_serial_basic(&ret_buf[bytes_written],
				tot_len - bytes_written, 0,
				info->display_format, info->display_type, RAW_DEL);
		}
		arr_elem = elem[info->ring_type - 1][EWPR_DELTA3_POS];
		for (; idx2 < EWPR_ARRAY_CNT; idx2++) {
			if (arr_elem == NULL) {
				DHD_FILTER_ERR(("ARR IS NULL : %d %p \n",
					idx2, elem[info->ring_type - 1][EWPR_DELTA3_POS]));
				break;
			}
			bytes_written += ewpr_single_serial(info, &ret_buf[bytes_written],
				tot_len - bytes_written, arr_elem, RAW_DEL);
			arr_elem = dhd_ring_get_next(ring[info->ring_type - 1], arr_elem);
		}
		DHD_FILTER_ERR(("%d:%s\n", bytes_written, last_print));
		last_print = &ret_buf[bytes_written];
	}

finished:
	DHD_FILTER_ERR(("RET LEN:%d\n", (int)strlen(ret_buf)));
	dhd_ring_lock_free(ring[EWPF_IDX_TYPE_SLICE - 1]);
	dhd_ring_lock_free(ring[EWPF_IDX_TYPE_IFACE - 1]);
	return bytes_written;
}

int
ewpr_set_period_lock(ewpr_lock_param_t *param)
{
	void *last;
	void *first;
	void *cur;
	int lock_cnt;
	int idx2;
	int delta_idx;
	uint32 last_armcycle;
	uint32 first_armcycle;
	uint32 cur_armcycle = 0;
	void *ring = param->ring;

	/* GET LATEST PTR */
	last = dhd_ring_get_last(ring);
	while (TRUE) {
		if (last == NULL) {
			DHD_FILTER_ERR(("NO LAST\n"));
			return -1;
		}
		last_armcycle = *(uint32 *)last;
		if (last_armcycle <= param->max_armcycle ||
			last_armcycle + EWPF_EPOCH >= param->max_armcycle) {
			break;
		}
		last = dhd_ring_get_prev(ring, last);
	}

	if (last_armcycle != param->max_armcycle) {
		DHD_FILTER_TRACE(("MAX ARMCYCLE IS CHANGEd new:%d prev:%d\n",
			last_armcycle, param->max_armcycle));
		param->max_armcycle = last_armcycle;
	}

	if (last_armcycle < param->min_armcycle) {
		param->min_armcycle = 0;
	}

	/* GET FIRST PTR */
	first_armcycle = last_armcycle;
	first = last;
	while (TRUE) {
		cur = dhd_ring_get_prev(ring, first);
		if (cur == NULL) {
			break;
		}
		cur_armcycle = *(uint32 *)cur;
		if (cur_armcycle >= first_armcycle) {
			DHD_FILTER_TRACE(("case 1: %d %d\n", first_armcycle, cur_armcycle));
			/* dongle is rebooted */
			break;
		}
		if (cur_armcycle + EWPF_EPOCH < param->min_armcycle) {
			DHD_FILTER_TRACE(("case 2: %d %d\n", param->min_armcycle, cur_armcycle));
			/* Reach Limitation */
			break;
		}
		if (cur_armcycle + param->max_period + EWPF_EPOCH < last_armcycle) {
			DHD_FILTER_TRACE(("case 3: %d %d\n", param->max_period, cur_armcycle));
			/* exceed max period */
			break;
		}
		first = cur;
		first_armcycle = cur_armcycle;
	}

	if (first_armcycle != param->min_armcycle) {
		DHD_FILTER_TRACE(("MIN ARMCYCLE IS CHANGEd new:%d prev:%d %d\n",
			first_armcycle, param->min_armcycle, cur_armcycle));
		param->min_armcycle = first_armcycle;
	}

	DHD_FILTER_TRACE(("ARM CYCLE of first(%d), last(%d)\n", first_armcycle, last_armcycle));

	dhd_ring_lock(ring, first, last);

	lock_cnt = dhd_ring_lock_get_count(ring);
	if (lock_cnt <= 0) {
		DHD_FILTER_ERR((" NO VALID RECORD : %d\n", lock_cnt));
		return -1;
	}
	DHD_FILTER_TRACE(("Lock Count:%d\n", lock_cnt));

	/* Validate delta position */
	for (idx2 = 0; idx2 < param->delta_cnt - 1; idx2++) {
		if (param->delta_list[idx2] >= param->delta_list[idx2 + 1]) {
			DHD_FILTER_ERR(("INVALID DELTA at %d\n", idx2 + 1));
			param->delta_list[idx2 + 1] = param->delta_list[idx2];
		}
	}

	delta_idx = 0;
	for (idx2 = 0; idx2 < lock_cnt && delta_idx < param->delta_cnt; idx2++) {
		if (idx2 == 0) {
			cur = dhd_ring_lock_get_last(ring);
		} else {
			cur = dhd_ring_get_prev(ring, cur);
		}

		if (idx2 >= param->delta_list[delta_idx]) {
			param->elem_list[delta_idx] = cur;
			delta_idx ++;
		}
	}

	/* COPY last elem to rest of the list */
	delta_idx--;
	for (idx2 = delta_idx + 1; idx2 < param->delta_cnt; idx2++) {
		param->elem_list[idx2] = cur;
	}
	return lock_cnt;
}

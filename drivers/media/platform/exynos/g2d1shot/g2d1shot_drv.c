/* linux/drivers/media/platform/exynos/fimg2d_v5/g2d1shot_drv.c
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *	http://www.samsung.com/
 *
 * Samsung Graphics 2D driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/pm_runtime.h>
#include <linux/suspend.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/exynos_iovmm.h>
#include <linux/smc.h>
#include <linux/ion.h>
#include <linux/exynos_ion.h>
#include <soc/samsung/bts.h>

#include "g2d1shot.h"
#include "g2d1shot_helper.h"

int g2d_debug = DBG_INFO;
module_param(g2d_debug, int, S_IRUGO | S_IWUSR);

int g2d_dump;
module_param(g2d_dump, int, S_IRUGO | S_IWUSR);

static void g2d_pm_qos_update_cpufreq(struct g2d_qos_reqs *reqs,
				u32 freq_c1, u32 freq_c0)
{
	if (!pm_qos_request_active(&reqs->cluster0_req))
		pm_qos_add_request(&reqs->cluster0_req,
						PM_QOS_CLUSTER0_FREQ_MIN, 0);

	pm_qos_update_request(&reqs->cluster0_req, freq_c0);

	if (!pm_qos_request_active(&reqs->cluster1_req))
		pm_qos_add_request(&reqs->cluster1_req,
						PM_QOS_CLUSTER1_FREQ_MIN, 0);

	pm_qos_update_request(&reqs->cluster1_req, freq_c1);
}
static void g2d_pm_qos_remove_cpufreq(struct g2d_qos_reqs *reqs)
{
	if (pm_qos_request_active(&reqs->cluster0_req))
		pm_qos_remove_request(&reqs->cluster0_req);

	if (pm_qos_request_active(&reqs->cluster1_req))
		pm_qos_remove_request(&reqs->cluster1_req);
}

#ifdef CONFIG_PM_DEVFREQ
static void g2d_pm_qos_update_devfreq(struct g2d_qos_reqs *reqs,
				int pm_qos_class, u32 freq)
{
	struct pm_qos_request *req;

	if (pm_qos_class == PM_QOS_BUS_THROUGHPUT)
		req = &reqs->mif_req;
	else if (pm_qos_class == PM_QOS_DEVICE_THROUGHPUT)
		req = &reqs->int_req;
	else
		return;

	if (!pm_qos_request_active(req))
		pm_qos_add_request(req, pm_qos_class, 0);

	pm_qos_update_request(req, freq);
}
static void g2d_pm_qos_remove_devfreq(struct g2d_qos_reqs *reqs,
				int pm_qos_class)
{
	struct pm_qos_request *req;

	if (pm_qos_class == PM_QOS_BUS_THROUGHPUT)
		req = &reqs->mif_req;
	else if (pm_qos_class == PM_QOS_DEVICE_THROUGHPUT)
		req = &reqs->int_req;
	else
		return;

	if (pm_qos_request_active(req))
		pm_qos_remove_request(req);
}
#else
#define g2d_pm_qos_update_devfreq(reqs, pm_qos_class, freq) do { } while (0)
#define g2d_pm_qos_remove_devfreq(reqs, pm_qos_class) do { } while (0)
#endif

#define g2d_pm_qos_remove_all(g2d_ctx)	\
do {	\
	g2d_pm_qos_remove_cpufreq(&g2d_ctx->pm_qos_reqs);	\
	g2d_pm_qos_remove_devfreq(&g2d_ctx->pm_qos_reqs,	\
					PM_QOS_BUS_THROUGHPUT);	\
	g2d_pm_qos_remove_devfreq(&g2d_ctx->pm_qos_reqs,	\
					PM_QOS_DEVICE_THROUGHPUT);	\
} while (0)

static int g2d1shot_set_frequency_for_skia(struct g2d1shot_dev *g2d_dev,
				struct g2d1shot_ctx *g2d_ctx, unsigned int lv)
{
	struct skia_qos_data *data = g2d_dev->priv;
	struct skia_qos_entry *table = data->table;

	if (lv >= data->size)
		return -EINVAL;

	g2d_pm_qos_update_cpufreq(&g2d_ctx->pm_qos_reqs,
			table[lv].c1_freq,
			table[lv].c0_freq);
	g2d_pm_qos_update_devfreq(&g2d_ctx->pm_qos_reqs,
			PM_QOS_BUS_THROUGHPUT,
			table[lv].mif_freq);

	return 0;
}

static void g2d1shot_set_frequency_for_device(struct g2d1shot_dev *g2d_dev,
					  struct g2d1shot_ctx *g2d_ctx,
					  struct m2m1shot2_performance_data *data)
{
	unsigned int ppc, i, j, cycle, ip_clock;
	struct m2m1shot2_performance_frame_data *frame;
	struct m2m1shot2_performance_layer_data *layer;

	cycle = 0;

	/* calculate the total size within 1 frame */
	for (i = 0; i < data->num_frames; i++) {
		frame = &data->frame[i];

		ppc = g2d_dev->hw_ppc[PPC_DEFAULT];

		for (j = 0; j < frame->num_layers; j++) {
			layer = &frame->layer[j];

			if (!!(layer->layer_attr & M2M1SHOT2_PERF_LAYER_ROTATE))
				ppc = g2d_dev->hw_ppc[PPC_ROTATION];
		}

		for (j = 0; j < frame->num_layers; j++) {
			layer = &frame->layer[j];
			cycle += layer->pixelcount / ppc;
		}

		if (!!(frame->frame_attr & M2M1SHOT2_PERF_FRAME_SOLIDCOLORFILL))
			cycle += frame->target_pixelcount /
					g2d_dev->hw_ppc[PPC_COLORFILL];
	}

	/* ip_clock(Mhz) = cycles / time_in_ms * 1000 */
	ip_clock = cycle / 8 * 1000;

	g2d_pm_qos_update_devfreq(&g2d_ctx->pm_qos_reqs,
			PM_QOS_DEVICE_THROUGHPUT, ip_clock);
}

static void g2d1shot_request_bts_performance(struct g2d1shot_dev *g2d_dev,
					  struct g2d1shot_ctx *g2d_ctx,
					  struct m2m1shot2_performance_data *data)
{
	struct m2m1shot2_performance_frame_data *frame;
	u32 cur_rbw, rbw;
	u32 cur_wbw, wbw;
	int i;

	cur_rbw = 0;
	cur_wbw = 0;
	rbw = 0;
	wbw = 0;

	if (data) {
		for (i = 0; i < data->num_frames; i++) {
			frame = &data->frame[i];

			rbw += frame->bandwidth_read;
			wbw += frame->bandwidth_write;
		}
	}

	if (list_empty(&g2d_ctx->qos_node) && !rbw && !wbw)
		return;

	mutex_lock(&g2d_dev->lock_qos);

	if (!list_empty(&g2d_dev->qos_contexts)) {
		struct g2d1shot_ctx *ctx_qos;

		ctx_qos = list_first_entry(&g2d_dev->qos_contexts,
					   struct g2d1shot_ctx, qos_node);
		cur_rbw = ctx_qos->r_bw;
		cur_wbw = ctx_qos->w_bw;
	}

	/* this works although ctx is not attached to qos_contexts */
	list_del_init(&g2d_ctx->qos_node);

	g2d_ctx->r_bw = rbw;
	g2d_ctx->w_bw = wbw;

	if (rbw || wbw) {
		struct list_head *node;

		for (node = g2d_dev->qos_contexts.prev;
				node != &g2d_dev->qos_contexts;
						node = node->prev) {
			struct g2d1shot_ctx *curctx = list_entry(node,
					struct g2d1shot_ctx, qos_node);
			if ((curctx->r_bw + curctx->w_bw) > (rbw + wbw))
				break;
		}
		/*
		 * node always points to the head node or the smallest bw node
		 * among the larger bw nodes than qosnode
		 */
		list_add(&g2d_ctx->qos_node, node);
	}

	if (!list_empty(&g2d_dev->qos_contexts)) {
		struct g2d1shot_ctx *ctx_qos;

		ctx_qos = list_first_entry(&g2d_dev->qos_contexts,
				      struct g2d1shot_ctx, qos_node);
		/* bandwidth request is changed */
		rbw = ctx_qos->r_bw;
		wbw = ctx_qos->w_bw;
	}

	if ((rbw != cur_rbw) || (wbw != cur_wbw)) {
#if defined(CONFIG_EXYNOS8895_BTS)
		struct bts_bw bw;
		bw.peak = ((rbw + wbw) / 1000) * BTS_PEAK_FPS_RATIO / 2;
		bw.write = wbw;
		bw.read = rbw;
		bts_update_bw(BTS_BW_G2D, bw);
#endif
	}

	mutex_unlock(&g2d_dev->lock_qos);
}

static int m2m1shot2_g2d_init_context(struct m2m1shot2_context *ctx)
{
	struct g2d1shot_dev *g2d_dev = dev_get_drvdata(ctx->m21dev->dev);
	struct g2d1shot_ctx *g2d_ctx;
	int ret;

	g2d_dbg_begin();

	g2d_ctx = kzalloc(sizeof(*g2d_ctx), GFP_KERNEL);
	if (!g2d_ctx)
		return -ENOMEM;

	ctx->priv = g2d_ctx;

	g2d_ctx->g2d_dev = g2d_dev;

	ret = clk_prepare(g2d_dev->clock);
	if (ret) {
		pr_err("Failed to prepare clock (%d)\n", ret);
		goto err_clk;
	}

	INIT_LIST_HEAD(&g2d_ctx->qos_node);

	g2d_dbg_end();

	return 0;
err_clk:
	kfree(g2d_ctx);

	g2d_dbg_end_err();

	return ret;
}

static int m2m1shot2_g2d_free_context(struct m2m1shot2_context *ctx)
{
	struct g2d1shot_dev *g2d_dev = dev_get_drvdata(ctx->m21dev->dev);
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;

	g2d_dbg_begin();

	g2d1shot_request_bts_performance(g2d_dev, g2d_ctx, NULL);
	g2d_pm_qos_remove_all(g2d_ctx);

	clk_unprepare(g2d_dev->clock);
	kfree(g2d_ctx);

	g2d_dbg_end();

	return 0;
}

static const struct g2d1shot_fmt g2d_formats[] = {
	{
		.name		= "ABGR8888",
		.pixelformat	= V4L2_PIX_FMT_ABGR32,	/* [31:0] ABGR */
		.bpp		= { 32 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_RGB8888 | G2D_SWIZZLING_ABGR,
	}, {
		.name		= "XBGR8888",
		.pixelformat	= V4L2_PIX_FMT_XBGR32,	/* [31:0] XBGR */
		.bpp		= { 32 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_RGB8888 | G2D_SWIZZLING_XBGR,
	}, {
		.name		= "ARGB4444",
		.pixelformat	= V4L2_PIX_FMT_ARGB444,	/* [15:0] ARGB */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value	= G2D_DATAFORMAT_RGB4444 | G2D_SWIZZLING_ARGB,
	}, {
		.name		= "ARGB555",
		.pixelformat	= V4L2_PIX_FMT_ARGB555,	/* [15:0] ARGB */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value	= G2D_DATAFORMAT_RGB1555 | G2D_SWIZZLING_ARGB,
	}, {
		.name		= "ARGB8888",
		.pixelformat	= V4L2_PIX_FMT_ARGB32,	/* [31:0] ARGB */
		.bpp		= { 32 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_RGB8888 | G2D_SWIZZLING_ARGB,
	}, {
		.name		= "RGB565",
		.pixelformat	= V4L2_PIX_FMT_RGB565,	/* [15:0] RGB */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_RGB565 | G2D_SWIZZLING_RGB,
	}, {
		.name		= "NV12",
		.pixelformat	= V4L2_PIX_FMT_NV12,	/* Y/CbCr 4:2:0 contig */
		.bpp		= { 12 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRCB,
	}, {
		.name		= "NV12N",
		.pixelformat	= V4L2_PIX_FMT_NV12N,	/* Y/CbCr 4:2:0 contig with align */
		.bpp		= { 12 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRCB,
	}, {
		.name		= "NV12N_10B",
		.pixelformat	= V4L2_PIX_FMT_NV12N_10B,	/* Y/CbCr 4:2:0 contig 10-bit */
		.bpp		= { 15 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRCB,
	}, {
		.name		= "NV12M",
		.pixelformat	= V4L2_PIX_FMT_NV12M,	/* Y/CbCr 4:2:0 2-planar */
		.bpp		= { 8, 4 },
		.num_planes	= 2,
		.num_buffer	= 2,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRCB,
	}, {
		.name		= "NV21",
		.pixelformat	= V4L2_PIX_FMT_NV21,	/* Y/CrCb 4:2:0 contig */
		.bpp		= { 12 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CBCR,
	}, {
		.name		= "NV21M",
		.pixelformat	= V4L2_PIX_FMT_NV21M,	/* Y/CrCb 4:2:0 2-planar */
		.bpp		= { 8, 4 },
		.num_planes	= 2,
		.num_buffer	= 2,
		.value		= G2D_DATAFORMAT_YCBCR420_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CBCR,
	}, {
		.name		= "YUYV",
		.pixelformat	= V4L2_PIX_FMT_YUYV,	/* YCbYCr 4:2:2 packed */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR422_1P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRYCBY,
	}, {
		.name		= "UYVY",
		.pixelformat	= V4L2_PIX_FMT_UYVY,	/* CbYCrY 4:2:2 packed */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR422_1P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_YCRYCB,
	}, {
		.name		= "YVYU",
		.pixelformat	= V4L2_PIX_FMT_YVYU,	/* YCrYCb 4:2:2 packed */
		.bpp		= { 16 },
		.num_planes	= 1,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR422_1P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CBYCRY,
	}, {
		.name		= "NV16",
		.pixelformat	= V4L2_PIX_FMT_NV16,	/* Y/CbCr 4:2:2 2-planar, contig */
		.bpp		= { 16 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR422_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CRCB,
	}, {
		.name		= "NV61",
		.pixelformat	= V4L2_PIX_FMT_NV61,	/* Y/CrCb 4:2:2 2-planar, contig */
		.bpp		= { 16 },
		.num_planes	= 2,
		.num_buffer	= 1,
		.value		= G2D_DATAFORMAT_YCBCR422_2P |
					G2D_SWIZZLING_ARGB | G2D_ORDER_CBCR,
	},
};

static const struct g2d1shot_fmt *find_format(bool is_source, u32 fmt)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(g2d_formats); i++) {
		if (fmt == g2d_formats[i].pixelformat) {
			/* TODO: check more.. H/W version, source/dest.. */
			return &g2d_formats[i];
		}
	}

	return NULL;
}

static bool g2d1shot_still_need_perf(struct m2m1shot2_context *ctx)
{
	struct m2m1shot2_device *m21dev = ctx->m21dev;
	struct m2m1shot2_context *pctx;
	unsigned long flags;

	spin_lock_irqsave(&m21dev->lock_ctx, flags);

	pctx = m2m1shot2_current_context(m21dev);
	if (pctx && (pctx->priority == ctx->priority))
		goto need_perf;

	list_for_each_entry(pctx, &m21dev->active_contexts, node) {
		if (pctx->priority == ctx->priority)
			goto need_perf;
	}

	list_for_each_entry(pctx, &m21dev->contexts, node) {
		if (M2M1S2_CTXSTATE_BUSY(pctx) &&
				(pctx->priority == ctx->priority))
			goto need_perf;
	}

	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	return false;

need_perf:
	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	return true;
}

static int m2m1shot2_g2d_prepare_performance(struct m2m1shot2_context *ctx,
		struct m2m1shot2_performance_data *data)
{
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	struct g2d1shot_dev *g2d_dev = g2d_ctx->g2d_dev;

	if (!data || data->num_frames == 0) {
		if (g2d1shot_still_need_perf(ctx))
			return 0;
		/* remove the request */
		g2d1shot_request_bts_performance(g2d_dev, g2d_ctx, NULL);
		g2d_pm_qos_remove_all(g2d_ctx);
	} else {
		g2d1shot_request_bts_performance(g2d_dev, g2d_ctx, data);
		g2d1shot_set_frequency_for_device(g2d_dev, g2d_ctx, data);
	}

	return 0;
}

static int m2m1shot2_g2d_prepare_format(
			struct m2m1shot2_context_format *ctx_fmt,
			unsigned int index, enum dma_data_direction dir,
			size_t payload[], unsigned int *num_planes)
{
	const struct g2d1shot_fmt *g2d_fmt;
	struct m2m1shot2_format *fmt = &ctx_fmt->fmt;
	int i;

	g2d_dbg_begin();

	g2d_fmt = find_format((dir == DMA_TO_DEVICE), fmt->pixelformat);
	if (!g2d_fmt) {
		pr_err("Not supported format (%u)\n", fmt->pixelformat);
		return -EINVAL;
	}

	/* m2m1shot2's num_planes is not number of Y/CB/CR but the number of buffer */
	*num_planes = g2d_fmt->num_buffer;
	for (i = 0; i < g2d_fmt->num_buffer; i++) {
		payload[i] = fmt->width * fmt->height * g2d_fmt->bpp[i];
		payload[i] /= 8;
	}
	ctx_fmt->priv = (void *)g2d_fmt;

	g2d_dbg_end();

	return 0;
}

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
static bool g2d_prepare_secure_buffer(struct m2m1shot2_context *ctx)
{
	int i;
	bool secure = !!(ctx->target.flags & M2M1SHOT2_IMGFLAG_SECURE);

	for (i = 0; i < ctx->num_sources; i++) {
		if (!!(ctx->source[i].img.flags & M2M1SHOT2_IMGFLAG_COLORFILL))
			continue;

		if (secure ^ !!(ctx->source[i].img.flags & M2M1SHOT2_IMGFLAG_SECURE)) {
			pr_err("%s: secure flag is discord (src [%d] flag %x,  dst flag %x)\n",
				__func__, i, ctx->source[i].img.flags, ctx->target.flags);
			return false;
		}
	}

	return true;
}

#define G2D_SMC_PROTECTION_ID 14

static void g2d_enable_secure(struct g2d1shot_dev *g2d_dev,
		struct m2m1shot2_context *ctx)
{
	int ret = 0;

	g2d_dbg_begin();
	if (ctx->target.flags & M2M1SHOT2_IMGFLAG_SECURE) {
		ret = exynos_smc(SMC_PROTECTION_SET, 0,
				G2D_SMC_PROTECTION_ID, SMC_PROTECTION_ENABLE);
		if (ret)
			dev_err(g2d_dev->dev,
				"fail to set protection (%d)\n", ret);
	}
	g2d_dbg_end();
}

static void g2d_disable_secure(struct g2d1shot_dev *g2d_dev,
		struct m2m1shot2_context *ctx)
{
	int ret = 0;

	g2d_dbg_begin();
	if (ctx->target.flags & M2M1SHOT2_IMGFLAG_SECURE) {
		ret = exynos_smc(SMC_PROTECTION_SET, 0,
				G2D_SMC_PROTECTION_ID, SMC_PROTECTION_DISABLE);
		if (ret)
			dev_err(g2d_dev->dev,
				"fail to disable protection (%d)\n", ret);
	}
	g2d_dbg_end();
}
#else
static bool g2d_prepare_secure_buffer(struct m2m1shot2_context *ctx)
{
	return true;
}

#define g2d_enable_secure(g2d_dev, ctx) do { } while (0)
#define g2d_disable_secure(g2d_dev, ctx) do { } while (0)
#endif

static int m2m1shot2_g2d_prepare_target(struct m2m1shot2_context *ctx,
		struct m2m1shot2_context_image *img)
{
	bool compressed = img->flags & M2M1SHOT2_IMGFLAG_COMPRESSED;
	bool u_order = img->flags & M2M1SHOT2_IMGFLAG_UORDER_ADDR;
	struct m2m1shot2_context_format *ctx_fmt = m2m1shot2_dst_format(ctx);
	struct m2m1shot2_format *fmt = &ctx_fmt->fmt;
	struct g2d1shot_fmt *g2d_fmt = ctx_fmt->priv;
	const struct g2d_csc_fmt *g2d_csc_fmt;
	unsigned char w_align = 1;
	unsigned char h_align = 1;

	/* check format conflict */
	if (compressed && u_order) {
		pr_err("Invalid request with compressed and u-order at the same time\n");
		return -EINVAL;
	}
	if (u_order && (!is_rgb(g2d_fmt->value))) {
		pr_err("Only ARGB format colud be written by u-order\n");
		return -EINVAL;
	}
	if (compressed && (!is_rgb(g2d_fmt->value))) {
		pr_err("Only ARGB format could be compressed\n");
		return -EINVAL;
	}
	if (!g2d_prepare_secure_buffer(ctx)) {
		pr_err("Select all or notihg attribute of secure about source and dest\n");
		return -EINVAL;
	}

	if (compressed) {
		w_align = G2D_COMP_ALIGN_WIDTH;
		h_align = G2D_COMP_ALIGN_DST_HEIGHT;
	} else if (u_order) {
		w_align = h_align = G2D_UORDER_ALIGN;
	}

	if (is_yuv(g2d_fmt->value)) {
		w_align = 2;
		if (is_yuv420(g2d_fmt->value))
			h_align = 2;
	}

	/* check width and height */
	if (fmt->width == 0 || fmt->height == 0 ||
			fmt->width > G2D_MAX_SIZE ||
			fmt->height > G2D_MAX_SIZE) {
		pr_err("Invalid size of width or height (%u, %u)\n",
				fmt->width, fmt->height);
		return -EINVAL;
	}
	if (!IS_ALIGNED(fmt->width, w_align) ||
			!IS_ALIGNED(fmt->height, h_align)) {
		pr_err("Invalid alignment width %u height %u\n",
			fmt->width, fmt->height);
		return -EINVAL;
	}

	/* invalid crop range */
	if (fmt->crop.left < 0 || fmt->crop.top < 0 ||
			(fmt->crop.left + fmt->crop.width > fmt->width) ||
			(fmt->crop.top + fmt->crop.height > fmt->height) ||
			(fmt->crop.width == 0) ||
			(fmt->crop.height == 0)) {
		pr_err("Invalid range of crop ltwh(%d, %d, %d, %d)\n",
				fmt->crop.left, fmt->crop.top,
				fmt->crop.width, fmt->crop.height);
		pr_err("width/height : %u/%u\n", fmt->width, fmt->height);
		return -EINVAL;
	}

	if (u_order) {
		w_align = h_align = 1;
	}
	/* check crop coordinate alignment for destinaion only */
	if (!IS_ALIGNED(fmt->crop.left, w_align) ||
			!IS_ALIGNED(fmt->crop.height, h_align)) {
		pr_err("Invalid alignment left %d top %d\n",
			fmt->crop.left, fmt->crop.top);
		return -EINVAL;
	}

	/* check address alignment */
	if (compressed) {
		dma_addr_t header;

		/* AFBC address align
		 * NOTE : AFBC format is supported for ARGB (1 plane)
		 */
		header = m2m1shot2_dst_dma_addr(ctx, 0);
		if (!IS_ALIGNED(header, G2D_COMP_ALIGN_DST_ADDR)) {
			pr_err("Invalid header address for compressed format : 0x%lx\n",
					(unsigned long)header);
			return -EINVAL;
		}
	}

	/* check the colorspace of yuv format */
	if (is_yuv(g2d_fmt->value)) {
		g2d_csc_fmt = find_colorspace(ctx_fmt->colorspace);
		if (g2d_csc_fmt == NULL) {
			pr_err("Not supported color space : %d\n", ctx_fmt->colorspace);
			return -EINVAL;
		} else if ((g2d_csc_fmt->colorspace != G2D_COLORSPACE_601) &&
					(g2d_csc_fmt->colorspace != G2D_COLORSPACE_709)) {
			pr_err("destination sholud be set as 601 or 709 : %d\n",
					ctx_fmt->colorspace);
			return -EINVAL;
		}
	}

	return 0;
}

static int m2m1shot2_g2d_prepare_source(struct m2m1shot2_context *ctx,
			unsigned int index, struct m2m1shot2_source_image *img)
{
	bool compressed = img->img.flags & M2M1SHOT2_IMGFLAG_COMPRESSED;
	bool u_order = img->img.flags & M2M1SHOT2_IMGFLAG_UORDER_ADDR;
	struct m2m1shot2_context_format *ctx_fmt = m2m1shot2_src_format(ctx, index);
	struct m2m1shot2_format *fmt = &ctx_fmt->fmt;
	struct g2d1shot_fmt *g2d_fmt = ctx_fmt->priv;
	const struct g2d_csc_fmt *g2d_csc_fmt;
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	unsigned char w_align = 1;
	unsigned char h_align = 1;

	/* check format conflict */
	if (u_order) {
		pr_err("Invalid request with u-order on source image\n");
		return -EINVAL;
	}
	if (compressed && (!is_rgb(g2d_fmt->value))) {
		pr_err("Only ARGB format could be compressed\n");
		return -EINVAL;
	}

	if (compressed) {
		w_align = G2D_COMP_ALIGN_WIDTH;
		h_align = G2D_COMP_ALIGN_SRC_HEIGHT;
	}

	if (is_yuv(g2d_fmt->value)) {
		w_align = 2;
		if (is_yuv420(g2d_fmt->value))
			h_align = 2;
	}

	/* check width and height */
	if (fmt->width == 0 || fmt->height == 0 ||
			fmt->width > G2D_MAX_SIZE ||
			fmt->height > G2D_MAX_SIZE) {
		pr_err("Invalid size of width or height (%u, %u)\n",
				fmt->width, fmt->height);
		return -EINVAL;
	}
	if (!IS_ALIGNED(fmt->width, w_align) ||
			!IS_ALIGNED(fmt->height, h_align)) {
		pr_err("Invalid alignment of width or height (%u, %u)\n",
			fmt->width, fmt->height);
		return -EINVAL;
	}

	/* invalid crop range */
	if (fmt->crop.left < 0 || fmt->crop.top < 0 ||
			(fmt->crop.left + fmt->crop.width > fmt->width) ||
			(fmt->crop.top + fmt->crop.height > fmt->height) ||
			(fmt->crop.width == 0) || (fmt->window.width == 0) ||
			(fmt->crop.height == 0) || (fmt->window.height == 0)) {
		pr_err("Invalid range of crop ltwh(%d, %d, %d, %d)\n",
				fmt->crop.left, fmt->crop.top,
				fmt->crop.width, fmt->crop.height);
		pr_err("width/height : %u/%u\n", fmt->width, fmt->height);
		return -EINVAL;
	}

	/* check address alignment */
	if (compressed) {
		dma_addr_t header;
		/* AFBC address align
		 * NOTE : AFBC format is supported for ARGB (1 plane)
		 */
		header = m2m1shot2_src_dma_addr(ctx, index, 0);
		if (!IS_ALIGNED(header, G2D_COMP_ALIGN_SRC_ADDR)) {
			pr_err("Invalid header address for compressed format : 0x%lx\n",
					(unsigned long)header);
			return -EINVAL;
		}
	}

	/* check colorspace of yuv format */
	if (index == 0) {
		int i = 0;

		g2d_ctx->num_req_coeff = 0;
		for (i = 0; i < G2D_MAX_CSC_FMT; i++)
			g2d_ctx->csc_idx_map[i] = -1;
	}

	if (is_yuv(g2d_fmt->value)) {
		s8 fmt_idx;

		g2d_csc_fmt = find_colorspace(ctx_fmt->colorspace);
		if (g2d_csc_fmt == NULL) {
			pr_err("Not supported color space : %d\n", ctx_fmt->colorspace);
			return -EINVAL;
		}

		fmt_idx = g2d_ctx->csc_idx_map[g2d_csc_fmt->index];

		if (fmt_idx >= 0) {
			g2d_ctx->src_csc_value[index] = fmt_idx;
		} else {
			if (g2d_ctx->num_req_coeff >= G2D_CSC_HW_SUPPORT) {
				pr_err("Not supported over 4 colorspace : %x\n",
							g2d_ctx->num_req_coeff);
				return -EINVAL;
			}
			g2d_ctx->csc_idx_map[g2d_csc_fmt->index] =
					g2d_ctx->num_req_coeff;
			g2d_ctx->src_csc_value[index] = g2d_ctx->num_req_coeff;

			g2d_ctx->num_req_coeff++;
		}
	}
	return 0;
}

static int enable_g2d(struct g2d1shot_dev *g2d_dev)
{
	int ret;

	g2d_dbg_begin();

	ret = in_irq() ? pm_runtime_get(g2d_dev->dev) :
			pm_runtime_get_sync(g2d_dev->dev);
	if (ret < 0) {
		pr_err("Failed to enable power (%d)\n", ret);
		return ret;
	}

	ret = clk_enable(g2d_dev->clock);
	if (ret) {
		pr_err("Failed to enable clock (%d)\n", ret);
		pm_runtime_put(g2d_dev->dev);
		return ret;
	}

	g2d_dbg_end();

	return 0;
}

static int disable_g2d(struct g2d1shot_dev *g2d_dev)
{
	g2d_dbg_begin();

	clk_disable(g2d_dev->clock);
	pm_runtime_put(g2d_dev->dev);

	g2d_dbg_end();

	return 0;
}

static void g2d_set_source(struct g2d1shot_dev *g2d_dev,
		struct m2m1shot2_context *ctx,
		struct m2m1shot2_source_image *source, int layer_num)
{
	struct m2m1shot2_context_format *ctx_fmt =
				m2m1shot2_src_format(ctx, layer_num);
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	u32 src_type = G2D_LAYER_SELECT_NORMAL;
	u32 img_flags = source->img.flags;
	bool compressed = img_flags & M2M1SHOT2_IMGFLAG_COMPRESSED;

	g2d_dbg_begin();

	if (img_flags & M2M1SHOT2_IMGFLAG_COLORFILL) {
		g2d_hw_set_source_color(g2d_dev, layer_num,
						source->ext.fillcolor);
		src_type = G2D_LAYER_SELECT_CONSTANT_COLOR;
	} else {
		/* use composit_mode */
		g2d_hw_set_source_premult(g2d_dev, layer_num, img_flags);
		g2d_hw_set_source_blending(g2d_dev, layer_num, &source->ext);
		/* set source address */
		g2d_hw_set_source_address(ctx, ctx_fmt, g2d_dev, layer_num, compressed);
		/* set repeat mode */
		g2d_hw_set_source_repeat(g2d_dev, layer_num, &source->ext);
		/* set scaling mode */
		if (!(img_flags & M2M1SHOT2_IMGFLAG_NO_RESCALING))
			g2d_hw_set_source_scale(g2d_dev, layer_num, &source->ext,
				img_flags, ctx_fmt);
		/* set rotation mode */
		g2d_hw_set_source_rotate(g2d_dev, layer_num, &source->ext);
		/* set ycbcr mode */
		g2d_hw_set_source_ycbcr(g2d_ctx, layer_num, ctx_fmt);
	}

	/* set source type */
	g2d_hw_set_source_type(g2d_dev, layer_num, src_type);
	/* set source rect, dest clip and pixel format */
	g2d_hw_set_source_format(g2d_dev, layer_num, ctx_fmt, compressed);
	/* set layer valid */
	g2d_hw_set_source_valid(g2d_dev, layer_num);

	g2d_dbg_end();
}

static void g2d_set_target(struct g2d1shot_dev *g2d_dev,
		struct m2m1shot2_context *ctx,
		struct m2m1shot2_context_image *target)
{
	struct m2m1shot2_context_format *ctx_fmt = m2m1shot2_dst_format(ctx);
	bool compressed = target->flags & M2M1SHOT2_IMGFLAG_COMPRESSED;

	g2d_dbg_begin();

	g2d_hw_set_dest_addr(ctx, ctx_fmt, g2d_dev, compressed);

	/* set dest rect and pixel format */
	g2d_hw_set_dest_format(g2d_dev, ctx_fmt, target->flags);
	/* set dest premult */
	g2d_hw_set_dest_premult(g2d_dev, target->flags);
	/* set ycbcr mode */
	g2d_hw_set_dest_ycbcr(g2d_dev, ctx_fmt);
	/* set dither */
	if (ctx->flags & M2M1SHOT2_FLAG_DITHER)
		g2d_hw_set_dither(g2d_dev);

	g2d_dbg_end();
}

/* bitblt the rect 4x2@14x0 on 32x2 destination */
static const struct {
	u32 val;
	u32 offset;
} warmup_vec[] = {
	{0x1, G2D_LAYER_UPDATE_REG},
	{0x3210, G2D_DST_COLOR_MODE_REG},
	{0xe, G2D_DST_LEFT_REG},
	{0x0, G2D_DST_TOP_REG},
	{0x12, G2D_DST_RIGHT_REG},
	{0x2, G2D_DST_BOTTOM_REG},
	{0x20, G2D_DST_IMAGE_WIDTH_REG},
	{0x2, G2D_DST_IMAGE_HEIGHT_REG},
	{0x0, G2D_TILE_DIRECTION_ORDER_REG},
	{0x10001, G2D_DST_SPLIT_TILE_IDX_REG},
	{0x1, G2D_LAYER0_COMMAND_REG},
	{0x1, G2D_LAYER0_SELECT_REG},
	{0xe, G2D_LAYER0_DST_LEFT_REG},
	{0x0, G2D_LAYER0_DST_TOP_REG},
	{0x12, G2D_LAYER0_DST_RIGHT_REG},
	{0x2, G2D_LAYER0_DST_BOTTOM_REG},
	{0x0, G2D_LAYER0_BASE_ADDR_REG},
	{0x80, G2D_LAYER0_STRIDE_REG},
	{0x3210, G2D_LAYER0_COLOR_MODE_REG},
	{0x0, G2D_LAYER0_LEFT_REG},
	{0x0, G2D_LAYER0_TOP_REG},
	{0x12, G2D_LAYER0_RIGHT_REG},
	{0x2, G2D_LAYER0_BOTTOM_REG},
	{0x0, G2D_LAYER0_COLOR_MODE_REG},
	{0x12, G2D_LAYER0_IMAGE_WIDTH_REG},
	{0x2, G2D_LAYER0_IMAGE_HEIGHT_REG},
};

static void clear_flipflop_for_nv12(struct m2m1shot2_context *ctx)
{
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	struct g2d1shot_dev *g2d_dev = g2d_ctx->g2d_dev;
	struct m2m1shot2_context_format *ctx_fmt = m2m1shot2_dst_format(ctx);
	struct g2d1shot_fmt *fmt = ctx_fmt->priv;
	int i;

	if (!is_yuv420(fmt->value))
		return;

	g2d_hw_init(g2d_dev);

	for (i = 0; i < ARRAY_SIZE(warmup_vec); i++)
		writel_relaxed(warmup_vec[i].val,
				g2d_dev->reg + warmup_vec[i].offset);

	writel_relaxed(g2d_dev->d_buf.dma_addr,
			g2d_dev->reg + G2D_DST_BASE_ADDR_REG);

	/* it called on disabling the interrupt */
	writel(G2D_START_BITBLT, g2d_dev->reg + G2D_BITBLT_START_REG);

	udelay(2);
	while (!(readl(g2d_dev->reg + G2D_FIFO_STAT_REG) & 0x1))
		; /* polling the completion of execution of a bitblt */
}

static int m2m1shot2_g2d_device_run(struct m2m1shot2_context *ctx)
{
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	struct g2d1shot_dev *g2d_dev = g2d_ctx->g2d_dev;
	unsigned long flags;
	int ret;
	int i;

	g2d_dbg_begin();

	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	if (g2d_dev->state & G2D_STATE_SUSPENDING) {
		dev_info(g2d_dev->dev, "G2D is in suspend state.\n");
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);
		return -EAGAIN;
	}
	g2d_dev->state |= G2D_STATE_RUNNING;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	/* enable power, clock */
	ret = enable_g2d(g2d_dev);
	if (ret) {
		spin_lock_irqsave(&g2d_dev->state_lock, flags);
		g2d_dev->state &= ~G2D_STATE_RUNNING;
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);
		return ret;
	}

	/* execute dummy bitblt to clear non-reset flipflop for nv12 */
	clear_flipflop_for_nv12(ctx);

	/* H/W initialization */
	g2d_hw_init(g2d_dev);

	/* setting for user csc coeff */
	g2d_hw_set_csc_coeff(g2d_ctx);

	/* setting for source */
	for (i = 0; i < ctx->num_sources; i++)
		g2d_set_source(g2d_dev, ctx, &ctx->source[i], i);

	/* setting for destination */
	g2d_set_target(g2d_dev, ctx, &ctx->target);

	g2d_hw_set_tile_direction(g2d_dev, ctx);

	/* setting for secure */
	g2d_enable_secure(g2d_dev, ctx);

	/* setting for common */

	if (g2d_dump) {
		g2d_disp_info(ctx);
		g2d_dump_regs(g2d_dev);
	}

	mod_timer(&g2d_dev->timer,
		jiffies + msecs_to_jiffies(G2D_TIMEOUT_INTERVAL));
	g2d_dev->t_start = sched_clock();
	/* run H/W */
	g2d_hw_start(g2d_dev);

	g2d_dbg_end();

	return 0;
}

int m2m1shot2_g2d_custom_ioctl(struct m2m1shot2_context *ctx,
				unsigned int cmd,
				unsigned int arg)
{
	struct g2d1shot_ctx *g2d_ctx = ctx->priv;
	struct g2d1shot_dev *g2d_dev = g2d_ctx->g2d_dev;

	return g2d1shot_set_frequency_for_skia(g2d_dev,
						g2d_ctx, arg);
}

static const struct m2m1shot2_devops m2m1shot2_g2d_ops = {
	.init_context = m2m1shot2_g2d_init_context,
	.free_context = m2m1shot2_g2d_free_context,
	.prepare_format = m2m1shot2_g2d_prepare_format,
	.prepare_source = m2m1shot2_g2d_prepare_source,
	.prepare_target = m2m1shot2_g2d_prepare_target,
	.prepare_perf = m2m1shot2_g2d_prepare_performance,
	.device_run = m2m1shot2_g2d_device_run,
	.custom_ioctl = m2m1shot2_g2d_custom_ioctl,
};

static irqreturn_t exynos_g2d_irq_handler(int irq, void *priv)
{
	struct g2d1shot_dev *g2d_dev = priv;
	struct m2m1shot2_context *m21ctx;
	unsigned long flags;
	bool suspending;
	unsigned long long t_stop;
	bool status = true;
	u32 irqpend;
	u32 hw_stat;
	int retry = 3;

	g2d_dbg_begin();

	/* IRQ handling */
	irqpend = g2d_int_status(g2d_dev);
	if ((irqpend & ~3) != 0) {
		status = false;
		dev_err(g2d_dev->dev, "g2d1shot makes i_rec #%d (%x)\n",
			g2d_dev->num_rec++, irqpend);

	}
	g2d_hw_stop(g2d_dev);

	t_stop = sched_clock();
	m21ctx = m2m1shot2_current_context(g2d_dev->oneshot2_dev);
	if (!m21ctx) {
		dev_err(g2d_dev->dev, "received null in irq handler\n");
		return IRQ_HANDLED;
	}

	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	if (!(g2d_dev->state & G2D_STATE_RUNNING)) {
		dev_err(g2d_dev->dev, "interrupt, but no running\n");
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);
		return IRQ_HANDLED;
	}
	if (g2d_dev->state & G2D_STATE_TIMEOUT) {
		dev_err(g2d_dev->dev, "interrupt, but already timedout\n");
		g2d_dev->state &= ~G2D_STATE_RUNNING;
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);
		return IRQ_HANDLED;
	}
	suspending = g2d_dev->state & G2D_STATE_SUSPENDING;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	del_timer(&g2d_dev->timer);

	hw_stat = readl(g2d_dev->reg + G2D_FIFO_STAT_REG);
	g2d_hw_reset(g2d_dev);

	while (!(readl(g2d_dev->reg + G2D_FIFO_STAT_REG) & 0x1)) {
		if (retry-- == 0) {
			dev_err(g2d_dev->dev,
				"couldn't reset the hw (status %x before reset)\n",
				hw_stat);
			break;
		}
	}

	g2d_disable_secure(g2d_dev, m21ctx);
	disable_g2d(g2d_dev);

	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	g2d_dev->state &= ~G2D_STATE_RUNNING;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	m21ctx->work_delay_in_nsec = t_stop - g2d_dev->t_start;
	if (g2d_debug == DBG_PERF) {
		g2d_info("G2D_operation time = %llu.%06llu ms\n",
					m21ctx->work_delay_in_nsec / 1000000,
					m21ctx->work_delay_in_nsec % 1000000);
	}
	if (!suspending)
		m2m1shot2_finish_context(m21ctx, status);
	else {
		g2d_dev->suspend_ctx = m21ctx;
		g2d_dev->suspend_ctx_success = true;
	}

	wake_up(&g2d_dev->suspend_wait);

	g2d_dbg_end();

	return IRQ_HANDLED;
}

static int g2d_iommu_fault_handler(
		struct iommu_domain *domain, struct device *dev,
		unsigned long fault_addr, int fault_flags, void *token)
{
	struct g2d1shot_dev *g2d_dev = token;
	struct m2m1shot2_context *m21ctx;

	g2d_dbg_begin();

	m21ctx = m2m1shot2_current_context(g2d_dev->oneshot2_dev);
	if (!m21ctx) {
		g2d_dump_regs(g2d_dev);
		dev_err(g2d_dev->dev, "received null in fault handler\n");
		return -EFAULT;
	}

	g2d_disp_info(m21ctx);
	g2d_dump_regs(g2d_dev);

	g2d_dbg_end();

	return 0;
}

static void g2d_timeout_handler(unsigned long arg)
{
	struct g2d1shot_dev *g2d_dev = (struct g2d1shot_dev *)arg;
	struct m2m1shot2_context *m21ctx;
	unsigned long flags;
	bool suspending;
	int hw_stat;
	int retry = 3;

	/* uninitialize H/W */
	g2d_hw_stop(g2d_dev);

	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	if (!(g2d_dev->state & G2D_STATE_RUNNING)) {
		dev_err(g2d_dev->dev, "timeout, but not processing state\n");
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);
		return;
	}

	g2d_dev->state |= G2D_STATE_TIMEOUT;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	dev_err(g2d_dev->dev, "g2d1shot makes t_rec #%d\n", g2d_dev->num_rec++);

	m21ctx = m2m1shot2_current_context(g2d_dev->oneshot2_dev);
	if (!m21ctx) {
		dev_err(g2d_dev->dev, "received null in timeout handler\n");
		return;
	}

	hw_stat = readl(g2d_dev->reg + G2D_FIFO_STAT_REG);
	g2d_hw_reset(g2d_dev);

	while (!(readl(g2d_dev->reg + G2D_FIFO_STAT_REG) & 0x1)) {
		if (retry-- == 0) {
			dev_err(g2d_dev->dev,
				"couldn't reset the hw (status %x before reset)\n",
				hw_stat);
			break;
		}
	}

	g2d_disp_info(m21ctx);
	g2d_dump_regs(g2d_dev);

	g2d_disable_secure(g2d_dev, m21ctx);
	disable_g2d(g2d_dev);

	/* notify m2m1shot2 with false */
	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	g2d_dev->state &= ~G2D_STATE_TIMEOUT;
	suspending = g2d_dev->state & G2D_STATE_SUSPENDING;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	if (!suspending)
		m2m1shot2_finish_context(m21ctx, false);
	else {
		g2d_dev->suspend_ctx = m21ctx;
		g2d_dev->suspend_ctx_success = false;
		wake_up(&g2d_dev->suspend_wait);
	}
};

static int g2d_init_clock(struct device *dev, struct g2d1shot_dev *g2d_dev)
{
	g2d_dev->clock = devm_clk_get(dev, "gate");
	if (IS_ERR(g2d_dev->clock)) {
		dev_err(dev, "Failed to get clock (%ld)\n",
					PTR_ERR(g2d_dev->clock));
		return PTR_ERR(g2d_dev->clock);
	}

	return 0;
}

static int g2d_get_hw_version(struct device *dev, struct g2d1shot_dev *g2d_dev)
{
	int ret;

	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		dev_err(dev, "Failed to enable power (%d)\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(g2d_dev->clock);
	if (!ret) {
		g2d_dev->version = g2d_hw_read_version(g2d_dev);
		dev_info(dev, "G2D version : %#010x\n", g2d_dev->version);

		clk_disable_unprepare(g2d_dev->clock);
	}

	pm_runtime_put(dev);

	return 0;
}

static int g2d_populate_dt(struct g2d1shot_dev *g2d_dev)
{
	struct device *dev = g2d_dev->dev;
	struct skia_qos_data *data;
	struct skia_qos_entry *table;
	int size, i;

	data = devm_kzalloc(dev, sizeof(struct skia_qos_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	size = of_property_count_u32_elems(dev->of_node, "skia_qos_table");
	if (size < 0)
		return size;

	table = devm_kzalloc(dev,
		sizeof(struct skia_qos_entry) * size / 3, GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	of_property_read_u32_array(dev->of_node, "skia_qos_table",
					(unsigned int *)table, size);

	of_property_read_u32_array(dev->of_node, "hw_ppc",
					(unsigned int *)g2d_dev->hw_ppc, PPC_ATTR_END);

	for (i = 0; i < (size / 3); i++) {
		dev_info(dev, "Skia QoS Table[%d] c1 : %u c0 : %u mif :%u\n", i,
			table[i].c0_freq,
			table[i].c1_freq,
			table[i].mif_freq);
	}

	data->table = table;
	data->size = (unsigned int) size / 3;

	g2d_dev->priv = data;

	return 0;
}

static int exynos_g2d_notifier_event(struct notifier_block *this,
		unsigned long event,
		void *ptr)
{
	unsigned long flags;
	struct g2d1shot_dev *g2d_dev;

	g2d_dev = container_of(this, struct g2d1shot_dev, pm_notifier);

	switch (event) {
	case PM_SUSPEND_PREPARE:
		spin_lock_irqsave(&g2d_dev->state_lock, flags);
		g2d_dev->state |= G2D_STATE_SUSPENDING;
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

		wait_event(g2d_dev->suspend_wait,
			!(g2d_dev->state & G2D_STATE_RUNNING));

		break;

	case PM_POST_SUSPEND:
		spin_lock_irqsave(&g2d_dev->state_lock, flags);
		g2d_dev->state &= ~G2D_STATE_SUSPENDING;
		spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

		if (g2d_dev->suspend_ctx) {
			m2m1shot2_finish_context(
				g2d_dev->suspend_ctx, g2d_dev->suspend_ctx_success);
			g2d_dev->suspend_ctx = NULL;
		}
		break;
	}

	return NOTIFY_OK;
}

static int exynos_g2d_probe(struct platform_device *pdev)
{
	struct scatterlist sgl;
	struct g2d1shot_dev *g2d_dev;
	struct resource *res;
	struct page *page;
	int ret;

	g2d_dev = devm_kzalloc(&pdev->dev, sizeof(*g2d_dev), GFP_KERNEL);
	if (!g2d_dev)
		return -ENOMEM;

	g2d_dev->dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	g2d_dev->reg = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(g2d_dev->reg))
		return PTR_ERR(g2d_dev->reg);

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "Failed to get IRQ resource");
		return -ENOENT;
	}

	ret = devm_request_irq(&pdev->dev, res->start, exynos_g2d_irq_handler,
				0, pdev->name, g2d_dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to install IRQ handler");
		return ret;
	}

	ret = g2d_init_clock(&pdev->dev, g2d_dev);
	if (ret)
		return ret;

	g2d_dev->oneshot2_dev = m2m1shot2_create_device(&pdev->dev,
		&m2m1shot2_g2d_ops, NODE_NAME, -1, M2M1SHOT2_DEVATTR_COHERENT);
	if (IS_ERR(g2d_dev->oneshot2_dev))
		return PTR_ERR(g2d_dev->oneshot2_dev);

	platform_set_drvdata(pdev, g2d_dev);
	g2d_dev->q_reg = ioremap(0x13a07000, 0x100);

	pm_runtime_enable(&pdev->dev);

	ret = g2d_get_hw_version(&pdev->dev, g2d_dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to get H/W version\n");
		goto err_hwver;
	}

	iovmm_set_fault_handler(&pdev->dev, g2d_iommu_fault_handler, g2d_dev);

	ret = iovmm_activate(&pdev->dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to activate iommu\n");
		goto err_hwver;
	}

	setup_timer(&g2d_dev->timer, g2d_timeout_handler,
						(unsigned long)g2d_dev);
	spin_lock_init(&g2d_dev->state_lock);
	mutex_init(&g2d_dev->lock_qos);
	init_waitqueue_head(&g2d_dev->suspend_wait);
	INIT_LIST_HEAD(&g2d_dev->qos_contexts);

	ret = g2d_populate_dt(g2d_dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to parse the device tree\n");
		goto err_hwver;
	}

	page = alloc_pages(GFP_KERNEL, 0);
	if (!page)
		goto err_hwver;

	sg_init_table(&sgl, 1);
	sg_set_page(&sgl, page, PAGE_SIZE, 0);

	g2d_dev->d_buf.page = page;
	g2d_dev->d_buf.dma_addr = iovmm_map(&pdev->dev,
			&sgl, 0, PAGE_SIZE, DMA_FROM_DEVICE,
			IOMMU_WRITE | IOMMU_CACHE);

	g2d_dev->pm_notifier.notifier_call = &exynos_g2d_notifier_event;
	register_pm_notifier(&g2d_dev->pm_notifier);

	dev_info(&pdev->dev, "G2D with m2m1shot2 is probed successfully.\n");

	return 0;
err_hwver:
	m2m1shot2_destroy_device(g2d_dev->oneshot2_dev);

	dev_err(&pdev->dev, "G2D m2m1shot2 probe is failed.\n");

	return ret;
}

static void g2d1shot_put_dummy_buf(struct platform_device *pdev,
		struct g2d_dummy_buf *d_buf)
{
	iovmm_unmap(&pdev->dev, d_buf->dma_addr);
	__free_pages(d_buf->page, 0);
}

static int exynos_g2d_remove(struct platform_device *pdev)
{
	struct g2d1shot_dev *g2d_dev = platform_get_drvdata(pdev);

	iounmap(g2d_dev->q_reg);

	g2d1shot_put_dummy_buf(pdev, &g2d_dev->d_buf);
	unregister_pm_notifier(&g2d_dev->pm_notifier);

	m2m1shot2_destroy_device(g2d_dev->oneshot2_dev);

	return 0;
}

static void exynos_g2d_shutdown(struct platform_device *pdev)
{
	struct g2d1shot_dev *g2d_dev = platform_get_drvdata(pdev);
	unsigned long flags;

	spin_lock_irqsave(&g2d_dev->state_lock, flags);
	g2d_dev->state |= G2D_STATE_SUSPENDING;
	spin_unlock_irqrestore(&g2d_dev->state_lock, flags);

	wait_event(g2d_dev->suspend_wait,
			!(g2d_dev->state & G2D_STATE_RUNNING));

	iovmm_deactivate(g2d_dev->dev);
}

#ifdef CONFIG_PM
static int g2d_runtime_suspend(struct device *dev)
{
	struct g2d1shot_dev *g2d_dev = dev_get_drvdata(dev);
	const u8 *ptr = g2d_dev->q_reg;
	size_t len = G2D_QCH_SIZE;
	int i, linelen, idx, remaining = len;
	char linebuf[SZ_128];
	int rowsize = 32;

	for (i = 0; i < len; i += rowsize) {
		idx = g2d_dev->dbg_idx % G2D_DEBUG_MAX_NUM;
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, 4,
			linebuf, sizeof(linebuf), false);

		g2d_dev->dbg_logs[idx].time = sched_clock();
		snprintf(g2d_dev->dbg_logs[idx].log,
			sizeof(g2d_dev->dbg_logs[idx].log),
			"%p: %s", ptr + i, linebuf);

		g2d_dev->dbg_idx++;
	}

	return 0;
}
static int g2d_runtime_resume(struct device *dev)
{
	return 0;
}
#endif

static const struct dev_pm_ops exynos_g2d_pm_ops = {
	SET_RUNTIME_PM_OPS(g2d_runtime_suspend, g2d_runtime_resume, NULL)
};

static const struct of_device_id exynos_g2d_match[] = {
	{
		.compatible = "samsung,s5p-fimg2d",
	},
	{},
};

static struct platform_driver exynos_g2d_driver = {
	.probe		= exynos_g2d_probe,
	.remove		= exynos_g2d_remove,
        .shutdown       = exynos_g2d_shutdown,
	.driver = {
		.name	= MODULE_NAME,
		.owner	= THIS_MODULE,
		.pm	= &exynos_g2d_pm_ops,
		.of_match_table = of_match_ptr(exynos_g2d_match),
	}
};

module_platform_driver(exynos_g2d_driver);

MODULE_AUTHOR("Janghyuck Kim <janghyuck.kim@samsung.com>");
MODULE_DESCRIPTION("Exynos Graphics 2D driver");
MODULE_LICENSE("GPL");

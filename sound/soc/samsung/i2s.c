/* sound/soc/samsung/i2s.c
 *
 * ALSA SoC Audio Layer - Samsung I2S Controller driver
 *
 * Copyright (c) 2010 Samsung Electronics Co. Ltd.
 *	Jaswinder Singh <jassisinghbrar@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pm_runtime.h>
#include <linux/mutex.h>

#include <sound/soc.h>
#include <sound/pcm_params.h>
#include <sound/exynos.h>

#include <linux/dma/dma-pl330.h>

#include <linux/platform_data/asoc-s3c.h>

#if 0
#include <plat/cpu.h>
#endif

#include "dma.h"
#include "lpass.h"
#ifdef CONFIG_SND_SAMSUNG_IDMA
#include "idma.h"
#endif
#include "i2s.h"
#include "i2s-regs.h"
#ifdef CONFIG_SND_SAMSUNG_FAKEDMA
#include "fdma.h"
#endif
#include "eax.h"
#ifdef CONFIG_SND_SAMSUNG_COMPR
#include "compr.h"
#endif

#define msecs_to_loops(t) (loops_per_jiffy / 1000 * HZ * t)

#define I2S_DEFAULT_SLOT_NUM	2 /* stereo default */

enum samsung_dai_type {
	TYPE_PRI,
	TYPE_SEC,
	TYPE_COMPR,
};

struct samsung_i2s_dai_data {
	int dai_type;
};

struct i2s_dai {
	/* Platform device for this DAI */
	struct platform_device *pdev;
	/* IOREMAP'd SFRs */
	void __iomem	*addr;
	/* Physical base address of SFRs */
	u32	base;
	/* IRQ number */
	unsigned int	irq;
	/* Rate of RCLK source clock */
	unsigned long rclk_srcrate;
	/* Frame Clock */
	unsigned frmclk;
	/*
	 * Specifically requested RCLK,BCLK by MACHINE Driver.
	 * 0 indicates CPU driver is free to choose any value.
	 */
	unsigned rfs, bfs;
	/* I2S Controller's core clock */
	struct clk *clk;
	/* Clock for generating I2S signals */
	struct clk *op_clk;
	struct clk *opclk0;
	struct clk *opclk1;
	/* Pointer to the Primary_Fifo if this is Sec_Fifo, NULL otherwise */
	struct i2s_dai *pri_dai;
	/* Pointer to the Secondary_Fifo if it has one, NULL otherwise */
	struct i2s_dai *sec_dai;
	/* Pointer to the Compress_dai if it has one, NULL otherwise */
#ifdef CONFIG_SND_SAMSUNG_COMPR
	struct i2s_dai *compr_dai;
	bool is_compress;
	bool running;
#endif
#define DAI_OPENED	(1 << 0) /* Dai is opened */
#define DAI_MANAGER	(1 << 1) /* Dai is the manager */
#define DAI_TDM_MODE	(1 << 2) /* Dai is set as TDM mode */
	unsigned mode;
	/* Driver for this DAI */
	struct snd_soc_dai_driver i2s_dai_drv;
	/* DMA parameters */
	struct s3c_dma_params dma_playback;
	struct s3c_dma_params dma_capture;
#ifdef CONFIG_SND_SAMSUNG_IDMA
	struct s3c_dma_params idma_playback;
#endif
#ifndef CONFIG_PM_RUNTIME
	int enable_cnt;
#endif
	u32	quirks;
	u32	amixer;
	u32	suspend_i2smod;
	u32	suspend_i2scon;
	u32	suspend_i2spsr;
#ifdef CONFIG_SND_SAMSUNG_IDMA
	u32	suspend_i2sahb[((I2SSTR1 - I2SAHB) >> 2) + 1];
#endif
	u32	suspend_i2stdm;
	/* GPIO pinctrl */
	struct pinctrl *pinctrl;
	/* MOD bit slice */
	u32	lrp_b;
	u32	cdclk_b;
	u32	slave_b;
	u32	rclks_b;
	u32	txr_sht;
	u32	txr_msk;
	u32	sdf_sht;
	u32	rfs_sht;
	u32	rfs_msk;
	u32	bfs_sht;
	u32	bfs_msk;
	int	slotnum;
};

/* Lock for cross i/f checks */
static DEFINE_SPINLOCK(lock);
static DEFINE_MUTEX(mutex);

#ifndef CONFIG_PM_RUNTIME
static int i2s_disable(struct device *dev);
static int i2s_enable(struct device *dev);
#endif

/* If this is the 'overlay' stereo DAI */
static inline bool is_secondary(struct i2s_dai *i2s)
{
	return i2s->pri_dai ? true : false;
}

/* If operating in SoC-Slave mode */
static inline bool is_slave(struct i2s_dai *i2s)
{
	return (readl(i2s->addr + I2SMOD) & i2s->slave_b) ? true : false;
}

#ifdef CONFIG_SND_SAMSUNG_COMPR
static DEFINE_SPINLOCK(sec_hw_lock);

static void i2s_print_dai_name(struct i2s_dai *i2s, char *dai_name)
{
	if (i2s->is_compress)
		snprintf(dai_name, 10, "compr");
	else if (is_secondary(i2s))
		snprintf(dai_name, 10, "sec");
	else
		snprintf(dai_name, 10, "pri");
}
#endif

/* If this interface of the controller is transmitting data */
static inline bool tx_active(struct i2s_dai *i2s)
{
	u32 active;

	if (!i2s)
		return false;

	active = readl(i2s->addr + I2SCON);

	if (is_secondary(i2s))
		active &= CON_TXSDMA_ACTIVE;
	else
		active &= CON_TXDMA_ACTIVE;

	return active ? true : false;
}

/* If the other interface of the controller is transmitting data */
static inline bool other_tx_active(struct i2s_dai *i2s)
{
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;

	return tx_active(other);
}

/* If any interface of the controller is transmitting data */
static inline bool any_tx_active(struct i2s_dai *i2s)
{
	return tx_active(i2s) || other_tx_active(i2s);
}

/* If this interface of the controller is receiving data */
static inline bool rx_active(struct i2s_dai *i2s)
{
	u32 active;

	if (!i2s)
		return false;

	active = readl(i2s->addr + I2SCON) & CON_RXDMA_ACTIVE;

	return active ? true : false;
}

/* If the other interface of the controller is receiving data */
static inline bool other_rx_active(struct i2s_dai *i2s)
{
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;

	return rx_active(other);
}

/* If any interface of the controller is receiving data */
static inline bool any_rx_active(struct i2s_dai *i2s)
{
	return rx_active(i2s) || other_rx_active(i2s);
}

/* If the other DAI is transmitting or receiving data */
static inline bool other_active(struct i2s_dai *i2s)
{
	return other_rx_active(i2s) || other_tx_active(i2s);
}

/* If this DAI is transmitting or receiving data */
static inline bool this_active(struct i2s_dai *i2s)
{
	return tx_active(i2s) || rx_active(i2s);
}

/* If the controller is active anyway */
static inline bool any_active(struct i2s_dai *i2s)
{
	return this_active(i2s) || other_active(i2s);
}

static inline struct i2s_dai *to_info(struct snd_soc_dai *dai)
{
	return snd_soc_dai_get_drvdata(dai);
}

static inline bool is_opened(struct i2s_dai *i2s)
{
	if (i2s && (i2s->mode & DAI_OPENED))
		return true;
	else
		return false;
}

static inline bool is_manager(struct i2s_dai *i2s)
{
	if (is_opened(i2s) && (i2s->mode & DAI_MANAGER))
		return true;
	else
		return false;
}

/* Read RCLK of I2S (in multiples of LRCLK) */
static inline unsigned get_rfs(struct i2s_dai *i2s)
{
	u32 rfs;

	rfs = readl(i2s->addr + I2SMOD) >> i2s->rfs_sht;
	rfs &= i2s->rfs_msk;

	switch (rfs) {
	case 7: return 192;
	case 6: return 96;
	case 5: return 128;
	case 4: return 64;
	case 3:	return 768;
	case 2: return 384;
	case 1:	return 512;
	default: return 256;
	}
}

/* Write RCLK of I2S (in multiples of LRCLK) */
static inline void set_rfs(struct i2s_dai *i2s, unsigned rfs)
{
	u32 mod = readl(i2s->addr + I2SMOD);
	u32 val;

	switch (rfs) {
	case 768:
		val = MOD_RCLK_768FS;
		break;
	case 512:
		val = MOD_RCLK_512FS;
		break;
	case 384:
		val = MOD_RCLK_384FS;
		break;
	case 192:
		val = EXYNOS5430_MOD_RCLK_192FS;
		break;
	case 128:
		val = EXYNOS5430_MOD_RCLK_128FS;
		break;
	case 96:
		val = EXYNOS5430_MOD_RCLK_96FS;
		break;
	case 64:
		val = EXYNOS5430_MOD_RCLK_64FS;
		break;
	default:
		val = MOD_RCLK_256FS;
		break;
	}

	mod &= ~(i2s->rfs_msk << i2s->rfs_sht);
	mod |= val << i2s->rfs_sht;
	writel(mod, i2s->addr + I2SMOD);
}

/* Read Bit-Clock of I2S (in multiples of LRCLK) */
static inline unsigned get_bfs(struct i2s_dai *i2s)
{
	u32 bfs;

	bfs = readl(i2s->addr + I2SMOD) >> i2s->bfs_sht;
	bfs &= i2s->bfs_msk;

	switch (bfs) {
	case 8: return 256;
	case 7: return 192;
	case 6: return 128;
	case 5: return 96;
	case 4: return 64;
	case 3: return 24;
	case 2: return 16;
	case 1:	return 48;
	default: return 32;
	}
}

/* Write Bit-Clock of I2S (in multiples of LRCLK) */
static inline void set_bfs(struct i2s_dai *i2s, unsigned bfs)
{
	u32 mod = readl(i2s->addr + I2SMOD);
	u32 val;

	switch (bfs) {
	case 48:
		val = MOD_BCLK_48FS;
		break;
	case 32:
		val = MOD_BCLK_32FS;
		break;
	case 24:
		val = MOD_BCLK_24FS;
		break;
	case 16:
		val = MOD_BCLK_16FS;
		break;
	case 64:
		val = EXYNOS5420_MOD_BCLK_64FS;
		break;
	case 96:
		val = EXYNOS5420_MOD_BCLK_96FS;
		break;
	case 128:
		val = EXYNOS5420_MOD_BCLK_128FS;
		break;
	case 192:
		val = EXYNOS5420_MOD_BCLK_192FS;
		break;
	case 256:
		val = EXYNOS5420_MOD_BCLK_256FS;
		break;
	default:
		dev_err(&i2s->pdev->dev, "Wrong BCLK Divider!\n");
		return;
	}

	mod &= ~(i2s->bfs_msk << i2s->bfs_sht);
	mod |= val << i2s->bfs_sht;
	writel(mod, i2s->addr + I2SMOD);
}

/* Sample-Size */
static inline int get_blc(struct i2s_dai *i2s)
{
	int blc = readl(i2s->addr + I2SMOD);

	blc = (blc >> 13) & 0x3;

	switch (blc) {
	case 2: return 24;
	case 1:	return 8;
	default: return 16;
	}
}

/* TX Channel Control */
static void i2s_txctrl(struct i2s_dai *i2s, int on)
{
	void __iomem *addr = i2s->addr;
	u32 con = readl(addr + I2SCON);
	u32 mod = readl(addr + I2SMOD);

	mod &= ~(i2s->txr_msk << i2s->txr_sht);
	mod |= MOD_TXR_TXRX << i2s->txr_sht;

	if (on) {
		con |= CON_ACTIVE;
		con &= ~CON_TXCH_PAUSE;

		if (is_secondary(i2s)) {
			con |= CON_TXSDMA_ACTIVE;
			con &= ~CON_TXSDMA_PAUSE;
		} else {
			con |= CON_TXDMA_ACTIVE;
			con &= ~CON_TXDMA_PAUSE;
		}

		if (any_rx_active(i2s))
			mod |= MOD_TXR_TXRX << i2s->txr_sht;
		else
			mod |= MOD_TXR_TXONLY << i2s->txr_sht;
	} else {
		if (is_secondary(i2s)) {
			con |=  CON_TXSDMA_PAUSE;
			con &= ~CON_TXSDMA_ACTIVE;
		} else {
			con |=  CON_TXDMA_PAUSE;
			con &= ~CON_TXDMA_ACTIVE;
		}

		if (other_tx_active(i2s)) {
			writel(con, addr + I2SCON);
			return;
		}

		con |=  CON_TXCH_PAUSE;

		if (any_rx_active(i2s))
			mod |= MOD_TXR_TXRX << i2s->txr_sht;
		else
			con &= ~CON_ACTIVE;
	}

	writel(mod, addr + I2SMOD);
	writel(con, addr + I2SCON);
}

/* RX Channel Control */
static void i2s_rxctrl(struct i2s_dai *i2s, int on)
{
	void __iomem *addr = i2s->addr;
	u32 con = readl(addr + I2SCON);
	u32 mod = readl(addr + I2SMOD);

	mod &= ~(i2s->txr_msk << i2s->txr_sht);
	mod |= MOD_TXR_TXRX << i2s->txr_sht;

	if (on) {
		con |= CON_RXDMA_ACTIVE | CON_ACTIVE;
		con &= ~(CON_RXDMA_PAUSE | CON_RXCH_PAUSE);

		if (any_tx_active(i2s))
			mod |= MOD_TXR_TXRX << i2s->txr_sht;
		else
			mod |= MOD_TXR_RXONLY << i2s->txr_sht;
	} else {
		con |=  CON_RXDMA_PAUSE | CON_RXCH_PAUSE;
		con &= ~CON_RXDMA_ACTIVE;

		if (any_tx_active(i2s))
			mod |= MOD_TXR_TXONLY << i2s->txr_sht;
		else
			con &= ~CON_ACTIVE;
	}

	writel(mod, addr + I2SMOD);
	writel(con, addr + I2SCON);
}

/* Flush FIFO of an interface */
static inline void i2s_fifo(struct i2s_dai *i2s, u32 flush)
{
	void __iomem *fic;
	u32 val;

	if (!i2s)
		return;

	if (is_secondary(i2s))
		fic = i2s->addr + I2SFICS;
	else
		fic = i2s->addr + I2SFIC;

	/* Flush the FIFO */
	writel(readl(fic) | flush, fic);

	/* Be patient */
	val = msecs_to_loops(1) / 1000; /* 1 usec */
	while (--val)
		cpu_relax();

	writel(readl(fic) & ~flush, fic);
}

static int i2s_set_sysclk(struct snd_soc_dai *dai,
	  int clk_id, unsigned int rfs, int dir)
{
	struct i2s_dai *i2s = to_info(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;
	u32 mod = readl(i2s->addr + I2SMOD);

	switch (clk_id) {
	case SAMSUNG_I2S_OPCLK:
		mod &= ~MOD_OPCLK_MASK;
		mod |= dir;
		break;

	case SAMSUNG_I2S_CDCLK:
		/* Shouldn't matter in GATING(CLOCK_IN) mode */
		if (dir == SND_SOC_CLOCK_IN)
			rfs = 0;

		if ((rfs && other->rfs && (other->rfs != rfs)) ||
				(any_active(i2s) &&
				(((dir == SND_SOC_CLOCK_IN)
					&& !(mod & i2s->cdclk_b)) ||
				((dir == SND_SOC_CLOCK_OUT)
					&& (mod & i2s->cdclk_b))))) {
			dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
			return -EAGAIN;
		}

		if (dir == SND_SOC_CLOCK_IN)
			mod |= i2s->cdclk_b;
		else
			mod &= ~i2s->cdclk_b;

		i2s->rfs = rfs;
		break;

	case SAMSUNG_I2S_RCLKSRC_0: /* clock corrsponding to RCLKSRC := 0 */
	case SAMSUNG_I2S_RCLKSRC_1: /* clock corrsponding to RCLKSRC := 1 */
		if ((i2s->quirks & QUIRK_NO_MUXPSR)
				|| (clk_id == SAMSUNG_I2S_RCLKSRC_0))
			clk_id = 0;
		else
			clk_id = 1;

		if (!any_active(i2s)) {
			if (i2s->op_clk) {
				if ((clk_id && !(mod & i2s->rclks_b)) ||
					(!clk_id && (mod & i2s->rclks_b))) {
				} else {
					i2s->rclk_srcrate =
						clk_get_rate(i2s->op_clk);
					return 0;
				}
			}

			if (clk_id) {
				i2s->op_clk = i2s->opclk1;
			} else {
				i2s->op_clk = i2s->opclk0;
			}
			i2s->rclk_srcrate = clk_get_rate(i2s->op_clk);

			/* Over-ride the other's */
			if (other) {
				other->op_clk = i2s->op_clk;
				other->rclk_srcrate = i2s->rclk_srcrate;
			}
		} else if ((!clk_id && (mod & i2s->rclks_b))
				|| (clk_id && !(mod & i2s->rclks_b))) {
			dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
			return -EAGAIN;
		} else {
			/* Call can't be on the active DAI */
			i2s->op_clk = other->op_clk;
			i2s->rclk_srcrate = other->rclk_srcrate;
			return 0;
		}

		if (clk_id == 0)
			mod &= ~i2s->rclks_b;
		else
			mod |= i2s->rclks_b;
		break;

	default:
		dev_err(&i2s->pdev->dev, "We don't serve that!\n");
		return -EINVAL;
	}
	writel(mod, i2s->addr + I2SMOD);

	return 0;
}

static int i2s_set_fmt(struct snd_soc_dai *dai,
	unsigned int fmt)
{
	struct i2s_dai *i2s = to_info(dai);
	u32 mod = readl(i2s->addr + I2SMOD);
	u32 tmp = 0;
	int sdf_mask = MOD_SDF_MASK << i2s->sdf_sht;

	/* Format is priority */
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_RIGHT_J:
		tmp |= i2s->lrp_b;
		tmp |= (MOD_SDF_MSB << i2s->sdf_sht);
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		tmp |= i2s->lrp_b;
		tmp |= (MOD_SDF_LSB << i2s->sdf_sht);
		break;
	case SND_SOC_DAIFMT_I2S:
	case SND_SOC_DAIFMT_DSP_A: /* both are same in exynos */
		tmp |= (MOD_SDF_IIS << i2s->sdf_sht);
		break;
	default:
		dev_err(&i2s->pdev->dev, "Format not supported\n");
		return -EINVAL;
	}

	/*
	 * INV flag is relative to the FORMAT flag - if set it simply
	 * flips the polarity specified by the Standard
	 */
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		break;
	case SND_SOC_DAIFMT_NB_IF:
		if (tmp & i2s->lrp_b)
			tmp &= ~i2s->lrp_b;
		else
			tmp |= i2s->lrp_b;
		break;
	default:
		dev_err(&i2s->pdev->dev, "Polarity not supported\n");
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		tmp |= i2s->slave_b;
		break;
	case SND_SOC_DAIFMT_CBS_CFS:
		tmp &= ~i2s->slave_b;
		break;
	default:
		dev_err(&i2s->pdev->dev, "master/slave format not supported\n");
		return -EINVAL;
	}

	/*
	 * Don't change the I2S mode if any controller is active on this
	 * channel.
	 */
	if (any_active(i2s) &&
	    ((mod & (sdf_mask | i2s->lrp_b | i2s->slave_b)) != tmp)) {
		dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
		return -EAGAIN;
	}

	mod &= ~(sdf_mask | i2s->lrp_b | i2s->slave_b);
	mod |= tmp;
	writel(mod, i2s->addr + I2SMOD);

	return 0;
}

#ifdef CONFIG_SND_SOC_I2S_1840_TDM
static int i2s_set_tdm_slot(struct snd_soc_dai *dai,
	unsigned int tx_mask, unsigned int rx_mask, int slots, int slot_width)
{
	struct i2s_dai *i2s = to_info(dai);
	u32 tdm;

	if (!(i2s->quirks & QUIRK_SUPPORTS_TDM)) {
		dev_err(&i2s->pdev->dev, "TDM not supported\n");
		return -EINVAL;
	}

	tdm = readl(i2s->addr + I2STDM);
	tdm &= ~(TDM_TX_SLOTS_MASK << TDM_TX_SLOTS_SHIFT);
	tdm &= ~(TDM_RX_SLOTS_MASK << TDM_RX_SLOTS_SHIFT);
	if (slots) {
		i2s->mode |= DAI_TDM_MODE;
		tdm |= TDM_ENABLE;
		tdm |= ((CONFIG_SND_SOC_I2S_TXSLOT_NUMBER-1) & TDM_TX_SLOTS_MASK)
			<< TDM_TX_SLOTS_SHIFT;
		tdm |= ((CONFIG_SND_SOC_I2S_RXSLOT_NUMBER-1) & TDM_RX_SLOTS_MASK)
			<< TDM_RX_SLOTS_SHIFT;
		pr_info("tdm mode transmission - tx: %d, rx: %d where txmask: 0x%08X, rxmask: 0x%08X\n",
			CONFIG_SND_SOC_I2S_TXSLOT_NUMBER, CONFIG_SND_SOC_I2S_RXSLOT_NUMBER,
			tx_mask, rx_mask);
	} else {
		i2s->mode &= ~DAI_TDM_MODE;
		tdm &= ~TDM_ENABLE;
	}
	writel(tdm, i2s->addr + I2STDM);

	return 0;
}
#endif

static int i2s_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
	u32 mod = readl(i2s->addr + I2SMOD);

	if (!is_secondary(i2s) &&
		(substream->stream == SNDRV_PCM_STREAM_PLAYBACK))
		mod &= ~(MOD_DC2_EN | MOD_DC1_EN);

	switch (params_channels(params)) {
	case 6:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			i2s->dma_playback.dma_size = 4;
			mod |= MOD_DC2_EN | MOD_DC1_EN;
		} else {
			i2s->dma_capture.dma_size = 4;
		}
		break;
	case 4:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			i2s->dma_playback.dma_size = 4;
			mod |= MOD_DC1_EN;
		} else {
			i2s->dma_capture.dma_size = 4;
		}
		break;
	case 2:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			i2s->dma_playback.dma_size = 4;
		else
			i2s->dma_capture.dma_size = 4;
		break;
	case 1:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			i2s->dma_playback.dma_size = 2;
		else
			i2s->dma_capture.dma_size = 2;

		break;
	default:
		dev_err(&i2s->pdev->dev, "%d channels not supported\n",
				params_channels(params));
		return -EINVAL;
	}

	if (is_secondary(i2s))
		mod &= ~MOD_BLCS_MASK;
	else
		mod &= ~MOD_BLCP_MASK;

	if (is_manager(i2s))
		mod &= ~MOD_BLC_MASK;

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S8:
		if (is_secondary(i2s))
			mod |= MOD_BLCS_8BIT;
		else
			mod |= MOD_BLCP_8BIT;
		if (is_manager(i2s))
			mod |= MOD_BLC_8BIT;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
		if (is_secondary(i2s))
			mod |= MOD_BLCS_16BIT;
		else
			mod |= MOD_BLCP_16BIT;
		if (is_manager(i2s))
			mod |= MOD_BLC_16BIT;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		if (is_secondary(i2s))
			mod |= MOD_BLCS_24BIT;
		else
			mod |= MOD_BLCP_24BIT;
		if (is_manager(i2s))
			mod |= MOD_BLC_24BIT;
		break;
	default:
		dev_err(&i2s->pdev->dev, "Format(%d) not supported\n",
				params_format(params));
		return -EINVAL;
	}
	writel(mod, i2s->addr + I2SMOD);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		snd_soc_dai_set_dma_data(dai, substream,
			(void *)&i2s->dma_playback);
	else
		snd_soc_dai_set_dma_data(dai, substream,
			(void *)&i2s->dma_capture);

	i2s->frmclk = params_rate(params);

#ifdef USE_EXYNOS_AUD_SCHED
	if ((mod & MOD_BLC_MASK) == MOD_BLC_24BIT)
		lpass_set_sched(pid_nr(substream->pid), AUD_MODE_UHQA);
	else if (mod & (MOD_DC2_EN | MOD_DC1_EN))
		lpass_set_sched(pid_nr(substream->pid), AUD_MODE_UHQA);
	else
		lpass_set_sched(pid_nr(substream->pid), AUD_MODE_NORM);
#endif
	return 0;
}

static void i2s_reg_save(struct i2s_dai *i2s)
{
#ifdef CONFIG_SND_SAMSUNG_IDMA
	u32 n, offset;
#endif
	i2s->suspend_i2smod = readl(i2s->addr + I2SMOD);
	i2s->suspend_i2scon = readl(i2s->addr + I2SCON);
	i2s->suspend_i2spsr = readl(i2s->addr + I2SPSR);
#ifdef CONFIG_SND_SAMSUNG_IDMA
	if (i2s->quirks & QUIRK_IDMA) {
		for (n = 0, offset = I2SAHB; offset <= I2SSTR1; offset += 4)
			i2s->suspend_i2sahb[n++] = readl(i2s->addr + offset);
	}
#endif
	if (i2s->quirks & QUIRK_SUPPORTS_TDM)
		i2s->suspend_i2stdm = readl(i2s->addr + I2STDM);

	dev_dbg(&i2s->pdev->dev, "Registers of I2S are saved\n");

	return;
}

static void i2s_reg_restore(struct i2s_dai *i2s)
{
#ifdef CONFIG_SND_SAMSUNG_IDMA
	u32 n, offset;
#endif
	writel(i2s->suspend_i2smod, i2s->addr + I2SMOD);
	writel(i2s->suspend_i2scon, i2s->addr + I2SCON);
	writel(i2s->suspend_i2spsr, i2s->addr + I2SPSR);
#ifdef CONFIG_SND_SAMSUNG_IDMA
	if (i2s->quirks & QUIRK_IDMA) {
		for (n = 0, offset = I2SAHB; offset <= I2SSTR1; offset += 4)
			writel(i2s->suspend_i2sahb[n++], i2s->addr + offset);
	}
#endif
	if (i2s->quirks & QUIRK_SUPPORTS_TDM)
		writel(i2s->suspend_i2stdm, i2s->addr + I2STDM);

	dev_dbg(&i2s->pdev->dev, "Registers of I2S are restored\n");

	return;
}

/* We set constraints on the substream acc to the version of I2S */
static int i2s_startup(struct snd_pcm_substream *substream,
	  struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;
	struct platform_device *pdev = NULL;
	unsigned long flags;
#ifdef CONFIG_SND_SAMSUNG_COMPR
	char dai_name[10];

	i2s_print_dai_name(i2s, dai_name);
	pr_info("%s : %s --\n", __func__, dai_name);
#else
	pr_info("%s : %s --\n", __func__, is_secondary(i2s)? "sec" : "pri");
#endif

#ifdef USE_EXYNOS_AUD_SCHED
	lpass_set_sched(pid_nr(substream->pid), AUD_MODE_DEFAULT);
#endif
#ifdef USE_EXYNOS_AUD_CPU_HOTPLUG
	if (!is_secondary(i2s))
		lpass_get_cpu_hotplug();
#endif
	lpass_add_stream();

	mutex_lock(&mutex);
	pdev = is_secondary(i2s) ? i2s->pri_dai->pdev : i2s->pdev;
#ifdef CONFIG_PM_RUNTIME
	pm_runtime_get_sync(&pdev->dev);
#else
	i2s_enable(&pdev->dev);
#endif

	spin_lock_irqsave(&lock, flags);

	i2s->mode |= DAI_OPENED;

	if (is_manager(other))
		i2s->mode &= ~DAI_MANAGER;
	else
		i2s->mode |= DAI_MANAGER;

	if (is_opened(other))
		i2s->mode |= other->mode & DAI_TDM_MODE;

	/* Enforce set_sysclk in Master mode */
	i2s->rclk_srcrate = 0;

	if (!any_active(i2s) && (i2s->quirks & QUIRK_NEED_RSTCLR))
		writel(CON_RSTCLR, i2s->addr + I2SCON);

	if (!any_tx_active(i2s) && (i2s->quirks & QUIRK_SEC_DAI)) {
		i2s_fifo(i2s, FIC_TXFLUSH);
		i2s_fifo(other, FIC_TXFLUSH);
	}

	spin_unlock_irqrestore(&lock, flags);
	mutex_unlock(&mutex);

#ifdef CONFIG_SND_SAMSUNG_COMPR
	pr_info("%s : %s --\n", __func__, dai_name);
#else
	pr_info("%s : %s --\n", __func__, is_secondary(i2s)? "sec" : "pri");
#endif
	return 0;
}

static void i2s_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;
	struct platform_device *pdev = NULL;
	unsigned long flags;
#ifdef CONFIG_SND_SAMSUNG_COMPR
	char dai_name[10];

	i2s_print_dai_name(i2s, dai_name);
	pr_info("%s : %s --\n", __func__, dai_name);
#else
	pr_info("%s : %s ++\n", __func__, is_secondary(i2s)? "sec" : "pri");
#endif
	mutex_lock(&mutex);
	spin_lock_irqsave(&lock, flags);

	i2s->mode &= ~DAI_OPENED;
	i2s->mode &= ~DAI_MANAGER;
	i2s->mode &= ~DAI_TDM_MODE;

	if (is_opened(other)) {
		other->mode |= DAI_MANAGER;
		i2s->mode |= other->mode & DAI_TDM_MODE;
	}

	/* Reset any constraint on RFS and BFS */
	i2s->rfs = 0;
	i2s->bfs = 0;

	spin_unlock_irqrestore(&lock, flags);

	pdev = is_secondary(i2s) ? i2s->pri_dai->pdev : i2s->pdev;
#ifdef CONFIG_PM_RUNTIME
	pm_runtime_put_sync(&pdev->dev);
#else
	i2s_disable(&pdev->dev);
#endif
	mutex_unlock(&mutex);
	lpass_remove_stream();

#ifdef USE_EXYNOS_AUD_CPU_HOTPLUG
	if (!is_secondary(i2s))
		lpass_put_cpu_hotplug();
#endif
#ifdef CONFIG_SND_SAMSUNG_COMPR
	pr_info("%s : %s --\n", __func__, dai_name);
#else
	pr_info("%s : %s --\n", __func__, is_secondary(i2s)? "sec" : "pri");
#endif
}

static int config_setup(struct i2s_dai *i2s)
{
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;
	unsigned rfs, bfs, blc;
	u32 psr;

	blc = get_blc(i2s);

	bfs = i2s->bfs;

	if (!bfs && other)
		bfs = other->bfs;

	/* Select least possible multiple(2) if no constraint set */
	if (!bfs)
		bfs = blc * i2s->slotnum;

	rfs = i2s->rfs;

	if (!rfs && other)
		rfs = other->rfs;

	if (!rfs) {
		if (bfs == 16 || bfs == 32)
			rfs = 256;
		else if (bfs == 48)
			rfs = 384;
		else
			rfs = 512;
		rfs /= (i2s->slotnum / I2S_DEFAULT_SLOT_NUM);
	}

	if ((rfs % bfs) || (rfs > 768)) {
		dev_err(&i2s->pdev->dev,
			"%d-RFS not supported for %d-BFS\n", rfs, bfs);
		return -EINVAL;
	}

	/* If already setup and running */
	if (any_active(i2s) && (get_rfs(i2s) != rfs || get_bfs(i2s) != bfs)) {
		dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
		return -EAGAIN;
	}

	set_bfs(i2s, bfs);
	set_rfs(i2s, rfs);

	/* Don't bother with PSR in Slave mode */
	if (is_slave(i2s))
		return 0;

	if (!(i2s->quirks & QUIRK_NO_MUXPSR)) {
		psr = (i2s->rclk_srcrate + (rfs / 2)) / i2s->frmclk / rfs;
		writel(((psr - 1) << 8) | PSR_PSREN, i2s->addr + I2SPSR);
		dev_dbg(&i2s->pdev->dev,
			"RCLK_SRC=%luHz PSR=%u, RCLK=%dfs, BCLK=%dfs\n",
				i2s->rclk_srcrate, psr, rfs, bfs);
	}

	return 0;
}

static int i2s_trigger(struct snd_pcm_substream *substream,
	int cmd, struct snd_soc_dai *dai)
{
	int capture = (substream->stream == SNDRV_PCM_STREAM_CAPTURE);
	struct i2s_dai *i2s = to_info(dai);
	unsigned long flags;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		local_irq_save(flags);

		if (config_setup(i2s)) {
			local_irq_restore(flags);
			return -EINVAL;
		}

#ifdef CONFIG_SND_SAMSUNG_COMPR
		if (!capture && is_secondary(i2s)) {
			spin_lock(&sec_hw_lock);
			i2s->running = true;
			if ((i2s->is_compress && i2s->sec_dai->running) ||
			   (!i2s->is_compress && i2s->compr_dai->running)) {
				spin_unlock(&sec_hw_lock);
				break;
			}
		}
#endif

		if (capture)
			i2s_rxctrl(i2s, 1);
		else
			i2s_txctrl(i2s, 1);

#ifdef CONFIG_SND_SAMSUNG_COMPR
		if (!capture && is_secondary(i2s))
			spin_unlock(&sec_hw_lock);
#endif

		local_irq_restore(flags);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		local_irq_save(flags);

#ifdef CONFIG_SND_SAMSUNG_COMPR
		if (!capture && is_secondary(i2s)) {
			spin_lock(&sec_hw_lock);
			i2s->running = false;
			if ((i2s->is_compress && i2s->sec_dai->running) ||
			   (!i2s->is_compress && i2s->compr_dai->running)) {
				spin_unlock(&sec_hw_lock);
				break;
			}
		}
#endif

		if (capture) {
			i2s_rxctrl(i2s, 0);
			i2s_fifo(i2s, FIC_RXFLUSH);
		} else {
			i2s_txctrl(i2s, 0);
			if (!(i2s->quirks & QUIRK_SEC_DAI))
				i2s_fifo(i2s, FIC_TXFLUSH);
		}

#ifdef CONFIG_SND_SAMSUNG_COMPR
		if (!capture && is_secondary(i2s))
			spin_unlock(&sec_hw_lock);
#endif

		local_irq_restore(flags);
		break;
	}

	return 0;
}

static int i2s_set_clkdiv(struct snd_soc_dai *dai,
	int div_id, int div)
{
	struct i2s_dai *i2s = to_info(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;

	switch (div_id) {
	case SAMSUNG_I2S_DIV_BCLK:
		if ((any_active(i2s) && div && (get_bfs(i2s) != div))
			|| (other && other->bfs && (other->bfs != div))) {
			dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
			return -EAGAIN;
		}
		i2s->bfs = div;
		break;
	case SAMSUNG_I2S_DIV_RCLK:
		if ((any_active(i2s) && div && (get_rfs(i2s) != div))
			|| (other && other->rfs && (other->rfs != div))) {
			dev_err(&i2s->pdev->dev,
				"%s:%d Other DAI busy\n", __func__, __LINE__);
			return -EAGAIN;
		}
		i2s->rfs = div;
		break;
	default:
		dev_err(&i2s->pdev->dev,
			"Invalid clock divider(%d)\n", div_id);
		return -EINVAL;
	}

	return 0;
}

static snd_pcm_sframes_t
i2s_delay(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
	u32 reg = readl(i2s->addr + I2SFIC);
	snd_pcm_sframes_t delay;

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		delay = FIC_RXCOUNT(reg);
	else if (is_secondary(i2s))
		delay = FICS_TXCOUNT(readl(i2s->addr + I2SFICS));
	else
		delay = FIC_TXCOUNT(reg);

	return delay;
}

static void i2s_init_bit_slice(struct i2s_dai *i2s)
{
	if (i2s->quirks & QUIRK_SUPPORTS_TDM) {	/* IIS V5.1 (new) */
		if (i2s->quirks & QUIRK_SUPPORTS_LOW_RFS) {
			i2s->lrp_b   = EXYNOS5430_MOD_LRP;
			i2s->cdclk_b = EXYNOS5430_MOD_CDCLKCON;
			i2s->slave_b = EXYNOS5430_MOD_SLAVE;
			i2s->rclks_b = EXYNOS5430_MOD_RCLKSRC;
			i2s->txr_sht = EXYNOS5430_MOD_TXR_SHIFT;
			i2s->txr_msk = EXYNOS5430_MOD_TXR_MASK;
			i2s->sdf_sht = EXYNOS5430_MOD_SDF_SHIFT;
			i2s->rfs_sht = EXYNOS5430_MOD_RCLK_SHIFT;
			i2s->rfs_msk = EXYNOS5430_MOD_RCLK_MASK;
			i2s->bfs_sht = EXYNOS5430_MOD_BCLK_SHIFT;
			i2s->bfs_msk = EXYNOS5430_MOD_BCLK_MASK;
		} else {
			i2s->lrp_b   = EXYNOS5420_MOD_LRP;
			i2s->cdclk_b = EXYNOS5420_MOD_CDCLKCON;
			i2s->slave_b = EXYNOS5420_MOD_SLAVE;
			i2s->rclks_b = EXYNOS5420_MOD_RCLKSRC;
			i2s->txr_sht = EXYNOS5420_MOD_TXR_SHIFT;
			i2s->txr_msk = EXYNOS5420_MOD_TXR_MASK;
			i2s->sdf_sht = EXYNOS5420_MOD_SDF_SHIFT;
			i2s->rfs_sht = EXYNOS5420_MOD_RCLK_SHIFT;
			i2s->rfs_msk = EXYNOS5420_MOD_RCLK_MASK;
			i2s->bfs_sht = EXYNOS5420_MOD_BCLK_SHIFT;
			i2s->bfs_msk = EXYNOS5420_MOD_BCLK_MASK;
		}
	} else {				/* IIS V5.1 (old) */
		i2s->lrp_b   = MOD_LRP;
		i2s->cdclk_b = MOD_CDCLKCON;
		i2s->slave_b = MOD_SLAVE;
		i2s->rclks_b = MOD_RCLKSRC;
		i2s->txr_sht = MOD_TXR_SHIFT;
		i2s->txr_msk = MOD_TXR_MASK;
		i2s->sdf_sht = MOD_SDF_SHIFT;
		i2s->rfs_sht = MOD_RCLK_SHIFT;
		i2s->rfs_msk = MOD_RCLK_MASK;
		i2s->bfs_sht = MOD_BCLK_SHIFT;
		i2s->bfs_msk = MOD_BCLK_MASK;
	}
}

#ifdef CONFIG_SND_SAMSUNG_FAKEDMA
int i2s_get_fifo_cnt(struct snd_pcm_substream * substream,
			struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
#ifdef CONFIG_SOC_EXYNOS7420
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		if (i2s->quirks & QUIRK_SEC_DAI)
			return (readl(i2s->addr + I2SFIC1) & 0x7F);
		else
			return (readl(i2s->addr + I2SFIC) & 0x7F);
	} else {
		if (is_secondary(i2s))
			return ((readl(i2s->addr + I2SFICS) >> 8) & 0x7F);
		else if (i2s->quirks & QUIRK_SEC_DAI)
			return (readl(i2s->addr + I2SFIC) & 0x7F);
		else
			return ((readl(i2s->addr + I2SFIC) >> 8) & 0x7F);
	}
#else
	u32 fic = readl(i2s->addr + I2SFIC);
	u32 fics = readl(i2s->addr + I2SFICS);

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		return (fic & 0x7F);
	else if (is_secondary(i2s))
		return ((fics >> 8) & 0x7F);
	else
		return ((fic >> 8) & 0x7F);
#endif
}

void i2s_write_fifo(struct snd_pcm_substream * substream,
			struct snd_soc_dai *dai, u32 val)
{
	struct i2s_dai *i2s = to_info(dai);

	writel(val, i2s->addr + (is_secondary(i2s) ? I2STXDS : I2STXD));
}

u32 i2s_read_fifo(struct snd_pcm_substream * substream,
			struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);

	return readl(i2s->addr + I2SRXD);
}

static struct samsung_fdma_cpu_ops cpu_ops = {
	.get_fifo_cnt	= i2s_get_fifo_cnt,
	.write_fifo	= i2s_write_fifo,
	.read_fifo	= i2s_read_fifo
};
#endif

static void i2s_cfg_gpio(struct i2s_dai *i2s, const char *name)
{
	struct platform_device *pdev;
	struct s3c_audio_pdata *i2s_pdata;
	struct pinctrl_state *pin_state;

	pdev = is_secondary(i2s) ? i2s->pri_dai->pdev : i2s->pdev;

	if (pdev->dev.of_node) {
		pin_state = pinctrl_lookup_state(i2s->pinctrl, name);
		if (IS_ERR(pin_state))
			goto err;
		if (pinctrl_select_state(i2s->pinctrl, pin_state) < 0)
			goto err;
	} else {
		i2s_pdata = pdev->dev.platform_data;
		if (i2s_pdata->cfg_gpio && i2s_pdata->cfg_gpio(pdev))
			goto err;
	}

	return;
err:
	dev_dbg(&pdev->dev, "Unable to configure i2s gpio as %s\n", name);
	return;
}

#ifdef CONFIG_PM
static int i2s_suspend(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);

	if (dai->active) {
		i2s_cfg_gpio(i2s, "idle");
		i2s_reg_save(i2s);
	}

	return 0;
}

static int i2s_resume(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);

	if (dai->active) {
		i2s_reg_restore(i2s);
		i2s_cfg_gpio(i2s, "default");
	}

	return 0;
}

static int i2s_suspend_force(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);

	i2s_cfg_gpio(i2s, "idle");
	i2s_reg_save(i2s);

	return 0;
}

static int i2s_resume_force(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);

	i2s_reg_restore(i2s);
	i2s_cfg_gpio(i2s, "default");

	return 0;
}
#else
#define i2s_suspend NULL
#define i2s_resume  NULL
#define i2s_suspend_force NULL
#define i2s_resume_force  NULL
#endif

static const struct snd_soc_dai_ops samsung_i2s_dai_ops;
static int samsung_i2s_dai_probe(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = to_info(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;
#ifdef CONFIG_SND_SAMSUNG_COMPR
	struct i2s_dai *compr = i2s->compr_dai;

#ifndef CONFIG_SND_SOC_EAX_SLOWPATH
	if ((other && other->clk) || i2s->is_compress) /* If this is probe on secondary */
		goto probe_exit;
#else
	if (other && other->clk) {
		if (i2s->is_compress)  { /* If this is probe on secondary */
			goto probe_exit;
		} else {
			eax_slowpath_dai_register(dai, &samsung_i2s_dai_ops,
					i2s_suspend_force, i2s_resume_force);
			goto probe_exit;
		}
	}
#endif
#else
	if (other && other->clk) /* If this is probe on secondary */
		goto probe_exit;
#endif

	i2s->addr = ioremap(i2s->base, 0x100);
	if (i2s->addr == NULL) {
		dev_err(&i2s->pdev->dev, "cannot ioremap registers\n");
		return -ENXIO;
	}

#ifndef CONFIG_SOC_EXYNOS8890
	i2s->clk = clk_get(&i2s->pdev->dev, "iis");
	if (IS_ERR(i2s->clk)) {
		dev_err(&i2s->pdev->dev, "failed to get i2s_clock\n");
		iounmap(i2s->addr);
		return -ENOENT;
	}

	i2s->opclk1 = clk_get(&i2s->pdev->dev, "i2s_opclk1");
	if (IS_ERR(i2s->opclk1)) {
		dev_err(&i2s->pdev->dev, "failed to get i2s_opclk1\n");
		clk_put(i2s->clk);
		iounmap(i2s->addr);
		return -ENOENT;
	}

	i2s->opclk0 = clk_get(&i2s->pdev->dev, "i2s_opclk0");
	if (IS_ERR(i2s->opclk0)) {
		dev_err(&i2s->pdev->dev, "failed to get i2s_opclk0\n");
		clk_put(i2s->opclk1);
		clk_put(i2s->clk);
		iounmap(i2s->addr);
		return -ENOENT;
	}
#else
	i2s->clk = clk_get(&i2s->pdev->dev, "gate_aud_mi2s");
	if (IS_ERR(i2s->clk)) {
		dev_err(&i2s->pdev->dev, "failed to get gate_aud_mi2s clock\n");
		iounmap(i2s->addr);
		return -ENOENT;
	}

	i2s->opclk1 = clk_get(&i2s->pdev->dev, "gate_aud_sclk_mi2s");
	if (IS_ERR(i2s->opclk1) &&
		!(i2s->opclk1 == ERR_PTR(-ENOENT))) {
		dev_err(&i2s->pdev->dev, "failed to get i2s_opclk1\n");
		clk_put(i2s->clk);
		iounmap(i2s->addr);
		return -ENOENT;
	}

	i2s->opclk0 = clk_get(&i2s->pdev->dev, "gate_aud_lpass");
	if (IS_ERR(i2s->opclk0) &&
		!(i2s->opclk0 == ERR_PTR(-ENOENT))) {
		dev_err(&i2s->pdev->dev, "failed to get i2s_opclk0\n");
		clk_put(i2s->opclk1);
		clk_put(i2s->clk);
		iounmap(i2s->addr);
		return -ENOENT;
	}
#endif


	if (other) {
		other->addr = i2s->addr;
		other->clk = i2s->clk;
		other->opclk0 = i2s->opclk0;
		other->opclk1 = i2s->opclk1;
#ifdef CONFIG_SND_SAMSUNG_COMPR
		if (compr) {
			compr->addr = i2s->addr;
			compr->clk = i2s->clk;
			compr->opclk0 = i2s->opclk0;
			compr->opclk1 = i2s->opclk1;
		}
#endif
	}

#ifdef CONFIG_SND_SAMSUNG_IDMA
	if (i2s->quirks & QUIRK_IDMA)
		idma_reg_addr_init(i2s->addr,
					i2s->sec_dai->idma_playback.dma_addr);
#endif
	if (i2s->amixer)
		eax_dai_register(dai, &samsung_i2s_dai_ops,
					i2s_suspend_force, i2s_resume_force);

probe_exit:
	clk_prepare_enable(i2s->opclk0);
	clk_prepare_enable(i2s->opclk1);
	clk_prepare_enable(i2s->clk);

	/* Initialize bit slice as I2S HW version */
	i2s_init_bit_slice(i2s);

	if (i2s->quirks & QUIRK_NEED_RSTCLR)
		writel(CON_RSTCLR, i2s->addr + I2SCON);

	/* Reset any constraint on RFS and BFS */
	i2s->rfs = 0;
	i2s->bfs = 0;
	i2s_txctrl(i2s, 0);
	i2s_rxctrl(i2s, 0);
	i2s_fifo(i2s, FIC_TXFLUSH);
	i2s_fifo(other, FIC_TXFLUSH);
	i2s_fifo(i2s, FIC_RXFLUSH);

	/* Gate CDCLK by default */
	if (!is_opened(other))
		i2s_set_sysclk(dai, SAMSUNG_I2S_CDCLK,
				0, SND_SOC_CLOCK_IN);

	clk_disable_unprepare(i2s->clk);
	clk_disable_unprepare(i2s->opclk0);
	clk_disable_unprepare(i2s->opclk1);
	return 0;
}

static int samsung_i2s_dai_remove(struct snd_soc_dai *dai)
{
	struct i2s_dai *i2s = snd_soc_dai_get_drvdata(dai);
	struct i2s_dai *other = i2s->pri_dai ? : i2s->sec_dai;

	if (!other || !other->clk) {

		if (i2s->quirks & QUIRK_NEED_RSTCLR)
			writel(0, i2s->addr + I2SCON);

		clk_put(i2s->clk);
		clk_put(i2s->opclk0);
		clk_put(i2s->opclk1);

		iounmap(i2s->addr);
	}

	i2s->clk = NULL;

	if (i2s->amixer)
		eax_dai_unregister();

	return 0;
}

static const struct snd_soc_dai_ops samsung_i2s_dai_ops = {
	.trigger = i2s_trigger,
	.hw_params = i2s_hw_params,
	.set_fmt = i2s_set_fmt,
	.set_clkdiv = i2s_set_clkdiv,
	.set_sysclk = i2s_set_sysclk,
#ifdef CONFIG_SND_SOC_I2S_1840_TDM
	.set_tdm_slot = i2s_set_tdm_slot,
#endif
	.startup = i2s_startup,
	.shutdown = i2s_shutdown,
	.delay = i2s_delay,
};

static const struct snd_soc_component_driver samsung_i2s_component = {
	.name		= "samsung-i2s",
};

#define SAMSUNG_I2S_RATES	SNDRV_PCM_RATE_8000_192000

#define SAMSUNG_I2S_FMTS	(SNDRV_PCM_FMTBIT_S8 | \
					SNDRV_PCM_FMTBIT_S16_LE | \
					SNDRV_PCM_FMTBIT_S24_LE)

static struct i2s_dai *i2s_alloc_dai(struct platform_device *pdev,
				     enum samsung_dai_type type, u32 quirks)
{
	struct i2s_dai *i2s;
	int ret;

	i2s = devm_kzalloc(&pdev->dev, sizeof(struct i2s_dai), GFP_KERNEL);
	if (i2s == NULL)
		return NULL;

	i2s->pdev = pdev;
	i2s->quirks = quirks;
	i2s->pri_dai = NULL;
	i2s->sec_dai = NULL;
	i2s->i2s_dai_drv.symmetric_rates = 1;
	i2s->i2s_dai_drv.probe = samsung_i2s_dai_probe;
	i2s->i2s_dai_drv.remove = samsung_i2s_dai_remove;
	i2s->i2s_dai_drv.ops = &samsung_i2s_dai_ops;
	i2s->i2s_dai_drv.suspend = i2s_suspend;
	i2s->i2s_dai_drv.resume = i2s_resume;
	i2s->i2s_dai_drv.playback.channels_min = 2;
	i2s->i2s_dai_drv.playback.channels_max = CONFIG_SND_SOC_I2S_TXSLOT_NUMBER;
	i2s->i2s_dai_drv.playback.rates = SAMSUNG_I2S_RATES;
	i2s->i2s_dai_drv.playback.formats = SAMSUNG_I2S_FMTS;

	if (type == TYPE_PRI) {
		i2s->i2s_dai_drv.capture.channels_min = 1;
		i2s->i2s_dai_drv.capture.channels_max = CONFIG_SND_SOC_I2S_RXSLOT_NUMBER;
		i2s->i2s_dai_drv.capture.rates = SAMSUNG_I2S_RATES;
		i2s->i2s_dai_drv.capture.formats = SAMSUNG_I2S_FMTS;
		dev_set_drvdata(&i2s->pdev->dev, i2s);
	} else if (type == TYPE_SEC) {
		/* Create a new platform_device for Secondary */
		i2s->pdev = platform_device_alloc("samsung-i2s-sec", -1);
		if (IS_ERR(i2s->pdev))
			return NULL;

		platform_set_drvdata(i2s->pdev, i2s);
		ret = platform_device_add(i2s->pdev);
		if (ret < 0)
			return NULL;
	} else if (type == TYPE_COMPR) {
		/* Create a new platform_device for Secondary */
		i2s->pdev = platform_device_alloc("samsung-i2s-compr", -1);
		if (IS_ERR(i2s->pdev))
			return NULL;

		platform_set_drvdata(i2s->pdev, i2s);
		ret = platform_device_add(i2s->pdev);
		if (ret < 0)
			return NULL;
	}


	return i2s;
}

static const struct of_device_id exynos_i2s_match[];

static inline int samsung_i2s_get_driver_data(struct platform_device *pdev)
{
#ifdef CONFIG_OF
	struct samsung_i2s_dai_data *data;
	if (pdev->dev.of_node) {
		const struct of_device_id *match;
		match = of_match_node(exynos_i2s_match, pdev->dev.of_node);
		data = (struct samsung_i2s_dai_data *) match->data;
		return data->dai_type;
	} else
#endif
		return platform_get_device_id(pdev)->driver_data;
}

#ifdef CONFIG_PM_RUNTIME
static int i2s_runtime_suspend(struct device *dev)
{
	struct i2s_dai *i2s = dev_get_drvdata(dev);

	pr_debug("%s entered\n", __func__);

	i2s_cfg_gpio(i2s, "idle");
	i2s_reg_save(i2s);
	clk_disable_unprepare(i2s->clk);
	clk_disable_unprepare(i2s->opclk0);
	clk_disable_unprepare(i2s->opclk1);
	lpass_put_sync(dev);

	return 0;
}

static int i2s_runtime_resume(struct device *dev)
{
	struct i2s_dai *i2s = dev_get_drvdata(dev);

	pr_debug("%s entered\n", __func__);

	lpass_get_sync(dev);
	clk_prepare_enable(i2s->opclk0);
	clk_prepare_enable(i2s->opclk1);
	clk_prepare_enable(i2s->clk);
	i2s_reg_restore(i2s);
	i2s_cfg_gpio(i2s, "default");

	return 0;
}
#else
static int i2s_disable(struct device *dev)
{
	struct i2s_dai *i2s = dev_get_drvdata(dev);

	spin_lock(&lock);
	i2s->enable_cnt--;
	if (i2s->enable_cnt) {
		spin_unlock(&lock);
		return 1;
	}
	spin_unlock(&lock);

	i2s_cfg_gpio(i2s, "idle");
	i2s_reg_save(i2s);
	clk_disable_unprepare(i2s->clk);
	clk_disable_unprepare(i2s->opclk0);
	clk_disable_unprepare(i2s->opclk1);
	lpass_put_sync(dev);

	return 0;
}

static int i2s_enable(struct device *dev)
{
	struct i2s_dai *i2s = dev_get_drvdata(dev);

	spin_lock(&lock);
	i2s->enable_cnt++;
	if (i2s->enable_cnt > 1) {
		spin_unlock(&lock);
		return 1;
	}
	spin_unlock(&lock);

	lpass_get_sync(dev);
	clk_prepare_enable(i2s->opclk0);
	clk_prepare_enable(i2s->opclk1);
	clk_prepare_enable(i2s->clk);
	i2s_reg_restore(i2s);
	i2s_cfg_gpio(i2s, "default");

	return 0;
}
#endif /* CONFIG_PM_RUNTIME */

static int samsung_i2s_probe(struct platform_device *pdev)
{
	struct i2s_dai *pri_dai, *sec_dai = NULL;
#ifdef CONFIG_SND_SAMSUNG_COMPR
	struct i2s_dai *compr_dai = NULL;
#endif
	struct s3c_audio_pdata *i2s_pdata = pdev->dev.platform_data;
	struct samsung_i2s *i2s_cfg = NULL;
	struct resource *res;
	u32 regs_base, quirks = 0;
	u32 amixer = 0;
	int slotnum;
#ifdef CONFIG_SND_SAMSUNG_IDMA
	u32 idma_addr;
#endif
	struct device_node *np = pdev->dev.of_node;
	struct pinctrl *pinctrl;
	enum samsung_dai_type samsung_dai_type;
	int ret = 0;

	/* Call during Seconday interface registration */
	samsung_dai_type = samsung_i2s_get_driver_data(pdev);

	if (samsung_dai_type != TYPE_PRI) {
		struct i2s_dai *cpu_dai = NULL;
		cpu_dai = dev_get_drvdata(&pdev->dev);
		if (!cpu_dai) {
			dev_err(&pdev->dev, "Unable to get drvdata\n");
			return -EFAULT;
		}

		if (samsung_dai_type == TYPE_SEC) {
#ifdef CONFIG_SND_SOC_EAX_SLOWPATH
			lpass_register_subip(&pdev->dev, "i2s-sec");
#endif
			snd_soc_register_component(&cpu_dai->pdev->dev,
					&samsung_i2s_component,
					&cpu_dai->i2s_dai_drv, 1);
#ifdef CONFIG_SND_SAMSUNG_FAKEDMA
			asoc_fdma_platform_register(&pdev->dev, &cpu_ops);
#else
			asoc_dma_platform_register(&pdev->dev);
#endif
#ifdef CONFIG_SND_SAMSUNG_COMPR
		} else if (samsung_dai_type == TYPE_COMPR) {
			cpu_dai->i2s_dai_drv.compress_dai = 1;
			snd_soc_register_component(&cpu_dai->pdev->dev,
					&samsung_i2s_component,
					&cpu_dai->i2s_dai_drv, 1);
			asoc_compr_platform_register(&pdev->dev);
#endif
		}
		return 0;
	}

	pri_dai = i2s_alloc_dai(pdev, TYPE_PRI, quirks);
	if (!pri_dai) {
		dev_err(&pdev->dev, "Unable to alloc I2S_pri\n");
		return -ENOMEM;
	}

	if (!np) {
		if (i2s_pdata == NULL) {
			dev_err(&pdev->dev, "Can't work without s3c_audio_pdata\n");
			return -EINVAL;
		}

		pri_dai->dma_playback.slave = i2s_pdata->dma_playback;
		pri_dai->dma_capture.slave = i2s_pdata->dma_capture;

		if (&i2s_pdata->type)
			i2s_cfg = &i2s_pdata->type.i2s;

		if (i2s_cfg) {
			quirks = i2s_cfg->quirks;
#ifdef CONFIG_SND_SAMSUNG_IDMA
			idma_addr = i2s_cfg->idma_addr;
#endif
		}
	} else {
		if (of_find_property(np, "samsung,supports-6ch", NULL))
			quirks |= QUIRK_PRI_6CHAN;

		if (of_find_property(np, "samsung,supports-secdai", NULL))
			quirks |= QUIRK_SEC_DAI;

		if (of_find_property(np, "samsung,supports-rstclr", NULL))
			quirks |= QUIRK_NEED_RSTCLR;

		if (of_find_property(np, "samsung,supports-tdm", NULL)) {
			quirks |= QUIRK_SUPPORTS_TDM;
			of_property_read_u32(np, "samsung,tdm-slotnum", &slotnum);
			if (!slotnum)
				pri_dai->slotnum = I2S_DEFAULT_SLOT_NUM;
			dev_info(&pdev->dev, "TDM mode was applied : %d\n",
				slotnum);
		}

		if (of_find_property(np, "samsung,supports-low-rfs", NULL))
			quirks |= QUIRK_SUPPORTS_LOW_RFS;
#ifdef CONFIG_SND_SAMSUNG_IDMA
		if (of_find_property(np, "samsung,supports-idma", NULL)) {
			quirks |= QUIRK_IDMA;

			if (of_property_read_u32(np, "samsung,idma-addr",
						 &idma_addr)) {
				if (quirks & QUIRK_SEC_DAI) {
					dev_err(&pdev->dev, "idma address is not"\
							"specified");
					return -EINVAL;
				}
			}
		}
#endif
		if (of_find_property(np, "samsung,supports-esa-dma", NULL))
			quirks |= QUIRK_ESA_DMA;

		if (of_find_property(np, "samsung,supports-sec-compr", NULL))
			quirks |= QUIRK_SEC_DAI_COMPR;

#ifdef CONFIG_SND_SOC_EAX_SLOWPATH
		amixer = 2;
#else
		if (of_property_read_u32(np, "samsung,amixer", &amixer))
			amixer = 0;
#endif

		if (of_find_property(np, "samsung,lpass-subip", NULL))
			lpass_register_subip(&pdev->dev, "i2s");
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Unable to get I2S SFR address\n");
		return -ENXIO;
	}

	if (!request_mem_region(res->start, resource_size(res),
							"samsung-i2s")) {
		dev_err(&pdev->dev, "Unable to request SFR region\n");
		return -EBUSY;
	}
	regs_base = res->start;

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get irq resource\n");
		return -ENXIO;
	}
	pri_dai->irq = res->start;

	pri_dai->dma_playback.dma_addr = regs_base + I2STXD;
	pri_dai->dma_capture.dma_addr = regs_base + I2SRXD;
	pri_dai->dma_playback.client =
		(struct s3c2410_dma_client *)&pri_dai->dma_playback;
	pri_dai->dma_playback.ch_name = "tx";
	pri_dai->dma_capture.client =
		(struct s3c2410_dma_client *)&pri_dai->dma_capture;
	pri_dai->dma_capture.ch_name = "rx";
	pri_dai->dma_playback.dma_size = 4;
	pri_dai->dma_capture.dma_size = 4;
	pri_dai->base = regs_base;
	pri_dai->quirks = quirks;
	pri_dai->amixer = amixer;
	pri_dai->slotnum = slotnum;

	if (quirks & QUIRK_PRI_6CHAN)
		pri_dai->i2s_dai_drv.playback.channels_max = 6;

	if (quirks & QUIRK_ESA_DMA) {
		pri_dai->dma_playback.esa_dma = true;
		pri_dai->dma_capture.esa_dma = true;
	}

	if (quirks & QUIRK_SEC_DAI) {
		sec_dai = i2s_alloc_dai(pdev, TYPE_SEC, quirks);
		if (!sec_dai) {
			dev_err(&pdev->dev, "Unable to alloc I2S_sec\n");
			ret = -ENOMEM;
			goto err;
		}
		sec_dai->dma_playback.dma_addr = regs_base + I2STXDS;
		sec_dai->dma_playback.client =
			(struct s3c2410_dma_client *)&sec_dai->dma_playback;
		sec_dai->dma_playback.ch_name = "tx-sec";

		if (!np)
			sec_dai->dma_playback.slave = i2s_pdata->dma_play_sec;

		sec_dai->slotnum = pri_dai->slotnum;
		sec_dai->dma_playback.dma_size = 4;
		sec_dai->dma_playback.sec_dma_dev = &sec_dai->pdev->dev;
		sec_dai->base = regs_base;
		sec_dai->quirks = quirks;
#ifdef CONFIG_SND_SAMSUNG_IDMA
		sec_dai->idma_playback.dma_addr = idma_addr;
#endif
		if (quirks & QUIRK_ESA_DMA)
			sec_dai->dma_playback.esa_dma = true;

		sec_dai->pri_dai = pri_dai;
		pri_dai->sec_dai = sec_dai;

#ifdef CONFIG_SND_SOC_EAX_SLOWPATH
		eax_slowpath_dev_register(&sec_dai->pdev->dev, "i2s-sec",
			     &sec_dai->dma_playback, 2);
#endif

		if (np)
			sec_dai->pdev->dev.of_node = of_get_child_by_name(np, "i2s-sec");
#ifdef CONFIG_SND_SAMSUNG_COMPR
		/* Register Compress CPU DAI */
		compr_dai = i2s_alloc_dai(pdev, TYPE_COMPR, quirks);
		if (!compr_dai) {
			dev_err(&pdev->dev, "Unable to alloc I2S_compr\n");
			ret = -ENOMEM;
			goto err;
		}
		compr_dai->slotnum = pri_dai->slotnum;
		compr_dai->dma_playback.dma_addr = regs_base + I2STXDS;
		compr_dai->dma_playback.client =
			(struct s3c2410_dma_client *)&compr_dai->dma_playback;
		compr_dai->dma_playback.ch_name = "tx-sec";
		compr_dai->dma_playback.dma_size = 4;
		compr_dai->base = regs_base;
		compr_dai->quirks = quirks;
		compr_dai->dma_playback.esa_dma = true;
		compr_dai->dma_playback.compr_dma = true;
		compr_dai->dma_playback.sec_dma_dev = &sec_dai->pdev->dev;
		pr_info("Compress dai : sec_dai = %s\n",
				dev_name(&sec_dai->pdev->dev));

		compr_dai->pri_dai = pri_dai;
		compr_dai->sec_dai = sec_dai;
		compr_dai->is_compress = true;
		pri_dai->compr_dai = compr_dai;
		sec_dai->compr_dai = compr_dai;

		if (np)
			compr_dai->pdev->dev.of_node = of_get_child_by_name(np, "i2s-compr");
#endif
	}

	if (!np) {
		if (i2s_pdata->cfg_gpio && i2s_pdata->cfg_gpio(pdev)) {
			dev_err(&pdev->dev, "Unable to configure gpio\n");
			ret = -EINVAL;
			goto err;
		}
	} else {
		pinctrl = devm_pinctrl_get(&pdev->dev);
		if (IS_ERR(pinctrl)) {
			dev_warn(&pdev->dev, "did not get pins for i2s: %li\n",
				PTR_ERR(pinctrl));
		} else {
			pri_dai->pinctrl = pinctrl;
			if (quirks & QUIRK_SEC_DAI) {
				sec_dai->pinctrl = pinctrl;
#ifdef CONFIG_SND_SAMSUNG_COMPR
				compr_dai->pinctrl = pinctrl;
#endif
			}
		}
	}
	i2s_cfg_gpio(pri_dai, "idle");

	snd_soc_register_component(&pri_dai->pdev->dev, &samsung_i2s_component,
				   &pri_dai->i2s_dai_drv, 1);

	if (pri_dai->amixer)
		eax_dev_register(&pri_dai->pdev->dev, "i2s",
			     &pri_dai->dma_playback, pri_dai->amixer);

	pm_runtime_enable(&pdev->dev);

#ifdef CONFIG_SND_SAMSUNG_FAKEDMA
	asoc_fdma_platform_register(&pdev->dev, &cpu_ops);
#else
	asoc_dma_platform_register(&pdev->dev);
#endif
#ifdef CONFIG_SND_SAMSUNG_IDMA
	if (quirks & QUIRK_IDMA)
		asoc_idma_platform_register(&pdev->dev);
#endif
	return 0;
err:
	release_mem_region(regs_base, resource_size(res));

	return ret;
}

static int samsung_i2s_remove(struct platform_device *pdev)
{
	struct i2s_dai *i2s, *other;
	struct resource *res;

	i2s = dev_get_drvdata(&pdev->dev);
	other = i2s->pri_dai ? : i2s->sec_dai;

	if (other) {
		other->pri_dai = NULL;
		other->sec_dai = NULL;
	} else {
		pm_runtime_disable(&pdev->dev);
		res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
		if (res)
			release_mem_region(res->start, resource_size(res));
	}

	i2s->pri_dai = NULL;
	i2s->sec_dai = NULL;

#ifdef CONFIG_SND_SAMSUNG_FAKEDMA
	asoc_fdma_platform_unregister(&pdev->dev);
#else
	asoc_dma_platform_unregister(&pdev->dev);
#endif
	snd_soc_unregister_component(&pdev->dev);

	return 0;
}

static struct platform_device_id samsung_i2s_driver_ids[] = {
	{
		.name           = "samsung-i2s",
		.driver_data	= TYPE_PRI,
	}, {
		.name           = "samsung-i2s-sec",
		.driver_data	= TYPE_SEC,
	}, {
		.name           = "samsung-i2s-compr",
		.driver_data	= TYPE_COMPR,
	},
	{},
};
MODULE_DEVICE_TABLE(platform, samsung_i2s_driver_ids);

#ifdef CONFIG_OF
static struct samsung_i2s_dai_data samsung_i2s_dai_data_array[] = {
	[TYPE_PRI] = { TYPE_PRI },
	[TYPE_SEC] = { TYPE_SEC },
	[TYPE_COMPR] = { TYPE_COMPR },
};

static const struct of_device_id exynos_i2s_match[] = {
	{ .compatible = "samsung,i2s-v5",
	  .data = &samsung_i2s_dai_data_array[TYPE_PRI],
	},
	{},
};
MODULE_DEVICE_TABLE(of, exynos_i2s_match);
#endif

static const struct dev_pm_ops samsung_i2s_pm = {
	SET_RUNTIME_PM_OPS(i2s_runtime_suspend,
				i2s_runtime_resume, NULL)
};

static struct platform_driver samsung_i2s_driver = {
	.probe  = samsung_i2s_probe,
	.remove = samsung_i2s_remove,
	.id_table = samsung_i2s_driver_ids,
	.driver = {
		.name = "samsung-i2s",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(exynos_i2s_match),
		.pm = &samsung_i2s_pm,
	},
};

module_platform_driver(samsung_i2s_driver);

/* Module information */
MODULE_AUTHOR("Jaswinder Singh, <jassisinghbrar@gmail.com>");
MODULE_DESCRIPTION("Samsung I2S Interface");
MODULE_ALIAS("platform:samsung-i2s");
MODULE_LICENSE("GPL");

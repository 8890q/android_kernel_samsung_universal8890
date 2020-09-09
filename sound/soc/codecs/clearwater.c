/*
 * clearwater.c  --  ALSA SoC Audio driver for CLEARWATER-class devices
 *
 * Copyright 2014 Cirrus Logic
 *
 * Author: Nariman Poushin <nariman@opensource.wolfsonmicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/jack.h>
#include <sound/initval.h>
#include <sound/tlv.h>

#include <linux/mfd/arizona/core.h>
#include <linux/mfd/arizona/registers.h>

#include "arizona.h"
#include "wm_adsp.h"
#include "clearwater.h"

#define CLEARWATER_NUM_ADSP 7

/* Number of compressed DAI hookups, each pair of DSP and dummy CPU
 * are counted as one DAI
 */
#define CLEARWATER_NUM_COMPR_DAI 2

#define CLEARWATER_FRF_COEFFICIENT_LEN 4

static int clearwater_frf_bytes_put(struct snd_kcontrol *kcontrol,
		      struct snd_ctl_elem_value *ucontrol);

#define CLEARWATER_FRF_BYTES(xname, xbase, xregs)			\
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname,	\
	.info = snd_soc_bytes_info, .get = snd_soc_bytes_get,	\
	.put = clearwater_frf_bytes_put, .private_value =		\
	((unsigned long)&(struct soc_bytes)			\
		{.base = xbase, .num_regs = xregs }) }

/* 2 mixer inputs with a stride of n in the register address */
#define CLEARWATER_MIXER_INPUTS_2_N(_reg, n)	\
	(_reg),					\
	(_reg) + (1 * (n))

/* 4 mixer inputs with a stride of n in the register address */
#define CLEARWATER_MIXER_INPUTS_4_N(_reg, n)		\
	CLEARWATER_MIXER_INPUTS_2_N(_reg, n),		\
	CLEARWATER_MIXER_INPUTS_2_N(_reg + (2 * n), n)

#define CLEARWATER_DSP_MIXER_INPUTS(_reg) \
	CLEARWATER_MIXER_INPUTS_4_N(_reg, 2),		\
	CLEARWATER_MIXER_INPUTS_4_N(_reg + 8, 2),	\
	CLEARWATER_MIXER_INPUTS_4_N(_reg + 16, 8),	\
	CLEARWATER_MIXER_INPUTS_2_N(_reg + 48, 8)

static const int clearwater_fx_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_EQ1MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_EQ2MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_EQ3MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_EQ4MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_DRC1LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_DRC1RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_DRC2LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_DRC2RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_HPLP1MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_HPLP2MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_HPLP3MIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_HPLP4MIX_INPUT_1_SOURCE, 2),
};

static const int clearwater_asrc1_1_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(CLEARWATER_ASRC1_1LMIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_asrc1_2_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(CLEARWATER_ASRC1_2LMIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_asrc2_1_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(CLEARWATER_ASRC2_1LMIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_asrc2_2_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(CLEARWATER_ASRC2_2LMIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc1_fsl_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_ISRC1INT1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc1_fsh_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_ISRC1DEC1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc2_fsl_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_ISRC2INT1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc2_fsh_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_ISRC2DEC1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc3_fsl_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(ARIZONA_ISRC3INT1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc3_fsh_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(ARIZONA_ISRC3DEC1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc4_fsl_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(ARIZONA_ISRC4INT1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_isrc4_fsh_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(ARIZONA_ISRC4DEC1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_out_inputs[] = {
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT1LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT1RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT2LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT2RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT3LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT3RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT4LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT4RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT5LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT5RMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT6LMIX_INPUT_1_SOURCE, 2),
	CLEARWATER_MIXER_INPUTS_4_N(ARIZONA_OUT6RMIX_INPUT_1_SOURCE, 2),
};

static const int clearwater_spd1_inputs[] = {
	CLEARWATER_MIXER_INPUTS_2_N(ARIZONA_SPDIFTX1MIX_INPUT_1_SOURCE, 8),
};

static const int clearwater_dsp1_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(ARIZONA_DSP1LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp2_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(ARIZONA_DSP2LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp3_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(ARIZONA_DSP3LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp4_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(ARIZONA_DSP4LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp5_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(CLEARWATER_DSP5LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp6_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(CLEARWATER_DSP6LMIX_INPUT_1_SOURCE),
};

static const int clearwater_dsp7_inputs[] = {
	CLEARWATER_DSP_MIXER_INPUTS(CLEARWATER_DSP7LMIX_INPUT_1_SOURCE),
};

static int clearwater_rate_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);

#define CLEARWATER_RATE_ENUM(xname, xenum) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname,\
	.info = snd_soc_info_enum_double, \
	.get = snd_soc_get_enum_double, .put = clearwater_rate_put, \
	.private_value = (unsigned long)&xenum }

struct clearwater_priv;

struct clearwater_compr {
	struct wm_adsp_compr adsp_compr;
	const char *dai_name;
	bool trig;
	struct mutex trig_lock;
	struct clearwater_priv *priv;
};

struct clearwater_priv {
	struct arizona_priv core;
	struct arizona_fll fll[3];
	struct clearwater_compr compr_info[CLEARWATER_NUM_COMPR_DAI];

	struct mutex fw_lock;
};

static const struct {
	const char *dai_name;
	int adsp_num;
} compr_dai_mapping[CLEARWATER_NUM_COMPR_DAI] = {
	{
		.dai_name = "clearwater-dsp-voicectrl",
		.adsp_num = 5,
	},
	{
		.dai_name = "clearwater-dsp-trace",
		.adsp_num = 0,
	},
};

static const struct wm_adsp_region clearwater_dsp1_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x080000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x0e0000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x0a0000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x0c0000 },
};

static const struct wm_adsp_region clearwater_dsp2_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x100000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x160000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x120000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x140000 },
};

static const struct wm_adsp_region clearwater_dsp3_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x180000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x1e0000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x1a0000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x1c0000 },
};

static const struct wm_adsp_region clearwater_dsp4_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x200000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x260000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x220000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x240000 },
};

static const struct wm_adsp_region clearwater_dsp5_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x280000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x2e0000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x2a0000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x2c0000 },
};

static const struct wm_adsp_region clearwater_dsp6_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x300000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x360000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x320000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x340000 },
};

static const struct wm_adsp_region clearwater_dsp7_regions[] = {
	{ .type = WMFW_ADSP2_PM, .base = 0x380000 },
	{ .type = WMFW_ADSP2_ZM, .base = 0x3e0000 },
	{ .type = WMFW_ADSP2_XM, .base = 0x3a0000 },
	{ .type = WMFW_ADSP2_YM, .base = 0x3c0000 },
};

static const struct wm_adsp_region *clearwater_dsp_regions[] = {
	clearwater_dsp1_regions,
	clearwater_dsp2_regions,
	clearwater_dsp3_regions,
	clearwater_dsp4_regions,
	clearwater_dsp5_regions,
	clearwater_dsp6_regions,
	clearwater_dsp7_regions,
};

static const int wm_adsp2_control_bases[] = {
	CLEARWATER_DSP1_CONFIG,
	CLEARWATER_DSP2_CONFIG,
	CLEARWATER_DSP3_CONFIG,
	CLEARWATER_DSP4_CONFIG,
	CLEARWATER_DSP5_CONFIG,
	CLEARWATER_DSP6_CONFIG,
	CLEARWATER_DSP7_CONFIG,
};

static const char * const clearwater_inmux_texts[] = {
	"A",
	"B",
};

static SOC_ENUM_SINGLE_DECL(clearwater_in1mux_enum,
			    ARIZONA_ADC_DIGITAL_VOLUME_1L,
			    ARIZONA_IN1L_SRC_SHIFT,
			    clearwater_inmux_texts);

static SOC_ENUM_SINGLE_DECL(clearwater_in2muxl_enum,
			    ARIZONA_ADC_DIGITAL_VOLUME_2L,
			    ARIZONA_IN2L_SRC_SHIFT,
			    clearwater_inmux_texts);
static SOC_ENUM_SINGLE_DECL(clearwater_in2muxr_enum,
			    ARIZONA_ADC_DIGITAL_VOLUME_2R,
			    ARIZONA_IN2R_SRC_SHIFT,
			    clearwater_inmux_texts);

static const struct snd_kcontrol_new clearwater_in1mux =
	SOC_DAPM_ENUM("IN1L Mux", clearwater_in1mux_enum);

static const struct snd_kcontrol_new clearwater_in2mux[2] = {
	SOC_DAPM_ENUM("IN2L Mux", clearwater_in2muxl_enum),
	SOC_DAPM_ENUM("IN2R Mux", clearwater_in2muxr_enum),
};

static int clearwater_frf_bytes_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct soc_bytes *params = (void *)kcontrol->private_value;
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct arizona_priv *priv = snd_soc_codec_get_drvdata(codec);
	struct arizona *arizona = priv->arizona;
	int ret, len;
	void *data;

	len = params->num_regs * component->val_bytes;

	data = kmemdup(ucontrol->value.bytes.data, len, GFP_KERNEL | GFP_DMA);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	mutex_lock(&arizona->reg_setting_lock);
	regmap_write(arizona->regmap, 0x80, 0x3);

	ret = regmap_raw_write(component->regmap, params->base,
			       data, len);

	regmap_write(arizona->regmap, 0x80, 0x0);
	mutex_unlock(&arizona->reg_setting_lock);

out:
	kfree(data);
	return ret;
}

/* Allow the worst case number of sources (FX Rate currently) */
static unsigned int mixer_sources_cache[ARRAY_SIZE(clearwater_fx_inputs)];

static int clearwater_get_sources(unsigned int reg,
				  const int **cur_sources, int *lim)
{
	int ret = 0;

	switch (reg) {
	case ARIZONA_FX_CTRL1:
		*cur_sources = clearwater_fx_inputs;
		*lim = ARRAY_SIZE(clearwater_fx_inputs);
		break;
	case CLEARWATER_ASRC1_RATE1:
		*cur_sources = clearwater_asrc1_1_inputs;
		*lim = ARRAY_SIZE(clearwater_asrc1_1_inputs);
		break;
	case CLEARWATER_ASRC1_RATE2:
		*cur_sources = clearwater_asrc1_2_inputs;
		*lim = ARRAY_SIZE(clearwater_asrc1_2_inputs);
		break;
	case CLEARWATER_ASRC2_RATE1:
		*cur_sources = clearwater_asrc2_1_inputs;
		*lim = ARRAY_SIZE(clearwater_asrc2_1_inputs);
		break;
	case CLEARWATER_ASRC2_RATE2:
		*cur_sources = clearwater_asrc2_2_inputs;
		*lim = ARRAY_SIZE(clearwater_asrc2_2_inputs);
		break;
	case ARIZONA_ISRC_1_CTRL_1:
		*cur_sources = clearwater_isrc1_fsh_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc1_fsh_inputs);
		break;
	case ARIZONA_ISRC_1_CTRL_2:
		*cur_sources = clearwater_isrc1_fsl_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc1_fsl_inputs);
		break;
	case ARIZONA_ISRC_2_CTRL_1:
		*cur_sources = clearwater_isrc2_fsh_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc2_fsh_inputs);
		break;
	case ARIZONA_ISRC_2_CTRL_2:
		*cur_sources = clearwater_isrc2_fsl_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc2_fsl_inputs);
		break;
	case ARIZONA_ISRC_3_CTRL_1:
		*cur_sources = clearwater_isrc3_fsh_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc3_fsh_inputs);
		break;
	case ARIZONA_ISRC_3_CTRL_2:
		*cur_sources = clearwater_isrc3_fsl_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc3_fsl_inputs);
		break;
	case ARIZONA_ISRC_4_CTRL_1:
		*cur_sources = clearwater_isrc4_fsh_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc4_fsh_inputs);
		break;
	case ARIZONA_ISRC_4_CTRL_2:
		*cur_sources = clearwater_isrc4_fsl_inputs;
		*lim = ARRAY_SIZE(clearwater_isrc4_fsl_inputs);
		break;
	case ARIZONA_OUTPUT_RATE_1:
		*cur_sources = clearwater_out_inputs;
		*lim = ARRAY_SIZE(clearwater_out_inputs);
		break;
	case ARIZONA_SPD1_TX_CONTROL:
		*cur_sources = clearwater_spd1_inputs;
		*lim = ARRAY_SIZE(clearwater_spd1_inputs);
		break;
	case CLEARWATER_DSP1_CONFIG:
		*cur_sources = clearwater_dsp1_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp1_inputs);
		break;
	case CLEARWATER_DSP2_CONFIG:
		*cur_sources = clearwater_dsp2_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp2_inputs);
		break;
	case CLEARWATER_DSP3_CONFIG:
		*cur_sources = clearwater_dsp3_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp3_inputs);
		break;
	case CLEARWATER_DSP4_CONFIG:
		*cur_sources = clearwater_dsp4_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp4_inputs);
		break;
	case CLEARWATER_DSP5_CONFIG:
		*cur_sources = clearwater_dsp5_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp5_inputs);
		break;
	case CLEARWATER_DSP6_CONFIG:
		*cur_sources = clearwater_dsp6_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp6_inputs);
		break;
	case CLEARWATER_DSP7_CONFIG:
		*cur_sources = clearwater_dsp7_inputs;
		*lim = ARRAY_SIZE(clearwater_dsp7_inputs);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int clearwater_rate_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	int ret, err;
	int lim;
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct soc_enum *e = (struct soc_enum *)kcontrol->private_value;

	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(codec);
	struct arizona_priv *priv = &clearwater->core;
	struct arizona *arizona = priv->arizona;

	const int *cur_sources;

	unsigned int val, cur;
	unsigned int mask;

	if (ucontrol->value.enumerated.item[0] > e->items - 1)
		return -EINVAL;

	val = e->values[ucontrol->value.enumerated.item[0]] << e->shift_l;
	mask = e->mask << e->shift_l;

	ret = regmap_read(arizona->regmap, e->reg, &cur);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to read current reg: %d\n", ret);
		return ret;
	}

	if ((cur & mask) == (val & mask))
		return 0;

	ret = clearwater_get_sources((int)e->reg, &cur_sources, &lim);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to get sources for 0x%08x: %d\n",
			e->reg,
			ret);
		return ret;
	}

	mutex_lock(&arizona->rate_lock);

	ret = arizona_cache_and_clear_sources(arizona, cur_sources,
					      mixer_sources_cache, lim);
	if (ret != 0) {
		dev_err(arizona->dev,
			"%s Failed to cache and clear sources %d\n",
			__func__,
			ret);
		goto out;
	}

	/* Apply the rate through the original callback */
	clearwater_spin_sysclk(arizona);
	mutex_lock(&codec->mutex);
	ret = snd_soc_update_bits(codec, e->reg, mask, val);
	mutex_unlock(&codec->mutex);
	clearwater_spin_sysclk(arizona);

out:
	err = arizona_restore_sources(arizona, cur_sources,
				      mixer_sources_cache, lim);
	if (err != 0) {
		dev_err(arizona->dev,
			"%s Failed to restore sources %d\n",
			__func__,
			err);
	}

	mutex_unlock(&arizona->rate_lock);
	return ret;
}

static int clearwater_adsp_rate_put_cb(struct wm_adsp *adsp,
				       unsigned int mask,
				       unsigned int val)
{
	int ret, err;
	int lim;
	const int *cur_sources;
	struct arizona *arizona = dev_get_drvdata(adsp->dev);
	unsigned int cur;

	ret = regmap_read(adsp->regmap,  adsp->base, &cur);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to read current: %d\n", ret);
		return ret;
	}

	if ((val & mask) == (cur & mask))
		return 0;

	ret = clearwater_get_sources(adsp->base, &cur_sources, &lim);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to get sources for 0x%08x: %d\n",
			adsp->base,
			ret);
		return ret;
	}

	dev_dbg(arizona->dev, "%s for DSP%d\n", __func__, adsp->num);

	mutex_lock(&arizona->rate_lock);

	ret = arizona_cache_and_clear_sources(arizona, cur_sources,
					      mixer_sources_cache, lim);

	if (ret != 0) {
		dev_err(arizona->dev,
			"%s Failed to cache and clear sources %d\n",
			__func__,
			ret);
		goto out;
	}

	clearwater_spin_sysclk(arizona);
	/* Apply the rate */
	ret = regmap_update_bits(adsp->regmap, adsp->base, mask, val);
	clearwater_spin_sysclk(arizona);

out:
	err = arizona_restore_sources(arizona, cur_sources,
				      mixer_sources_cache, lim);

	if (err != 0) {
		dev_err(arizona->dev,
			"%s Failed to restore sources %d\n",
			__func__,
			err);
	}

	mutex_unlock(&arizona->rate_lock);
	return ret;
}

static int clearwater_sysclk_ev(struct snd_soc_dapm_widget *w,
		struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = w->codec;
	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(codec);
	struct arizona_priv *priv = &clearwater->core;
	struct arizona *arizona = priv->arizona;

	clearwater_spin_sysclk(arizona);

	return 0;
}

static int clearwater_dspclk_ev(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *kcontrol,
			int event)
{
	struct snd_soc_codec *codec = w->codec;
	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(codec);
	struct arizona_priv *priv = &clearwater->core;
	struct arizona *arizona = priv->arizona;

	switch (event) {
	case SND_SOC_DAPM_PRE_REG:
		mutex_lock(&arizona->dspclk_ena_lock);
		break;
	case SND_SOC_DAPM_POST_REG:
		mutex_unlock(&arizona->dspclk_ena_lock);
		break;
	}

	return 0;
}

static int clearwater_adsp_power_ev(struct snd_soc_dapm_widget *w,
				    struct snd_kcontrol *kcontrol,
				    int event)
{
	struct snd_soc_codec *codec = w->codec;
	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(codec);
	struct arizona_priv *priv = &clearwater->core;
	struct arizona *arizona = priv->arizona;
	unsigned int freq;
	int i, ret;

	ret = regmap_read(arizona->regmap, CLEARWATER_DSP_CLOCK_1, &freq);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to read CLEARWATER_DSP_CLOCK_1: %d\n", ret);
		return ret;
	}

	freq &= CLEARWATER_DSP_CLK_FREQ_LEGACY_MASK;
	freq >>= CLEARWATER_DSP_CLK_FREQ_LEGACY_SHIFT;

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		for (i = 0; i < ARRAY_SIZE(clearwater->compr_info); ++i) {
			if (clearwater->compr_info[i].adsp_compr.dsp->num !=
			    w->shift + 1)
				continue;

			mutex_lock(&clearwater->compr_info[i].trig_lock);
			clearwater->compr_info[i].trig = false;
			mutex_unlock(&clearwater->compr_info[i].trig_lock);
		}
		break;
	default:
		break;
	}

	return wm_adsp2_early_event(w, kcontrol, event, freq);
}

static DECLARE_TLV_DB_SCALE(ana_tlv, 0, 100, 0);
static DECLARE_TLV_DB_SCALE(eq_tlv, -1200, 100, 0);
static DECLARE_TLV_DB_SCALE(digital_tlv, -6400, 50, 0);
static DECLARE_TLV_DB_SCALE(noise_tlv, -13200, 600, 0);
static DECLARE_TLV_DB_SCALE(ng_tlv, -10200, 600, 0);

#define CLEARWATER_NG_SRC(name, base) \
	SOC_SINGLE(name " NG HPOUT1L Switch",  base,  0, 1, 0), \
	SOC_SINGLE(name " NG HPOUT1R Switch",  base,  1, 1, 0), \
	SOC_SINGLE(name " NG HPOUT2L Switch",  base,  2, 1, 0), \
	SOC_SINGLE(name " NG HPOUT2R Switch",  base,  3, 1, 0), \
	SOC_SINGLE(name " NG HPOUT3L Switch",  base,  4, 1, 0), \
	SOC_SINGLE(name " NG HPOUT3R Switch",  base,  5, 1, 0), \
	SOC_SINGLE(name " NG SPKOUTL Switch",  base,  6, 1, 0), \
	SOC_SINGLE(name " NG SPKOUTR Switch",  base,  7, 1, 0), \
	SOC_SINGLE(name " NG SPKDAT1L Switch", base,  8, 1, 0), \
	SOC_SINGLE(name " NG SPKDAT1R Switch", base,  9, 1, 0), \
	SOC_SINGLE(name " NG SPKDAT2L Switch", base, 10, 1, 0), \
	SOC_SINGLE(name " NG SPKDAT2R Switch", base, 11, 1, 0)

#define CLEARWATER_RXANC_INPUT_ROUTES(widget, name) \
	{ widget, NULL, name " NG Mux" }, \
	{ name " NG Internal", NULL, "RXANC NG Clock" }, \
	{ name " NG Internal", NULL, name " Channel" }, \
	{ name " NG External", NULL, "RXANC NG External Clock" }, \
	{ name " NG External", NULL, name " Channel" }, \
	{ name " NG Mux", "None", name " Channel" }, \
	{ name " NG Mux", "Internal", name " NG Internal" }, \
	{ name " NG Mux", "External", name " NG External" }, \
	{ name " Channel", "Left", name " Left Input" }, \
	{ name " Channel", "Combine", name " Left Input" }, \
	{ name " Channel", "Right", name " Right Input" }, \
	{ name " Channel", "Combine", name " Right Input" }, \
	{ name " Left Input", "IN1", "IN1L PGA" }, \
	{ name " Right Input", "IN1", "IN1R PGA" }, \
	{ name " Left Input", "IN2", "IN2L PGA" }, \
	{ name " Right Input", "IN2", "IN2R PGA" }, \
	{ name " Left Input", "IN3", "IN3L PGA" }, \
	{ name " Right Input", "IN3", "IN3R PGA" }, \
	{ name " Left Input", "IN4", "IN4L PGA" }, \
	{ name " Right Input", "IN4", "IN4R PGA" }, \
	{ name " Left Input", "IN5", "IN5L PGA" }, \
	{ name " Right Input", "IN5", "IN5R PGA" }, \
	{ name " Left Input", "IN6", "IN6L PGA" }, \
	{ name " Right Input", "IN6", "IN6R PGA" }

#define CLEARWATER_RXANC_OUTPUT_ROUTES(widget, name) \
	{ widget, NULL, name " ANC Source" }, \
	{ name " ANC Source", "RXANCL", "RXANCL" }, \
	{ name " ANC Source", "RXANCR", "RXANCR" }

static int clearwater_cp_mode_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct arizona_priv *priv = snd_soc_codec_get_drvdata(codec);
	struct arizona *arizona = priv->arizona;
	unsigned int val;

	regmap_read(arizona->regmap, CLEARWATER_CP_MODE, &val);
	if (val == 0x400)
		ucontrol->value.enumerated.item[0] = 0;
	else
		ucontrol->value.enumerated.item[0] = 1;

	return 0;
}

static int clearwater_cp_mode_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct arizona_priv *priv = snd_soc_codec_get_drvdata(codec);
	struct arizona *arizona = priv->arizona;
	struct soc_enum *e = (struct soc_enum *)kcontrol->private_value;
	unsigned int val = ucontrol->value.enumerated.item[0];

	if (val > e->items - 1)
		return -EINVAL;

	mutex_lock(&arizona->reg_setting_lock);
	if (val ==0) { /* Default */
		regmap_write(arizona->regmap, 0x80, 0x1);
		regmap_write(arizona->regmap, CLEARWATER_CP_MODE, 0x400);
		regmap_write(arizona->regmap, 0x80, 0x0);
	} else {/* Inverting */
		regmap_write(arizona->regmap, 0x80, 0x1);
		regmap_write(arizona->regmap, CLEARWATER_CP_MODE, 0x407);
		regmap_write(arizona->regmap, 0x80, 0x0);
	}
	mutex_unlock(&arizona->reg_setting_lock);

	return 0;
}

static const char * const clearwater_cp_mode_text[2] = {
	"Default", "Inverting",
};

static const struct soc_enum clearwater_cp_mode[] = {
	SOC_ENUM_SINGLE(0, 0, ARRAY_SIZE(clearwater_cp_mode_text),
		clearwater_cp_mode_text),
};

static const struct snd_kcontrol_new clearwater_snd_controls[] = {
SOC_ENUM("IN1 OSR", clearwater_in_dmic_osr[0]),
SOC_ENUM("IN2 OSR", clearwater_in_dmic_osr[1]),
SOC_ENUM("IN3 OSR", clearwater_in_dmic_osr[2]),
SOC_ENUM("IN4 OSR", clearwater_in_dmic_osr[3]),
SOC_ENUM("IN5 OSR", clearwater_in_dmic_osr[4]),
SOC_ENUM("IN6 OSR", clearwater_in_dmic_osr[5]),

SOC_SINGLE_RANGE_TLV("IN1L Volume", ARIZONA_IN1L_CONTROL,
		     ARIZONA_IN1L_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),
SOC_SINGLE_RANGE_TLV("IN1R Volume", ARIZONA_IN1R_CONTROL,
		     ARIZONA_IN1R_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),
SOC_SINGLE_RANGE_TLV("IN2L Volume", ARIZONA_IN2L_CONTROL,
		     ARIZONA_IN2L_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),
SOC_SINGLE_RANGE_TLV("IN2R Volume", ARIZONA_IN2R_CONTROL,
		     ARIZONA_IN2R_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),
SOC_SINGLE_RANGE_TLV("IN3L Volume", ARIZONA_IN3L_CONTROL,
		     ARIZONA_IN3L_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),
SOC_SINGLE_RANGE_TLV("IN3R Volume", ARIZONA_IN3R_CONTROL,
		     ARIZONA_IN3R_PGA_VOL_SHIFT, 0x40, 0x5f, 0, ana_tlv),

SOC_ENUM("IN HPF Cutoff Frequency", arizona_in_hpf_cut_enum),

SOC_SINGLE("IN1L HPF Switch", ARIZONA_IN1L_CONTROL,
	   ARIZONA_IN1L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN1R HPF Switch", ARIZONA_IN1R_CONTROL,
	   ARIZONA_IN1R_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN2L HPF Switch", ARIZONA_IN2L_CONTROL,
	   ARIZONA_IN2L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN2R HPF Switch", ARIZONA_IN2R_CONTROL,
	   ARIZONA_IN2R_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN3L HPF Switch", ARIZONA_IN3L_CONTROL,
	   ARIZONA_IN3L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN3R HPF Switch", ARIZONA_IN3R_CONTROL,
	   ARIZONA_IN3R_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN4L HPF Switch", ARIZONA_IN4L_CONTROL,
	   ARIZONA_IN4L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN4R HPF Switch", ARIZONA_IN4R_CONTROL,
	   ARIZONA_IN4R_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN5L HPF Switch", ARIZONA_IN5L_CONTROL,
	   ARIZONA_IN5L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN5R HPF Switch", ARIZONA_IN5R_CONTROL,
	   ARIZONA_IN5R_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN6L HPF Switch", ARIZONA_IN6L_CONTROL,
	   ARIZONA_IN6L_HPF_SHIFT, 1, 0),
SOC_SINGLE("IN6R HPF Switch", ARIZONA_IN6R_CONTROL,
	   ARIZONA_IN6R_HPF_SHIFT, 1, 0),

SOC_SINGLE_TLV("IN1L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_1L,
	       ARIZONA_IN1L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN1R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_1R,
	       ARIZONA_IN1R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN2L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_2L,
	       ARIZONA_IN2L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN2R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_2R,
	       ARIZONA_IN2R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN3L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_3L,
	       ARIZONA_IN3L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN3R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_3R,
	       ARIZONA_IN3R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN4L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_4L,
	       ARIZONA_IN4L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN4R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_4R,
	       ARIZONA_IN4R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN5L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_5L,
	       ARIZONA_IN5L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN5R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_5R,
	       ARIZONA_IN5R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN6L Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_6L,
	       ARIZONA_IN6L_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),
SOC_SINGLE_TLV("IN6R Digital Volume", ARIZONA_ADC_DIGITAL_VOLUME_6R,
	       ARIZONA_IN6R_DIG_VOL_SHIFT, 0xbf, 0, digital_tlv),

SOC_ENUM_EXT("IN1 Mode", arizona_ip_mode[0],
		snd_soc_get_enum_double, arizona_ip_mode_put),
SOC_ENUM_EXT("IN2 Mode", arizona_ip_mode[1],
		snd_soc_get_enum_double, arizona_ip_mode_put),
SOC_ENUM_EXT("IN3 Mode", arizona_ip_mode[2],
		snd_soc_get_enum_double, arizona_ip_mode_put),
SOC_ENUM_EXT("CP Mode", clearwater_cp_mode[0],
			clearwater_cp_mode_get, clearwater_cp_mode_put),

SOC_ENUM("Input Ramp Up", arizona_in_vi_ramp),
SOC_ENUM("Input Ramp Down", arizona_in_vd_ramp),

SND_SOC_BYTES("RXANC Coefficients", ARIZONA_ANC_COEFF_START,
	      ARIZONA_ANC_COEFF_END - ARIZONA_ANC_COEFF_START + 1),
SND_SOC_BYTES("RXANCL Config", ARIZONA_FCL_FILTER_CONTROL, 1),
SND_SOC_BYTES("RXANCL Coefficients", ARIZONA_FCL_COEFF_START,
	      ARIZONA_FCL_COEFF_END - ARIZONA_FCL_COEFF_START + 1),
SND_SOC_BYTES("RXANCR Config", CLEARWATER_FCR_FILTER_CONTROL, 1),
SND_SOC_BYTES("RXANCR Coefficients", CLEARWATER_FCR_COEFF_START,
	      CLEARWATER_FCR_COEFF_END - CLEARWATER_FCR_COEFF_START + 1),

CLEARWATER_FRF_BYTES("FRF COEFF 1L", CLEARWATER_FRF_COEFFICIENT_1L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 1R", CLEARWATER_FRF_COEFFICIENT_1R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 2L", CLEARWATER_FRF_COEFFICIENT_2L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 2R", CLEARWATER_FRF_COEFFICIENT_2R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 3L", CLEARWATER_FRF_COEFFICIENT_3L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 3R", CLEARWATER_FRF_COEFFICIENT_3R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 4L", CLEARWATER_FRF_COEFFICIENT_4L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 4R", CLEARWATER_FRF_COEFFICIENT_4R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 5L", CLEARWATER_FRF_COEFFICIENT_5L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 5R", CLEARWATER_FRF_COEFFICIENT_5R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 6L", CLEARWATER_FRF_COEFFICIENT_6L_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),
CLEARWATER_FRF_BYTES("FRF COEFF 6R", CLEARWATER_FRF_COEFFICIENT_6R_1,
				 CLEARWATER_FRF_COEFFICIENT_LEN),

SND_SOC_BYTES("DAC COMP 1", CLEARWATER_DAC_COMP_1, 1),
SND_SOC_BYTES("DAC COMP 2", CLEARWATER_DAC_COMP_2, 1),

ARIZONA_MIXER_CONTROLS("EQ1", ARIZONA_EQ1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("EQ2", ARIZONA_EQ2MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("EQ3", ARIZONA_EQ3MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("EQ4", ARIZONA_EQ4MIX_INPUT_1_SOURCE),

ARIZONA_EQ_CONTROL("EQ1 Coefficients", ARIZONA_EQ1_2),
SOC_SINGLE_TLV("EQ1 B1 Volume", ARIZONA_EQ1_1, ARIZONA_EQ1_B1_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ1 B2 Volume", ARIZONA_EQ1_1, ARIZONA_EQ1_B2_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ1 B3 Volume", ARIZONA_EQ1_1, ARIZONA_EQ1_B3_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ1 B4 Volume", ARIZONA_EQ1_2, ARIZONA_EQ1_B4_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ1 B5 Volume", ARIZONA_EQ1_2, ARIZONA_EQ1_B5_GAIN_SHIFT,
	       24, 0, eq_tlv),

ARIZONA_EQ_CONTROL("EQ2 Coefficients", ARIZONA_EQ2_2),
SOC_SINGLE_TLV("EQ2 B1 Volume", ARIZONA_EQ2_1, ARIZONA_EQ2_B1_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ2 B2 Volume", ARIZONA_EQ2_1, ARIZONA_EQ2_B2_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ2 B3 Volume", ARIZONA_EQ2_1, ARIZONA_EQ2_B3_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ2 B4 Volume", ARIZONA_EQ2_2, ARIZONA_EQ2_B4_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ2 B5 Volume", ARIZONA_EQ2_2, ARIZONA_EQ2_B5_GAIN_SHIFT,
	       24, 0, eq_tlv),

ARIZONA_EQ_CONTROL("EQ3 Coefficients", ARIZONA_EQ3_2),
SOC_SINGLE_TLV("EQ3 B1 Volume", ARIZONA_EQ3_1, ARIZONA_EQ3_B1_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ3 B2 Volume", ARIZONA_EQ3_1, ARIZONA_EQ3_B2_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ3 B3 Volume", ARIZONA_EQ3_1, ARIZONA_EQ3_B3_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ3 B4 Volume", ARIZONA_EQ3_2, ARIZONA_EQ3_B4_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ3 B5 Volume", ARIZONA_EQ3_2, ARIZONA_EQ3_B5_GAIN_SHIFT,
	       24, 0, eq_tlv),

ARIZONA_EQ_CONTROL("EQ4 Coefficients", ARIZONA_EQ4_2),
SOC_SINGLE_TLV("EQ4 B1 Volume", ARIZONA_EQ4_1, ARIZONA_EQ4_B1_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ4 B2 Volume", ARIZONA_EQ4_1, ARIZONA_EQ4_B2_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ4 B3 Volume", ARIZONA_EQ4_1, ARIZONA_EQ4_B3_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ4 B4 Volume", ARIZONA_EQ4_2, ARIZONA_EQ4_B4_GAIN_SHIFT,
	       24, 0, eq_tlv),
SOC_SINGLE_TLV("EQ4 B5 Volume", ARIZONA_EQ4_2, ARIZONA_EQ4_B5_GAIN_SHIFT,
	       24, 0, eq_tlv),

ARIZONA_MIXER_CONTROLS("DRC1L", ARIZONA_DRC1LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DRC1R", ARIZONA_DRC1RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DRC2L", ARIZONA_DRC2LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DRC2R", ARIZONA_DRC2RMIX_INPUT_1_SOURCE),

SND_SOC_BYTES_MASK("DRC1", ARIZONA_DRC1_CTRL1, 5,
		   ARIZONA_DRC1R_ENA | ARIZONA_DRC1L_ENA),
SND_SOC_BYTES_MASK("DRC2", CLEARWATER_DRC2_CTRL1, 5,
		   ARIZONA_DRC2R_ENA | ARIZONA_DRC2L_ENA),

ARIZONA_MIXER_CONTROLS("LHPF1", ARIZONA_HPLP1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("LHPF2", ARIZONA_HPLP2MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("LHPF3", ARIZONA_HPLP3MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("LHPF4", ARIZONA_HPLP4MIX_INPUT_1_SOURCE),

ARIZONA_LHPF_CONTROL("LHPF1 Coefficients", ARIZONA_HPLPF1_2),
ARIZONA_LHPF_CONTROL("LHPF2 Coefficients", ARIZONA_HPLPF2_2),
ARIZONA_LHPF_CONTROL("LHPF3 Coefficients", ARIZONA_HPLPF3_2),
ARIZONA_LHPF_CONTROL("LHPF4 Coefficients", ARIZONA_HPLPF4_2),

SOC_ENUM("LHPF1 Mode", arizona_lhpf1_mode),
SOC_ENUM("LHPF2 Mode", arizona_lhpf2_mode),
SOC_ENUM("LHPF3 Mode", arizona_lhpf3_mode),
SOC_ENUM("LHPF4 Mode", arizona_lhpf4_mode),

SOC_ENUM("Sample Rate 2", arizona_sample_rate[0]),
SOC_ENUM("Sample Rate 3", arizona_sample_rate[1]),
SOC_ENUM("ASYNC Sample Rate 2", arizona_sample_rate[2]),

CLEARWATER_RATE_ENUM("FX Rate", arizona_fx_rate),

CLEARWATER_RATE_ENUM("ISRC1 FSL", arizona_isrc_fsl[0]),
CLEARWATER_RATE_ENUM("ISRC2 FSL", arizona_isrc_fsl[1]),
CLEARWATER_RATE_ENUM("ISRC3 FSL", arizona_isrc_fsl[2]),
CLEARWATER_RATE_ENUM("ISRC4 FSL", arizona_isrc_fsl[3]),
CLEARWATER_RATE_ENUM("ISRC1 FSH", arizona_isrc_fsh[0]),
CLEARWATER_RATE_ENUM("ISRC2 FSH", arizona_isrc_fsh[1]),
CLEARWATER_RATE_ENUM("ISRC3 FSH", arizona_isrc_fsh[2]),
CLEARWATER_RATE_ENUM("ISRC4 FSH", arizona_isrc_fsh[3]),
CLEARWATER_RATE_ENUM("ASRC1 Rate 1", clearwater_asrc1_rate[0]),
CLEARWATER_RATE_ENUM("ASRC1 Rate 2", clearwater_asrc1_rate[1]),
CLEARWATER_RATE_ENUM("ASRC2 Rate 1", clearwater_asrc2_rate[0]),
CLEARWATER_RATE_ENUM("ASRC2 Rate 2", clearwater_asrc2_rate[1]),

ARIZONA_MIXER_CONTROLS("DSP1L", ARIZONA_DSP1LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP1R", ARIZONA_DSP1RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP2L", ARIZONA_DSP2LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP2R", ARIZONA_DSP2RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP3L", ARIZONA_DSP3LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP3R", ARIZONA_DSP3RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP4L", ARIZONA_DSP4LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP4R", ARIZONA_DSP4RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP5L", CLEARWATER_DSP5LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP5R", CLEARWATER_DSP5RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP6L", CLEARWATER_DSP6LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP6R", CLEARWATER_DSP6RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP7L", CLEARWATER_DSP7LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("DSP7R", CLEARWATER_DSP7RMIX_INPUT_1_SOURCE),

SOC_SINGLE_TLV("Noise Generator Volume", CLEARWATER_COMFORT_NOISE_GENERATOR,
	       CLEARWATER_NOISE_GEN_GAIN_SHIFT, 0x16, 0, noise_tlv),

ARIZONA_MIXER_CONTROLS("HPOUT1L", ARIZONA_OUT1LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("HPOUT1R", ARIZONA_OUT1RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("HPOUT2L", ARIZONA_OUT2LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("HPOUT2R", ARIZONA_OUT2RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("HPOUT3L", ARIZONA_OUT3LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("HPOUT3R", ARIZONA_OUT3RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKOUTL", ARIZONA_OUT4LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKOUTR", ARIZONA_OUT4RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKDAT1L", ARIZONA_OUT5LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKDAT1R", ARIZONA_OUT5RMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKDAT2L", ARIZONA_OUT6LMIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SPKDAT2R", ARIZONA_OUT6RMIX_INPUT_1_SOURCE),

SOC_SINGLE("HPOUT1 SC Protect Switch", ARIZONA_HP1_SHORT_CIRCUIT_CTRL,
	   ARIZONA_HP1_SC_ENA_SHIFT, 1, 0),
SOC_SINGLE("HPOUT2 SC Protect Switch", ARIZONA_HP2_SHORT_CIRCUIT_CTRL,
	   ARIZONA_HP2_SC_ENA_SHIFT, 1, 0),
SOC_SINGLE("HPOUT3 SC Protect Switch", ARIZONA_HP3_SHORT_CIRCUIT_CTRL,
	   ARIZONA_HP3_SC_ENA_SHIFT, 1, 0),

SOC_SINGLE("HPOUT1L ONEFLT Switch", ARIZONA_HP_TEST_CTRL_5,
				    ARIZONA_HP1L_ONEFLT_SHIFT, 1, 0),
SOC_SINGLE("HPOUT1R ONEFLT Switch", ARIZONA_HP_TEST_CTRL_6,
				    ARIZONA_HP1R_ONEFLT_SHIFT, 1, 0),

SOC_SINGLE("SPKDAT1 High Performance Switch", ARIZONA_OUTPUT_PATH_CONFIG_5L,
	   ARIZONA_OUT5_OSR_SHIFT, 1, 0),
SOC_SINGLE("SPKDAT2 High Performance Switch", ARIZONA_OUTPUT_PATH_CONFIG_6L,
	   ARIZONA_OUT6_OSR_SHIFT, 1, 0),

SOC_DOUBLE_R("HPOUT1 Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_1L,
	     ARIZONA_DAC_DIGITAL_VOLUME_1R, ARIZONA_OUT1L_MUTE_SHIFT, 1, 1),
SOC_DOUBLE_R("HPOUT2 Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_2L,
	     ARIZONA_DAC_DIGITAL_VOLUME_2R, ARIZONA_OUT2L_MUTE_SHIFT, 1, 1),
SOC_DOUBLE_R("HPOUT3 Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_3L,
	     ARIZONA_DAC_DIGITAL_VOLUME_3R, ARIZONA_OUT3L_MUTE_SHIFT, 1, 1),
SOC_DOUBLE_R("Speaker Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_4L,
	     ARIZONA_DAC_DIGITAL_VOLUME_4R, ARIZONA_OUT4L_MUTE_SHIFT, 1, 1),
SOC_DOUBLE_R("SPKDAT1 Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_5L,
	     ARIZONA_DAC_DIGITAL_VOLUME_5R, ARIZONA_OUT5L_MUTE_SHIFT, 1, 1),
SOC_DOUBLE_R("SPKDAT2 Digital Switch", ARIZONA_DAC_DIGITAL_VOLUME_6L,
	     ARIZONA_DAC_DIGITAL_VOLUME_6R, ARIZONA_OUT6L_MUTE_SHIFT, 1, 1),

SOC_DOUBLE_R_TLV("HPOUT1 Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_1L,
		 ARIZONA_DAC_DIGITAL_VOLUME_1R, ARIZONA_OUT1L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),
SOC_DOUBLE_R_TLV("HPOUT2 Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_2L,
		 ARIZONA_DAC_DIGITAL_VOLUME_2R, ARIZONA_OUT2L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),
SOC_DOUBLE_R_TLV("HPOUT3 Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_3L,
		 ARIZONA_DAC_DIGITAL_VOLUME_3R, ARIZONA_OUT3L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),
SOC_DOUBLE_R_TLV("Speaker Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_4L,
		 ARIZONA_DAC_DIGITAL_VOLUME_4R, ARIZONA_OUT4L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),
SOC_DOUBLE_R_TLV("SPKDAT1 Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_5L,
		 ARIZONA_DAC_DIGITAL_VOLUME_5R, ARIZONA_OUT5L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),
SOC_DOUBLE_R_TLV("SPKDAT2 Digital Volume", ARIZONA_DAC_DIGITAL_VOLUME_6L,
		 ARIZONA_DAC_DIGITAL_VOLUME_6R, ARIZONA_OUT6L_VOL_SHIFT,
		 0xbf, 0, digital_tlv),

SOC_DOUBLE("SPKDAT1 Switch", ARIZONA_PDM_SPK1_CTRL_1, ARIZONA_SPK1L_MUTE_SHIFT,
	   ARIZONA_SPK1R_MUTE_SHIFT, 1, 1),
SOC_DOUBLE("SPKDAT2 Switch", ARIZONA_PDM_SPK2_CTRL_1, ARIZONA_SPK2L_MUTE_SHIFT,
	   ARIZONA_SPK2R_MUTE_SHIFT, 1, 1),

SOC_DOUBLE_EXT("HPOUT1 DRE Switch", ARIZONA_DRE_ENABLE,
	   VEGAS_DRE1L_ENA_SHIFT, VEGAS_DRE1R_ENA_SHIFT, 1, 0,
	   snd_soc_get_volsw, clearwater_put_dre),
SOC_DOUBLE_EXT("HPOUT2 DRE Switch", ARIZONA_DRE_ENABLE,
	   VEGAS_DRE2L_ENA_SHIFT, VEGAS_DRE2R_ENA_SHIFT, 1, 0,
	   snd_soc_get_volsw, clearwater_put_dre),
SOC_DOUBLE_EXT("HPOUT3 DRE Switch", ARIZONA_DRE_ENABLE,
	   VEGAS_DRE3L_ENA_SHIFT, VEGAS_DRE3R_ENA_SHIFT, 1, 0,
	   snd_soc_get_volsw, clearwater_put_dre),

SOC_DOUBLE("HPOUT1 EDRE Switch", CLEARWATER_EDRE_ENABLE,
	   CLEARWATER_EDRE_OUT1L_THR1_ENA_SHIFT,
	   CLEARWATER_EDRE_OUT1R_THR1_ENA_SHIFT, 1, 0),
SOC_DOUBLE("HPOUT2 EDRE Switch", CLEARWATER_EDRE_ENABLE,
	   CLEARWATER_EDRE_OUT2L_THR1_ENA_SHIFT,
	   CLEARWATER_EDRE_OUT2R_THR1_ENA_SHIFT, 1, 0),
SOC_DOUBLE("HPOUT3 EDRE Switch", CLEARWATER_EDRE_ENABLE,
	   CLEARWATER_EDRE_OUT3L_THR1_ENA_SHIFT,
	   CLEARWATER_EDRE_OUT3R_THR1_ENA_SHIFT, 1, 0),

SOC_ENUM("Output Ramp Up", arizona_out_vi_ramp),
SOC_ENUM("Output Ramp Down", arizona_out_vd_ramp),

CLEARWATER_RATE_ENUM("SPDIF Rate", arizona_spdif_rate),

SOC_SINGLE("Noise Gate Switch", ARIZONA_NOISE_GATE_CONTROL,
	   ARIZONA_NGATE_ENA_SHIFT, 1, 0),
SOC_SINGLE_TLV("Noise Gate Threshold Volume", ARIZONA_NOISE_GATE_CONTROL,
	       ARIZONA_NGATE_THR_SHIFT, 7, 1, ng_tlv),
SOC_ENUM("Noise Gate Hold", arizona_ng_hold),

CLEARWATER_RATE_ENUM("Output Rate 1", arizona_output_rate),
SOC_ENUM("In Rate", arizona_input_rate),

CLEARWATER_NG_SRC("HPOUT1L", ARIZONA_NOISE_GATE_SELECT_1L),
CLEARWATER_NG_SRC("HPOUT1R", ARIZONA_NOISE_GATE_SELECT_1R),
CLEARWATER_NG_SRC("HPOUT2L", ARIZONA_NOISE_GATE_SELECT_2L),
CLEARWATER_NG_SRC("HPOUT2R", ARIZONA_NOISE_GATE_SELECT_2R),
CLEARWATER_NG_SRC("HPOUT3L", ARIZONA_NOISE_GATE_SELECT_3L),
CLEARWATER_NG_SRC("HPOUT3R", ARIZONA_NOISE_GATE_SELECT_3R),
CLEARWATER_NG_SRC("SPKOUTL", ARIZONA_NOISE_GATE_SELECT_4L),
CLEARWATER_NG_SRC("SPKOUTR", ARIZONA_NOISE_GATE_SELECT_4R),
CLEARWATER_NG_SRC("SPKDAT1L", ARIZONA_NOISE_GATE_SELECT_5L),
CLEARWATER_NG_SRC("SPKDAT1R", ARIZONA_NOISE_GATE_SELECT_5R),
CLEARWATER_NG_SRC("SPKDAT2L", ARIZONA_NOISE_GATE_SELECT_6L),
CLEARWATER_NG_SRC("SPKDAT2R", ARIZONA_NOISE_GATE_SELECT_6R),

ARIZONA_MIXER_CONTROLS("AIF1TX1", ARIZONA_AIF1TX1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX2", ARIZONA_AIF1TX2MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX3", ARIZONA_AIF1TX3MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX4", ARIZONA_AIF1TX4MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX5", ARIZONA_AIF1TX5MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX6", ARIZONA_AIF1TX6MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX7", ARIZONA_AIF1TX7MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF1TX8", ARIZONA_AIF1TX8MIX_INPUT_1_SOURCE),

ARIZONA_MIXER_CONTROLS("AIF2TX1", ARIZONA_AIF2TX1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX2", ARIZONA_AIF2TX2MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX3", ARIZONA_AIF2TX3MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX4", ARIZONA_AIF2TX4MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX5", ARIZONA_AIF2TX5MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX6", ARIZONA_AIF2TX6MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX7", ARIZONA_AIF2TX7MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF2TX8", ARIZONA_AIF2TX8MIX_INPUT_1_SOURCE),

ARIZONA_MIXER_CONTROLS("AIF3TX1", ARIZONA_AIF3TX1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF3TX2", ARIZONA_AIF3TX2MIX_INPUT_1_SOURCE),

ARIZONA_MIXER_CONTROLS("AIF4TX1", ARIZONA_AIF4TX1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("AIF4TX2", ARIZONA_AIF4TX2MIX_INPUT_1_SOURCE),

ARIZONA_MIXER_CONTROLS("SLIMTX1", ARIZONA_SLIMTX1MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX2", ARIZONA_SLIMTX2MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX3", ARIZONA_SLIMTX3MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX4", ARIZONA_SLIMTX4MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX5", ARIZONA_SLIMTX5MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX6", ARIZONA_SLIMTX6MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX7", ARIZONA_SLIMTX7MIX_INPUT_1_SOURCE),
ARIZONA_MIXER_CONTROLS("SLIMTX8", ARIZONA_SLIMTX8MIX_INPUT_1_SOURCE),

ARIZONA_GAINMUX_CONTROLS("SPDIFTX1", ARIZONA_SPDIFTX1MIX_INPUT_1_SOURCE),
ARIZONA_GAINMUX_CONTROLS("SPDIFTX2", ARIZONA_SPDIFTX2MIX_INPUT_1_SOURCE),
};

CLEARWATER_MIXER_ENUMS(EQ1, ARIZONA_EQ1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(EQ2, ARIZONA_EQ2MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(EQ3, ARIZONA_EQ3MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(EQ4, ARIZONA_EQ4MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DRC1L, ARIZONA_DRC1LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DRC1R, ARIZONA_DRC1RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DRC2L, ARIZONA_DRC2LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DRC2R, ARIZONA_DRC2RMIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(LHPF1, ARIZONA_HPLP1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(LHPF2, ARIZONA_HPLP2MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(LHPF3, ARIZONA_HPLP3MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(LHPF4, ARIZONA_HPLP4MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP1L, ARIZONA_DSP1LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP1R, ARIZONA_DSP1RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP1, ARIZONA_DSP1AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP2L, ARIZONA_DSP2LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP2R, ARIZONA_DSP2RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP2, ARIZONA_DSP2AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP3L, ARIZONA_DSP3LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP3R, ARIZONA_DSP3RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP3, ARIZONA_DSP3AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP4L, ARIZONA_DSP4LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP4R, ARIZONA_DSP4RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP4, ARIZONA_DSP4AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP5L, CLEARWATER_DSP5LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP5R, CLEARWATER_DSP5RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP5, CLEARWATER_DSP5AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP6L, CLEARWATER_DSP6LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP6R, CLEARWATER_DSP6RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP6, CLEARWATER_DSP6AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(DSP7L, CLEARWATER_DSP7LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(DSP7R, CLEARWATER_DSP7RMIX_INPUT_1_SOURCE);
CLEARWATER_DSP_AUX_ENUMS(DSP7, CLEARWATER_DSP7AUX1MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(PWM1, ARIZONA_PWM1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(PWM2, ARIZONA_PWM2MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(OUT1L, ARIZONA_OUT1LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(OUT1R, ARIZONA_OUT1RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(OUT2L, ARIZONA_OUT2LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(OUT2R, ARIZONA_OUT2RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(OUT3L, ARIZONA_OUT3LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(OUT3R, ARIZONA_OUT3RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKOUTL, ARIZONA_OUT4LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKOUTR, ARIZONA_OUT4RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKDAT1L, ARIZONA_OUT5LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKDAT1R, ARIZONA_OUT5RMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKDAT2L, ARIZONA_OUT6LMIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SPKDAT2R, ARIZONA_OUT6RMIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(AIF1TX1, ARIZONA_AIF1TX1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX2, ARIZONA_AIF1TX2MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX3, ARIZONA_AIF1TX3MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX4, ARIZONA_AIF1TX4MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX5, ARIZONA_AIF1TX5MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX6, ARIZONA_AIF1TX6MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX7, ARIZONA_AIF1TX7MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF1TX8, ARIZONA_AIF1TX8MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(AIF2TX1, ARIZONA_AIF2TX1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX2, ARIZONA_AIF2TX2MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX3, ARIZONA_AIF2TX3MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX4, ARIZONA_AIF2TX4MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX5, ARIZONA_AIF2TX5MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX6, ARIZONA_AIF2TX6MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX7, ARIZONA_AIF2TX7MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF2TX8, ARIZONA_AIF2TX8MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(AIF3TX1, ARIZONA_AIF3TX1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF3TX2, ARIZONA_AIF3TX2MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(AIF4TX1, ARIZONA_AIF4TX1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(AIF4TX2, ARIZONA_AIF4TX2MIX_INPUT_1_SOURCE);

CLEARWATER_MIXER_ENUMS(SLIMTX1, ARIZONA_SLIMTX1MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX2, ARIZONA_SLIMTX2MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX3, ARIZONA_SLIMTX3MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX4, ARIZONA_SLIMTX4MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX5, ARIZONA_SLIMTX5MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX6, ARIZONA_SLIMTX6MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX7, ARIZONA_SLIMTX7MIX_INPUT_1_SOURCE);
CLEARWATER_MIXER_ENUMS(SLIMTX8, ARIZONA_SLIMTX8MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(SPD1TX1, ARIZONA_SPDIFTX1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(SPD1TX2, ARIZONA_SPDIFTX2MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ASRC1IN1L, CLEARWATER_ASRC1_1LMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC1IN1R, CLEARWATER_ASRC1_1RMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC1IN2L, CLEARWATER_ASRC1_2LMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC1IN2R, CLEARWATER_ASRC1_2RMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC2IN1L, CLEARWATER_ASRC2_1LMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC2IN1R, CLEARWATER_ASRC2_1RMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC2IN2L, CLEARWATER_ASRC2_2LMIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ASRC2IN2R, CLEARWATER_ASRC2_2RMIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC1INT1, ARIZONA_ISRC1INT1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1INT2, ARIZONA_ISRC1INT2MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1INT3, ARIZONA_ISRC1INT3MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1INT4, ARIZONA_ISRC1INT4MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC1DEC1, ARIZONA_ISRC1DEC1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1DEC2, ARIZONA_ISRC1DEC2MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1DEC3, ARIZONA_ISRC1DEC3MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC1DEC4, ARIZONA_ISRC1DEC4MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC2INT1, ARIZONA_ISRC2INT1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2INT2, ARIZONA_ISRC2INT2MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2INT3, ARIZONA_ISRC2INT3MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2INT4, ARIZONA_ISRC2INT4MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC2DEC1, ARIZONA_ISRC2DEC1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2DEC2, ARIZONA_ISRC2DEC2MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2DEC3, ARIZONA_ISRC2DEC3MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC2DEC4, ARIZONA_ISRC2DEC4MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC3INT1, ARIZONA_ISRC3INT1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC3INT2, ARIZONA_ISRC3INT2MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC3DEC1, ARIZONA_ISRC3DEC1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC3DEC2, ARIZONA_ISRC3DEC2MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC4INT1, ARIZONA_ISRC4INT1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC4INT2, ARIZONA_ISRC4INT2MIX_INPUT_1_SOURCE);

CLEARWATER_MUX_ENUMS(ISRC4DEC1, ARIZONA_ISRC4DEC1MIX_INPUT_1_SOURCE);
CLEARWATER_MUX_ENUMS(ISRC4DEC2, ARIZONA_ISRC4DEC2MIX_INPUT_1_SOURCE);

static const char * const clearwater_dsp_output_texts[] = {
	"None",
	"DSP6",
};

static const struct soc_enum clearwater_dsp_output_enum =
	SOC_ENUM_SINGLE(SND_SOC_NOPM, 0, ARRAY_SIZE(clearwater_dsp_output_texts),
			clearwater_dsp_output_texts);

static const struct snd_kcontrol_new clearwater_dsp_output_mux[] = {
	SOC_DAPM_ENUM("DSP Virtual Output Mux", clearwater_dsp_output_enum),
};

static const char * const clearwater_memory_mux_texts[] = {
	"None",
	"Shared Memory",
};

static const struct soc_enum clearwater_memory_enum =
	SOC_ENUM_SINGLE(SND_SOC_NOPM, 0, ARRAY_SIZE(clearwater_memory_mux_texts),
			clearwater_memory_mux_texts);

static const struct snd_kcontrol_new clearwater_memory_mux[] = {
	SOC_DAPM_ENUM("DSP2 Virtual Input", clearwater_memory_enum),
	SOC_DAPM_ENUM("DSP3 Virtual Input", clearwater_memory_enum),
};

static const char * const clearwater_aec_loopback_texts[] = {
	"HPOUT1L", "HPOUT1R", "HPOUT2L", "HPOUT2R", "HPOUT3L", "HPOUT3R",
	"SPKOUTL", "SPKOUTR", "SPKDAT1L", "SPKDAT1R", "SPKDAT2L", "SPKDAT2R",
};

static const unsigned int clearwater_aec_loopback_values[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
};

static const struct soc_enum clearwater_aec1_loopback =
	SOC_VALUE_ENUM_SINGLE(ARIZONA_DAC_AEC_CONTROL_1,
			      ARIZONA_AEC_LOOPBACK_SRC_SHIFT, 0xf,
			      ARRAY_SIZE(clearwater_aec_loopback_texts),
			      clearwater_aec_loopback_texts,
			      clearwater_aec_loopback_values);

static const struct soc_enum clearwater_aec2_loopback =
	SOC_VALUE_ENUM_SINGLE(ARIZONA_DAC_AEC_CONTROL_2,
			      ARIZONA_AEC_LOOPBACK_SRC_SHIFT, 0xf,
			      ARRAY_SIZE(clearwater_aec_loopback_texts),
			      clearwater_aec_loopback_texts,
			      clearwater_aec_loopback_values);

static const struct snd_kcontrol_new clearwater_aec_loopback_mux[] = {
	SOC_DAPM_ENUM("AEC1 Loopback", clearwater_aec1_loopback),
	SOC_DAPM_ENUM("AEC2 Loopback", clearwater_aec2_loopback),
};

static const struct snd_kcontrol_new clearwater_anc_input_mux[] = {
	SOC_DAPM_ENUM("RXANCL Input", clearwater_anc_input_src[0]),
	SOC_DAPM_ENUM("RXANCL Channel", clearwater_anc_input_src[1]),
	SOC_DAPM_ENUM("RXANCR Input", clearwater_anc_input_src[2]),
	SOC_DAPM_ENUM("RXANCR Channel", clearwater_anc_input_src[3]),
};

static const struct snd_kcontrol_new clearwater_anc_ng_mux =
	SOC_DAPM_ENUM("RXANC NG Source", arizona_anc_ng_enum);

static const struct snd_kcontrol_new clearwater_output_anc_src[] = {
	SOC_DAPM_ENUM("HPOUT1L ANC Source", arizona_output_anc_src[0]),
	SOC_DAPM_ENUM("HPOUT1R ANC Source", arizona_output_anc_src[1]),
	SOC_DAPM_ENUM("HPOUT2L ANC Source", arizona_output_anc_src[2]),
	SOC_DAPM_ENUM("HPOUT2R ANC Source", arizona_output_anc_src[3]),
	SOC_DAPM_ENUM("HPOUT3L ANC Source", arizona_output_anc_src[4]),
	SOC_DAPM_ENUM("HPOUT3R ANC Source", clearwater_output_anc_src_defs[0]),
	SOC_DAPM_ENUM("SPKOUTL ANC Source", arizona_output_anc_src[6]),
	SOC_DAPM_ENUM("SPKOUTR ANC Source", arizona_output_anc_src[7]),
	SOC_DAPM_ENUM("SPKDAT1L ANC Source", arizona_output_anc_src[8]),
	SOC_DAPM_ENUM("SPKDAT1R ANC Source", arizona_output_anc_src[9]),
	SOC_DAPM_ENUM("SPKDAT2L ANC Source", arizona_output_anc_src[10]),
	SOC_DAPM_ENUM("SPKDAT2R ANC Source", arizona_output_anc_src[11]),
};

static const struct snd_soc_dapm_widget clearwater_dapm_widgets[] = {
SND_SOC_DAPM_SUPPLY("SYSCLK", ARIZONA_SYSTEM_CLOCK_1, ARIZONA_SYSCLK_ENA_SHIFT,
		    0, clearwater_sysclk_ev,
		    SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
SND_SOC_DAPM_SUPPLY("ASYNCCLK", ARIZONA_ASYNC_CLOCK_1,
		    ARIZONA_ASYNC_CLK_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("OPCLK", ARIZONA_OUTPUT_SYSTEM_CLOCK,
		    ARIZONA_OPCLK_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("ASYNCOPCLK", ARIZONA_OUTPUT_ASYNC_CLOCK,
		    ARIZONA_OPCLK_ASYNC_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("DSPCLK", CLEARWATER_DSP_CLOCK_1, 6,
		    0, clearwater_dspclk_ev,
		    SND_SOC_DAPM_PRE_REG | SND_SOC_DAPM_POST_REG),


SND_SOC_DAPM_REGULATOR_SUPPLY("DBVDD2", 0, 0),
SND_SOC_DAPM_REGULATOR_SUPPLY("DBVDD3", 0, 0),
SND_SOC_DAPM_REGULATOR_SUPPLY("DBVDD4", 0, 0),
SND_SOC_DAPM_REGULATOR_SUPPLY("CPVDD", 20, 0),
SND_SOC_DAPM_REGULATOR_SUPPLY("MICVDD", 0, SND_SOC_DAPM_REGULATOR_BYPASS),
SND_SOC_DAPM_REGULATOR_SUPPLY("SPKVDDL", 0, 0),
SND_SOC_DAPM_REGULATOR_SUPPLY("SPKVDDR", 0, 0),

SND_SOC_DAPM_SIGGEN("TONE"),
SND_SOC_DAPM_SIGGEN("NOISE"),
SND_SOC_DAPM_SIGGEN("HAPTICS"),

SND_SOC_DAPM_INPUT("IN1AL"),
SND_SOC_DAPM_INPUT("IN1B"),
SND_SOC_DAPM_INPUT("IN1R"),
SND_SOC_DAPM_INPUT("IN2AL"),
SND_SOC_DAPM_INPUT("IN2AR"),
SND_SOC_DAPM_INPUT("IN2BL"),
SND_SOC_DAPM_INPUT("IN2BR"),
SND_SOC_DAPM_INPUT("IN3L"),
SND_SOC_DAPM_INPUT("IN3R"),
SND_SOC_DAPM_INPUT("IN4L"),
SND_SOC_DAPM_INPUT("IN4R"),
SND_SOC_DAPM_INPUT("IN5L"),
SND_SOC_DAPM_INPUT("IN5R"),
SND_SOC_DAPM_INPUT("IN6L"),
SND_SOC_DAPM_INPUT("IN6R"),

SND_SOC_DAPM_MUX("IN1L Mux", SND_SOC_NOPM, 0, 0, &clearwater_in1mux),
SND_SOC_DAPM_MUX("IN2L Mux", SND_SOC_NOPM, 0, 0, &clearwater_in2mux[0]),
SND_SOC_DAPM_MUX("IN2R Mux", SND_SOC_NOPM, 0, 0, &clearwater_in2mux[1]),

SND_SOC_DAPM_OUTPUT("DRC1 Signal Activity"),
SND_SOC_DAPM_OUTPUT("DRC2 Signal Activity"),

SND_SOC_DAPM_OUTPUT("DSP Virtual Output"),

SND_SOC_DAPM_PGA_E("IN1L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN1L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN1R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN1R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN2L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN2L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN2R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN2R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN3L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN3L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN3R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN3R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN4L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN4L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN4R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN4R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN5L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN5L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN5R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN5R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN6L PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN6L_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("IN6R PGA", ARIZONA_INPUT_ENABLES, ARIZONA_IN6R_ENA_SHIFT,
		   0, NULL, 0, arizona_in_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),

SND_SOC_DAPM_SUPPLY("MICBIAS1", ARIZONA_MIC_BIAS_CTRL_1,
		    ARIZONA_MICB1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("MICBIAS2", ARIZONA_MIC_BIAS_CTRL_2,
		    ARIZONA_MICB1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("MICBIAS3", ARIZONA_MIC_BIAS_CTRL_3,
		    ARIZONA_MICB1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_SUPPLY("MICBIAS4", ARIZONA_MIC_BIAS_CTRL_4,
		    ARIZONA_MICB1_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("Noise Generator", CLEARWATER_COMFORT_NOISE_GENERATOR,
		 CLEARWATER_NOISE_GEN_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("Tone Generator 1", ARIZONA_TONE_GENERATOR_1,
		 ARIZONA_TONE1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("Tone Generator 2", ARIZONA_TONE_GENERATOR_1,
		 ARIZONA_TONE2_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("EQ1", ARIZONA_EQ1_1, ARIZONA_EQ1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("EQ2", ARIZONA_EQ2_1, ARIZONA_EQ2_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("EQ3", ARIZONA_EQ3_1, ARIZONA_EQ3_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("EQ4", ARIZONA_EQ4_1, ARIZONA_EQ4_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("DRC1L", ARIZONA_DRC1_CTRL1, ARIZONA_DRC1L_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("DRC1R", ARIZONA_DRC1_CTRL1, ARIZONA_DRC1R_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("DRC2L", CLEARWATER_DRC2_CTRL1, ARIZONA_DRC2L_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("DRC2R", CLEARWATER_DRC2_CTRL1, ARIZONA_DRC2R_ENA_SHIFT, 0,
		 NULL, 0),

SND_SOC_DAPM_PGA("LHPF1", ARIZONA_HPLPF1_1, ARIZONA_LHPF1_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("LHPF2", ARIZONA_HPLPF2_1, ARIZONA_LHPF2_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("LHPF3", ARIZONA_HPLPF3_1, ARIZONA_LHPF3_ENA_SHIFT, 0,
		 NULL, 0),
SND_SOC_DAPM_PGA("LHPF4", ARIZONA_HPLPF4_1, ARIZONA_LHPF4_ENA_SHIFT, 0,
		 NULL, 0),

SND_SOC_DAPM_PGA("PWM1 Driver", ARIZONA_PWM_DRIVE_1, ARIZONA_PWM1_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("PWM2 Driver", ARIZONA_PWM_DRIVE_1, ARIZONA_PWM2_ENA_SHIFT,
		 0, NULL, 0),

SND_SOC_DAPM_PGA("ASRC1IN1L", CLEARWATER_ASRC1_ENABLE, CLEARWATER_ASRC1_IN1L_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC1IN1R", CLEARWATER_ASRC1_ENABLE, CLEARWATER_ASRC1_IN1R_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC1IN2L", CLEARWATER_ASRC1_ENABLE, CLEARWATER_ASRC1_IN2L_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC1IN2R", CLEARWATER_ASRC1_ENABLE, CLEARWATER_ASRC1_IN2R_ENA_SHIFT,
		 0, NULL, 0),

SND_SOC_DAPM_PGA("ASRC2IN1L", CLEARWATER_ASRC2_ENABLE, CLEARWATER_ASRC2_IN1L_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC2IN1R", CLEARWATER_ASRC2_ENABLE, CLEARWATER_ASRC2_IN1R_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC2IN2L", CLEARWATER_ASRC2_ENABLE, CLEARWATER_ASRC2_IN2L_ENA_SHIFT,
		 0, NULL, 0),
SND_SOC_DAPM_PGA("ASRC2IN2R", CLEARWATER_ASRC2_ENABLE, CLEARWATER_ASRC2_IN2R_ENA_SHIFT,
		 0, NULL, 0),

WM_ADSP2("DSP1", 0, clearwater_adsp_power_ev),
WM_ADSP2("DSP2", 1, clearwater_adsp_power_ev),
WM_ADSP2("DSP3", 2, clearwater_adsp_power_ev),
WM_ADSP2("DSP4", 3, clearwater_adsp_power_ev),
WM_ADSP2("DSP5", 4, clearwater_adsp_power_ev),
WM_ADSP2("DSP6", 5, clearwater_adsp_power_ev),
WM_ADSP2("DSP7", 6, clearwater_adsp_power_ev),

SND_SOC_DAPM_PGA("ISRC1INT1", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_INT0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1INT2", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_INT1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1INT3", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_INT2_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1INT4", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_INT3_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC1DEC1", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_DEC0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1DEC2", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_DEC1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1DEC3", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_DEC2_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC1DEC4", ARIZONA_ISRC_1_CTRL_3,
		 ARIZONA_ISRC1_DEC3_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC2INT1", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_INT0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2INT2", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_INT1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2INT3", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_INT2_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2INT4", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_INT3_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC2DEC1", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_DEC0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2DEC2", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_DEC1_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2DEC3", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_DEC2_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC2DEC4", ARIZONA_ISRC_2_CTRL_3,
		 ARIZONA_ISRC2_DEC3_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC3INT1", ARIZONA_ISRC_3_CTRL_3,
		 ARIZONA_ISRC3_INT0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC3INT2", ARIZONA_ISRC_3_CTRL_3,
		 ARIZONA_ISRC3_INT1_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC3DEC1", ARIZONA_ISRC_3_CTRL_3,
		 ARIZONA_ISRC3_DEC0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC3DEC2", ARIZONA_ISRC_3_CTRL_3,
		 ARIZONA_ISRC3_DEC1_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC4INT1", ARIZONA_ISRC_4_CTRL_3,
		 ARIZONA_ISRC4_INT0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC4INT2", ARIZONA_ISRC_4_CTRL_3,
		 ARIZONA_ISRC4_INT1_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_PGA("ISRC4DEC1", ARIZONA_ISRC_4_CTRL_3,
		 ARIZONA_ISRC4_DEC0_ENA_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("ISRC4DEC2", ARIZONA_ISRC_4_CTRL_3,
		 ARIZONA_ISRC4_DEC1_ENA_SHIFT, 0, NULL, 0),

SND_SOC_DAPM_MUX("AEC1 Loopback", ARIZONA_DAC_AEC_CONTROL_1,
			ARIZONA_AEC_LOOPBACK_ENA_SHIFT, 0,
			&clearwater_aec_loopback_mux[0]),
SND_SOC_DAPM_MUX("AEC2 Loopback", ARIZONA_DAC_AEC_CONTROL_2,
			ARIZONA_AEC_LOOPBACK_ENA_SHIFT, 0,
			&clearwater_aec_loopback_mux[1]),

SND_SOC_DAPM_SUPPLY("RXANC NG External Clock", SND_SOC_NOPM,
		    ARIZONA_EXT_NG_SEL_SET_SHIFT, 0, arizona_anc_ev,
		    SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
SND_SOC_DAPM_PGA("RXANCL NG External", SND_SOC_NOPM, 0, 0, NULL, 0),
SND_SOC_DAPM_PGA("RXANCR NG External", SND_SOC_NOPM, 0, 0, NULL, 0),

SND_SOC_DAPM_SUPPLY("RXANC NG Clock", SND_SOC_NOPM,
		    ARIZONA_CLK_NG_ENA_SET_SHIFT, 0, arizona_anc_ev,
		    SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
SND_SOC_DAPM_PGA("RXANCL NG Internal", SND_SOC_NOPM, 0, 0, NULL, 0),
SND_SOC_DAPM_PGA("RXANCR NG Internal", SND_SOC_NOPM, 0, 0, NULL, 0),

SND_SOC_DAPM_MUX("RXANCL Left Input", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[0]),
SND_SOC_DAPM_MUX("RXANCL Right Input", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[0]),
SND_SOC_DAPM_MUX("RXANCL Channel", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[1]),
SND_SOC_DAPM_MUX("RXANCL NG Mux", SND_SOC_NOPM, 0, 0, &clearwater_anc_ng_mux),
SND_SOC_DAPM_MUX("RXANCR Left Input", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[2]),
SND_SOC_DAPM_MUX("RXANCR Right Input", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[2]),
SND_SOC_DAPM_MUX("RXANCR Channel", SND_SOC_NOPM, 0, 0,
		 &clearwater_anc_input_mux[3]),
SND_SOC_DAPM_MUX("RXANCR NG Mux", SND_SOC_NOPM, 0, 0, &clearwater_anc_ng_mux),

SND_SOC_DAPM_PGA_E("RXANCL", SND_SOC_NOPM, ARIZONA_CLK_L_ENA_SET_SHIFT,
		   0, NULL, 0, arizona_anc_ev,
		   SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),
SND_SOC_DAPM_PGA_E("RXANCR", SND_SOC_NOPM, ARIZONA_CLK_R_ENA_SET_SHIFT,
		   0, NULL, 0, arizona_anc_ev,
		   SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),

SND_SOC_DAPM_MUX("HPOUT1L ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[0]),
SND_SOC_DAPM_MUX("HPOUT1R ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[1]),
SND_SOC_DAPM_MUX("HPOUT2L ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[2]),
SND_SOC_DAPM_MUX("HPOUT2R ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[3]),
SND_SOC_DAPM_MUX("HPOUT3L ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[4]),
SND_SOC_DAPM_MUX("HPOUT3R ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[5]),
SND_SOC_DAPM_MUX("SPKOUTL ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[6]),
SND_SOC_DAPM_MUX("SPKOUTR ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[7]),
SND_SOC_DAPM_MUX("SPKDAT1L ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[8]),
SND_SOC_DAPM_MUX("SPKDAT1R ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[9]),
SND_SOC_DAPM_MUX("SPKDAT2L ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[10]),
SND_SOC_DAPM_MUX("SPKDAT2R ANC Source", SND_SOC_NOPM, 0, 0,
		 &clearwater_output_anc_src[11]),

SND_SOC_DAPM_AIF_OUT("AIF1TX1", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX2", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX3", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX4", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX5", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX6", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX7", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF1TX8", NULL, 0,
		     ARIZONA_AIF1_TX_ENABLES, ARIZONA_AIF1TX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_IN("AIF1RX1", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX2", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX3", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX4", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX5", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX6", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX7", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF1RX8", NULL, 0,
		    ARIZONA_AIF1_RX_ENABLES, ARIZONA_AIF1RX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_OUT("AIF2TX1", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX2", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX3", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX4", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX5", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX6", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX7", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF2TX8", NULL, 0,
		     ARIZONA_AIF2_TX_ENABLES, ARIZONA_AIF2TX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_IN("AIF2RX1", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX2", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX3", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX4", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX5", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX6", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX7", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF2RX8", NULL, 0,
		    ARIZONA_AIF2_RX_ENABLES, ARIZONA_AIF2RX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_IN("SLIMRX1", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX2", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX3", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX4", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX5", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX6", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX7", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("SLIMRX8", NULL, 0,
		    ARIZONA_SLIMBUS_RX_CHANNEL_ENABLE,
		    ARIZONA_SLIMRX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_OUT("SLIMTX1", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX2", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX2_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX3", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX3_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX4", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX4_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX5", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX5_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX6", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX6_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX7", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX7_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("SLIMTX8", NULL, 0,
		     ARIZONA_SLIMBUS_TX_CHANNEL_ENABLE,
		     ARIZONA_SLIMTX8_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_OUT("AIF3TX1", NULL, 0,
		     ARIZONA_AIF3_TX_ENABLES, ARIZONA_AIF3TX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF3TX2", NULL, 0,
		     ARIZONA_AIF3_TX_ENABLES, ARIZONA_AIF3TX2_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_IN("AIF3RX1", NULL, 0,
		    ARIZONA_AIF3_RX_ENABLES, ARIZONA_AIF3RX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF3RX2", NULL, 0,
		    ARIZONA_AIF3_RX_ENABLES, ARIZONA_AIF3RX2_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_OUT("AIF4TX1", NULL, 0,
		     ARIZONA_AIF4_TX_ENABLES, ARIZONA_AIF4TX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_OUT("AIF4TX2", NULL, 0,
		     ARIZONA_AIF4_TX_ENABLES, ARIZONA_AIF4TX2_ENA_SHIFT, 0),

SND_SOC_DAPM_AIF_IN("AIF4RX1", NULL, 0,
		    ARIZONA_AIF4_RX_ENABLES, ARIZONA_AIF4RX1_ENA_SHIFT, 0),
SND_SOC_DAPM_AIF_IN("AIF4RX2", NULL, 0,
		    ARIZONA_AIF4_RX_ENABLES, ARIZONA_AIF4RX2_ENA_SHIFT, 0),

SND_SOC_DAPM_PGA_E("OUT1L", SND_SOC_NOPM,
		   ARIZONA_OUT1L_ENA_SHIFT, 0, NULL, 0, clearwater_hp_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT1R", SND_SOC_NOPM,
		   ARIZONA_OUT1R_ENA_SHIFT, 0, NULL, 0, clearwater_hp_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT2L", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT2L_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT2R", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT2R_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT3L", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT3L_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT3R", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT3R_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMD |
		   SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT5L", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT5L_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT5R", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT5R_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT6L", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT6L_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMU),
SND_SOC_DAPM_PGA_E("OUT6R", ARIZONA_OUTPUT_ENABLES_1,
		   ARIZONA_OUT6R_ENA_SHIFT, 0, NULL, 0, arizona_out_ev,
		   SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMU),

SND_SOC_DAPM_PGA("SPD1TX1", ARIZONA_SPD1_TX_CONTROL,
		   ARIZONA_SPD1_VAL1_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_PGA("SPD1TX2", ARIZONA_SPD1_TX_CONTROL,
		   ARIZONA_SPD1_VAL2_SHIFT, 0, NULL, 0),
SND_SOC_DAPM_OUT_DRV("SPD1", ARIZONA_SPD1_TX_CONTROL,
		     ARIZONA_SPD1_ENA_SHIFT, 0, NULL, 0),

ARIZONA_MIXER_WIDGETS(EQ1, "EQ1"),
ARIZONA_MIXER_WIDGETS(EQ2, "EQ2"),
ARIZONA_MIXER_WIDGETS(EQ3, "EQ3"),
ARIZONA_MIXER_WIDGETS(EQ4, "EQ4"),

ARIZONA_MIXER_WIDGETS(DRC1L, "DRC1L"),
ARIZONA_MIXER_WIDGETS(DRC1R, "DRC1R"),
ARIZONA_MIXER_WIDGETS(DRC2L, "DRC2L"),
ARIZONA_MIXER_WIDGETS(DRC2R, "DRC2R"),

ARIZONA_MIXER_WIDGETS(LHPF1, "LHPF1"),
ARIZONA_MIXER_WIDGETS(LHPF2, "LHPF2"),
ARIZONA_MIXER_WIDGETS(LHPF3, "LHPF3"),
ARIZONA_MIXER_WIDGETS(LHPF4, "LHPF4"),

ARIZONA_MIXER_WIDGETS(PWM1, "PWM1"),
ARIZONA_MIXER_WIDGETS(PWM2, "PWM2"),

ARIZONA_MIXER_WIDGETS(OUT1L, "HPOUT1L"),
ARIZONA_MIXER_WIDGETS(OUT1R, "HPOUT1R"),
ARIZONA_MIXER_WIDGETS(OUT2L, "HPOUT2L"),
ARIZONA_MIXER_WIDGETS(OUT2R, "HPOUT2R"),
ARIZONA_MIXER_WIDGETS(OUT3L, "HPOUT3L"),
ARIZONA_MIXER_WIDGETS(OUT3R, "HPOUT3R"),
ARIZONA_MIXER_WIDGETS(SPKOUTL, "SPKOUTL"),
ARIZONA_MIXER_WIDGETS(SPKOUTR, "SPKOUTR"),
ARIZONA_MIXER_WIDGETS(SPKDAT1L, "SPKDAT1L"),
ARIZONA_MIXER_WIDGETS(SPKDAT1R, "SPKDAT1R"),
ARIZONA_MIXER_WIDGETS(SPKDAT2L, "SPKDAT2L"),
ARIZONA_MIXER_WIDGETS(SPKDAT2R, "SPKDAT2R"),

ARIZONA_MIXER_WIDGETS(AIF1TX1, "AIF1TX1"),
ARIZONA_MIXER_WIDGETS(AIF1TX2, "AIF1TX2"),
ARIZONA_MIXER_WIDGETS(AIF1TX3, "AIF1TX3"),
ARIZONA_MIXER_WIDGETS(AIF1TX4, "AIF1TX4"),
ARIZONA_MIXER_WIDGETS(AIF1TX5, "AIF1TX5"),
ARIZONA_MIXER_WIDGETS(AIF1TX6, "AIF1TX6"),
ARIZONA_MIXER_WIDGETS(AIF1TX7, "AIF1TX7"),
ARIZONA_MIXER_WIDGETS(AIF1TX8, "AIF1TX8"),

ARIZONA_MIXER_WIDGETS(AIF2TX1, "AIF2TX1"),
ARIZONA_MIXER_WIDGETS(AIF2TX2, "AIF2TX2"),
ARIZONA_MIXER_WIDGETS(AIF2TX3, "AIF2TX3"),
ARIZONA_MIXER_WIDGETS(AIF2TX4, "AIF2TX4"),
ARIZONA_MIXER_WIDGETS(AIF2TX5, "AIF2TX5"),
ARIZONA_MIXER_WIDGETS(AIF2TX6, "AIF2TX6"),
ARIZONA_MIXER_WIDGETS(AIF2TX7, "AIF2TX7"),
ARIZONA_MIXER_WIDGETS(AIF2TX8, "AIF2TX8"),

ARIZONA_MIXER_WIDGETS(AIF3TX1, "AIF3TX1"),
ARIZONA_MIXER_WIDGETS(AIF3TX2, "AIF3TX2"),

ARIZONA_MIXER_WIDGETS(AIF4TX1, "AIF4TX1"),
ARIZONA_MIXER_WIDGETS(AIF4TX2, "AIF4TX2"),

ARIZONA_MIXER_WIDGETS(SLIMTX1, "SLIMTX1"),
ARIZONA_MIXER_WIDGETS(SLIMTX2, "SLIMTX2"),
ARIZONA_MIXER_WIDGETS(SLIMTX3, "SLIMTX3"),
ARIZONA_MIXER_WIDGETS(SLIMTX4, "SLIMTX4"),
ARIZONA_MIXER_WIDGETS(SLIMTX5, "SLIMTX5"),
ARIZONA_MIXER_WIDGETS(SLIMTX6, "SLIMTX6"),
ARIZONA_MIXER_WIDGETS(SLIMTX7, "SLIMTX7"),
ARIZONA_MIXER_WIDGETS(SLIMTX8, "SLIMTX8"),

ARIZONA_MUX_WIDGETS(SPD1TX1, "SPDIFTX1"),
ARIZONA_MUX_WIDGETS(SPD1TX2, "SPDIFTX2"),

ARIZONA_MUX_WIDGETS(ASRC1IN1L, "ASRC1IN1L"),
ARIZONA_MUX_WIDGETS(ASRC1IN1R, "ASRC1IN1R"),
ARIZONA_MUX_WIDGETS(ASRC1IN2L, "ASRC1IN2L"),
ARIZONA_MUX_WIDGETS(ASRC1IN2R, "ASRC1IN2R"),
ARIZONA_MUX_WIDGETS(ASRC2IN1L, "ASRC2IN1L"),
ARIZONA_MUX_WIDGETS(ASRC2IN1R, "ASRC2IN1R"),
ARIZONA_MUX_WIDGETS(ASRC2IN2L, "ASRC2IN2L"),
ARIZONA_MUX_WIDGETS(ASRC2IN2R, "ASRC2IN2R"),


ARIZONA_DSP_WIDGETS(DSP1, "DSP1"),
ARIZONA_DSP_WIDGETS(DSP2, "DSP2"),
ARIZONA_DSP_WIDGETS(DSP3, "DSP3"),
ARIZONA_DSP_WIDGETS(DSP4, "DSP4"),
ARIZONA_DSP_WIDGETS(DSP5, "DSP5"),
ARIZONA_DSP_WIDGETS(DSP6, "DSP6"),
ARIZONA_DSP_WIDGETS(DSP7, "DSP7"),

SND_SOC_DAPM_MUX("DSP2 Virtual Input", SND_SOC_NOPM, 0, 0,
		      &clearwater_memory_mux[0]),
SND_SOC_DAPM_MUX("DSP3 Virtual Input", SND_SOC_NOPM, 0, 0,
		      &clearwater_memory_mux[1]),

SND_SOC_DAPM_MUX("DSP Virtual Output Mux", SND_SOC_NOPM, 0, 0,
		      &clearwater_dsp_output_mux[0]),

ARIZONA_MUX_WIDGETS(ISRC1DEC1, "ISRC1DEC1"),
ARIZONA_MUX_WIDGETS(ISRC1DEC2, "ISRC1DEC2"),
ARIZONA_MUX_WIDGETS(ISRC1DEC3, "ISRC1DEC3"),
ARIZONA_MUX_WIDGETS(ISRC1DEC4, "ISRC1DEC4"),

ARIZONA_MUX_WIDGETS(ISRC1INT1, "ISRC1INT1"),
ARIZONA_MUX_WIDGETS(ISRC1INT2, "ISRC1INT2"),
ARIZONA_MUX_WIDGETS(ISRC1INT3, "ISRC1INT3"),
ARIZONA_MUX_WIDGETS(ISRC1INT4, "ISRC1INT4"),

ARIZONA_MUX_WIDGETS(ISRC2DEC1, "ISRC2DEC1"),
ARIZONA_MUX_WIDGETS(ISRC2DEC2, "ISRC2DEC2"),
ARIZONA_MUX_WIDGETS(ISRC2DEC3, "ISRC2DEC3"),
ARIZONA_MUX_WIDGETS(ISRC2DEC4, "ISRC2DEC4"),

ARIZONA_MUX_WIDGETS(ISRC2INT1, "ISRC2INT1"),
ARIZONA_MUX_WIDGETS(ISRC2INT2, "ISRC2INT2"),
ARIZONA_MUX_WIDGETS(ISRC2INT3, "ISRC2INT3"),
ARIZONA_MUX_WIDGETS(ISRC2INT4, "ISRC2INT4"),

ARIZONA_MUX_WIDGETS(ISRC3DEC1, "ISRC3DEC1"),
ARIZONA_MUX_WIDGETS(ISRC3DEC2, "ISRC3DEC2"),

ARIZONA_MUX_WIDGETS(ISRC3INT1, "ISRC3INT1"),
ARIZONA_MUX_WIDGETS(ISRC3INT2, "ISRC3INT2"),

ARIZONA_MUX_WIDGETS(ISRC4DEC1, "ISRC4DEC1"),
ARIZONA_MUX_WIDGETS(ISRC4DEC2, "ISRC4DEC2"),

ARIZONA_MUX_WIDGETS(ISRC4INT1, "ISRC4INT1"),
ARIZONA_MUX_WIDGETS(ISRC4INT2, "ISRC4INT2"),

SND_SOC_DAPM_OUTPUT("HPOUT1L"),
SND_SOC_DAPM_OUTPUT("HPOUT1R"),
SND_SOC_DAPM_OUTPUT("HPOUT2L"),
SND_SOC_DAPM_OUTPUT("HPOUT2R"),
SND_SOC_DAPM_OUTPUT("HPOUT3L"),
SND_SOC_DAPM_OUTPUT("HPOUT3R"),
SND_SOC_DAPM_OUTPUT("SPKOUTLN"),
SND_SOC_DAPM_OUTPUT("SPKOUTLP"),
SND_SOC_DAPM_OUTPUT("SPKOUTRN"),
SND_SOC_DAPM_OUTPUT("SPKOUTRP"),
SND_SOC_DAPM_OUTPUT("SPKDAT1L"),
SND_SOC_DAPM_OUTPUT("SPKDAT1R"),
SND_SOC_DAPM_OUTPUT("SPKDAT2L"),
SND_SOC_DAPM_OUTPUT("SPKDAT2R"),
SND_SOC_DAPM_OUTPUT("SPDIF"),

SND_SOC_DAPM_OUTPUT("MICSUPP"),
};

#define ARIZONA_MIXER_INPUT_ROUTES(name)	\
	{ name, "Noise Generator", "Noise Generator" }, \
	{ name, "Tone Generator 1", "Tone Generator 1" }, \
	{ name, "Tone Generator 2", "Tone Generator 2" }, \
	{ name, "Haptics", "HAPTICS" }, \
	{ name, "AEC", "AEC1 Loopback" }, \
	{ name, "AEC2", "AEC2 Loopback" }, \
	{ name, "IN1L", "IN1L PGA" }, \
	{ name, "IN1R", "IN1R PGA" }, \
	{ name, "IN2L", "IN2L PGA" }, \
	{ name, "IN2R", "IN2R PGA" }, \
	{ name, "IN3L", "IN3L PGA" }, \
	{ name, "IN3R", "IN3R PGA" }, \
	{ name, "IN4L", "IN4L PGA" }, \
	{ name, "IN4R", "IN4R PGA" }, \
	{ name, "IN5L", "IN5L PGA" }, \
	{ name, "IN5R", "IN5R PGA" }, \
	{ name, "IN6L", "IN6L PGA" }, \
	{ name, "IN6R", "IN6R PGA" }, \
	{ name, "AIF1RX1", "AIF1RX1" }, \
	{ name, "AIF1RX2", "AIF1RX2" }, \
	{ name, "AIF1RX3", "AIF1RX3" }, \
	{ name, "AIF1RX4", "AIF1RX4" }, \
	{ name, "AIF1RX5", "AIF1RX5" }, \
	{ name, "AIF1RX6", "AIF1RX6" }, \
	{ name, "AIF1RX7", "AIF1RX7" }, \
	{ name, "AIF1RX8", "AIF1RX8" }, \
	{ name, "AIF2RX1", "AIF2RX1" }, \
	{ name, "AIF2RX2", "AIF2RX2" }, \
	{ name, "AIF2RX3", "AIF2RX3" }, \
	{ name, "AIF2RX4", "AIF2RX4" }, \
	{ name, "AIF2RX5", "AIF2RX5" }, \
	{ name, "AIF2RX6", "AIF2RX6" }, \
	{ name, "AIF2RX7", "AIF2RX7" }, \
	{ name, "AIF2RX8", "AIF2RX8" }, \
	{ name, "AIF3RX1", "AIF3RX1" }, \
	{ name, "AIF3RX2", "AIF3RX2" }, \
	{ name, "AIF4RX1", "AIF4RX1" }, \
	{ name, "AIF4RX2", "AIF4RX2" }, \
	{ name, "SLIMRX1", "SLIMRX1" }, \
	{ name, "SLIMRX2", "SLIMRX2" }, \
	{ name, "SLIMRX3", "SLIMRX3" }, \
	{ name, "SLIMRX4", "SLIMRX4" }, \
	{ name, "SLIMRX5", "SLIMRX5" }, \
	{ name, "SLIMRX6", "SLIMRX6" }, \
	{ name, "SLIMRX7", "SLIMRX7" }, \
	{ name, "SLIMRX8", "SLIMRX8" }, \
	{ name, "EQ1", "EQ1" }, \
	{ name, "EQ2", "EQ2" }, \
	{ name, "EQ3", "EQ3" }, \
	{ name, "EQ4", "EQ4" }, \
	{ name, "DRC1L", "DRC1L" }, \
	{ name, "DRC1R", "DRC1R" }, \
	{ name, "DRC2L", "DRC2L" }, \
	{ name, "DRC2R", "DRC2R" }, \
	{ name, "LHPF1", "LHPF1" }, \
	{ name, "LHPF2", "LHPF2" }, \
	{ name, "LHPF3", "LHPF3" }, \
	{ name, "LHPF4", "LHPF4" }, \
	{ name, "ASRC1IN1L", "ASRC1IN1L" }, \
	{ name, "ASRC1IN1R", "ASRC1IN1R" }, \
	{ name, "ASRC1IN2L", "ASRC1IN2L" }, \
	{ name, "ASRC1IN2R", "ASRC1IN2R" }, \
	{ name, "ASRC2IN1L", "ASRC2IN1L" }, \
	{ name, "ASRC2IN1R", "ASRC2IN1R" }, \
	{ name, "ASRC2IN2L", "ASRC2IN2L" }, \
	{ name, "ASRC2IN2R", "ASRC2IN2R" }, \
	{ name, "ISRC1DEC1", "ISRC1DEC1" }, \
	{ name, "ISRC1DEC2", "ISRC1DEC2" }, \
	{ name, "ISRC1DEC3", "ISRC1DEC3" }, \
	{ name, "ISRC1DEC4", "ISRC1DEC4" }, \
	{ name, "ISRC1INT1", "ISRC1INT1" }, \
	{ name, "ISRC1INT2", "ISRC1INT2" }, \
	{ name, "ISRC1INT3", "ISRC1INT3" }, \
	{ name, "ISRC1INT4", "ISRC1INT4" }, \
	{ name, "ISRC2DEC1", "ISRC2DEC1" }, \
	{ name, "ISRC2DEC2", "ISRC2DEC2" }, \
	{ name, "ISRC2DEC3", "ISRC2DEC3" }, \
	{ name, "ISRC2DEC4", "ISRC2DEC4" }, \
	{ name, "ISRC2INT1", "ISRC2INT1" }, \
	{ name, "ISRC2INT2", "ISRC2INT2" }, \
	{ name, "ISRC2INT3", "ISRC2INT3" }, \
	{ name, "ISRC2INT4", "ISRC2INT4" }, \
	{ name, "ISRC3DEC1", "ISRC3DEC1" }, \
	{ name, "ISRC3DEC2", "ISRC3DEC2" }, \
	{ name, "ISRC3INT1", "ISRC3INT1" }, \
	{ name, "ISRC3INT2", "ISRC3INT2" }, \
	{ name, "ISRC4DEC1", "ISRC4DEC1" }, \
	{ name, "ISRC4DEC2", "ISRC4DEC2" }, \
	{ name, "ISRC4INT1", "ISRC4INT1" }, \
	{ name, "ISRC4INT2", "ISRC4INT2" }, \
	{ name, "DSP1.1", "DSP1" }, \
	{ name, "DSP1.2", "DSP1" }, \
	{ name, "DSP1.3", "DSP1" }, \
	{ name, "DSP1.4", "DSP1" }, \
	{ name, "DSP1.5", "DSP1" }, \
	{ name, "DSP1.6", "DSP1" }, \
	{ name, "DSP2.1", "DSP2" }, \
	{ name, "DSP2.2", "DSP2" }, \
	{ name, "DSP2.3", "DSP2" }, \
	{ name, "DSP2.4", "DSP2" }, \
	{ name, "DSP2.5", "DSP2" }, \
	{ name, "DSP2.6", "DSP2" }, \
	{ name, "DSP3.1", "DSP3" }, \
	{ name, "DSP3.2", "DSP3" }, \
	{ name, "DSP3.3", "DSP3" }, \
	{ name, "DSP3.4", "DSP3" }, \
	{ name, "DSP3.5", "DSP3" }, \
	{ name, "DSP3.6", "DSP3" }, \
	{ name, "DSP4.1", "DSP4" }, \
	{ name, "DSP4.2", "DSP4" }, \
	{ name, "DSP4.3", "DSP4" }, \
	{ name, "DSP4.4", "DSP4" }, \
	{ name, "DSP4.5", "DSP4" }, \
	{ name, "DSP4.6", "DSP4" }, \
	{ name, "DSP5.1", "DSP5" }, \
	{ name, "DSP5.2", "DSP5" }, \
	{ name, "DSP5.3", "DSP5" }, \
	{ name, "DSP5.4", "DSP5" }, \
	{ name, "DSP5.5", "DSP5" }, \
	{ name, "DSP5.6", "DSP5" }, \
	{ name, "DSP6.1", "DSP6" }, \
	{ name, "DSP6.2", "DSP6" }, \
	{ name, "DSP6.3", "DSP6" }, \
	{ name, "DSP6.4", "DSP6" }, \
	{ name, "DSP6.5", "DSP6" }, \
	{ name, "DSP6.6", "DSP6" }, \
	{ name, "DSP7.1", "DSP7" }, \
	{ name, "DSP7.2", "DSP7" }, \
	{ name, "DSP7.3", "DSP7" }, \
	{ name, "DSP7.4", "DSP7" }, \
	{ name, "DSP7.5", "DSP7" }, \
	{ name, "DSP7.6", "DSP7" }

static const struct snd_soc_dapm_route clearwater_dapm_routes[] = {
	{ "AIF2 Capture", NULL, "DBVDD2" },
	{ "AIF2 Playback", NULL, "DBVDD2" },

	{ "AIF3 Capture", NULL, "DBVDD3" },
	{ "AIF3 Playback", NULL, "DBVDD3" },

	{ "AIF4 Capture", NULL, "DBVDD3" },
	{ "AIF4 Playback", NULL, "DBVDD3" },

	{ "OUT1L", NULL, "CPVDD" },
	{ "OUT1R", NULL, "CPVDD" },
	{ "OUT2L", NULL, "CPVDD" },
	{ "OUT2R", NULL, "CPVDD" },
	{ "OUT3L", NULL, "CPVDD" },
	{ "OUT3R", NULL, "CPVDD" },

	{ "OUT4L", NULL, "SPKVDDL" },
	{ "OUT4R", NULL, "SPKVDDR" },

	{ "OUT1L", NULL, "SYSCLK" },
	{ "OUT1R", NULL, "SYSCLK" },
	{ "OUT2L", NULL, "SYSCLK" },
	{ "OUT2R", NULL, "SYSCLK" },
	{ "OUT3L", NULL, "SYSCLK" },
	{ "OUT3R", NULL, "SYSCLK" },
	{ "OUT4L", NULL, "SYSCLK" },
	{ "OUT4R", NULL, "SYSCLK" },
	{ "OUT5L", NULL, "SYSCLK" },
	{ "OUT5R", NULL, "SYSCLK" },
	{ "OUT6L", NULL, "SYSCLK" },
	{ "OUT6R", NULL, "SYSCLK" },

	{ "SPD1", NULL, "SYSCLK" },
	{ "SPD1", NULL, "SPD1TX1" },
	{ "SPD1", NULL, "SPD1TX2" },

	{ "IN1AL", NULL, "SYSCLK" },
	{ "IN1B", NULL, "SYSCLK" },
	{ "IN1R", NULL, "SYSCLK" },
	{ "IN2AL", NULL, "SYSCLK" },
	{ "IN2AR", NULL, "SYSCLK" },
	{ "IN2BL", NULL, "SYSCLK" },
	{ "IN2BR", NULL, "SYSCLK" },
	{ "IN3L", NULL, "SYSCLK" },
	{ "IN3R", NULL, "SYSCLK" },
	{ "IN4L", NULL, "SYSCLK" },
	{ "IN4R", NULL, "SYSCLK" },
	{ "IN5L", NULL, "SYSCLK" },
	{ "IN5R", NULL, "SYSCLK" },
	{ "IN6L", NULL, "SYSCLK" },
	{ "IN6R", NULL, "SYSCLK" },

	{ "IN4L", NULL, "DBVDD4" },
	{ "IN4R", NULL, "DBVDD4" },
	{ "IN5L", NULL, "DBVDD4" },
	{ "IN5R", NULL, "DBVDD4" },
	{ "IN6L", NULL, "DBVDD4" },
	{ "IN6R", NULL, "DBVDD4" },

	{ "DSP1", NULL, "DSPCLK"},
	{ "DSP2", NULL, "DSPCLK"},
	{ "DSP3", NULL, "DSPCLK"},
	{ "DSP4", NULL, "DSPCLK"},
	{ "DSP5", NULL, "DSPCLK"},
	{ "DSP6", NULL, "DSPCLK"},
	{ "DSP7", NULL, "DSPCLK"},

	{ "MICBIAS1", NULL, "MICVDD" },
	{ "MICBIAS2", NULL, "MICVDD" },
	{ "MICBIAS3", NULL, "MICVDD" },
	{ "MICBIAS4", NULL, "MICVDD" },

	{ "Noise Generator", NULL, "SYSCLK" },
	{ "Tone Generator 1", NULL, "SYSCLK" },
	{ "Tone Generator 2", NULL, "SYSCLK" },

	{ "Noise Generator", NULL, "NOISE" },
	{ "Tone Generator 1", NULL, "TONE" },
	{ "Tone Generator 2", NULL, "TONE" },

	{ "AIF1 Capture", NULL, "AIF1TX1" },
	{ "AIF1 Capture", NULL, "AIF1TX2" },
	{ "AIF1 Capture", NULL, "AIF1TX3" },
	{ "AIF1 Capture", NULL, "AIF1TX4" },
	{ "AIF1 Capture", NULL, "AIF1TX5" },
	{ "AIF1 Capture", NULL, "AIF1TX6" },
	{ "AIF1 Capture", NULL, "AIF1TX7" },
	{ "AIF1 Capture", NULL, "AIF1TX8" },

	{ "AIF1RX1", NULL, "AIF1 Playback" },
	{ "AIF1RX2", NULL, "AIF1 Playback" },
	{ "AIF1RX3", NULL, "AIF1 Playback" },
	{ "AIF1RX4", NULL, "AIF1 Playback" },
	{ "AIF1RX5", NULL, "AIF1 Playback" },
	{ "AIF1RX6", NULL, "AIF1 Playback" },
	{ "AIF1RX7", NULL, "AIF1 Playback" },
	{ "AIF1RX8", NULL, "AIF1 Playback" },

	{ "AIF2 Capture", NULL, "AIF2TX1" },
	{ "AIF2 Capture", NULL, "AIF2TX2" },
	{ "AIF2 Capture", NULL, "AIF2TX3" },
	{ "AIF2 Capture", NULL, "AIF2TX4" },
	{ "AIF2 Capture", NULL, "AIF2TX5" },
	{ "AIF2 Capture", NULL, "AIF2TX6" },
	{ "AIF2 Capture", NULL, "AIF2TX7" },
	{ "AIF2 Capture", NULL, "AIF2TX8" },

	{ "AIF2RX1", NULL, "AIF2 Playback" },
	{ "AIF2RX2", NULL, "AIF2 Playback" },
	{ "AIF2RX3", NULL, "AIF2 Playback" },
	{ "AIF2RX4", NULL, "AIF2 Playback" },
	{ "AIF2RX5", NULL, "AIF2 Playback" },
	{ "AIF2RX6", NULL, "AIF2 Playback" },
	{ "AIF2RX7", NULL, "AIF2 Playback" },
	{ "AIF2RX8", NULL, "AIF2 Playback" },

	{ "AIF3 Capture", NULL, "AIF3TX1" },
	{ "AIF3 Capture", NULL, "AIF3TX2" },

	{ "AIF3RX1", NULL, "AIF3 Playback" },
	{ "AIF3RX2", NULL, "AIF3 Playback" },

	{ "AIF4 Capture", NULL, "AIF4TX1" },
	{ "AIF4 Capture", NULL, "AIF4TX2" },

	{ "AIF4RX1", NULL, "AIF4 Playback" },
	{ "AIF4RX2", NULL, "AIF4 Playback" },

	{ "Slim1 Capture", NULL, "SLIMTX1" },
	{ "Slim1 Capture", NULL, "SLIMTX2" },
	{ "Slim1 Capture", NULL, "SLIMTX3" },
	{ "Slim1 Capture", NULL, "SLIMTX4" },

	{ "SLIMRX1", NULL, "Slim1 Playback" },
	{ "SLIMRX2", NULL, "Slim1 Playback" },
	{ "SLIMRX3", NULL, "Slim1 Playback" },
	{ "SLIMRX4", NULL, "Slim1 Playback" },

	{ "Slim2 Capture", NULL, "SLIMTX5" },
	{ "Slim2 Capture", NULL, "SLIMTX6" },

	{ "SLIMRX5", NULL, "Slim2 Playback" },
	{ "SLIMRX6", NULL, "Slim2 Playback" },

	{ "Slim3 Capture", NULL, "SLIMTX7" },
	{ "Slim3 Capture", NULL, "SLIMTX8" },

	{ "SLIMRX7", NULL, "Slim3 Playback" },
	{ "SLIMRX8", NULL, "Slim3 Playback" },

	{ "AIF1 Playback", NULL, "SYSCLK" },
	{ "AIF2 Playback", NULL, "SYSCLK" },
	{ "AIF3 Playback", NULL, "SYSCLK" },
	{ "AIF4 Playback", NULL, "SYSCLK" },
	{ "Slim1 Playback", NULL, "SYSCLK" },
	{ "Slim2 Playback", NULL, "SYSCLK" },
	{ "Slim3 Playback", NULL, "SYSCLK" },

	{ "AIF1 Capture", NULL, "SYSCLK" },
	{ "AIF2 Capture", NULL, "SYSCLK" },
	{ "AIF3 Capture", NULL, "SYSCLK" },
	{ "AIF4 Capture", NULL, "SYSCLK" },
	{ "Slim1 Capture", NULL, "SYSCLK" },
	{ "Slim2 Capture", NULL, "SYSCLK" },
	{ "Slim3 Capture", NULL, "SYSCLK" },

	{ "Voice Control CPU", NULL, "Voice Control DSP" },
	{ "Voice Control DSP", NULL, "DSP6" },
	{ "Voice Control CPU", NULL, "SYSCLK" },
	{ "Voice Control DSP", NULL, "SYSCLK" },

	{ "Trace CPU", NULL, "Trace DSP" },
	{ "Trace DSP", NULL, "DSP1" },
	{ "Trace CPU", NULL, "SYSCLK" },
	{ "Trace DSP", NULL, "SYSCLK" },

	{ "IN1L Mux", "A", "IN1AL" },
	{ "IN1L Mux", "B", "IN1B" },

	{ "IN2L Mux", "A", "IN2AL" },
	{ "IN2L Mux", "B", "IN2BL" },
	{ "IN2R Mux", "A", "IN2AR" },
	{ "IN2R Mux", "B", "IN2BR" },

	{ "IN1L PGA", NULL, "IN1L Mux" },
	{ "IN1R PGA", NULL, "IN1R" },

	{ "IN2L PGA", NULL, "IN2L Mux" },
	{ "IN2R PGA", NULL, "IN2R Mux" },

	{ "IN3L PGA", NULL, "IN3L" },
	{ "IN3R PGA", NULL, "IN3R" },

	{ "IN4L PGA", NULL, "IN4L" },
	{ "IN4R PGA", NULL, "IN4R" },

	{ "IN5L PGA", NULL, "IN5L" },
	{ "IN5R PGA", NULL, "IN5R" },

	{ "IN6L PGA", NULL, "IN6L" },
	{ "IN6R PGA", NULL, "IN6R" },

	ARIZONA_MIXER_ROUTES("OUT1L", "HPOUT1L"),
	ARIZONA_MIXER_ROUTES("OUT1R", "HPOUT1R"),
	ARIZONA_MIXER_ROUTES("OUT2L", "HPOUT2L"),
	ARIZONA_MIXER_ROUTES("OUT2R", "HPOUT2R"),
	ARIZONA_MIXER_ROUTES("OUT3L", "HPOUT3L"),
	ARIZONA_MIXER_ROUTES("OUT3R", "HPOUT3R"),

	ARIZONA_MIXER_ROUTES("OUT4L", "SPKOUTL"),
	ARIZONA_MIXER_ROUTES("OUT4R", "SPKOUTR"),
	ARIZONA_MIXER_ROUTES("OUT5L", "SPKDAT1L"),
	ARIZONA_MIXER_ROUTES("OUT5R", "SPKDAT1R"),
	ARIZONA_MIXER_ROUTES("OUT6L", "SPKDAT2L"),
	ARIZONA_MIXER_ROUTES("OUT6R", "SPKDAT2R"),

	ARIZONA_MIXER_ROUTES("PWM1 Driver", "PWM1"),
	ARIZONA_MIXER_ROUTES("PWM2 Driver", "PWM2"),

	ARIZONA_MIXER_ROUTES("AIF1TX1", "AIF1TX1"),
	ARIZONA_MIXER_ROUTES("AIF1TX2", "AIF1TX2"),
	ARIZONA_MIXER_ROUTES("AIF1TX3", "AIF1TX3"),
	ARIZONA_MIXER_ROUTES("AIF1TX4", "AIF1TX4"),
	ARIZONA_MIXER_ROUTES("AIF1TX5", "AIF1TX5"),
	ARIZONA_MIXER_ROUTES("AIF1TX6", "AIF1TX6"),
	ARIZONA_MIXER_ROUTES("AIF1TX7", "AIF1TX7"),
	ARIZONA_MIXER_ROUTES("AIF1TX8", "AIF1TX8"),

	ARIZONA_MIXER_ROUTES("AIF2TX1", "AIF2TX1"),
	ARIZONA_MIXER_ROUTES("AIF2TX2", "AIF2TX2"),
	ARIZONA_MIXER_ROUTES("AIF2TX3", "AIF2TX3"),
	ARIZONA_MIXER_ROUTES("AIF2TX4", "AIF2TX4"),
	ARIZONA_MIXER_ROUTES("AIF2TX5", "AIF2TX5"),
	ARIZONA_MIXER_ROUTES("AIF2TX6", "AIF2TX6"),
	ARIZONA_MIXER_ROUTES("AIF2TX7", "AIF2TX7"),
	ARIZONA_MIXER_ROUTES("AIF2TX8", "AIF2TX8"),

	ARIZONA_MIXER_ROUTES("AIF3TX1", "AIF3TX1"),
	ARIZONA_MIXER_ROUTES("AIF3TX2", "AIF3TX2"),

	ARIZONA_MIXER_ROUTES("AIF4TX1", "AIF4TX1"),
	ARIZONA_MIXER_ROUTES("AIF4TX2", "AIF4TX2"),

	ARIZONA_MIXER_ROUTES("SLIMTX1", "SLIMTX1"),
	ARIZONA_MIXER_ROUTES("SLIMTX2", "SLIMTX2"),
	ARIZONA_MIXER_ROUTES("SLIMTX3", "SLIMTX3"),
	ARIZONA_MIXER_ROUTES("SLIMTX4", "SLIMTX4"),
	ARIZONA_MIXER_ROUTES("SLIMTX5", "SLIMTX5"),
	ARIZONA_MIXER_ROUTES("SLIMTX6", "SLIMTX6"),
	ARIZONA_MIXER_ROUTES("SLIMTX7", "SLIMTX7"),
	ARIZONA_MIXER_ROUTES("SLIMTX8", "SLIMTX8"),

	ARIZONA_MUX_ROUTES("SPD1TX1", "SPDIFTX1"),
	ARIZONA_MUX_ROUTES("SPD1TX2", "SPDIFTX2"),

	ARIZONA_MIXER_ROUTES("EQ1", "EQ1"),
	ARIZONA_MIXER_ROUTES("EQ2", "EQ2"),
	ARIZONA_MIXER_ROUTES("EQ3", "EQ3"),
	ARIZONA_MIXER_ROUTES("EQ4", "EQ4"),

	ARIZONA_MIXER_ROUTES("DRC1L", "DRC1L"),
	ARIZONA_MIXER_ROUTES("DRC1R", "DRC1R"),
	ARIZONA_MIXER_ROUTES("DRC2L", "DRC2L"),
	ARIZONA_MIXER_ROUTES("DRC2R", "DRC2R"),

	ARIZONA_MIXER_ROUTES("LHPF1", "LHPF1"),
	ARIZONA_MIXER_ROUTES("LHPF2", "LHPF2"),
	ARIZONA_MIXER_ROUTES("LHPF3", "LHPF3"),
	ARIZONA_MIXER_ROUTES("LHPF4", "LHPF4"),

	ARIZONA_MUX_ROUTES("ASRC1IN1L", "ASRC1IN1L"),
	ARIZONA_MUX_ROUTES("ASRC1IN1R", "ASRC1IN1R"),
	ARIZONA_MUX_ROUTES("ASRC1IN2L", "ASRC1IN2L"),
	ARIZONA_MUX_ROUTES("ASRC1IN2R", "ASRC1IN2R"),
	ARIZONA_MUX_ROUTES("ASRC2IN1L", "ASRC2IN1L"),
	ARIZONA_MUX_ROUTES("ASRC2IN1R", "ASRC2IN1R"),
	ARIZONA_MUX_ROUTES("ASRC2IN2L", "ASRC2IN2L"),
	ARIZONA_MUX_ROUTES("ASRC2IN2R", "ASRC2IN2R"),

	ARIZONA_DSP_ROUTES("DSP1"),
	ARIZONA_DSP_ROUTES("DSP2"),
	ARIZONA_DSP_ROUTES("DSP3"),
	ARIZONA_DSP_ROUTES("DSP4"),
	ARIZONA_DSP_ROUTES("DSP5"),
	ARIZONA_DSP_ROUTES("DSP6"),
	ARIZONA_DSP_ROUTES("DSP7"),

	{ "DSP2 Preloader",  NULL, "DSP2 Virtual Input" },
	{ "DSP2 Virtual Input", "Shared Memory", "DSP3" },
	{ "DSP3 Preloader", NULL, "DSP3 Virtual Input" },
	{ "DSP3 Virtual Input", "Shared Memory", "DSP2" },

	{ "DSP Virtual Output", NULL, "DSP Virtual Output Mux" },
	{ "DSP Virtual Output Mux", "DSP6", "DSP6" },
	{ "DSP Virtual Output", NULL, "SYSCLK" },

	ARIZONA_MUX_ROUTES("ISRC1INT1", "ISRC1INT1"),
	ARIZONA_MUX_ROUTES("ISRC1INT2", "ISRC1INT2"),
	ARIZONA_MUX_ROUTES("ISRC1INT3", "ISRC1INT3"),
	ARIZONA_MUX_ROUTES("ISRC1INT4", "ISRC1INT4"),

	ARIZONA_MUX_ROUTES("ISRC1DEC1", "ISRC1DEC1"),
	ARIZONA_MUX_ROUTES("ISRC1DEC2", "ISRC1DEC2"),
	ARIZONA_MUX_ROUTES("ISRC1DEC3", "ISRC1DEC3"),
	ARIZONA_MUX_ROUTES("ISRC1DEC4", "ISRC1DEC4"),

	ARIZONA_MUX_ROUTES("ISRC2INT1", "ISRC2INT1"),
	ARIZONA_MUX_ROUTES("ISRC2INT2", "ISRC2INT2"),
	ARIZONA_MUX_ROUTES("ISRC2INT3", "ISRC2INT3"),
	ARIZONA_MUX_ROUTES("ISRC2INT4", "ISRC2INT4"),

	ARIZONA_MUX_ROUTES("ISRC2DEC1", "ISRC2DEC1"),
	ARIZONA_MUX_ROUTES("ISRC2DEC2", "ISRC2DEC2"),
	ARIZONA_MUX_ROUTES("ISRC2DEC3", "ISRC2DEC3"),
	ARIZONA_MUX_ROUTES("ISRC2DEC4", "ISRC2DEC4"),

	ARIZONA_MUX_ROUTES("ISRC3INT1", "ISRC3INT1"),
	ARIZONA_MUX_ROUTES("ISRC3INT2", "ISRC3INT2"),

	ARIZONA_MUX_ROUTES("ISRC3DEC1", "ISRC3DEC1"),
	ARIZONA_MUX_ROUTES("ISRC3DEC2", "ISRC3DEC2"),

	ARIZONA_MUX_ROUTES("ISRC4INT1", "ISRC4INT1"),
	ARIZONA_MUX_ROUTES("ISRC4INT2", "ISRC4INT2"),

	ARIZONA_MUX_ROUTES("ISRC4DEC1", "ISRC4DEC1"),
	ARIZONA_MUX_ROUTES("ISRC4DEC2", "ISRC4DEC2"),

	{ "AEC1 Loopback", "HPOUT1L", "OUT1L" },
	{ "AEC1 Loopback", "HPOUT1R", "OUT1R" },
	{ "AEC2 Loopback", "HPOUT1L", "OUT1L" },
	{ "AEC2 Loopback", "HPOUT1R", "OUT1R" },
	{ "HPOUT1L", NULL, "OUT1L" },
	{ "HPOUT1R", NULL, "OUT1R" },

	{ "AEC1 Loopback", "HPOUT2L", "OUT2L" },
	{ "AEC1 Loopback", "HPOUT2R", "OUT2R" },
	{ "AEC2 Loopback", "HPOUT2L", "OUT2L" },
	{ "AEC2 Loopback", "HPOUT2R", "OUT2R" },
	{ "HPOUT2L", NULL, "OUT2L" },
	{ "HPOUT2R", NULL, "OUT2R" },

	{ "AEC1 Loopback", "HPOUT3L", "OUT3L" },
	{ "AEC1 Loopback", "HPOUT3R", "OUT3R" },
	{ "AEC2 Loopback", "HPOUT3L", "OUT3L" },
	{ "AEC2 Loopback", "HPOUT3R", "OUT3R" },
	{ "HPOUT3L", NULL, "OUT3L" },
	{ "HPOUT3R", NULL, "OUT3R" },

	{ "AEC1 Loopback", "SPKOUTL", "OUT4L" },
	{ "AEC2 Loopback", "SPKOUTL", "OUT4L" },
	{ "SPKOUTLN", NULL, "OUT4L" },
	{ "SPKOUTLP", NULL, "OUT4L" },

	{ "AEC1 Loopback", "SPKOUTR", "OUT4R" },
	{ "AEC2 Loopback", "SPKOUTR", "OUT4R" },
	{ "SPKOUTRN", NULL, "OUT4R" },
	{ "SPKOUTRP", NULL, "OUT4R" },

	{ "AEC1 Loopback", "SPKDAT1L", "OUT5L" },
	{ "AEC1 Loopback", "SPKDAT1R", "OUT5R" },
	{ "AEC2 Loopback", "SPKDAT1L", "OUT5L" },
	{ "AEC2 Loopback", "SPKDAT1R", "OUT5R" },
	{ "SPKDAT1L", NULL, "OUT5L" },
	{ "SPKDAT1R", NULL, "OUT5R" },

	{ "AEC1 Loopback", "SPKDAT2L", "OUT6L" },
	{ "AEC1 Loopback", "SPKDAT2R", "OUT6R" },
	{ "AEC2 Loopback", "SPKDAT2L", "OUT6L" },
	{ "AEC2 Loopback", "SPKDAT2R", "OUT6R" },
	{ "SPKDAT2L", NULL, "OUT6L" },
	{ "SPKDAT2R", NULL, "OUT6R" },

	CLEARWATER_RXANC_INPUT_ROUTES("RXANCL", "RXANCL"),
	CLEARWATER_RXANC_INPUT_ROUTES("RXANCR", "RXANCR"),

	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT1L", "HPOUT1L"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT1R", "HPOUT1R"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT2L", "HPOUT2L"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT2R", "HPOUT2R"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT3L", "HPOUT3L"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT3R", "HPOUT3R"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT4L", "SPKOUTL"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT4R", "SPKOUTR"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT5L", "SPKDAT1L"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT5R", "SPKDAT1R"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT6L", "SPKDAT2L"),
	CLEARWATER_RXANC_OUTPUT_ROUTES("OUT6R", "SPKDAT2R"),

	{ "SPDIF", NULL, "SPD1" },

	{ "MICSUPP", NULL, "SYSCLK" },

	{ "DRC1 Signal Activity", NULL, "DRC1L" },
	{ "DRC1 Signal Activity", NULL, "DRC1R" },
	{ "DRC2 Signal Activity", NULL, "DRC2L" },
	{ "DRC2 Signal Activity", NULL, "DRC2R" },
};

static int clearwater_set_fll(struct snd_soc_codec *codec, int fll_id, int source,
			  unsigned int Fref, unsigned int Fout)
{
	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(codec);

	switch (fll_id) {
	case CLEARWATER_FLL1:
		return arizona_set_fll(&clearwater->fll[0], source, Fref, Fout);
	case CLEARWATER_FLL2:
		return arizona_set_fll(&clearwater->fll[1], source, Fref, Fout);
	case CLEARWATER_FLL3:
		return arizona_set_fll(&clearwater->fll[2], source, Fref, Fout);
	case CLEARWATER_FLL1_REFCLK:
		return arizona_set_fll_refclk(&clearwater->fll[0], source, Fref,
					      Fout);
	case CLEARWATER_FLL2_REFCLK:
		return arizona_set_fll_refclk(&clearwater->fll[1], source, Fref,
					      Fout);
	case CLEARWATER_FLL3_REFCLK:
		return arizona_set_fll_refclk(&clearwater->fll[2], source, Fref,
					      Fout);
	default:
		return -EINVAL;
	}
}

#define CLEARWATER_RATES SNDRV_PCM_RATE_KNOT

#define CLEARWATER_FORMATS (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S20_3LE |\
			SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE)

static struct snd_soc_dai_driver clearwater_dai[] = {
	{
		.name = "clearwater-aif1",
		.id = 1,
		.base = ARIZONA_AIF1_BCLK_CTRL,
		.playback = {
			.stream_name = "AIF1 Playback",
			.channels_min = 1,
			.channels_max = 8,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "AIF1 Capture",
			 .channels_min = 1,
			 .channels_max = 8,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "clearwater-aif2",
		.id = 2,
		.base = ARIZONA_AIF2_BCLK_CTRL,
		.playback = {
			.stream_name = "AIF2 Playback",
			.channels_min = 1,
			.channels_max = 8,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "AIF2 Capture",
			 .channels_min = 1,
			 .channels_max = 8,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "clearwater-aif3",
		.id = 3,
		.base = ARIZONA_AIF3_BCLK_CTRL,
		.playback = {
			.stream_name = "AIF3 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "AIF3 Capture",
			 .channels_min = 1,
			 .channels_max = 2,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "clearwater-aif4",
		.id = 4,
		.base = ARIZONA_AIF4_BCLK_CTRL,
		.playback = {
			.stream_name = "AIF4 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "AIF4 Capture",
			 .channels_min = 1,
			 .channels_max = 2,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "clearwater-slim1",
		.id = 5,
		.playback = {
			.stream_name = "Slim1 Playback",
			.channels_min = 1,
			.channels_max = 4,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "Slim1 Capture",
			 .channels_min = 1,
			 .channels_max = 4,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_simple_dai_ops,
	},
	{
		.name = "clearwater-slim2",
		.id = 6,
		.playback = {
			.stream_name = "Slim2 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "Slim2 Capture",
			 .channels_min = 1,
			 .channels_max = 2,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_simple_dai_ops,
	},
	{
		.name = "clearwater-slim3",
		.id = 7,
		.playback = {
			.stream_name = "Slim3 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.capture = {
			 .stream_name = "Slim3 Capture",
			 .channels_min = 1,
			 .channels_max = 2,
			 .rates = CLEARWATER_RATES,
			 .formats = CLEARWATER_FORMATS,
		 },
		.ops = &arizona_simple_dai_ops,
	},
	{
		.name = "clearwater-cpu-voicectrl",
		.capture = {
			.stream_name = "Voice Control CPU",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.compress_dai = 1,
	},
	{
		.name = "clearwater-dsp-voicectrl",
		.capture = {
			.stream_name = "Voice Control DSP",
			.channels_min = 1,
			.channels_max = 2,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
	},
	{
		.name = "clearwater-cpu-trace",
		.capture = {
			.stream_name = "Trace CPU",
			.channels_min = 2,
			.channels_max = 8,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
		.compress_dai = 1,
	},
	{
		.name = "clearwater-dsp-trace",
		.capture = {
			.stream_name = "Trace DSP",
			.channels_min = 2,
			.channels_max = 8,
			.rates = CLEARWATER_RATES,
			.formats = CLEARWATER_FORMATS,
		},
	},
};

static void clearwater_compr_irq(struct clearwater_priv *clearwater,
				 struct clearwater_compr *compr)
{
	struct arizona *arizona = clearwater->core.arizona;
	bool trigger = false;
	int ret;

	ret = wm_adsp_compr_irq(&compr->adsp_compr, &trigger);
	if (ret < 0)
		return;

	if (trigger && arizona->pdata.ez2ctrl_trigger) {
		mutex_lock(&compr->trig_lock);
		if (!compr->trig) {
			compr->trig = true;

			if (wm_adsp_fw_has_voice_trig(compr->adsp_compr.dsp))
				arizona->pdata.ez2ctrl_trigger();
		}
		mutex_unlock(&compr->trig_lock);
	}
}

static irqreturn_t clearwater_adsp2_irq(int irq, void *data)
{
	struct clearwater_priv *clearwater = data;
	int i;

	for (i = 0; i < ARRAY_SIZE(clearwater->compr_info); ++i) {
		if (!clearwater->compr_info[i].adsp_compr.dsp->running)
			continue;

		clearwater_compr_irq(clearwater, &clearwater->compr_info[i]);
	}
	return IRQ_HANDLED;
}

static struct clearwater_compr *clearwater_get_compr(
					struct snd_soc_pcm_runtime *rtd,
					struct clearwater_priv *clearwater)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(clearwater->compr_info); ++i) {
		if (strcmp(rtd->codec_dai->name,
			   clearwater->compr_info[i].dai_name) == 0)
			return &clearwater->compr_info[i];
	}

	return NULL;
}

static int clearwater_compr_open(struct snd_compr_stream *stream)
{
	struct snd_soc_pcm_runtime *rtd = stream->private_data;
	struct clearwater_priv *clearwater = snd_soc_codec_get_drvdata(rtd->codec);
	struct clearwater_compr *compr;

	compr = clearwater_get_compr(rtd, clearwater);
	if (!compr) {
		dev_err(clearwater->core.arizona->dev,
			"No compressed stream for dai '%s'\n",
			rtd->codec_dai->name);
		return -EINVAL;
	}

	return wm_adsp_compr_open(&compr->adsp_compr, stream);
}

static int clearwater_compr_trigger(struct snd_compr_stream *stream, int cmd)
{
	struct wm_adsp_compr *adsp_compr =
			(struct wm_adsp_compr *)stream->runtime->private_data;
	struct clearwater_compr *compr = container_of(adsp_compr,
						      struct clearwater_compr,
						      adsp_compr);
	struct arizona *arizona = compr->priv->core.arizona;
	int ret;

	ret = wm_adsp_compr_trigger(stream, cmd);

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		if (compr->trig)
			/*
			 * If the firmware already triggered before the stream
			 * was opened trigger another interrupt so irq handler
			 * will run and process any outstanding data
			 */
			regmap_write(arizona->regmap,
				     CLEARWATER_ADSP2_IRQ0, 0x01);
		break;
	default:
		break;
	}

	return ret;
}

static int clearwater_codec_probe(struct snd_soc_codec *codec)
{
	struct clearwater_priv *priv = snd_soc_codec_get_drvdata(codec);
	struct arizona *arizona = priv->core.arizona;
	int i, ret;

	priv->core.arizona->dapm = &codec->dapm;

	arizona_init_spk(codec);
	arizona_init_gpio(codec);
	arizona_init_mono(codec);
	arizona_init_input(codec);

	for (i = 0; i < CLEARWATER_NUM_ADSP; ++i) {
		ret = wm_adsp2_codec_probe(&priv->core.adsp[i], codec);
		if (ret)
			return ret;
	}

	ret = snd_soc_add_codec_controls(codec,
					 arizona_adsp2v2_rate_controls,
					 CLEARWATER_NUM_ADSP);
	if (ret)
		return ret;

	/* Update Sample Rate 1 to 48kHz for cases when no AIF1 hw_params */
	regmap_update_bits(arizona->regmap, ARIZONA_SAMPLE_RATE_1,
			   ARIZONA_SAMPLE_RATE_1_MASK, 0x03);

	snd_soc_dapm_disable_pin(&codec->dapm, "HAPTICS");

	priv->core.arizona->dapm = &codec->dapm;

	ret = arizona_request_irq(arizona, ARIZONA_IRQ_DSP_IRQ1,
				  "ADSP2 interrupt 1",
				  clearwater_adsp2_irq, priv);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to request DSP IRQ: %d\n", ret);
		return ret;
	}

	ret = irq_set_irq_wake(arizona->irq, 1);
	if (ret)
		dev_err(arizona->dev,
			"Failed to set DSP IRQ to wake source: %d\n",
			ret);

	snd_soc_dapm_enable_pin(&codec->dapm, "DRC2 Signal Activity");

	ret = regmap_update_bits(arizona->regmap, CLEARWATER_IRQ2_MASK_9,
				 CLEARWATER_DRC2_SIG_DET_EINT2,
				 0);
	if (ret != 0) {
		dev_err(arizona->dev,
			"Failed to unmask DRC2 IRQ for DSP: %d\n",
			ret);
		return ret;
	}

	return 0;
}

static int clearwater_codec_remove(struct snd_soc_codec *codec)
{
	struct clearwater_priv *priv = snd_soc_codec_get_drvdata(codec);
	struct arizona *arizona = priv->core.arizona;
	int i;

	irq_set_irq_wake(arizona->irq, 0);
	arizona_free_irq(arizona, ARIZONA_IRQ_DSP_IRQ1, priv);
	regmap_update_bits(arizona->regmap, CLEARWATER_IRQ2_MASK_9,
			   CLEARWATER_DRC2_SIG_DET_EINT2,
			   CLEARWATER_DRC2_SIG_DET_EINT2);

	for (i = 0; i < CLEARWATER_NUM_ADSP; ++i)
		wm_adsp2_codec_remove(&priv->core.adsp[i], codec);

	priv->core.arizona->dapm = NULL;

	return 0;
}

#define CLEARWATER_DIG_VU 0x0200

static unsigned int clearwater_digital_vu[] = {
	ARIZONA_DAC_DIGITAL_VOLUME_1L,
	ARIZONA_DAC_DIGITAL_VOLUME_1R,
	ARIZONA_DAC_DIGITAL_VOLUME_2L,
	ARIZONA_DAC_DIGITAL_VOLUME_2R,
	ARIZONA_DAC_DIGITAL_VOLUME_3L,
	ARIZONA_DAC_DIGITAL_VOLUME_3R,
	ARIZONA_DAC_DIGITAL_VOLUME_4L,
	ARIZONA_DAC_DIGITAL_VOLUME_4R,
	ARIZONA_DAC_DIGITAL_VOLUME_5L,
	ARIZONA_DAC_DIGITAL_VOLUME_5R,
	ARIZONA_DAC_DIGITAL_VOLUME_6L,
	ARIZONA_DAC_DIGITAL_VOLUME_6R,
};

static struct regmap *clearwater_get_regmap(struct device *dev)
{
	struct clearwater_priv *priv = dev_get_drvdata(dev);

	return priv->core.arizona->regmap;
}

static struct snd_soc_codec_driver soc_codec_dev_clearwater = {
	.probe = clearwater_codec_probe,
	.remove = clearwater_codec_remove,
	.get_regmap = clearwater_get_regmap,

	.idle_bias_off = true,

	.set_sysclk = arizona_set_sysclk,
	.set_pll = clearwater_set_fll,

	.controls = clearwater_snd_controls,
	.num_controls = ARRAY_SIZE(clearwater_snd_controls),
	.dapm_widgets = clearwater_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(clearwater_dapm_widgets),
	.dapm_routes = clearwater_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(clearwater_dapm_routes),
};

static struct snd_compr_ops clearwater_compr_ops = {
	.open = clearwater_compr_open,
	.free = wm_adsp_compr_free,
	.set_params = wm_adsp_compr_set_params,
	.trigger = clearwater_compr_trigger,
	.pointer = wm_adsp_compr_pointer,
	.copy = wm_adsp_compr_copy,
	.get_caps = wm_adsp_compr_get_caps,
};

static struct snd_soc_platform_driver clearwater_compr_platform = {
	.compr_ops = &clearwater_compr_ops,
};

static void clearwater_init_compr_info(struct clearwater_priv *clearwater)
{
	struct wm_adsp *dsp;
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(clearwater->compr_info) !=
		     ARRAY_SIZE(compr_dai_mapping));

	for (i = 0; i < ARRAY_SIZE(clearwater->compr_info); ++i) {
		clearwater->compr_info[i].priv = clearwater;

		clearwater->compr_info[i].dai_name =
			compr_dai_mapping[i].dai_name;

		dsp = &clearwater->core.adsp[compr_dai_mapping[i].adsp_num],
		wm_adsp_compr_init(dsp, &clearwater->compr_info[i].adsp_compr);

		mutex_init(&clearwater->compr_info[i].trig_lock);
	}
}

static void clearwater_destroy_compr_info(struct clearwater_priv *clearwater)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(clearwater->compr_info); ++i)
		wm_adsp_compr_destroy(&clearwater->compr_info[i].adsp_compr);
}

static int clearwater_probe(struct platform_device *pdev)
{
	struct arizona *arizona = dev_get_drvdata(pdev->dev.parent);
	struct clearwater_priv *clearwater;
	int i, ret;

	BUILD_BUG_ON(ARRAY_SIZE(clearwater_dai) > ARIZONA_MAX_DAI);

	clearwater = devm_kzalloc(&pdev->dev, sizeof(struct clearwater_priv),
			      GFP_KERNEL);
	if (clearwater == NULL)
		return -ENOMEM;
	platform_set_drvdata(pdev, clearwater);

	/* Set of_node to parent from the SPI device to allow DAPM to
	 * locate regulator supplies */
	pdev->dev.of_node = arizona->dev->of_node;

	mutex_init(&clearwater->fw_lock);

	clearwater->core.arizona = arizona;
	clearwater->core.num_inputs = 8;

	for (i = 0; i < CLEARWATER_NUM_ADSP; i++) {
		clearwater->core.adsp[i].part = "clearwater";
		if (arizona->pdata.rev_specific_fw)
			clearwater->core.adsp[i].part_rev = 'a' + arizona->rev;
		clearwater->core.adsp[i].num = i + 1;
		clearwater->core.adsp[i].type = WMFW_ADSP2;
		clearwater->core.adsp[i].rev = 1;
		clearwater->core.adsp[i].dev = arizona->dev;
		clearwater->core.adsp[i].regmap = arizona->regmap_32bit;

		clearwater->core.adsp[i].base = wm_adsp2_control_bases[i];
		clearwater->core.adsp[i].mem = clearwater_dsp_regions[i];
		clearwater->core.adsp[i].num_mems
			= ARRAY_SIZE(clearwater_dsp1_regions);

		if (arizona->pdata.num_fw_defs[i]) {
			clearwater->core.adsp[i].firmwares
				= arizona->pdata.fw_defs[i];

			clearwater->core.adsp[i].num_firmwares
				= arizona->pdata.num_fw_defs[i];
		}

		clearwater->core.adsp[i].rate_put_cb =
					clearwater_adsp_rate_put_cb;

		clearwater->core.adsp[i].hpimp_cb = arizona_hpimp_cb;

		ret = wm_adsp2_init(&clearwater->core.adsp[i], &clearwater->fw_lock);
		if (ret != 0)
			return ret;
	}

	clearwater_init_compr_info(clearwater);

	for (i = 0; i < ARRAY_SIZE(clearwater->fll); i++) {
		clearwater->fll[i].vco_mult = 3;
		clearwater->fll[i].min_outdiv = 3;
		clearwater->fll[i].max_outdiv = 3;
	}

	arizona_init_fll(arizona, 1, ARIZONA_FLL1_CONTROL_1 - 1,
			 ARIZONA_IRQ_FLL1_LOCK, ARIZONA_IRQ_FLL1_CLOCK_OK,
			 &clearwater->fll[0]);
	arizona_init_fll(arizona, 2, ARIZONA_FLL2_CONTROL_1 - 1,
			 ARIZONA_IRQ_FLL2_LOCK, ARIZONA_IRQ_FLL2_CLOCK_OK,
			 &clearwater->fll[1]);
	arizona_init_fll(arizona, 3, ARIZONA_FLL3_CONTROL_1 - 1,
			 ARIZONA_IRQ_FLL3_LOCK, ARIZONA_IRQ_FLL3_CLOCK_OK,
			 &clearwater->fll[2]);

	for (i = 0; i < ARRAY_SIZE(clearwater_dai); i++)
		arizona_init_dai(&clearwater->core, i);

	/* Latch volume update bits */
	for (i = 0; i < ARRAY_SIZE(clearwater_digital_vu); i++)
		regmap_update_bits(arizona->regmap, clearwater_digital_vu[i],
				   CLEARWATER_DIG_VU, CLEARWATER_DIG_VU);

	pm_runtime_enable(&pdev->dev);
	pm_runtime_idle(&pdev->dev);

	ret = snd_soc_register_platform(&pdev->dev, &clearwater_compr_platform);
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Failed to register platform: %d\n",
			ret);
		goto error;
	}

	ret = snd_soc_register_codec(&pdev->dev, &soc_codec_dev_clearwater,
				      clearwater_dai, ARRAY_SIZE(clearwater_dai));
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Failed to register codec: %d\n",
			ret);
		snd_soc_unregister_platform(&pdev->dev);
		goto error;
	}

	return ret;

error:
	clearwater_destroy_compr_info(clearwater);
	mutex_destroy(&clearwater->fw_lock);

	return ret;
}

static int clearwater_remove(struct platform_device *pdev)
{
	struct clearwater_priv *clearwater = platform_get_drvdata(pdev);
	int i;

	snd_soc_unregister_platform(&pdev->dev);
	snd_soc_unregister_codec(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	clearwater_destroy_compr_info(clearwater);

	for (i = 0; i < CLEARWATER_NUM_ADSP; i++)
		wm_adsp2_remove(&clearwater->core.adsp[i]);

	mutex_destroy(&clearwater->fw_lock);

	return 0;
}

static struct platform_driver clearwater_codec_driver = {
	.driver = {
		.name = "clearwater-codec",
		.owner = THIS_MODULE,
	},
	.probe = clearwater_probe,
	.remove = clearwater_remove,
};

module_platform_driver(clearwater_codec_driver);

MODULE_DESCRIPTION("ASoC CLEARWATER driver");
MODULE_AUTHOR("Nariman Poushin <nariman@opensource.wolfsonmicro.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:clearwater-codec");

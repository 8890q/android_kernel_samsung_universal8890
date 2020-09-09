/*
 * wm_adsp.c  --  Wolfson ADSP support
 *
 * Copyright 2012 Wolfson Microelectronics plc
 *
 * Author: Mark Brown <broonie@opensource.wolfsonmicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/jack.h>
#include <sound/initval.h>
#include <sound/tlv.h>

#include <linux/mfd/arizona/registers.h>

#include "arizona.h"
#include "wm_adsp.h"

#define adsp_crit(_dsp, fmt, ...) \
	dev_crit(_dsp->dev, "DSP%d: " fmt, _dsp->num, ##__VA_ARGS__)
#define adsp_err(_dsp, fmt, ...) \
	dev_err(_dsp->dev, "DSP%d: " fmt, _dsp->num, ##__VA_ARGS__)
#define adsp_warn(_dsp, fmt, ...) \
	dev_warn(_dsp->dev, "DSP%d: " fmt, _dsp->num, ##__VA_ARGS__)
#define adsp_info(_dsp, fmt, ...) \
	dev_info(_dsp->dev, "DSP%d: " fmt, _dsp->num, ##__VA_ARGS__)
#define adsp_dbg(_dsp, fmt, ...) \
	dev_dbg(_dsp->dev, "DSP%d: " fmt, _dsp->num, ##__VA_ARGS__)

#define ADSP1_CONTROL_1                   0x00
#define ADSP1_CONTROL_2                   0x02
#define ADSP1_CONTROL_3                   0x03
#define ADSP1_CONTROL_4                   0x04
#define ADSP1_CONTROL_5                   0x06
#define ADSP1_CONTROL_6                   0x07
#define ADSP1_CONTROL_7                   0x08
#define ADSP1_CONTROL_8                   0x09
#define ADSP1_CONTROL_9                   0x0A
#define ADSP1_CONTROL_10                  0x0B
#define ADSP1_CONTROL_11                  0x0C
#define ADSP1_CONTROL_12                  0x0D
#define ADSP1_CONTROL_13                  0x0F
#define ADSP1_CONTROL_14                  0x10
#define ADSP1_CONTROL_15                  0x11
#define ADSP1_CONTROL_16                  0x12
#define ADSP1_CONTROL_17                  0x13
#define ADSP1_CONTROL_18                  0x14
#define ADSP1_CONTROL_19                  0x16
#define ADSP1_CONTROL_20                  0x17
#define ADSP1_CONTROL_21                  0x18
#define ADSP1_CONTROL_22                  0x1A
#define ADSP1_CONTROL_23                  0x1B
#define ADSP1_CONTROL_24                  0x1C
#define ADSP1_CONTROL_25                  0x1E
#define ADSP1_CONTROL_26                  0x20
#define ADSP1_CONTROL_27                  0x21
#define ADSP1_CONTROL_28                  0x22
#define ADSP1_CONTROL_29                  0x23
#define ADSP1_CONTROL_30                  0x24
#define ADSP1_CONTROL_31                  0x26

/*
 * ADSP1 Control 19
 */
#define ADSP1_WDMA_BUFFER_LENGTH_MASK     0x00FF  /* DSP1_WDMA_BUFFER_LENGTH - [7:0] */
#define ADSP1_WDMA_BUFFER_LENGTH_SHIFT         0  /* DSP1_WDMA_BUFFER_LENGTH - [7:0] */
#define ADSP1_WDMA_BUFFER_LENGTH_WIDTH         8  /* DSP1_WDMA_BUFFER_LENGTH - [7:0] */


/*
 * ADSP1 Control 30
 */
#define ADSP1_DBG_CLK_ENA                 0x0008  /* DSP1_DBG_CLK_ENA */
#define ADSP1_DBG_CLK_ENA_MASK            0x0008  /* DSP1_DBG_CLK_ENA */
#define ADSP1_DBG_CLK_ENA_SHIFT                3  /* DSP1_DBG_CLK_ENA */
#define ADSP1_DBG_CLK_ENA_WIDTH                1  /* DSP1_DBG_CLK_ENA */
#define ADSP1_SYS_ENA                     0x0004  /* DSP1_SYS_ENA */
#define ADSP1_SYS_ENA_MASK                0x0004  /* DSP1_SYS_ENA */
#define ADSP1_SYS_ENA_SHIFT                    2  /* DSP1_SYS_ENA */
#define ADSP1_SYS_ENA_WIDTH                    1  /* DSP1_SYS_ENA */
#define ADSP1_CORE_ENA                    0x0002  /* DSP1_CORE_ENA */
#define ADSP1_CORE_ENA_MASK               0x0002  /* DSP1_CORE_ENA */
#define ADSP1_CORE_ENA_SHIFT                   1  /* DSP1_CORE_ENA */
#define ADSP1_CORE_ENA_WIDTH                   1  /* DSP1_CORE_ENA */
#define ADSP1_START                       0x0001  /* DSP1_START */
#define ADSP1_START_MASK                  0x0001  /* DSP1_START */
#define ADSP1_START_SHIFT                      0  /* DSP1_START */
#define ADSP1_START_WIDTH                      1  /* DSP1_START */

/*
 * ADSP1 Control 31
 */
#define ADSP1_CLK_SEL_MASK                0x0007  /* CLK_SEL_ENA */
#define ADSP1_CLK_SEL_SHIFT                    0  /* CLK_SEL_ENA */
#define ADSP1_CLK_SEL_WIDTH                    3  /* CLK_SEL_ENA */

#define ADSP2_CONTROL        0x0
#define ADSP2_CLOCKING       0x1
#define ADSP2V2_CLOCKING     0x2
#define ADSP2_STATUS1        0x4
#define ADSP2_WDMA_CONFIG_1   0x30
#define ADSP2_WDMA_CONFIG_2   0x31
#define ADSP2V2_WDMA_CONFIG_2 0x32
#define ADSP2_RDMA_CONFIG_1   0x34

#define ADSP2_SCRATCH0        0x40
#define ADSP2_SCRATCH1        0x41
#define ADSP2_SCRATCH2        0x42
#define ADSP2_SCRATCH3        0x43

#define ADSP2V2_SCRATCH0_1        0x40
#define ADSP2V2_SCRATCH2_3        0x42

/*
 * ADSP2 Control
 */

#define ADSP2_MEM_ENA                     0x0010  /* DSP1_MEM_ENA */
#define ADSP2_MEM_ENA_MASK                0x0010  /* DSP1_MEM_ENA */
#define ADSP2_MEM_ENA_SHIFT                    4  /* DSP1_MEM_ENA */
#define ADSP2_MEM_ENA_WIDTH                    1  /* DSP1_MEM_ENA */
#define ADSP2_SYS_ENA                     0x0004  /* DSP1_SYS_ENA */
#define ADSP2_SYS_ENA_MASK                0x0004  /* DSP1_SYS_ENA */
#define ADSP2_SYS_ENA_SHIFT                    2  /* DSP1_SYS_ENA */
#define ADSP2_SYS_ENA_WIDTH                    1  /* DSP1_SYS_ENA */
#define ADSP2_CORE_ENA                    0x0002  /* DSP1_CORE_ENA */
#define ADSP2_CORE_ENA_MASK               0x0002  /* DSP1_CORE_ENA */
#define ADSP2_CORE_ENA_SHIFT                   1  /* DSP1_CORE_ENA */
#define ADSP2_CORE_ENA_WIDTH                   1  /* DSP1_CORE_ENA */
#define ADSP2_START                       0x0001  /* DSP1_START */
#define ADSP2_START_MASK                  0x0001  /* DSP1_START */
#define ADSP2_START_SHIFT                      0  /* DSP1_START */
#define ADSP2_START_WIDTH                      1  /* DSP1_START */

/*
 * ADSP2 clocking
 */
#define ADSP2_CLK_SEL_MASK                0x0007  /* CLK_SEL_ENA */
#define ADSP2_CLK_SEL_SHIFT                    0  /* CLK_SEL_ENA */
#define ADSP2_CLK_SEL_WIDTH                    3  /* CLK_SEL_ENA */

/*
 * ADSP2V2 clocking
 */
#define ADSP2V2_CLK_SEL_MASK               0x70000 /* CLK_SEL_ENA */
#define ADSP2V2_CLK_SEL_SHIFT                   16  /* CLK_SEL_ENA */
#define ADSP2V2_CLK_SEL_WIDTH                    3  /* CLK_SEL_ENA */

#define ADSP2V2_RATE_MASK                   0x7800  /* DSP_RATE */
#define ADSP2V2_RATE_SHIFT                      11  /* DSP_RATE */
#define ADSP2V2_RATE_WIDTH                       4  /* DSP_RATE */

/*
 * ADSP2 Status 1
 */
#define ADSP2_RAM_RDY                     0x0001
#define ADSP2_RAM_RDY_MASK                0x0001
#define ADSP2_RAM_RDY_SHIFT                    0
#define ADSP2_RAM_RDY_WIDTH                    1

/*
 * ADSP2 Lock support
 */

#define ADSP2_LOCK_CODE_0                    0x5555
#define ADSP2_LOCK_CODE_1                    0xAAAA

#define ADSP2_WATCHDOG                       0x0A
#define ADSP2_BUS_ERR_ADDR                   0x52
#define ADSP2_REGION_LOCK_STATUS             0x64
#define ADSP2_LOCK_REGION_1_LOCK_REGION_0    0x66
#define ADSP2_LOCK_REGION_3_LOCK_REGION_2    0x68
#define ADSP2_LOCK_REGION_5_LOCK_REGION_4    0x6A
#define ADSP2_LOCK_REGION_7_LOCK_REGION_6    0x6C
#define ADSP2_LOCK_REGION_9_LOCK_REGION_8    0x6E
#define ADSP2_LOCK_REGION_CTRL               0x7A
#define ADSP2_PMEM_ERR_ADDR_XMEM_ERR_ADDR    0x7C

#define ADSP2_REGION_LOCK_ERR_MASK           0x8000
#define ADSP2_SLAVE_ERR_MASK                 0x4000
#define ADSP2_WDT_TIMEOUT_STS_MASK           0x2000
#define ADSP2_CTRL_ERR_PAUSE_ENA             0x0002
#define ADSP2_CTRL_ERR_EINT                  0x0001

#define ADSP2_BUS_ERR_ADDR_MASK              0x00FFFFFF
#define ADSP2_XMEM_ERR_ADDR_MASK             0x0000FFFF
#define ADSP2_PMEM_ERR_ADDR_MASK             0x7FFF0000
#define ADSP2_PMEM_ERR_ADDR_SHIFT            16
#define ADSP2_WDT_ENA_MASK                   0xFFFFFFFD

#define ADSP2_LOCK_REGION_SHIFT              16

#define WM_ADSP_ACKED_CTL_TIMEOUT_MS         100
#define WM_ADSP_ACKED_CTL_N_QUICKPOLLS       10
#define WM_ADSP_ACKED_CTL_MIN_VALUE          0
#define WM_ADSP_ACKED_CTL_MAX_VALUE          0xFFFFFF
/* ADSP2V1  accessed through 16-bit register map so only low 16-bits atomic */
#define WM_ADSP_ACKED_CTL_MAX_VALUE_V1       0xFFFF

/*
 * Event control messages
 */
#define WM_ADSP_FW_EVENT_SHUTDOWN            0x000001

static int wm_adsp_init_host_buf_info(struct wm_adsp_compr_buf *buf);
static void wm_adsp_free_host_buf_info(struct wm_adsp_compr_buf *buf);

struct wm_adsp_buf {
	struct list_head list;
	void *buf;
};

static struct wm_adsp_buf *wm_adsp_buf_alloc(const void *src, size_t len,
					     struct list_head *list)
{
	struct wm_adsp_buf *buf = kzalloc(sizeof(*buf), GFP_KERNEL);

	if (buf == NULL)
		return NULL;

	buf->buf = kmemdup(src, len, GFP_KERNEL | GFP_DMA);
	if (!buf->buf) {
		kfree(buf);
		return NULL;
	}

	if (list)
		list_add_tail(&buf->list, list);

	return buf;
}

static void wm_adsp_buf_free(struct list_head *list)
{
	while (!list_empty(list)) {
		struct wm_adsp_buf *buf = list_first_entry(list,
							   struct wm_adsp_buf,
							   list);
		list_del(&buf->list);
		kfree(buf->buf);
		kfree(buf);
	}
}

/* Must remain a power of two */
#define WM_ADSP_CAPTURE_BUFFER_SIZE      1048576

#define WM_ADSP_FW_MBC_VSS  0
#define WM_ADSP_FW_HIFI     1
#define WM_ADSP_FW_TX       2
#define WM_ADSP_FW_TX_SPK   3
#define WM_ADSP_FW_RX       4
#define WM_ADSP_FW_RX_ANC   5
#define WM_ADSP_FW_CTRL     6
#define WM_ADSP_FW_ASR      7
#define WM_ADSP_FW_TRACE    8
#define WM_ADSP_FW_SPK_PROT 9
#define WM_ADSP_FW_MISC     10

#define WM_ADSP_NUM_FW      11

static const char *wm_adsp_fw_text[WM_ADSP_NUM_FW] = {
	[WM_ADSP_FW_MBC_VSS] =  "MBC/VSS",
	[WM_ADSP_FW_HIFI] =     "MasterHiFi",
	[WM_ADSP_FW_TX] =       "Tx",
	[WM_ADSP_FW_TX_SPK] =   "Tx Speaker",
	[WM_ADSP_FW_RX] =       "Rx",
	[WM_ADSP_FW_RX_ANC] =   "Rx ANC",
	[WM_ADSP_FW_CTRL] =     "Voice Ctrl",
	[WM_ADSP_FW_ASR] =      "ASR Assist",
	[WM_ADSP_FW_TRACE] =    "Dbg Trace",
	[WM_ADSP_FW_SPK_PROT] = "Protection",
	[WM_ADSP_FW_MISC] =     "Misc",
};

struct wm_adsp_system_config_xm_hdr {
	__be32 sys_enable;
	__be32 fw_id;
	__be32 fw_rev;
	__be32 boot_status;
	__be32 watchdog;
	__be32 dma_buffer_size;
	__be32 rdma[6];
	__be32 wdma[8];
	__be32 build_job_name[3];
	__be32 build_job_number;
};

struct wm_adsp_alg_xm_struct {
	__be32 magic;
	__be32 smoothing;
	__be32 threshold;
	__be32 host_buf_ptr;
	__be32 start_seq;
	__be32 high_water_mark;
	__be32 low_water_mark;
	__be64 smoothed_power;
};

struct wm_adsp_host_buffer {
	__be32 X_buf_base;		/* XM base addr of first X area */
	__be32 X_buf_size;		/* Size of 1st X area in words */
	__be32 X_buf_base2;		/* XM base addr of 2nd X area */
	__be32 X_buf_brk;		/* Total X size in words */
	__be32 Y_buf_base;		/* YM base addr of Y area */
	__be32 wrap;			/* Total size X and Y in words */
	__be32 high_water_mark;		/* Point at which IRQ is asserted */
	__be32 irq_count;		/* bits 1-31 count IRQ assertions */
	__be32 irq_ack;			/* acked IRQ count, bit 0 enables IRQ */
	__be32 next_write_index;	/* word index of next write */
	__be32 next_read_index;		/* word index of next read */
	__be32 error;			/* error if any */
	__be32 oldest_block_index;	/* word index of oldest surviving */
	__be32 requested_rewind;	/* how many blocks rewind was done */
	__be32 reserved_space;		/* internal */
	__be32 min_free;		/* min free space since stream start */
	__be32 blocks_written[2];	/* total blocks written (64 bit) */
	__be32 words_written[2];	/* total words written (64 bit) */
};

#define WM_ADSP_DATA_WORD_SIZE		3
#define WM_ADSP_MIN_FRAGMENTS		1
#define WM_ADSP_MAX_FRAGMENTS		256
#define WM_ADSP_MIN_FRAGMENT_SIZE	(64 * WM_ADSP_DATA_WORD_SIZE)
#define WM_ADSP_MAX_FRAGMENT_SIZE	(4096 * WM_ADSP_DATA_WORD_SIZE)


#define WM_ADSP_ALG_XM_STRUCT_MAGIC    0x49aec7

#define WM_ADSP_DEFAULT_WATERMARK      DIV_ROUND_UP(2048, WM_ADSP_DATA_WORD_SIZE)

#define ADSP2_SYSTEM_CONFIG_XM_PTR \
	(offsetof(struct wmfw_adsp2_id_hdr, xm) / sizeof(__be32))

#define WM_ADSP_ALG_XM_PTR \
	(sizeof(struct wm_adsp_system_config_xm_hdr) / sizeof(__be32))

#define HOST_BUFFER_FIELD(field) \
	(offsetof(struct wm_adsp_host_buffer, field) / sizeof(__be32))

#define ALG_XM_FIELD(field) \
	(offsetof(struct wm_adsp_alg_xm_struct, field) / sizeof(__be32))

static struct wm_adsp_buffer_region_def ez2control_regions[] = {
	{
		.mem_type = WMFW_ADSP2_XM,
		.base_offset = HOST_BUFFER_FIELD(X_buf_base),
		.size_offset = HOST_BUFFER_FIELD(X_buf_size),
	},
	{
		.mem_type = WMFW_ADSP2_XM,
		.base_offset = HOST_BUFFER_FIELD(X_buf_base2),
		.size_offset = HOST_BUFFER_FIELD(X_buf_brk),
	},
	{
		.mem_type = WMFW_ADSP2_YM,
		.base_offset = HOST_BUFFER_FIELD(Y_buf_base),
		.size_offset = HOST_BUFFER_FIELD(wrap),
	},
};

static struct wm_adsp_fw_caps ez2control_caps[] = {
	{
		.id = SND_AUDIOCODEC_PCM,
		.desc = {
			.max_ch = 2,
			.sample_rates = { 16000 },
			.num_sample_rates = 1,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.num_host_regions = ARRAY_SIZE(ez2control_regions),
		.host_region_defs = ez2control_regions,
	},
};

static struct wm_adsp_buffer_region_def trace_regions[] = {
	{
		.mem_type = WMFW_ADSP2_XM,
		.base_offset = HOST_BUFFER_FIELD(X_buf_base),
		.size_offset = HOST_BUFFER_FIELD(X_buf_size),
	},
	{
		.mem_type = WMFW_ADSP2_XM,
		.base_offset = HOST_BUFFER_FIELD(X_buf_base2),
		.size_offset = HOST_BUFFER_FIELD(X_buf_brk),
	},
	{
		.mem_type = WMFW_ADSP2_YM,
		.base_offset = HOST_BUFFER_FIELD(Y_buf_base),
		.size_offset = HOST_BUFFER_FIELD(wrap),
	},
};

static struct wm_adsp_fw_caps trace_caps[] = {
	{
		.id = SND_AUDIOCODEC_PCM,
		.desc = {
			.max_ch = 8,
			.sample_rates = {
				4000,8000,11025,12000,16000,22050,
				24000,32000,44100,48000,64000,88200,
				96000,176400,192000
			},
			.num_sample_rates = 15,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.num_host_regions = ARRAY_SIZE(trace_regions),
		.host_region_defs = trace_regions,
	},
};

static struct wm_adsp_fw_defs wm_adsp_fw[WM_ADSP_NUM_FW] = {
	[WM_ADSP_FW_MBC_VSS] =  { .file = "mbc-vss" },
	[WM_ADSP_FW_HIFI] =     { .file = "hifi" },
	[WM_ADSP_FW_TX] =       { .file = "tx" },
	[WM_ADSP_FW_TX_SPK] =   { .file = "tx-spk" },
	[WM_ADSP_FW_RX] =       { .file = "rx" },
	[WM_ADSP_FW_RX_ANC] =   { .file = "rx-anc" },
	[WM_ADSP_FW_CTRL] =     {
		.file = "ctrl",
		.compr_direction = SND_COMPRESS_CAPTURE,
		.num_caps = ARRAY_SIZE(ez2control_caps),
		.caps = ez2control_caps,
	},
	[WM_ADSP_FW_ASR] =      { .file = "asr" },
	[WM_ADSP_FW_TRACE] =    {
		.file = "trace",
		.compr_direction = SND_COMPRESS_CAPTURE,
		.num_caps = ARRAY_SIZE(trace_caps),
		.caps = trace_caps,
	},
	[WM_ADSP_FW_SPK_PROT] = { .file = "spk-prot" },
	[WM_ADSP_FW_MISC] =     { .file = "misc" },
};

struct wm_coeff_ctl_ops {
	int (*xget)(struct snd_kcontrol *kcontrol,
		    struct snd_ctl_elem_value *ucontrol);
	int (*xput)(struct snd_kcontrol *kcontrol,
		    struct snd_ctl_elem_value *ucontrol);
	int (*xinfo)(struct snd_kcontrol *kcontrol,
		     struct snd_ctl_elem_info *uinfo);
};

struct wm_coeff_ctl {
	const char *name;
	const char *fw_name;
	struct wm_adsp_alg_region alg_region;
	struct wm_coeff_ctl_ops ops;
	struct wm_adsp *dsp;
	unsigned int enabled:1;
	struct list_head list;
	void *cache;
	unsigned int offset;
	size_t len;
	unsigned int set:1;
	struct snd_kcontrol *kcontrol;
	unsigned int flags;
	struct mutex lock;
	unsigned int type;
};

static const char *wm_adsp_mem_region_name(unsigned int type)
{
	switch (type) {
	case WMFW_ADSP1_PM:
		return "PM";
	case WMFW_ADSP1_DM:
		return "DM";
	case WMFW_ADSP2_XM:
		return "XM";
	case WMFW_ADSP2_YM:
		return "YM";
	case WMFW_ADSP1_ZM:
		return "ZM";
	default:
		return NULL;
	}
}

#ifdef CONFIG_DEBUG_FS
static void wm_adsp_debugfs_save_wmfwname(struct wm_adsp *dsp, const char *s)
{
	char *tmp = kasprintf(GFP_KERNEL, "%s\n", s);

	mutex_lock(&dsp->debugfs_lock);
	kfree(dsp->wmfw_file_name);
	dsp->wmfw_file_name = tmp;
	mutex_unlock(&dsp->debugfs_lock);
}

static void wm_adsp_debugfs_save_binname(struct wm_adsp *dsp, const char *s)
{
	char *tmp = kasprintf(GFP_KERNEL, "%s\n", s);

	mutex_lock(&dsp->debugfs_lock);
	kfree(dsp->bin_file_name);
	dsp->bin_file_name = tmp;
	mutex_unlock(&dsp->debugfs_lock);
}

static void wm_adsp_debugfs_clear(struct wm_adsp *dsp)
{
	mutex_lock(&dsp->debugfs_lock);
	kfree(dsp->wmfw_file_name);
	kfree(dsp->bin_file_name);
	dsp->wmfw_file_name = NULL;
	dsp->bin_file_name = NULL;
	mutex_unlock(&dsp->debugfs_lock);
}

static ssize_t wm_adsp_debugfs_wmfw_read(struct file *file,
					 char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	struct wm_adsp *dsp = file->private_data;
	ssize_t ret;

	mutex_lock(&dsp->debugfs_lock);

	if (!dsp->wmfw_file_name || !dsp->running)
		ret = 0;
	else
		ret = simple_read_from_buffer(user_buf, count, ppos,
					      dsp->wmfw_file_name,
					      strlen(dsp->wmfw_file_name));

	mutex_unlock(&dsp->debugfs_lock);
	return ret;
}

static ssize_t wm_adsp_debugfs_bin_read(struct file *file,
					char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct wm_adsp *dsp = file->private_data;
	ssize_t ret;

	mutex_lock(&dsp->debugfs_lock);

	if (!dsp->bin_file_name || !dsp->running)
		ret = 0;
	else
		ret = simple_read_from_buffer(user_buf, count, ppos,
					      dsp->bin_file_name,
					      strlen(dsp->bin_file_name));

	mutex_unlock(&dsp->debugfs_lock);
	return ret;
}

static const struct {
	const char *name;
	const struct file_operations fops;
} wm_adsp_debugfs_fops[] = {
	{
		.name = "wmfw_file_name",
		.fops = {
			.open = simple_open,
			.read = wm_adsp_debugfs_wmfw_read,
		},
	},
	{
		.name = "bin_file_name",
		.fops = {
			.open = simple_open,
			.read = wm_adsp_debugfs_bin_read,
		},
	},
};

static void wm_adsp2_init_debugfs(struct wm_adsp *dsp,
				  struct snd_soc_codec *codec)
{
	struct dentry *root = NULL;
	char *root_name;
	int i;

	if (!codec->component.debugfs_root) {
		adsp_err(dsp, "No codec debugfs root\n");
		goto err;
	}

	root_name = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!root_name)
		goto err;

	snprintf(root_name, PAGE_SIZE, "dsp%d", dsp->num);
	root = debugfs_create_dir(root_name, codec->component.debugfs_root);
	kfree(root_name);

	if (!root)
		goto err;

	if (!debugfs_create_bool("running", S_IRUGO, root, &dsp->running))
		goto err;

	if (!debugfs_create_x32("fw_id", S_IRUGO, root, &dsp->fw_id))
		goto err;

	if (!debugfs_create_x32("fw_version", S_IRUGO, root,
				&dsp->fw_id_version))
		goto err;

	for (i = 0; i < ARRAY_SIZE(wm_adsp_debugfs_fops); ++i) {
		if (!debugfs_create_file(wm_adsp_debugfs_fops[i].name,
					 S_IRUGO, root, dsp,
					 &wm_adsp_debugfs_fops[i].fops))
			goto err;
	}

	dsp->debugfs_root = root;
	return;

err:
	debugfs_remove_recursive(root);
	adsp_err(dsp, "Failed to create debugfs\n");
}

static void wm_adsp2_cleanup_debugfs(struct wm_adsp *dsp)
{
	wm_adsp_debugfs_clear(dsp);
	debugfs_remove_recursive(dsp->debugfs_root);
}
#else
static inline void wm_adsp2_init_debugfs(struct wm_adsp *dsp,
					 struct snd_soc_codec *codec)
{
}

static inline void wm_adsp2_cleanup_debugfs(struct wm_adsp *dsp)
{
}

static inline void wm_adsp_debugfs_save_wmfwname(struct wm_adsp *dsp,
						 const char *s)
{
}

static inline void wm_adsp_debugfs_save_binname(struct wm_adsp *dsp,
						const char *s)
{
}

static inline void wm_adsp_debugfs_clear(struct wm_adsp *dsp)
{
}
#endif

static int wm_adsp_fw_get(struct snd_kcontrol *kcontrol,
			  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct soc_enum *e = (struct soc_enum *)kcontrol->private_value;
	struct wm_adsp *dsp = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = dsp[e->shift_l].fw;

	return 0;
}

static int wm_adsp2_start_dsp(struct wm_adsp *dsp);
static int wm_adsp2_shutdown_dsp(struct wm_adsp *dsp);
static void wm_adsp2_set_dspclk(struct wm_adsp *dsp, unsigned int freq);

static int wm_adsp_fw_put(struct snd_kcontrol *kcontrol,
			  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct snd_soc_card *card = codec->component.card;
	struct soc_enum *e = (struct soc_enum *)kcontrol->private_value;
	struct wm_adsp *dsps = snd_soc_codec_get_drvdata(codec);
	struct wm_adsp *dsp = &dsps[e->shift_l];
	int ret;

	if (ucontrol->value.integer.value[0] == dsp->fw)
		return 0;

	if (ucontrol->value.integer.value[0] >= dsp->num_firmwares)
		return -EINVAL;

	switch (dsp->type) {
	case WMFW_ADSP2:
		if (dsp->rev == 2 && dsp->running)
			break;
		/* fall through for rev other than 2 */
	case WMFW_ADSP1:
		if (dsp->running)
			return -EBUSY;
		dsp->fw = ucontrol->value.integer.value[0];
		return 0;
	default:
		return -EINVAL;
	}


	/* change fw on a running dsp */
	mutex_lock_nested(&card->dapm_mutex,
		SND_SOC_DAPM_CLASS_RUNTIME);

	wm_adsp2_shutdown_dsp(dsp);
	dsp->fw = ucontrol->value.integer.value[0];
	wm_adsp2_set_dspclk(dsp, dsp->freq_cache);
	queue_work(system_unbound_wq, &dsp->boot_work);
	ret = wm_adsp2_start_dsp(dsp);
	if (ret != 0)
		wm_adsp2_shutdown_dsp(dsp);

	mutex_unlock(&card->dapm_mutex);

	return 0;
}

static struct soc_enum wm_adsp_fw_enum[] = {
	SOC_ENUM_SINGLE(0, 0, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 1, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 2, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 3, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 4, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 5, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
	SOC_ENUM_SINGLE(0, 6, ARRAY_SIZE(wm_adsp_fw_text), wm_adsp_fw_text),
};

const struct snd_kcontrol_new wm_adsp_fw_controls[] = {
	SOC_ENUM_EXT("DSP1 Firmware", wm_adsp_fw_enum[0],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP2 Firmware", wm_adsp_fw_enum[1],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP3 Firmware", wm_adsp_fw_enum[2],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP4 Firmware", wm_adsp_fw_enum[3],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP5 Firmware", wm_adsp_fw_enum[4],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP6 Firmware", wm_adsp_fw_enum[5],
		     wm_adsp_fw_get, wm_adsp_fw_put),
	SOC_ENUM_EXT("DSP7 Firmware", wm_adsp_fw_enum[6],
		     wm_adsp_fw_get, wm_adsp_fw_put),
};
EXPORT_SYMBOL_GPL(wm_adsp_fw_controls);

static struct wm_adsp_region const *wm_adsp_find_region(struct wm_adsp *dsp,
							int type)
{
	int i;

	for (i = 0; i < dsp->num_mems; i++)
		if (dsp->mem[i].type == type)
			return &dsp->mem[i];

	return NULL;
}

static unsigned int wm_adsp_region_to_reg(struct wm_adsp_region const *mem,
					  unsigned int offset)
{
	if (WARN_ON(!mem))
		return offset;
	switch (mem->type) {
	case WMFW_ADSP1_PM:
		return mem->base + (offset * 3);
	case WMFW_ADSP1_DM:
		return mem->base + (offset * 2);
	case WMFW_ADSP2_XM:
		return mem->base + (offset * 2);
	case WMFW_ADSP2_YM:
		return mem->base + (offset * 2);
	case WMFW_ADSP1_ZM:
		return mem->base + (offset * 2);
	default:
		WARN(1, "Unknown memory region type");
		return offset;
	}
}

static void wm_adsp2_show_fw_status(struct wm_adsp *dsp)
{
	u16 scratch[4];
	int ret;

	ret = regmap_raw_read(dsp->regmap, dsp->base + ADSP2_SCRATCH0,
				scratch, sizeof(scratch));

	if (ret) {
		adsp_err(dsp, "Failed to read SCRATCH regs: %d\n", ret);
		return;
	}

	adsp_dbg(dsp, "FW SCRATCH 0:0x%x 1:0x%x 2:0x%x 3:0x%x\n",
		 be16_to_cpu(scratch[0]),
		 be16_to_cpu(scratch[1]),
		 be16_to_cpu(scratch[2]),
		 be16_to_cpu(scratch[3]));
}

static void wm_adsp2v2_show_fw_status(struct wm_adsp *dsp)
{
	u32 scratch[2];
	int ret;

	ret = regmap_raw_read(dsp->regmap, dsp->base + ADSP2V2_SCRATCH0_1,
				scratch, sizeof(scratch));

	if (ret) {
		adsp_err(dsp, "Failed to read SCRATCH regs: %d\n", ret);
		return;
	}

	scratch[0] = be32_to_cpu(scratch[0]);
	scratch[1] = be32_to_cpu(scratch[1]);

	adsp_dbg(dsp, "FW SCRATCH 0:0x%x 1:0x%x 2:0x%x 3:0x%x\n",
		 scratch[0] & 0xFFFF,
		 scratch[0] >> 16,
		 scratch[1] & 0xFFFF,
		 scratch[1] >> 16);
}

static int wm_coeff_base_reg(struct wm_coeff_ctl *ctl, unsigned int *reg)
{
	const struct wm_adsp_alg_region *alg_region = &ctl->alg_region;
	struct wm_adsp *dsp = ctl->dsp;
	const struct wm_adsp_region *mem;

	mem = wm_adsp_find_region(dsp, alg_region->type);
	if (!mem) {
		adsp_err(dsp, "No base for region %x\n",
			 alg_region->type);
		return -EINVAL;
	}

	*reg = wm_adsp_region_to_reg(mem, ctl->alg_region.base + ctl->offset);

	return 0;
}

static int wm_coeff_info(struct snd_kcontrol *kcontrol,
			 struct snd_ctl_elem_info *uinfo)
{
	struct wm_coeff_ctl *ctl = (struct wm_coeff_ctl *)kcontrol->private_value;

	switch (ctl->type) {
	case WMFW_CTL_TYPE_ACKED:
		uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
		uinfo->value.integer.min = WM_ADSP_ACKED_CTL_MIN_VALUE;

		switch (ctl->dsp->rev) {
		case 0:
			uinfo->value.integer.max =
				WM_ADSP_ACKED_CTL_MAX_VALUE_V1;
			break;
		default:
			uinfo->value.integer.max = WM_ADSP_ACKED_CTL_MAX_VALUE;
			break;
		}

		uinfo->value.integer.step = 1;
		uinfo->count = 1;
		break;
	default:
		uinfo->type = SNDRV_CTL_ELEM_TYPE_BYTES;
		uinfo->count = ctl->len;
		break;
	}

	return 0;
}

static int wm_coeff_write_acked_control(struct wm_coeff_ctl *ctl,
					unsigned int event_id)
{
	struct wm_adsp *dsp = ctl->dsp;
	u32 val = cpu_to_be32(event_id);
	unsigned int reg;
	int i, ret;

	ret = wm_coeff_base_reg(ctl, &reg);
	if (ret)
		return ret;

	adsp_dbg(dsp, "Sending 0x%x to acked control alg 0x%x %s:0x%x\n",
		 event_id, ctl->alg_region.alg,
		 wm_adsp_mem_region_name(ctl->alg_region.type), ctl->offset);

	ret = regmap_raw_write(dsp->regmap, reg, &val, sizeof(val));
	if (ret) {
		adsp_err(dsp, "Failed to write %x: %d\n", reg, ret);
		return ret;
	}

	/* Poll for ack, we initially poll at 1ms intervals for firmwares
	 * that respond quickly, then go to 10ms polls. A firmware is unlikely
	 * to ack instantly so we do the first 1ms delay before reading the
	 * control to avoid a pointless bus transaction
	 */
	for (i = 0; i < WM_ADSP_ACKED_CTL_TIMEOUT_MS;) {
		switch (i) {
		case 0 ... WM_ADSP_ACKED_CTL_N_QUICKPOLLS:
			usleep_range(1000, 2000);
			++i;
			break;
		default:
			usleep_range(10000, 20000);
			i += 10;
			break;
		}

		ret = regmap_raw_read(dsp->regmap, reg, &val, sizeof(val));
		if (ret) {
			adsp_err(dsp, "Failed to read %x: %d\n", reg, ret);
			return ret;
		}

		if (val == 0) {
			adsp_dbg(dsp, "Acked control ACKED at poll %u\n", i);
			return 0;
		}
	}

	adsp_warn(dsp, "Acked control @0x%x alg:0x%x %s:0x%x timed out\n",
			reg, ctl->alg_region.alg,
			wm_adsp_mem_region_name(ctl->alg_region.type),
			ctl->offset);

	return -ETIMEDOUT;
}

static int wm_coeff_put_acked(struct snd_kcontrol *kcontrol,
			      struct snd_ctl_elem_value *ucontrol)
{
	struct wm_coeff_ctl *ctl =
				(struct wm_coeff_ctl *)kcontrol->private_value;
	unsigned int val = ucontrol->value.integer.value[0];

	if (!ctl->enabled)
		return -EPERM;

	if (val == 0)
		return 0;	/* 0 means no event */

	return wm_coeff_write_acked_control(ctl, val);
}

static int wm_coeff_write_control(struct wm_coeff_ctl *ctl,
				  const void *buf, size_t len)
{
	struct wm_adsp *dsp = ctl->dsp;
	void *scratch;
	int ret;
	unsigned int reg;

	ret = wm_coeff_base_reg(ctl, &reg);
	if (ret)
		return ret;

	scratch = kmemdup(buf, len, GFP_KERNEL | GFP_DMA);
	if (!scratch)
		return -ENOMEM;

	ret = regmap_raw_write(dsp->regmap, reg, scratch,
			       len);
	if (ret) {
		adsp_err(dsp, "Failed to write %zu bytes to %x: %d\n",
			 len, reg, ret);
		kfree(scratch);
		return ret;
	}
	adsp_dbg(dsp, "Wrote %zu bytes to %x\n", len, reg);

	kfree(scratch);

	return 0;
}

static int wm_coeff_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	struct wm_coeff_ctl *ctl = (struct wm_coeff_ctl *)kcontrol->private_value;
	char *p = ucontrol->value.bytes.data;
	int ret = 0;

	mutex_lock(&ctl->lock);

	memcpy(ctl->cache, p, ctl->len);

	ctl->set = 1;
	if (!ctl->enabled)
		goto out;

	ret = wm_coeff_write_control(ctl, p, ctl->len);

out:
	mutex_unlock(&ctl->lock);
	return ret;
}

static int wm_coeff_read_control(struct wm_coeff_ctl *ctl,
				 void *buf, size_t len)
{
	struct wm_adsp *dsp = ctl->dsp;
	void *scratch;
	int ret;
	unsigned int reg;

	ret = wm_coeff_base_reg(ctl, &reg);
	if (ret)
		return ret;

	scratch = kmalloc(len, GFP_KERNEL | GFP_DMA);
	if (!scratch)
		return -ENOMEM;

	ret = regmap_raw_read(dsp->regmap, reg, scratch, len);
	if (ret) {
		adsp_err(dsp, "Failed to read %zu bytes from %x: %d\n",
			 len, reg, ret);
		kfree(scratch);
		return ret;
	}
	adsp_dbg(dsp, "Read %zu bytes from %x\n", len, reg);

	memcpy(buf, scratch, len);
	kfree(scratch);

	return 0;
}

static int wm_coeff_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	struct wm_coeff_ctl *ctl = (struct wm_coeff_ctl *)kcontrol->private_value;
	char *p = ucontrol->value.bytes.data;
	int ret = 0;

	mutex_lock(&ctl->lock);

	if (ctl->flags & WMFW_CTL_FLAG_VOLATILE) {
		if (ctl->enabled)
			ret = wm_coeff_read_control(ctl, p, ctl->len);
		else
			ret = -EPERM;
		goto out;
	} else if (!ctl->flags && ctl->enabled) {
		ret = wm_coeff_read_control(ctl, ctl->cache, ctl->len);
	}

	memcpy(p, ctl->cache, ctl->len);

out:
	mutex_unlock(&ctl->lock);
	return ret;
}

static int wm_coeff_get_acked(struct snd_kcontrol *kcontrol,
			      struct snd_ctl_elem_value *ucontrol)
{
	/* Although it's not useful to read an acked control, we must satisfy
	 * user-side assumptions that all controls are readable and that a
	 * write of the same value should be filtered out (it's valid to send
	 * the same event number again to the firmware). We therefore return 0,
	 * meaning "no event" so valid event numbers will always be a change
	 */
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

struct wmfw_ctl_work {
	struct wm_adsp *dsp;
	struct wm_coeff_ctl *ctl;
	struct work_struct work;
};

static int wmfw_add_ctl(struct wm_adsp *dsp, struct wm_coeff_ctl *ctl)
{
	struct snd_kcontrol_new *kcontrol;
	int ret;

	if (!ctl || !ctl->name)
		return -EINVAL;

	kcontrol = kzalloc(sizeof(*kcontrol), GFP_KERNEL);
	if (!kcontrol)
		return -ENOMEM;
	kcontrol->iface = SNDRV_CTL_ELEM_IFACE_MIXER;

	kcontrol->name = ctl->name;
	kcontrol->info = wm_coeff_info;
	kcontrol->private_value = (unsigned long)ctl;

	if (ctl->flags) {
		if (ctl->flags & WMFW_CTL_FLAG_WRITEABLE)
			kcontrol->access |= SNDRV_CTL_ELEM_ACCESS_WRITE;
		if (ctl->flags & WMFW_CTL_FLAG_READABLE)
			kcontrol->access |= SNDRV_CTL_ELEM_ACCESS_READ;
		if (ctl->flags & WMFW_CTL_FLAG_VOLATILE)
			kcontrol->access |= SNDRV_CTL_ELEM_ACCESS_VOLATILE;
	} else {
		kcontrol->access = SNDRV_CTL_ELEM_ACCESS_READWRITE;
		kcontrol->access |= SNDRV_CTL_ELEM_ACCESS_VOLATILE;
	}

	switch (ctl->type) {
	case WMFW_CTL_TYPE_ACKED:
		kcontrol->get = wm_coeff_get_acked;
		kcontrol->put = wm_coeff_put_acked;
		break;
	default:
		kcontrol->get = wm_coeff_get;
		kcontrol->put = wm_coeff_put;
		break;
	}

	ret = snd_soc_add_card_controls(dsp->card, kcontrol, 1);
	if (ret < 0)
		goto err_kcontrol;

	kfree(kcontrol);

	ctl->kcontrol = snd_soc_card_get_kcontrol(dsp->card, ctl->name);

	return 0;

err_kcontrol:
	kfree(kcontrol);
	return ret;
}

static int wm_coeff_init_control_caches(struct wm_adsp *dsp)
{
	struct wm_coeff_ctl *ctl;
	int ret = 0;

	list_for_each_entry(ctl, &dsp->ctl_list, list) {
		if (!ctl->enabled || (ctl->flags & WMFW_CTL_FLAG_VOLATILE))
			continue;

		mutex_lock(&ctl->lock);

		if (!ctl->set)
			ret = wm_coeff_read_control(ctl, ctl->cache, ctl->len);

		mutex_unlock(&ctl->lock);

		if (ret < 0)
			return ret;
	}

	return 0;
}

static int wm_coeff_sync_controls(struct wm_adsp *dsp)
{
	struct wm_coeff_ctl *ctl;
	int ret = 0;

	list_for_each_entry(ctl, &dsp->ctl_list, list) {
		if (!ctl->enabled || (ctl->flags & WMFW_CTL_FLAG_VOLATILE))
			continue;

		mutex_lock(&ctl->lock);

		if (ctl->set)
			ret = wm_coeff_write_control(ctl, ctl->cache, ctl->len);

		mutex_unlock(&ctl->lock);

		if (ret < 0)
			return ret;
	}

	return 0;
}

static void wm_adsp_signal_event_controls(struct wm_adsp *dsp,
					  unsigned int event)
{
	struct wm_coeff_ctl *ctl;
	int ret;

	list_for_each_entry(ctl, &dsp->ctl_list, list) {
		if (ctl->type != WMFW_CTL_TYPE_HOSTEVENT)
			continue;

		ret = wm_coeff_write_acked_control(ctl, event);
		if (ret)
			adsp_warn(dsp,
				  "Failed to send 0x%x event to alg 0x%x (%d)\n",
				  event, ctl->alg_region.alg, ret);
	}
}

static void wm_adsp_ctl_work(struct work_struct *work)
{
	struct wmfw_ctl_work *ctl_work = container_of(work,
						      struct wmfw_ctl_work,
						      work);

	wmfw_add_ctl(ctl_work->dsp, ctl_work->ctl);
	kfree(ctl_work);
}

static int wm_adsp_create_ctl_blk(struct wm_adsp *dsp,
				  const struct wm_adsp_alg_region *alg_region,
				  unsigned int offset, unsigned int len,
				  const char *subname, unsigned int subname_len,
				  unsigned int flags, unsigned int type,
				  int block)
{
	struct wm_coeff_ctl *ctl;
	struct wmfw_ctl_work *ctl_work;
	char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
	const char *region_name;
	int ret;

	region_name = wm_adsp_mem_region_name(alg_region->type);
	if (!region_name) {
		adsp_err(dsp, "Unknown region type: %d\n", alg_region->type);
		return -EINVAL;
	}

	switch (dsp->fw_ver) {
	case 0:
	case 1:
		snprintf(name, SNDRV_CTL_ELEM_ID_NAME_MAXLEN, "DSP%d %s %x:%d",
			 dsp->num, region_name, alg_region->alg, block);
		break;
	default:
		ret = snprintf(name, SNDRV_CTL_ELEM_ID_NAME_MAXLEN,
			       "DSP%d%c %.10s %x:%d",
			       dsp->num, *region_name, wm_adsp_fw_text[dsp->fw],
			       alg_region->alg, block);

		/* Truncate the subname from the start if it is too long */
		if (subname) {
			int avail = SNDRV_CTL_ELEM_ID_NAME_MAXLEN - ret - 2;
			int skip = 0;

			if (subname_len > avail)
				skip = subname_len - avail;

			snprintf(name + ret,
				 SNDRV_CTL_ELEM_ID_NAME_MAXLEN - ret, " %.*s",
				 subname_len - skip, subname + skip);
		}
		break;
	}

	list_for_each_entry(ctl, &dsp->ctl_list,
			    list) {
		if (!strcmp(ctl->name, name)) {
			if (!ctl->enabled)
				ctl->enabled = 1;
			return 0;
		}
	}

	ctl = kzalloc(sizeof(*ctl), GFP_KERNEL);
	if (!ctl)
		return -ENOMEM;
	ctl->fw_name = dsp->firmwares[dsp->fw].name;
	ctl->alg_region = *alg_region;
	ctl->name = kmemdup(name, strlen(name) + 1, GFP_KERNEL);
	if (!ctl->name) {
		ret = -ENOMEM;
		goto err_ctl;
	}
	ctl->enabled = 1;
	ctl->set = 0;
	ctl->ops.xget = wm_coeff_get;
	ctl->ops.xput = wm_coeff_put;
	ctl->dsp = dsp;

	ctl->flags = flags;
	ctl->type = type;
	ctl->offset = offset;
	if (len > 512) {
		adsp_warn(dsp, "Truncating control %s from %d\n",
			  ctl->name, len);
		len = 512;
	}
	ctl->len = len;
	ctl->cache = kzalloc(ctl->len, GFP_KERNEL);
	if (!ctl->cache) {
		ret = -ENOMEM;
		goto err_ctl_name;
	}
	mutex_init(&ctl->lock);

	mutex_lock(&dsp->ctl_lock);
	list_add(&ctl->list, &dsp->ctl_list);
	mutex_unlock(&dsp->ctl_lock);

	if (flags & WMFW_CTL_FLAG_SYS)
		return 0;

	ctl_work = kzalloc(sizeof(*ctl_work), GFP_KERNEL);
	if (!ctl_work) {
		ret = -ENOMEM;
		goto err_ctl_cache;
	}

	ctl_work->dsp = dsp;
	ctl_work->ctl = ctl;
	INIT_WORK(&ctl_work->work, wm_adsp_ctl_work);
	schedule_work(&ctl_work->work);

	return 0;

err_ctl_cache:
	kfree(ctl->cache);
err_ctl_name:
	kfree(ctl->name);
err_ctl:
	kfree(ctl);

	return ret;
}

static void wm_adsp_free_ctl_blk(struct wm_coeff_ctl *ctl)
{
	kfree(ctl->cache);
	kfree(ctl->name);
	kfree(ctl);
}

static int wm_adsp_create_control(struct wm_adsp *dsp,
				  const struct wm_adsp_alg_region *alg_region,
				  unsigned int offset, unsigned int len,
				  const char *subname, unsigned int subname_len,
				  unsigned int flags, unsigned int type)
{
	unsigned int ctl_len;
	int block = 0;
	int ret;

	while (len) {
		ctl_len = len;
		if (ctl_len > 512)
			ctl_len = 512;

		ret = wm_adsp_create_ctl_blk(dsp, alg_region, offset,
					     ctl_len, subname, subname_len,
					     flags, type, block);
		if (ret < 0)
			return ret;

		offset += ctl_len / 4;
		len -= ctl_len;

		block++;
	}

	return 0;
}

static int wm_adsp_hpimp_update(struct wm_adsp *dsp)
{
	struct wm_coeff_ctl *ctl;
	int ret = 0;
	u32 tmp;

	list_for_each_entry(ctl, &dsp->ctl_list, list) {
		if (ctl->type != WMFW_CTL_TYPE_HP_IMP)
			continue;
		if (!dsp->hpimp_cb) {
			adsp_err(dsp,
				 "HP imp callback not registered: %s\n",
				 ctl->name);
			return -EINVAL;
		}

		mutex_lock(&ctl->lock);

		tmp = dsp->hpimp_cb(dsp->dev);
		tmp = cpu_to_be32(tmp & 0x00ffffffu);
		memcpy(ctl->cache, &tmp, sizeof(tmp));
		ret = wm_coeff_write_control(ctl, ctl->cache, ctl->len);

		mutex_unlock(&ctl->lock);

		if (ret < 0)
			return ret;
	}

	return 0;
}

struct wm_coeff_parsed_alg {
	int id;
	const u8 *name;
	int name_len;
	int ncoeff;
};

struct wm_coeff_parsed_coeff {
	int offset;
	int mem_type;
	const u8 *name;
	int name_len;
	int ctl_type;
	int flags;
	int len;
};

static int wm_coeff_parse_string(int bytes, const u8 **pos, const u8 **str)
{
	int length;

	switch (bytes) {
	case 1:
		length = **pos;
		break;
	case 2:
		length = le16_to_cpu(*((u16 *)*pos));
		break;
	default:
		return 0;
	}

	if (str)
		*str = *pos + bytes;

	*pos += ((length + bytes) + 3) & ~0x03;

	return length;
}

static int wm_coeff_parse_int(int bytes, const u8 **pos)
{
	int val = 0;

	switch (bytes) {
	case 2:
		val = le16_to_cpu(*((u16 *)*pos));
		break;
	case 4:
		val = le32_to_cpu(*((u32 *)*pos));
		break;
	default:
		break;
	}

	*pos += bytes;

	return val;
}

static inline void wm_coeff_parse_alg(struct wm_adsp *dsp, const u8 **data,
				      struct wm_coeff_parsed_alg *blk)
{
	const struct wmfw_adsp_alg_data *raw;

	switch (dsp->fw_ver) {
	case 0:
	case 1:
		raw = (const struct wmfw_adsp_alg_data *)*data;
		*data = raw->data;

		blk->id = le32_to_cpu(raw->id);
		blk->name = raw->name;
		blk->name_len = strlen(raw->name);
		blk->ncoeff = le32_to_cpu(raw->ncoeff);
		break;
	default:
		blk->id = wm_coeff_parse_int(sizeof(raw->id), data);
		blk->name_len = wm_coeff_parse_string(sizeof(u8), data,
						      &blk->name);
		/* Discard description we have no use for it in the driver */
		wm_coeff_parse_string(sizeof(u16), data, NULL);
		blk->ncoeff = wm_coeff_parse_int(sizeof(raw->ncoeff), data);
		break;
	}

	adsp_dbg(dsp, "Algorithm ID: %#x\n", blk->id);
	adsp_dbg(dsp, "Algorithm name: %.*s\n", blk->name_len, blk->name);
	adsp_dbg(dsp, "# of coefficient descriptors: %#x\n", blk->ncoeff);
}

static inline void wm_coeff_parse_coeff(struct wm_adsp *dsp, const u8 **data,
					struct wm_coeff_parsed_coeff *blk)
{
	const struct wmfw_adsp_coeff_data *raw;
	const u8 *tmp;
	int length;

	switch (dsp->fw_ver) {
	case 0:
	case 1:
		raw = (const struct wmfw_adsp_coeff_data *)*data;
		*data = *data + sizeof(raw->hdr) + le32_to_cpu(raw->hdr.size);

		blk->offset = le16_to_cpu(raw->hdr.offset);
		blk->mem_type = le16_to_cpu(raw->hdr.type);
		blk->name = raw->name;
		blk->name_len = strlen(raw->name);
		blk->ctl_type = le16_to_cpu(raw->ctl_type);
		blk->flags = le16_to_cpu(raw->flags);
		blk->len = le32_to_cpu(raw->len);
		break;
	default:
		tmp = *data;
		blk->offset = wm_coeff_parse_int(sizeof(raw->hdr.offset), &tmp);
		blk->mem_type = wm_coeff_parse_int(sizeof(raw->hdr.type), &tmp);
		length = wm_coeff_parse_int(sizeof(raw->hdr.size), &tmp);
		blk->name_len = wm_coeff_parse_string(sizeof(u8), &tmp,
						      &blk->name);
		/* Discard extended name we have no use for it in the driver */
		wm_coeff_parse_string(sizeof(u8), &tmp, NULL);
		/* Discard description we have no use for it in the driver */
		wm_coeff_parse_string(sizeof(u16), &tmp, NULL);
		blk->ctl_type = wm_coeff_parse_int(sizeof(raw->ctl_type), &tmp);
		blk->flags = wm_coeff_parse_int(sizeof(raw->flags), &tmp);
		blk->len = wm_coeff_parse_int(sizeof(raw->len), &tmp);

		*data = *data + sizeof(raw->hdr) + length;
		break;
	}

	adsp_dbg(dsp, "\tCoefficient type: %#x\n", blk->mem_type);
	adsp_dbg(dsp, "\tCoefficient offset: %#x\n", blk->offset);
	adsp_dbg(dsp, "\tCoefficient name: %.*s\n", blk->name_len, blk->name);
	adsp_dbg(dsp, "\tCoefficient flags: %#x\n", blk->flags);
	adsp_dbg(dsp, "\tALSA control type: %#x\n", blk->ctl_type);
	adsp_dbg(dsp, "\tALSA control len: %#x\n", blk->len);
}

static int wm_adsp_check_coeff_flags(struct wm_adsp *dsp,
				const struct wm_coeff_parsed_coeff *coeff_blk,
				unsigned int f_required,
				unsigned int f_illegal)
{
	if ((coeff_blk->flags & f_illegal) ||
	    ((coeff_blk->flags & f_required) != f_required)) {
		adsp_err(dsp, "Illegal flags 0x%x for control type 0x%x\n",
			 coeff_blk->flags, coeff_blk->ctl_type);
		return -EINVAL;
	}

	return 0;
}

static int wm_adsp_parse_coeff(struct wm_adsp *dsp,
			       const struct wmfw_region *region)
{
	struct wm_adsp_alg_region alg_region = {};
	struct wm_coeff_parsed_alg alg_blk;
	struct wm_coeff_parsed_coeff coeff_blk;
	const u8 *data = region->data;
	int i, ret;

	wm_coeff_parse_alg(dsp, &data, &alg_blk);
	for (i = 0; i < alg_blk.ncoeff; i++) {
		wm_coeff_parse_coeff(dsp, &data, &coeff_blk);

		switch (coeff_blk.ctl_type) {
		case SNDRV_CTL_ELEM_TYPE_BYTES:
			break;
		case WMFW_CTL_TYPE_HP_IMP:
			if (!(coeff_blk.flags & WMFW_CTL_FLAG_WRITEABLE)) {
				adsp_err(dsp,
					 "HP imp coeff not writeable: %.*s\n",
					 coeff_blk.name_len,
					 coeff_blk.name);
				continue;
			}
			if (coeff_blk.len != WMFW_CTL_HP_IMP_LEN) {
				adsp_err(dsp, "Bad HP imp coeff len: %d\n",
					 coeff_blk.len);
				continue;
			}
			break;
		case WMFW_CTL_TYPE_ACKED:
			if (coeff_blk.flags & WMFW_CTL_FLAG_SYS)
				continue;	/* ignore */

			ret = wm_adsp_check_coeff_flags(dsp, &coeff_blk,
						WMFW_CTL_FLAG_VOLATILE |
						WMFW_CTL_FLAG_WRITEABLE |
						WMFW_CTL_FLAG_READABLE,
						0);
			if (ret)
				return -EINVAL;
			break;
		case WMFW_CTL_TYPE_HOSTEVENT:
			ret = wm_adsp_check_coeff_flags(dsp, &coeff_blk,
						WMFW_CTL_FLAG_SYS |
						WMFW_CTL_FLAG_VOLATILE |
						WMFW_CTL_FLAG_WRITEABLE |
						WMFW_CTL_FLAG_READABLE,
						0);
			if (ret)
				return -EINVAL;
			break;
		default:
			adsp_err(dsp, "Unknown control type: %d\n",
				 coeff_blk.ctl_type);
			return -EINVAL;
		}

		alg_region.type = coeff_blk.mem_type;
		alg_region.alg = alg_blk.id;

		ret = wm_adsp_create_control(dsp, &alg_region,
					     coeff_blk.offset,
					     coeff_blk.len,
					     coeff_blk.name,
					     coeff_blk.name_len,
					     coeff_blk.flags,
					     coeff_blk.ctl_type);
		if (ret < 0)
			adsp_err(dsp, "Failed to create control: %.*s, %d\n",
				 coeff_blk.name_len, coeff_blk.name, ret);
	}

	return 0;
}

static int wm_adsp_write_blocks(struct wm_adsp *dsp, const u8 *data, size_t len,
				unsigned reg, struct list_head *list)

{
	size_t to_write = PAGE_SIZE;
	size_t remain = len;
	struct wm_adsp_buf *buf;
	int ret;

	while (remain > 0) {
		if (remain < PAGE_SIZE)
			to_write = remain;

		buf = wm_adsp_buf_alloc(data, to_write, list);
		if (!buf) {
			adsp_err(dsp, "Out of memory\n");
			return -ENOMEM;
		}

		ret = regmap_raw_write_async(dsp->regmap, reg,
					     buf->buf, to_write);
		if (ret != 0) {
			adsp_err(dsp,
				 "Failed to write %zd bytes at %d\n",
				 to_write, reg);

			return ret;
		}

		data += to_write;
		reg += to_write / 2;
		remain -= to_write;
	}

	return 0;
}

static int wm_adsp_load(struct wm_adsp *dsp)
{
	LIST_HEAD(buf_list);
	const struct firmware *firmware;
	struct regmap *regmap = dsp->regmap;
	unsigned int pos = 0;
	const struct wmfw_header *header;
	const struct wmfw_adsp1_sizes *adsp1_sizes;
	const struct wmfw_adsp2_sizes *adsp2_sizes;
	const struct wmfw_footer *footer;
	const struct wmfw_region *region;
	const struct wm_adsp_region *mem;
	const char *region_name;
	char *file, *text;
	unsigned int reg;
	int regions = 0;
	int ret, offset, type, sizes;

	file = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (file == NULL)
		return -ENOMEM;

	if (dsp->firmwares[dsp->fw].full_name)
		snprintf(file, PAGE_SIZE, "%s",
			 dsp->firmwares[dsp->fw].file);
	else if (dsp->part_rev)
		snprintf(file, PAGE_SIZE, "%s%c-dsp%d-%s.wmfw",
			 dsp->part, dsp->part_rev, dsp->num,
			 dsp->firmwares[dsp->fw].file);
	else
		snprintf(file, PAGE_SIZE, "%s-dsp%d-%s.wmfw", dsp->part,
			 dsp->num, dsp->firmwares[dsp->fw].file);

	file[PAGE_SIZE - 1] = '\0';
	mutex_lock(dsp->fw_lock);
	ret = request_firmware(&firmware, file, dsp->dev);
	mutex_unlock(dsp->fw_lock);

	if (ret != 0) {
		adsp_err(dsp, "Failed to request: '%s'\n", file);
		goto out;
	}
	ret = -EINVAL;

	pos = sizeof(*header) + sizeof(*adsp1_sizes) + sizeof(*footer);
	if (pos >= firmware->size) {
		adsp_err(dsp, "%s: file too short, %zu bytes\n",
			 file, firmware->size);
		goto out_fw;
	}

	header = (void*)&firmware->data[0];

	if (memcmp(&header->magic[0], "WMFW", 4) != 0) {
		adsp_err(dsp, "%s: invalid magic\n", file);
		goto out_fw;
	}

	switch (header->ver) {
	case 0:
		adsp_warn(dsp, "%s: Depreciated file format %d\n",
			  file, header->ver);
		break;
	case 1:
	case 2:
		break;
	default:
		adsp_err(dsp, "%s: unknown file format %d\n",
			 file, header->ver);
		goto out_fw;
	}
	adsp_info(dsp, "Firmware version: %d\n", header->ver);
	dsp->fw_ver = header->ver;

	if (header->core != dsp->type) {
		adsp_err(dsp, "%s: invalid core %d != %d\n",
			 file, header->core, dsp->type);
		goto out_fw;
	}

	switch (dsp->type) {
	case WMFW_ADSP1:
		pos = sizeof(*header) + sizeof(*adsp1_sizes) + sizeof(*footer);
		adsp1_sizes = (void *)&(header[1]);
		footer = (void *)&(adsp1_sizes[1]);
		sizes = sizeof(*adsp1_sizes);

		adsp_dbg(dsp, "%s: %d DM, %d PM, %d ZM\n",
			 file, le32_to_cpu(adsp1_sizes->dm),
			 le32_to_cpu(adsp1_sizes->pm),
			 le32_to_cpu(adsp1_sizes->zm));
		break;

	case WMFW_ADSP2:
		pos = sizeof(*header) + sizeof(*adsp2_sizes) + sizeof(*footer);
		adsp2_sizes = (void *)&(header[1]);
		footer = (void *)&(adsp2_sizes[1]);
		sizes = sizeof(*adsp2_sizes);

		adsp_dbg(dsp, "%s: %d XM, %d YM %d PM, %d ZM\n",
			 file, le32_to_cpu(adsp2_sizes->xm),
			 le32_to_cpu(adsp2_sizes->ym),
			 le32_to_cpu(adsp2_sizes->pm),
			 le32_to_cpu(adsp2_sizes->zm));
		break;

	default:
		WARN(1, "Unknown DSP type");
		goto out_fw;
	}

	if (le32_to_cpu(header->len) != sizeof(*header) +
	    sizes + sizeof(*footer)) {
		adsp_err(dsp, "%s: unexpected header length %d\n",
			 file, le32_to_cpu(header->len));
		goto out_fw;
	}

	adsp_dbg(dsp, "%s: timestamp %llu\n", file,
		 le64_to_cpu(footer->timestamp));

	while (pos < firmware->size &&
	       pos - firmware->size > sizeof(*region)) {
		region = (void *)&(firmware->data[pos]);
		region_name = "Unknown";
		reg = 0;
		text = NULL;
		offset = le32_to_cpu(region->offset) & 0xffffff;
		type = be32_to_cpu(region->type) & 0xff;
		mem = wm_adsp_find_region(dsp, type);

		switch (type) {
		case WMFW_NAME_TEXT:
			region_name = "Firmware name";
			text = kzalloc(le32_to_cpu(region->len) + 1,
				       GFP_KERNEL);
			break;
		case WMFW_ALGORITHM_DATA:
			region_name = "Algorithm";
			ret = wm_adsp_parse_coeff(dsp, region);
			if (ret != 0)
				goto out_fw;
			break;
		case WMFW_INFO_TEXT:
			region_name = "Information";
			text = kzalloc(le32_to_cpu(region->len) + 1,
				       GFP_KERNEL);
			break;
		case WMFW_ABSOLUTE:
			region_name = "Absolute";
			reg = offset;
			break;
		case WMFW_ADSP1_PM:
		case WMFW_ADSP1_DM:
		case WMFW_ADSP2_XM:
		case WMFW_ADSP2_YM:
		case WMFW_ADSP1_ZM:
			region_name = wm_adsp_mem_region_name(type);
			reg = wm_adsp_region_to_reg(mem, offset);
			break;
		default:
			adsp_warn(dsp,
				  "%s.%d: Unknown region type %x at %d(%x)\n",
				  file, regions, type, pos, pos);
			break;
		}

		adsp_dbg(dsp, "%s.%d: %d bytes at %d in %s\n", file,
			 regions, le32_to_cpu(region->len), offset,
			 region_name);

		if (text) {
			memcpy(text, region->data, le32_to_cpu(region->len));
			adsp_info(dsp, "%s: %s\n", file, text);
			kfree(text);
		}

		if (reg) {
			ret = wm_adsp_write_blocks(dsp, region->data,
						   le32_to_cpu(region->len),
						   reg, &buf_list);
			if (ret != 0) {
				adsp_err(dsp,
					"%s.%d: Failed writing data at %d in %s: %d\n",
					file, regions,
					offset, region_name, ret);
				goto out_buf;
			}
		}

		pos += le32_to_cpu(region->len) + sizeof(*region);
		regions++;
	}

	ret = regmap_async_complete(regmap);
	if (ret != 0) {
		adsp_err(dsp, "Failed to complete async write: %d\n", ret);
		goto out_buf;
	}

	if (pos > firmware->size)
		adsp_warn(dsp, "%s.%d: %zu bytes at end of file\n",
			  file, regions, pos - firmware->size);

	wm_adsp_debugfs_save_wmfwname(dsp, file);

out_buf:
	wm_adsp_buf_free(&buf_list);
out_fw:
	release_firmware(firmware);
out:
	kfree(file);

	return ret;
}

static void wm_adsp_ctl_fixup_base(struct wm_adsp *dsp,
				  const struct wm_adsp_alg_region *alg_region)
{
	struct wm_coeff_ctl *ctl;

	list_for_each_entry(ctl, &dsp->ctl_list, list) {
		if (ctl->fw_name == dsp->firmwares[dsp->fw].name &&
		    alg_region->alg == ctl->alg_region.alg &&
		    alg_region->type == ctl->alg_region.type) {
			ctl->alg_region.base = alg_region->base;
		}
	}
}

static void *wm_adsp_read_algs(struct wm_adsp *dsp, size_t n_algs,
			       unsigned int pos, unsigned int len)
{
	void *alg;
	int ret;
	__be32 val;

	if (n_algs == 0) {
		adsp_err(dsp, "No algorithms\n");
		return ERR_PTR(-EINVAL);
	}

	if (n_algs > 1024) {
		adsp_err(dsp, "Algorithm count %zx excessive\n", n_algs);
		return ERR_PTR(-EINVAL);
	}

	/* Read the terminator first to validate the length */
	ret = regmap_raw_read(dsp->regmap, pos + len, &val, sizeof(val));
	if (ret != 0) {
		adsp_err(dsp, "Failed to read algorithm list end: %d\n",
			ret);
		return ERR_PTR(ret);
	}

	if (be32_to_cpu(val) != 0xbedead)
		adsp_warn(dsp, "Algorithm list end %x 0x%x != 0xbeadead\n",
			  pos + len, be32_to_cpu(val));

	alg = kzalloc(len * 2, GFP_KERNEL | GFP_DMA);
	if (!alg)
		return ERR_PTR(-ENOMEM);

	ret = regmap_raw_read(dsp->regmap, pos, alg, len * 2);
	if (ret != 0) {
		adsp_err(dsp, "Failed to read algorithm list: %d\n", ret);
		kfree(alg);
		return ERR_PTR(ret);
	}

	return alg;
}

static struct wm_adsp_alg_region *
	wm_adsp_find_alg_region(struct wm_adsp *dsp, int type, unsigned int id)
{
	struct wm_adsp_alg_region *alg_region;

	list_for_each_entry(alg_region, &dsp->alg_regions, list) {
		if (id == alg_region->alg && type == alg_region->type)
			return alg_region;
	}

	return NULL;
}

static struct wm_adsp_alg_region *wm_adsp_create_region(struct wm_adsp *dsp,
							int type, __be32 id,
							__be32 base)
{
	struct wm_adsp_alg_region *alg_region;

	alg_region = kzalloc(sizeof(*alg_region), GFP_KERNEL);
	if (!alg_region)
		return ERR_PTR(-ENOMEM);

	alg_region->type = type;
	alg_region->alg = be32_to_cpu(id);
	alg_region->base = be32_to_cpu(base);

	list_add_tail(&alg_region->list, &dsp->alg_regions);

	if (dsp->fw_ver > 0)
		wm_adsp_ctl_fixup_base(dsp, alg_region);

	return alg_region;
}

static void wm_adsp_free_alg_regions(struct wm_adsp *dsp)
{
	struct wm_adsp_alg_region *alg_region;

	while (!list_empty(&dsp->alg_regions)) {
		alg_region = list_first_entry(&dsp->alg_regions,
					      struct wm_adsp_alg_region,
					      list);
		list_del(&alg_region->list);
		kfree(alg_region);
	}
}

static int wm_adsp1_setup_algs(struct wm_adsp *dsp)
{
	struct wmfw_adsp1_id_hdr adsp1_id;
	struct wmfw_adsp1_alg_hdr *adsp1_alg;
	struct wm_adsp_alg_region *alg_region;
	const struct wm_adsp_region *mem;
	unsigned int pos, len;
	size_t n_algs;
	int i, ret;

	mem = wm_adsp_find_region(dsp, WMFW_ADSP1_DM);
	if (WARN_ON(!mem))
		return -EINVAL;

	ret = regmap_raw_read(dsp->regmap, mem->base, &adsp1_id,
			      sizeof(adsp1_id));
	if (ret != 0) {
		adsp_err(dsp, "Failed to read algorithm info: %d\n",
			 ret);
		return ret;
	}

	n_algs = be32_to_cpu(adsp1_id.n_algs);
	dsp->fw_id = be32_to_cpu(adsp1_id.fw.id);
	adsp_info(dsp, "Firmware: %x v%d.%d.%d, %zu algorithms\n",
		  dsp->fw_id,
		  (be32_to_cpu(adsp1_id.fw.ver) & 0xff0000) >> 16,
		  (be32_to_cpu(adsp1_id.fw.ver) & 0xff00) >> 8,
		  be32_to_cpu(adsp1_id.fw.ver) & 0xff,
		  n_algs);

	alg_region = wm_adsp_create_region(dsp, WMFW_ADSP1_ZM,
					   adsp1_id.fw.id, adsp1_id.zm);
	if (IS_ERR(alg_region))
		return PTR_ERR(alg_region);

	alg_region = wm_adsp_create_region(dsp, WMFW_ADSP1_DM,
					   adsp1_id.fw.id, adsp1_id.dm);
	if (IS_ERR(alg_region))
		return PTR_ERR(alg_region);

	pos = sizeof(adsp1_id) / 2;
	len = (sizeof(*adsp1_alg) * n_algs) / 2;

	adsp1_alg = wm_adsp_read_algs(dsp, n_algs, mem->base + pos, len);
	if (IS_ERR(adsp1_alg))
		return PTR_ERR(adsp1_alg);

	for (i = 0; i < n_algs; i++) {
		adsp_info(dsp, "%d: ID %x v%d.%d.%d DM@%x ZM@%x\n",
			  i, be32_to_cpu(adsp1_alg[i].alg.id),
			  (be32_to_cpu(adsp1_alg[i].alg.ver) & 0xff0000) >> 16,
			  (be32_to_cpu(adsp1_alg[i].alg.ver) & 0xff00) >> 8,
			  be32_to_cpu(adsp1_alg[i].alg.ver) & 0xff,
			  be32_to_cpu(adsp1_alg[i].dm),
			  be32_to_cpu(adsp1_alg[i].zm));

		alg_region = wm_adsp_create_region(dsp, WMFW_ADSP1_DM,
						   adsp1_alg[i].alg.id,
						   adsp1_alg[i].dm);
		if (IS_ERR(alg_region)) {
			ret = PTR_ERR(alg_region);
			goto out;
		}

		if (dsp->fw_ver == 0) {
			if (i + 1 < n_algs) {
				len = be32_to_cpu(adsp1_alg[i + 1].dm);
				len -= be32_to_cpu(adsp1_alg[i].dm);
				len *= 4;
				wm_adsp_create_control(dsp, alg_region, 0,
						     len, NULL, 0, 0,
						     SNDRV_CTL_ELEM_TYPE_BYTES);
			} else {
				adsp_warn(dsp,
					  "Missing length info for region DM with ID %x\n",
					  be32_to_cpu(adsp1_alg[i].alg.id));
			}
		}

		alg_region = wm_adsp_create_region(dsp, WMFW_ADSP1_ZM,
						   adsp1_alg[i].alg.id,
						   adsp1_alg[i].zm);
		if (IS_ERR(alg_region)) {
			ret = PTR_ERR(alg_region);
			goto out;
		}

		if (dsp->fw_ver == 0) {
			if (i + 1 < n_algs) {
				len = be32_to_cpu(adsp1_alg[i + 1].zm);
				len -= be32_to_cpu(adsp1_alg[i].zm);
				len *= 4;
				wm_adsp_create_control(dsp, alg_region, 0,
						     len, NULL, 0, 0,
						     SNDRV_CTL_ELEM_TYPE_BYTES);
			} else {
				adsp_warn(dsp,
					  "Missing length info for region ZM with ID %x\n",
					  be32_to_cpu(adsp1_alg[i].alg.id));
			}
		}
	}

out:
	kfree(adsp1_alg);
	return ret;
}

static int wm_adsp2_setup_algs(struct wm_adsp *dsp)
{
	struct wmfw_adsp2_id_hdr adsp2_id;
	struct wmfw_adsp2_alg_hdr *adsp2_alg;
	struct wm_adsp_alg_region *alg_region;
	const struct wm_adsp_region *mem;
	unsigned int pos, len;
	size_t n_algs;
	int i, ret;

	mem = wm_adsp_find_region(dsp, WMFW_ADSP2_XM);
	if (WARN_ON(!mem))
		return -EINVAL;

	ret = regmap_raw_read(dsp->regmap, mem->base, &adsp2_id,
			      sizeof(adsp2_id));
	if (ret != 0) {
		adsp_err(dsp, "Failed to read algorithm info: %d\n",
			 ret);
		return ret;
	}

	n_algs = be32_to_cpu(adsp2_id.n_algs);
	dsp->fw_id = be32_to_cpu(adsp2_id.fw.id);
	dsp->fw_id_version = be32_to_cpu(adsp2_id.fw.ver);
	adsp_info(dsp, "Firmware: %x v%d.%d.%d, %zu algorithms\n",
		  dsp->fw_id,
		  (dsp->fw_id_version & 0xff0000) >> 16,
		  (dsp->fw_id_version & 0xff00) >> 8,
		  dsp->fw_id_version & 0xff,
		  n_algs);

	alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_XM,
					   adsp2_id.fw.id, adsp2_id.xm);
	if (IS_ERR(alg_region))
		return PTR_ERR(alg_region);

	alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_YM,
					   adsp2_id.fw.id, adsp2_id.ym);
	if (IS_ERR(alg_region))
		return PTR_ERR(alg_region);

	alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_ZM,
					   adsp2_id.fw.id, adsp2_id.zm);
	if (IS_ERR(alg_region))
		return PTR_ERR(alg_region);

	pos = sizeof(adsp2_id) / 2;
	len = (sizeof(*adsp2_alg) * n_algs) / 2;

	adsp2_alg = wm_adsp_read_algs(dsp, n_algs, mem->base + pos, len);
	if (IS_ERR(adsp2_alg))
		return PTR_ERR(adsp2_alg);

	for (i = 0; i < n_algs; i++) {
		adsp_info(dsp,
			  "%d: ID %x v%d.%d.%d XM@%x YM@%x ZM@%x\n",
			  i, be32_to_cpu(adsp2_alg[i].alg.id),
			  (be32_to_cpu(adsp2_alg[i].alg.ver) & 0xff0000) >> 16,
			  (be32_to_cpu(adsp2_alg[i].alg.ver) & 0xff00) >> 8,
			  be32_to_cpu(adsp2_alg[i].alg.ver) & 0xff,
			  be32_to_cpu(adsp2_alg[i].xm),
			  be32_to_cpu(adsp2_alg[i].ym),
			  be32_to_cpu(adsp2_alg[i].zm));

		alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_XM,
						   adsp2_alg[i].alg.id,
						   adsp2_alg[i].xm);
		if (IS_ERR(alg_region)) {
			ret = PTR_ERR(alg_region);
			goto out;
		}

		if (dsp->fw_ver == 0) {
			if (i + 1 < n_algs) {
				len = be32_to_cpu(adsp2_alg[i + 1].xm);
				len -= be32_to_cpu(adsp2_alg[i].xm);
				len *= 4;
				wm_adsp_create_control(dsp, alg_region, 0,
						     len, NULL, 0, 0,
						     SNDRV_CTL_ELEM_TYPE_BYTES);
			} else {
				adsp_warn(dsp,
					  "Missing length info for region XM with ID %x\n",
					  be32_to_cpu(adsp2_alg[i].alg.id));
			}
		}

		alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_YM,
						   adsp2_alg[i].alg.id,
						   adsp2_alg[i].ym);
		if (IS_ERR(alg_region)) {
			ret = PTR_ERR(alg_region);
			goto out;
		}

		if (dsp->fw_ver == 0) {
			if (i + 1 < n_algs) {
				len = be32_to_cpu(adsp2_alg[i + 1].ym);
				len -= be32_to_cpu(adsp2_alg[i].ym);
				len *= 4;
				wm_adsp_create_control(dsp, alg_region, 0,
						     len, NULL, 0, 0,
						     SNDRV_CTL_ELEM_TYPE_BYTES);
			} else {
				adsp_warn(dsp,
					  "Missing length info for region YM with ID %x\n",
					  be32_to_cpu(adsp2_alg[i].alg.id));
			}
		}

		alg_region = wm_adsp_create_region(dsp, WMFW_ADSP2_ZM,
						   adsp2_alg[i].alg.id,
						   adsp2_alg[i].zm);
		if (IS_ERR(alg_region)) {
			ret = PTR_ERR(alg_region);
			goto out;
		}

		if (dsp->fw_ver == 0) {
			if (i + 1 < n_algs) {
				len = be32_to_cpu(adsp2_alg[i + 1].zm);
				len -= be32_to_cpu(adsp2_alg[i].zm);
				len *= 4;
				wm_adsp_create_control(dsp, alg_region, 0,
						     len, NULL, 0, 0,
						     SNDRV_CTL_ELEM_TYPE_BYTES);
			} else {
				adsp_warn(dsp,
					  "Missing length info for region ZM with ID %x\n",
					  be32_to_cpu(adsp2_alg[i].alg.id));
			}
		}
	}

out:
	kfree(adsp2_alg);
	return ret;
}

static int wm_adsp_load_coeff(struct wm_adsp *dsp)
{
	LIST_HEAD(buf_list);
	struct regmap *regmap = dsp->regmap;
	struct wmfw_coeff_hdr *hdr;
	struct wmfw_coeff_item *blk;
	const struct firmware *firmware;
	const struct wm_adsp_region *mem;
	struct wm_adsp_alg_region *alg_region;
	const char *region_name;
	int ret = 0;
	int err, pos, blocks, type, offset, reg;
	char *file;

	if (dsp->firmwares[dsp->fw].binfile &&
	    !(strcmp(dsp->firmwares[dsp->fw].binfile, "None")))
		return 0;

	file = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (file == NULL)
		return -ENOMEM;

	if (dsp->firmwares[dsp->fw].binfile && dsp->firmwares[dsp->fw].full_name)
		snprintf(file, PAGE_SIZE, "%s",
			dsp->firmwares[dsp->fw].binfile);
	else if (dsp->firmwares[dsp->fw].binfile)
		snprintf(file, PAGE_SIZE, "%s-dsp%d-%s.bin", dsp->part,
			 dsp->num, dsp->firmwares[dsp->fw].binfile);
	else
		snprintf(file, PAGE_SIZE, "%s-dsp%d-%s.bin", dsp->part,
			 dsp->num, dsp->firmwares[dsp->fw].file);
	file[PAGE_SIZE - 1] = '\0';

	mutex_lock(dsp->fw_lock);
	ret = request_firmware(&firmware, file, dsp->dev);
	mutex_unlock(dsp->fw_lock);
	if (ret != 0) {
		adsp_warn(dsp, "Failed to request '%s'\n", file);
		ret = 0;
		goto out;
	}
	ret = -EINVAL;

	if (sizeof(*hdr) >= firmware->size) {
		adsp_err(dsp, "%s: file too short, %zu bytes\n",
			file, firmware->size);
		goto out_fw;
	}

	hdr = (void*)&firmware->data[0];
	if (memcmp(hdr->magic, "WMDR", 4) != 0) {
		adsp_err(dsp, "%s: invalid magic\n", file);
		goto out_fw;
	}

	switch (be32_to_cpu(hdr->rev) & 0xff) {
	case 1:
		break;
	default:
		adsp_err(dsp, "%s: Unsupported coefficient file format %d\n",
			 file, be32_to_cpu(hdr->rev) & 0xff);
		ret = -EINVAL;
		goto out_fw;
	}

	adsp_dbg(dsp, "%s: v%d.%d.%d\n", file,
		(le32_to_cpu(hdr->ver) >> 16) & 0xff,
		(le32_to_cpu(hdr->ver) >>  8) & 0xff,
		le32_to_cpu(hdr->ver) & 0xff);

	pos = le32_to_cpu(hdr->len);

	blocks = 0;
	while (pos < firmware->size &&
	       pos - firmware->size > sizeof(*blk)) {
		blk = (void*)(&firmware->data[pos]);

		type = le16_to_cpu(blk->type);
		offset = le16_to_cpu(blk->offset);

		adsp_dbg(dsp, "%s.%d: %x v%d.%d.%d\n",
			 file, blocks, le32_to_cpu(blk->id),
			 (le32_to_cpu(blk->ver) >> 16) & 0xff,
			 (le32_to_cpu(blk->ver) >>  8) & 0xff,
			 le32_to_cpu(blk->ver) & 0xff);
		adsp_dbg(dsp, "%s.%d: %d bytes at 0x%x in %x\n",
			 file, blocks, le32_to_cpu(blk->len), offset, type);

		reg = 0;
		region_name = "Unknown";
		switch (type) {
		case (WMFW_NAME_TEXT << 8):
		case (WMFW_INFO_TEXT << 8):
			break;
		case (WMFW_ABSOLUTE << 8):
			/*
			 * Old files may use this for global
			 * coefficients.
			 */
			if (le32_to_cpu(blk->id) == dsp->fw_id &&
			    offset == 0) {
				region_name = "global coefficients";
				mem = wm_adsp_find_region(dsp, type);
				if (!mem) {
					adsp_err(dsp, "No ZM\n");
					ret = -EINVAL;
					goto out_fw;
				}
				reg = wm_adsp_region_to_reg(mem, 0);

			} else {
				region_name = "register";
				reg = offset;
			}
			break;

		case WMFW_ADSP1_DM:
		case WMFW_ADSP1_ZM:
		case WMFW_ADSP2_XM:
		case WMFW_ADSP2_YM:
			adsp_dbg(dsp, "%s.%d: %d bytes in %x for %x\n",
				 file, blocks, le32_to_cpu(blk->len),
				 type, le32_to_cpu(blk->id));

			mem = wm_adsp_find_region(dsp, type);
			if (!mem) {
				adsp_err(dsp, "No base for region %x\n", type);
				ret = -EINVAL;
				goto out_fw;
			}

			alg_region = wm_adsp_find_alg_region(dsp, type,
						le32_to_cpu(blk->id));
			if (alg_region) {
				reg = alg_region->base;
				reg = wm_adsp_region_to_reg(mem, reg);
				reg += offset;
			} else {
				adsp_err(dsp, "No %x for algorithm %x\n",
					 type, le32_to_cpu(blk->id));
			}
			break;

		default:
			adsp_err(dsp, "%s.%d: Unknown region type %x at %d\n",
				 file, blocks, type, pos);
			ret = -EINVAL;
			goto out_fw;
		}

		if (reg) {
			ret = wm_adsp_write_blocks(dsp, blk->data,
						   le32_to_cpu(blk->len),
						   reg, &buf_list);

			if (ret != 0) {
				adsp_err(dsp,
					"%s.%d: Failed to write to %x in %s: %d\n",
					file, blocks, reg, region_name, ret);
				goto out_fw;
			}
		}

		pos += (le32_to_cpu(blk->len) + sizeof(*blk) + 3) & ~0x03;
		blocks++;
	}

	if (pos > firmware->size)
		adsp_warn(dsp, "%s.%d: %zu bytes at end of file\n",
			  file, blocks, pos - firmware->size);

	err = regmap_async_complete(regmap);
	if (err != 0) {
		adsp_err(dsp, "Failed to complete async write: %d\n", err);
		if (!ret)
			ret = err;
	}

	wm_adsp_debugfs_save_binname(dsp, file);

out_fw:
	regmap_async_complete(regmap);
	release_firmware(firmware);
	wm_adsp_buf_free(&buf_list);
out:
	kfree(file);
	return ret;
}

int wm_adsp1_init(struct wm_adsp *dsp)
{
	INIT_LIST_HEAD(&dsp->alg_regions);

#ifdef CONFIG_DEBUG_FS
	mutex_init(&dsp->debugfs_lock);
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp1_init);

static int wm_adsp_get_features(struct wm_adsp *dsp)
{
	memset(&dsp->fw_features, 0, sizeof(dsp->fw_features));

	switch (dsp->fw_id) {
	case 0x4000d:
	case 0x40036:
	case 0x5f003:
	case 0x6000d:
	case 0x60037:
	case 0x60053:
	case 0x7000d:
	case 0x70036:
	case 0x8000d:
	case 0x80053:
	case 0x9000d:
		/* ez2control */
		dsp->fw_features.ez2control_trigger = true;
		dsp->fw_features.host_read_buf = true;
		break;
	case 0x4001e:
	case 0x5001e:
	case 0x6001e:
	case 0x7001e:
	case 0x8001e:
	case 0x9001e:
		/* trace firmware */
		dsp->fw_features.host_read_buf = true;
		break;
	case 0x40019:
	case 0x4001f:
	case 0x5001f:
	case 0x7001f:
		dsp->fw_features.edac_shutdown = true;
	default:
		break;
	}

	return 0;
}


int wm_adsp1_event(struct snd_soc_dapm_widget *w,
		   struct snd_kcontrol *kcontrol,
		   int event)
{
	struct snd_soc_codec *codec = w->codec;
	struct wm_adsp *dsps = snd_soc_codec_get_drvdata(codec);
	struct wm_adsp *dsp = &dsps[w->shift];
	struct wm_coeff_ctl *ctl;
	int ret;
	unsigned int val;

	dsp->card = codec->component.card;

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_30,
				   ADSP1_SYS_ENA, ADSP1_SYS_ENA);

		/*
		 * For simplicity set the DSP clock rate to be the
		 * SYSCLK rate rather than making it configurable.
		 */
		if(dsp->sysclk_reg) {
			ret = regmap_read(dsp->regmap, dsp->sysclk_reg, &val);
			if (ret != 0) {
				adsp_err(dsp, "Failed to read SYSCLK state: %d\n",
				ret);
				return ret;
			}

			val = (val & dsp->sysclk_mask) >> dsp->sysclk_shift;

			ret = regmap_update_bits(dsp->regmap,
						 dsp->base + ADSP1_CONTROL_31,
						 ADSP1_CLK_SEL_MASK, val);
			if (ret != 0) {
				adsp_err(dsp, "Failed to set clock rate: %d\n",
					 ret);
				return ret;
			}
		}

		ret = wm_adsp_load(dsp);
		if (ret != 0)
			goto err;

		ret = wm_adsp1_setup_algs(dsp);
		if (ret != 0)
			goto err;

		ret = wm_adsp_load_coeff(dsp);
		if (ret != 0)
			goto err;

		/* Initialize caches for enabled and unset controls */
		ret = wm_coeff_init_control_caches(dsp);
		if (ret != 0)
			goto err;

		/* Sync set controls */
		ret = wm_coeff_sync_controls(dsp);
		if (ret != 0)
			goto err;

		/* Start the core running */
		regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_30,
				   ADSP1_CORE_ENA | ADSP1_START,
				   ADSP1_CORE_ENA | ADSP1_START);
		break;

	case SND_SOC_DAPM_PRE_PMD:
		/* Halt the core */
		regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_30,
				   ADSP1_CORE_ENA | ADSP1_START, 0);

		regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_19,
				   ADSP1_WDMA_BUFFER_LENGTH_MASK, 0);

		regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_30,
				   ADSP1_SYS_ENA, 0);

		list_for_each_entry(ctl, &dsp->ctl_list, list)
			ctl->enabled = 0;


		wm_adsp_free_alg_regions(dsp);
		break;

	default:
		break;
	}

	return 0;

err:
	regmap_update_bits(dsp->regmap, dsp->base + ADSP1_CONTROL_30,
			   ADSP1_SYS_ENA, 0);
	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp1_event);

static int wm_adsp2_ena(struct wm_adsp *dsp)
{
	unsigned int val;
	int ret, count;

	switch (dsp->rev) {
	case 0:
		ret = regmap_update_bits_async(dsp->regmap,
						dsp->base + ADSP2_CONTROL,
						ADSP2_SYS_ENA, ADSP2_SYS_ENA);
		if (ret != 0)
			return ret;

		/* Wait for the RAM to start, should be near instantaneous */
		for (count = 0; count < 10; ++count) {
			ret = regmap_read(dsp->regmap,
					  dsp->base + ADSP2_STATUS1,
					  &val);
			if (ret != 0)
				return ret;

			if (val & ADSP2_RAM_RDY)
				break;

			msleep(1);
		}

		if (!(val & ADSP2_RAM_RDY)) {
			adsp_err(dsp, "Failed to start DSP RAM\n");
			return -EBUSY;
		}
		adsp_dbg(dsp, "RAM ready after %d polls\n", count);
		break;
	default:
		ret = regmap_update_bits(dsp->regmap, dsp->base + ADSP2_CONTROL,
				 ADSP2_MEM_ENA, ADSP2_MEM_ENA);

		if (ret != 0)
			return ret;

		break;
	}

	return 0;
}

static void wm_adsp2_boot_work(struct work_struct *work)
{
	struct wm_adsp *dsp = container_of(work,
					   struct wm_adsp,
					   boot_work);
	int ret;

	ret = wm_adsp2_ena(dsp);
	if (ret != 0)
		return;

	ret = wm_adsp_load(dsp);
	if (ret != 0)
		goto err;

	ret = wm_adsp2_setup_algs(dsp);
	if (ret != 0)
		goto err;

	ret = wm_adsp_load_coeff(dsp);
	if (ret != 0)
		goto err;

	/* Initialize caches for enabled and unset controls */
	ret = wm_coeff_init_control_caches(dsp);
	if (ret != 0)
		goto err;

	/* Sync set controls */
	ret = wm_coeff_sync_controls(dsp);
	if (ret != 0)
		goto err;

	/* Check firmware features */
	ret = wm_adsp_get_features(dsp);
	if (ret != 0)
		goto err;

	/* Populate HP impedance coefficients */
	ret = wm_adsp_hpimp_update(dsp);
	if (ret != 0)
		goto err;

	dsp->running = true;

	return;

err:
	regmap_update_bits(dsp->regmap, dsp->base + ADSP2_CONTROL,
			   ADSP2_SYS_ENA | ADSP2_CORE_ENA | ADSP2_START, 0);
}

static void wm_adsp2_set_dspclk(struct wm_adsp *dsp, unsigned int freq)
{
	int ret;
	unsigned int mask, val;

	switch (dsp->rev) {
	case 0:
		ret = regmap_update_bits(dsp->regmap,
					 dsp->base + ADSP2_CLOCKING,
					 ADSP2_CLK_SEL_MASK,
					 freq << ADSP2_CLK_SEL_SHIFT);
		if (ret != 0) {
			adsp_err(dsp, "Failed to set clock rate: %d\n", ret);
			return;
		}
		break;
	default:
		mutex_lock(&dsp->rate_lock);

		mask = ADSP2V2_RATE_MASK;
		val = dsp->rate_cache << ADSP2V2_RATE_SHIFT;

		switch (dsp->rev) {
		case 0:
		case 1:
			/* use legacy frequency registers */
			mask |= ADSP2V2_CLK_SEL_MASK;
			val |= (freq << ADSP2V2_CLK_SEL_SHIFT);
			break;
		default:
			/* Configure exact dsp frequency */
			ret = regmap_write(dsp->regmap,
					dsp->base + ADSP2V2_CLOCKING,
					freq);
			if (ret != 0) {
				adsp_err(dsp,
					 "Failed to set DSP freq: %d\n",
					 ret);
				mutex_unlock(&dsp->rate_lock);
				return;
			}
			break;
		}

		ret = dsp->rate_put_cb(dsp, mask, val);
		if (ret != 0) {
			adsp_err(dsp, "Failed to set DSP_CLK rate: %d\n", ret);
			mutex_unlock(&dsp->rate_lock);
			return;
		}

		mutex_unlock(&dsp->rate_lock);
		break;
	}
}

int wm_adsp2_early_event(struct snd_soc_dapm_widget *w,
		   struct snd_kcontrol *kcontrol, int event,
		   unsigned int freq)
{
	struct snd_soc_codec *codec = w->codec;
	struct wm_adsp *dsps = snd_soc_codec_get_drvdata(codec);
	struct wm_adsp *dsp = &dsps[w->shift];

	dsp->card = codec->component.card;

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		dsp->freq_cache = freq;
		wm_adsp2_set_dspclk(dsp, freq);
		queue_work(system_unbound_wq, &dsp->boot_work);
		break;
	default:
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp2_early_event);

static void wm_adsp_edac_shutdown(struct wm_adsp *dsp)
{
	int i, ret;
	unsigned int val = 1;
	const struct wm_adsp_region *mem;

	mem = wm_adsp_find_region(dsp, WMFW_ADSP2_YM);
	if (!mem) {
		adsp_err(dsp, "Failed to locate YM\n");
		return;
	}

	ret = regmap_write(dsp->regmap, mem->base + 0x1, val);
	if (ret != 0) {
		adsp_err(dsp,
			 "Failed to inform eDAC to shutdown: %d\n",
			 ret);
		return;
	}

	for (i = 0; i < 5; ++i) {
		ret = regmap_read(dsp->regmap, mem->base + 0x1, &val);
		if (ret != 0) {
			adsp_err(dsp,
				 "Failed to check for eDAC shutdown: %d\n",
				 ret);
			return;
		}

		if (!val)
			break;

		msleep(1);
	}

	if (val)
		adsp_err(dsp, "Failed to shutdown eDAC firmware\n");
}

static inline void wm_adsp_stop_watchdog(struct wm_adsp *dsp)
{
	switch (dsp->rev) {
	case 0:
	case 1:
		return;
	default:
		regmap_update_bits(dsp->regmap,
			dsp->base + ADSP2_WATCHDOG,
			ADSP2_WDT_ENA_MASK, 0);
	}
}

static int wm_adsp2_start_dsp(struct wm_adsp *dsp)
{
	int ret;

	flush_work(&dsp->boot_work);

	if (!dsp->running)
		return -EIO;

	wm_adsp2_lock(dsp, dsp->lock_regions);

	ret = regmap_update_bits(dsp->regmap,
			dsp->base + ADSP2_CONTROL,
			ADSP2_CORE_ENA | ADSP2_START,
			ADSP2_CORE_ENA | ADSP2_START);
	if (ret != 0)
		return ret;

	if (dsp->fw_features.host_read_buf &&
	    dsp->firmwares[dsp->fw].num_caps != 0) {
		ret = wm_adsp_init_host_buf_info(&dsp->compr_buf);
		if (ret < 0) {
			adsp_err(dsp,
				"Failed to init host buffer (%d)\n",
				ret);
			return ret;
		}
	}

	return 0;
}

static int wm_adsp2_shutdown_dsp(struct wm_adsp *dsp)
{
	struct wm_coeff_ctl *ctl;

	/* Log firmware state, it can be useful for analysis */
	switch (dsp->rev) {
	case 0:
		wm_adsp2_show_fw_status(dsp);
		break;
	default:
		wm_adsp2v2_show_fw_status(dsp);
		break;
	};

	if (dsp->fw_features.edac_shutdown)
		wm_adsp_edac_shutdown(dsp);
	else
		wm_adsp_signal_event_controls(dsp,
					      WM_ADSP_FW_EVENT_SHUTDOWN);

	wm_adsp_stop_watchdog(dsp);

	dsp->running = false;

	if (dsp->fw_features.host_read_buf) {
		adsp_dbg(dsp, "host buf invalidated by DSP shutdown\n");
		wm_adsp_free_host_buf_info(&dsp->compr_buf);
	}

	wm_adsp_debugfs_clear(dsp);

	dsp->fw_id = 0;
	dsp->fw_id_version = 0;
	dsp->running = false;

	switch (dsp->rev) {
	case 0:
		regmap_update_bits(dsp->regmap,
				   dsp->base + ADSP2_CONTROL,
				   ADSP2_SYS_ENA | ADSP2_CORE_ENA |
				   ADSP2_START, 0);

		/* Make sure DMAs are quiesced */
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2_WDMA_CONFIG_1, 0);
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2_WDMA_CONFIG_2, 0);
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2_RDMA_CONFIG_1, 0);
		break;
	default:
		regmap_update_bits(dsp->regmap,
				   dsp->base + ADSP2_CONTROL,
				   ADSP2_MEM_ENA | ADSP2_SYS_ENA |
				   ADSP2_CORE_ENA | ADSP2_START, 0);

		/* Make sure DMAs are quiesced */
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2_WDMA_CONFIG_1, 0);
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2V2_WDMA_CONFIG_2, 0);
		regmap_write(dsp->regmap,
				 dsp->base + ADSP2_RDMA_CONFIG_1, 0);
		break;
	}

	list_for_each_entry(ctl, &dsp->ctl_list, list)
		ctl->enabled = 0;

	wm_adsp_free_alg_regions(dsp);

	adsp_info(dsp, "Shutdown complete\n");

	return 0;
}

int wm_adsp2_event(struct snd_soc_dapm_widget *w,
		   struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = w->codec;
	struct wm_adsp *dsps = snd_soc_codec_get_drvdata(codec);
	struct wm_adsp *dsp = &dsps[w->shift];
	int ret;

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		ret = wm_adsp2_start_dsp(dsp);
		if (ret != 0)
			goto err;
		break;
	case SND_SOC_DAPM_PRE_PMD:
		wm_adsp2_shutdown_dsp(dsp);
		break;
	default:
		break;
	}

	return 0;
err:
	regmap_update_bits(dsp->regmap, dsp->base + ADSP2_CONTROL,
			   ADSP2_SYS_ENA | ADSP2_CORE_ENA | ADSP2_START, 0);
	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp2_event);

#ifdef CONFIG_OF
static int wm_adsp_of_parse_caps(struct wm_adsp *dsp,
				 struct device_node *np,
				 struct wm_adsp_fw_defs *fw)
{
	const char *prop = "wlf,compr-caps";
	int i;
	int len_prop;
	u32 of_cap;

	if (!of_get_property(np, prop, &len_prop))
		return -EINVAL;

	len_prop /= sizeof(u32);

	if (len_prop < 5 || len_prop > 5 + MAX_NUM_SAMPLE_RATES)
		return -EOVERFLOW;

	fw->num_caps = 1;
	fw->caps = devm_kzalloc(dsp->dev,
				sizeof(struct wm_adsp_fw_caps),
				GFP_KERNEL);
	if (!fw->caps)
		return -ENOMEM;

	fw->caps->num_host_regions = ARRAY_SIZE(ez2control_regions);
	fw->caps->host_region_defs =
		devm_kzalloc(dsp->dev,
			     sizeof(ez2control_regions),
			     GFP_KERNEL);
	if (!fw->caps->host_region_defs)
		return -ENOMEM;

	memcpy(fw->caps->host_region_defs,
	       ez2control_regions,
	       sizeof(ez2control_regions));

	of_property_read_u32_index(np, prop, 0, &of_cap);
	fw->caps->id = of_cap;
	of_property_read_u32_index(np, prop, 1, &of_cap);
	fw->caps->desc.max_ch = of_cap;
	of_property_read_u32_index(np, prop, 2, &of_cap);
	fw->caps->desc.formats = of_cap;
	of_property_read_u32_index(np, prop, 3, &of_cap);
	fw->compr_direction = of_cap;

	for (i = 4; i < len_prop; ++i) {
		of_property_read_u32_index(np, prop, i, &of_cap);
		fw->caps->desc.sample_rates[i - 4] = of_cap;
	}
	fw->caps->desc.num_sample_rates = i - 4;

	return 0;
}

static int wm_adsp_of_parse_firmware(struct wm_adsp *dsp,
				     struct device_node *np)
{
	struct device_node *fws = of_get_child_by_name(np, "firmware");
	struct device_node *fw = NULL;
	const char **ctl_names;
	int ret;
	int i;

	if (!fws)
		return 0;

	i = 0;
	while ((fw = of_get_next_child(fws, fw)) != NULL)
		i++;

	if (i == 0)
		return 0;

	dsp->num_firmwares = i;

	dsp->firmwares = devm_kzalloc(dsp->dev,
				       i * sizeof(struct wm_adsp_fw_defs),
				       GFP_KERNEL);
	if (!dsp->firmwares)
		return -ENOMEM;

	ctl_names = devm_kzalloc(dsp->dev,
				 i * sizeof(const char *),
				 GFP_KERNEL);
	if (!ctl_names)
		return -ENOMEM;

	i = 0;
	while ((fw = of_get_next_child(fws, fw)) != NULL) {
		ctl_names[i] = fw->name;
		dsp->firmwares[i].name = fw->name;

		ret = of_property_read_string(fw, "wlf,wmfw-file",
					      &dsp->firmwares[i].file);
		if (ret < 0) {
			adsp_err(dsp,
				 "Firmware filename missing/malformed: %d\n",
				 ret);
			return ret;
		}

		ret = of_property_read_string(fw, "wlf,bin-file",
					      &dsp->firmwares[i].binfile);
		if (ret < 0)
			dsp->firmwares[i].binfile = NULL;

		dsp->firmwares[i].full_name =
			of_property_read_bool(fw, "wlf,full-name");

		wm_adsp_of_parse_caps(dsp, fw, &dsp->firmwares[i]);

		i++;
	}

	wm_adsp_fw_enum[dsp->num - 1].items = dsp->num_firmwares;
	wm_adsp_fw_enum[dsp->num - 1].texts = ctl_names;

	return dsp->num_firmwares;
}

static int wm_adsp_of_parse_adsp(struct wm_adsp *dsp)
{
	struct device_node *np = of_get_child_by_name(dsp->dev->of_node,
						      "adsps");
	struct device_node *core = NULL;
	unsigned int addr;
	int ret;

	if (!np)
		return 0;

	while ((core = of_get_next_child(np, core)) != NULL) {
		ret = of_property_read_u32(core, "reg", &addr);
		if (ret < 0) {
			adsp_err(dsp,
				 "Failed to get ADSP base address: %d\n",
				 ret);
			return ret;
		}

		if (addr == dsp->base)
			break;
	}

	if (!core)
		return 0;

	return wm_adsp_of_parse_firmware(dsp, core);
}
#else
static inline int wm_adsp_of_parse_adsp(struct wm_adsp *dsp)
{
	return 0;
}
#endif

int wm_adsp2_codec_probe(struct wm_adsp *dsp, struct snd_soc_codec *codec)
{
	wm_adsp2_init_debugfs(dsp, codec);

	return snd_soc_add_codec_controls(codec,
					  &wm_adsp_fw_controls[dsp->num - 1],
					  1);
}
EXPORT_SYMBOL_GPL(wm_adsp2_codec_probe);

int wm_adsp2_codec_remove(struct wm_adsp *dsp, struct snd_soc_codec *codec)
{
	wm_adsp2_cleanup_debugfs(dsp);

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp2_codec_remove);

int wm_adsp2_init(struct wm_adsp *dsp, struct mutex *fw_lock)
{
	int ret, i;
	const char **ctl_names;

	switch (dsp->rev) {
	case 0:
		/*
		 * Disable the DSP memory by default when in reset for a small
		 * power saving
		 */
		ret = regmap_update_bits(dsp->regmap, dsp->base + ADSP2_CONTROL,
					 ADSP2_MEM_ENA, 0);
		if (ret != 0) {
			adsp_err(dsp, "Failed to clear memory retention: %d\n",
				 ret);
			return ret;
		}
		break;

	default:
		break;
	}

	INIT_LIST_HEAD(&dsp->alg_regions);
	INIT_LIST_HEAD(&dsp->ctl_list);
	INIT_WORK(&dsp->boot_work, wm_adsp2_boot_work);
	mutex_init(&dsp->ctl_lock);
	mutex_init(&dsp->rate_lock);
	mutex_init(&dsp->compr_buf.lock);

	dsp->fw_lock = fw_lock;

	dsp->compr_buf.dsp = dsp;

	if (!dsp->num_firmwares) {
		if (!dsp->dev->of_node || wm_adsp_of_parse_adsp(dsp) <= 0) {
			dsp->num_firmwares = WM_ADSP_NUM_FW;
			dsp->firmwares = wm_adsp_fw;
			for (i = 0; i < dsp->num_firmwares; i++)
				dsp->firmwares[i].name = wm_adsp_fw_text[i];
		}
	} else {
		ctl_names = devm_kzalloc(dsp->dev,
				dsp->num_firmwares * sizeof(const char *),
				GFP_KERNEL);

		for (i = 0; i < dsp->num_firmwares; i++)
			ctl_names[i] = dsp->firmwares[i].name;

		wm_adsp_fw_enum[dsp->num - 1].items = dsp->num_firmwares;
		wm_adsp_fw_enum[dsp->num - 1].texts = ctl_names;
	}

#ifdef CONFIG_DEBUG_FS
	mutex_init(&dsp->debugfs_lock);
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp2_init);

void wm_adsp2_remove(struct wm_adsp *dsp)
{
	struct wm_coeff_ctl *ctl;

	while (!list_empty(&dsp->ctl_list)) {
		ctl = list_first_entry(&dsp->ctl_list, struct wm_coeff_ctl,
					list);
		list_del(&ctl->list);
		wm_adsp_free_ctl_blk(ctl);
	}

	if (dsp->firmwares != wm_adsp_fw) {
		if (wm_adsp_fw_enum[dsp->num - 1].texts != wm_adsp_fw_text)
			kfree(wm_adsp_fw_enum[dsp->num - 1].texts);

		kfree(dsp->firmwares);
	}
}
EXPORT_SYMBOL_GPL(wm_adsp2_remove);

static bool wm_adsp_compress_supported(const struct wm_adsp *dsp,
				const struct snd_compr_stream *stream)
{
	if (dsp->fw >= 0 && dsp->fw < dsp->num_firmwares) {
		const struct wm_adsp_fw_defs *fw_defs =
				&dsp->firmwares[dsp->fw];

		if (fw_defs->num_caps == 0)
			return false;

		if (fw_defs->compr_direction == stream->direction)
			return true;
	}

	return false;
}

int wm_adsp_compr_open(struct wm_adsp_compr *compr,
			struct snd_compr_stream *stream)
{
	if (compr->stream)
		return -EBUSY;

	if (!wm_adsp_compress_supported(compr->dsp, stream)) {
		adsp_err(compr->dsp,
			"Firmware does not support compressed stream\n");
		return -EINVAL;
	}

	compr->buf = &compr->dsp->compr_buf;
	compr->stream = stream;
	stream->runtime->private_data = compr;

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_open);

int wm_adsp_compr_free(struct snd_compr_stream *stream)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	struct wm_adsp_compr_buf *buf;

	if (!compr)
		return -EINVAL;

	/* Take buffer lock to prevent race conditions with the IRQ handler
	 * while we disconnect the buffer from the stream
	 */
	if (compr->buf) {
		buf = compr->buf;
		mutex_lock(&buf->lock);

		compr->buf = NULL;
		compr->stream = NULL;

		mutex_unlock(&buf->lock);
	}

	compr->copied_total = 0;
	compr->sample_rate = 0;

	stream->runtime->private_data = NULL;

	kfree(compr->capt_buf);
	compr->capt_buf = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_free);

static int wm_adsp_compr_check_params(struct snd_compr_stream *stream,
				      struct snd_compr_params *params)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	struct wm_adsp *dsp = compr->dsp;
	const struct wm_adsp_fw_caps *caps;
	const struct snd_codec_desc *desc;
	int i, j;

	if (params->buffer.fragment_size < WM_ADSP_MIN_FRAGMENT_SIZE ||
	    params->buffer.fragment_size > WM_ADSP_MAX_FRAGMENT_SIZE ||
	    params->buffer.fragments < WM_ADSP_MIN_FRAGMENTS ||
	    params->buffer.fragments > WM_ADSP_MAX_FRAGMENTS ||
	    params->buffer.fragment_size % WM_ADSP_DATA_WORD_SIZE) {
		adsp_err(dsp, "Invalid buffer fragsize=%d fragments=%d\n",
			 params->buffer.fragment_size,
			 params->buffer.fragments);
		return -EINVAL;
	}

	for (i = 0; i < dsp->firmwares[dsp->fw].num_caps; i++) {
		caps = &dsp->firmwares[dsp->fw].caps[i];
		desc = &caps->desc;

		if (caps->id != params->codec.id)
			continue;

		if (stream->direction == SND_COMPRESS_PLAYBACK) {
			if (desc->max_ch < params->codec.ch_out)
				continue;
		} else {
			if (desc->max_ch < params->codec.ch_in)
				continue;
		}

		if (!(desc->formats & (1 << params->codec.format)))
			continue;

		for (j = 0; j < desc->num_sample_rates; ++j)
			if (desc->sample_rates[j] == params->codec.sample_rate)
				return 0;
	}

	adsp_err(dsp, "Invalid params id=%u ch=%u,%u rate=%u fmt=%u\n",
		 params->codec.id, params->codec.ch_in, params->codec.ch_out,
		 params->codec.sample_rate, params->codec.format);

	return -EINVAL;
}

static int wm_adsp_streambuf_alloc(struct wm_adsp_compr *compr,
			 const struct snd_compr_params *params)
{
	unsigned int size;

	if (params->buffer.fragment_size == 0)
		return -EINVAL;

	compr->max_read_words =
		params->buffer.fragment_size / WM_ADSP_DATA_WORD_SIZE;

	if (!compr->capt_buf) {
		size = compr->max_read_words * sizeof(*compr->capt_buf);
		compr->capt_buf = kmalloc(size, GFP_DMA | GFP_KERNEL);

		if (!compr->capt_buf)
			return -ENOMEM;
	}

	compr->irq_watermark = params->buffer.fragment_size /
				WM_ADSP_DATA_WORD_SIZE;

	return 0;
}

int wm_adsp_compr_set_params(struct snd_compr_stream *stream,
			     struct snd_compr_params *params)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	int ret;

	ret = wm_adsp_compr_check_params(stream, params);
	if (ret)
		return ret;

	ret = wm_adsp_streambuf_alloc(compr, params);

	compr->sample_rate = params->codec.sample_rate;

	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_set_params);

int wm_adsp_compr_get_caps(struct snd_compr_stream *stream,
			   struct snd_compr_caps *caps)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	struct wm_adsp *dsp = compr->dsp;
	int i;

	memset(caps, 0, sizeof(*caps));

	caps->direction = stream->direction;
	caps->min_fragment_size = WM_ADSP_MIN_FRAGMENT_SIZE;
	caps->max_fragment_size = WM_ADSP_MAX_FRAGMENT_SIZE;
	caps->min_fragments = WM_ADSP_MIN_FRAGMENTS;
	caps->max_fragments = WM_ADSP_MAX_FRAGMENTS;

	if (dsp->firmwares[dsp->fw].caps) {
		for (i = 0; i < dsp->firmwares[dsp->fw].num_caps; i++)
			caps->codecs[i] = dsp->firmwares[dsp->fw].caps[i].id;

		caps->num_codecs = i;
		caps->direction = dsp->firmwares[dsp->fw].compr_direction;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_get_caps);

static int wm_adsp_read_data_block(struct wm_adsp *dsp, int mem_type,
				   unsigned int mem_addr,
				   unsigned int num_words,
				   u32 *data)
{
	struct wm_adsp_region const *mem = wm_adsp_find_region(dsp,
							       mem_type);
	unsigned int i, reg;
	int ret;

	if (!mem)
		return -EINVAL;

	reg = wm_adsp_region_to_reg(mem, mem_addr);

	ret = regmap_raw_read(dsp->regmap, reg, data,
			      sizeof(*data) * num_words);
	if (ret < 0)
		return ret;

	for (i = 0; i < num_words; ++i)
		data[i] = be32_to_cpu(data[i]) & 0x00ffffffu;

	return 0;
}

static int wm_adsp_read_data_word(struct wm_adsp *dsp, int mem_type,
				  unsigned int mem_addr, u32 *data)
{
	return wm_adsp_read_data_block(dsp, mem_type, mem_addr, 1, data);
}

static int wm_adsp_write_data_word(struct wm_adsp *dsp, int mem_type,
				   unsigned int mem_addr, u32 data)
{
	struct wm_adsp_region const *mem = wm_adsp_find_region(dsp,
							       mem_type);
	unsigned int reg;

	if (!mem)
		return -EINVAL;

	reg = wm_adsp_region_to_reg(mem, mem_addr);

	data = cpu_to_be32(data & 0x00ffffffu);

	return regmap_raw_write(dsp->regmap, reg, &data, sizeof(data));
}

static inline int wm_adsp_host_buffer_read(struct wm_adsp_compr_buf *buf,
					   unsigned int field_offset, u32 *data)
{
	lockdep_assert_held(&buf->lock);

	return wm_adsp_read_data_word(buf->dsp, WMFW_ADSP2_XM,
				      buf->host_buf_ptr +
				      field_offset,
				      data);
}

static inline int wm_adsp_host_buffer_write(struct wm_adsp_compr_buf *buf,
					    unsigned int field_offset, u32 data)
{
	lockdep_assert_held(&buf->lock);

	return wm_adsp_write_data_word(buf->dsp, WMFW_ADSP2_XM,
				       buf->host_buf_ptr +
				       field_offset,
				       data);
}

static int wm_adsp_buffer_locate(struct wm_adsp_compr_buf *buf)
{
	struct wm_adsp_alg_region *alg_region;
	struct wm_adsp *dsp = buf->dsp;
	u32 xmalg, addr, magic;
	int i, ret;

	alg_region = wm_adsp_find_alg_region(dsp, WMFW_ADSP2_XM, dsp->fw_id);
	xmalg = sizeof(struct wm_adsp_system_config_xm_hdr) / sizeof(__be32);

	addr = alg_region->base + xmalg + ALG_XM_FIELD(magic);
	ret = wm_adsp_read_data_word(dsp, WMFW_ADSP2_XM, addr, &magic);
	if (ret < 0)
		return ret;

	if (magic != WM_ADSP_ALG_XM_STRUCT_MAGIC)
		return -EINVAL;

	addr = alg_region->base + xmalg + ALG_XM_FIELD(host_buf_ptr);
	for (i = 0; i < 5; ++i) {
		ret = wm_adsp_read_data_word(dsp, WMFW_ADSP2_XM, addr,
					     &buf->host_buf_ptr);
		if (ret < 0)
			return ret;

		if (buf->host_buf_ptr)
			break;

		msleep(10);
	}

	if (!buf->host_buf_ptr)
		return -EIO;

	adsp_dbg(dsp, "host_buf_ptr=%x\n", buf->host_buf_ptr);

	return 0;
}

static int wm_adsp_populate_buffer_regions(struct wm_adsp_compr_buf *buf)
{
	int i, ret;
	u32 offset = 0;
	struct wm_adsp *dsp = buf->dsp;
	struct wm_adsp_buffer_region_def *host_region_defs =
		dsp->firmwares[dsp->fw].caps->host_region_defs;
	struct wm_adsp_buffer_region *region;

	lockdep_assert_held(&buf->lock);

	BUG_ON(buf->host_regions != NULL);

	buf->host_regions =
		kcalloc(dsp->firmwares[dsp->fw].caps->num_host_regions,
			sizeof(*buf->host_regions),
			GFP_KERNEL);

	if (!buf->host_regions)
		return -ENOMEM;

	for (i = 0; i < dsp->firmwares[dsp->fw].caps->num_host_regions; ++i) {
		region = &buf->host_regions[i];

		region->offset = offset;
		region->mem_type = host_region_defs[i].mem_type;

		ret = wm_adsp_host_buffer_read(buf,
					       host_region_defs[i].base_offset,
					       &region->base_addr);
		if (ret < 0)
			return ret;

		ret = wm_adsp_host_buffer_read(buf,
					       host_region_defs[i].size_offset,
					       &offset);
		if (ret < 0)
			return ret;

		region->cumulative_size = offset;

		adsp_dbg(dsp,
			 "Region %d type %d base %04x off %04x size %04x\n",
			 i, region->mem_type, region->base_addr,
			 region->offset, region->cumulative_size);
	}

	return 0;
}

static int wm_adsp_init_host_buf_info(struct wm_adsp_compr_buf *buf)
{
	int ret;

	mutex_lock(&buf->lock);

	buf->read_index = -1;
	buf->irq_ack = 0xFFFFFFFF;
	buf->error = 0;
	buf->avail = 0;

	ret = wm_adsp_buffer_locate(buf);
	if (ret < 0) {
		adsp_err(buf->dsp, "Failed to acquire host buffer: %d\n", ret);
		goto out;
	}

	ret = wm_adsp_populate_buffer_regions(buf);
	if (ret < 0)
		adsp_err(buf->dsp, "Failed to populate host buffer: %d\n", ret);

out:
	mutex_unlock(&buf->lock);

	return ret;
}

static void wm_adsp_free_host_buf_info(struct wm_adsp_compr_buf *buf)
{
	struct wm_adsp_buffer_region *host_regions;

	mutex_lock(&buf->lock);

	host_regions = buf->host_regions;
	buf->host_regions = NULL;
	buf->host_buf_ptr = 0;

	mutex_unlock(&buf->lock);

	kfree(host_regions);
}

static inline int wm_adsp_buffer_size(struct wm_adsp_compr_buf *buf)
{
	const struct wm_adsp *dsp = buf->dsp;
	int last_region = dsp->firmwares[dsp->fw].caps->num_host_regions - 1;

	return buf->host_regions[last_region].cumulative_size;
}

static int wm_adsp_stream_start(struct wm_adsp_compr *compr)
{
	struct wm_adsp_compr_buf *buf = compr->buf;
	int ret;

	mutex_lock(&buf->lock);

	if (!buf->host_buf_ptr) {
		adsp_warn(buf->dsp, "No host buffer info\n");
		ret = -EIO;
		goto out_unlock;
	}

	buf->read_index = -1;
	buf->avail = 0;

	ret = wm_adsp_host_buffer_write(buf,
					HOST_BUFFER_FIELD(high_water_mark),
					compr->irq_watermark);
	if (ret < 0)
		goto out_unlock;

	adsp_dbg(buf->dsp, "Set watermark to %u\n", compr->irq_watermark);

out_unlock:
	mutex_unlock(&buf->lock);

	return ret;
}

int wm_adsp_compr_trigger(struct snd_compr_stream *stream, int cmd)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		return wm_adsp_stream_start(compr);
	case SNDRV_PCM_TRIGGER_STOP:
		return 0;
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_trigger);

static int wm_adsp_buffer_update_avail(struct wm_adsp_compr_buf *buf)
{
	u32 next_read_index, next_write_index;
	int write_index, read_index, avail;
	int ret;

	lockdep_assert_held(&buf->lock);

	/* Only sync the read index if we haven't already read a valid index */
	if (buf->read_index < 0) {
		ret = wm_adsp_host_buffer_read(buf,
					HOST_BUFFER_FIELD(next_read_index),
					&next_read_index);
		if (ret < 0)
			return ret;

		read_index = sign_extend32(next_read_index, 23);

		if (read_index < 0) {
			adsp_dbg(buf->dsp, "Avail check on unstarted stream\n");
			return 0;
		}

		buf->read_index = read_index;
	}

	ret = wm_adsp_host_buffer_read(buf,
				       HOST_BUFFER_FIELD(next_write_index),
				       &next_write_index);
	if (ret < 0)
		return ret;

	write_index = sign_extend32(next_write_index, 23);

	avail = write_index - buf->read_index;
	if (avail < 0)
		avail += wm_adsp_buffer_size(buf);

	adsp_dbg(buf->dsp, "readindex=0x%x, writeindex=0x%x, avail=%d\n",
		 buf->read_index, write_index, avail);

	buf->avail = avail;

	return 0;
}

static int wm_adsp_buffer_has_error_locked(struct wm_adsp_compr_buf *buf)
{
	int ret;

	lockdep_assert_held(&buf->lock);

	if (buf->error != 0)
		return -EIO;

	ret = wm_adsp_host_buffer_read(buf,
					HOST_BUFFER_FIELD(error),
					&buf->error);
	if (ret < 0) {
		adsp_err(buf->dsp, "Failed to read error field: %d\n", ret);
		return ret;
	}

	if (buf->error != 0) {
		/* log the first time we see the error */
		adsp_warn(buf->dsp,  "DSP stream error occurred: %d\n",
			  buf->error);
		return -EIO;
	}

	return 0;
}

int wm_adsp_compr_irq(struct wm_adsp_compr *compr, bool *trigger)
{
	struct wm_adsp_compr_buf *buf = &compr->dsp->compr_buf;
	int ret;

	if (!buf)
		return -ENODEV;

	mutex_lock(&buf->lock);

	if (!buf->host_buf_ptr) {
		if (trigger)
			*trigger = true;
		ret = 0;
		goto out_buf_unlock;
	}

	ret = wm_adsp_buffer_has_error_locked(buf);
	if (ret)
		goto out_notify; /* Wake the poll to report error */

	ret = wm_adsp_host_buffer_read(buf, HOST_BUFFER_FIELD(irq_count),
					&buf->irq_ack);
	if (ret < 0) {
		adsp_err(buf->dsp, "Failed to get irq_count: %d\n", ret);
		goto out_buf_unlock;
	}

	if (trigger) {
		/* irq_count = 2 only on the initial trigger */
		if (buf->irq_ack == 2)
			*trigger = true;
		else
			*trigger = false;
	}

	/* Fetch read_index and update count of available data */
	ret = wm_adsp_buffer_update_avail(buf);
	if (ret < 0) {
		adsp_err(buf->dsp, "Error reading read_index: %d\n", ret);
		goto out_buf_unlock;
	}

out_notify:
	if (compr->stream)
		snd_compr_fragment_elapsed(compr->stream);

out_buf_unlock:
	mutex_unlock(&buf->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_irq);

static int wm_adsp_buffer_ack_irq(struct wm_adsp_compr_buf *buf)
{
	if (buf->irq_ack & 0x01)
		return 0;

	adsp_dbg(buf->dsp, "Acking buffer IRQ(0x%x)\n", buf->irq_ack);

	buf->irq_ack |= 0x01;

	return wm_adsp_host_buffer_write(buf, HOST_BUFFER_FIELD(irq_ack),
					 buf->irq_ack);
}

int wm_adsp_compr_pointer(struct snd_compr_stream *stream,
			  struct snd_compr_tstamp *tstamp)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	struct wm_adsp_compr_buf *buf = compr->buf;
	int ret = 0;

	mutex_lock(&buf->lock);

	tstamp->copied_total = compr->copied_total;
	tstamp->sampling_rate = compr->sample_rate;

	if (!buf->host_buf_ptr) {
		adsp_warn(buf->dsp, "No host buffer info\n");
		ret = -EIO;
		goto out_buf_unlock;
	}

	ret = wm_adsp_buffer_has_error_locked(buf);
	if (ret)
		goto out_buf_unlock;

	if (buf->avail < compr->max_read_words) {
		ret = wm_adsp_buffer_update_avail(buf);
		if (ret < 0) {
			adsp_err(compr->dsp, "Error reading avail: %d\n", ret);
			goto out_buf_unlock;
		}

		/*
		 * If we really have less than 1 fragment available ack the
		 * last DSP IRQ and rely on the IRQ to inform us when a whole
		 * fragment is available.
		 */
		if (buf->avail < compr->max_read_words) {
			ret = wm_adsp_buffer_ack_irq(buf);
			if (ret < 0) {
				adsp_err(compr->dsp,
					"Failed to ack buffer IRQ: %d\n", ret);
				goto out_buf_unlock;
			}
		}
	}

	tstamp->copied_total += buf->avail * WM_ADSP_DATA_WORD_SIZE;

	adsp_dbg(compr->dsp, "tstamp->copied_total=%d (avail=%d)\n",
		 tstamp->copied_total, buf->avail);

	mutex_unlock(&buf->lock);

	return ret;

out_buf_unlock:
	/* Get user-space to issue a read so it can detect the error */
	tstamp->copied_total += compr->irq_watermark * WM_ADSP_DATA_WORD_SIZE;

	mutex_unlock(&buf->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_pointer);

static int wm_adsp_buffer_capture_block(struct wm_adsp_compr *compr, int target)
{
	struct wm_adsp_compr_buf *buf = compr->buf;
	struct wm_adsp *dsp = buf->dsp;
	const struct wm_adsp_buffer_region *host_regions = buf->host_regions;
	int num_regions = dsp->firmwares[dsp->fw].caps->num_host_regions;
	u8 *pack_in = (u8 *)compr->capt_buf;
	u8 *pack_out = (u8 *)compr->capt_buf;
	unsigned int adsp_addr;
	int mem_type, nwords;
	int i, j, ret;

	lockdep_assert_held(&buf->lock);
	BUG_ON(!buf->host_regions);

	/* Calculate read parameters */
	for (i = 0; i < num_regions; ++i)
		if (buf->read_index < host_regions[i].cumulative_size)
			break;

	if (i == num_regions)
		return -EINVAL;

	mem_type = host_regions[i].mem_type;
	adsp_addr = host_regions[i].base_addr +
		    (buf->read_index - host_regions[i].offset);

	nwords = host_regions[i].cumulative_size - buf->read_index;

	if (nwords > target)
		nwords = target;
	if (nwords > buf->avail)
		nwords = buf->avail;
	if (nwords > compr->max_read_words)
		nwords = compr->max_read_words;
	if (!nwords)
		return 0;

	/* Read data from DSP */
	ret = wm_adsp_read_data_block(dsp, mem_type, adsp_addr,
				      nwords, compr->capt_buf);
	if (ret < 0)
		return ret;

	/* Remove the padding bytes from the data read from the DSP */
	for (i = 0; i < nwords; i++) {
		for (j = 0; j < WM_ADSP_DATA_WORD_SIZE; j++)
			*pack_out++ = *pack_in++;

		pack_in += sizeof(*(compr->capt_buf)) - WM_ADSP_DATA_WORD_SIZE;
	}

	/* update read index to account for words read */
	buf->read_index += nwords;
	if (buf->read_index == wm_adsp_buffer_size(buf))
		buf->read_index = 0;

	ret = wm_adsp_host_buffer_write(buf, HOST_BUFFER_FIELD(next_read_index),
					buf->read_index);
	if (ret < 0)
		return ret;

	/* update avail to account for words read */
	buf->avail -= nwords;

	return nwords;
}

static int wm_adsp_compr_read(struct wm_adsp_compr *compr,
			      char __user *buf, size_t count)
{
	struct wm_adsp *dsp = compr->dsp;
	int ntotal = 0;
	int nwords, nbytes;
	int ret;

	lockdep_assert_held(&compr->buf->lock);
	BUG_ON(!compr->buf->host_regions);

	adsp_dbg(dsp, "Requested read of %zu bytes\n", count);

	ret = wm_adsp_buffer_has_error_locked(compr->buf);
	if (ret)
		return ret;

	count /= WM_ADSP_DATA_WORD_SIZE;

	do {
		nwords = wm_adsp_buffer_capture_block(compr, count);
		if (nwords < 0) {
			adsp_err(dsp, "Failed to capture block: %d\n", nwords);
			return nwords;
		}

		nbytes = nwords * WM_ADSP_DATA_WORD_SIZE;

		adsp_dbg(dsp, "Read %d bytes\n", nbytes);

		if (copy_to_user(buf + ntotal, compr->capt_buf, nbytes)) {
			adsp_err(dsp, "Failed to copy data to user: %d, %d\n",
				 ntotal, nbytes);
			return -EFAULT;
		}

		count -= nwords;
		ntotal += nbytes;
	} while (nwords > 0 && count > 0);

	compr->copied_total += ntotal;

	return ntotal;
}

int wm_adsp_compr_copy(struct snd_compr_stream *stream,
		       char __user *buf, size_t count)
{
	struct wm_adsp_compr *compr = stream->runtime->private_data;
	int ret;

	mutex_lock(&compr->buf->lock);


	if (!compr->buf->host_buf_ptr) {
		adsp_warn(compr->buf->dsp, "No host buffer info\n");
		ret = -EIO;
		goto out_buf_unlock;
	}

	if (stream->direction == SND_COMPRESS_CAPTURE)
		ret = wm_adsp_compr_read(compr, buf, count);
	else
		ret = -ENOTSUPP;

out_buf_unlock:
	mutex_unlock(&compr->buf->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_copy);

void wm_adsp_compr_init(struct wm_adsp *dsp, struct wm_adsp_compr *compr)
{
	compr->dsp = dsp;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_init);

void wm_adsp_compr_destroy(struct wm_adsp_compr *compr)
{
	if (!compr->dsp)
		return;
}
EXPORT_SYMBOL_GPL(wm_adsp_compr_destroy);


/* DSP lock region support */
int wm_adsp2_lock(struct wm_adsp *dsp, unsigned int lock_regions)
{
	struct regmap *regmap_32bit = dsp->regmap;
	unsigned int lockcode0, lockcode1, lock_reg;

	if (!(lock_regions & WM_ADSP2_REGION_ALL))
		return 0;

	lock_regions &= WM_ADSP2_REGION_ALL;
	lock_reg = dsp->base +
		ADSP2_LOCK_REGION_1_LOCK_REGION_0;

	while (lock_regions) {
		lockcode0 = lockcode1 = 0;
		if (lock_regions & BIT(0)) {
			lockcode0 = ADSP2_LOCK_CODE_0;
			lockcode1 = ADSP2_LOCK_CODE_1;
		}
		if (lock_regions & BIT(1)) {
			lockcode0 |= ADSP2_LOCK_CODE_0 <<
				ADSP2_LOCK_REGION_SHIFT;
			lockcode1 |= ADSP2_LOCK_CODE_1 <<
				ADSP2_LOCK_REGION_SHIFT;
		}
		regmap_write(regmap_32bit,
			lock_reg, lockcode0);
		regmap_write(regmap_32bit,
			lock_reg, lockcode1);
		lock_regions >>= 2;
		lock_reg += 2;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(wm_adsp2_lock);

irqreturn_t wm_adsp2_bus_error(struct wm_adsp *dsp)
{
	unsigned int reg_val;
	int ret = 0;
	struct regmap *regmap = dsp->regmap;

	ret = regmap_read(regmap, dsp->base +
			ADSP2_LOCK_REGION_CTRL, &reg_val);
	if (ret != 0) {
		adsp_err(dsp,
			"Failed to read Region Lock Ctrl register: %d\n",
			ret);
		goto exit;
	}

	if (reg_val & ADSP2_WDT_TIMEOUT_STS_MASK) {
		adsp_err(dsp, "watchdog timeout error\n");
		wm_adsp_stop_watchdog(dsp);
	}

	if (reg_val & (ADSP2_SLAVE_ERR_MASK | ADSP2_REGION_LOCK_ERR_MASK)) {
		if (reg_val & ADSP2_SLAVE_ERR_MASK)
			adsp_err(dsp, "bus error: slave error\n");
		else
			adsp_err(dsp, "bus error: region lock error\n");

		ret = regmap_read(regmap, dsp->base +
				ADSP2_BUS_ERR_ADDR, &reg_val);
		if (ret != 0) {
			adsp_err(dsp,
				"Failed to read Bus Err Addr register: %d\n",
				ret);
			goto exit;
		}
		adsp_err(dsp, "bus error address = 0x%x\n",
			(reg_val & ADSP2_BUS_ERR_ADDR_MASK));

		ret = regmap_read(regmap, dsp->base +
				ADSP2_PMEM_ERR_ADDR_XMEM_ERR_ADDR,
				&reg_val);
		if (ret != 0) {
			adsp_err(dsp,
				"Failed to read Pmem Xmem Err Addr register: %d\n",
				ret);
			goto exit;
		}
		adsp_err(dsp, "xmem error address = 0x%x\n",
			(reg_val & ADSP2_XMEM_ERR_ADDR_MASK));
		adsp_err(dsp, "pmem error address = 0x%x\n",
			(reg_val & ADSP2_PMEM_ERR_ADDR_MASK)
			>> ADSP2_PMEM_ERR_ADDR_SHIFT);
	}

	regmap_update_bits(regmap, dsp->base + ADSP2_LOCK_REGION_CTRL,
			   ADSP2_CTRL_ERR_EINT, ADSP2_CTRL_ERR_EINT);
exit:
	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(wm_adsp2_bus_error);

void wm_adsp_control_dump(const struct wm_adsp *adsp)
{
	struct wm_coeff_ctl *ctl;
	struct wm_adsp_alg_region *alg;
	char *buf;
	char prefix[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];

	if (!adsp->running) {
		adsp_info(adsp, "%s: DSP not running\n", __func__);
		return;
	}

	buf = kmalloc(512, GFP_KERNEL);
	if (!buf) {
		adsp_err(adsp, "%s: cannot allocate buffer\n", __func__);
		return;
	}

	/* for each algorithm-id of this DSP */
	list_for_each_entry(alg, &adsp->alg_regions, list) {

		/* for each ALSA control of this DSP */
		list_for_each_entry(ctl, &adsp->ctl_list, list) {

			/* if alg-id is found in ALSA control name */
			if ((alg->alg == ctl->alg_region.alg) &&
			    (alg->type == ctl->alg_region.type)) {

				/* if that control is enabled */
				if (ctl->enabled == 1) {

					/* read the control and dump it */
					if (!wm_coeff_read_control(ctl, buf,
						ctl->len)) {

						snprintf(prefix, SNDRV_CTL_ELEM_ID_NAME_MAXLEN, "%s - ",
							 ctl->name);

						print_hex_dump(KERN_DEBUG,
							prefix,
							DUMP_PREFIX_NONE,
							32, 1,
							buf,
							ctl->len, false);
					} else
						adsp_warn(adsp,
							"%s: could not read: %s\n",
							__func__, ctl->name);
				}
			}
		}
	}

	kfree(buf);
}
EXPORT_SYMBOL_GPL(wm_adsp_control_dump);

MODULE_LICENSE("GPL v2");

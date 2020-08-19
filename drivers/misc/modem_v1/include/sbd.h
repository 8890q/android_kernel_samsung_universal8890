/*
 * Copyright (C) 2010 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __MODEM_INCLUDE_SBD_H__
#define __MODEM_INCLUDE_SBD_H__

/**
@file		sbd.h
@brief		header file for shared buffer descriptor (SBD) architecture
		designed by MIPI Alliance
@date		2014/02/05
@author		Hankook Jang (hankook.jang@samsung.com)
*/

#ifdef GROUP_MEM_LINK_SBD
/**
@addtogroup group_mem_link_sbd
@{
*/

#include <linux/types.h>
#include "../modem_v1.h"

#include "link_device_memory_config.h"
#include "circ_queue.h"

/*
Abbreviations
=============
SB, sb		Shared Buffer
SBD, sbd	Shared Buffer Descriptor
SBDV, sbdv	Shared Buffer Descriptor Vector (Array)
--------
RB, rb		Ring Buffer
RBO, rbo	Ring Buffer Offset (offset of an RB)
RBD, rbd	Ring Buffer Descriptor (descriptor of an RB)
RBDO, rbdo	Ring Buffer Descriptor Offset (offset of an RBD)
--------
RBP, rbp	Ring Buffer Pointer (read pointer, write pointer)
RBPS, rbps	Ring Buffer Pointer Set (set of RBPs)
--------
CH, ch		Channel
CHD, chd	Channel Descriptor
--------
desc		descriptor
*/

#define CMD_DESC_RGN_OFFSET	0
#define CMD_DESC_RGN_SIZE	SZ_64K

#define CTRL_RGN_OFFSET	(CMD_DESC_RGN_OFFSET)
#define CTRL_RGN_SIZE	(1 * SZ_1K)

#define CMD_RGN_OFFSET	(CTRL_RGN_OFFSET + CTRL_RGN_SIZE)
#define CMD_RGN_SIZE	(1 * SZ_1K)

#define DESC_RGN_OFFSET	(CMD_RGN_OFFSET + CMD_RGN_SIZE)
#define DESC_RGN_SIZE	(CMD_DESC_RGN_SIZE - CTRL_RGN_SIZE - CMD_RGN_SIZE)

#define BUFF_RGN_OFFSET	(CMD_DESC_RGN_SIZE)

/**
@brief		Priority for QoS(Quality of Service)
*/
enum qos_prio {
	QOS_HIPRIO = 10,
	QOS_NORMAL,
	QOS_MAX_PRIO,
};

/**
@brief		SBD Ring Buffer Descriptor
		(i.e. IPC Channel Descriptor Structure in MIPI LLI_IPC_AN)
*/
struct __packed sbd_rb_desc {
	/*
	ch		Channel number defined in the Samsung IPC specification
	--------
	reserved
	*/
	u16 ch;
	u16 reserved;

	/*
	direction	0 (UL, TX, AP-to-CP), 1 (DL, RX, CP-to-AP)
	--------
	signaling	0 (polling), 1 (interrupt)
	*/
	u16 direction;
	u16 signaling;

	/*
	Mask to be written to the signal register (viz. 1 << @@id)
	(i.e. write_signal)
	*/
	u32 sig_mask;

	/*
	length		Length of an SBD Ring Buffer
	--------
	id		(1) ID for a link channel that consists of an RB pair
			(2) Index into each array in the set of RBP arrays
			    N.B. set of RBP arrays =
			    {[ul_rp], [ul_wp], [dl_rp], [dl_wp]}
	*/
	u16 length;
	u16 id;

	/*
	buff_size	Size of each data buffer in an SBD RB (default 2048)
	--------
	payload_offset	Offset of the payload in each data buffer (default 0)
	*/
	u16 buff_size;
	u16 payload_offset;
};

/**
@brief		SBD Channel Descriptor
*/
struct __packed sbd_rb_channel {
	u32 ul_rbd_offset;	/* UL RB Descriptor Offset	*/
	u32 ul_sbdv_offset;	/* UL SBD Vectors's Offset	*/
	u32 dl_rbd_offset;	/* DL RB Descriptor's Offset	*/
	u32 dl_sbdv_offset;	/* DL SBD Vector's Offset	*/
};

/**
@brief		SBD Global Descriptor
*/
struct __packed sbd_global_desc {
	/*
	Version
	*/
	u32 version;

	/*
	Number of link channels
	*/
	u32 num_channels;

	/*
	Offset of the array of "SBD Ring Buffer Pointers Set" in SHMEM
	*/
	u32 rbps_offset;

	/*
	Array of SBD channel descriptors
	*/
	struct sbd_rb_channel rb_ch[MAX_LINK_CHANNELS];

	/*
	Array of SBD ring buffer descriptor pairs
	*/
	struct sbd_rb_desc rb_desc[MAX_LINK_CHANNELS][ULDL];
};

#if 1
#endif

/**
@brief		SBD ring buffer (with logical view)
@remark		physical SBD ring buffer
		= {length, *rp, *wp, offset array, size array}
*/
struct sbd_ring_buffer {
	/*
	Spin-lock for each SBD RB
	*/
	spinlock_t lock;

	/*
	Pointer to the "SBD link" device instance to which an RB belongs
	*/
	struct sbd_link_device *sl;

	/*
	UL/DL socket buffer queues
	*/
	struct sk_buff_head skb_q;

	/*
	Whether or not link-layer header is used
	*/
	bool lnk_hdr;

	/*
	Variables for receiving a frame with the SIPC5 "EXT_LEN" attribute
	(With SBD architecture, a frame with EXT_LEN can be scattered into
	 consecutive multiple data buffer slots.)
	*/
	bool more;
	unsigned int total;
	unsigned int rcvd;

	/*
	Link ID, SIPC channel, and IPC direction
	*/
	u16 id;			/* for @desc->id			*/
	u16 ch;			/* for @desc->ch			*/
	u16 dir;		/* for @desc->direction			*/
	u16 len;		/* for @desc->length			*/
	u16 buff_size;		/* for @desc->buff_size			*/
	u16 payload_offset;	/* for @desc->payload_offset		*/

	/*
	Pointer to the array of pointers to each data buffer
	*/
	u8 **buff;

	/*
	Pointer to the data buffer region in SHMEM
	*/
	u8 *buff_rgn;

	/*
	Pointers to variables in the shared region for a physical SBD RB
	*/
	u16 *rp;		/* sl->rp[@dir][@id]			*/
	u16 *wp;		/* sl->wp[@dir][@id]			*/
	u32 *addr_v;		/* Vector array of offsets		*/
	u32 *size_v;		/* Vector array of sizes		*/

	/*
	Pointer to the IO device and the link device to which an SBD RB belongs
	*/
	struct io_device *iod;
	struct link_device *ld;
};

struct sbd_link_attr {
	/*
	Link ID and SIPC channel number
	*/
	u16 id;
	u16 ch;

	/*
	Whether or not link-layer header is used
	*/
	bool lnk_hdr;

	/*
	Length of an SBD RB
	*/
	unsigned int rb_len[ULDL];

	/*
	Size of the data buffer for each SBD in an SBD RB
	*/
	unsigned int buff_size[ULDL];
};

struct sbd_ipc_device {
	/*
	Pointer to the IO device to which an SBD IPC device belongs
	*/
	struct io_device *iod;

	/*
	SBD IPC device ID == Link ID --> rb.id
	*/
	u16 id;

	/*
	SIPC Channel ID --> rb.ch
	*/
	u16 ch;

	atomic_t config_done;

	/*
	UL/DL SBD RB pair in the kernel space
	*/
	struct sbd_ring_buffer rb[ULDL];
};

struct sbd_link_device {
	/*
	Pointer to the link device to which an SBD link belongs
	*/
	struct link_device *ld;

	/*
	Flag for checking whether or not an SBD link is active
	*/
	atomic_t active;

	/*
	Version of SBD IPC
	*/
	unsigned int version;

	/*
	Start address of SHMEM
	@shmem = SHMEM.VA
	*/
	u8 *shmem;
	unsigned int shmem_size;

	/*
	Variables for DESC & BUFF allocation management
	*/
	unsigned int desc_alloc_offset;
	unsigned int buff_alloc_offset;

	/*
	The number of link channels for AP-CP IPC
	*/
	unsigned int num_channels;

	/*
	Table of link attributes
	*/
	struct sbd_link_attr link_attr[MAX_LINK_CHANNELS];

	/*
	Logical IPC devices
	*/
	struct sbd_ipc_device ipc_dev[MAX_LINK_CHANNELS];

	/*
	(1) Conversion tables from "Link ID (ID)" to "SIPC Channel Number (CH)"
	(2) Conversion tables from "SIPC Channel Number (CH)" to "Link ID (ID)"
	*/
	u16 id2ch[MAX_LINK_CHANNELS];
	u16 ch2id[MAX_SIPC_CHANNELS];

	/*
	Pointers to each array of arrays of SBD RB Pointers,
	viz. rp[UL] = pointer to ul_rp[]
	     rp[DL] = pointer to dl_rp[]
	     wp[UL] = pointer to ul_wp[]
	     wp[DL] = pointer to dl_wp[]
	*/
	u16 *rp[ULDL];
	u16 *wp[ULDL];

	/*
	Above are variables for managing and controlling SBD IPC
	========================================================================
	Below are pointers to the descriptor sections in SHMEM
	*/

	/*
	Pointer to the SBD global descriptor header
	*/
	struct sbd_global_desc *g_desc;

	u16 *rbps;

	unsigned long rxdone_mask;
};

static inline void sbd_activate(struct sbd_link_device *sl)
{
	if (sl)
		atomic_set(&sl->active, 1);
}

static inline void sbd_deactivate(struct sbd_link_device *sl)
{
	if (sl)
		atomic_set(&sl->active, 0);
}

static inline bool sbd_active(struct sbd_link_device *sl)
{
	if (!sl)
		return false;
	return atomic_read(&sl->active) ? true : false;
}

static inline u16 sbd_ch2id(struct sbd_link_device *sl, u16 ch)
{
	return sl->ch2id[ch];
}

static inline u16 sbd_id2ch(struct sbd_link_device *sl, u16 id)
{
	return sl->id2ch[id];
}

static inline struct sbd_ipc_device *sbd_ch2dev(struct sbd_link_device *sl,
						u16 ch)
{
	u16 id = sbd_ch2id(sl, ch);
	return (id < MAX_LINK_CHANNELS) ? &sl->ipc_dev[id] : NULL;
}

static inline struct sbd_ipc_device *sbd_id2dev(struct sbd_link_device *sl,
						u16 id)
{
	return (id < MAX_LINK_CHANNELS) ? &sl->ipc_dev[id] : NULL;
}

static inline struct sbd_ring_buffer *sbd_ch2rb(struct sbd_link_device *sl,
						unsigned int ch,
						enum direction dir)
{
	u16 id = sbd_ch2id(sl, ch);
	return (id < MAX_LINK_CHANNELS) ? &sl->ipc_dev[id].rb[dir] : NULL;
}

static inline struct sbd_ring_buffer *sbd_ch2rb_with_skb(struct sbd_link_device *sl,
						unsigned int ch,
						enum direction dir,
						struct sk_buff *skb)
{
	u16 id;

#ifdef CONFIG_MODEM_IF_QOS
	if (sipc_ps_ch(ch))
		ch = (skb && skb->queue_mapping == 1) ? QOS_HIPRIO : QOS_NORMAL;
#endif

	id = sbd_ch2id(sl, ch);
	return (id < MAX_LINK_CHANNELS) ? &sl->ipc_dev[id].rb[dir] : NULL;
}

static inline struct sbd_ring_buffer *sbd_id2rb(struct sbd_link_device *sl,
						unsigned int id,
						enum direction dir)
{
	return (id < MAX_LINK_CHANNELS) ? &sl->ipc_dev[id].rb[dir] : NULL;
}

static inline bool rb_empty(struct sbd_ring_buffer *rb)
{
	return circ_empty(*rb->rp, *rb->wp);
}

static inline unsigned int rb_space(struct sbd_ring_buffer *rb)
{
	return circ_get_space(rb->len, *rb->wp, *rb->rp);
}

static inline unsigned int rb_usage(struct sbd_ring_buffer *rb)
{
	return circ_get_usage(rb->len, *rb->wp, *rb->rp);
}

static inline unsigned int rb_full(struct sbd_ring_buffer *rb)
{
	return (rb_space(rb) == 0);
}

int create_sbd_link_device(struct link_device *ld, struct sbd_link_device *sl,
			   u8 *shmem_base, unsigned int shmem_size);

int init_sbd_link(struct sbd_link_device *sl);

int sbd_pio_tx(struct sbd_ring_buffer *rb, struct sk_buff *skb);
struct sk_buff *sbd_pio_rx(struct sbd_ring_buffer *rb);

#define SBD_UL_LIMIT		16	/* Uplink burst limit */

/**
// End of group_mem_link_sbd
@}
*/
#endif

#endif

/* Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _UFS_QUIRKS_H_
#define _UFS_QUIRKS_H_

/* return true if s1 is a prefix of s2 */
#define STR_PRFX_EQUAL(s1, s2) !strncmp(s1, s2, strlen(s1))

#define UFS_ANY_VENDOR 0xffff
#define UFS_ANY_MODEL  "ANY_MODEL"

#define MAX_MODEL_LEN 16

#define UFS_VENDOR_ID_SAMSUNG	0x1ce
#define UFS_VENDOR_TOSHIBA 0x98
/* UFS TOSHIBA MODELS */
#define UFS_MODEL_TOSHIBA_32GB "THGLF2G8D4KBADR"
#define UFS_MODEL_TOSHIBA_64GB "THGLF2G9D8KBADG"

/*uniqueu number*/
#define	UFS_UN_16_DIGITS 16
#define UFS_UN_18_DIGITS 18
#define UFS_UN_MAX_DIGITS 19 //current max digit + 1

/**
 * ufs_card_info - ufs device details
 * @wmanufacturerid: card details
 * @model: card model
 */
struct ufs_card_info {
	u16 wmanufacturerid;
	u8 lifetime;
	char *model;
};

/**
 * ufs_card_fix - ufs device quirk info
 * @card: ufs card details
 * @quirk: device quirk
 */
struct ufs_card_fix {
	struct ufs_card_info card;
	unsigned int quirk;
};

#define END_FIX { { 0 } , 0 }

/* add specific device quirk */
#define UFS_FIX(_vendor, _model, _quirk) \
		{						  \
				.card.wmanufacturerid = (_vendor),\
				.card.model = (_model),		  \
				.quirk = (_quirk),		  \
		}

/*
 * If UFS device is having issue in processing LCC (Line Control
 * Command) coming from UFS host controller then enable this quirk.
 * When this quirk is enabled, host controller driver should disable
 * the LCC transmission on UFS host controller (by clearing
 * TX_LCC_ENABLE attribute of host to 0).
 */
#define UFS_DEVICE_QUIRK_BROKEN_LCC		UFS_BIT(0)
#define UFS_DEVICE_QUIRK_BROKEN_LINEREST	UFS_BIT(1)

struct ufs_hba;
void ufs_advertise_fixup_device(struct ufs_hba *hba);
#endif /* UFS_QUIRKS_H_ */

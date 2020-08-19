/*
 *
 * (C) COPYRIGHT 2010, 2012-2015, 2018 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can access it online at
 * http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */



/**
 * @file mali_uk.h
 * Types and definitions that are common across OSs for both the user
 * and kernel side of the User-Kernel interface.
 */

#ifndef _UK_H_
#define _UK_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

/**
 * @addtogroup base_api
 * @{
 */

/**
 * @defgroup uk_api User-Kernel Interface API
 *
 * The User-Kernel Interface abstracts the communication mechanism between the user and kernel-side code of device
 * drivers developed as part of the Midgard DDK. Currently that includes the Base driver.
 *
 * It exposes an OS independent API to user-side code (UKU) which routes functions calls to an OS-independent
 * kernel-side API (UKK) via an OS-specific communication mechanism.
 *
 * This API is internal to the Midgard DDK and is not exposed to any applications.
 *
 * @{
 */

/**
 * These are identifiers for kernel-side drivers implementing a UK interface, aka UKK clients. The
 * UK module maps this to an OS specific device name, e.g. "gpu_base" -> "GPU0:". Specify this
 * identifier to select a UKK client to the uku_open() function.
 *
 * When a new UKK client driver is created a new identifier needs to be added to the uk_client_id
 * enumeration and the uku_open() implemenation for the various OS ports need to be updated to
 * provide a mapping of the identifier to the OS specific device name.
 *
 */
enum uk_client_id {
	/**
	 * Value used to identify the Base driver UK client.
	 */
	UK_CLIENT_MALI_T600_BASE,

	/** The number of uk clients supported. This must be the last member of the enum */
	UK_CLIENT_COUNT
};


/** @} end group uk_api */

/** @} *//* end group base_api */


/*MALI_SEC_INTEGRATION - removed uk_func at ARM original m_r28p0. but, SLSI have to use UK_FUNC_ID. so, add it temporary */
/**
 * Each function callable through the UK interface has a unique number.
 * Functions provided by UK clients start from number UK_FUNC_ID.
 * Numbers below UK_FUNC_ID are used for internal UK functions.
 */
enum uk_func {
    UKP_FUNC_ID_CHECK_VERSION,   /**< UKK Core internal function */
    /**
     * Each UK client numbers the functions they provide starting from
     * number UK_FUNC_ID. This number is then eventually assigned to the
     * id field of the union uk_header structure when preparing to make a
     * UK call. See your UK client for a list of their function numbers.
     */
    UK_FUNC_ID = 512
};


/* MALI_SEC_INTEGRATION */
enum kbase_uk_function_id {
	KBASE_FUNC_SET_MIN_LOCK = (UK_FUNC_ID + 1),
	KBASE_FUNC_UNSET_MIN_LOCK,

	KBASE_FUNC_MAX
};

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* _UK_H_ */

/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __EXYNOS_EARLY_TMU_H_
#define __EXYNOS_EARLY_TMU_H_

#if defined(CONFIG_EXYNOS_EARLY_TMU)
extern int exynos_earlytmu_get_boot_freq(int);
#else
static inline int exynos_earlytmu_get_boot_freq(int cpu) { return -1; }
#endif

#endif

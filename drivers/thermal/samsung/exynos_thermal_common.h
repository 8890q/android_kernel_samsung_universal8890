/*
 * exynos_thermal_common.h - Samsung EXYNOS common header file
 *
 *  Copyright (C) 2013 Samsung Electronics
 *  Amit Daniel Kachhap <amit.daniel@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _EXYNOS_THERMAL_COMMON_H
#define _EXYNOS_THERMAL_COMMON_H

#include <linux/types.h>

/* In-kernel thermal framework related macros & definations */
#define SENSOR_NAME_LEN	16
#define MAX_TRIP_COUNT	8
#define MAX_COOLING_DEVICE 4
#define MAX_TRIMINFO_CTRL_REG	2

#define ACTIVE_INTERVAL 300
#define IDLE_INTERVAL 	500
#define MCELSIUS	1000

#define MAX_TMU_COUNT	10

/* CPU Zone information */
#define PANIC_ZONE      4
#define WARN_ZONE       3
#define MONITOR_ZONE    2
#define SAFE_ZONE       1

#define GET_ZONE(trip) (trip + 2)
#define GET_TRIP(zone) (zone - 2)

/* Bit type */
#define TYPE_8BIT_MASK	(0xFF)
#define TYPE_9BIT_MASK	(0x1FF)

#define CLUSTER0_CORE	(0)
#define CLUSTER1_CORE	(4)

enum trigger_type {
	THROTTLE_ACTIVE = 1,
	THROTTLE_PASSIVE,
	SW_TRIP,
	HW_TRIP,
};

enum dev_type {
	CLUSTER0,
	CLUSTER1,
	GPU,
	ISP,
};

/**
 * struct freq_clip_table
 * @freq_clip_max: maximum frequency allowed for this cooling state.
 * @temp_level: Temperature level at which the temperature clipping will
 *	happen.
 * @mask_val: cpumask of the allowed cpu's where the clipping will take place.
 *
 * This structure is required to be filled and passed to the
 * cpufreq_cooling_unregister function.
 */
struct freq_clip_table {
	unsigned int freq_clip_max;
	unsigned int temp_level;
	const struct cpumask *mask_val;
};

struct	thermal_trip_point_conf {
	int trip_val[MAX_TRIP_COUNT];
	int trip_type[MAX_TRIP_COUNT];
	int trip_count;
	int trip_old_val;
	unsigned char trigger_falling;
};

struct	thermal_cooling_conf {
	struct freq_clip_table freq_data[MAX_TRIP_COUNT];
	int freq_clip_count;
};

struct thermal_sensor_conf {
	char name[SENSOR_NAME_LEN];
	int (*read_temperature)(void *data);
	int (*write_emul_temp)(void *drv_data, unsigned long temp);
	struct thermal_trip_point_conf trip_data;
	struct thermal_cooling_conf cooling_data;
	void *driver_data;
	void *pzone_data;
	struct device *dev;
	enum dev_type d_type;
	int id;
	bool hotplug_enable;
	int count;
	int hotplug_in_threshold;
	int hotplug_out_threshold;
};

/*Functions used exynos based thermal sensor driver*/
#ifdef CONFIG_EXYNOS_THERMAL_CORE
void exynos_unregister_thermal(struct thermal_sensor_conf *sensor_conf);
int exynos_register_thermal(struct thermal_sensor_conf *sensor_conf);
void exynos_report_trigger(struct thermal_sensor_conf *sensor_conf);
void change_core_boost_thermal(struct thermal_sensor_conf *quad, struct thermal_sensor_conf *dual, int mode);
#else
static inline void
exynos_unregister_thermal(struct thermal_sensor_conf *sensor_conf) { return; }

static inline int
exynos_register_thermal(struct thermal_sensor_conf *sensor_conf) { return 0; }

static inline void
exynos_report_trigger(struct thermal_sensor_conf *sensor_conf) { return; }

#endif /* CONFIG_EXYNOS_THERMAL_CORE */
#if defined(CONFIG_EXYNOS_BIG_FREQ_BOOST)
void core_boost_lock(void);
void core_boost_unlock(void);
#else
static inline void core_boost_lock(void) {return ;}
static inline void core_boost_unlock(void) {return ;}
#endif
#endif /* _EXYNOS_THERMAL_COMMON_H */

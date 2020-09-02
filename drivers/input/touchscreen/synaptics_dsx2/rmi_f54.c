/*
 * Synaptics DSX touchscreen driver
 *
 * Copyright (C) 2012 Synaptics Incorporated
 *
 * Copyright (C) 2012 Alexandra Chin <alexandra.chin@tw.synaptics.com>
 * Copyright (C) 2012 Scott Lin <scott.lin@tw.synaptics.com>
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
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unaligned.h>
//#include <mach/cpufreq.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/ctype.h>
#include <linux/hrtimer.h>
#include <linux/firmware.h>
#include <linux/gpio.h>
#include <linux/sec_sysfs.h>

#include "synaptics_i2c_rmi.h"

#define USE_ACTIVE_REPORT_RATE

#define CMD_GET_REPORT	1

#define TSP_RAWCAP_MAX	6000
#define TSP_RAWCAP_MIN	300
#define TSP_DELTA_MAX	10
#define TSP_DELTA_MIN	-10

#define WATCHDOG_HRTIMER
#define WATCHDOG_TIMEOUT_S 2
#define FORCE_TIMEOUT_100MS 10
#define STATUS_WORK_INTERVAL 20 /* ms */

#define DO_PREPATION_RETRY_COUNT	2

#define RMI_DEFAULT_FFU_FW	"ffu_tsp.bin"
/*
#define RAW_HEX
#define HUMAN_READABLE
 */

#define STATUS_IDLE 0
#define STATUS_BUSY 1
#define STATUS_ERROR 2

#define DATA_REPORT_INDEX_OFFSET 1
#define DATA_REPORT_DATA_OFFSET 3

#define SENSOR_RX_MAPPING_OFFSET 1
#define SENSOR_TX_MAPPING_OFFSET 2

#define COMMAND_GET_REPORT 1
#define COMMAND_FORCE_CAL 2
#define COMMAND_FORCE_UPDATE 4

#define CONTROL_42_SIZE 2
#define CONTROL_43_54_SIZE 13
#define CONTROL_55_56_SIZE 2
#define CONTROL_58_SIZE 1
#define CONTROL_59_SIZE 2
#define CONTROL_60_62_SIZE 3
#define CONTROL_63_SIZE 1
#define CONTROL_64_67_SIZE 4
#define CONTROL_68_73_SIZE 8
#define CONTROL_74_SIZE 2
#define CONTROL_76_SIZE 1
#define CONTROL_77_78_SIZE 2
#define CONTROL_79_83_SIZE 5
#define CONTROL_84_85_SIZE 2
#define CONTROL_86_SIZE 1
#define CONTROL_87_SIZE 1
#define CONTROL_89_SIZE 1
#define CONTROL_90_SIZE 1
#define CONTROL_91_SIZE 1
#define CONTROL_92_SIZE 1
#define CONTROL_93_SIZE 1

#define HIGH_RESISTANCE_DATA_SIZE 6
#define FULL_RAW_CAP_MIN_MAX_DATA_SIZE 4
#define TREX_DATA_SIZE 7

#define NO_AUTO_CAL_MASK 0x01
#define ATTRIBUTE_FOLDER_NAME "f54"

#define concat(a, b) a##b
#define tostring(x) (#x)

#define GROUP(_attrs) {\
	.attrs = _attrs,\
}

#define attrify(propname) (&kobj_attr_##propname.attr)

#define show_prototype(propname)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_show)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		char *buf);\
\
static struct kobj_attribute kobj_attr_##propname =\
		__ATTR(propname, S_IRUGO,\
		concat(synaptics_rmi4_f54, _##propname##_show),\
		synaptics_rmi4_store_error);

#define store_prototype(propname)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_store)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		const char *buf, size_t count);\
\
static struct kobj_attribute kobj_attr_##propname =\
		__ATTR(propname, S_IWUSR | S_IWGRP,\
		synaptics_rmi4_show_error,\
		concat(synaptics_rmi4_f54, _##propname##_store));

#define show_store_prototype(propname)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_show)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		char *buf);\
\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_store)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		const char *buf, size_t count);\
\
struct kobj_attribute kobj_attr_##propname =\
		__ATTR(propname, (S_IRUGO | S_IWUSR | S_IWGRP),\
		concat(synaptics_rmi4_f54, _##propname##_show),\
		concat(synaptics_rmi4_f54, _##propname##_store));

#define simple_show_func(rtype, propname, fmt)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_show)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		char *buf)\
{\
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);\
	return snprintf(buf, PAGE_SIZE, fmt, rmi4_data->f54->rtype.propname);\
} \

#define simple_show_func_unsigned(rtype, propname)\
simple_show_func(rtype, propname, "%u\n")

#define show_func(rtype, rgrp, propname, fmt)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_show)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		char *buf)\
{\
	int retval;\
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);\
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;\
\
	mutex_lock(&f54->rtype##_mutex);\
\
	retval = rmi4_data->i2c_read(rmi4_data,\
			f54->rtype.rgrp->address,\
			f54->rtype.rgrp->data,\
			sizeof(f54->rtype.rgrp->data));\
	mutex_unlock(&f54->rtype##_mutex);\
	if (retval < 0) {\
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
				"%s: Failed to read " #rtype\
				" " #rgrp "\n",\
				__func__);\
		return retval;\
	} \
\
	return snprintf(buf, PAGE_SIZE, fmt,\
			f54->rtype.rgrp->propname);\
} \

#define show_store_func(rtype, rgrp, propname, fmt)\
show_func(rtype, rgrp, propname, fmt)\
\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_store)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		const char *buf, size_t count)\
{\
	int retval;\
	unsigned long setting;\
	unsigned long o_setting;\
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);\
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;\
	\
	retval = kstrtoul(buf, 10, &setting);\
	if (retval)\
		return retval;\
\
	mutex_lock(&f54->rtype##_mutex);\
	retval = rmi4_data->i2c_read(rmi4_data,\
			f54->rtype.rgrp->address,\
			f54->rtype.rgrp->data,\
			sizeof(f54->rtype.rgrp->data));\
	if (retval < 0) {\
		mutex_unlock(&f54->rtype##_mutex);\
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
				"%s: Failed to read " #rtype\
				" " #rgrp "\n",\
				__func__);\
		return retval;\
	} \
\
	if (f54->rtype.rgrp->propname == setting) {\
		mutex_unlock(&f54->rtype##_mutex);\
		return count;\
	} \
\
	o_setting = f54->rtype.rgrp->propname;\
	f54->rtype.rgrp->propname = setting;\
\
	retval = rmi4_data->i2c_write(rmi4_data,\
			f54->rtype.rgrp->address,\
			f54->rtype.rgrp->data,\
			sizeof(f54->rtype.rgrp->data));\
	if (retval < 0) {\
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
				"%s: Failed to write " #rtype\
				" " #rgrp "\n",\
				__func__);\
		f54->rtype.rgrp->propname = o_setting;\
		mutex_unlock(&f54->rtype##_mutex);\
		return retval;\
	} \
\
	mutex_unlock(&f54->rtype##_mutex);\
	return count;\
} \

#define show_store_func_unsigned(rtype, rgrp, propname)\
show_store_func(rtype, rgrp, propname, "%u\n")

#define show_replicated_func(rtype, rgrp, propname, fmt)\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_show)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		char *buf)\
{\
	int retval;\
	int size = 0;\
	unsigned char ii;\
	unsigned char length;\
	unsigned char *temp;\
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);\
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;\
\
	mutex_lock(&f54->rtype##_mutex);\
\
	length = f54->rtype.rgrp->length;\
\
	retval = rmi4_data->i2c_read(rmi4_data,\
			f54->rtype.rgrp->address,\
			(unsigned char *)f54->rtype.rgrp->data,\
			length);\
	mutex_unlock(&f54->rtype##_mutex);\
	if (retval < 0) {\
		tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,\
				"%s: Failed to read " #rtype\
				" " #rgrp "\n",\
				__func__);\
	} \
\
	temp = buf;\
\
	for (ii = 0; ii < length; ii++) {\
		retval = snprintf(temp, PAGE_SIZE - size, fmt " ",\
				f54->rtype.rgrp->data[ii].propname);\
		if (retval < 0) {\
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
					"%s: Faild to write output\n",\
					__func__);\
			return retval;\
		} \
		size += retval;\
		temp += retval;\
	} \
\
	retval = snprintf(temp, PAGE_SIZE - size, "\n");\
	if (retval < 0) {\
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
				"%s: Faild to write null terminator\n",\
				__func__);\
		return retval;\
	} \
\
	return size + retval;\
} \

#define show_replicated_func_unsigned(rtype, rgrp, propname)\
show_replicated_func(rtype, rgrp, propname, "%u")

#define show_store_replicated_func(rtype, rgrp, propname, fmt)\
show_replicated_func(rtype, rgrp, propname, fmt)\
\
static ssize_t concat(synaptics_rmi4_f54, _##propname##_store)(\
		struct kobject *kobj,\
		struct kobj_attribute *attr,\
		const char *buf, size_t count)\
{\
	int retval;\
	unsigned int setting;\
	unsigned char ii;\
	unsigned char length;\
	const unsigned char *temp;\
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);\
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;\
\
	mutex_lock(&f54->rtype##_mutex);\
\
	length = f54->rtype.rgrp->length;\
\
	retval = rmi4_data->i2c_read(rmi4_data,\
			f54->rtype.rgrp->address,\
			(unsigned char *)f54->rtype.rgrp->data,\
			length);\
	if (retval < 0) {\
		tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,\
				"%s: Failed to read " #rtype\
				" " #rgrp "\n",\
				__func__);\
	} \
\
	temp = buf;\
\
	for (ii = 0; ii < length; ii++) {\
		if (sscanf(temp, fmt, &setting) == 1) {\
			f54->rtype.rgrp->data[ii].propname = setting;\
		} else {\
			retval = rmi4_data->i2c_read(rmi4_data,\
					f54->rtype.rgrp->address,\
					(unsigned char *)f54->rtype.rgrp->data,\
					length);\
			mutex_unlock(&f54->rtype##_mutex);\
			return -EINVAL;\
		} \
\
		while (*temp != 0) {\
			temp++;\
			if (isspace(*(temp - 1)) && !isspace(*temp))\
				break;\
		} \
	} \
\
	retval = rmi4_data->i2c_write(rmi4_data,\
			f54->rtype.rgrp->address,\
			(unsigned char *)f54->rtype.rgrp->data,\
			length);\
	mutex_unlock(&f54->rtype##_mutex);\
	if (retval < 0) {\
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,\
				"%s: Failed to write " #rtype\
				" " #rgrp "\n",\
				__func__);\
		return retval;\
	} \
\
	return count;\
} \

#define show_store_replicated_func_unsigned(rtype, rgrp, propname)\
show_store_replicated_func(rtype, rgrp, propname, "%u")

#ifdef FACTORY_MODE
static int synaptics_rmi4_f54_get_report_type(struct synaptics_rmi4_data *rmi4_data, int type);

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count);

static ssize_t cmd_status_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t cmd_result_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t cmd_list_show(struct device *dev,
		struct device_attribute *attr, char *buf);

#ifdef USE_LPGW_MODE
static ssize_t rmi_scrub_position(struct device *dev,
		struct device_attribute *attr, char *buf);
#endif

static ssize_t debug_address_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t debug_register_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t debug_register_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count);

static DEVICE_ATTR(cmd, S_IWUSR | S_IWGRP, NULL, cmd_store);
static DEVICE_ATTR(cmd_status, S_IRUGO, cmd_status_show, NULL);
static DEVICE_ATTR(cmd_result, S_IRUGO, cmd_result_show, NULL);
static DEVICE_ATTR(cmd_list, S_IRUGO, cmd_list_show, NULL);
static DEVICE_ATTR(debug_address, S_IRUGO, debug_address_show, NULL);
static DEVICE_ATTR(debug_register, S_IRUGO | S_IWUSR, debug_register_show, debug_register_store);
#ifdef USE_LPGW_MODE
static DEVICE_ATTR(scrub_pos, S_IRUGO, rmi_scrub_position, NULL);
#endif

static struct attribute *cmd_attributes[] = {
	&dev_attr_cmd.attr,
	&dev_attr_cmd_status.attr,
	&dev_attr_cmd_result.attr,
	&dev_attr_cmd_list.attr,
	&dev_attr_debug_address.attr,
	&dev_attr_debug_register.attr,
#ifdef USE_LPGW_MODE
	&dev_attr_scrub_pos.attr,
#endif
	NULL,
};

static struct attribute_group cmd_attr_group = {
	.attrs = cmd_attributes,
};

/*
 * Factory CMD for Synaptics IC.
 *
 * fw_update :	0 (Update with internal firmware).
 *				1 (Update with external firmware).
 *				2 (Update with Internal factory firmware).
 *				3 (Update with FFU firmware from air).
 * get_fw_ver_bin : Display firmware version in binary.
 * get_fw_ver_ic : Display firmware version in IC.
 * get_config_ver : Display configuration version.
 * get_checksum_data : Display PR number.
 * get_threshold : Display threshold of mutual.
 * module_off/on_master/slave : Control ot touch IC's power.
 * get_chip_vendor : Display vendor name.
 * get_chip_name : Display chip name.
 * get_x/y_num : Return RX/TX line of IC.
 * get_rawcap : Return the rawcap(mutual) about selected.
 * run_rawcap_read : Get the rawcap(mutual value about entire screen.
 * get_delta : Return the delta(mutual jitter) about selected.
 * run_delta_read : Get the delta value about entire screen.
 * run_abscap_read : Get the abscap(self) value about entire screen.
 * get_abscap_read_test : Return the abscap(self) RX/TX MIN & MAX value about entire screen.
 * run_absdelta_read : Get the absdelta(self jitter) value about entire screen.
 * run_trx_short_test : Test for open/short state each node.
 *		(each node return the valu ->  0: ok 1: not ok).
 * dead_zone_enable : Set dead zone mode on(1)/off(0).
 * hover_enable : To control the hover functionality dinamically.
 *		( 0: disalbe, 1: enable)
 * hover_no_sleep_enable : To keep the no sleep state before enter the hover test.
 *		This command was requested by Display team /HW.
 * hover_set_edge_rx : To change grip edge exclustion RX value during hover factory test.
 * glove_mode : Set glove mode on/off
 * clear_cover_mode : Set the touch sensitivity mode. we are supporting various mode
		in sensitivity such as (glove, flip cover, clear cover mode) and they are controled
		by this sysfs.
 * get_glove_sensitivity : Display glove's sensitivity.
 * fast_glove_mode : Set the fast glove mode such as incomming screen.
 * secure_mode : Set the secure mode.
 * boost_level : Control touch booster level.
 * handgrip_enable : Enable reporting the grip infomation based on hover shape.
 * set_tsp_test_result : Write the result of tsp test in config area.
 * get_tsp_test_result : Read the result of tsp test in config area.
 * lcd_orientation : Get LCD orientation status inform(param/degree) : (0/0), (1/90), (2/180), (3/270)
  */

static void fw_update(void *dev_data);
static void get_fw_ver_bin(void *dev_data);
static void get_fw_ver_ic(void *dev_data);
static void get_config_ver(void *dev_data);
static void get_checksum_data(void *dev_data);
static void get_threshold(void *dev_data);
static void module_off_master(void *dev_data);
static void module_on_master(void *dev_data);
static void get_chip_vendor(void *dev_data);
static void get_chip_name(void *dev_data);
static void get_x_num(void *dev_data);
static void get_y_num(void *dev_data);
static void get_rawcap(void *dev_data);
static void run_rawcap_read(void *dev_data);
static void get_delta(void *dev_data);
static void run_delta_read(void *dev_data);
static void run_abscap_read(void *dev_data);
static void get_abscap_read_test(void *dev_data);
static void run_absdelta_read(void *dev_data);
static void run_trx_short_test(void *dev_data);
static void dead_zone_enable(void *dev_data);
#ifdef PROXIMITY_MODE
static void hover_enable(void *dev_data);
static void hover_no_sleep_enable(void *dev_data);
static void hover_set_edge_rx(void *dev_data);
#endif
static void set_jitter_level(void *dev_data);
#ifdef GLOVE_MODE
static void glove_mode(void *dev_data);
static void clear_cover_mode(void *dev_data);
static void fast_glove_mode(void *dev_data);
#endif
#ifdef TSP_BOOSTER
static void boost_level(void *dev_data);
#endif
#ifdef SIDE_TOUCH
static void sidekey_enable(void *dev_data);
static void set_sidekey_only_enable(void *dev_data);
static void get_sidekey_threshold(void *dev_data);
static void run_sidekey_delta_read(void *dev_data);
static void run_sidekey_abscap_read(void *dev_data);
static void set_deepsleep_mode(void *dev_data);
static void lozemode_enable(void *dev_data);
#endif
static void set_tsp_test_result(void *dev_data);
static void get_tsp_test_result(void *dev_data);
#ifdef USE_ACTIVE_REPORT_RATE
static void report_rate(void *dev_data);
#endif
#ifdef USE_STYLUS
static void stylus_enable(void *dev_data);
#endif
#ifdef USE_LPGW_MODE
static void lpm_mode(void *dev_data);
#endif
static void lcd_orientation(void *dev_data);

static void not_support_cmd(void *dev_data);

static struct ft_cmd ft_cmds[] = {
	{FT_CMD("fw_update", fw_update),},
	{FT_CMD("get_fw_ver_bin", get_fw_ver_bin),},
	{FT_CMD("get_fw_ver_ic", get_fw_ver_ic),},
	{FT_CMD("get_config_ver", get_config_ver),},
	{FT_CMD("get_checksum_data", get_checksum_data),},
	{FT_CMD("get_threshold", get_threshold),},
	{FT_CMD("module_off_master", module_off_master),},
	{FT_CMD("module_on_master", module_on_master),},
	{FT_CMD("module_off_slave", not_support_cmd),},
	{FT_CMD("module_on_slave", not_support_cmd),},
	{FT_CMD("get_chip_vendor", get_chip_vendor),},
	{FT_CMD("get_chip_name", get_chip_name),},
	{FT_CMD("get_x_num", get_x_num),},
	{FT_CMD("get_y_num", get_y_num),},
	{FT_CMD("get_rawcap", get_rawcap),},
	{FT_CMD("run_rawcap_read", run_rawcap_read),},
	{FT_CMD("get_delta", get_delta),},
	{FT_CMD("run_delta_read", run_delta_read),},
	{FT_CMD("run_abscap_read", run_abscap_read),},
	{FT_CMD("get_abscap_read_test", get_abscap_read_test),},
	{FT_CMD("run_absdelta_read", run_absdelta_read),},
	{FT_CMD("run_trx_short_test", run_trx_short_test),},
	{FT_CMD("dead_zone_enable", dead_zone_enable),},
#ifdef PROXIMITY_MODE
	{FT_CMD("hover_enable", hover_enable),},
	{FT_CMD("hover_no_sleep_enable", hover_no_sleep_enable),},
	{FT_CMD("hover_set_edge_rx", hover_set_edge_rx),},
#endif
	{FT_CMD("set_jitter_level", set_jitter_level),},
	{FT_CMD("handgrip_enable", not_support_cmd),},
#ifdef GLOVE_MODE
	{FT_CMD("glove_mode", glove_mode),},
	{FT_CMD("clear_cover_mode", clear_cover_mode),},
	{FT_CMD("fast_glove_mode", fast_glove_mode),},
	{FT_CMD("get_glove_sensitivity", not_support_cmd),},
#endif
#ifdef TSP_BOOSTER
	{FT_CMD("boost_level", boost_level),},
#endif
#ifdef SIDE_TOUCH
	{FT_CMD("sidekey_enable", sidekey_enable),},
	{FT_CMD("set_sidekey_only_enable", set_sidekey_only_enable),},
	{FT_CMD("get_sidekey_threshold", get_sidekey_threshold),},
	{FT_CMD("run_sidekey_delta_read", run_sidekey_delta_read),},
	{FT_CMD("run_sidekey_abscap_read", run_sidekey_abscap_read),},
	{FT_CMD("set_deepsleep_mode", set_deepsleep_mode),},
	{FT_CMD("lozemode_enable", lozemode_enable),},
#endif
	{FT_CMD("set_tsp_test_result", set_tsp_test_result),},
	{FT_CMD("get_tsp_test_result", get_tsp_test_result),},
#ifdef USE_ACTIVE_REPORT_RATE
	{FT_CMD("report_rate", report_rate),},
#endif
#ifdef USE_STYLUS
	{FT_CMD("stylus_enable", stylus_enable),},
#endif
#ifdef USE_LPGW_MODE
	{FT_CMD("lpm_mode", lpm_mode),},
#endif
	{FT_CMD("lcd_orientation", lcd_orientation),},
	{FT_CMD("not_support_cmd", not_support_cmd),},
};
#endif

show_prototype(status)
show_prototype(report_size)
show_store_prototype(no_auto_cal)
show_store_prototype(report_type)
show_store_prototype(fifoindex)
store_prototype(do_preparation)
store_prototype(get_report)
store_prototype(force_cal)
show_prototype(num_of_mapped_rx)
show_prototype(num_of_mapped_tx)
show_prototype(num_of_rx_electrodes)
show_prototype(num_of_tx_electrodes)
show_prototype(has_image16)
show_prototype(has_image8)
show_prototype(has_baseline)
show_prototype(clock_rate)
show_prototype(touch_controller_family)
show_prototype(has_pixel_touch_threshold_adjustment)
show_prototype(has_sensor_assignment)
show_prototype(has_interference_metric)
show_prototype(has_sense_frequency_control)
show_prototype(has_firmware_noise_mitigation)
show_prototype(has_two_byte_report_rate)
show_prototype(has_one_byte_report_rate)
show_prototype(has_relaxation_control)
show_prototype(curve_compensation_mode)
show_prototype(has_iir_filter)
show_prototype(has_cmn_removal)
show_prototype(has_cmn_maximum)
show_prototype(has_touch_hysteresis)
show_prototype(has_edge_compensation)
show_prototype(has_per_frequency_noise_control)
show_prototype(has_signal_clarity)
show_prototype(number_of_sensing_frequencies)

show_store_prototype(no_relax)
show_store_prototype(no_scan)
show_store_prototype(bursts_per_cluster)
show_store_prototype(saturation_cap)
show_store_prototype(pixel_touch_threshold)
show_store_prototype(rx_feedback_cap)
show_store_prototype(low_ref_cap)
show_store_prototype(low_ref_feedback_cap)
show_store_prototype(low_ref_polarity)
show_store_prototype(high_ref_cap)
show_store_prototype(high_ref_feedback_cap)
show_store_prototype(high_ref_polarity)
show_store_prototype(cbc_cap)
show_store_prototype(cbc_polarity)
show_store_prototype(cbc_tx_carrier_selection)
show_store_prototype(integration_duration)
show_store_prototype(reset_duration)
show_store_prototype(noise_sensing_bursts_per_image)
show_store_prototype(slow_relaxation_rate)
show_store_prototype(fast_relaxation_rate)
show_store_prototype(rxs_on_xaxis)
show_store_prototype(curve_comp_on_txs)
show_prototype(sensor_rx_assignment)
show_prototype(sensor_tx_assignment)
show_prototype(burst_count)
show_prototype(disable)
show_prototype(filter_bandwidth)
show_prototype(stretch_duration)
show_store_prototype(disable_noise_mitigation)
show_store_prototype(freq_shift_noise_threshold)
show_store_prototype(medium_noise_threshold)
show_store_prototype(high_noise_threshold)
show_store_prototype(noise_density)
show_store_prototype(frame_count)
show_store_prototype(iir_filter_coef)
show_store_prototype(quiet_threshold)
show_store_prototype(cmn_filter_disable)
show_store_prototype(cmn_filter_max)
show_store_prototype(touch_hysteresis)
show_store_prototype(rx_low_edge_comp)
show_store_prototype(rx_high_edge_comp)
show_store_prototype(tx_low_edge_comp)
show_store_prototype(tx_high_edge_comp)
show_store_prototype(axis1_comp)
show_store_prototype(axis2_comp)
show_prototype(noise_control_1)
show_prototype(noise_control_2)
show_prototype(noise_control_3)
show_store_prototype(no_signal_clarity)
show_store_prototype(cbc_cap_0d)
show_store_prototype(cbc_polarity_0d)
show_store_prototype(cbc_tx_carrier_selection_0d)

static struct attribute *attrs[] = {
	attrify(status),
	attrify(report_size),
	attrify(no_auto_cal),
	attrify(report_type),
	attrify(fifoindex),
	attrify(do_preparation),
	attrify(get_report),
	attrify(force_cal),
	attrify(num_of_mapped_rx),
	attrify(num_of_mapped_tx),
	attrify(num_of_rx_electrodes),
	attrify(num_of_tx_electrodes),
	attrify(has_image16),
	attrify(has_image8),
	attrify(has_baseline),
	attrify(clock_rate),
	attrify(touch_controller_family),
	attrify(has_pixel_touch_threshold_adjustment),
	attrify(has_sensor_assignment),
	attrify(has_interference_metric),
	attrify(has_sense_frequency_control),
	attrify(has_firmware_noise_mitigation),
	attrify(has_two_byte_report_rate),
	attrify(has_one_byte_report_rate),
	attrify(has_relaxation_control),
	attrify(curve_compensation_mode),
	attrify(has_iir_filter),
	attrify(has_cmn_removal),
	attrify(has_cmn_maximum),
	attrify(has_touch_hysteresis),
	attrify(has_edge_compensation),
	attrify(has_per_frequency_noise_control),
	attrify(has_signal_clarity),
	attrify(number_of_sensing_frequencies),
	NULL,
};

static struct attribute_group attr_group = GROUP(attrs);

static struct attribute *attrs_reg_0[] = {
	attrify(no_relax),
	attrify(no_scan),
	NULL,
};

static struct attribute *attrs_reg_1[] = {
	attrify(bursts_per_cluster),
	NULL,
};

static struct attribute *attrs_reg_2[] = {
	attrify(saturation_cap),
	NULL,
};

static struct attribute *attrs_reg_3[] = {
	attrify(pixel_touch_threshold),
	NULL,
};

static struct attribute *attrs_reg_4__6[] = {
	attrify(rx_feedback_cap),
	attrify(low_ref_cap),
	attrify(low_ref_feedback_cap),
	attrify(low_ref_polarity),
	attrify(high_ref_cap),
	attrify(high_ref_feedback_cap),
	attrify(high_ref_polarity),
	NULL,
};

static struct attribute *attrs_reg_7[] = {
	attrify(cbc_cap),
	attrify(cbc_polarity),
	attrify(cbc_tx_carrier_selection),
	NULL,
};

static struct attribute *attrs_reg_8__9[] = {
	attrify(integration_duration),
	attrify(reset_duration),
	NULL,
};

static struct attribute *attrs_reg_10[] = {
	attrify(noise_sensing_bursts_per_image),
	NULL,
};

static struct attribute *attrs_reg_11[] = {
	NULL,
};

static struct attribute *attrs_reg_12__13[] = {
	attrify(slow_relaxation_rate),
	attrify(fast_relaxation_rate),
	NULL,
};

static struct attribute *attrs_reg_14__16[] = {
	attrify(rxs_on_xaxis),
	attrify(curve_comp_on_txs),
	attrify(sensor_rx_assignment),
	attrify(sensor_tx_assignment),
	NULL,
};

static struct attribute *attrs_reg_17__19[] = {
	attrify(burst_count),
	attrify(disable),
	attrify(filter_bandwidth),
	attrify(stretch_duration),
	NULL,
};

static struct attribute *attrs_reg_20[] = {
	attrify(disable_noise_mitigation),
	NULL,
};

static struct attribute *attrs_reg_21[] = {
	attrify(freq_shift_noise_threshold),
	NULL,
};

static struct attribute *attrs_reg_22__26[] = {
	attrify(medium_noise_threshold),
	attrify(high_noise_threshold),
	attrify(noise_density),
	attrify(frame_count),
	NULL,
};

static struct attribute *attrs_reg_27[] = {
	attrify(iir_filter_coef),
	NULL,
};

static struct attribute *attrs_reg_28[] = {
	attrify(quiet_threshold),
	NULL,
};

static struct attribute *attrs_reg_29[] = {
	attrify(cmn_filter_disable),
	NULL,
};

static struct attribute *attrs_reg_30[] = {
	attrify(cmn_filter_max),
	NULL,
};

static struct attribute *attrs_reg_31[] = {
	attrify(touch_hysteresis),
	NULL,
};

static struct attribute *attrs_reg_32__35[] = {
	attrify(rx_low_edge_comp),
	attrify(rx_high_edge_comp),
	attrify(tx_low_edge_comp),
	attrify(tx_high_edge_comp),
	NULL,
};

static struct attribute *attrs_reg_36[] = {
	attrify(axis1_comp),
	NULL,
};

static struct attribute *attrs_reg_37[] = {
	attrify(axis2_comp),
	NULL,
};

static struct attribute *attrs_reg_38__40[] = {
	attrify(noise_control_1),
	attrify(noise_control_2),
	attrify(noise_control_3),
	NULL,
};

static struct attribute *attrs_reg_41[] = {
	attrify(no_signal_clarity),
	NULL,
};

static struct attribute *attrs_reg_57[] = {
	attrify(cbc_cap_0d),
	attrify(cbc_polarity_0d),
	attrify(cbc_tx_carrier_selection_0d),
	NULL,
};

static struct attribute_group attrs_ctrl_regs[] = {
	GROUP(attrs_reg_0),
	GROUP(attrs_reg_1),
	GROUP(attrs_reg_2),
	GROUP(attrs_reg_3),
	GROUP(attrs_reg_4__6),
	GROUP(attrs_reg_7),
	GROUP(attrs_reg_8__9),
	GROUP(attrs_reg_10),
	GROUP(attrs_reg_11),
	GROUP(attrs_reg_12__13),
	GROUP(attrs_reg_14__16),
	GROUP(attrs_reg_17__19),
	GROUP(attrs_reg_20),
	GROUP(attrs_reg_21),
	GROUP(attrs_reg_22__26),
	GROUP(attrs_reg_27),
	GROUP(attrs_reg_28),
	GROUP(attrs_reg_29),
	GROUP(attrs_reg_30),
	GROUP(attrs_reg_31),
	GROUP(attrs_reg_32__35),
	GROUP(attrs_reg_36),
	GROUP(attrs_reg_37),
	GROUP(attrs_reg_38__40),
	GROUP(attrs_reg_41),
	GROUP(attrs_reg_57),
};

static bool attrs_ctrl_regs_exist[ARRAY_SIZE(attrs_ctrl_regs)];

static ssize_t synaptics_rmi4_f54_data_read(struct file *data_file,
		struct kobject *kobj, struct bin_attribute *attributes,
		char *buf, loff_t pos, size_t count);

static struct bin_attribute dev_report_data = {
	.attr = {
		.name = "report_data",
		.mode = S_IRUGO,
	},
	.size = 0,
	.read = synaptics_rmi4_f54_data_read,
};

static bool is_report_type_valid(struct synaptics_rmi4_data *rmi4_data, enum f54_report_types report_type)
{
	switch (report_type) {
	case F54_8BIT_IMAGE:
	case F54_16BIT_IMAGE:
	case F54_RAW_16BIT_IMAGE:
	case F54_HIGH_RESISTANCE:
	case F54_TX_TO_TX_SHORT:
	case F54_RX_TO_RX1:
	case F54_TRUE_BASELINE:
	case F54_FULL_RAW_CAP_MIN_MAX:
	case F54_RX_OPENS1:
	case F54_TX_OPEN:
	case F54_TX_TO_GROUND:
	case F54_RX_TO_RX2:
	case F54_RX_OPENS2:
	case F54_FULL_RAW_CAP:
	case F54_FULL_RAW_CAP_RX_COUPLING_COMP:
	case F54_SENSOR_SPEED:
	case F54_ADC_RANGE:
	case F54_TREX_OPENS:
	case F54_TREX_TO_GND:
	case F54_TREX_SHORTS:
	case F54_ABS_CAP:
	case F54_ABS_DELTA:
	case F54_ABS_ADC:
		return true;
		break;
	default:
		rmi4_data->f54->report_type = INVALID_REPORT_TYPE;
		rmi4_data->f54->report_size = 0;
		return false;

	}
}

static void set_report_size(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	int retval;
	unsigned char rx = f54->rx_assigned;
	unsigned char tx = f54->tx_assigned;

	switch (f54->report_type) {
	case F54_8BIT_IMAGE:
		f54->report_size = rx * tx;
		break;
	case F54_16BIT_IMAGE:
	case F54_RAW_16BIT_IMAGE:
	case F54_TRUE_BASELINE:
	case F54_FULL_RAW_CAP:
	case F54_FULL_RAW_CAP_RX_COUPLING_COMP:
	case F54_SENSOR_SPEED:
		f54->report_size = 2 * rx * tx;
		break;
	case F54_HIGH_RESISTANCE:
		f54->report_size = HIGH_RESISTANCE_DATA_SIZE;
		break;
	case F54_TX_TO_TX_SHORT:
	case F54_TX_OPEN:
	case F54_TX_TO_GROUND:
		f54->report_size = (tx + 7) / 8;
		break;
	case F54_RX_TO_RX1:
	case F54_RX_OPENS1:
		if (rx < tx)
			f54->report_size = 2 * rx * rx;
		else
			f54->report_size = 2 * rx * tx;
		break;
	case F54_FULL_RAW_CAP_MIN_MAX:
		f54->report_size = FULL_RAW_CAP_MIN_MAX_DATA_SIZE;
		break;
	case F54_RX_TO_RX2:
	case F54_RX_OPENS2:
		if (rx <= tx)
			f54->report_size = 0;
		else
			f54->report_size = 2 * rx * (rx - tx);
		break;
	case F54_ADC_RANGE:
		if (f54->query.has_signal_clarity) {
			mutex_lock(&f54->control_mutex);
			retval = rmi4_data->i2c_read(rmi4_data,
					f54->control.reg_41->address,
					f54->control.reg_41->data,
					sizeof(f54->control.reg_41->data));
			mutex_unlock(&f54->control_mutex);
			if (retval < 0) {
				tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,
						"%s: Failed to read control reg_41\n",
						__func__);
				f54->report_size = 0;
				break;
			}
			if (!f54->control.reg_41->no_signal_clarity) {
				if (tx % 4)
					tx += 4 - (tx % 4);
			}
		}
		f54->report_size = 2 * rx * tx;
		break;
	case F54_TREX_OPENS:
	case F54_TREX_TO_GND:
	case F54_TREX_SHORTS:
		f54->report_size = TREX_DATA_SIZE;
		break;
	case F54_ABS_CAP:
	case F54_ABS_DELTA:
#ifdef SIDE_TOUCH
		f54->report_size = 4 * (rx + tx + NUM_OF_ACTIVE_SIDE_BUTTONS);
#else
		f54->report_size = 4 * (rx + tx);
#endif
		break;
	case F54_ABS_ADC:
		f54->report_size = 2 * (rx + tx);
		break;
	default:
		f54->report_size = 0;
	}

	return;
}

static int set_interrupt(struct synaptics_rmi4_data *rmi4_data, bool set)
{
	int retval;
	unsigned char ii;
	unsigned char zero = 0x00;
	unsigned char *intr_mask;
	unsigned short f01_ctrl_reg;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	intr_mask = rmi4_data->intr_mask;
	f01_ctrl_reg = rmi4_data->f01_ctrl_base_addr + 1 + f54->intr_reg_num;

	if (!set) {
		retval = rmi4_data->i2c_write(rmi4_data,
				f01_ctrl_reg,
				&zero,
				sizeof(zero));
		if (retval < 0)
			return retval;
	}

	for (ii = 0; ii < rmi4_data->num_of_intr_regs; ii++) {
		if (intr_mask[ii] != 0x00) {
			f01_ctrl_reg = rmi4_data->f01_ctrl_base_addr + 1 + ii;
			if (set) {
				retval = rmi4_data->i2c_write(rmi4_data,
						f01_ctrl_reg,
						&zero,
						sizeof(zero));
				if (retval < 0)
					return retval;
			} else {
				retval = rmi4_data->i2c_write(rmi4_data,
						f01_ctrl_reg,
						&(intr_mask[ii]),
						sizeof(intr_mask[ii]));
				if (retval < 0)
					return retval;
			}
		}
	}

	f01_ctrl_reg = rmi4_data->f01_ctrl_base_addr + 1 + f54->intr_reg_num;

	if (set) {
		retval = rmi4_data->i2c_write(rmi4_data,
				f01_ctrl_reg,
				&f54->intr_mask,
				1);
		if (retval < 0)
			return retval;
	}

	return 0;
}

static int do_preparation(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char value;
	unsigned char command;
	unsigned char timeout_count;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	mutex_lock(&f54->control_mutex);

	if (f54->query.touch_controller_family == 1) {
		value = 0;
		retval = rmi4_data->i2c_write(rmi4_data,
				f54->control.reg_7->address,
				&value,
				sizeof(f54->control.reg_7->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to disable CBC\n",
					__func__);
			mutex_unlock(&f54->control_mutex);
			return retval;
		}
	} else if (f54->query.has_ctrl88 == 1) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->control.reg_88->address,
				f54->control.reg_88->data,
				sizeof(f54->control.reg_88->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to disable CBC (read ctrl88)\n",
					__func__);
			mutex_unlock(&f54->control_mutex);
			return retval;
		}
		f54->control.reg_88->cbc_polarity = 0;
		f54->control.reg_88->cbc_tx_carrier_selection = 0;
		retval = rmi4_data->i2c_write(rmi4_data,
				f54->control.reg_88->address,
				f54->control.reg_88->data,
				sizeof(f54->control.reg_88->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to disable CBC (write ctrl88)\n",
					__func__);
			mutex_unlock(&f54->control_mutex);
			return retval;
		}
	}
	/* check this code to using S5000 and S5050 */
	if (f54->query.has_0d_acquisition_control) {
		value = 0;
		retval = rmi4_data->i2c_write(rmi4_data,
				f54->control.reg_57->address,
				&value,
				sizeof(f54->control.reg_57->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to disable 0D CBC\n",
					__func__);
			mutex_unlock(&f54->control_mutex);
			return retval;
		}
	}

	if (f54->query.has_signal_clarity) {
		value = 1;
		retval = rmi4_data->i2c_write(rmi4_data,
				f54->control.reg_41->address,
				&value,
				sizeof(f54->control.reg_41->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to disable signal clarity\n",
					__func__);
			mutex_unlock(&f54->control_mutex);
			return retval;
		}
	}

	mutex_unlock(&f54->control_mutex);

	command = (unsigned char)COMMAND_FORCE_UPDATE;

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->command_base_addr,
			&command,
			sizeof(command));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write force update command\n",
				__func__);
		return retval;
	}

	timeout_count = 0;
	do {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->command_base_addr,
				&value,
				sizeof(value));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to read command register\n",
					__func__);
			return retval;
		}

		if (value == 0x00)
			break;

		msleep(100);
		timeout_count++;
	} while (timeout_count < FORCE_TIMEOUT_100MS);

	if (timeout_count == FORCE_TIMEOUT_100MS) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Timed out waiting for force update\n",
				__func__);
		return -ETIMEDOUT;
	}

	command = (unsigned char)COMMAND_FORCE_CAL;

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->command_base_addr,
			&command,
			sizeof(command));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write force cal command\n",
				__func__);
		return retval;
	}

	timeout_count = 0;
	do {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->command_base_addr,
				&value,
				sizeof(value));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to read command register\n",
					__func__);
			return retval;
		}

		if (value == 0x00)
			break;

		msleep(100);
		timeout_count++;
	} while (timeout_count < FORCE_TIMEOUT_100MS);

	if (timeout_count == FORCE_TIMEOUT_100MS) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Timed out waiting for force cal\n",
				__func__);
		return -ETIMEDOUT;
	}

	return 0;
}

#ifdef WATCHDOG_HRTIMER
static void timeout_set_status(struct work_struct *work)
{
	int retval;
	unsigned char command;
	struct synaptics_rmi4_f54_handle *f54 =
		container_of(work, struct synaptics_rmi4_f54_handle, timeout_work);
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)f54->rmi4_data;

	mutex_lock(&f54->status_mutex);
	if (f54->status == STATUS_BUSY) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->command_base_addr,
				&command,
				sizeof(command));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to read command register\n",
					__func__);
			f54->status = STATUS_ERROR;
		} else if (command & COMMAND_GET_REPORT) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Report type not supported by FW\n",
					__func__);
			f54->status = STATUS_ERROR;
		} else {
			queue_delayed_work(f54->status_workqueue,
					&f54->status_work,
					0);
			mutex_unlock(&f54->status_mutex);
			return;
		}
		f54->report_type = INVALID_REPORT_TYPE;
		f54->report_size = 0;
	}
	mutex_unlock(&f54->status_mutex);

	/* read fail : need ic reset */
	if (f54->status == STATUS_ERROR) {
		if (rmi4_data->touch_stopped) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is stopped\n",
				__func__);
			f54->status = STATUS_IDLE;
			return;
		}
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: reset device\n",
			__func__);

		retval = rmi4_data->reset_device(rmi4_data);
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to issue reset command, error = %d\n",
					__func__, retval);
		}

		mutex_lock(&f54->status_mutex);
		f54->status = STATUS_IDLE;
		mutex_unlock(&f54->status_mutex);
	}

	return;
}

static enum hrtimer_restart get_report_timeout(struct hrtimer *timer)
{
	struct synaptics_rmi4_f54_handle *f54 =
		container_of(timer, struct synaptics_rmi4_f54_handle, watchdog);
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)f54->rmi4_data;

	schedule_work(&(rmi4_data->f54->timeout_work));

	return HRTIMER_NORESTART;
}
#endif

#ifdef RAW_HEX
static void print_raw_hex_report(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	unsigned int ii;

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Report data (raw hex)\n", __func__);

	switch (f54->report_type) {
	case F54_16BIT_IMAGE:
	case F54_RAW_16BIT_IMAGE:
	case F54_HIGH_RESISTANCE:
	case F54_TRUE_BASELINE:
	case F54_FULL_RAW_CAP_MIN_MAX:
	case F54_FULL_RAW_CAP:
	case F54_FULL_RAW_CAP_RX_COUPLING_COMP:
	case F54_SENSOR_SPEED:
	case F54_ADC_RANGE:
	case F54_ABS_ADC:
		for (ii = 0; ii < f54->report_size; ii += 2) {
			tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%03d: 0x%02x%02x\n",
					ii / 2,
					f54->report_data[ii + 1],
					f54->report_data[ii]);
		}
		break;
	case F54_ABS_CAP:
	case F54_ABS_DELTA:
		for (ii = 0; ii < f54->report_size; ii += 4) {
			tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%03d: 0x%02x%02x%02x%02x\n",
					ii / 4,
					f54->report_data[ii + 3],
					f54->report_data[ii + 2],
					f54->report_data[ii + 1],
					f54->report_data[ii]);
		}
		break;
	default:
		for (ii = 0; ii < f54->report_size; ii++)
			tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%03d: 0x%02x\n", ii, f54->report_data[ii]);
		break;
	}

	return;
}
#endif

#ifdef HUMAN_READABLE
static void print_image_report(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned int ii;
	unsigned int jj;
	short *report_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	switch (f54->report_type) {
	case F54_16BIT_IMAGE:
	case F54_RAW_16BIT_IMAGE:
	case F54_TRUE_BASELINE:
	case F54_FULL_RAW_CAP:
	case F54_FULL_RAW_CAP_RX_COUPLING_COMP:
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Report data (image)\n", __func__);

		report_data = (short *)f54->report_data;

		for (ii = 0; ii < f54->tx_assigned; ii++) {
			for (jj = 0; jj < f54->rx_assigned; jj++) {
				if (*report_data < -64)
					pr_cont(".");
				else if (*report_data < 0)
					pr_cont("-");
				else if (*report_data > 64)
					pr_cont("*");
				else if (*report_data > 0)
					pr_cont("+");
				else
					pr_cont("0");

				report_data++;
			}
			tsp_debug_info(true, &rmi4_data->i2c_client->dev, "");
		}
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: End of report\n", __func__);
		break;
	default:
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Image not supported for report type %d\n",
				__func__, f54->report_type);
	}

	return;
}
#endif

static void free_control_mem(struct synaptics_rmi4_f54_handle *f54)
{
	struct f54_control control = f54->control;

	kfree(control.reg_0);
	kfree(control.reg_1);
	kfree(control.reg_2);
	kfree(control.reg_3);
	kfree(control.reg_4__6);
	kfree(control.reg_7);
	kfree(control.reg_8__9);
	kfree(control.reg_10);
	kfree(control.reg_11);
	kfree(control.reg_12__13);
	kfree(control.reg_14);
	if (control.reg_15)
		kfree(control.reg_15->data);
	kfree(control.reg_15);
	if (control.reg_16)
		kfree(control.reg_16->data);
	kfree(control.reg_16);
	if (control.reg_17)
		kfree(control.reg_17->data);
	kfree(control.reg_17);
	if (control.reg_18)
		kfree(control.reg_18->data);
	kfree(control.reg_18);
	if (control.reg_19)
		kfree(control.reg_19->data);
	kfree(control.reg_19);
	kfree(control.reg_20);
	kfree(control.reg_21);
	kfree(control.reg_22__26);
	kfree(control.reg_27);
	kfree(control.reg_28);
	kfree(control.reg_29);
	kfree(control.reg_30);
	kfree(control.reg_31);
	kfree(control.reg_32__35);
	if (control.reg_36)
		kfree(control.reg_36->data);
	kfree(control.reg_36);
	if (control.reg_37)
		kfree(control.reg_37->data);
	kfree(control.reg_37);
	if (control.reg_38)
		kfree(control.reg_38->data);
	kfree(control.reg_38);
	if (control.reg_39)
		kfree(control.reg_39->data);
	kfree(control.reg_39);
	if (control.reg_40)
		kfree(control.reg_40->data);
	kfree(control.reg_40);
	kfree(control.reg_41);
	kfree(control.reg_57);
	kfree(control.reg_88);
	kfree(control.reg_94);

	return;
}

static void remove_sysfs(struct synaptics_rmi4_f54_handle *f54)
{
	int reg_num;

	sysfs_remove_bin_file(f54->attr_dir, &dev_report_data);

	sysfs_remove_group(f54->attr_dir, &attr_group);

	for (reg_num = 0; reg_num < ARRAY_SIZE(attrs_ctrl_regs); reg_num++)
		sysfs_remove_group(f54->attr_dir, &attrs_ctrl_regs[reg_num]);

	kobject_put(f54->attr_dir);

	return;
}

#ifdef FACTORY_MODE
static void set_default_result(struct factory_data *data)
{
	char delim = ':';

	memset(data->cmd_buff, 0x00, sizeof(data->cmd_buff));
	memset(data->cmd_result, 0x00, sizeof(data->cmd_result));
	memcpy(data->cmd_result, data->cmd, strlen(data->cmd));
	strncat(data->cmd_result, &delim, 1);

	return;
}

static void set_cmd_result(struct factory_data *data, char *buf, int length)
{
	strncat(data->cmd_result, buf, length);

	return;
}

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned char param_cnt = 0;
	char *start;
	char *end;
	char *pos;
	char delim = ',';
	char buffer[CMD_STR_LEN];
	bool cmd_found = false;
	int *param;
	int length;
	struct ft_cmd *ft_cmd_ptr;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct factory_data *data = rmi4_data->f54->factory_data;

	if (strlen(buf) >= CMD_STR_LEN) {		
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: cmd length is over (%s,%d)!!\n", __func__, buf, (int)strlen(buf));
		return -EINVAL;
	}

	if (data->cmd_is_running == true) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Still servicing previous command. Skip cmd :%s\n",
			 __func__, buf);
		return count;
	}

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = true;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_RUNNING;

	length = (int)count;
	if (*(buf + length - 1) == '\n')
		length--;

	memset(data->cmd, 0x00, sizeof(data->cmd));
	memcpy(data->cmd, buf, length);
	memset(data->cmd_param, 0, sizeof(data->cmd_param));

	memset(buffer, 0x00, sizeof(buffer));
	pos = strchr(buf, (int)delim);
	if (pos)
		memcpy(buffer, buf, pos - buf);
	else
		memcpy(buffer, buf, length);

	/* find command */
	list_for_each_entry(ft_cmd_ptr, &data->cmd_list_head, list) {
		if (!ft_cmd_ptr) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: ft_cmd_ptr is NULL\n",
				__func__);
				return count;
		}
		if (!ft_cmd_ptr->cmd_name) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: ft_cmd_ptr->cmd_name is NULL\n",
				__func__);
				return count;
		}

		if (!strcmp(buffer, ft_cmd_ptr->cmd_name)) {
			cmd_found = true;
			break;
		}
	}

	/* set not_support_cmd */
	if (!cmd_found) {
		list_for_each_entry(ft_cmd_ptr,
			&data->cmd_list_head, list) {
			if (!strcmp("not_support_cmd", ft_cmd_ptr->cmd_name))
				break;
		}
	}

	/* parsing parameters */
	if (cmd_found && pos) {
		pos++;
		start = pos;
		do {
			if ((*pos == delim) || (pos - buf == length)) {
				end = pos;
				memset(buffer, 0x00, sizeof(buffer));
				memcpy(buffer, start, end - start);
				*(buffer + strlen(buffer)) = '\0';
				param = data->cmd_param + param_cnt;
				if (kstrtoint(buffer, 10, param) < 0)
					break;
				param_cnt++;
				start = pos + 1;
			}
			pos++;
		} while ((pos - buf <= length) && (param_cnt < CMD_PARAM_NUM));
	}

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Command = %s\n",
			__func__, buf);

	ft_cmd_ptr->cmd_func(rmi4_data);

	return count;
}

static ssize_t cmd_status_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	char buffer[CMD_RESULT_STR_LEN];
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct factory_data *data = rmi4_data->f54->factory_data;

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Command status = %d\n",
	    __func__, data->cmd_state);

	switch (data->cmd_state) {
	case CMD_STATUS_WAITING:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(WAITING));
		break;
	case CMD_STATUS_RUNNING:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(RUNNING));
		break;
	case CMD_STATUS_OK:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(OK));
		break;
	case CMD_STATUS_FAIL:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(FAIL));
		break;
	case CMD_STATUS_NOT_APPLICABLE:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(NOT_APPLICABLE));
		break;
	default:
		snprintf(buffer, CMD_RESULT_STR_LEN, "%s", tostring(NOT_APPLICABLE));
		break;
	}

	return snprintf(buf, PAGE_SIZE, "%s\n", buffer);
}

static ssize_t cmd_result_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct factory_data *data = rmi4_data->f54->factory_data;

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Command result = %s\n",
		__func__, data->cmd_result);

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;

	return snprintf(buf, PAGE_SIZE, "%s\n", data->cmd_result);
}

static char debug_buffer[DEBUG_RESULT_STR_LEN];

static ssize_t cmd_list_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int ii = 0;
	char buffer_name[CMD_STR_LEN] = {0,};

	memset(debug_buffer, 0, DEBUG_RESULT_STR_LEN);

	DEBUG_PRNT_SCREEN(debug_buffer, buffer_name, CMD_STR_LEN, "++factory command list++\n");
	while (strncmp(ft_cmds[ii].cmd_name, "not_support_cmd", 16) != 0) {
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_name, CMD_STR_LEN, "%s\n", ft_cmds[ii].cmd_name);
		ii++;
	}

	return snprintf(buf, PAGE_SIZE, "%s\n", debug_buffer);
}

static ssize_t debug_address_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct synaptics_rmi4_f51_handle *f51 = rmi4_data->f51;
	char buffer_temp[DEBUG_STR_LEN] = {0,};

	memset(debug_buffer, 0, DEBUG_RESULT_STR_LEN);

	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### F12 User control Registers ###\n");
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F12_2D_CTRL11(jitter)\t 0x%04x, 0x%02x\n",
			rmi4_data->f12.ctrl11_addr, 0xFF);
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F12_2D_CTRL15(threshold)\t 0x%04x, 0x%02x\n",
			rmi4_data->f12.ctrl15_addr, 0xFF);
#ifdef GLOVE_MODE
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F12_2D_CTRL23(obj_type)\t 0x%04x, 0x%02x\n",
			rmi4_data->f12.ctrl23_addr, rmi4_data->f12.obj_report_enable);
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F12_2D_CTRL26(glove)\t 0x%04x, 0x%02x\n",
			rmi4_data->f12.ctrl26_addr, rmi4_data->f12.feature_enable);
#endif
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F12_2D_CTRL28(report)\t 0x%04x, 0x%02x\n",
			rmi4_data->f12.ctrl28_addr, rmi4_data->f12.report_enable);

	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### F51 User control Registers ###\n");
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL00(proximity)\t 0x%04x, 0x%02x\n",
			f51->proximity_enables_addr, f51->proximity_enables);
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL01(general)\t 0x%04x, 0x%02x\n",
			f51->general_control_addr, f51->general_control);
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL02(general2)\t 0x%04x, 0x%02x\n",
			f51->general_control_2_addr, f51->general_control_2);
#ifdef SIDE_TOUCH
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_DATA (Side button)\t 0x%04x, 0x%02x\n",
			f51->side_button_data_addr, 0xFF);
#endif
#ifdef USE_DETECTION_FLAG_2
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_DATA (Detection flag2)\t 0x%04x, 0x%02x\n",
			f51->detection_flag_2_addr, 0xFF);
#endif
#ifdef EDGE_SWIPE
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_DATA (Edge swipe)\t 0x%04x, 0x%02x\n",
			f51->edge_swipe_data_addr, 0xFF);
#endif

	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Manual defined offset ###\n");
#ifdef PROXIMITY_MODE
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL24(Grip edge exclusion RX)\t 0x%04x\n",
			f51->grip_edge_exclusion_rx_addr);
#endif
#ifdef SIDE_TOUCH
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL78(Side button tap threshold)\t 0x%04x\n",
			f51->sidebutton_tapthreshold_addr);
#endif
#ifdef USE_STYLUS
	DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "#F51_CUSTOM_CTRL87(ForceFingeronEdge)\t 0x%04x\n",
			f51->forcefinger_onedge_addr);
#endif

	return snprintf(buf, PAGE_SIZE, "%s\n", debug_buffer);
}

static ssize_t debug_register_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", debug_buffer);
}

static ssize_t debug_register_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{

	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	unsigned int mode, page, addr, offset, param;
	unsigned char i;
	unsigned short register_addr;
	unsigned char *register_val;

	char buffer_temp[DEBUG_STR_LEN] = {0,};

	int retval = 0;

	memset(debug_buffer, 0, DEBUG_RESULT_STR_LEN);

	if (sscanf(buf, "%x%x%x%x%x", &mode, &page, &addr, &offset, &param) != 5) {
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### keep below format !!!! ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### mode page_num address offset data ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### (EX: 1 4 15 1 10 > debug_address) ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### Write 0x10 value at 0x415[1] address ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### if packet register, offset mean [register/offset] ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### (EX: 0 4 15 0 a > debug_address) ###\n");
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### Read 10byte from 0x415 address ###\n");
		goto out;
	}

	if (rmi4_data->touch_stopped) {
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### ERROR : Sensor stopped\n");
		goto out;
	}

	register_addr = (page << 8) | addr;

	if (mode) {
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Write [0x%02x]value at [0x%04x/0x%02x]address.\n",
			param, register_addr, offset);

		if (offset) {
			if (offset > MAX_VAL_OFFSET_AND_LENGTH) {
				DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### offset is too large. [ < %d]\n", MAX_VAL_OFFSET_AND_LENGTH);
				goto out;
			}
			register_val = kzalloc(offset + 1, GFP_KERNEL);

			retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_READ, register_addr, offset + 1, register_val);
			if (retval < 0) {
				DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Failed to read\n");
				goto free_mem;
			}
			register_val[offset] = param;

			for (i = 0; i < offset + 1; i++)
				DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### offset[%d] --> 0x%02x ###\n", i, register_val[i]);

			retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_WRITE, register_addr, offset + 1, register_val);
			if (retval < 0) {
				DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Failed to write\n");
				goto free_mem;
			}
		} else {
			register_val = kzalloc(1, GFP_KERNEL);

			*register_val = param;

			DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### 0x%04x --> 0x%02x ###\n", register_addr, *register_val);

			retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_WRITE, register_addr, 1, register_val);
			if (retval < 0) {
				DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Failed to write\n");
				goto free_mem;
			}
		}
	} else {
		DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Read [%u]byte from [0x%04x]address.\n",
			param, register_addr);

		if (param > MAX_VAL_OFFSET_AND_LENGTH) {
			DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### length is too large. [ < %d]\n", MAX_VAL_OFFSET_AND_LENGTH);
			goto out;
		}

		register_val = kzalloc(param, GFP_KERNEL);

		retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_READ, register_addr, param, register_val);
		if (retval < 0) {
			DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "\n### Failed to read\n");
			goto free_mem;
		}

		for (i = 0; i < param; i++)
			DEBUG_PRNT_SCREEN(debug_buffer, buffer_temp, DEBUG_STR_LEN, "### offset[%d] --> 0x%02x ###\n", i, register_val[i]);
	}

free_mem:
	kfree(register_val);

out:
	return count;
}

/* TODO: Below functions are added to check that firmware update is needed or not.
 * During development period, we need to support test firmware and various H/W
 * type such as A0/A1/B0.... So Below conditions are very compex, maybe we need to
 * simplify this function..
 *
 * synaptics_get_firmware_name		: get firmware name according to board enviroment.
 * synaptics_check_pr_number		: to check that configuration block is correct or not.
 * synaptics_skip_firmware_update	: check condition(according to requiremnt by CS).
 */

/* Define for board specific firmware name....*/
#define FW_IMAGE_NAME_NONE	NULL

static void synaptics_get_firmware_name(struct synaptics_rmi4_data *rmi4_data)
{
	const struct synaptics_rmi4_platform_data *pdata = rmi4_data->board;

	if (pdata->firmware_name) {
		rmi4_data->firmware_name = pdata->firmware_name;
		goto out;
	}

	/*
	 * Get the firmware name.. for your board.
	 * I recommend to get the firmware name from platform data(board or dt data)
	 * instead of using below code.
	 * If firmware is FW_IMAGE_NAME_NONE, firmware update will be skipped..
	 */
	rmi4_data->firmware_name = FW_IMAGE_NAME_NONE;

out:
	return;
}

#ifdef CHECK_PR_NUMBER
static bool synaptics_check_pr_number_v7(struct synaptics_rmi4_data *rmi4_data,
		const struct firmware *fw_entry)
{
	unsigned int fw_pr_number = 0;

	/* Check base fw version. base fw version is PR number. ex)PR1566790_...img */
	fw_pr_number = ((int)(fw_entry->data[PR_NUMBER_0TH_BYTE_BIN_OFFSET_V7+ 3] & 0xFF) << 24) |
					((int)(fw_entry->data[PR_NUMBER_0TH_BYTE_BIN_OFFSET_V7 + 2] & 0xFF) << 16) |
					((int)(fw_entry->data[PR_NUMBER_0TH_BYTE_BIN_OFFSET_V7 + 1] & 0xFF) << 8) |
					(int)(fw_entry->data[PR_NUMBER_0TH_BYTE_BIN_OFFSET_V7] & 0xFF);

	if (fw_pr_number != rmi4_data->rmi4_mod_info.pr_number) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: pr_number mismatched[IC/BIN] : %X / %X, excute update!!\n",
				__func__, rmi4_data->rmi4_mod_info.pr_number, fw_pr_number);
		return false;
	}

	tsp_debug_info(false, &rmi4_data->i2c_client->dev, "%s: pr_number[IC/BIN] : %X / %X\n",
			__func__, rmi4_data->rmi4_mod_info.pr_number, fw_pr_number);

	return true;
}

#endif

static bool synaptics_skip_firmware_update_v7(struct synaptics_rmi4_data *rmi4_data,
		const struct firmware *fw_entry)
{

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: FW size. revision, version [%d, 0x%02X/0x%02X(BIN/IC), 0x%02X/0x%02X(BIN/IC)]\n",
		__func__, (int)fw_entry->size,
		rmi4_data->ic_revision_of_bin, rmi4_data->ic_revision_of_ic,
		rmi4_data->fw_version_of_bin, rmi4_data->fw_version_of_ic);

	if (strncmp(rmi4_data->rmi4_mod_info.product_id_string, rmi4_data->product_id_string_of_bin, 5) != 0) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Skip update because FW file is mismatched.\n",
			__func__);
		return true;
	}

	if (rmi4_data->flash_prog_mode) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Force firmware update : Flash prog bit is setted fw\n",
			__func__);
		goto out;
	}

	if (rmi4_data->ic_revision_of_ic != 0x00 && (rmi4_data->ic_revision_of_bin != rmi4_data->ic_revision_of_ic)) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Skip update because revision is mismatched.\n",
			__func__);
		return true;
	}

	/* Temporary code */
	if (rmi4_data->fw_version_of_ic > 0xF0) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Force firmware update : Test FW[%X] in TSP IC.\n",
			__func__, rmi4_data->fw_version_of_ic);
		goto out;
	}

	if (rmi4_data->fw_version_of_bin < rmi4_data->fw_version_of_ic) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Do not need to update\n",
			__func__);
		return true;
	}

	if (rmi4_data->fw_version_of_bin == rmi4_data->fw_version_of_ic) {
#ifdef CHECK_PR_NUMBER
		if (!synaptics_check_pr_number_v7(rmi4_data, fw_entry))
			goto out;
#endif
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Do not need to update\n",
			__func__);
		return true;
	}

out:
	return false;
}

int synaptics_rmi4_fw_update_on_probe(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	const struct firmware *fw_entry = NULL;
	unsigned char *fw_data = NULL;

	synaptics_get_firmware_name(rmi4_data);

	if (rmi4_data->firmware_name == NULL) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: firmware name is NULL!, Skip update firmware.\n",
				__func__);
		return 0;
	} else {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Load firmware : %s\n",
					__func__, rmi4_data->firmware_name);
	}

#ifdef SKIP_UPDATE_FW_ON_PROBE
	tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Intentionally skip update firmware.\n",
			__func__);
	goto done;
#endif

	retval = request_firmware(&fw_entry, rmi4_data->firmware_name, &rmi4_data->i2c_client->dev);
	if (retval) {
		/* Even fail to get request firmware, load tsp driver. */
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Firmware image %s not available, skip it.\n",
				__func__, rmi4_data->firmware_name);
		retval = 0;
		goto done;
	}

	fw_data = (unsigned char *) fw_entry->data;
	fwu_parse_image_header_10_simple(rmi4_data, fw_data);

	if (synaptics_skip_firmware_update_v7(rmi4_data, fw_entry))
		goto done;

	retval = synaptics_fw_updater(rmi4_data, fw_data);
	if (retval)
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed update firmware\n",
				__func__);
done:
	if (fw_entry)
		release_firmware(fw_entry);

	return retval;
}
EXPORT_SYMBOL(synaptics_rmi4_fw_update_on_probe);

static int synaptics_load_fw_from_kernel(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	const struct firmware *fw_entry = NULL;
	unsigned char *fw_data = NULL;

	synaptics_get_firmware_name(rmi4_data);

	if (rmi4_data->firmware_name == NULL) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: firmware name is NULL!, Skip update firmware.\n",
				__func__);
		return 0;
	} else {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Load firmware : %s\n",
					__func__, rmi4_data->firmware_name);
	}

	retval = request_firmware(&fw_entry, rmi4_data->firmware_name,
				&rmi4_data->i2c_client->dev);

	if (retval) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Firmware image %s not available\n",
				__func__, rmi4_data->firmware_name);
		goto done;
	}

	fw_data = (unsigned char *) fw_entry->data;
	fwu_parse_image_header_10_simple(rmi4_data, fw_data);

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: FW size. revision, version [%d, 0x%02X/0x%02X(BIN/IC), 0x%02X/0x%02X(BIN/IC)]\n",
		__func__, (int)fw_entry->size,
		rmi4_data->ic_revision_of_bin, rmi4_data->ic_revision_of_ic,
		rmi4_data->fw_version_of_bin, rmi4_data->fw_version_of_ic);

	retval = synaptics_fw_updater(rmi4_data, fw_data);
	if (retval)
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed update firmware\n",
				__func__);
done:
	if (fw_entry)
		release_firmware(fw_entry);

	return retval;
}

static int synaptics_load_fw_from_ffu(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	const struct firmware *fw_entry = NULL;
	unsigned char *fw_data = NULL;
	const char *fw_path = RMI_DEFAULT_FFU_FW;

	retval = request_firmware(&fw_entry, fw_path,
				&rmi4_data->i2c_client->dev);

	if (retval) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Firmware image %s not available\n",
				__func__, rmi4_data->firmware_name);
		goto done;
	}

	fw_data = (unsigned char *) fw_entry->data;
	fwu_parse_image_header_10_simple(rmi4_data, fw_data);

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: FW size. revision, version [%d, 0x%02X/0x%02X(BIN/IC), 0x%02X/0x%02X(BIN/IC)]\n",
		__func__, (int)fw_entry->size,
		rmi4_data->ic_revision_of_bin, rmi4_data->ic_revision_of_ic,
		rmi4_data->fw_version_of_bin, rmi4_data->fw_version_of_ic);


	retval = synaptics_fw_updater(rmi4_data, fw_data);
	if (retval)
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed update firmware\n",
				__func__);
done:
	if (fw_entry)
		release_firmware(fw_entry);

	return retval;
}

static int synaptics_load_fw_from_ums(struct synaptics_rmi4_data *rmi4_data)
{
	struct file *fp;
	mm_segment_t old_fs;
	int fw_size, nread;
	int error = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	fp = filp_open(SYNAPTICS_DEFAULT_UMS_FW, O_RDONLY, S_IRUSR);
	if (IS_ERR(fp)) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed to open %s.\n",
				__func__, SYNAPTICS_DEFAULT_UMS_FW);
		error = -ENOENT;
		goto open_err;
	}

	fw_size = fp->f_path.dentry->d_inode->i_size;

	if (0 < fw_size) {
		unsigned char *fw_data;
		fw_data = kzalloc(fw_size, GFP_KERNEL);
		nread = vfs_read(fp, (char __user *)fw_data,
			fw_size, &fp->f_pos);

		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
			"%s: start, file path %s, size %u Bytes\n", __func__,
		       SYNAPTICS_DEFAULT_UMS_FW, fw_size);

		if (nread != fw_size) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed to read firmware file, nread %u Bytes\n",
			       __func__, nread);
			error = -EIO;
		} else {
			/* UMS case */
			error = synaptics_fw_updater(rmi4_data, fw_data);
		}

		if (error < 0)
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed update firmware\n",
				__func__);

		kfree(fw_data);
	}

	filp_close(fp, current->files);

 open_err:
	set_fs(old_fs);
	return error;
}

static int synaptics_rmi4_fw_update_on_hidden_menu(struct synaptics_rmi4_data *rmi4_data,
		int update_type)
{
	int retval = 0;

	/* Factory cmd for firmware update
	 * argument represent what is source of firmware like below.
	 *
	 * 0, 2 : Getting firmware which is for user.
	 * 1 : Getting firmware from sd card.
	 */
	switch (update_type) {
	case BUILT_IN:
	case BUILT_IN_FAC:
		retval = synaptics_load_fw_from_kernel(rmi4_data);
		break;
	case UMS:
		retval = synaptics_load_fw_from_ums(rmi4_data);
		break;
	case FFU:
		retval = synaptics_load_fw_from_ffu(rmi4_data);
		break;
	default:
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Not support command[%d]\n",
			__func__, update_type);
		break;
	}

	return retval;
}

static void fw_update(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;

	set_default_result(data);
#if defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	if (data->cmd_param[0] == 1) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(OK));
		data->cmd_state = CMD_STATUS_OK;
		set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: user_ship, success\n", __func__);
		return;
	}
#endif

	retval = synaptics_rmi4_fw_update_on_hidden_menu(rmi4_data,
		data->cmd_param[0]);
	msleep(1000);

	if (retval < 0) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
		data->cmd_state = CMD_STATUS_FAIL;
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed [%d]\n",
			__func__, retval);
		goto out;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(OK));
	data->cmd_state = CMD_STATUS_OK;
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: success [%d]\n",
		__func__, retval);

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_fw_ver_bin(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "SY%02X%02X%02X",
			rmi4_data->panel_revision,
			rmi4_data->ic_revision_of_bin,
			rmi4_data->fw_version_of_bin);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_fw_ver_ic(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "SY%02X%02X%02X",
			rmi4_data->panel_revision,
			rmi4_data->ic_revision_of_ic,
			rmi4_data->fw_version_of_ic);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_config_ver(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;
	const struct synaptics_rmi4_platform_data *pdata = rmi4_data->board;

	set_default_result(data);

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s_SY_%02d%02d",
		pdata->model_name ?: pdata->project_name ?:SYNAPTICS_DEVICE_NAME, (rmi4_data->fw_release_date_of_ic >> 8) & 0x0F,
	    rmi4_data->fw_release_date_of_ic & 0x00FF);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}
static void get_checksum_data(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%X", rmi4_data->rmi4_mod_info.pr_number);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_threshold(void *dev_data)
{
	unsigned char saturationcap_lsb;
	unsigned char saturationcap_msb;
	unsigned char amplitudethreshold;
	unsigned int saturationcap;
	unsigned int threshold_integer;
	unsigned int threshold_fraction;
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;


	rmi4_data->i2c_read(rmi4_data,
	   rmi4_data->f12.ctrl15_addr,
	   &amplitudethreshold,
	   sizeof(amplitudethreshold));
	rmi4_data->i2c_read(rmi4_data,
	   f54->control.reg_2->address,
	   &saturationcap_lsb,
	   sizeof(saturationcap_lsb));
	rmi4_data->i2c_read(rmi4_data,
	   f54->control.reg_2->address + 1,
	   &saturationcap_msb,
	   sizeof(saturationcap_msb));

	saturationcap = (saturationcap_lsb & 0xFF) | ((saturationcap_msb & 0xFF) << 8);
	threshold_integer = (amplitudethreshold * saturationcap)/256;
	threshold_fraction = ((amplitudethreshold * saturationcap * 1000)/256)%1000;

	tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: FingerAmp : %d, Satruration cap : %d\n",
				__func__, amplitudethreshold, saturationcap);

	set_default_result(data);
	sprintf(data->cmd_buff, "%u.%u",
		threshold_integer, threshold_fraction);
	data->cmd_state = CMD_STATUS_OK;

	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void module_off_master(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	mutex_lock(&rmi4_data->input_dev->mutex);

	rmi4_data->stop_device(rmi4_data);

	mutex_unlock(&rmi4_data->input_dev->mutex);

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(OK));
	data->cmd_state = CMD_STATUS_OK;

	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void module_on_master(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;
	int retval;

	set_default_result(data);

	mutex_lock(&rmi4_data->input_dev->mutex);

	retval = rmi4_data->start_device(rmi4_data);
	if (retval < 0)
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to start device\n", __func__);

	mutex_unlock(&rmi4_data->input_dev->mutex);

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(OK));
	data->cmd_state = CMD_STATUS_OK;

	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_chip_vendor(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(SYNAPTICS));
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_chip_name(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	switch (rmi4_data->product_id) {
	case SYNAPTICS_PRODUCT_ID_S5807:
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(S5807));
		break;
	case SYNAPTICS_PRODUCT_ID_S5806:
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(S5806));
		break;
	case SYNAPTICS_PRODUCT_ID_S5300:
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(S5300));
		break;
	default:
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
	}

	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_x_num(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d", rmi4_data->f54->tx_assigned);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_y_num(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d", rmi4_data->f54->rx_assigned);
	data->cmd_state = CMD_STATUS_OK;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static int check_rx_tx_num(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int node;

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: param[0] = %d, param[1] = %d\n",
			__func__, data->cmd_param[0], data->cmd_param[1]);

	if (data->cmd_param[0] < 0 ||
			data->cmd_param[0] >= f54->tx_assigned ||
			data->cmd_param[1] < 0 ||
			data->cmd_param[1] >= f54->rx_assigned) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: parameter error: %u,%u\n",
			__func__, data->cmd_param[0], data->cmd_param[1]);
		node = -1;
	} else {
		node = data->cmd_param[0] * f54->rx_assigned +
						data->cmd_param[1];
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: node = %d\n",
				__func__, node);
	}
	return node;
}

static void get_rawcap(void *dev_data)
{
	int node;
	short report_data;
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	node = check_rx_tx_num(rmi4_data);

	if (node < 0) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	report_data = data->rawcap_data[node];

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d", report_data);
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_rawcap_read(void *dev_data)
{
	int retval;
	int kk = 0;
	unsigned char ii;
	unsigned char jj;
	unsigned char num_of_tx;
	unsigned char num_of_rx;
	short *report_data;
	short max_value;
	short min_value;
	short cur_value;
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned char cmd_state = CMD_STATUS_RUNNING;
	unsigned char no_sleep = 0;
	int retry = DO_PREPATION_RETRY_COUNT;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	do {
		retval = rmi4_data->i2c_read(rmi4_data,
		rmi4_data->f01_ctrl_base_addr, &no_sleep, sizeof(no_sleep));
		if (retval <= 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: fail to read no_sleep[ret:%d]\n",
				__func__, retval);
			snprintf(data->cmd_buff, CMD_RESULT_STR_LEN,
				"%s", "Error read of f01_ctrl00");
			cmd_state = CMD_STATUS_FAIL;
			goto out;
		}

		no_sleep |= NO_SLEEP_ON;

		retval = rmi4_data->i2c_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr, &no_sleep, sizeof(no_sleep));
		if (retval <= 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: fail to write no_sleep[ret:%d]\n",
				__func__, retval);
			snprintf(data->cmd_buff, CMD_RESULT_STR_LEN,
				"%s", "Error write to f01_ctrl00");
			cmd_state = CMD_STATUS_FAIL;
			goto out;
		}

		retval = do_preparation(rmi4_data);
		if (retval >= 0)
			break;

		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to do preparation. reset and retry again.\n",
			__func__);
		retval = rmi4_data->reset_device(rmi4_data);
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to issue reset command, error = %d\n",
					__func__, retval);
		}
		retry--;
	} while (retry > 0);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to do preparation\n",
				__func__);
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error preparation");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_FULL_RAW_CAP_RX_COUPLING_COMP)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		cmd_state = CMD_STATUS_FAIL;
		goto sw_reset;
	}

	report_data = data->rawcap_data;
	memcpy(report_data, f54->report_data, f54->report_size);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;
	max_value = min_value = report_data[0];

	for (ii = 0; ii < num_of_tx; ii++) {
		for (jj = 0; jj < num_of_rx; jj++) {
			cur_value = *report_data;
			max_value = max(max_value, cur_value);
			min_value = min(min_value, cur_value);
			report_data++;

			if (cur_value > TSP_RAWCAP_MAX || cur_value < TSP_RAWCAP_MIN)
				tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"tx = %02d, rx = %02d, data[%d] = %d\n",
					ii, jj, kk, cur_value);
			kk++;
		}
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d,%d", min_value, max_value);
	cmd_state = CMD_STATUS_OK;

sw_reset:
	retval = rmi4_data->reset_device(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
	}

out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_delta(void *dev_data)
{
	int node;
	short report_data;
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	node = check_rx_tx_num(rmi4_data);
	if (node < 0) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	report_data = data->delta_data[node];

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d", report_data);
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_delta_read(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;
	short *report_data;
	short cur_value;
	unsigned char ii;
	unsigned char jj;
	unsigned char num_of_tx;
	unsigned char num_of_rx;
	int kk = 0;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_16BIT_IMAGE)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	report_data = data->delta_data;
	memcpy(report_data, f54->report_data, f54->report_size);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;

	for (ii = 0; ii < num_of_tx; ii++) {
		for (jj = 0; jj < num_of_rx; jj++) {
			cur_value = *report_data;
			report_data++;
			if (cur_value > TSP_DELTA_MAX || cur_value < TSP_DELTA_MIN)
				tsp_debug_info(true, &rmi4_data->i2c_client->dev, "tx = %02d, rx = %02d, data[%d] = %d\n",
					ii, jj, kk, cur_value);
			kk++;
		}
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_abscap_read(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned int *report_data;
	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];
	unsigned char ii;
	unsigned short num_of_tx;
	unsigned short num_of_rx;
	int retval;
	unsigned char cmd_state = CMD_STATUS_RUNNING;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_ABS_CAP)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		cmd_state = CMD_STATUS_FAIL;
		goto sw_reset;
	}

	report_data = data->abscap_data;
	memcpy(report_data, f54->report_data, f54->report_size);
	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;

	data->abscap_rx_min = data->abscap_rx_max = report_data[0];
	data->abscap_tx_min = data->abscap_tx_max = report_data[num_of_rx];

	for (ii = 0; ii < num_of_rx + num_of_tx ; ii++) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: %s [%d] = %d\n",
				__func__, ii >= num_of_rx ? "Tx" : "Rx",
				ii < num_of_rx ? ii : ii - num_of_rx,
				*report_data);

		if (ii >= num_of_rx) {
			data->abscap_tx_min = min(data->abscap_tx_min , *report_data);
			data->abscap_tx_max = max(data->abscap_tx_max , *report_data);
		} else {
			data->abscap_rx_min = min(data->abscap_rx_min , *report_data);
			data->abscap_rx_max = max(data->abscap_rx_max , *report_data);
		}

		if (ii == num_of_rx + num_of_tx -1)
			snprintf(temp, CMD_STR_LEN, "%d", *report_data);
		else
			snprintf(temp, CMD_STR_LEN, "%d,", *report_data);
		strncat(temp2, temp, RPT_DATA_STRNCAT_LENGTH);
		report_data++;
	}

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: RX:[%d][%d], TX:[%d][%d]\n",
					__func__, data->abscap_rx_min, data->abscap_rx_max,
					data->abscap_tx_min, data->abscap_tx_max);


	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	cmd_state = CMD_STATUS_OK;

sw_reset:
	retval = rmi4_data->reset_device(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
	}

out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_abscap_read_test(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned char cmd_state = CMD_STATUS_RUNNING;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: RX:[%d][%d], TX:[%d][%d]\n",
					__func__, data->abscap_rx_min, data->abscap_rx_max,
					data->abscap_tx_min, data->abscap_tx_max);

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%d,%d,%d,%d",
								data->abscap_rx_min, data->abscap_rx_max,
								data->abscap_tx_min, data->abscap_tx_max);
	cmd_state = CMD_STATUS_OK;

	data->abscap_rx_min = data->abscap_rx_max = data->abscap_tx_min = data->abscap_tx_max = 0;

out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_absdelta_read(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct synaptics_rmi4_f51_handle *f51 = rmi4_data->f51;
	struct factory_data *data = f54->factory_data;

	int *report_data;
	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];
	unsigned char ii;
	unsigned short num_of_tx;
	unsigned short num_of_rx;
	unsigned char proximity_enables = FINGER_HOVER_EN;

	int retval;
	unsigned char cmd_state = CMD_STATUS_RUNNING;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	/* Enable hover before read abs delta */
	retval = rmi4_data->i2c_write(rmi4_data, f51->proximity_enables_addr,
			&proximity_enables,	sizeof(proximity_enables));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write proximity_enables\n",
			__func__);
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "NG");
		cmd_state = CMD_STATUS_FAIL;
		goto out;
	}
	/* at least 5 frame time are needed after enable hover
	 * to get creadible abs delta data( 16.6 * 5 = 88 msec )
	 */
	msleep(150);

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_ABS_DELTA)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		cmd_state = CMD_STATUS_FAIL;
		goto sw_reset;
	}

	report_data = data->absdelta_data;
	memcpy(report_data, f54->report_data, f54->report_size);
	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;

	for (ii = 0; ii < num_of_rx + num_of_tx; ii++) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: %s [%d] = %d\n",
				__func__, ii >= num_of_rx ? "Tx" : "Rx",
				ii < num_of_rx ? ii : ii - num_of_rx,
				*report_data);
		snprintf(temp, CMD_STR_LEN, "%d,", *report_data);
		strncat(temp2, temp, RPT_DATA_STRNCAT_LENGTH);
		report_data++;
	}
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	cmd_state = CMD_STATUS_OK;

sw_reset:
	retval = rmi4_data->reset_device(rmi4_data);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
	}
out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

/* trx_short_test register mapping
 * 0 : not used ( using 5.2 inch)
 * 1 ~ 28 : Rx
 * 29 ~ 31 : Side Button 0, 1, 2
 * 32 ~ 33 : Guard
 * 34 : Charge Substraction
 * 35 ~ 50 : Tx
 * 51 ~ 53 : Side Button 3, 4, 5
 */

static void run_trx_short_test(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	char *report_data;
	unsigned char ii, jj;
	int retval = 0;
	unsigned char cmd_state = CMD_STATUS_RUNNING;

	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	disable_irq(rmi4_data->i2c_client->irq);
	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_TREX_SHORTS)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		cmd_state = CMD_STATUS_FAIL;
		goto sw_reset;
	}

	report_data = data->trx_short;
	memcpy(report_data, f54->report_data, f54->report_size);
	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	for (ii = 0; ii < f54->report_size; ii++) {
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: [%d]: [%x][%x][%x][%x][%x][%x][%x][%x]\n",
			__func__, ii, *report_data & 0x1, (*report_data & 0x2) >> 1,
			(*report_data & 0x4) >> 2, (*report_data & 0x8) >> 3,
			(*report_data & 0x10) >> 4, (*report_data & 0x20) >> 5,
			(*report_data & 0x40) >> 6, (*report_data & 0x80) >> 7);

		for (jj = 0; jj < 8; jj++) {
			snprintf(temp, CMD_STR_LEN, "%d,", (*report_data >> jj) & 0x01);
			strncat(temp2, temp, RPT_DATA_STRNCAT_LENGTH);
		}
		report_data++;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	cmd_state = CMD_STATUS_OK;

sw_reset:
	enable_irq(rmi4_data->i2c_client->irq);
	retval = rmi4_data->reset_device(rmi4_data);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
	}

out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void dead_zone_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;
	unsigned char dead_zone_en = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 2) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	retval = rmi4_data->i2c_read(rmi4_data,
				rmi4_data->f51->general_control_addr, &dead_zone_en, sizeof(dead_zone_en));

	if (retval <= 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: fail to read no_sleep[ret:%d]\n",
				__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	/* 0: Disable dead Zone for factory app   , 1: Enable dead Zone (default) */
	if (data->cmd_param[0])
		dead_zone_en |= DEAD_ZONE_EN;
	else
		dead_zone_en &= ~(DEAD_ZONE_EN);

	retval = rmi4_data->i2c_write(rmi4_data,
			rmi4_data->f51->general_control_addr, &dead_zone_en, sizeof(dead_zone_en));
	if (retval <= 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: fail to read dead_zone_en[ret:%d]\n",
				__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}
	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

#ifdef PROXIMITY_MODE
static void hover_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0, enables = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	enables = data->cmd_param[0];
	retval = synaptics_rmi4_proximity_enables(rmi4_data, enables);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, retval = %d\n",
			__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

static void hover_no_sleep_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned char no_sleep = 0;
	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}
	retval = rmi4_data->i2c_read(rmi4_data,
				rmi4_data->f01_ctrl_base_addr, &no_sleep, sizeof(no_sleep));
	if (retval <= 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: fail to read no_sleep[ret:%d]\n",
				__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0])
		no_sleep |= NO_SLEEP_ON;
	else
		no_sleep &= ~(NO_SLEEP_ON);

	retval = rmi4_data->i2c_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr, &no_sleep, sizeof(no_sleep));
	if (retval <= 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: fail to read no_sleep[ret:%d]\n",
				__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void hover_set_edge_rx(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	unsigned char edge_exculsion_rx = 0x10;
	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0])
		edge_exculsion_rx = 0x0;
	else
		edge_exculsion_rx = 0x10;

	retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_WRITE,
				rmi4_data->f51->grip_edge_exclusion_rx_addr, sizeof(edge_exculsion_rx), &edge_exculsion_rx);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write grip edge exclustion rx with [0x%02X].\n",
				__func__, edge_exculsion_rx);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}
#endif

static void set_jitter_level(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0, level = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 255) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, the range of jitter level is 0~255\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	level = data->cmd_param[0];

	retval = synaptics_rmi4_f12_ctrl11_set(rmi4_data, level);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, retval = %d\n",
			__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

#ifdef GLOVE_MODE
static void glove_mode(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;

	set_default_result(data);

	if (rmi4_data->f12.feature_enable & CLOSED_COVER_EN) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
		data->cmd_state = CMD_STATUS_OK;
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s Skip glove mode set (cover bit enabled)\n",
				__func__);
		goto out;
	}

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0]){
		rmi4_data->f12.feature_enable |= GLOVE_DETECTION_EN;
		rmi4_data->f12.obj_report_enable |= OBJ_TYPE_GLOVE;
	} else {
		rmi4_data->f12.feature_enable &= ~(GLOVE_DETECTION_EN);
		rmi4_data->f12.obj_report_enable &= ~(OBJ_TYPE_GLOVE);
	}

	retval = synaptics_rmi4_glove_mode_enables(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, retval = %d\n",
			__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

static void fast_glove_mode(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0]) {
		rmi4_data->f12.feature_enable |= FAST_GLOVE_DECTION_EN | GLOVE_DETECTION_EN;
		rmi4_data->f12.obj_report_enable |= OBJ_TYPE_GLOVE;
		rmi4_data->fast_glove_state = true;
	} else {
		rmi4_data->f12.feature_enable &= ~(FAST_GLOVE_DECTION_EN);
		rmi4_data->f12.obj_report_enable |= OBJ_TYPE_GLOVE;
		rmi4_data->fast_glove_state = false;
	}

	retval = synaptics_rmi4_glove_mode_enables(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, retval = %d\n",
			__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

static void clear_cover_mode(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 3) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	rmi4_data->f12.feature_enable = data->cmd_param[0];

	if (data->cmd_param[0] && rmi4_data->fast_glove_state)
		rmi4_data->f12.feature_enable |= FAST_GLOVE_DECTION_EN;

	retval = synaptics_rmi4_glove_mode_enables(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s failed, retval = %d\n",
			__func__, retval);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}
	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

	/* Sync user setting value when wakeup with flip cover opened */
	if (rmi4_data->f12.feature_enable == CLOSED_COVER_EN
		|| rmi4_data->f12.feature_enable == (CLOSED_COVER_EN | FAST_GLOVE_DECTION_EN)) {

		rmi4_data->f12.feature_enable &= ~(CLOSED_COVER_EN);
		if (rmi4_data->fast_glove_state)
			rmi4_data->f12.feature_enable |= GLOVE_DETECTION_EN;
	}

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}
#endif

#ifdef TSP_BOOSTER
static void boost_level(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;


	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] >= BOOSTER_LEVEL_MAX) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	change_booster_level_for_tsp(data->cmd_param[0]);
	tsp_debug_dbg(false, &rmi4_data->i2c_client->dev, "%s %d\n",
					__func__, data->cmd_param[0]);

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}
#endif

#ifdef SIDE_TOUCH
static void sidekey_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int retval = 0;
	unsigned char general_control_2;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&general_control_2, sizeof(general_control_2));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read general control 2.\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0])
		general_control_2 |= SIDE_BUTTONS_EN;
	else
		general_control_2 &= ~(SIDE_BUTTONS_EN);

	retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&general_control_2,	sizeof(general_control_2));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write general control 2 register with [0x%02X].\n",
				__func__, general_control_2);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	rmi4_data->f51->general_control_2 = general_control_2;
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: General Control2 [0x%02X]\n",
			__func__, rmi4_data->f51->general_control_2);

	if (!data->cmd_param[0])
		synpatics_rmi4_release_all_event(rmi4_data, RELEASE_TYPE_SIDEKEY);

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}

static void set_sidekey_only_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int retval = 0;
	unsigned char device_control = 0;
	bool sidekey_only_enable;

	set_default_result(data);

	mutex_lock(&rmi4_data->rmi4_device_mutex);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	sidekey_only_enable = data->cmd_param[0] ? true : false;

	/* Control device_control value */
	retval = rmi4_data->i2c_read(rmi4_data,
				rmi4_data->f01_ctrl_base_addr, &device_control, sizeof(device_control));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read Device Control register.\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (sidekey_only_enable)
		device_control &= ~(SENSOR_SLEEP);
	else
		device_control |= SENSOR_SLEEP;

	retval = rmi4_data->i2c_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr, &device_control, sizeof(device_control));

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write Device Control register [0x%02X].\n",
				__func__, device_control);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (sidekey_only_enable)
		rmi4_data->sensor_sleep = false;
	else
		rmi4_data->sensor_sleep = true;

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s : [F01_CTRL] 0x%02X, [F51_CTRL] 0x%02X/0x%02X/0x%02X]\n",
		__func__, device_control, rmi4_data->f51->proximity_enables, rmi4_data->f51->general_control, rmi4_data->f51->general_control_2);

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	mutex_unlock(&rmi4_data->rmi4_device_mutex);

	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_sidekey_threshold(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	unsigned char sidekey_threshold[NUM_OF_ACTIVE_SIDE_BUTTONS];
	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];
	int retval = 0, ii = 0;

	set_default_result(data);

	if (rmi4_data->touch_stopped) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is stopped\n",
			__func__);
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "TSP turned off");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_READ,
				rmi4_data->f51->sidebutton_tapthreshold_addr,
				NUM_OF_ACTIVE_SIDE_BUTTONS, sidekey_threshold);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write general control 2 register with [0x%02X].\n",
				__func__, rmi4_data->f51->general_control_2);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	while (ii < NUM_OF_ACTIVE_SIDE_BUTTONS) {
		snprintf(temp, CMD_STR_LEN, "%u ", sidekey_threshold[ii]);
		strcat(temp2, temp);
		ii++;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_sidekey_delta_read(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int *report_data;
	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];
	unsigned char ii;
	unsigned short num_of_tx;
	unsigned short num_of_rx;
	unsigned char sidekey_production_test;
	int retval;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	/* Set sidekey production test */
	retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&sidekey_production_test, sizeof(sidekey_production_test));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read general control 2.\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	sidekey_production_test |= SIDE_BUTTONS_PRODUCTION_TEST;

	retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&sidekey_production_test,
			sizeof(sidekey_production_test));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write general control 2 register with [0x%02X].\n",
				__func__, sidekey_production_test);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	msleep(100);

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_ABS_DELTA)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	report_data = f54->factory_data->absdelta_data;
	memcpy(report_data, f54->report_data, f54->report_size);
	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;

	for (ii = 0; ii < (num_of_rx + num_of_tx + NUM_OF_ACTIVE_SIDE_BUTTONS); ii++) {
		if (rmi4_data->product_id < SYNAPTICS_PRODUCT_ID_S5100)
			*report_data &= 0x0FFFF;

		if (ii < (num_of_rx + num_of_tx)) {
			report_data++;
			continue;
		}

		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
				"%s: %s [%d] = %d\n", __func__,	"SIDE",
				 ii - (num_of_rx + num_of_tx), *report_data);
		snprintf(temp, CMD_STR_LEN, "%d,", *report_data);
		strncat(temp2, temp, RPT_DATA_STRNCAT_LENGTH);
		report_data++;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void run_sidekey_abscap_read(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned int *report_data;
	char temp[CMD_STR_LEN];
	char temp2[CMD_RESULT_STR_LEN];
	unsigned char ii;
	unsigned short num_of_tx;
	unsigned short num_of_rx;
	unsigned char cmd_state = CMD_STATUS_RUNNING;

	unsigned char sidekey_production_test;
	int retval;

	set_default_result(data);

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	/* Set sidekey production test */
	retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&sidekey_production_test, sizeof(sidekey_production_test));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read general control 2.\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	sidekey_production_test |= SIDE_BUTTONS_PRODUCTION_TEST;

	retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&sidekey_production_test,
			sizeof(sidekey_production_test));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write general control 2 register with [0x%02X].\n",
				__func__, sidekey_production_test);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	msleep(100);

	if (!synaptics_rmi4_f54_get_report_type(rmi4_data, F54_ABS_CAP)) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "Error get report type");
		cmd_state = CMD_STATUS_FAIL;
		goto sw_reset;
	}

	report_data = f54->factory_data->abscap_data;
	memcpy(report_data, f54->report_data, f54->report_size);
	memset(temp, 0, CMD_STR_LEN);
	memset(temp2, 0, CMD_RESULT_STR_LEN);

	num_of_tx = f54->tx_assigned;
	num_of_rx = f54->rx_assigned;

	for (ii = 0; ii < num_of_rx + num_of_tx + NUM_OF_ACTIVE_SIDE_BUTTONS; ii++) {
		if (rmi4_data->product_id < SYNAPTICS_PRODUCT_ID_S5100)
			*report_data &= 0x0FFFF;

		if (ii < (num_of_rx + num_of_tx)) {
			report_data++;
			continue;
		}

		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
				"%s: %s [%d] = %d\n", __func__,	"SIDE",
				 ii - (num_of_rx + num_of_tx), *report_data);
		snprintf(temp, CMD_STR_LEN, "%d,", *report_data);
		strncat(temp2, temp, RPT_DATA_STRNCAT_LENGTH);
		report_data++;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", temp2);
	cmd_state = CMD_STATUS_OK;

sw_reset:
	retval = rmi4_data->reset_device(rmi4_data);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
	}

out:
	data->cmd_state = cmd_state;
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void set_sidekey_only_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);

	if (rmi4_data->touch_stopped) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	rmi4_data->use_deepsleep = data->cmd_param[0] ? true : false;

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void lozemode_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	unsigned char general_control_2 = 0;
	int retval;

	set_default_result(data);

	retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&general_control_2, sizeof(general_control_2));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read general control 2.\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (data->cmd_param[0])
		general_control_2 |= ENTER_SLEEP_MODE;
	else
		general_control_2 &= ~ENTER_SLEEP_MODE;

	retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f51->general_control_2_addr,
			&general_control_2,	sizeof(general_control_2));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write general control 2 register with [0x%02X].\n",
				__func__, general_control_2);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NA");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	rmi4_data->f51->general_control_2 = general_control_2;
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: General Control2 [0x%02X]\n",
			__func__, rmi4_data->f51->general_control_2);

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}
#endif

static void set_tsp_test_result(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int retval = 0;
	unsigned char device_status = 0;

	set_default_result(data);

	if (data->cmd_param[0] < TSP_FACTEST_RESULT_NONE
		 || data->cmd_param[0] > TSP_FACTEST_RESULT_PASS) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		return;
	}

	if (rmi4_data->touch_stopped || rmi4_data->sensor_sleep) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is %s\n",
			__func__, rmi4_data->touch_stopped ? "stopped" : "Sleep state");
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "TSP is %s",
			rmi4_data->touch_stopped ? "off" : "sleep");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	retval = rmi4_data->i2c_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			&device_status,
			sizeof(device_status));
	if (device_status != 0) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NR));
		data->cmd_state = CMD_STATUS_FAIL;
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: IC not ready[%d]\n",
				__func__, device_status);
		goto out;
	}

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: check status register[%d]\n",
			__func__, device_status);

	retval = synaptics_rmi4_set_tsp_test_result_in_config(rmi4_data, data->cmd_param[0]);
	msleep(200);

	if (retval < 0) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
		data->cmd_state = CMD_STATUS_FAIL;
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed [%d]\n",
				__func__, retval);
		goto out;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(OK));
	data->cmd_state = CMD_STATUS_OK;
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: success to save test result\n",
			__func__);

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

static void get_tsp_test_result(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	int result = 0;

	set_default_result(data);

	if (rmi4_data->touch_stopped) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is stopped\n",
			__func__);
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "TSP turned off");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	result = synaptics_rmi4_read_tsp_test_result(rmi4_data);

	if (result < TSP_FACTEST_RESULT_NONE || result > TSP_FACTEST_RESULT_PASS) {
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NG));
		data->cmd_state = CMD_STATUS_FAIL;
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: failed [%d]\n",
				__func__, result);
		goto out;
	}

	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s",
		result == TSP_FACTEST_RESULT_PASS ? tostring(PASS) :
		result == TSP_FACTEST_RESULT_FAIL ? tostring(FAIL) :
		tostring(NONE));
	data->cmd_state = CMD_STATUS_OK;
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: success [%s][%d]",	__func__,
		result == TSP_FACTEST_RESULT_PASS ? "PASS" :
		result == TSP_FACTEST_RESULT_FAIL ? "FAIL" :
		"NONE", result);

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}

#ifdef USE_ACTIVE_REPORT_RATE
int change_report_rate(struct synaptics_rmi4_data *rmi4_data, int mode)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int retval;
	unsigned char command = COMMAND_FORCE_UPDATE;
	unsigned char rpt_rate = 0;

#if defined(HAS_ALTERNATER_R_R)
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: %sSupprot alternate report rate.\n",
		__func__, f54->query_55.has_alternatereportrate ? "" : "NOT ");

	/* f54.query_55.has_alternatereportrate = 1 : Supprot alternate report rate*/
	if (f54->query_55.has_alternatereportrate) {

		retval = rmi4_data->i2c_read(rmi4_data, f54->control.reg_168->address,
				f54->control.reg_168->data, sizeof(f54->control.reg_168->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read control_168 register.\n",
					__func__);
			goto out;
		}

		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Read control_168 register[%x].\n",
					__func__, f54->control.reg_168->data[0]);

		switch (data->cmd_param[0]) {
		case SYNAPTICS_RPT_RATE_90HZ:
			rpt_rate = 0x00;
			break;
		case SYNAPTICS_RPT_RATE_60HZ:
			rpt_rate = 0x10;
			break;
		}

		f54->control.reg_168->data[0] = rpt_rate;

		retval = rmi4_data->i2c_write(rmi4_data, f54->control.reg_168->address,
				f54->control.reg_168->data, sizeof(f54->control.reg_168->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write control_168 register.\n",
					__func__);
			snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		}
	} else
#endif

	{
		retval = rmi4_data->i2c_read(rmi4_data, f54->control.reg_94->address,
				f54->control.reg_94->data, sizeof(f54->control.reg_94->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read control_94 register.\n",
					__func__);
			goto out;
		}

		switch (mode) {
		case SYNAPTICS_RPT_RATE_90HZ:
			rpt_rate = SYNAPTICS_RPT_RATE_90HZ_VAL;
			break;
		case SYNAPTICS_RPT_RATE_60HZ:
			rpt_rate = SYNAPTICS_RPT_RATE_60HZ_VAL;
			break;
		case SYNAPTICS_RPT_RATE_30HZ:
			rpt_rate = SYNAPTICS_RPT_RATE_30HZ_VAL;
			break;
		}

		if (f54->control.reg_94->noise_bursts_per_cluster == rpt_rate) {
			return 0;
		}

		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
			"%s: Set report rate %sHz [0x%02X->0x%02X]\n", __func__,
			data->cmd_param[0] == SYNAPTICS_RPT_RATE_90HZ ? "90" :
			data->cmd_param[0] == SYNAPTICS_RPT_RATE_60HZ ? "60" : "30",
			f54->control.reg_94->noise_bursts_per_cluster, rpt_rate);

		f54->control.reg_94->noise_bursts_per_cluster = rpt_rate;

		retval = rmi4_data->i2c_write(rmi4_data, f54->control.reg_94->address,
				f54->control.reg_94->data, sizeof(f54->control.reg_94->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write control_94 register.\n",
					__func__);
			goto out;
		}

		retval = rmi4_data->i2c_write(rmi4_data,
				f54->command_base_addr,
				&command, sizeof(command));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write force update command\n",
					__func__);
			goto out;
		}
	}

	return 0;
out:
	return -1;
}

static void report_rate(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;
	int retval;

	set_default_result(data);

	if (data->cmd_param[0] < SYNAPTICS_RPT_RATE_START
		 || data->cmd_param[0] >= SYNAPTICS_RPT_RATE_END) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (rmi4_data->tsp_change_report_rate == data->cmd_param[0]){
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: already change report rate[%d]\n",
			__func__, rmi4_data->tsp_change_report_rate);
		goto success;
	} else
		rmi4_data->tsp_change_report_rate = data->cmd_param[0];

	if (rmi4_data->touch_stopped) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: [ERROR] Touch is stopped\n",
			__func__);
		snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", "TSP turned off");
		data->cmd_state = CMD_STATUS_NOT_APPLICABLE;
		goto out;
	}

	retval = change_report_rate(rmi4_data, rmi4_data->tsp_change_report_rate);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: change_report_rate func() error!\n",
				__func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

success:
	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;
}
#endif

#ifdef USE_STYLUS
static void stylus_enable(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	unsigned char value;
	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 2) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	if (rmi4_data->use_stylus != (data->cmd_param[0] ? true : false)) {
		rmi4_data->use_stylus = data->cmd_param[0] ? true : false;
		synpatics_rmi4_release_all_event(rmi4_data, RELEASE_TYPE_FINGER);
	}

	value = data->cmd_param[0] ? 0x01 : 0x00;

	retval = synaptics_rmi4_access_register(rmi4_data, SYNAPTICS_ACCESS_WRITE,
				rmi4_data->f51->forcefinger_onedge_addr, sizeof(value), &value);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to write force finger on edge with [0x%02X].\n",
				__func__, value);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
}
#endif

#ifdef USE_LPGW_MODE
static ssize_t rmi_scrub_position(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	char buff[CMD_STR_LEN] = { 0 };

	if (!rmi4_data) {
		printk(KERN_ERR "%s: No platform data found\n",
				__func__);
		return -EINVAL;
	}

	if (!rmi4_data->input_dev) {
		printk(KERN_ERR "%s: No input_dev data found\n",
				__func__);
		return -EINVAL;
	}

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: %d\n",
				__func__, rmi4_data->scrub_id);
	snprintf(buff, sizeof(buff), "%d 0 0", rmi4_data->scrub_id);

	rmi4_data->scrub_id = 0;

	return snprintf(buf, PAGE_SIZE, "%s\n", buff);
}

int set_lpgw_mode(struct synaptics_rmi4_data *rmi4_data, int on)
{
	int retval;
	unsigned char report_flags_data[3];
	unsigned char wake_up_gesture_data[2];

	if (on) {
		rmi4_data->use_lpwg_sleep = true;

		/* read value : F12_2D_CTRL20(01)/00 (0x001A, 02) Report Flags(2nd bit) set 1 */
		retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f12.ctrl20_addr,
										report_flags_data, sizeof(report_flags_data));
		tsp_debug_dbg(true, &rmi4_data->i2c_client->dev,
					"%s: READ report_flags_data[2] = [0x%X] addr = [0x%X]\n",
					__func__, report_flags_data[2], rmi4_data->f12.ctrl20_addr);
		/* set value */
		report_flags_data[2] = report_flags_data[2] | 0x1 << 1;
		/* write value */
		retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f12.ctrl20_addr, report_flags_data, sizeof(report_flags_data));
		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"%s: WRITE report_flags_data[2] = [0x%X] addr = [0x%X]\n",
					__func__, report_flags_data[2], rmi4_data->f12.ctrl20_addr);

		/* read value : F12_2D_CTRL27(01)/00 (0x001E, 01) Report Rate Wakeup Gesture (8 bits) set 0x32 */
		retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f12.ctrl27_addr,
										wake_up_gesture_data, sizeof(wake_up_gesture_data));
		tsp_debug_dbg(true, &rmi4_data->i2c_client->dev,
					"%s: READ wake_up_gesture_data[1] = [0x%X] addr = [0x%X]\n",
					__func__, wake_up_gesture_data[1], rmi4_data->f12.ctrl27_addr);
		/* set value */
		wake_up_gesture_data[1] = 0x32;
		/* write value */
		retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f12.ctrl27_addr, wake_up_gesture_data, sizeof(wake_up_gesture_data));
		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"%s: WRITE wake_up_gesture_data[1] = [0x%X] addr = [0x%X]\n",
					__func__, wake_up_gesture_data[1], rmi4_data->f12.ctrl27_addr);

	} else {
		rmi4_data->use_lpwg_sleep = false;

		/* read value : F12_2D_CTRL20(01)/00 (0x001A, 02) Report Flags(2nd bit) set 1 : rmi4_data->f12.ctrl20_addr*/
		retval = rmi4_data->i2c_read(rmi4_data, rmi4_data->f12.ctrl20_addr, report_flags_data, sizeof(report_flags_data));
		tsp_debug_dbg(true, &rmi4_data->i2c_client->dev,
						"%s: READ report_flags_data[2] = [0x%X]\n",
						__func__, report_flags_data[2]);
		/* set value */
		report_flags_data[2] = report_flags_data[2] & ~(0x1 << 1);
		/* write value */
		retval = rmi4_data->i2c_write(rmi4_data, rmi4_data->f12.ctrl20_addr, report_flags_data, sizeof(report_flags_data));
		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"%s: WRITE report_flags_data[2] = [0x%X] addr = [0x%X]\n",
					__func__, report_flags_data[2], rmi4_data->f12.ctrl20_addr);
	}
	return 0;
}

static void lpm_mode(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int retval;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 1) {
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	mutex_lock(&rmi4_data->rmi4_lpgw_mutex);
	switch (data->cmd_param[0]) {
	case 0: /* Out lpwg mode */
		if (rmi4_data->touch_stopped) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Skip lpwg mode out, IC OFF\n", __func__);
		} else {
			retval = set_lpgw_mode(rmi4_data, false);
		}
		break;
	case 1: /* Enter lpwg mode */
		if (rmi4_data->touch_stopped) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Skip lpwg mode in, IC OFF\n", __func__);
		} else {
			retval = set_lpgw_mode(rmi4_data, true);
		}
		break;
	}
	mutex_unlock(&rmi4_data->rmi4_lpgw_mutex);

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to set_lpgw_mode.\n", __func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;

}
#endif

static void lcd_orientation(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct factory_data *data = f54->factory_data;

	int retval = 0;

	set_default_result(data);

	if (data->cmd_param[0] < 0 || data->cmd_param[0] > 3) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: LCD orientation value error.\n", __func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	switch (data->cmd_param[0]) {
	case ORIENTATION_0: /* Out lpwg mode */
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Get 0 degree LCD orientation.\n", __func__);
		break;
	case ORIENTATION_90: /* Enter lpwg mode */
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Get 90 degree LCD orientation.\n", __func__);
		break;
	case ORIENTATION_180: /* Enter lpwg mode */
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Get 180 degree LCD orientation.\n", __func__);
		break;
	case ORIENTATION_270: /* Enter lpwg mode */
		tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: Get 270 degree LCD orientation.\n", __func__);
		break;
	default:
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: LCD orientation value error.\n", __func__);
		retval = -1;
		break;
	}

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to set LCD orientation.\n", __func__);
		snprintf(data->cmd_buff, sizeof(data->cmd_buff), "NG");
		data->cmd_state = CMD_STATUS_FAIL;
		goto out;
	}

	rmi4_data->orientation = data->cmd_param[0];

	snprintf(data->cmd_buff, sizeof(data->cmd_buff), "OK");
	data->cmd_state = CMD_STATUS_OK;

out:
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));

	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);

	data->cmd_state = CMD_STATUS_WAITING;

}

static void not_support_cmd(void *dev_data)
{
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)dev_data;
	struct factory_data *data = rmi4_data->f54->factory_data;

	set_default_result(data);
	snprintf(data->cmd_buff, CMD_RESULT_STR_LEN, "%s", tostring(NA));
	set_cmd_result(data, data->cmd_buff, strlen(data->cmd_buff));
	data->cmd_state = CMD_STATUS_NOT_APPLICABLE;

	/* Some cmds are supported in specific IC and they are clear the cmd_is running flag
	 * itself(without show_cmd_result_) in their function such as hover_enable, glove_mode.
	 * So we need to clear cmd_is runnint flag if that command is replaced with
	 * not_support_cmd */
	mutex_lock(&data->cmd_lock);
	data->cmd_is_running = false;
	mutex_unlock(&data->cmd_lock);
}
#endif

static ssize_t synaptics_rmi4_f54_status_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->status);
}

static ssize_t synaptics_rmi4_f54_report_size_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->report_size);
}

static ssize_t synaptics_rmi4_f54_no_auto_cal_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->no_auto_cal);
}

static ssize_t synaptics_rmi4_f54_no_auto_cal_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned char data;
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	if (setting > 1)
		return -EINVAL;

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->control_base_addr,
			&data,
			sizeof(data));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to read control register\n",
				__func__);
		return retval;
	}

	if ((data & NO_AUTO_CAL_MASK) == setting)
		return count;

	data = (data & ~NO_AUTO_CAL_MASK) | (data & NO_AUTO_CAL_MASK);

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->control_base_addr,
			&data,
			sizeof(data));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write control register\n",
				__func__);
		return retval;
	}

	f54->no_auto_cal = (setting == 1);

	return count;
}

static ssize_t synaptics_rmi4_f54_report_type_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->report_type);
}

static ssize_t synaptics_rmi4_f54_report_type_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned char data;
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	if (!is_report_type_valid(rmi4_data, (enum f54_report_types)setting)) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Report type not supported by driver\n",
				__func__);
		return -EINVAL;
	}

	mutex_lock(&f54->status_mutex);

	if (f54->status != STATUS_BUSY) {
		f54->report_type = (enum f54_report_types)setting;
		data = (unsigned char)setting;
		retval = rmi4_data->i2c_write(rmi4_data,
				f54->data_base_addr,
				&data,
				sizeof(data));
		mutex_unlock(&f54->status_mutex);
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to write data register\n",
					__func__);
			return retval;
		}
		return count;
	} else {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Previous get report still ongoing\n",
				__func__);
		mutex_unlock(&f54->status_mutex);
		return -EINVAL;
	}
}

static ssize_t synaptics_rmi4_f54_fifoindex_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int retval;
	unsigned char data[2];
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->data_base_addr + DATA_REPORT_INDEX_OFFSET,
			data,
			sizeof(data));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to read data registers\n",
				__func__);
		return retval;
	}

	batohs(&f54->fifoindex, data);

	return snprintf(buf, PAGE_SIZE, "%u\n", f54->fifoindex);
}
static ssize_t synaptics_rmi4_f54_fifoindex_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned char data[2];
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	f54->fifoindex = setting;

	hstoba(data, (unsigned short)setting);

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->data_base_addr + DATA_REPORT_INDEX_OFFSET,
			data,
			sizeof(data));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write data registers\n",
				__func__);
		return retval;
	}

	return count;
}

static ssize_t synaptics_rmi4_f54_do_preparation_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	if (setting != 1)
		return -EINVAL;

	mutex_lock(&f54->status_mutex);

	if (f54->status != STATUS_IDLE) {
		if (f54->status != STATUS_BUSY) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Invalid status (%d)\n",
					__func__, f54->status);
		} else {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Previous get report still ongoing\n",
					__func__);
		}
		mutex_unlock(&f54->status_mutex);
		return -EBUSY;
	}

	mutex_unlock(&f54->status_mutex);

	retval = do_preparation(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to do preparation\n",
				__func__);
		return retval;
	}

	return count;
}

static ssize_t synaptics_rmi4_f54_get_report_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned char command;
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	if (setting != 1)
		return -EINVAL;

	command = (unsigned char)COMMAND_GET_REPORT;

	if (!is_report_type_valid(rmi4_data, f54->report_type)) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Invalid report type\n",
				__func__);
		return -EINVAL;
	}

	mutex_lock(&f54->status_mutex);

	if (f54->status != STATUS_IDLE) {
		if (f54->status != STATUS_BUSY) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Invalid status (%d)\n",
					__func__, f54->status);
		} else {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Previous get report still ongoing\n",
					__func__);
		}
		mutex_unlock(&f54->status_mutex);
		return -EBUSY;
	}

	set_interrupt(rmi4_data, true);

	f54->status = STATUS_BUSY;

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->command_base_addr,
			&command,
			sizeof(command));
	mutex_unlock(&f54->status_mutex);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write get report command\n",
				__func__);
		return retval;
	}

#ifdef WATCHDOG_HRTIMER
	hrtimer_start(&f54->watchdog,
			ktime_set(WATCHDOG_TIMEOUT_S, 0),
			HRTIMER_MODE_REL);
#endif

	return count;
}

static ssize_t synaptics_rmi4_f54_force_cal_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned char command;
	unsigned long setting;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = kstrtoul(buf, 10, &setting);
	if (retval)
		return retval;

	if (setting != 1)
		return count;

	command = (unsigned char)COMMAND_FORCE_CAL;

	if (f54->status == STATUS_BUSY)
		return -EBUSY;

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->command_base_addr,
			&command,
			sizeof(command));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write force cal command\n",
				__func__);
		return retval;
	}

	return count;
}

static ssize_t synaptics_rmi4_f54_num_of_mapped_rx_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->rx_assigned);
}

static ssize_t synaptics_rmi4_f54_num_of_mapped_tx_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", rmi4_data->f54->tx_assigned);
}

simple_show_func_unsigned(query, num_of_rx_electrodes)
simple_show_func_unsigned(query, num_of_tx_electrodes)
simple_show_func_unsigned(query, has_image16)
simple_show_func_unsigned(query, has_image8)
simple_show_func_unsigned(query, has_baseline)
simple_show_func_unsigned(query, clock_rate)
simple_show_func_unsigned(query, touch_controller_family)
simple_show_func_unsigned(query, has_pixel_touch_threshold_adjustment)
simple_show_func_unsigned(query, has_sensor_assignment)
simple_show_func_unsigned(query, has_interference_metric)
simple_show_func_unsigned(query, has_sense_frequency_control)
simple_show_func_unsigned(query, has_firmware_noise_mitigation)
simple_show_func_unsigned(query, has_two_byte_report_rate)
simple_show_func_unsigned(query, has_one_byte_report_rate)
simple_show_func_unsigned(query, has_relaxation_control)
simple_show_func_unsigned(query, curve_compensation_mode)
simple_show_func_unsigned(query, has_iir_filter)
simple_show_func_unsigned(query, has_cmn_removal)
simple_show_func_unsigned(query, has_cmn_maximum)
simple_show_func_unsigned(query, has_touch_hysteresis)
simple_show_func_unsigned(query, has_edge_compensation)
simple_show_func_unsigned(query, has_per_frequency_noise_control)
simple_show_func_unsigned(query, has_signal_clarity)
simple_show_func_unsigned(query, number_of_sensing_frequencies)

show_store_func_unsigned(control, reg_0, no_relax)
show_store_func_unsigned(control, reg_0, no_scan)
show_store_func_unsigned(control, reg_1, bursts_per_cluster)
show_store_func_unsigned(control, reg_2, saturation_cap)
show_store_func_unsigned(control, reg_3, pixel_touch_threshold)
show_store_func_unsigned(control, reg_4__6, rx_feedback_cap)
show_store_func_unsigned(control, reg_4__6, low_ref_cap)
show_store_func_unsigned(control, reg_4__6, low_ref_feedback_cap)
show_store_func_unsigned(control, reg_4__6, low_ref_polarity)
show_store_func_unsigned(control, reg_4__6, high_ref_cap)
show_store_func_unsigned(control, reg_4__6, high_ref_feedback_cap)
show_store_func_unsigned(control, reg_4__6, high_ref_polarity)
show_store_func_unsigned(control, reg_7, cbc_cap)
show_store_func_unsigned(control, reg_7, cbc_polarity)
show_store_func_unsigned(control, reg_7, cbc_tx_carrier_selection)
show_store_func_unsigned(control, reg_8__9, integration_duration)
show_store_func_unsigned(control, reg_8__9, reset_duration)
show_store_func_unsigned(control, reg_10, noise_sensing_bursts_per_image)
show_store_func_unsigned(control, reg_12__13, slow_relaxation_rate)
show_store_func_unsigned(control, reg_12__13, fast_relaxation_rate)
show_store_func_unsigned(control, reg_14, rxs_on_xaxis)
show_store_func_unsigned(control, reg_14, curve_comp_on_txs)
show_store_func_unsigned(control, reg_20, disable_noise_mitigation)
show_store_func_unsigned(control, reg_21, freq_shift_noise_threshold)
show_store_func_unsigned(control, reg_22__26, medium_noise_threshold)
show_store_func_unsigned(control, reg_22__26, high_noise_threshold)
show_store_func_unsigned(control, reg_22__26, noise_density)
show_store_func_unsigned(control, reg_22__26, frame_count)
show_store_func_unsigned(control, reg_27, iir_filter_coef)
show_store_func_unsigned(control, reg_28, quiet_threshold)
show_store_func_unsigned(control, reg_29, cmn_filter_disable)
show_store_func_unsigned(control, reg_30, cmn_filter_max)
show_store_func_unsigned(control, reg_31, touch_hysteresis)
show_store_func_unsigned(control, reg_32__35, rx_low_edge_comp)
show_store_func_unsigned(control, reg_32__35, rx_high_edge_comp)
show_store_func_unsigned(control, reg_32__35, tx_low_edge_comp)
show_store_func_unsigned(control, reg_32__35, tx_high_edge_comp)
show_store_func_unsigned(control, reg_41, no_signal_clarity)
show_store_func_unsigned(control, reg_57, cbc_cap_0d)
show_store_func_unsigned(control, reg_57, cbc_polarity_0d)
show_store_func_unsigned(control, reg_57, cbc_tx_carrier_selection_0d)

show_replicated_func_unsigned(control, reg_15, sensor_rx_assignment)
show_replicated_func_unsigned(control, reg_16, sensor_tx_assignment)
show_replicated_func_unsigned(control, reg_17, disable)
show_replicated_func_unsigned(control, reg_17, filter_bandwidth)
show_replicated_func_unsigned(control, reg_19, stretch_duration)
show_replicated_func_unsigned(control, reg_38, noise_control_1)
show_replicated_func_unsigned(control, reg_39, noise_control_2)
show_replicated_func_unsigned(control, reg_40, noise_control_3)

show_store_replicated_func_unsigned(control, reg_36, axis1_comp)
show_store_replicated_func_unsigned(control, reg_37, axis2_comp)

static ssize_t synaptics_rmi4_f54_burst_count_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int retval;
	int size = 0;
	unsigned char ii;
	unsigned char *temp;
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	mutex_lock(&f54->control_mutex);

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->control.reg_17->address,
			(unsigned char *)f54->control.reg_17->data,
			f54->control.reg_17->length);
	if (retval < 0) {
		tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,
				"%s: Failed to read control reg_17\n",
				__func__);
	}

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->control.reg_18->address,
			(unsigned char *)f54->control.reg_18->data,
			f54->control.reg_18->length);
	if (retval < 0) {
		tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,
				"%s: Failed to read control reg_18\n",
				__func__);
	}

	mutex_unlock(&f54->control_mutex);

	temp = buf;

	for (ii = 0; ii < f54->control.reg_17->length; ii++) {
		retval = snprintf(temp, PAGE_SIZE - size, "%u ", (1 << 8) *
			f54->control.reg_17->data[ii].burst_count_b8__10 +
			f54->control.reg_18->data[ii].burst_count_b0__7);
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Faild to write output\n",
					__func__);
			return retval;
		}
		size += retval;
		temp += retval;
	}

	retval = snprintf(temp, PAGE_SIZE - size, "\n");
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Faild to write null terminator\n",
				__func__);
		return retval;
	}

	return size + retval;
}

static ssize_t synaptics_rmi4_f54_data_read(struct file *data_file,
		struct kobject *kobj, struct bin_attribute *attributes,
		char *buf, loff_t pos, size_t count)
{
	struct synaptics_rmi4_data *rmi4_data = rmi_attr_kobj_to_drvdata(kobj);
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	mutex_lock(&f54->data_mutex);

	if (count < f54->report_size) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Report type %d data size (%d) too large\n",
				__func__, f54->report_type, f54->report_size);
		mutex_unlock(&f54->data_mutex);
		return -EINVAL;
	}

	if (f54->report_data) {
		memcpy(buf, f54->report_data, f54->report_size);
		mutex_unlock(&f54->data_mutex);
		return f54->report_size;
	} else {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Report type %d data not available\n",
				__func__, f54->report_type);
		mutex_unlock(&f54->data_mutex);
		return -EINVAL;
	}
}

static int synaptics_rmi4_f54_set_sysfs(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	int reg_num;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	f54->attr_dir = kobject_create_and_add(ATTRIBUTE_FOLDER_NAME,
			&rmi4_data->input_dev->dev.kobj);
	if (!f54->attr_dir) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
			"%s: Failed to create sysfs directory\n",
			__func__);
		goto exit_1;
	}

	retval = sysfs_create_bin_file(f54->attr_dir, &dev_report_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to create sysfs bin file\n",
				__func__);
		goto exit_2;
	}

	retval = sysfs_create_group(f54->attr_dir, &attr_group);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to create sysfs attributes\n",
				__func__);
		goto exit_3;
	}

	for (reg_num = 0; reg_num < ARRAY_SIZE(attrs_ctrl_regs); reg_num++) {
		if (attrs_ctrl_regs_exist[reg_num]) {
			retval = sysfs_create_group(f54->attr_dir,
					&attrs_ctrl_regs[reg_num]);
			if (retval < 0) {
				tsp_debug_err(true, &rmi4_data->i2c_client->dev,
						"%s: Failed to create sysfs attributes\n",
						__func__);
				goto exit_4;
			}
		}
	}

	return 0;

exit_4:
	sysfs_remove_group(f54->attr_dir, &attr_group);

	for (reg_num--; reg_num >= 0; reg_num--)
		sysfs_remove_group(f54->attr_dir, &attrs_ctrl_regs[reg_num]);

exit_3:
	sysfs_remove_bin_file(f54->attr_dir, &dev_report_data);

exit_2:
	kobject_put(f54->attr_dir);

exit_1:
	return -ENODEV;
}

static int synaptics_rmi4_f54_set_ctrl(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned char length;
	unsigned char reg_num = 0;
	unsigned char num_of_sensing_freqs;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	struct f54_control *control = &f54->control;
#if defined(HAS_ALTERNATER_R_R)
	int retval;
	unsigned char noise_bpc_ctrl200 = 0;
#endif

	unsigned short reg_addr = f54->control_base_addr;

	num_of_sensing_freqs = f54->query.number_of_sensing_frequencies;

	/* control 0 */
	attrs_ctrl_regs_exist[reg_num] = true;
	control->reg_0 = kzalloc(sizeof(*(control->reg_0)),
			GFP_KERNEL);
	if (!control->reg_0)
		goto exit_no_mem;
	control->reg_0->address = reg_addr;
	reg_addr += sizeof(control->reg_0->data);
	reg_num++;

	/* control 1 */
	if ((f54->query.touch_controller_family == 0) ||
			(f54->query.touch_controller_family == 1)) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_1 = kzalloc(sizeof(*(control->reg_1)),
				GFP_KERNEL);
		if (!control->reg_1)
			goto exit_no_mem;
		control->reg_1->address = reg_addr;
		reg_addr += sizeof(control->reg_1->data);
	}
	reg_num++;

	/* control 2 */
	attrs_ctrl_regs_exist[reg_num] = true;
	control->reg_2 = kzalloc(sizeof(*(control->reg_2)),
			GFP_KERNEL);
	if (!control->reg_2)
		goto exit_no_mem;
	control->reg_2->address = reg_addr;
	reg_addr += sizeof(control->reg_2->data);
	reg_num++;

	/* control 3 */
	if (f54->query.has_pixel_touch_threshold_adjustment == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_3 = kzalloc(sizeof(*(control->reg_3)),
				GFP_KERNEL);
		if (!control->reg_3)
			goto exit_no_mem;
		control->reg_3->address = reg_addr;
		reg_addr += sizeof(control->reg_3->data);
	}
	reg_num++;

	/* controls 4 5 6 */
	if ((f54->query.touch_controller_family == 0) ||
			(f54->query.touch_controller_family == 1)) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_4__6 = kzalloc(sizeof(*(control->reg_4__6)),
				GFP_KERNEL);
		if (!control->reg_4__6)
			goto exit_no_mem;
		control->reg_4__6->address = reg_addr;
		reg_addr += sizeof(control->reg_4__6->data);
	}
	reg_num++;

	/* control 7 */
	if (f54->query.touch_controller_family == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_7 = kzalloc(sizeof(*(control->reg_7)),
				GFP_KERNEL);
		if (!control->reg_7)
			goto exit_no_mem;
		control->reg_7->address = reg_addr;
		reg_addr += sizeof(control->reg_7->data);
	}
	reg_num++;

	/* controls 8 9 */
	if ((f54->query.touch_controller_family == 0) ||
			(f54->query.touch_controller_family == 1)) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_8__9 = kzalloc(sizeof(*(control->reg_8__9)),
				GFP_KERNEL);
		if (!control->reg_8__9)
			goto exit_no_mem;
		control->reg_8__9->address = reg_addr;
		reg_addr += sizeof(control->reg_8__9->data);
	}
	reg_num++;

	/* control 10 */
	if (f54->query.has_interference_metric == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_10 = kzalloc(sizeof(*(control->reg_10)),
				GFP_KERNEL);
		if (!control->reg_10)
			goto exit_no_mem;
		control->reg_10->address = reg_addr;
		reg_addr += sizeof(control->reg_10->data);
	}
	reg_num++;

	/* control 11 */
	if (f54->query.has_ctrl11 == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_11 = kzalloc(sizeof(*(control->reg_11)),
				GFP_KERNEL);
		if (!control->reg_11)
			goto exit_no_mem;
		control->reg_11->address = reg_addr;
		reg_addr += sizeof(control->reg_11->data);
	}
	reg_num++;

	/* controls 12 13 */
	if (f54->query.has_relaxation_control == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_12__13 = kzalloc(sizeof(*(control->reg_12__13)),
				GFP_KERNEL);
		if (!control->reg_12__13)
			goto exit_no_mem;
		control->reg_12__13->address = reg_addr;
		reg_addr += sizeof(control->reg_12__13->data);
	}
	reg_num++;

	/* controls 14 15 16 */
	if (f54->query.has_sensor_assignment == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;

		control->reg_14 = kzalloc(sizeof(*(control->reg_14)),
				GFP_KERNEL);
		if (!control->reg_14)
			goto exit_no_mem;
		control->reg_14->address = reg_addr;
		reg_addr += sizeof(control->reg_14->data);

		control->reg_15 = kzalloc(sizeof(*(control->reg_15)),
				GFP_KERNEL);
		if (!control->reg_15)
			goto exit_no_mem;
		control->reg_15->length = f54->query.num_of_rx_electrodes;
		control->reg_15->data = kzalloc(control->reg_15->length *
				sizeof(*(control->reg_15->data)), GFP_KERNEL);
		if (!control->reg_15->data)
			goto exit_no_mem;
		control->reg_15->address = reg_addr;
		reg_addr += control->reg_15->length;

		control->reg_16 = kzalloc(sizeof(*(control->reg_16)),
				GFP_KERNEL);
		if (!control->reg_16)
			goto exit_no_mem;
		control->reg_16->length = f54->query.num_of_tx_electrodes;
		control->reg_16->data = kzalloc(control->reg_16->length *
				sizeof(*(control->reg_16->data)), GFP_KERNEL);
		if (!control->reg_16->data)
			goto exit_no_mem;
		control->reg_16->address = reg_addr;
		reg_addr += control->reg_16->length;
	}
	reg_num++;

	/* controls 17 18 19 */
	if (f54->query.has_sense_frequency_control == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;

		length = num_of_sensing_freqs;

		control->reg_17 = kzalloc(sizeof(*(control->reg_17)),
				GFP_KERNEL);
		if (!control->reg_17)
			goto exit_no_mem;
		control->reg_17->length = length;
		control->reg_17->data = kzalloc(length *
				sizeof(*(control->reg_17->data)), GFP_KERNEL);
		if (!control->reg_17->data)
			goto exit_no_mem;
		control->reg_17->address = reg_addr;
		reg_addr += length;

		control->reg_18 = kzalloc(sizeof(*(control->reg_18)),
				GFP_KERNEL);
		if (!control->reg_18)
			goto exit_no_mem;
		control->reg_18->length = length;
		control->reg_18->data = kzalloc(length *
				sizeof(*(control->reg_18->data)), GFP_KERNEL);
		if (!control->reg_18->data)
			goto exit_no_mem;
		control->reg_18->address = reg_addr;
		reg_addr += length;

		control->reg_19 = kzalloc(sizeof(*(control->reg_19)),
				GFP_KERNEL);
		if (!control->reg_19)
			goto exit_no_mem;
		control->reg_19->length = length;
		control->reg_19->data = kzalloc(length *
				sizeof(*(control->reg_19->data)), GFP_KERNEL);
		if (!control->reg_19->data)
			goto exit_no_mem;
		control->reg_19->address = reg_addr;
		reg_addr += length;
	}
	reg_num++;

	/* control 20 */
	attrs_ctrl_regs_exist[reg_num] = true;
	control->reg_20 = kzalloc(sizeof(*(control->reg_20)),
			GFP_KERNEL);
	if (!control->reg_20)
		goto exit_no_mem;
	control->reg_20->address = reg_addr;
	reg_addr += sizeof(control->reg_20->data);
	reg_num++;

	/* control 21 */
	if (f54->query.has_sense_frequency_control == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_21 = kzalloc(sizeof(*(control->reg_21)),
				GFP_KERNEL);
		if (!control->reg_21)
			goto exit_no_mem;
		control->reg_21->address = reg_addr;
		reg_addr += sizeof(control->reg_21->data);
	}
	reg_num++;

	/* controls 22 23 24 25 26 */
	if (f54->query.has_firmware_noise_mitigation == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_22__26 = kzalloc(sizeof(*(control->reg_22__26)),
				GFP_KERNEL);
		if (!control->reg_22__26)
			goto exit_no_mem;
		control->reg_22__26->address = reg_addr;
		reg_addr += sizeof(control->reg_22__26->data);
	}
	reg_num++;

	/* control 27 */
	if (f54->query.has_iir_filter == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_27 = kzalloc(sizeof(*(control->reg_27)),
				GFP_KERNEL);
		if (!control->reg_27)
			goto exit_no_mem;
		control->reg_27->address = reg_addr;
		reg_addr += sizeof(control->reg_27->data);
	}
	reg_num++;

	/* control 28 */
	if (f54->query.has_firmware_noise_mitigation == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_28 = kzalloc(sizeof(*(control->reg_28)),
				GFP_KERNEL);
		if (!control->reg_28)
			goto exit_no_mem;
		control->reg_28->address = reg_addr;
		reg_addr += sizeof(control->reg_28->data);
	}
	reg_num++;

	/* control 29 */
	if (f54->query.has_cmn_removal == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_29 = kzalloc(sizeof(*(control->reg_29)),
				GFP_KERNEL);
		if (!control->reg_29)
			goto exit_no_mem;
		control->reg_29->address = reg_addr;
		reg_addr += sizeof(control->reg_29->data);
	}
	reg_num++;

	/* control 30 */
	if (f54->query.has_cmn_maximum == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_30 = kzalloc(sizeof(*(control->reg_30)),
				GFP_KERNEL);
		if (!control->reg_30)
			goto exit_no_mem;
		control->reg_30->address = reg_addr;
		reg_addr += sizeof(control->reg_30->data);
	}
	reg_num++;

	/* control 31 */
	if (f54->query.has_touch_hysteresis == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_31 = kzalloc(sizeof(*(control->reg_31)),
				GFP_KERNEL);
		if (!control->reg_31)
			goto exit_no_mem;
		control->reg_31->address = reg_addr;
		reg_addr += sizeof(control->reg_31->data);
	}
	reg_num++;

	/* controls 32 33 34 35 */
	if (f54->query.has_edge_compensation == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_32__35 = kzalloc(sizeof(*(control->reg_32__35)),
				GFP_KERNEL);
		if (!control->reg_32__35)
			goto exit_no_mem;
		control->reg_32__35->address = reg_addr;
		reg_addr += sizeof(control->reg_32__35->data);
	}
	reg_num++;

	/* control 36 */
	if ((f54->query.curve_compensation_mode == 1) ||
			(f54->query.curve_compensation_mode == 2)) {
		attrs_ctrl_regs_exist[reg_num] = true;

		if (f54->query.curve_compensation_mode == 1) {
			length = max(f54->query.num_of_rx_electrodes,
					f54->query.num_of_tx_electrodes);
		} else if (f54->query.curve_compensation_mode == 2) {
			length = f54->query.num_of_rx_electrodes;
		}

		control->reg_36 = kzalloc(sizeof(*(control->reg_36)),
				GFP_KERNEL);
		if (!control->reg_36)
			goto exit_no_mem;
		control->reg_36->length = length;
		control->reg_36->data = kzalloc(length *
				sizeof(*(control->reg_36->data)), GFP_KERNEL);
		if (!control->reg_36->data)
			goto exit_no_mem;
		control->reg_36->address = reg_addr;
		reg_addr += length;
	}
	reg_num++;

	/* control 37 */
	if (f54->query.curve_compensation_mode == 2) {
		attrs_ctrl_regs_exist[reg_num] = true;

		control->reg_37 = kzalloc(sizeof(*(control->reg_37)),
				GFP_KERNEL);
		if (!control->reg_37)
			goto exit_no_mem;
		control->reg_37->length = f54->query.num_of_tx_electrodes;
		control->reg_37->data = kzalloc(control->reg_37->length *
				sizeof(*(control->reg_37->data)), GFP_KERNEL);
		if (!control->reg_37->data)
			goto exit_no_mem;

		control->reg_37->address = reg_addr;
		reg_addr += control->reg_37->length;
	}
	reg_num++;

	/* controls 38 39 40 */
	if (f54->query.has_per_frequency_noise_control == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;

		control->reg_38 = kzalloc(sizeof(*(control->reg_38)),
				GFP_KERNEL);
		if (!control->reg_38)
			goto exit_no_mem;
		control->reg_38->length = num_of_sensing_freqs;
		control->reg_38->data = kzalloc(control->reg_38->length *
				sizeof(*(control->reg_38->data)), GFP_KERNEL);
		if (!control->reg_38->data)
			goto exit_no_mem;
		control->reg_38->address = reg_addr;
		reg_addr += control->reg_38->length;

		control->reg_39 = kzalloc(sizeof(*(control->reg_39)),
				GFP_KERNEL);
		if (!control->reg_39)
			goto exit_no_mem;
		control->reg_39->length = num_of_sensing_freqs;
		control->reg_39->data = kzalloc(control->reg_39->length *
				sizeof(*(control->reg_39->data)), GFP_KERNEL);
		if (!control->reg_39->data)
			goto exit_no_mem;
		control->reg_39->address = reg_addr;
		reg_addr += control->reg_39->length;

		control->reg_40 = kzalloc(sizeof(*(control->reg_40)),
				GFP_KERNEL);
		if (!control->reg_40)
			goto exit_no_mem;
		control->reg_40->length = num_of_sensing_freqs;
		control->reg_40->data = kzalloc(control->reg_40->length *
				sizeof(*(control->reg_40->data)), GFP_KERNEL);
		if (!control->reg_40->data)
			goto exit_no_mem;
		control->reg_40->address = reg_addr;
		reg_addr += control->reg_40->length;
	}
	reg_num++;

	/* control 41 */
	if (f54->query.has_signal_clarity == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_41 = kzalloc(sizeof(*(control->reg_41)),
				GFP_KERNEL);
		if (!control->reg_41)
			goto exit_no_mem;
		control->reg_41->address = reg_addr;
		reg_addr += sizeof(control->reg_41->data);
	}
	reg_num++;

	/* control 42 */
	if (f54->query.has_variance_metric == 1)
		reg_addr += CONTROL_42_SIZE;

	/* controls 43 44 45 46 47 48 49 50 51 52 53 54 */
	if (f54->query.has_multi_metric_state_machine == 1)
		reg_addr += CONTROL_43_54_SIZE;

	/* controls 55 56 */
	if (f54->query.has_0d_relaxation_control == 1)
		reg_addr += CONTROL_55_56_SIZE;

	/* control 57 */
	if (f54->query.has_0d_acquisition_control == 1) {
		attrs_ctrl_regs_exist[reg_num] = true;
		control->reg_57 = kzalloc(sizeof(*(control->reg_57)),
				GFP_KERNEL);
		if (!control->reg_57)
			goto exit_no_mem;
		control->reg_57->address = reg_addr;
		reg_addr += sizeof(control->reg_57->data);
	}
	reg_num++;

	/* control 58 */
	if (f54->query.has_0d_acquisition_control == 1)
		reg_addr += CONTROL_58_SIZE;

	/* control 59 */
	if (f54->query.has_h_blank == 1)
		reg_addr += CONTROL_59_SIZE;

	/* controls 60 61 62 */
	if ((f54->query.has_h_blank == 1) ||
			(f54->query.has_v_blank == 1) ||
			(f54->query.has_long_h_blank == 1))
		reg_addr += CONTROL_60_62_SIZE;

	/* control 63 */
	if ((f54->query.has_h_blank == 1) ||
			(f54->query.has_v_blank == 1) ||
			(f54->query.has_long_h_blank == 1) ||
			(f54->query.has_slew_metric == 1) ||
			(f54->query.has_slew_option == 1) ||
			(f54->query.has_noise_mitigation2 == 1))
		reg_addr += CONTROL_63_SIZE;

	/* controls 64 65 66 67 */
	if (f54->query.has_h_blank == 1)
		reg_addr += CONTROL_64_67_SIZE * 7;
	else if ((f54->query.has_v_blank == 1) ||
			(f54->query.has_long_h_blank == 1))
		reg_addr += CONTROL_64_67_SIZE;

	/* controls 68 69 70 71 72 73 */
	if ((f54->query.has_h_blank == 1) ||
			(f54->query.has_v_blank == 1) ||
			(f54->query.has_long_h_blank == 1))
		reg_addr += CONTROL_68_73_SIZE;

	/* control 74 */
	if (f54->query.has_slew_metric == 1)
		reg_addr += CONTROL_74_SIZE;

	/* control 75 */
	if (f54->query.has_enhanced_stretch == 1)
		reg_addr += num_of_sensing_freqs;

	/* control 76 */
	if (f54->query.has_startup_fast_relaxation == 1)
		reg_addr += CONTROL_76_SIZE;

	/* controls 77 78 */
	if (f54->query.has_esd_control == 1)
		reg_addr += CONTROL_77_78_SIZE;

	/* controls 79 80 81 82 83 */
	if (f54->query.has_noise_mitigation2 == 1)
		reg_addr += CONTROL_79_83_SIZE;

	/* controls 84 85 */
	if (f54->query.has_energy_ratio_relaxation == 1)
		reg_addr += CONTROL_84_85_SIZE;

	/* control 86 */
	if ((f54->query.has_query13 == 1) && (f54->query_13.has_ctrl86 == 1))
		reg_addr += CONTROL_86_SIZE;

	/* control 87 */
	if ((f54->query.has_query13 == 1) && (f54->query_13.has_ctrl87 == 1))
		reg_addr += CONTROL_87_SIZE;

	/* control 88 */
	if (f54->query.has_ctrl88 == 1) {
		control->reg_88 = kzalloc(sizeof(*(control->reg_88)),
				GFP_KERNEL);
		if (!control->reg_88)
			goto exit_no_mem;
		control->reg_88->address = reg_addr;
		reg_addr += sizeof(control->reg_88->data);
	}

	/* control 89 */
	if ((f54->query.has_query13 == 1) &&
			((f54->query_13.has_cidim == 1) ||
			(f54->query_13.has_noise_mitigation_enhancement == 1) ||
			(f54->query_13.has_rail_im)))
		reg_addr += CONTROL_89_SIZE;

	/* control 90 */
	if ((f54->query.has_query15) && (f54->query_15.has_ctrl90))
		reg_addr += CONTROL_90_SIZE;

	/* control 91 */
	if (f54->query_21.has_ctrl91)
		reg_addr += CONTROL_91_SIZE;

	/* control 92 */
	if (f54->query_16.has_ctrl92)
		reg_addr += CONTROL_92_SIZE;

	/* control 93 */
	if (f54->query_16.has_ctrl93)
		reg_addr += CONTROL_93_SIZE;

	/* control 94 */
	if (f54->query_16.has_ctrl94_query18) {
		control->reg_94 = kzalloc(sizeof(*(control->reg_94)),
				GFP_KERNEL);
		if (!control->reg_94)
			goto exit_no_mem;
		control->reg_94->address = reg_addr;
		reg_addr += 1;
	}

	/* control 95 */
	if (f54->query_16.has_ctrl95_query19)
		reg_addr += 1;

	/* control 96 */
	if (f54->query_21.has_ctrl96)
		reg_addr += 1;

	/* control 97 */
	if (f54->query_21.has_ctrl97)
		reg_addr += 1;

	/* control 98 */
	if (f54->query_21.has_ctrl98)
		reg_addr += 1;

	/* control 99 */
	if (f54->query_16.has_ctrl99)
		reg_addr += 1;

	/* control 100 */
	if (f54->query_16.has_ctrl100)
		reg_addr += 1;

	/* control 101 */
	if (f54->query_22.has_ctrl101)
		reg_addr += 1;

	/* control 102 */
	if (f54->query_25.has_ctrl102_sub12)
		reg_addr += 1;

	/* control 103 */
	if (f54->query_22.has_ctrl103_query26)
		reg_addr += 1;

	/* control 104 */
	if (f54->query_22.has_ctrl104)
		reg_addr += 1;

	/* control 105 */
	if (f54->query_22.has_ctrl105)
		reg_addr += 1;

	/* control 106 */
	if (f54->query_25.has_ctrl106)
		reg_addr += 1;

	/* control 107 */
	if (f54->query_25.has_ctrl107)
		reg_addr += 1;

	/* control 108 */
	if (f54->query_25.has_ctrl108)
		reg_addr += 1;

	/* control 109 */
	if (f54->query_25.has_ctrl109)
		reg_addr += 1;

	/* control 110 */
	if (f54->query_27.has_ctrl110)
		reg_addr += 1;

	/* control 111 */
	if (f54->query_27.has_ctrl111)
		reg_addr += 1;

	/* control 112 */
	if (f54->query_27.has_ctrl112)
		reg_addr += 1;

	/* control 113 */
	if (f54->query_27.has_ctrl113)
		reg_addr += 1;

	/* control 114 */
	if (f54->query_27.has_ctrl114)
		reg_addr += 1;

	/* control 115 */
	if (f54->query_29.has_ctrl115)
		reg_addr += 1;

	/* control 116 */
	if (f54->query_29.has_ctrl116)
		reg_addr += 1;

	/* control 117 */
	if (f54->query_29.has_ctrl117)
		reg_addr += 1;

	/* control 118 */
	if (f54->query_30.has_ctrl118)
		reg_addr += 1;

	/* control 119~124 */

	/* control 125 */
	if (f54->query_32.has_ctrl125)
		reg_addr += 1;

	/* control 126 */
	if (f54->query_32.has_ctrl126)
		reg_addr += 1;

	/* control 127 */
	if (f54->query_32.has_ctrl127)
		reg_addr += 1;


	/* control 128~141 */

	/* control 142 */
	if (f54->query_36.has_ctrl142)
		reg_addr += 1;

	/* control 143~147 */

	/* control 148 */
	if (f54->query_38.has_ctrl148)
		reg_addr += 1;

	/* control 149 */
	if (f54->query_38.has_ctrl149)
		reg_addr += 1;

	/* control 150~156 */

	/* control 157 & 158 */
	if (f54->query_39.has_ctrl157_ctrl158)
		reg_addr += 2;

	/* control 159~162 */

	/* control 163 */
	if (f54->query_40.has_ctrl163_query41)
		reg_addr += 1;

	/* control 164~167 */

#if defined(HAS_ALTERNATER_R_R)
	/* control 168 */
	if (f54->query_55.has_alternatereportrate){
		control->reg_168 = kzalloc(sizeof(*(control->reg_168)),
				GFP_KERNEL);
		if (!control->reg_168)
			goto exit_no_mem;

		control->reg_168->address = reg_addr;
		retval = rmi4_data->i2c_read(rmi4_data,
				control->reg_168->address,
				control->reg_168->data,
				sizeof(control->reg_168->data));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
						"%s: Ctrl Reg 168 [%X]\n", __func__, control->reg_168->address);
		}
		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"%s: Ctrl Reg 168 [%X] => [%X]\n",
					__func__, control->reg_168->address, control->reg_168->data[0]);
		reg_addr += 1;
	}

	/* control 169~170 */

	/* control 171 */
	if (f54->query_43.has_ctrl171)
		reg_addr += 1;

	/* control 172 */
	/* control 173 */
	if (f54->query_43.has_ctrl173)
		reg_addr += 1;

	/* control 174 */
	if (f54->query_43.has_ctrl174)
		reg_addr += 1;

	/* control 175 */
	if (f54->query_43.has_ctrl175)
		reg_addr += 1;

	/* control 176~199 */

	/* control 200 */
	if (f54->query_55.has_ctrl200) {
		retval = rmi4_data->i2c_read(rmi4_data,
				reg_addr,
				&noise_bpc_ctrl200,
				sizeof(noise_bpc_ctrl200));
		if (retval < 0) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
						"%s: Ctrl Reg 200 [%X]\n", __func__, reg_addr);
		}
		tsp_debug_info(true, &rmi4_data->i2c_client->dev,
					"%s: Ctrl Reg 200 [%X] => [0x%02X]\n", __func__, reg_addr, noise_bpc_ctrl200);
	}
#endif

	return 0;

exit_no_mem:
	tsp_debug_err(true, &rmi4_data->i2c_client->dev,
			"%s: Failed to alloc mem for control registers\n",
			__func__);
	return -ENOMEM;
}

static int synaptics_rmi4_f54_set_query(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char offset;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->query_base_addr,
			f54->query.data,
			sizeof(f54->query.data));
	if (retval < 0)
		return retval;

	offset = sizeof(f54->query.data);

	/* query 12 */
	if (f54->query.has_sense_frequency_control == 0)
		offset -= 1;

	/* query 13 */
	if (f54->query.has_query13) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_13.data,
				sizeof(f54->query_13.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 14 */
	if ((f54->query.has_query13) && (f54->query_13.has_ctrl87))
		offset += 1;

	/* query 15 */
	if (f54->query.has_query15) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_15.data,
				sizeof(f54->query_15.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 16 */
	if (f54->query_15.has_query16) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_16.data,
				sizeof(f54->query_16.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 17 */
	if (f54->query_16.has_query17)
		offset += 1;

	/* query 18 */
	if (f54->query_16.has_ctrl94_query18)
		offset += 1;

	/* query 19 */
	if (f54->query_16.has_ctrl95_query19)
		offset += 1;

	/* query 20 */
	if ((f54->query.has_query15) && (f54->query_15.has_query20))
		offset += 1;

	/* query 21 */
	if (f54->query_15.has_query21) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_21.data,
				sizeof(f54->query_21.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 22 */
	if ((f54->query_15.has_query22)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_22.data,
				sizeof(f54->query_22.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 23 */
	if (f54->query_22.has_query23)
		offset += 1;

	/* query 24 */
	if (f54->query_21.has_query24_data18)
		offset += 1;

	/* query 25 */
	if ((f54->query_15.has_query25)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_25.data,
				sizeof(f54->query_25.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 26 */
	if (f54->query_22.has_ctrl103_query26)
		offset += 1;

	/* query 27 */
	if ((f54->query_25.has_query27)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_27.data,
				sizeof(f54->query_27.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 28 */
	if (f54->query_22.has_query28)
		offset += 1;

	/* query 29 */
	if ((f54->query_27.has_query29)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_29.data,
				sizeof(f54->query_29.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 30 */
	if ((f54->query_29.has_query30)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_30.data,
				sizeof(f54->query_30.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 31 */
	if (f54->query_30.has_ctrl122_query31)
		offset += 1;

	/* query 32 */
	if ((f54->query_30.has_query32)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_32.data,
				sizeof(f54->query_32.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 33 */
	if ((f54->query_32.has_query33)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_33.data,
				sizeof(f54->query_33.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 34 */
	if (f54->query_32.has_query34)
		offset += 1;

	/* query 35 */
	if (f54->query_32.has_query35)
		offset += 1;

	/* query 36 */
	if ((f54->query_33.has_query36)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_36.data,
				sizeof(f54->query_36.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 37 */
	if (f54->query_36.has_query37)
		offset += 1;

	/* query 38 */
	if ((f54->query_36.has_query38)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_38.data,
				sizeof(f54->query_38.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 39 */
	if ((f54->query_38.has_query39)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_39.data,
				sizeof(f54->query_39.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 40 */
	if ((f54->query_39.has_query40)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_40.data,
				sizeof(f54->query_40.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 41 */
	if (f54->query_40.has_ctrl163_query41)
		offset += 1;

	/* query 42 */
	if (f54->query_40.has_ctrl165_query42)
		offset += 1;

	/* query 43 */
	if ((f54->query_40.has_query43)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_43.data,
				sizeof(f54->query_43.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 44 */
	/* query 45 */

	/* query 46 */
	if ((f54->query_43.has_query46)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_46.data,
				sizeof(f54->query_46.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 47 */
	if ((f54->query_46.has_query47)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_47.data,
				sizeof(f54->query_47.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 49 */
	if ((f54->query_47.has_query49)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_49.data,
				sizeof(f54->query_49.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 50 */
	if ((f54->query_49.has_query50)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_50.data,
				sizeof(f54->query_50.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 51 */
	if ((f54->query_50.has_query51)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_51.data,
				sizeof(f54->query_51.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

#if defined(HAS_ALTERNATER_R_R)
	/* query 55 */
	if ((f54->query_51.has_query55)) {
		retval = rmi4_data->i2c_read(rmi4_data,
				f54->query_base_addr + offset,
				f54->query_55.data,
				sizeof(f54->query_55.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}
	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: %sSupport Has Alternate Report Rate[%d]\n",
				__func__, f54->query_55.has_alternatereportrate ? "" : "NOT ", offset);
#endif

	return 0;
}

static int synaptics_rmi4_f54_reinit(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned short ii;
	unsigned char page;
	unsigned char intr_count = 0;
	unsigned char intr_offset;
	struct synaptics_rmi4_fn_desc rmi_fd;
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	for (page = 0; page < PAGES_TO_SERVICE; page++) {
		for (ii = PDT_START; ii > PDT_END; ii -= PDT_ENTRY_SIZE) {
			ii |= (page << 8);

			retval = rmi4_data->i2c_read(rmi4_data,
					ii,
					(unsigned char *)&rmi_fd,
					sizeof(rmi_fd));
			if (retval < 0) {
				tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to read page description table\n",
						__func__);
				goto err_out;
			}

			if (rmi_fd.fn_number == SYNAPTICS_RMI4_F54)
				goto f54_found;

			if (!rmi_fd.fn_number)
				break;

			intr_count += (rmi_fd.intr_src_count & MASK_3BIT);
		}
	}

	tsp_debug_dbg(false, &rmi4_data->i2c_client->dev, "%s: Can not find F54 in descripttion table\n", __func__);
	goto pdt_done;

f54_found:
	f54->query_base_addr = rmi_fd.query_base_addr | (page << 8);
	f54->control_base_addr = rmi_fd.ctrl_base_addr | (page << 8);
	f54->data_base_addr = rmi_fd.data_base_addr | (page << 8);
	f54->command_base_addr = rmi_fd.cmd_base_addr | (page << 8);

	f54->intr_reg_num = (intr_count + 7) / 8;
	if (f54->intr_reg_num != 0)
		f54->intr_reg_num -= 1;

	f54->intr_mask = 0;
	intr_offset = intr_count % 8;
	for (ii = intr_offset;
			ii < ((rmi_fd.intr_src_count & MASK_3BIT) +
			intr_offset);
			ii++) {
		f54->intr_mask |= 1 << ii;
	}

	tsp_debug_dbg(false, &rmi4_data->i2c_client->dev,
		"%s: F54 found : NUM_INT_REG[%02X] INT_MASK[%02x] BASE_ADDRS[%04x,%04x,%04x,%04x]\n",
		__func__, f54->intr_reg_num, f54->intr_mask,
		f54->query_base_addr, f54->control_base_addr, f54->data_base_addr, f54->command_base_addr);

	retval = synaptics_rmi4_f54_set_query(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to read query registers\n",
				__func__);
		goto err_out;
	}

#if 0
	f54->rx_assigned = f54->query.num_of_rx_electrodes;
	f54->tx_assigned = f54->query.num_of_tx_electrodes;
#else
	f54->rx_assigned = rmi4_data->num_of_rx;
	f54->tx_assigned = rmi4_data->num_of_tx;
#endif

	tsp_debug_info(true, &rmi4_data->i2c_client->dev,
			"%s: F54 rx,tx = %d, %d\n", __func__, f54->rx_assigned, f54->tx_assigned);

	free_control_mem(rmi4_data->f54);
	retval = synaptics_rmi4_f54_set_ctrl(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to set up control registers\n",
				__func__);
		goto err_set_ctrl;
	}

	return 0;

err_set_ctrl:
	free_control_mem(rmi4_data->f54);

err_out:
pdt_done:
	return retval;
}

#ifdef FACTORY_MODE
static int synaptics_rmi4_f54_get_report_type(struct synaptics_rmi4_data *rmi4_data, int type)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	int retval;
	char buf[3];
	unsigned int patience = 250;

	if (!f54) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: F54 is Null\n",
				__func__);
		return 0;
	}

	memset(buf, 0x00, sizeof(buf));
	snprintf(buf, 3, "%u\n", type);
	retval = synaptics_rmi4_f54_report_type_store(f54->attr_dir, NULL, buf, 2);
	if (retval != 2)
		return 0;

	memset(buf, 0x00, sizeof(buf));
	snprintf(buf, 3, "%u\n", CMD_GET_REPORT);
	retval = synaptics_rmi4_f54_get_report_store(f54->attr_dir, NULL, buf, 2);
	if (retval != 2)
		return 0;

	do {
		msleep(20);
		if (f54->status == STATUS_IDLE)
			break;
	} while (--patience > 0);

	if ((f54->report_size == 0) || (f54->status != STATUS_IDLE))
		return 0;
	else
		return 1;
}
#endif

static void synaptics_rmi4_f54_status_work(struct work_struct *work)
{
	int retval;
	unsigned char report_index[2];

	struct synaptics_rmi4_f54_handle *f54 =
		container_of(work, struct synaptics_rmi4_f54_handle, status_work.work);
	struct synaptics_rmi4_data *rmi4_data = (struct synaptics_rmi4_data *)f54->rmi4_data;

	if (f54->status != STATUS_BUSY)
		return;

	set_report_size(rmi4_data);
	if (f54->report_size == 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Report data size = 0\n",
				__func__);
		retval = -EINVAL;
		goto error_exit;
	}

	if (f54->data_buffer_size < f54->report_size) {
		mutex_lock(&f54->data_mutex);
		if (f54->data_buffer_size)
			kfree(f54->report_data);
		f54->report_data = kzalloc(f54->report_size, GFP_KERNEL);
		if (!f54->report_data) {
			tsp_debug_err(true, &rmi4_data->i2c_client->dev,
					"%s: Failed to alloc mem for data buffer\n",
					__func__);
			f54->data_buffer_size = 0;
			mutex_unlock(&f54->data_mutex);
			retval = -ENOMEM;
			goto error_exit;
		}
		f54->data_buffer_size = f54->report_size;
		mutex_unlock(&f54->data_mutex);
	}

	report_index[0] = 0;
	report_index[1] = 0;

	retval = rmi4_data->i2c_write(rmi4_data,
			f54->data_base_addr + DATA_REPORT_INDEX_OFFSET,
			report_index,
			sizeof(report_index));
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to write report data index\n",
				__func__);
		retval = -EINVAL;
		goto error_exit;
	}

	retval = rmi4_data->i2c_read(rmi4_data,
			f54->data_base_addr + DATA_REPORT_DATA_OFFSET,
			f54->report_data,
			f54->report_size);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to read report data\n",
				__func__);
		retval = -EINVAL;
		goto error_exit;
	}

	retval = STATUS_IDLE;

#ifdef RAW_HEX
	print_raw_hex_report(rmi4_data);
#endif

#ifdef HUMAN_READABLE
	print_image_report(rmi4_data);
#endif

error_exit:
	mutex_lock(&f54->status_mutex);
	set_interrupt(rmi4_data, false);
	f54->status = retval;
	mutex_unlock(&f54->status_mutex);

	return;
}

static void synaptics_rmi4_f54_attn(struct synaptics_rmi4_data *rmi4_data,
		unsigned char intr_mask)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	if (!f54)
		return;

	if (f54->intr_mask & intr_mask) {
		queue_delayed_work(f54->status_workqueue,
				&f54->status_work,
				msecs_to_jiffies(STATUS_WORK_INTERVAL));
	}

	return;
}

#ifdef FACTORY_MODE
static void synaptics_rmi4_remove_factory_mode(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	if (!f54)
		return;

	sysfs_remove_link(&f54->factory_data->fac_dev_ts->kobj, "input");
	sysfs_remove_group(f54->attr_dir, &cmd_attr_group);
	sec_device_destroy(f54->factory_data->fac_dev_ts->devt);

	kfree(f54->factory_data->trx_short);
	kfree(f54->factory_data->abscap_data);
	kfree(f54->factory_data->absdelta_data);
	kfree(f54->factory_data->rawcap_data);
	kfree(f54->factory_data->delta_data);
	kfree(f54->factory_data);
}

static int synaptics_rmi4_init_factory_mode(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;
	unsigned char rx;
	unsigned char tx;
	int retval = 0, ii;
	struct factory_data *factory_data;
	char fac_dir_name[20] = {0, };

	if (!f54) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
			"%s: F54 data is null\n", __func__);
		return -ENOMEM;
	}

	rx = f54->rx_assigned;
	tx = f54->tx_assigned;

	factory_data = kzalloc(sizeof(*factory_data), GFP_KERNEL);
	if (!factory_data) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for factory_data\n",
				__func__);
		retval = -ENOMEM;
		goto exit_factory_data;
	}

	factory_data->rawcap_data = kzalloc(2 * rx * tx, GFP_KERNEL);
	if (!factory_data->rawcap_data) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for rawcap_data\n",
				__func__);
		retval = -ENOMEM;
		goto exit_rawcap_data;
	}

	factory_data->delta_data = kzalloc(2 * rx * tx, GFP_KERNEL);
	if (!factory_data->delta_data) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for delta_data\n",
				__func__);
		retval = -ENOMEM;
		goto exit_delta_data;
	}

	factory_data->abscap_data = kzalloc(4 * rx * tx, GFP_KERNEL);
	if (!factory_data->abscap_data) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for abscap_data\n",
				__func__);
		retval = -ENOMEM;
		goto exit_abscap_data;
	}
	factory_data->absdelta_data = kzalloc(4 * rx * tx, GFP_KERNEL);
	if (!factory_data->abscap_data) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for abscap_data\n",
				__func__);
		retval = -ENOMEM;
		goto exit_absdelta_data;
	}

	factory_data->trx_short = kzalloc(TREX_DATA_SIZE, GFP_KERNEL);
	if (!factory_data->trx_short) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for trx_short\n",
				__func__);
		retval = -ENOMEM;
		goto exit_trx_short;
	}

	INIT_LIST_HEAD(&factory_data->cmd_list_head);
	for (ii = 0; ii < ARRAY_SIZE(ft_cmds); ii++)
		list_add_tail(&ft_cmds[ii].list, &factory_data->cmd_list_head);

	mutex_init(&factory_data->cmd_lock);
	factory_data->cmd_is_running = false;

	if (rmi4_data->board->device_num > DEFAULT_DEVICE_NUM)
		sprintf(fac_dir_name, "tsp%d", rmi4_data->board->device_num);
	else
		sprintf(fac_dir_name, "tsp");

	tsp_debug_info(true, &rmi4_data->i2c_client->dev, "%s: fac_dir_name : %s\n",
			__func__, fac_dir_name);

	factory_data->fac_dev_ts = sec_device_create(rmi4_data, fac_dir_name);

	retval = IS_ERR(factory_data->fac_dev_ts);
	if (retval) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev, "%s: Failed to create device for the sysfs\n",
				__func__);
		retval = IS_ERR(factory_data->fac_dev_ts);
		goto exit_sec_device_create;
	}

	retval = sysfs_create_group(&factory_data->fac_dev_ts->kobj,
	    &cmd_attr_group);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to create sysfs attributes\n",
				__func__);
		goto exit_cmd_attr_group;
	}

	retval = sysfs_create_link(&factory_data->fac_dev_ts->kobj,
		&rmi4_data->input_dev->dev.kobj, "input");

	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to create link\n", __func__);
		goto exit_cmd_attr_group;
	}

	f54->factory_data = factory_data;

	return 0;

exit_cmd_attr_group:
	sysfs_remove_group(&factory_data->fac_dev_ts->kobj, &cmd_attr_group);
exit_sec_device_create:
	sec_device_destroy(factory_data->fac_dev_ts->devt);
	kfree(factory_data->trx_short);
exit_trx_short:
	kfree(factory_data->absdelta_data);
exit_absdelta_data:
	kfree(factory_data->abscap_data);
exit_abscap_data:
	kfree(factory_data->delta_data);
exit_delta_data:
	kfree(factory_data->rawcap_data);
exit_rawcap_data:
	kfree(factory_data);
	factory_data = NULL;
exit_factory_data:

	return retval;
}
#endif

static int synaptics_rmi4_f54_init(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	struct synaptics_rmi4_f54_handle *f54 = NULL;

	f54 = kzalloc(sizeof(struct synaptics_rmi4_f54_handle), GFP_KERNEL);
	if (!f54) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to alloc mem for f54\n",
				__func__);
		retval = -ENOMEM;
		return retval;
	}

	rmi4_data->f54 = f54;
	f54->rmi4_data = rmi4_data;
	f54->rx_assigned = rmi4_data->num_of_rx;
	f54->tx_assigned = rmi4_data->num_of_tx;

	retval = synaptics_rmi4_f54_reinit(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to reinit f54.\n",
				__func__);
		goto err_reinit;
	}

	mutex_init(&f54->status_mutex);
	mutex_init(&f54->data_mutex);
	mutex_init(&f54->control_mutex);

	retval = synaptics_rmi4_f54_set_sysfs(rmi4_data);
	if (retval < 0) {
		tsp_debug_err(true, &rmi4_data->i2c_client->dev,
				"%s: Failed to create sysfs entries\n",
				__func__);
		goto err_set_sysfs;
	}

	f54->status_workqueue =
			create_singlethread_workqueue("f54_status_workqueue");
	INIT_DELAYED_WORK(&f54->status_work,
			synaptics_rmi4_f54_status_work);

#ifdef WATCHDOG_HRTIMER
	/* Watchdog timer to catch unanswered get report commands */
	hrtimer_init(&f54->watchdog, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	f54->watchdog.function = get_report_timeout;

	/* Work function to do actual cleaning up */
	INIT_WORK(&f54->timeout_work, timeout_set_status);
#endif

	f54->status = STATUS_IDLE;

#ifdef FACTORY_MODE
	synaptics_rmi4_init_factory_mode(rmi4_data);
#endif

	return 0;

err_set_sysfs:
	remove_sysfs(f54);

err_reinit:
	free_control_mem(f54);
	kfree(f54);
	rmi4_data->f54 = NULL;

	return retval;
}

static void synaptics_rmi4_f54_remove(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_f54_handle *f54 = rmi4_data->f54;

	if (!f54)
		goto exit;

#ifdef WATCHDOG_HRTIMER
	hrtimer_cancel(&f54->watchdog);
#endif

	cancel_delayed_work_sync(&f54->status_work);
	flush_workqueue(f54->status_workqueue);
	destroy_workqueue(f54->status_workqueue);

#ifdef FACTORY_MODE
	synaptics_rmi4_remove_factory_mode(rmi4_data);
#endif
	remove_sysfs(f54);
	free_control_mem(f54);

	if (f54->data_buffer_size)
		kfree(f54->report_data);

	kfree(f54);
	rmi4_data->f54 = NULL;

exit:
	return;
}

int rmi4_f54_module_register(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;

	retval = synaptics_rmi4_new_function(RMI_F54,
			rmi4_data,
			synaptics_rmi4_f54_init,
			synaptics_rmi4_f54_reinit,
			synaptics_rmi4_f54_remove,
			synaptics_rmi4_f54_attn);

	return retval;
}

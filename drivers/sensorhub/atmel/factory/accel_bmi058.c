/*
 *  Copyright (C) 2012, Samsung Electronics Co. Ltd. All Rights Reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */
#include "../ssp.h"

/*************************************************************************/
/* factory Sysfs                                                         */
/*************************************************************************/

#define VENDOR		"BOSCH"
#define CHIP_ID		"BMI058"

#define CALIBRATION_FILE_PATH	"/efs/calibration_data"
#define CALIBRATION_DATA_AMOUNT	20

static ssize_t accel_vendor_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", VENDOR);
}

static ssize_t accel_name_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", CHIP_ID);
}

int accel_open_calibration(struct ssp_data *data)
{
	int iRet = 0;
	mm_segment_t old_fs;
	struct file *cal_filp = NULL;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	cal_filp = filp_open(CALIBRATION_FILE_PATH, O_RDONLY, 0660);
	if (IS_ERR(cal_filp)) {
		set_fs(old_fs);
		iRet = PTR_ERR(cal_filp);

		data->accelcal.x = 0;
		data->accelcal.y = 0;
		data->accelcal.z = 0;

		return iRet;
	}

	iRet = cal_filp->f_op->read(cal_filp, (char *)&data->accelcal,
		3 * sizeof(int), &cal_filp->f_pos);
	if (iRet != 3 * sizeof(int))
		iRet = -EIO;

	filp_close(cal_filp, current->files);
	set_fs(old_fs);

	ssp_dbg("[SSP]: open accel calibration %d, %d, %d\n",
		data->accelcal.x, data->accelcal.y, data->accelcal.z);

	if ((data->accelcal.x == 0) && (data->accelcal.y == 0)
		&& (data->accelcal.z == 0))
		return ERROR;

	return iRet;
}

int set_accel_cal(struct ssp_data *data)
{
	int iRet = 0;
	struct ssp_msg *msg;
	s16 accel_cal[3];

	if (!(data->uSensorState & (1 << ACCELEROMETER_SENSOR))) {
		pr_info("[SSP]: %s - Skip this function!!!"\
			", accel sensor is not connected(0x%x)\n",
			__func__, data->uSensorState);
		return iRet;
	}
	accel_cal[0] = data->accelcal.x;
	accel_cal[1] = data->accelcal.y;
	accel_cal[2] = data->accelcal.z;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if(!msg)
		return -ENOMEM;

	msg->cmd = MSG2SSP_AP_MCU_SET_ACCEL_CAL;
	msg->length = 6;
	msg->options = AP2HUB_WRITE;
	msg->buffer = (char*) kzalloc(6, GFP_KERNEL);
	if(!(msg->buffer)){
		kfree(msg);
		return -ENOMEM;
	}
	msg->free_buffer = 1;
	memcpy(msg->buffer, accel_cal, 6);

	iRet = ssp_spi_async(data, msg);

	if (iRet != SUCCESS) {
		pr_err("[SSP]: %s - i2c fail %d\n", __func__, iRet);
		iRet = ERROR;
	}

	pr_info("[SSP] Set accel cal data %d, %d, %d\n", accel_cal[0], accel_cal[1], accel_cal[2]);
	return iRet;
}

static int enable_accel_for_cal(struct ssp_data *data)
{
	u8 uBuf[4] = { 0, };
	s32 dMsDelay = get_msdelay(data->adDelayBuf[ACCELEROMETER_SENSOR]);
	memcpy(&uBuf[0], &dMsDelay, 4);

	if (atomic_read(&data->aSensorEnable) & (1 << ACCELEROMETER_SENSOR)) {
		if (get_msdelay(data->adDelayBuf[ACCELEROMETER_SENSOR]) != 10) {
			send_instruction(data, CHANGE_DELAY,
				ACCELEROMETER_SENSOR, uBuf, 4);
			return SUCCESS;
		}
	} else {
		send_instruction(data, ADD_SENSOR,
			ACCELEROMETER_SENSOR, uBuf, 4);
	}

	return FAIL;
}

static void disable_accel_for_cal(struct ssp_data *data, int iDelayChanged)
{
	u8 uBuf[4] = { 0, };
	s32 dMsDelay = get_msdelay(data->adDelayBuf[ACCELEROMETER_SENSOR]);
	memcpy(&uBuf[0], &dMsDelay, 4);

	if (atomic_read(&data->aSensorEnable) & (1 << ACCELEROMETER_SENSOR)) {
		if (iDelayChanged)
			send_instruction(data, CHANGE_DELAY,
				ACCELEROMETER_SENSOR, uBuf, 4);
	} else {
		send_instruction(data, REMOVE_SENSOR,
			ACCELEROMETER_SENSOR, uBuf, 4);
	}
}

static int accel_do_calibrate(struct ssp_data *data, int iEnable)
{
	int iSum[3] = { 0, };
	int iRet = 0, iCount;
	struct file *cal_filp = NULL;
	mm_segment_t old_fs;

	if (iEnable) {
		data->accelcal.x = 0;
		data->accelcal.y = 0;
		data->accelcal.z = 0;
		set_accel_cal(data);

		iRet = enable_accel_for_cal(data);
		msleep(300);

		for (iCount = 0; iCount < CALIBRATION_DATA_AMOUNT; iCount++) {
			iSum[0] += data->buf[ACCELEROMETER_SENSOR].x;
			iSum[1] += data->buf[ACCELEROMETER_SENSOR].y;
			iSum[2] += data->buf[ACCELEROMETER_SENSOR].z;
			mdelay(10);
		}
		disable_accel_for_cal(data, iRet);

		data->accelcal.x = (iSum[0] / CALIBRATION_DATA_AMOUNT);
		data->accelcal.y = (iSum[1] / CALIBRATION_DATA_AMOUNT);
		data->accelcal.z = (iSum[2] / CALIBRATION_DATA_AMOUNT);

		if (data->accelcal.z > 0)
			data->accelcal.z -= MAX_ACCEL_1G;
		else if (data->accelcal.z < 0)
			data->accelcal.z += MAX_ACCEL_1G;
	} else {
		data->accelcal.x = 0;
		data->accelcal.y = 0;
		data->accelcal.z = 0;
	}

	ssp_dbg("[SSP]: do accel calibrate %d, %d, %d\n",
		data->accelcal.x, data->accelcal.y, data->accelcal.z);

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	cal_filp = filp_open(CALIBRATION_FILE_PATH,
			O_CREAT | O_TRUNC | O_WRONLY, 0660);
	if (IS_ERR(cal_filp)) {
		pr_err("[SSP]: %s - Can't open calibration file\n", __func__);
		set_fs(old_fs);
		iRet = PTR_ERR(cal_filp);
		return iRet;
	}

	iRet = cal_filp->f_op->write(cal_filp, (char *)&data->accelcal,
		3 * sizeof(int), &cal_filp->f_pos);
	if (iRet != 3 * sizeof(int)) {
		pr_err("[SSP]: %s - Can't write the accelcal to file\n",
			__func__);
		iRet = -EIO;
	}

	filp_close(cal_filp, current->files);
	set_fs(old_fs);
	set_accel_cal(data);
	return iRet;
}

static ssize_t accel_calibration_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int iRet;
	int iCount = 0;
	struct ssp_data *data = dev_get_drvdata(dev);

	iRet = accel_open_calibration(data);
	if (iRet < 0)
		pr_err("[SSP]: %s - calibration open failed(%d)\n", __func__, iRet);

	ssp_dbg("[SSP] Cal data : %d %d %d - %d\n",
		data->accelcal.x, data->accelcal.y, data->accelcal.z, iRet);

	iCount = sprintf(buf, "%d %d %d %d\n", iRet, data->accelcal.x,
			data->accelcal.y, data->accelcal.z);
	return iCount;
}

static ssize_t accel_calibration_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	int iRet;
	int64_t dEnable;
	struct ssp_data *data = dev_get_drvdata(dev);

	iRet = kstrtoll(buf, 10, &dEnable);
	if (iRet < 0)
		return iRet;

	iRet = accel_do_calibrate(data, (int)dEnable);
	if (iRet < 0)
		pr_err("[SSP]: %s - accel_do_calibrate() failed\n", __func__);

	return size;
}

static ssize_t raw_data_read(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ssp_data *data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d,%d,%d\n",
		data->buf[ACCELEROMETER_SENSOR].x,
		data->buf[ACCELEROMETER_SENSOR].y,
		data->buf[ACCELEROMETER_SENSOR].z);
}

static ssize_t accel_reactive_alert_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	int iRet = 0;
	char chTempBuf = 1;
	struct ssp_data *data = dev_get_drvdata(dev);

	struct ssp_msg *msg;

	if (sysfs_streq(buf, "1"))
		ssp_dbg("[SSP]: %s - on\n", __func__);
	else if (sysfs_streq(buf, "0"))
		ssp_dbg("[SSP]: %s - off\n", __func__);
	else if (sysfs_streq(buf, "2")) {
		ssp_dbg("[SSP]: %s - factory\n", __func__);

		data->bAccelAlert = 0;

		msg = kzalloc(sizeof(*msg), GFP_KERNEL);
		if (msg == NULL) {
			pr_err("[SSP] %s, failed to alloc memory for ssp_msg\n", __func__);
			goto exit;
		}
		msg->cmd = ACCELEROMETER_FACTORY;
		msg->length = 1;
		msg->options = AP2HUB_READ;
		msg->data = chTempBuf;
		msg->buffer = &chTempBuf;
		msg->free_buffer = 0;

		iRet = ssp_spi_sync(data, msg, 3000);
		data->bAccelAlert = chTempBuf;

		if (iRet != SUCCESS) {
			pr_err("[SSP]: %s - accel Selftest Timeout!!\n", __func__);
			goto exit;
		}

		ssp_dbg("[SSP]: %s factory test success!\n", __func__);
	} else {
		pr_err("[SSP]: %s - invalid value %d\n", __func__, *buf);
		return -EINVAL;
	}
exit:
	return size;
}

static ssize_t accel_reactive_alert_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	bool bSuccess = false;
	struct ssp_data *data = dev_get_drvdata(dev);

	if (data->bAccelAlert == true)
		bSuccess = true;
	else
		bSuccess = false;

	data->bAccelAlert = false;
	return sprintf(buf, "%u\n", bSuccess);
}

static ssize_t accel_hw_selftest_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	char chTempBuf[8] = { 2, 0, };
	s8 init_status = 0, result = -1;
	s16 shift_ratio[3] = { 0, };
	int iRet;
	struct ssp_data *data = dev_get_drvdata(dev);
	struct ssp_msg *msg;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (msg == NULL) {
		pr_err("[SSP] %s, failed to alloc memory for ssp_msg\n", __func__);
		goto exit;
	}
	msg->cmd = ACCELEROMETER_FACTORY;
	msg->length = 8;
	msg->options = AP2HUB_READ;
	msg->data = chTempBuf[0];
	msg->buffer = chTempBuf;
	msg->free_buffer = 0;

	iRet = ssp_spi_sync(data, msg, 3000);
	if (iRet != SUCCESS) {
		pr_err("[SSP] %s - accel hw selftest Timeout!!\n", __func__);
		goto exit;
	}

	init_status = chTempBuf[0];
	shift_ratio[0] = (s16)((chTempBuf[2] << 8) + chTempBuf[1]);
	shift_ratio[1] = (s16)((chTempBuf[4] << 8) + chTempBuf[3]);
	shift_ratio[2] = (s16)((chTempBuf[6] << 8) + chTempBuf[5]);
	result = chTempBuf[7];

	pr_info("[SSP] %s - %d, %d, %d, %d, %d\n", __func__,
		init_status, result, shift_ratio[0], shift_ratio[1], shift_ratio[2]);

	return sprintf(buf, "%d,%d.%d,%d.%d,%d.%d\n", result,
		shift_ratio[0] / 10, shift_ratio[0] % 10,
		shift_ratio[1] / 10, shift_ratio[1] % 10,
		shift_ratio[2] / 10, shift_ratio[2] % 10);
exit:
	return sprintf(buf, "%d,%d,%d,%d\n", -5, 0, 0, 0);
}


static DEVICE_ATTR(name, S_IRUGO, accel_name_show, NULL);
static DEVICE_ATTR(vendor, S_IRUGO, accel_vendor_show, NULL);
static DEVICE_ATTR(calibration, S_IRUGO | S_IWUSR | S_IWGRP,
	accel_calibration_show, accel_calibration_store);
static DEVICE_ATTR(raw_data, S_IRUGO, raw_data_read, NULL);
static DEVICE_ATTR(reactive_alert, S_IRUGO | S_IWUSR | S_IWGRP,
	accel_reactive_alert_show, accel_reactive_alert_store);
static DEVICE_ATTR(selftest, S_IRUGO, accel_hw_selftest_show, NULL);

static struct device_attribute *acc_attrs[] = {
	&dev_attr_name,
	&dev_attr_vendor,
	&dev_attr_calibration,
	&dev_attr_raw_data,
	&dev_attr_reactive_alert,
	&dev_attr_selftest,
	NULL,
};

void initialize_accel_factorytest(struct ssp_data *data)
{
	sensors_register(data->acc_device, data, acc_attrs,
		"accelerometer_sensor");
}

void remove_accel_factorytest(struct ssp_data *data)
{
	sensors_unregister(data->acc_device, acc_attrs);
}

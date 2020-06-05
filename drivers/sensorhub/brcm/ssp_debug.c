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
#include "ssp.h"
#include <linux/fs.h>
#include <linux/sec_debug.h>
#include <linux/iio/iio.h>
#include <linux/iio/buffer.h>

//#define SSP_DEBUG_TIMER_SEC		(5 * HZ)

#define LIMIT_RESET_CNT			40
#define LIMIT_TIMEOUT_CNT		3

#define DUMP_FILE_PATH "/data/log/MCU_DUMP"

void ssp_dump_task(struct work_struct *work)
{
#ifdef CONFIG_SENSORS_SSP_BBD
	pr_err("[SSPBBD]:TODO:%s()\n", __func__);
#else

	struct ssp_big *big;
	struct file *dump_file;
	struct ssp_msg *msg;
	char *buffer;
	char strFilePath[60];
	struct timeval cur_time;
	int iTimeTemp;
	mm_segment_t fs;
	int buf_len, packet_len, residue;
	int iRet = 0, index = 0, iRetTrans = 0, iRetWrite = 0;

	big = container_of(work, struct ssp_big, work);
	pr_err("[SSP]: %s - start ssp dumping (%d)(%d)\n",
		__func__, big->data->bMcuDumpMode, big->data->uDumpCnt);
	big->data->uDumpCnt++;
	wake_lock(&big->data->ssp_wake_lock);

	fs = get_fs();
	set_fs(get_ds());

	if (big->data->bMcuDumpMode == true) {
		do_gettimeofday(&cur_time);
		iTimeTemp = (int) cur_time.tv_sec;

		sprintf(strFilePath, "%s%d.txt", DUMP_FILE_PATH, iTimeTemp);

		dump_file = filp_open(strFilePath,
				O_RDWR|O_CREAT|O_APPEND, 0660);
		if (IS_ERR(dump_file)) {
			pr_err("[SSP]: %s - Can't open dump file\n", __func__);
			set_fs(fs);
			iRet = PTR_ERR(dump_file);
			wake_unlock(&big->data->ssp_wake_lock);
			kfree(big);
			return;
		}
	} else
		dump_file = NULL;

	buf_len = (big->length > DATA_PACKET_SIZE) ?
			DATA_PACKET_SIZE : big->length;
	buffer = kzalloc(buf_len, GFP_KERNEL);
	residue = big->length;

	while (residue > 0) {
		packet_len = residue > DATA_PACKET_SIZE ?
				DATA_PACKET_SIZE : residue;

		msg = kzalloc(sizeof(*msg), GFP_KERNEL);
		msg->cmd = MSG2SSP_AP_GET_BIG_DATA;
		msg->length = packet_len;
		msg->options = AP2HUB_READ | (index++ << SSP_INDEX);
		msg->data = big->addr;
		msg->buffer = buffer;
		msg->free_buffer = 0;

		iRetTrans = ssp_spi_sync(big->data, msg, 1000);
		if (iRetTrans != SUCCESS) {
			pr_err("[SSP]: %s - Fail to receive data %d (%d)\n",
				__func__, iRetTrans, residue);
			break;
		}
		if (big->data->bMcuDumpMode == true) {
			iRetWrite = vfs_write(dump_file,
					(char __user *) buffer,
					packet_len,
					&dump_file->f_pos);
			if (iRetWrite < 0) {
				pr_err("[SSP] %s Can't write dump to file\n",
					__func__);
				break;
			}
		}
		residue -= packet_len;
	}

	if (big->data->bMcuDumpMode == true &&
		(iRetTrans != SUCCESS || iRetWrite < 0)) {

		char FAILSTRING[100];

		sprintf(FAILSTRING, "FAIL OCCURED(%d)(%d)(%d)",
			iRetTrans,
			iRetWrite,
			big->length);
		vfs_write(dump_file, (char __user *) FAILSTRING,
			strlen(FAILSTRING),
			&dump_file->f_pos);
	}

	big->data->bDumping = false;
	if (big->data->bMcuDumpMode == true)
		filp_close(dump_file, current->files);

	set_fs(fs);

	wake_unlock(&big->data->ssp_wake_lock);
	kfree(buffer);
	kfree(big);

	pr_err("[SSP]: %s done\n", __func__);
#endif
}

void ssp_temp_task(struct work_struct *work)
{
#ifdef CONFIG_SENSORS_SSP_BBD
	pr_err("[SSPBBD]:TODO:%s()\n", __func__);
#else
	struct ssp_big *big;
	struct ssp_msg *msg;
	char *buffer;
	int buf_len, packet_len, residue;
	int iRet = 0, index = 0, i = 0, buffindex = 0;

	big = container_of(work, struct ssp_big, work);
	buf_len = big->length > DATA_PACKET_SIZE ?
		DATA_PACKET_SIZE : big->length;
	buffer = kzalloc(buf_len, GFP_KERNEL);
	residue = big->length;
#ifdef CONFIG_SENSORS_SSP_SHTC1
	mutex_lock(&big->data->bulk_temp_read_lock);
	if (big->data->bulk_buffer == NULL)
		big->data->bulk_buffer = kzalloc(sizeof(struct shtc1_buffer),
				GFP_KERNEL);
	big->data->bulk_buffer->len = big->length / 12;
#endif
	while (residue > 0) {
		packet_len = (residue > DATA_PACKET_SIZE) ?
				DATA_PACKET_SIZE : residue;

		msg = kzalloc(sizeof(*msg), GFP_KERNEL);
		msg->cmd = MSG2SSP_AP_GET_BIG_DATA;
		msg->length = packet_len;
		msg->options = AP2HUB_READ | (index++ << SSP_INDEX);
		msg->data = big->addr;
		msg->buffer = buffer;
		msg->free_buffer = 0;

		iRet = ssp_spi_sync(big->data, msg, 1000);
		if (iRet != SUCCESS) {
			pr_err("[SSP]: %s - Fail to receive data %d\n",
				__func__, iRet);
			break;
		}
		/* 12 = 1 chunk size for ks79.shin
		 * order is thermistor Bat, thermistor PA, Temp,
		 * Humidity, Baro, Gyro
		 * each data consist of 2bytes
		 */
		i = 0;
		while (packet_len - i >= 12) {
			ssp_dbg("[SSP]: %s %d %d %d %d %d %d", __func__,
					*((s16 *) (buffer + i + 0)), *((s16 *) (buffer + i + 2)),
					*((s16 *) (buffer + i + 4)), *((s16 *) (buffer + i + 6)),
					*((s16 *) (buffer + i + 8)), *((s16 *) (buffer + i + 10)));
#ifdef CONFIG_SENSORS_SSP_SHTC1
			big->data->bulk_buffer->batt[buffindex] = *((u16 *) (buffer + i + 0));
			big->data->bulk_buffer->chg[buffindex] = *((u16 *) (buffer + i + 2));
			big->data->bulk_buffer->temp[buffindex] = *((s16 *) (buffer + i + 4));
			big->data->bulk_buffer->humidity[buffindex] = *((u16 *) (buffer + i + 6));
			big->data->bulk_buffer->baro[buffindex] = *((s16 *) (buffer + i + 8));
			big->data->bulk_buffer->gyro[buffindex] = *((s16 *) (buffer + i + 10));
			buffindex++;
			i += 12;
#else
			buffindex++;
			i += 12;/* 6 ?? */
#endif
		}

		residue -= packet_len;
	}
#ifdef CONFIG_SENSORS_SSP_SHTC1
	if (iRet == SUCCESS)
		report_bulk_comp_data(big->data);
	mutex_unlock(&big->data->bulk_temp_read_lock);
#endif
	kfree(buffer);
	kfree(big);
	ssp_dbg("[SSP]: %s done\n", __func__);
#endif
}

/*************************************************************************/
/* SSP Debug timer function                                              */
/*************************************************************************/
int print_mcu_debug(char *pchRcvDataFrame, int *pDataIdx,
		int iRcvDataFrameLength)
{
	int iLength = 0;
	int cur = *pDataIdx;
#if ANDROID_VERSION < 80000
	iLength = pchRcvDataFrame[(*pDataIdx)++];
#else
	memcpy(&iLength, pchRcvDataFrame + *pDataIdx, sizeof(u16));
	*pDataIdx += sizeof(u16);
#endif

	if (iLength > iRcvDataFrameLength - *pDataIdx || iLength <= 0) {
		ssp_dbg("[SSP]: MSG From MCU - invalid debug length(%d/%d/%d)\n",
			iLength, iRcvDataFrameLength, cur);
		return iLength ? iLength : ERROR;
	}

	ssp_dbg("[SSP]: MSG From MCU - %s\n", &pchRcvDataFrame[*pDataIdx]);
	*pDataIdx += iLength;
	return 0;
}

void reset_mcu(struct ssp_data *data)
{
	func_dbg();

	ssp_enable(data, false);
	clean_pending_list(data);
	bbd_mcu_reset();

	data->uTimeOutCnt = 0;
	data->uComFailCnt = 0;
	data->mcuAbnormal = false;
}

void sync_sensor_state(struct ssp_data *data)
{
	unsigned char uBuf[9] = {0,};
	unsigned int uSensorCnt;
	int iRet = 0;

	gyro_open_calibration(data);
	iRet = set_gyro_cal(data);
	if (iRet < 0)
		pr_err("[SSP]: %s - set_gyro_cal failed\n", __func__);

	iRet = set_accel_cal(data);
	if (iRet < 0)
		pr_err("[SSP]: %s - set_accel_cal failed\n", __func__);

#ifdef CONFIG_SENSORS_SSP_SX9306
	if (atomic64_read(&data->aSensorEnable) & (1 << GRIP_SENSOR)) {
		open_grip_caldata(data);
		set_grip_calibration(data, true);
	}
#endif

	udelay(10);

	for (uSensorCnt = 0; uSensorCnt < SENSOR_MAX; uSensorCnt++) {
		mutex_lock(&data->enable_mutex);
		if (atomic64_read(&data->aSensorEnable) & (1ULL << uSensorCnt)) {
			s32 dMsDelay =
				get_msdelay(data->adDelayBuf[uSensorCnt]);
			memcpy(&uBuf[0], &dMsDelay, 4);
			memcpy(&uBuf[4], &data->batchLatencyBuf[uSensorCnt], 4);
			uBuf[8] = data->batchOptBuf[uSensorCnt];
			send_instruction(data, ADD_SENSOR, uSensorCnt, uBuf, 9);
			udelay(10);
		}
		mutex_unlock(&data->enable_mutex);
	}

        if (atomic64_read(&data->aSensorEnable) & (1ULL << GYROSCOPE_SENSOR))
                send_vdis_flag(data, data->IsVDIS_Enabled);

	if (data->bProximityRawEnabled == true) {
		s32 dMsDelay = 20;

		memcpy(&uBuf[0], &dMsDelay, 4);
		send_instruction(data, ADD_SENSOR, PROXIMITY_RAW, uBuf, 4);
	}

	set_proximity_threshold(data);
	set_light_coef(data);
#if ANDROID_VERSION < 80000
	set_gyro_cal_lib_enable(data, true);
#endif
	data->bMcuDumpMode = ssp_check_sec_dump_mode();
	iRet = ssp_send_cmd(data, MSG2SSP_AP_MCU_SET_DUMPMODE,
		data->bMcuDumpMode);
	if (iRet < 0)
		pr_err("[SSP]: %s - MSG2SSP_AP_MCU_SET_DUMPMODE failed\n",
			__func__);
}

/*
	check_sensor_event
	- return 
		true : there is no accel or light sensor event over 5sec when sensor is registered
*/
bool check_wait_event(struct ssp_data *data)
{
	u64 timestamp = get_current_timestamp();
	int check_sensors[2] = {ACCELEROMETER_SENSOR, LIGHT_SENSOR};
	int i, sensor; 
	bool res = false;
	
	for(i = 0 ; i < 2 ; i++)
	{
		sensor = check_sensors[i];
		//the sensor is registered
		if((atomic64_read(&data->aSensorEnable) & (1 << sensor))
			//non batching mode
			&& data->IsBypassMode[sensor] == 1
			//there is no sensor event over 3sec
			&& data->LastSensorTimeforReset[sensor] + 7000000000ULL < timestamp) {
			pr_info("[SSP] %s - sensor(%d) last = %lld, cur = %lld\n",
				__func__,sensor,data->LastSensorTimeforReset[sensor],timestamp);
			res = true;
			data->uNoRespSensorCnt++;
		}
		//pr_info("[SSP]test %s - sensor(%d mode %d) last = %lld, cur = %lld\n",
		//__func__,sensor,data->IsBypassMode[sensor],data->LastSensorTimeforReset[sensor],timestamp);
	}

	return res;
}

static void debug_timer_func(unsigned long ptr)
{
	struct ssp_data *data = (struct ssp_data *)ptr;

	queue_work(data->debug_wq, &data->work_debug);
}

void enable_debug_timer(struct ssp_data *data)
{
}

void disable_debug_timer(struct ssp_data *data)
{
}

int initialize_debug_timer(struct ssp_data *data)
{
	return 0;   
}

/* if returns true dump mode on */
unsigned int ssp_check_sec_dump_mode(void)
{
#if 0 /* def CONFIG_SEC_DEBUG */
	if (sec_debug_level.en.kernel_fault == 1)
		return 1;
	else
		return 0;
#endif
	return 0;
}

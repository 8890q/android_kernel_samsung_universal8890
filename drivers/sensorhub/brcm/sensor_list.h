/*
 *  Copyright (C) 2015, Samsung Electronics Co. Ltd. All Rights Reserved.
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

#ifndef __SSP_SENSORS_H__
#define __SSP_SENSORS_H__
#define SENSOR_NAME_MAX_LEN		35

/* Magnetic Read Size */
#ifdef CONFIG_SSP_SUPPORT_MAGNETIC_OVERFLOW
    #define UNCAL_MAGNETIC_SIZE     13
    #define MAGNETIC_SIZE           8
#else
    #define UNCAL_MAGNETIC_SIZE     12
    #define MAGNETIC_SIZE           7
#endif

/* SENSOR_TYPE */
enum {
	ACCELEROMETER_SENSOR = 0,
	GYROSCOPE_SENSOR,
	GEOMAGNETIC_UNCALIB_SENSOR,
	GEOMAGNETIC_RAW,
	GEOMAGNETIC_SENSOR,
	PRESSURE_SENSOR,
	GESTURE_SENSOR,
	PROXIMITY_SENSOR,
	TEMPERATURE_HUMIDITY_SENSOR,
	LIGHT_SENSOR,
	PROXIMITY_RAW,
#ifdef CONFIG_SENSORS_SSP_SX9306
	GRIP_SENSOR,
	ORIENTATION_SENSOR,
#else
	ORIENTATION_SENSOR = 12,
#endif
	STEP_DETECTOR = 13,
	SIG_MOTION_SENSOR,
	GYRO_UNCALIB_SENSOR,
	GAME_ROTATION_VECTOR = 16,
	ROTATION_VECTOR,
	STEP_COUNTER,
	BIO_HRM_RAW,
	BIO_HRM_RAW_FAC,
	BIO_HRM_LIB,
	SHAKE_CAM = 23,
#ifdef CONFIG_SENSORS_SSP_IRDATA_FOR_CAMERA
	LIGHT_IR_SENSOR = 24,
#endif
#ifdef CONFIG_SENSORS_SSP_INTERRUPT_GYRO_SENSOR
	INTERRUPT_GYRO_SENSOR = 25,
#endif
	TILT_DETECTOR,
	PICKUP_GESTURE,
	BULK_SENSOR,
	GPS_SENSOR,
	PROXIMITY_ALERT_SENSOR,
	LIGHT_FLICKER_SENSOR,
#if ANDROID_VERSION >= 80000
	LIGHT_CCT_SENSOR,
	ACCEL_UNCALIB_SENSOR = 33,
#endif
	SENSOR_MAX,
#ifdef CONFIG_SENSORS_SSP_HIFI_BATCHING
	META_SENSOR = 200,
#endif
};

/* Sensors's reporting mode */
#define REPORT_MODE_CONTINUOUS	0
#define REPORT_MODE_ON_CHANGE	1
#define REPORT_MODE_SPECIAL	2
#define REPORT_MODE_UNKNOWN	3

#define SCONTEXT_DATA_SIZE		72

struct sensor_info {
	char *name;
	int type;
	bool enable;
	int report_mode;
	int get_data_len;
	int report_data_len;
};

#define SENSOR_INFO_UNKNOWN			{"", -1, false,	REPORT_MODE_UNKNOWN, 0, 0}
#define SENSOR_INFO_ACCELEROMETER		{"accelerometer_sensor", ACCELEROMETER_SENSOR, true, REPORT_MODE_CONTINUOUS, 6, 6}
#define SENSOR_INFO_GEOMAGNETIC			{"geomagnetic_sensor", GEOMAGNETIC_SENSOR, true, REPORT_MODE_CONTINUOUS, MAGNETIC_SIZE, MAGNETIC_SIZE}
#define SENSOR_INFO_GEOMAGNETIC_POWER		{"geomagnetic_power", GEOMAGNETIC_RAW, false, REPORT_MODE_CONTINUOUS, 6, 0}
#define SENSOR_INFO_GEOMAGNETIC_UNCAL		{"uncal_geomagnetic_sensor", GEOMAGNETIC_UNCALIB_SENSOR, true, REPORT_MODE_CONTINUOUS, UNCAL_MAGNETIC_SIZE, UNCAL_MAGNETIC_SIZE}
#define SENSOR_INFO_GYRO			{"gyro_sensor", GYROSCOPE_SENSOR, true, REPORT_MODE_CONTINUOUS, 12, 12}
#define SENSOR_INFO_GYRO_UNCALIBRATED		{"uncal_gyro_sensor", GYRO_UNCALIB_SENSOR, true, REPORT_MODE_CONTINUOUS, 24, 24}
#define SENSOR_INFO_INTERRUPT_GYRO		{"interrupt_gyro_sensor", INTERRUPT_GYRO_SENSOR, true, REPORT_MODE_ON_CHANGE, 12, 12}
#define SENSOR_INFO_PRESSURE			{"pressure_sensor", PRESSURE_SENSOR, true, REPORT_MODE_CONTINUOUS, 6, 12}
#define SENSOR_INFO_LIGHT			{"light_sensor", LIGHT_SENSOR, true, REPORT_MODE_ON_CHANGE, 18, 18}
#define SENSOR_INFO_LIGHT_IR			{"light_ir_sensor", LIGHT_IR_SENSOR, true, REPORT_MODE_ON_CHANGE, 12, 12}
#define SENSOR_INFO_LIGHT_FLICKER		{"light_flicker_sensor", LIGHT_FLICKER_SENSOR, true, REPORT_MODE_ON_CHANGE, 2, 2}
#define SENSOR_INFO_LIGHT_CCT			{"light_cct_sensor", LIGHT_CCT_SENSOR, true, REPORT_MODE_ON_CHANGE, 18, 18}
#define SENSOR_INFO_PROXIMITY			{"proximity_sensor", PROXIMITY_SENSOR, true, REPORT_MODE_ON_CHANGE, 3, 1}
#define SENSOR_INFO_PROXIMITY_ALERT		{"proximity_alert_sensor", PROXIMITY_ALERT_SENSOR, true, REPORT_MODE_ON_CHANGE, 3, 1}
#define SENSOR_INFO_PROXIMITY_RAW		{"proximity_raw", PROXIMITY_RAW, false, REPORT_MODE_ON_CHANGE, 1, 0}
#define SENSOR_INFO_ROTATION_VECTOR		{"rotation_vector_sensor", ROTATION_VECTOR, true, REPORT_MODE_CONTINUOUS, 17, 17}
#define SENSOR_INFO_GAME_ROTATION_VECTOR	{"game_rotation_vector", GAME_ROTATION_VECTOR, true, REPORT_MODE_CONTINUOUS, 17, 17}
#define SENSOR_INFO_SIGNIFICANT_MOTION		{"sig_motion_sensor", SIG_MOTION_SENSOR, true, REPORT_MODE_SPECIAL, 1, 1}
#define SENSOR_INFO_STEP_DETECTOR		{"step_det_sensor", STEP_DETECTOR, true, REPORT_MODE_ON_CHANGE, 1, 1}
#define SENSOR_INFO_STEP_COUNTER		{"step_cnt_sensor", STEP_COUNTER, true, REPORT_MODE_ON_CHANGE, 4, 8}
#define SENSOR_INFO_TILT_DETECTOR		{"tilt_detector", TILT_DETECTOR, true, REPORT_MODE_ON_CHANGE, 1, 1}
#define SENSOR_INFO_PICK_UP_GESTURE		{"pickup_gesture", PICKUP_GESTURE, true, REPORT_MODE_CONTINUOUS, 1, 1}
#define SENSOR_INFO_SCONTEXT			{"scontext_iio", META_SENSOR+1, true, REPORT_MODE_CONTINUOUS, 0, 64}
#if ANDROID_VERSION >= 80000
#define SENSOR_INFO_ACCEL_UNCALIBRATED		{"uncal_accel_sensor", ACCEL_UNCALIB_SENSOR, true, REPORT_MODE_CONTINUOUS, 12, 12}
#endif
#define SENSOR_INFO_META			{"meta_event", META_SENSOR, true, REPORT_MODE_CONTINUOUS, 8, 8}

#endif

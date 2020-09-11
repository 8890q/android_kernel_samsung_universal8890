/*
 * Wacom Penabled Driver for I2C
 *
 * Copyright (c) 2011-2014 Tatsunosuke Tobita, Wacom.
 * <tobita.tatsunosuke@wacom.co.jp>
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software
 * Foundation; either version of 2 of the License,
 * or (at your option) any later version.
 */
#include "wacom.h"
#include "wacom_i2c_func.h"
#include "wacom_i2c_firm.h"
#include "w9014_flash.h"

#if 0
int wacom_i2c_master_send(struct i2c_client *client,const char *buf ,int count, unsigned char addr)
{
        int ret;
        struct i2c_adapter *adap=client->adapter;
        struct i2c_msg msg;

        msg.addr = addr;
        msg.flags = client->flags & I2C_M_TEN;
        msg.len = count;
        msg.buf = (char *)buf;

        ret = i2c_transfer(adap, &msg, 1);

        /* If everything went ok (i.e. 1 msg transmitted), return #bytes
           transmitted, else error code. */
        return (ret == 1) ? count : ret;
}

int wacom_i2c_master_recv(struct i2c_client *client, const char *buf ,int count, unsigned char addr)
{
        int ret;
        struct i2c_adapter *adap=client->adapter;
        struct i2c_msg msg;

        msg.addr = addr;
        msg.flags = client->flags & I2C_M_TEN;
        msg.flags |= I2C_M_RD;
        msg.len = count;
        msg.buf = (char *)buf;

        ret = i2c_transfer(adap, &msg, 1);

        /* If everything went ok (i.e. 1 msg transmitted), return #bytes
           transmitted, else error code. */
        return (ret == 1) ? count : ret;
}
#endif

bool wacom_i2c_set_feature(struct wacom_i2c *wac_i2c, u8 report_id, unsigned int buf_size, u8 *data,
			   u16 cmdreg, u16 datareg)
{
	int i, ret = -1;
	int total = SFEATURE_SIZE + buf_size;
	u8 *sFeature = NULL;
	bool bRet = false;

	sFeature = kzalloc(sizeof(u8) * total, GFP_KERNEL);
	if (!sFeature) {
		printk(KERN_DEBUG"%s cannot preserve memory \n", __func__);
		goto out;
	}
	memset(sFeature, 0, sizeof(u8) * total);

	sFeature[0] = (u8)(cmdreg & 0x00ff);
	sFeature[1] = (u8)((cmdreg & 0xff00) >> 8);
	sFeature[2] = (RTYPE_FEATURE << 4) | report_id;
	sFeature[3] = CMD_SET_FEATURE;
	sFeature[4] = (u8)(datareg & 0x00ff);
	sFeature[5] = (u8)((datareg & 0xff00) >> 8);

	if ( (buf_size + 2) > 255) {
		sFeature[6] = (u8)((buf_size + 2) & 0x00ff);
		sFeature[7] = (u8)(( (buf_size + 2) & 0xff00) >> 8);
	} else {
		sFeature[6] = (u8)(buf_size + 2);
		sFeature[7] = (u8)(0x00);
	}

	for (i = 0; i < buf_size; i++)
		sFeature[i + SFEATURE_SIZE] = *(data + i);

//	ret = wacom_i2c_master_send(client, sFeature, total, WACOM_FLASH_W9014);
	ret = wacom_i2c_send(wac_i2c, sFeature, total, WACOM_I2C_MODE_BOOT);
	if (ret != total) {
		printk(KERN_DEBUG "Sending Set_Feature failed sent bytes: %d \n", ret);
		goto err;
	}

	usleep_range(60, 61);
	bRet = true;
 err:
	kfree(sFeature);
	sFeature = NULL;

 out:
	return bRet;
}

bool wacom_i2c_get_feature(struct wacom_i2c *wac_i2c, u8 report_id, unsigned int buf_size, u8 *data,
			   u16 cmdreg, u16 datareg, int delay)
{
	int ret = -1;
	u8 *recv = NULL;
	bool bRet = false;
	u8 gFeature[] = {
		(u8)(cmdreg & 0x00ff),
		(u8)((cmdreg & 0xff00) >> 8),
		(RTYPE_FEATURE << 4) | report_id,
		CMD_GET_FEATURE,
		(u8)(datareg & 0x00ff),
		(u8)((datareg & 0xff00) >> 8)
	};

	/*"+ 2", adding 2 more spaces for organizeing again later in the passed data, "data"*/
	recv = kzalloc(sizeof(u8) * (buf_size + 0), GFP_KERNEL);
	if (!recv) {
		printk(KERN_DEBUG"%s cannot preserve memory \n", __func__);
		goto out;
	}

	memset(recv, 0, sizeof(u8) * (buf_size + 0)); /*Append 2 bytes for length low and high of the byte*/

//	ret = wacom_i2c_master_send(client, gFeature, GFEATURE_SIZE, WACOM_FLASH_W9014);
	ret = wacom_i2c_send(wac_i2c, gFeature, GFEATURE_SIZE, WACOM_I2C_MODE_BOOT);
	if (ret != GFEATURE_SIZE) {
		printk(KERN_DEBUG"%s Sending Get_Feature failed; sent bytes: %d \n", __func__, ret);
		goto err;
	}

	udelay(delay);

//	ret = wacom_i2c_master_recv(client, recv, (buf_size), WACOM_FLASH_W9014);
	ret = wacom_i2c_recv(wac_i2c, recv, buf_size,WACOM_I2C_MODE_BOOT);
	if (ret != buf_size) {
		printk(KERN_DEBUG"%s Receiving data failed; recieved bytes: %d \n", __func__, ret);
		goto err;
	}

	/*Coppy data pointer, subtracting the first two bytes of the length*/
	memcpy(data, (recv + 0), buf_size);

	bRet = true;
 err:
	kfree(recv);
	recv = NULL;

 out:
	return bRet;
}

static int wacom_flash_cmd(struct wacom_i2c *wac_i2c)
{
	u8 command[10];
	int len = 0;
	int ret = -1;

	command[len++] = 0x0d;
	command[len++] = FLASH_START0;
	command[len++] = FLASH_START1;
	command[len++] = FLASH_START2;
	command[len++] = FLASH_START3;
	command[len++] = FLASH_START4;
	command[len++] = FLASH_START5;
	command[len++] = 0x0d;

//	ret = i2c_master_send(wac_i2c->client, command, len);
	ret = wacom_i2c_send(wac_i2c, command, len, WACOM_I2C_MODE_BOOT);
	if(ret < 0){
		printk("Sending flash command failed\n");
		return -EXIT_FAIL;
	}

	msleep(300);

	return 0;
}

int flash_query_w9014(struct wacom_i2c *wac_i2c)
{
	bool bRet = false;
	u8 command[CMD_SIZE];
	u8 response[RSP_SIZE];
	int ECH, len = 0;

	command[len++] = BOOT_CMD_REPORT_ID;	                /* Report:ReportID */
	command[len++] = BOOT_QUERY;				/* Report:Boot Query command */
	command[len++] = ECH = 7;				/* Report:echo */

	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, len, command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	bRet = wacom_i2c_get_feature(wac_i2c, REPORT_ID_2, RSP_SIZE, response, COMM_REG, DATA_REG, (10 * 1000));
	if (!bRet) {
		printk("%s failed to get feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	if ( (response[3] != QUERY_CMD) ||
	     (response[4] != ECH) ) {
		printk("%s res3:%x res4:%x \n", __func__, response[3], response[4]);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	if (response[5] != QUERY_RSP) {
		printk("%s res5:%x \n", __func__, response[5]);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	printk("QUERY SUCCEEDED \n");
	return 0;
}

static bool flash_blver_w9014(struct wacom_i2c *wac_i2c, int *blver)
{
	bool bRet = false;
	u8 command[CMD_SIZE];
	u8 response[RSP_SIZE];
	int ECH, len = 0;

	command[len++] = BOOT_CMD_REPORT_ID;	/* Report:ReportID */
	command[len++] = BOOT_BLVER;					/* Report:Boot Version command */
	command[len++] = ECH = 7;							/* Report:echo */

	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, len, command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature1\n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	bRet = wacom_i2c_get_feature(wac_i2c, REPORT_ID_2, RSP_SIZE, response, COMM_REG, DATA_REG, (10 * 1000));
	if (!bRet) {
		printk("%s 2 failed to set feature\n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	if ( (response[3] != BOOT_CMD) ||
	     (response[4] != ECH) ) {
		printk("%s res3:%x res4:%x \n", __func__, response[3], response[4]);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	if (response[5] != QUERY_RSP) {
		printk("%s res5:%x \n", __func__, response[5]);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	*blver = (int)response[5];

	return true;
}

static bool flash_mputype_w9014(struct wacom_i2c *wac_i2c, int* pMpuType)
{
	bool bRet = false;
	u8 command[CMD_SIZE];
	u8 response[RSP_SIZE];
	int ECH, len = 0;

	command[len++] = BOOT_CMD_REPORT_ID;	                        /* Report:ReportID */
	command[len++] = BOOT_MPU;					/* Report:Boot Query command */
	command[len++] = ECH = 7;					/* Report:echo */

	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, len, command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	bRet = wacom_i2c_get_feature(wac_i2c, REPORT_ID_2, RSP_SIZE, response, COMM_REG, DATA_REG, (10 * 1000));
	if (!bRet) {
		printk("%s failed to get feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	if ( (response[3] != MPU_CMD) ||
	     (response[4] != ECH) ) {
		printk("%s res3:%x res4:%x \n", __func__, response[3], response[4]);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	*pMpuType = (int)response[5];
	return true;
}

static bool flash_end_w9014(struct wacom_i2c *wac_i2c)
{
	bool bRet = false;
	u8 command[CMD_SIZE];
	int ECH, len = 0;

	command[len++] = BOOT_CMD_REPORT_ID;
	command[len++] = BOOT_EXIT;
	command[len++] = ECH = 7;

	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, len, command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature 1\n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	return true;
}

static bool flash_erase_all(struct wacom_i2c *wac_i2c)
{
	bool bRet = false;
	u8 command[BOOT_CMD_SIZE];
	u8 response[BOOT_RSP_SIZE];
	int i, len = 0;
	int ECH, sum = 0;

	command[len++] = 7;
	command[len++] = 16;
	command[len++] = ECH = 2;
	command[len++] = 3;

	/*Preliminarily store the data that cannnot appear here, but in wacom_set_feature()*/
	sum += 0x05;
	sum += 0x07;
	for (i = 0; i < len; i++)
		sum += command[i];

	command[len++] = ~sum + 1;

	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, len, command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	do {


		bRet = wacom_i2c_get_feature(wac_i2c, REPORT_ID_2, BOOT_RSP_SIZE, response, COMM_REG, DATA_REG, 0);
		if (!bRet) {
			printk("%s failed to set feature \n", __func__);
			return -EXIT_FAIL_SEND_QUERY_COMMAND;
		}
		if (!(response[3] & 0x10) || !(response[4] & ECH) ||
		    (!(response[5] & 0xff) && response[5] & 0x00)) {
			printk("%s failing 4 resp1: %x resp2: %x resp3: %x \n",
			       __func__, response[3], response[4], response[5]);
			return false;
		}

		mdelay(200);

	} while(response[3] == 0x10 && response[4] == ECH && response[5] == 0xff);

	return true;
}

static bool flash_write_block_w9014(struct wacom_i2c *wac_i2c, char *flash_data,
				    unsigned long ulAddress, u8 *pcommand_id, int *ECH)
{
	const int MAX_COM_SIZE = (8 + FLASH_BLOCK_SIZE + 2); //8: num of command[0] to command[7]
                                                              //FLASH_BLOCK_SIZE: unit to erase the block
                                                              //Num of Last 2 checksums
	bool bRet = false;
	u8 command[300];
	unsigned char sum = 0;
	int i;

	command[0] = BOOT_CMD_REPORT_ID;	                /* Report:ReportID */
	command[1] = BOOT_WRITE_FLASH;			        /* Report:program  command */
	command[2] = *ECH = ++(*pcommand_id);		        /* Report:echo */
	command[3] = ulAddress & 0x000000ff;
	command[4] = (ulAddress & 0x0000ff00) >> 8;
	command[5] = (ulAddress & 0x00ff0000) >> 16;
	command[6] = (ulAddress & 0xff000000) >> 24;			/* Report:address(4bytes) */
	command[7] = 8;						/* Report:size(8*8=64) */

	/*Preliminarily store the data that cannnot appear here, but in wacom_set_feature()*/
	sum = 0;
	sum += 0x05;
	sum += 0x4c;
	for (i = 0; i < 8; i++)
		sum += command[i];
	command[MAX_COM_SIZE - 2] = ~sum + 1;					/* Report:command checksum */

	sum = 0;
	for (i = 8; i < (FLASH_BLOCK_SIZE + 8); i++){
		command[i] = flash_data[ulAddress+(i - 8)];
		sum += flash_data[ulAddress+(i - 8)];
	}

	command[MAX_COM_SIZE - 1] = ~sum+1;				/* Report:data checksum */

	/*Subtract 8 for the first 8 bytes*/
	bRet = wacom_i2c_set_feature(wac_i2c, REPORT_ID_1, (BOOT_CMD_SIZE + 4 - 8), command, COMM_REG, DATA_REG);
	if (!bRet) {
		printk("%s failed to set feature \n", __func__);
		return -EXIT_FAIL_SEND_QUERY_COMMAND;
	}

	udelay(50);

	return true;
}

static bool flash_write_w9014(struct wacom_i2c *wac_i2c, unsigned char *flash_data,
			      unsigned long start_address, unsigned long *max_address)
{
	bool bRet = false;
	u8 command_id = 0;
	u8 response[BOOT_RSP_SIZE];
	int i, j, ECH = 0, ECH_len = 0;
	int ECH_ARRAY[3];
	unsigned long ulAddress;

	j = 0;
	for (ulAddress = start_address; ulAddress < *max_address; ulAddress += FLASH_BLOCK_SIZE) {
		for (i = 0; i < FLASH_BLOCK_SIZE; i++) {
			if (flash_data[ulAddress+i] != 0xFF)
				break;
		}
		if (i == (FLASH_BLOCK_SIZE))
			continue;

		/* for debug */
		//printk(KERN_DEBUG"epen:write data %#x\n", (unsigned int)ulAddress);

		bRet = flash_write_block_w9014(wac_i2c, flash_data, ulAddress, &command_id, &ECH);
		if(!bRet)
			return false;
		if (ECH_len == 3)
			ECH_len = 0;

		ECH_ARRAY[ECH_len++] = ECH;
		if (ECH_len == 3) {
			for (j = 0; j < 3; j++) {
				do {

					bRet = wacom_i2c_get_feature(wac_i2c, REPORT_ID_2, BOOT_RSP_SIZE, response, COMM_REG, DATA_REG, 50);
					if (!bRet) {
						printk("%s failed to set feature \n", __func__);
						return -EXIT_FAIL_SEND_QUERY_COMMAND;
					}

					if ((response[3] != 0x01 || response[4] != ECH_ARRAY[j]) || (response[5] != 0xff && response[5] != 0x00)) {
						printk("%s mismatched echo array \n", __func__);
//						printk("addr: %x res:%x \n", ulAddress, response[5]);
						return false;
					}
				} while (response[3] == 0x01 && response[4] == ECH_ARRAY[j] && response[5] == 0xff);
			}
		}
	}
	return true;
}

int wacom_i2c_flash_w9014(struct wacom_i2c *wac_i2c, unsigned char *fw_data)
{
	bool bRet = false;
	int result, i;
	int eraseBlock[200], eraseBlockNum;
	int iBLVer = 0, iMpuType = 0;
	unsigned long max_address = 0;			/* Max.address of Load data */
	unsigned long start_address = 0x2000;	        /* Start.address of Load data */

	/*Obtain boot loader version*/
	if (!flash_blver_w9014(wac_i2c, &iBLVer)) {
		printk("%s failed to get Boot Loader version \n", __func__);
		return -EXIT_FAIL_GET_BOOT_LOADER_VERSION;
	}
	printk("BL version: %x \n", iBLVer);

	/*Obtain MPU type: this can be manually done in user space*/
	if (!flash_mputype_w9014(wac_i2c, &iMpuType)) {
		printk("%s failed to get MPU type \n", __func__);
		return -EXIT_FAIL_GET_MPU_TYPE;
	}
	if (iMpuType != MPU_W9014) {
		printk("MPU is not for W9014 : %x \n", iMpuType);
		return -EXIT_FAIL_GET_MPU_TYPE;
	}
	printk("MPU type: %x \n", iMpuType);

	/*-----------------------------------*/
	/*Flashing operation starts from here*/

	/*Set start and end address and block numbers*/
	eraseBlockNum = 0;
	start_address = W9014_START_ADDR;
	max_address = W9014_END_ADDR;
	for (i = BLOCK_NUM; i >= 8; i--) {
		eraseBlock[eraseBlockNum] = i;
		eraseBlockNum++;
	}

	msleep(300);

	/*Erase the old program*/
	printk("%s erasing the current firmware \n", __func__);
	bRet = flash_erase_all(wac_i2c);
	if (!bRet) {
		printk("%s failed to erase the user program \n", __func__);
		result = -EXIT_FAIL_ERASE;
		goto fail;
	}

	/*Write the new program*/
	printk(KERN_DEBUG"epen:%s writing new firmware \n", __func__);
	bRet = flash_write_w9014(wac_i2c, fw_data, start_address, &max_address);
	if (!bRet) {
		printk("%s failed to write firmware \n", __func__);
		result = -EXIT_FAIL_WRITE_FIRMWARE;
		goto fail;
	}

	/*Return to the user mode*/
	printk("%s closing the boot mode \n", __func__);
	bRet = flash_end_w9014(wac_i2c);
	if (!bRet) {
		printk("%s closing boot mode failed  \n", __func__);
		result = -EXIT_FAIL_WRITING_MARK_NOT_SET;
		goto fail;
	}

	printk("%s write and verify completed \n", __func__);
	result = EXIT_OK;

 fail:
	return result;
}

int wacom_i2c_flash(struct wacom_i2c *wac_i2c)
{
	int ret;

	if (fw_data == NULL) {
		printk(KERN_ERR "epen:Data is NULL. Exit.\n");
		return -1;
	}

	wac_i2c->pdata->compulsory_flash_mode(true);
	wac_i2c->pdata->reset_platform_hw();
	msleep(200);

	ret = wacom_flash_cmd(wac_i2c);
	if (ret < 0) {
		printk(KERN_DEBUG"epen:%s cannot send flash command \n", __func__);
	}

	printk(KERN_DEBUG"epen:%s pass wacom_flash_cmd \n", __func__);

	ret = flash_query_w9014(wac_i2c);
	if(ret < 0) {
		printk(KERN_DEBUG"epen:%s Error: cannot send query \n", __func__);
		ret = -EXIT_FAIL;
		goto end_wacom_flash;
	}

	printk(KERN_DEBUG"epen:%s pass flash_query_w9014 \n", __func__);

	ret = wacom_i2c_flash_w9014(wac_i2c, fw_data);
	if (ret < 0) {
		printk(KERN_DEBUG"epen:%s Error: flash failed \n", __func__);
		ret = -EXIT_FAIL;
		goto end_wacom_flash;
	}

	msleep(200);
 end_wacom_flash:
	wac_i2c->pdata->compulsory_flash_mode(false);
	wac_i2c->pdata->reset_platform_hw();
	msleep(200);

	return ret;
}

int wacom_i2c_usermode(struct wacom_i2c *wac_i2c)
{
	int ret;
#if 0
	bool bRet = false;

	wac_i2c->pdata->compulsory_flash_mode(true);

	ret = wacom_flash_cmd(wac_i2c);
	if (ret < 0) {
		printk(KERN_DEBUG"epen:%s cannot send flash command at user-mode \n", __func__);
		return ret;
	}

	/*Return to the user mode */
	printk(KERN_DEBUG"epen:%s closing the boot mode \n", __func__);
	bRet = flash_end(wac_i2c);
	if (!bRet) {
		printk(KERN_DEBUG"epen:%s closing boot mode failed  \n", __func__);
		ret = -EXIT_FAIL_WRITING_MARK_NOT_SET;
		goto end_usermode;
	}


	wac_i2c->pdata->compulsory_flash_mode(false);
	printk(KERN_DEBUG"epen:%s making user-mode completed \n", __func__);
	ret = EXIT_OK;


 end_usermode:
#else
	ret = 0;
#endif
	return ret;
}

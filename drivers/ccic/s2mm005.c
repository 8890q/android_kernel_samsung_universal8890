/*
 * driver/../s2mm005.c - S2MM005 USBPD device driver
 *
 * Copyright (C) 2015 Samsung Electronics
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */
#include <linux/ccic/s2mm005.h>
#include <linux/ccic/s2mm005_ext.h>
#include <linux/ccic/s2mm005_fw.h>
#include <linux/usb_notify.h>
#include <linux/ccic/ccic_sysfs.h>

extern struct device *ccic_device;
extern struct pdic_notifier_struct pd_noti;

#if defined(CONFIG_BATTERY_SAMSUNG)
extern unsigned int lpcharge;
#endif

#if defined(CONFIG_DUAL_ROLE_USB_INTF)
static enum dual_role_property fusb_drp_properties[] = {
	DUAL_ROLE_PROP_MODE,
	DUAL_ROLE_PROP_PR,
	DUAL_ROLE_PROP_DR,
	DUAL_ROLE_PROP_VCONN_SUPPLY,
};
#endif
////////////////////////////////////////////////////////////////////////////////
// function definition
////////////////////////////////////////////////////////////////////////////////
void s2mm005_int_clear(struct s2mm005_data *usbpd_data);
int s2mm005_read_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_read_byte_flash(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_write_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_read_byte_16(const struct i2c_client *i2c, u16 reg, u8 *val);
int s2mm005_write_byte_16(const struct i2c_client *i2c, u16 reg, u8 val);
void s2mm005_rprd_mode_change(struct s2mm005_data *usbpd_data, u8 mode);
void s2mm005_manual_JIGON(struct s2mm005_data *usbpd_data, int mode);
void s2mm005_manual_LPM(struct s2mm005_data *usbpd_data, int cmd);
void s2mm005_control_option_command(struct s2mm005_data *usbpd_data, int cmd);
int s2mm005_fw_ver_check(void * data);
int ccic_misc_init(void);
void ccic_misc_exit(void);
////////////////////////////////////////////////////////////////////////////////
//status machine of s2mm005 ccic
////////////////////////////////////////////////////////////////////////////////
//enum ccic_status {
//	state_cc_unknown = 0,
//	state_cc_idle,
//	state_cc_rid,
//	state_cc_updatefw,
//	state_cc_alternate,
//	state_cc_end=0xff,
//};
////////////////////////////////////////////////////////////////////////////////

int s2mm005_read_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret, i2c_retry; u8 wbuf[2];
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_USB_HW_PARAM)	
	struct otg_notify *o_notify = get_otg_notify();
#endif

	mutex_lock(&usbpd_data->i2c_mutex);
	i2c_retry = 0;
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = size;
	msg[1].buf = val;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	do {
		ret = i2c_transfer(i2c->adapter, msg, ARRAY_SIZE(msg));
	} while (ret < 0 &&  i2c_retry++ < 5);

	if (ret < 0) {
#if defined(CONFIG_USB_HW_PARAM)
		if (o_notify)
			inc_hw_param(o_notify, USB_CCIC_I2C_ERROR_COUNT);
#endif
		dev_err(&i2c->dev, "i2c read16 fail reg:0x%x error %d\n", reg, ret);
	}
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_read_byte_flash(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret; u8 wbuf[2];
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_USB_HW_PARAM)	
	struct otg_notify *o_notify = get_otg_notify();
#endif

	u8 W_DATA[1];
	udelay(20);
	W_DATA[0] = 0xAA;
	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 1);
	udelay(20);

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = size;
	msg[1].buf = val;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0) {
#if defined(CONFIG_USB_HW_PARAM)
		if (o_notify)
			inc_hw_param(o_notify, USB_CCIC_I2C_ERROR_COUNT);
#endif
		dev_err(&i2c->dev, "i2c read16 fail reg:0x%x error %d\n", reg, ret);
	}
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_write_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret, i2c_retry; u8 buf[258] = {0,};
	struct i2c_msg msg[1];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_USB_HW_PARAM)	
	struct otg_notify *o_notify = get_otg_notify();
#endif

	if (size > 256)
	{
		pr_err("I2C error, over the size %d", size);
		return -EIO;
	}

	mutex_lock(&usbpd_data->i2c_mutex);
	i2c_retry = 0;
	msg[0].addr = i2c->addr;
	msg[0].flags = 0;
	msg[0].len = size+2;
	msg[0].buf = buf;

	buf[0] = (reg & 0xFF00) >> 8;
	buf[1] = (reg & 0xFF);
	memcpy(&buf[2], val, size);

	do {
		ret = i2c_transfer(i2c->adapter, msg, 1);
	} while (ret < 0 &&  i2c_retry++ < 5);

	if (ret < 0) {
#if defined(CONFIG_USB_HW_PARAM)
		if (o_notify)
			inc_hw_param(o_notify, USB_CCIC_I2C_ERROR_COUNT);
#endif
		dev_err(&i2c->dev, "i2c write fail reg:0x%x error %d\n", reg, ret);
	}
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_read_byte_16(const struct i2c_client *i2c, u16 reg, u8 *val)
{
	int ret; u8 wbuf[2], rbuf;
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_USB_HW_PARAM)	
	struct otg_notify *o_notify = get_otg_notify();
#endif

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = 1;
	msg[1].buf = &rbuf;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, 2);
	if (ret < 0) {
#if defined(CONFIG_USB_HW_PARAM)
		if (o_notify)
			inc_hw_param(o_notify, USB_CCIC_I2C_ERROR_COUNT);
#endif
		dev_err(&i2c->dev, "i2c read16 fail reg(0x%x), error %d\n", reg, ret);
	}
	mutex_unlock(&usbpd_data->i2c_mutex);

	*val = rbuf;
	return rbuf;
}

int s2mm005_write_byte_16(const struct i2c_client *i2c, u16 reg, u8 val)
{
	int ret = 0; u8 wbuf[3];
	struct i2c_msg msg[1];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_USB_HW_PARAM)
	struct otg_notify *o_notify = get_otg_notify();
#endif

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = 0;
	msg[0].len = 3;
	msg[0].buf = wbuf;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);
	wbuf[2] = (val & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, 1);
	if (ret < 0) {
#if defined(CONFIG_USB_HW_PARAM)
		if (o_notify)
			inc_hw_param(o_notify, USB_CCIC_I2C_ERROR_COUNT);
#endif
		dev_err(&i2c->dev, "i2c write fail reg(0x%x:%x), error %d\n", reg, val, ret);
	}
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

void s2mm005_int_clear(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	pr_info("%s : -- clear clear -- \n", __func__);
	s2mm005_write_byte_16(i2c, 0x10, 0x1);
}

void s2mm005_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	u8 R_DATA[1];
	int i;

	pr_info("%s\n", __func__);
	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	printk("%s\n",__func__);
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x1C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x01;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
	/* reset stable time */
	msleep(100);
}

void s2mm005_reset_enable(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	printk("%s\n",__func__);
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x5C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x01;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

void s2mm005_system_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	u8 W_DATA[6];
	u8 R_DATA[6];

	W_DATA[0] =0x2;
	W_DATA[1] =0x20;  //word write
	W_DATA[2] =0x64;
	W_DATA[3] =0x10;

	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
	s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 2);

	/* SYSTEM RESET */
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x02;
	W_DATA[2] = 0x68;
	W_DATA[3] = 0x10;
	W_DATA[4] = R_DATA[0];
	W_DATA[5] = R_DATA[1];

	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 6);

}

void s2mm005_hard_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	struct device *i2c_dev = i2c->dev.parent->parent;

	struct pinctrl *i2c_pinctrl;

	i2c_lock_adapter(i2c->adapter);
	i2c_pinctrl = devm_pinctrl_get_select(i2c_dev, "hard_reset");
	if (IS_ERR(i2c_pinctrl))
		pr_err("could not set reset pins\n");
	printk("hard_reset: %04d %1d %01d\n", __LINE__, gpio_get_value(usbpd_data->s2mm005_sda), gpio_get_value(usbpd_data->s2mm005_scl));

	usleep_range(10 * 1000, 10 * 1000);
	i2c_pinctrl = devm_pinctrl_get_select(i2c_dev, "default");
	if (IS_ERR(i2c_pinctrl))
		pr_err("could not set default pins\n");
	usleep_range(8 * 1000, 8 * 1000);
	i2c_unlock_adapter(i2c->adapter);
	printk("hard_reset: %04d %1d %01d\n", __LINE__, gpio_get_value(usbpd_data->s2mm005_sda), gpio_get_value(usbpd_data->s2mm005_scl));
}

void s2mm005_sram_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	printk("%s\n",__func__);
	/* boot control reset OM HIGH */
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x1C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x08;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

void s2mm005_reconnect(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[3];
	printk("%s\n",__func__);
	W_DATA[0] = 0x03;
	W_DATA[1] = 0x02;
	W_DATA[2] = 0x00;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 3);
}

void s2mm005_manual_JIGON(struct s2mm005_data *usbpd_data, int mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	u8 R_DATA[1];
	int i;
	pr_info("usb: %s mode=%s (fw=0x%x)\n", __func__, mode? "High":"Low", usbpd_data->firm_ver[2]);
	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	W_DATA[0] = 0x0F;
	if(mode) W_DATA[1] = 0x5;   // JIGON High
	else W_DATA[1] = 0x4;   // JIGON Low
	REG_ADD = 0x10;
 	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);

}

void s2mm005_manual_LPM(struct s2mm005_data *usbpd_data, int cmd)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];
	u8 R_DATA[1];
	int i;
	pr_info("usb: %s cmd=0x%x (fw=0x%x)\n", __func__, cmd, usbpd_data->firm_ver[2]);

	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	W_DATA[0] = 0x0F;
	W_DATA[1] = cmd;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

void s2mm005_control_option_command(struct s2mm005_data *usbpd_data, int cmd)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];
	u8 R_DATA[1];
	int i;
	printk("usb: %s cmd=0x%x (fw=0x%x)\n", __func__, cmd, usbpd_data->firm_ver[2]);

	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

// 0x81 : Vconn control option command ON
// 0x82 : Vconn control option command OFF
// 0x83 : Water Detect option command ON
// 0x84 : Water Detect option command OFF

#if defined(CONFIG_SEC_FACTORY)
	if((cmd&0xF) == 0x3)
		usbpd_data->fac_water_enable = 1;
	else if ((cmd&0xF) == 0x4)
		usbpd_data->fac_water_enable = 0;
#endif

        REG_ADD = 0x10;
        W_DATA[0] = 0x03;
        W_DATA[1] = 0x80 | (cmd&0xF);
        s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

static void s2mm005_new_toggling_control(struct s2mm005_data *usbpd_data, u8 mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];

	pr_info("%s, mode=0x%x\n",__func__, mode);

	W_DATA[0] = 0x03;
	W_DATA[1] = mode; // 0x12 : detach, 0x13 : SRC, 0x14 : SNK

	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

static void s2mm005_toggling_control(struct s2mm005_data *usbpd_data, u8 mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];

	pr_info("%s, mode=0x%x\n",__func__, mode);

	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x00;
	W_DATA[3] = 0x50;
	W_DATA[4] = mode; // 0x1 : SRC, 0x2 : SNK, 0x3: DRP

	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

int s2mm005_fw_ver_check(void * data)
{
	struct s2mm005_data *usbpd_data = data;
	struct s2mm005_version chip_swver, hwver;

	if ((usbpd_data->firm_ver[1] == 0xFF && usbpd_data->firm_ver[2] == 0xFF)
		|| (usbpd_data->firm_ver[1] == 0x00 && usbpd_data->firm_ver[2] == 0x00)
		|| !(usbpd_data->firm_ver[3] >= 3 && usbpd_data->firm_ver[3] <= 6)) {
		s2mm005_get_chip_hwversion(usbpd_data, &hwver);
		pr_err("%s CHIP HWversion %2x %2x %2x %2x\n", __func__,
			hwver.main[2] , hwver.main[1], hwver.main[0], hwver.boot);

		s2mm005_get_chip_swversion(usbpd_data, &chip_swver);
		pr_err("%s CHIP SWversion %2x %2x %2x %2x\n", __func__,
		       chip_swver.main[2] , chip_swver.main[1], chip_swver.main[0], chip_swver.boot);

	if ((chip_swver.main[0] == 0xFF && chip_swver.main[1] == 0xFF)
		|| (chip_swver.main[0] == 0x00 && chip_swver.main[1] == 0x00)
		|| !(chip_swver.boot >= 3 && chip_swver.boot <= 6)) {
			pr_err("%s Invalid FW version\n", __func__);
			return CCIC_FW_VERSION_INVALID;
		}

		store_ccic_version(&hwver.main[0], &chip_swver.main[0], &chip_swver.boot);
		usbpd_data->firm_ver[0] = chip_swver.main[2];
		usbpd_data->firm_ver[1] = chip_swver.main[1];
		usbpd_data->firm_ver[2] = chip_swver.main[0];
		usbpd_data->firm_ver[3] = chip_swver.boot;
	}
	return 0;
}

void s2mm005_set_upsm_mode(void)
{
	struct s2mm005_data *usbpd_data;
	u8 W_DATA[2];

	if(!ccic_device)
		return;
	usbpd_data = dev_get_drvdata(ccic_device);
	if(!usbpd_data)
		return;

	W_DATA[0] =0x3;
	W_DATA[1] =0x40;
	s2mm005_write_byte(usbpd_data->i2c, 0x10, &W_DATA[0], 2);
	pr_info("%s : current status is upsm! \n",__func__);
}

void s2mm005_rprd_mode_change(struct s2mm005_data *usbpd_data, u8 mode)
{
	pr_info("%s, mode=0x%x\n",__func__, mode);

	switch(mode)
	{
		case TYPE_C_ATTACH_DFP: // SRC
			s2mm005_new_toggling_control(usbpd_data, 0x12);
			msleep(1000);
			s2mm005_new_toggling_control(usbpd_data, 0x13);
		break;
		case TYPE_C_ATTACH_UFP: // SNK
			s2mm005_new_toggling_control(usbpd_data, 0x12);
			msleep(1000);
			s2mm005_new_toggling_control(usbpd_data, 0x14);
		break;
		case TYPE_C_ATTACH_DRP: // DRP
			s2mm005_toggling_control(usbpd_data, TYPE_C_ATTACH_DRP);
		break;	
	};
}

static irqreturn_t s2mm005_usbpd_irq_thread(int irq, void *data)
{
	struct s2mm005_data *usbpd_data = data;
	struct i2c_client *i2c = usbpd_data->i2c;
	int irq_gpio_status[2];
	u8 plug_attach_done;
	u8 pdic_attach = 0;
	uint32_t *pPRT_MSG = NULL;

	MSG_IRQ_STATUS_Type	MSG_IRQ_State;

	dev_info(&i2c->dev, "%d times\n", ++usbpd_data->wq_times);
	if (usbpd_data->ccic_check_at_booting) {
		usbpd_data->ccic_check_at_booting = 0;
		cancel_delayed_work_sync(&usbpd_data->ccic_init_work);
	}

	// Function State
	irq_gpio_status[0] = gpio_get_value(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "IRQ0:%02d\n", irq_gpio_status[0]);
	wake_lock_timeout(&usbpd_data->wlock, HZ);

	if (s2mm005_fw_ver_check(usbpd_data) == CCIC_FW_VERSION_INVALID) {
		goto ver_err;
	}

	// Send attach event
	process_cc_attach(usbpd_data, &plug_attach_done);

	if (usbpd_data->s2mm005_i2c_err < 0)
		goto i2cErr;

	if(usbpd_data->water_det || !usbpd_data->run_dry || !usbpd_data->booting_run_dry){
		process_cc_water_det(usbpd_data);
		goto water;
	}

	// Get staus interrupt register
	process_cc_get_int_status(usbpd_data, pPRT_MSG ,&MSG_IRQ_State);

	// pd irq processing
	process_pd(usbpd_data, plug_attach_done, &pdic_attach, &MSG_IRQ_State);

	// RID processing
	process_cc_rid(usbpd_data);

i2cErr:
ver_err:
water:
	/* ========================================== */
	//	s2mm005_int_clear(usbpd_data);
	irq_gpio_status[1] = gpio_get_value(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "IRQ1:%02d", irq_gpio_status[1]);

	return IRQ_HANDLED;
}

#if defined(CONFIG_OF)
static int of_s2mm005_usbpd_dt(struct device *dev,
			       struct s2mm005_data *usbpd_data)
{
	struct device_node *np = dev->of_node;
	int ret;

	usbpd_data->irq_gpio = of_get_named_gpio(np, "usbpd,usbpd_int", 0);
	usbpd_data->redriver_en = of_get_named_gpio(np, "usbpd,redriver_en", 0);

	usbpd_data->s2mm005_om = of_get_named_gpio(np, "usbpd,s2mm005_om", 0);
	usbpd_data->s2mm005_sda = of_get_named_gpio(np, "usbpd,s2mm005_sda", 0);
	usbpd_data->s2mm005_scl = of_get_named_gpio(np, "usbpd,s2mm005_scl", 0);
	if (of_property_read_u32(np, "usbpd,water_detect_support", &usbpd_data->water_detect_support)) {
		usbpd_data->water_detect_support = 1;
	}
	if (of_property_read_u32(np, "usbpd,s2mm005_fw_product_id", &usbpd_data->s2mm005_fw_product_id)) {
		usbpd_data->s2mm005_fw_product_id = 0x01;
	}

	np = of_find_all_nodes(NULL);
	ret = of_property_read_u32(np, "model_info-hw_rev", &usbpd_data->hw_rev);
	if (ret) {
		pr_info("%s: model_info-hw_rev is Empty\n", __func__);
		usbpd_data->hw_rev = 0;
	}

	dev_err(dev, "hw_rev:%02d usbpd_irq = %d redriver_en = %d s2mm005_om = %d\n"
		"s2mm005_sda = %d, s2mm005_scl = %d, fw_product_id=0x%02X\n",
		usbpd_data->hw_rev,
		usbpd_data->irq_gpio, usbpd_data->redriver_en, usbpd_data->s2mm005_om,
		usbpd_data->s2mm005_sda, usbpd_data->s2mm005_scl,
		usbpd_data->s2mm005_fw_product_id);

	return 0;
}
#endif /* CONFIG_OF */


void ccic_state_check_work(struct work_struct *wk)
{
	struct s2mm005_data *usbpd_data =
		container_of(wk, struct s2mm005_data, ccic_init_work.work);

	pr_info("%s - check state=%d\n", __func__, usbpd_data->ccic_check_at_booting);
	if(usbpd_data->ccic_check_at_booting) {
		usbpd_data->ccic_check_at_booting = 0;
		s2mm005_usbpd_irq_thread(usbpd_data->irq, usbpd_data);
	}
}


static int pdic_handle_usb_external_notifier_notification(struct notifier_block *nb,
				unsigned long action, void *data)
{
	struct s2mm005_data *usbpd_data = dev_get_drvdata(ccic_device);
	int ret = 0;
	int enable = *(int *)data;

	pr_info("%s : action=%lu , enable=%d\n",__func__,action,enable);
	switch (action) {
	case EXTERNAL_NOTIFY_HOSTBLOCK_PRE:
		if(enable) {
			set_enable_alternate_mode(ALTERNATE_MODE_STOP);
			if(usbpd_data->dp_is_connect)
				dp_detach(usbpd_data);
		} else {
			if(usbpd_data->dp_is_connect)
				dp_detach(usbpd_data);
		}
		break;
	case EXTERNAL_NOTIFY_HOSTBLOCK_POST:
		if(enable) {
		} else {
			set_enable_alternate_mode(ALTERNATE_MODE_START);
		}
		break;
	default:
		break;
	}

	return ret;
}

static void delayed_external_notifier_init(struct work_struct *work)
{
	int ret = 0;
	static int retry_count = 1;
	int max_retry_count = 5;
	struct s2mm005_data *usbpd_data = dev_get_drvdata(ccic_device);

	pr_info("%s : %d = times!\n",__func__,retry_count);

	// Register ccic handler to ccic notifier block list
	ret = usb_external_notify_register(&usbpd_data->usb_external_notifier_nb,
		pdic_handle_usb_external_notifier_notification,EXTERNAL_NOTIFY_DEV_PDIC);
	if(ret < 0) {
		pr_err("Manager notifier init time is %d.\n",retry_count);
		if(retry_count++ != max_retry_count)
			schedule_delayed_work(&usbpd_data->usb_external_notifier_register_work, msecs_to_jiffies(2000));
		else
			pr_err("fail to init external notifier\n");
	} else
		pr_info("%s : external notifier register done!\n",__func__);
}

static int s2mm005_usbpd_probe(struct i2c_client *i2c,
			       const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(i2c->dev.parent);
	struct s2mm005_data *usbpd_data;
	int ret = 0;
#ifdef CONFIG_CCIC_LPM_ENABLE
	u8 check[8] = {0,};
#endif
	uint16_t REG_ADD;
	uint8_t MSG_BUF[32] = {0,};
	SINK_VAR_SUPPLY_Typedef *pSINK_MSG;
	MSG_HEADER_Typedef *pMSG_HEADER;
#if defined(CONFIG_SEC_FACTORY)
	LP_STATE_Type Lp_DATA;
#endif
	uint32_t * MSG_DATA;
	uint8_t cnt;
	u8 W_DATA[8];
	u8 R_DATA[4];
	u8 temp, ftrim;
	struct s2mm005_version chip_swver, fw_swver, hwver;
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	struct dual_role_phy_desc *desc;
	struct dual_role_phy_instance *dual_role;
#endif
	struct otg_notify *o_notify = get_otg_notify();

	pr_info("%s\n", __func__);
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&i2c->dev, "i2c functionality check error\n");
		return -EIO;
	}
	usbpd_data = devm_kzalloc(&i2c->dev, sizeof(struct s2mm005_data), GFP_KERNEL);
	if (!usbpd_data) {
		dev_err(&i2c->dev, "Failed to allocate driver data\n");
		return -ENOMEM;
	}

#if defined(CONFIG_OF)
	if (i2c->dev.of_node)
		of_s2mm005_usbpd_dt(&i2c->dev, usbpd_data);
	else {
		dev_err(&i2c->dev, "not found ccic dt! ret:%d\n", ret);
		return -ENODEV;
	}
#endif
	ret = gpio_request(usbpd_data->irq_gpio, "s2mm005_irq");
	if (ret)
		goto err_free_irq_gpio;
	if (gpio_is_valid(usbpd_data->redriver_en)) {
		ret = gpio_request(usbpd_data->redriver_en, "s2mm005_redriver_en");
		if (ret)
			goto err_free_redriver_gpio;
		/* TODO REMOVE redriver always enable, Add sleep/resume */
		ret = gpio_direction_output(usbpd_data->redriver_en, 1);
		if (ret) {
			dev_err(&i2c->dev, "Unable to set input gpio direction, error %d\n", ret);
			goto err_free_redriver_gpio;
		}
	}

	gpio_direction_input(usbpd_data->irq_gpio);
	usbpd_data->irq = gpio_to_irq(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "%s:IRQ NUM %d\n", __func__, usbpd_data->irq);

	usbpd_data->dev = &i2c->dev;
	usbpd_data->i2c = i2c;
	i2c_set_clientdata(i2c, usbpd_data);
	dev_set_drvdata(ccic_device, usbpd_data);
	device_init_wakeup(usbpd_data->dev, 1);
	pd_noti.pusbpd = usbpd_data;
	mutex_init(&usbpd_data->i2c_mutex);

	/* Init */
	usbpd_data->p_prev_rid = -1;
	usbpd_data->prev_rid = -1;
	usbpd_data->cur_rid = -1;
	usbpd_data->is_dr_swap = 0;
	usbpd_data->is_pr_swap = 0;
	usbpd_data->pd_state = 0;
	usbpd_data->func_state = 0;
	usbpd_data->data_role = 0;
	usbpd_data->is_host = 0;
	usbpd_data->is_client = 0;
	usbpd_data->manual_lpm_mode = 0;
	usbpd_data->water_det = 0;
	usbpd_data->run_dry = 1;
	usbpd_data->booting_run_dry = 1;
	usbpd_data->vconn_en = 1;
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	usbpd_data->try_state_change = 0;
#endif
#if defined(CONFIG_SEC_FACTORY)
	usbpd_data->fac_water_enable = 0;
#endif

	wake_lock_init(&usbpd_data->wlock, WAKE_LOCK_SUSPEND,
		       "s2mm005-intr");

#if defined(CONFIG_CCIC_NOTIFIER)
	/* Create a work queue for the ccic irq thread */
	usbpd_data->ccic_wq
		= create_singlethread_workqueue("ccic_irq_event");
	 if (!usbpd_data->ccic_wq) {
		pr_err("%s failed to create work queue\n", __func__);
		ret = -ENOMEM;
		goto err_free_redriver_gpio;
	 }
#endif

	dev_err(&i2c->dev, "probed, irq %d\n", usbpd_data->irq_gpio);

	for (cnt = 0; cnt < 32; cnt++) {
		MSG_BUF[cnt] = 0;
	}

	REG_ADD = REG_TX_SINK_CAPA_MSG;
	ret = s2mm005_read_byte(i2c, REG_ADD, MSG_BUF, 32);
	if (ret < 0) {
		s2mm005_hard_reset(usbpd_data);
		msleep(1000);
		ret = s2mm005_read_byte(i2c, REG_ADD, MSG_BUF, 32);
		if (ret < 0) {
			/* to check wrong ccic chipsets, It will be removed after PRA */
//			panic("Intentional Panic - ccic i2c error\n");
//			dev_err(&i2c->dev, "%s has i2c read error.\n", __func__);
//			goto err_init_irq;
		}
	}

	s2mm005_get_chip_hwversion(usbpd_data, &hwver);
	pr_err("%s CHIP HWversion  %2x %2x %2x %2x\n", __func__,
	       hwver.main[2] , hwver.main[1], hwver.main[0], hwver.boot);

	if (hwver.boot <= 2) {
		W_DATA[0] =0x02; W_DATA[1] =0x40; W_DATA[2] =0x04; W_DATA[3] =0x11;
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
		s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 4);
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

		ftrim = ((R_DATA[1] & 0xF8) >> 3) - 2;
		temp = R_DATA[1] & 0x7;
		R_DATA[1] = (ftrim << 3) + temp;
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

		W_DATA[0] = 0x02; W_DATA[1] = 0x04; W_DATA[2] = 0x04; W_DATA[3] = 0x11;
		W_DATA[4] = R_DATA[0]; W_DATA[5] = R_DATA[1]; W_DATA[6] = R_DATA[2]; W_DATA[7] = R_DATA[3];
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 8);

		W_DATA[0] =0x02; W_DATA[1] =0x40; W_DATA[2] =0x04; W_DATA[3] =0x11;
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
		s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 4);
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

	}

	s2mm005_get_chip_swversion(usbpd_data, &chip_swver);
	pr_err("%s CHIP SWversion  %2x %2x %2x %2x\n", __func__,
	       chip_swver.main[2], chip_swver.main[1], chip_swver.main[0], chip_swver.boot);

	s2mm005_get_fw_version(usbpd_data->s2mm005_fw_product_id,
		&fw_swver, chip_swver.boot, usbpd_data->hw_rev);
	pr_err("%s SRC SWversion:  %2x,%2x,%2x,%2x\n", __func__,
		fw_swver.main[2], fw_swver.main[1], fw_swver.main[0], fw_swver.boot);

	pr_err("%s: FW UPDATE boot:%01d hw_rev:%02d\n", __func__, chip_swver.boot, usbpd_data->hw_rev);
#if defined(CONFIG_SEC_FACTORY)
	s2mm005_read_byte(i2c, 0x60, Lp_DATA.BYTE, 4);
	pr_err("%s: WATER reg:0x%02X BOOTING_RUN_DRY=%d\n", __func__,
		Lp_DATA.BYTE[0], Lp_DATA.BITS.BOOTING_RUN_DRY);

	usbpd_data->fac_booting_dry_check = Lp_DATA.BITS.BOOTING_RUN_DRY;
#endif
#ifdef CONFIG_SEC_FACTORY
		if ((chip_swver.main[0] != fw_swver.main[0])
			|| (chip_swver.main[1] != fw_swver.main[1]))
#else
	      if ((chip_swver.main[0] < fw_swver.main[0])
			|| ((chip_swver.main[0] == fw_swver.main[0]) && (chip_swver.main[1] < fw_swver.main[1])))
#endif
	 {
		if (chip_swver.boot == 4) {
			if (usbpd_data->hw_rev >= 9)
				s2mm005_flash_fw(usbpd_data, FLASH_WRITE);
			else
				s2mm005_flash_fw(usbpd_data, FLASH_WRITE4);
		} else if (chip_swver.boot == 5) {
				s2mm005_flash_fw(usbpd_data, FLASH_WRITE5);
		} else if (chip_swver.boot == 6) {
				s2mm005_flash_fw(usbpd_data, FLASH_WRITE6);
		}
	}

	s2mm005_get_chip_swversion(usbpd_data, &chip_swver);
	pr_err("%s CHIP SWversion %2x %2x %2x %2x\n", __func__,
	       chip_swver.main[2] , chip_swver.main[1], chip_swver.main[0], chip_swver.boot);
	store_ccic_version(&hwver.main[0], &chip_swver.main[0], &chip_swver.boot);

	usbpd_data->firm_ver[0] = chip_swver.main[2];
	usbpd_data->firm_ver[1] = chip_swver.main[1];
	usbpd_data->firm_ver[2] = chip_swver.main[0];
	usbpd_data->firm_ver[3] = chip_swver.boot;

	MSG_DATA = (uint32_t *)&MSG_BUF[0];
	dev_info(&i2c->dev, "--- Read Data on TX_SNK_CAPA_MSG(0x220)\n\r");
	for(cnt = 0; cnt < 8; cnt++) {
		dev_info(&i2c->dev, "   0x%08X\n\r", MSG_DATA[cnt]);
	}

	pMSG_HEADER = (MSG_HEADER_Typedef *)&MSG_BUF[0];
	pMSG_HEADER->BITS.Number_of_obj += 1;
	pSINK_MSG = (SINK_VAR_SUPPLY_Typedef *)&MSG_BUF[8];
	pSINK_MSG->DATA = 0x8F019032; // 5V~12V, 500mA

	dev_info(&i2c->dev, "--- Write DATA\n\r");
	for (cnt = 0; cnt < 8; cnt++) {
		dev_info(&i2c->dev, "   0x%08X\n\r", MSG_DATA[cnt]);
	}

	/* default value is written by CCIC FW. If you need others, overwrite it.*/
	//s2mm005_write_byte(i2c, REG_ADD, &MSG_BUF[0], 32);

	for (cnt = 0; cnt < 32; cnt++) {
		MSG_BUF[cnt] = 0;
	}

	for (cnt = 0; cnt < 8; cnt++) {
		dev_info(&i2c->dev, "   0x%08X\n\r", MSG_DATA[cnt]);
	}
	ret = s2mm005_read_byte(i2c, REG_ADD, MSG_BUF, 32);

	dev_info(&i2c->dev, "--- Read 2 new Data on TX_SNK_CAPA_MSG(0x220)\n\r");
	for(cnt = 0; cnt < 8; cnt++) {
		dev_info(&i2c->dev, "   0x%08X\n\r", MSG_DATA[cnt]);
	}

#ifdef CONFIG_CCIC_LPM_ENABLE
		pr_err("LPM_ENABLE\n");
		check[0] = 0x0F;
		check[1] = 0x06;
		s2mm005_write_byte(i2c, 0x10, &check[0], 2);
#endif

#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	desc =
		devm_kzalloc(&i2c->dev,
				 sizeof(struct dual_role_phy_desc), GFP_KERNEL);
	if (!desc) {
		pr_err("unable to allocate dual role descriptor\n");
		goto err_init_irq;
	}

	desc->name = "otg_default";
	desc->supported_modes = DUAL_ROLE_SUPPORTED_MODES_DFP_AND_UFP;
	desc->get_property = dual_role_get_local_prop;
	desc->set_property = dual_role_set_prop;
	desc->properties = fusb_drp_properties;
	desc->num_properties = ARRAY_SIZE(fusb_drp_properties);
	desc->property_is_writeable = dual_role_is_writeable;
	dual_role =
		devm_dual_role_instance_register(&i2c->dev, desc);
	dual_role->drv_data = usbpd_data;
	usbpd_data->dual_role = dual_role;
	usbpd_data->desc = desc;
	init_completion(&usbpd_data->reverse_completion);
	usbpd_data->power_role = DUAL_ROLE_PROP_PR_NONE;
	INIT_DELAYED_WORK(&usbpd_data->role_swap_work, role_swap_check);
#elif defined(CONFIG_TYPEC)
	usbpd_data->typec_cap.revision = USB_TYPEC_REV_1_2;
	usbpd_data->typec_cap.pd_revision = 0x300;
	usbpd_data->typec_cap.prefer_role = TYPEC_NO_PREFERRED_ROLE;
	usbpd_data->typec_cap.port_type_set = s2mm005_port_type_set;
	usbpd_data->typec_cap.type = TYPEC_PORT_DRP;
	usbpd_data->port = typec_register_port(usbpd_data->dev, &usbpd_data->typec_cap);
	if (IS_ERR(usbpd_data->port))
		pr_err("%s : unable to register typec_register_port\n", __func__);
	else
		pr_err("%s : success typec_register_port port=%pK\n", __func__, usbpd_data->port);

	init_completion(&usbpd_data->role_reverse_completion);
#endif
#if defined(CONFIG_USB_HOST_NOTIFY)
	send_otg_notify(o_notify, NOTIFY_EVENT_POWER_SOURCE, 0);
#endif
#if defined(CONFIG_CCIC_ALTERNATE_MODE)
	init_completion(&usbpd_data->uvdm_out_wait);
	init_completion(&usbpd_data->uvdm_longpacket_in_wait);
	usbpd_data->alternate_state = 0;
	usbpd_data->acc_type = 0;
	usbpd_data->dp_is_connect = 0;
	usbpd_data->dp_hs_connect = 0;
	usbpd_data->dp_selected_pin = 0;
	usbpd_data->pin_assignment = 0;
	usbpd_data->is_samsung_accessory_enter_mode = 0;
	usbpd_data->Vendor_ID = 0;
	usbpd_data->Product_ID = 0;
	usbpd_data->Device_Version = 0;
	ccic_register_switch_device(1);
	INIT_DELAYED_WORK(&usbpd_data->acc_detach_work, acc_detach_check);
	init_waitqueue_head(&usbpd_data->host_turn_on_wait_q);
	set_host_turn_on_event(0);
	usbpd_data->host_turn_on_wait_time = 2;
	ret = ccic_misc_init();
	if (ret) {
		dev_err(&i2c->dev, "ccic misc register is failed, error %d\n", ret);
		goto err_init_irq;
	}
#endif

	s2mm005_int_clear(usbpd_data);
	fp_select_pdo = s2mm005_select_pdo;

	usbpd_data->ccic_check_at_booting = 1;
	INIT_DELAYED_WORK(&usbpd_data->ccic_init_work, ccic_state_check_work);
	schedule_delayed_work(&usbpd_data->ccic_init_work, msecs_to_jiffies(200));

	ret = request_threaded_irq(usbpd_data->irq, NULL, s2mm005_usbpd_irq_thread,
		(IRQF_TRIGGER_FALLING | IRQF_NO_SUSPEND | IRQF_ONESHOT), "s2mm005-usbpd", usbpd_data);
	if (ret) {
		dev_err(&i2c->dev, "Failed to request IRQ %d, error %d\n", usbpd_data->irq, ret);
		goto err_init_irq;
	}

#if defined(CONFIG_BATTERY_SAMSUNG)
	if(usbpd_data->s2mm005_fw_product_id == PRODUCT_NUM_DREAM)
	{
		u8 W_CHG_INFO[3]={0,};

		W_CHG_INFO[0] = 0x0f;
		W_CHG_INFO[1] = 0x0c;

		if (lpcharge)
			W_CHG_INFO[2] = 0x1; // lpcharge
		else
			W_CHG_INFO[2] = 0x0; // normal

		s2mm005_write_byte(usbpd_data->i2c, 0x10, &W_CHG_INFO[0], 3); // send info to ccic
	}
#endif
	INIT_DELAYED_WORK(&usbpd_data->usb_external_notifier_register_work,
				  delayed_external_notifier_init);

	// Register ccic handler to ccic notifier block list
	ret = usb_external_notify_register(&usbpd_data->usb_external_notifier_nb,
		pdic_handle_usb_external_notifier_notification,EXTERNAL_NOTIFY_DEV_PDIC);
	if(ret < 0)
		schedule_delayed_work(&usbpd_data->usb_external_notifier_register_work, msecs_to_jiffies(2000));
	else
		pr_info("%s : external notifier register done!\n",__func__);

	s2mm005_int_clear(usbpd_data);
	return ret;

err_init_irq:
	if (usbpd_data->irq) {
		free_irq(usbpd_data->irq, usbpd_data);
		usbpd_data->irq = 0;
	}
err_free_redriver_gpio:
	gpio_free(usbpd_data->redriver_en);
err_free_irq_gpio:
	wake_lock_destroy(&usbpd_data->wlock);
	gpio_free(usbpd_data->irq_gpio);
	return ret;
}

static int s2mm005_usbpd_remove(struct i2c_client *i2c)
{
	struct s2mm005_data *usbpd_data = dev_get_drvdata(ccic_device);

	process_cc_detach(usbpd_data);

#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	devm_dual_role_instance_unregister(usbpd_data->dev, usbpd_data->dual_role);
	devm_kfree(usbpd_data->dev, usbpd_data->desc);
#elif defined(CONFIG_TYPEC)
	typec_unregister_port(usbpd_data->port);
#endif

	sysfs_remove_group(&ccic_device->kobj, &ccic_sysfs_group);

	if (usbpd_data->irq) {
		free_irq(usbpd_data->irq, usbpd_data);
		usbpd_data->irq = 0;
	}

	if (usbpd_data->i2c) {
		disable_irq_wake(usbpd_data->i2c->irq);
		free_irq(usbpd_data->i2c->irq, usbpd_data);

		mutex_destroy(&usbpd_data->i2c_mutex);
		i2c_set_clientdata(usbpd_data->i2c, NULL);
	}

	wake_lock_destroy(&usbpd_data->wlock);
	ccic_misc_exit();
	return 0;
}

static void s2mm005_usbpd_shutdown(struct i2c_client *i2c)
{
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);
#if defined(CONFIG_CCIC_ALTERNATE_MODE)
	struct device_node *np;
	int gpio_dp_sw_oe;
#endif

	disable_irq(usbpd_data->irq);

	if ((usbpd_data->cur_rid != RID_523K) &&
		(usbpd_data->cur_rid != RID_619K) &&
		(!usbpd_data->manual_lpm_mode)) {

		pr_info("%s: pd_state=%d, water=%d, dry=%d\n", __func__,
			usbpd_data->pd_state, usbpd_data->water_det, usbpd_data->run_dry);

		if (usbpd_data->water_det) {
			s2mm005_hard_reset(usbpd_data);
		} else {
			if (usbpd_data->pd_state) {
#if defined(CONFIG_CCIC_ALTERNATE_MODE)
				if (usbpd_data->dp_is_connect) {
					pr_info("aux_sw_oe pin set to high\n");
					np = of_find_node_by_name(NULL, "displayport"); 
					gpio_dp_sw_oe = of_get_named_gpio(np, "dp,aux_sw_oe", 0);
					gpio_direction_output(gpio_dp_sw_oe, 1);
				}
#endif
				s2mm005_manual_LPM(usbpd_data, 0xB);
				mdelay(110);
			}
			s2mm005_reset(usbpd_data);
		}

	}
}

#if defined(CONFIG_PM)
static int s2mm005_suspend(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	pr_info("%s:%s\n", USBPD005_DEV_NAME, __func__);
#endif /* CONFIG_SAMSUNG_PRODUCT_SHIP */

	if (device_may_wakeup(dev))
		enable_irq_wake(usbpd_data->irq);

	disable_irq(usbpd_data->irq);

	return 0;
}

static int s2mm005_resume(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	pr_info("%s:%s\n", USBPD005_DEV_NAME, __func__);
#endif /* CONFIG_SAMSUNG_PRODUCT_SHIP */

	if (device_may_wakeup(dev))
		disable_irq_wake(usbpd_data->irq);

	enable_irq(usbpd_data->irq);

	return 0;
}
#else
#define s2mm005_suspend	NULL
#define s2mm005_resume		NULL
#endif /* CONFIG_PM */

static const struct i2c_device_id s2mm005_usbpd_id[] = {
	{ USBPD005_DEV_NAME, 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, s2mm005_usbpd_id);

#if defined(CONFIG_OF)
static struct of_device_id s2mm005_i2c_dt_ids[] = {
	{ .compatible = "sec-s2mm005,i2c" },
	{ }
};
#endif /* CONFIG_OF */

#if defined(CONFIG_PM)
const struct dev_pm_ops s2mm005_pm = {
	.suspend = s2mm005_suspend,
	.resume = s2mm005_resume,
};
#endif /* CONFIG_PM */

static struct i2c_driver s2mm005_usbpd_driver = {
	.driver		= {
		.name	= USBPD005_DEV_NAME,
#if defined(CONFIG_PM)
		.pm	= &s2mm005_pm,
#endif /* CONFIG_PM */
#if defined(CONFIG_OF)
		.of_match_table	= s2mm005_i2c_dt_ids,
#endif /* CONFIG_OF */
	},
	.probe		= s2mm005_usbpd_probe,
	//.remove		= __devexit_p(s2mm005_usbpd_remove),
	.remove		= s2mm005_usbpd_remove,
	.shutdown	= s2mm005_usbpd_shutdown,
	.id_table	= s2mm005_usbpd_id,
};

static int __init s2mm005_usbpd_init(void)
{
	return i2c_add_driver(&s2mm005_usbpd_driver);
}
module_init(s2mm005_usbpd_init);

static void __exit s2mm005_usbpd_exit(void)
{
	i2c_del_driver(&s2mm005_usbpd_driver);
}
module_exit(s2mm005_usbpd_exit);

MODULE_DESCRIPTION("s2mm005 USB PD driver");
MODULE_LICENSE("GPL");

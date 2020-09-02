/*
 * s2mps13.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd
 *              http://www.samsung.com
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <linux/mfd/samsung/core.h>
#include <linux/mfd/samsung/s2mps13.h>

static struct s2mps13_info *static_info;

struct s2mps13_info {
	struct regulator_dev *rdev[S2MPS13_REGULATOR_MAX];
	unsigned int opmode[S2MPS13_REGULATOR_MAX];
	bool dvs_en;
	struct sec_pmic_dev *iodev;
	bool g3d_en;
	int g3d_pin;
	int dvs_pin;
};

/* Some LDOs supports [LPM/Normal]ON mode during suspend state */
static int s2m_set_mode(struct regulator_dev *rdev,
				     unsigned int mode)
{
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	unsigned int val;
	int ret, id = rdev_get_id(rdev);

	switch (mode) {
	case SEC_OPMODE_SUSPEND:			/* ON in Standby Mode */
		val = 0x1 << S2MPS13_ENABLE_SHIFT;
		break;
	case SEC_OPMODE_ON:			/* ON in Normal Mode */
		val = 0x3 << S2MPS13_ENABLE_SHIFT;
		break;
	default:
		pr_warn("%s: regulator_suspend_mode : 0x%x not supported\n",
			rdev->desc->name, mode);
		return -EINVAL;
	}

	ret = regmap_update_bits(rdev->regmap, rdev->desc->enable_reg,
				  rdev->desc->enable_mask, val);
	if (ret)
		return ret;

	s2mps13->opmode[id] = val;
	return 0;
}

static int s2m_enable(struct regulator_dev *rdev)
{
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	int reg_id = rdev_get_id(rdev);
	/* disregard BUCK6 enable */
	if (reg_id == S2MPS13_BUCK6 && SEC_PMIC_REV(s2mps13->iodev) > 0x02
		&& s2mps13->g3d_en && gpio_is_valid(s2mps13->g3d_pin)) {
		gpio_set_value(s2mps13->g3d_pin, 1);
		return 0;
	}

	return regmap_update_bits(rdev->regmap, rdev->desc->enable_reg,
				  rdev->desc->enable_mask,
				  s2mps13->opmode[rdev_get_id(rdev)]);
}

static int s2m_disable_regmap(struct regulator_dev *rdev)
{
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	int reg_id = rdev_get_id(rdev);
	unsigned int val;
	/* disregard BUCK6 disable */
	if (reg_id == S2MPS13_BUCK6 && SEC_PMIC_REV(s2mps13->iodev) > 0x02
		&& s2mps13->g3d_en && gpio_is_valid(s2mps13->g3d_pin)) {
		gpio_set_value(s2mps13->g3d_pin, 0);
		return 0;
	}

	if (rdev->desc->enable_is_inverted)
		val = rdev->desc->enable_mask;
	else
		val = 0;

	return regmap_update_bits(rdev->regmap, rdev->desc->enable_reg,
				  rdev->desc->enable_mask, val);
}

static int get_ramp_delay(int ramp_delay)
{
	unsigned char cnt = 0;

	ramp_delay /= 6;

	while (true) {
		ramp_delay = ramp_delay >> 1;
		if (ramp_delay == 0)
			break;
		cnt++;
	}
	return cnt;
}

static int s2m_set_ramp_delay(struct regulator_dev *rdev, int ramp_delay)
{
	int ramp_reg, ramp_shift, reg_id = rdev_get_id(rdev);
	int ramp_mask = 0x03;
	unsigned int ramp_value = 0;

	ramp_value = get_ramp_delay(ramp_delay/1000);
	if (ramp_value > 4) {
		pr_warn("%s: ramp_delay: %d not supported\n",
			rdev->desc->name, ramp_delay);
	}

	switch (reg_id) {
	case S2MPS13_BUCK1:
	case S2MPS13_BUCK5:
		ramp_reg = S2MPS13_REG_BUCK_RAMP2;
		ramp_shift = 0;
		break;
	case S2MPS13_BUCK2:
		ramp_reg = S2MPS13_REG_BUCK_RAMP1;
		ramp_shift = 6;
		break;
	case S2MPS13_BUCK3:
		ramp_reg = S2MPS13_REG_BUCK_RAMP1;
		ramp_shift = 4;
		break;
	case S2MPS13_BUCK4:
		ramp_reg = S2MPS13_REG_BUCK_RAMP1;
		ramp_shift = 2;
		break;
	case S2MPS13_BUCK6:
		ramp_reg = S2MPS13_REG_BUCK_RAMP1;
		ramp_shift = 0;
		break;
	case S2MPS13_BUCK7:
	case S2MPS13_BUCK10:
		ramp_reg = S2MPS13_REG_BUCK_RAMP2;
		ramp_shift = 6;
		break;
	case S2MPS13_BUCK8 ... S2MPS13_BUCK9:
		ramp_reg = S2MPS13_REG_BUCK_RAMP2;
		ramp_shift = 4;
		break;
	case S2MPS13_BB1:
		ramp_reg = S2MPS13_REG_BUCK_RAMP2;
		ramp_shift = 2;
		break;
	default:
		return -EINVAL;
	}

	return regmap_update_bits(rdev->regmap, ramp_reg,
				  ramp_mask << ramp_shift, ramp_value << ramp_shift);
}

static int s2m_is_enabled_regmap(struct regulator_dev *rdev)
{
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	int ret, reg_id = rdev_get_id(rdev);
	unsigned int val;
	/* BUCK6 is controlled by g3d gpio */
	if (reg_id == S2MPS13_BUCK6 && SEC_PMIC_REV(s2mps13->iodev) > 0x02
		&& s2mps13->g3d_en && gpio_is_valid(s2mps13->g3d_pin)) {
		if (gpio_get_value(s2mps13->g3d_pin))
			return 1;
		else
			return 0;
	} else {
		ret = regmap_read(rdev->regmap, rdev->desc->enable_reg, &val);
		if (ret)
			return ret;
	}
	if (rdev->desc->enable_is_inverted)
		return (val & rdev->desc->enable_mask) == 0;
	else
		return (val & rdev->desc->enable_mask) != 0;
}

int s2m_get_voltage_sel_regmap(struct regulator_dev *rdev)
{
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	int ret, reg_id = rdev_get_id(rdev);
	unsigned int val;
	/* if dvs pin set high, get the voltage on the diffrent register. */
	if (reg_id == S2MPS13_BUCK6 && SEC_PMIC_REV(s2mps13->iodev) > 0x02
			&& s2mps13->dvs_en && gpio_get_value(s2mps13->dvs_pin)) {
		ret = regmap_read(rdev->regmap, S2MPS13_REG_B6CTRL3, &val);
		if (ret)
			return ret;
	} else {
		ret = regmap_read(rdev->regmap, rdev->desc->vsel_reg, &val);
		if (ret)
			return ret;
	}

	val &= rdev->desc->vsel_mask;
	val >>= ffs(rdev->desc->vsel_mask) - 1;

	return val;
}

static int s2m_set_voltage_sel_regmap_rev0(struct regulator_dev *rdev, unsigned sel)
{
	int ret, reg_id = rdev_get_id(rdev);
	int mode_mask = 0x0c, pwm_mode = 0x03 << 2, auto_mode = 0x02 << 2;

	if (reg_id == S2MPS13_BUCK6) {
		ret = regmap_update_bits(rdev->regmap, rdev->desc->enable_reg,
				  mode_mask, pwm_mode);
		if (ret < 0)
			goto out;
	}

	ret = regmap_write(rdev->regmap, rdev->desc->vsel_reg, sel);
	if (ret < 0)
		goto out;

	if (reg_id == S2MPS13_BUCK6) {
		ret = regmap_update_bits(rdev->regmap, rdev->desc->enable_reg,
				  mode_mask, auto_mode);
		if (ret < 0)
			goto out;
	}

	if (rdev->desc->apply_bit)
		ret = regmap_update_bits(rdev->regmap, rdev->desc->apply_reg,
					 rdev->desc->apply_bit,
					 rdev->desc->apply_bit);
	return ret;
out :
	pr_warn("%s: failed to set voltage_sel_regmap\n", rdev->desc->name);
	return ret;
}

static int s2m_set_voltage_sel_regmap_rev1(struct regulator_dev *rdev, unsigned sel)
{
	int ret;
	struct s2mps13_info *s2mps13 = rdev_get_drvdata(rdev);
	int reg_id = rdev_get_id(rdev);

	/* If dvs_en = 0, dvs_pin = 1, occur BUG_ON */
	if (reg_id == S2MPS13_BUCK6 && SEC_PMIC_REV(s2mps13->iodev) > 0x02
		&& !s2mps13->dvs_en && gpio_is_valid(s2mps13->dvs_pin)) {
		BUG_ON(gpio_get_value(s2mps13->dvs_pin));
	}

	ret = regmap_write(rdev->regmap, rdev->desc->vsel_reg, sel);
	if (ret < 0)
		goto out;

	if (rdev->desc->apply_bit)
		ret = regmap_update_bits(rdev->regmap, rdev->desc->apply_reg,
					 rdev->desc->apply_bit,
					 rdev->desc->apply_bit);
	return ret;
out :
	pr_warn("%s: failed to set voltage_sel_regmap\n", rdev->desc->name);
	return ret;
}

static int s2m_set_voltage_time_sel(struct regulator_dev *rdev,
				   unsigned int old_selector,
				   unsigned int new_selector)
{
	unsigned int ramp_delay = 0;
	int old_volt, new_volt;

	if (rdev->constraints->ramp_delay)
		ramp_delay = rdev->constraints->ramp_delay;
	else if (rdev->desc->ramp_delay)
		ramp_delay = rdev->desc->ramp_delay;

	if (ramp_delay == 0) {
		pr_warn("%s: ramp_delay not set\n", rdev->desc->name);
		return -EINVAL;
	}

	/* sanity check */
	if (!rdev->desc->ops->list_voltage)
		return -EINVAL;

	old_volt = rdev->desc->ops->list_voltage(rdev, old_selector);
	new_volt = rdev->desc->ops->list_voltage(rdev, new_selector);

	if (old_selector < new_selector)
		return DIV_ROUND_UP(new_volt - old_volt, ramp_delay);

	return 0;
}

int s2m_set_dvs_pin(bool gpio_val)
{
	if ((SEC_PMIC_REV(static_info->iodev) < 0x03) || !static_info->dvs_en
		|| !gpio_is_valid(static_info->dvs_pin)) {
		pr_warn("%s: dvs pin ctrl failed\n", __func__);
		return -EINVAL;
	}

	gpio_set_value(static_info->dvs_pin, gpio_val);
	/* wait for 90us, 100us when dvs pin control */
	if (gpio_val)
		udelay(90);
	else
		udelay(100);

	return 0;
}
EXPORT_SYMBOL_GPL(s2m_set_dvs_pin);

int s2m_set_g3d_pin(bool gpio_val)
{
        if ((SEC_PMIC_REV(static_info->iodev) < 0x03) || !static_info->g3d_en
                || !gpio_is_valid(static_info->g3d_pin)) {
                pr_warn("%s: g3d pin ctrl failed\n", __func__);
		return -EINVAL;
	}

	gpio_set_value(static_info->g3d_pin, gpio_val);
	if (gpio_val)
		udelay(128);

	return 0;
}
EXPORT_SYMBOL_GPL(s2m_set_g3d_pin);

static struct regulator_ops s2mps13_ldo_ops = {
	.list_voltage		= regulator_list_voltage_linear,
	.map_voltage		= regulator_map_voltage_linear,
	.is_enabled		= regulator_is_enabled_regmap,
	.enable			= s2m_enable,
	.disable		= regulator_disable_regmap,
	.get_voltage_sel	= s2m_get_voltage_sel_regmap,
	.set_voltage_sel	= regulator_set_voltage_sel_regmap,
	.set_voltage_time_sel	= s2m_set_voltage_time_sel,
	.set_mode		= s2m_set_mode,
};

static struct regulator_ops s2mps13_buck_ops_rev0 = {
	.list_voltage		= regulator_list_voltage_linear,
	.map_voltage		= regulator_map_voltage_linear,
	.is_enabled		= regulator_is_enabled_regmap,
	.enable			= s2m_enable,
	.disable		= regulator_disable_regmap,
	.get_voltage_sel	= s2m_get_voltage_sel_regmap,
	.set_voltage_sel	= s2m_set_voltage_sel_regmap_rev0,
	.set_voltage_time_sel	= s2m_set_voltage_time_sel,
	.set_mode		= s2m_set_mode,
	.set_ramp_delay		= s2m_set_ramp_delay,
};

static struct regulator_ops s2mps13_buck_ops_rev1 = {
	.list_voltage		= regulator_list_voltage_linear,
	.map_voltage		= regulator_map_voltage_linear,
	.is_enabled		= s2m_is_enabled_regmap,
	.enable			= s2m_enable,
	.disable		= s2m_disable_regmap,
	.get_voltage_sel	= s2m_get_voltage_sel_regmap,
	.set_voltage_sel	= s2m_set_voltage_sel_regmap_rev1,
	.set_voltage_time_sel	= s2m_set_voltage_time_sel,
	.set_mode		= s2m_set_mode,
	.set_ramp_delay		= s2m_set_ramp_delay,
};

#define regulator_desc_ldo1(num, rev)	{		\
	.name		= "LDO"#num,			\
	.id		= S2MPS13_LDO##num,		\
	.ops		= &s2mps13_ldo_ops,		\
	.type		= REGULATOR_VOLTAGE,		\
	.owner		= THIS_MODULE,			\
	.min_uV		= S2MPS13_LDO_MIN1_REV##rev,	\
	.uV_step	= S2MPS13_LDO_STEP2,		\
	.n_voltages	= S2MPS13_LDO_N_VOLTAGES,	\
	.vsel_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.vsel_mask	= S2MPS13_LDO_VSEL_MASK,	\
	.enable_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,		\
	.enable_time	= S2MPS13_ENABLE_TIME_LDO	\
}
#define regulator_desc_ldo2(num)	{		\
	.name		= "LDO"#num,			\
	.id		= S2MPS13_LDO##num,		\
	.ops		= &s2mps13_ldo_ops,		\
	.type		= REGULATOR_VOLTAGE,		\
	.owner		= THIS_MODULE,			\
	.min_uV		= S2MPS13_LDO_MIN2,		\
	.uV_step	= S2MPS13_LDO_STEP1,		\
	.n_voltages	= S2MPS13_LDO_N_VOLTAGES,	\
	.vsel_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.vsel_mask	= S2MPS13_LDO_VSEL_MASK,	\
	.enable_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,		\
	.enable_time	= S2MPS13_ENABLE_TIME_LDO	\
}
#define regulator_desc_ldo3(num)	{		\
	.name		= "LDO"#num,			\
	.id		= S2MPS13_LDO##num,		\
	.ops		= &s2mps13_ldo_ops,		\
	.type		= REGULATOR_VOLTAGE,		\
	.owner		= THIS_MODULE,			\
	.min_uV		= S2MPS13_LDO_MIN2,		\
	.uV_step	= S2MPS13_LDO_STEP2,		\
	.n_voltages	= S2MPS13_LDO_N_VOLTAGES,	\
	.vsel_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.vsel_mask	= S2MPS13_LDO_VSEL_MASK,	\
	.enable_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,		\
	.enable_time	= S2MPS13_ENABLE_TIME_LDO	\
}
#define regulator_desc_ldo4(num)	{		\
	.name		= "LDO"#num,			\
	.id		= S2MPS13_LDO##num,		\
	.ops		= &s2mps13_ldo_ops,		\
	.type		= REGULATOR_VOLTAGE,		\
	.owner		= THIS_MODULE,			\
	.min_uV		= S2MPS13_LDO_MIN2,		\
	.uV_step	= S2MPS13_LDO_STEP3,		\
	.n_voltages	= S2MPS13_LDO_N_VOLTAGES,	\
	.vsel_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.vsel_mask	= S2MPS13_LDO_VSEL_MASK,	\
	.enable_reg	= S2MPS13_REG_L1CTRL + num - 1,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,		\
	.enable_time	= S2MPS13_ENABLE_TIME_LDO	\
}

#define regulator_desc_buck1_6(num, rev)	{		\
	.name		= "BUCK"#num,				\
	.id		= S2MPS13_BUCK##num,			\
	.ops		= &s2mps13_buck_ops_rev##rev,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN1_REV##rev,		\
	.uV_step	= S2MPS13_BUCK_STEP1,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_B1CTRL2 + (num - 1) * 2,	\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_B1CTRL1 + (num - 1) * 2,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,			\
	.enable_time	= S2MPS13_ENABLE_TIME_BUCK##num		\
}

#define regulator_desc_buck7(num, rev) {			\
	.name		= "BUCK7",				\
	.id		= S2MPS13_BUCK7,			\
	.ops		= &s2mps13_buck_ops_rev##rev,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN1_REV##rev,		\
	.uV_step	= S2MPS13_BUCK_STEP1,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_B7CTRL2,			\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_B7CTRL1,			\
	.enable_mask	= S2MPS13_ENABLE_MASK,			\
	.enable_time	= S2MPS13_ENABLE_TIME_BUCK7		\
}

#define regulator_desc_buck7_sw(num, rev)	{		\
	.name		= "BUCK7_SW",				\
	.id		= S2MPS13_BUCK7_SW,			\
	.ops		= &s2mps13_buck_ops_rev##rev,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN1_REV##rev,		\
	.uV_step	= S2MPS13_BUCK_STEP1,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_B7CTRL2,			\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_B7CTRL_SW,		\
	.enable_mask	= S2MPS13_SW_ENABLE_MASK		\
}

#define regulator_desc_buck10(num, rev) {			\
	.name		= "BUCK10",				\
	.id		= S2MPS13_BUCK10,			\
	.ops		= &s2mps13_buck_ops_rev##rev,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN1_REV##rev,		\
	.uV_step	= S2MPS13_BUCK_STEP1,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_B10CTRL2,			\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_B10CTRL1,			\
	.enable_mask	= S2MPS13_ENABLE_MASK,			\
	.enable_time	= S2MPS13_ENABLE_TIME_BUCK10		\
}

#define regulator_desc_buck89(num)	{			\
	.name		= "BUCK"#num,				\
	.id		= S2MPS13_BUCK##num,			\
	.ops		= &s2mps13_buck_ops_rev1,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN1,			\
	.uV_step	= S2MPS13_BUCK_STEP2,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_B8CTRL2 + (num - 8) * 2,	\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_B8CTRL1 + (num - 8) * 2,	\
	.enable_mask	= S2MPS13_ENABLE_MASK,			\
	.enable_time	= S2MPS13_ENABLE_TIME_BUCK##num		\
}

#define regulator_desc_bb1	{				\
	.name		= "BUCKBOOST",				\
	.id		= S2MPS13_BB1,				\
	.ops		= &s2mps13_buck_ops_rev1,		\
	.type		= REGULATOR_VOLTAGE,			\
	.owner		= THIS_MODULE,				\
	.min_uV		= S2MPS13_BUCK_MIN2,			\
	.uV_step	= S2MPS13_BUCK_STEP2,			\
	.n_voltages	= S2MPS13_BUCK_N_VOLTAGES,		\
	.vsel_reg	= S2MPS13_REG_BB1CTRL2,			\
	.vsel_mask	= S2MPS13_BUCK_VSEL_MASK,		\
	.enable_reg	= S2MPS13_REG_BB1CTRL1,			\
	.enable_mask	= S2MPS13_ENABLE_MASK,			\
	.enable_time	= S2MPS13_ENABLE_TIME_BB		\
}

enum regulator_desc_type {
	S2MPS13_DESC_TYPE0 = 0,
	S2MPS13_DESC_TYPE1,
};

static struct regulator_desc regulators[][S2MPS13_REGULATOR_MAX] = {
	[S2MPS13_DESC_TYPE0] = {
		/* for s2mps13 rev0 */
		regulator_desc_ldo2(1),
		regulator_desc_ldo4(2),
		regulator_desc_ldo3(3),
		regulator_desc_ldo2(4),
		regulator_desc_ldo2(5),
		regulator_desc_ldo2(6),
		regulator_desc_ldo3(7),
		regulator_desc_ldo3(8),
		regulator_desc_ldo3(9),
		regulator_desc_ldo4(10),
		regulator_desc_ldo1(11,0),
		regulator_desc_ldo1(12,0),
		regulator_desc_ldo1(13,0),
		regulator_desc_ldo2(14),
		regulator_desc_ldo2(15),
		regulator_desc_ldo4(16),
		regulator_desc_ldo4(17),
		regulator_desc_ldo3(18),
		regulator_desc_ldo3(19),
		regulator_desc_ldo4(20),
		regulator_desc_ldo3(21),
		regulator_desc_ldo3(22),
		regulator_desc_ldo2(23),
		regulator_desc_ldo2(24),
		regulator_desc_ldo4(25),
		regulator_desc_ldo4(26),
		regulator_desc_ldo4(27),
		regulator_desc_ldo3(28),
		regulator_desc_ldo4(29),
		regulator_desc_ldo4(30),
		regulator_desc_ldo3(31),
		regulator_desc_ldo3(32),
		regulator_desc_ldo4(33),
		regulator_desc_ldo3(34),
		regulator_desc_ldo4(35),
		regulator_desc_ldo2(36),
		regulator_desc_ldo3(37),
		regulator_desc_ldo4(38),
		regulator_desc_ldo3(39),
		regulator_desc_ldo4(40),
		regulator_desc_buck1_6(1,0),
		regulator_desc_buck1_6(2,0),
		regulator_desc_buck1_6(3,0),
		regulator_desc_buck1_6(4,0),
		regulator_desc_buck1_6(5,0),
		regulator_desc_buck1_6(6,0),
		regulator_desc_buck7(0,0),
		regulator_desc_buck7_sw(0,0),
		regulator_desc_buck89(8),
		regulator_desc_buck89(9),
		regulator_desc_buck10(0,0),
		regulator_desc_bb1,
	},
	[S2MPS13_DESC_TYPE1] = {
		/* for s2mps13 rev1 and others*/
		regulator_desc_ldo2(1),
		regulator_desc_ldo4(2),
		regulator_desc_ldo3(3),
		regulator_desc_ldo2(4),
		regulator_desc_ldo2(5),
		regulator_desc_ldo2(6),
		regulator_desc_ldo3(7),
		regulator_desc_ldo3(8),
		regulator_desc_ldo3(9),
		regulator_desc_ldo4(10),
		regulator_desc_ldo1(11,1),
		regulator_desc_ldo1(12,1),
		regulator_desc_ldo1(13,1),
		regulator_desc_ldo2(14),
		regulator_desc_ldo2(15),
		regulator_desc_ldo4(16),
		regulator_desc_ldo4(17),
		regulator_desc_ldo3(18),
		regulator_desc_ldo3(19),
		regulator_desc_ldo4(20),
		regulator_desc_ldo3(21),
		regulator_desc_ldo3(22),
		regulator_desc_ldo2(23),
		regulator_desc_ldo2(24),
		regulator_desc_ldo4(25),
		regulator_desc_ldo4(26),
		regulator_desc_ldo4(27),
		regulator_desc_ldo3(28),
		regulator_desc_ldo4(29),
		regulator_desc_ldo4(30),
		regulator_desc_ldo3(31),
		regulator_desc_ldo3(32),
		regulator_desc_ldo4(33),
		regulator_desc_ldo3(34),
		regulator_desc_ldo4(35),
		regulator_desc_ldo2(36),
		regulator_desc_ldo3(37),
		regulator_desc_ldo4(38),
		regulator_desc_ldo3(39),
		regulator_desc_ldo4(40),
		regulator_desc_buck1_6(1,1),
		regulator_desc_buck1_6(2,1),
		regulator_desc_buck1_6(3,1),
		regulator_desc_buck1_6(4,1),
		regulator_desc_buck1_6(5,1),
		regulator_desc_buck1_6(6,1),
		regulator_desc_buck7(0,1),
		regulator_desc_buck7_sw(0,1),
		regulator_desc_buck89(8),
		regulator_desc_buck89(9),
		regulator_desc_buck10(0,1),
		regulator_desc_bb1,
	}
};

#ifdef CONFIG_OF
static int s2mps13_pmic_dt_parse_pdata(struct sec_pmic_dev *iodev,
					struct sec_platform_data *pdata)
{
	struct device_node *pmic_np, *regulators_np, *reg_np;
	struct sec_regulator_data *rdata;
	unsigned int i, s2mps13_desc_type;
	int ret;
	u32 val;

	pmic_np = iodev->dev->of_node;
	if (!pmic_np) {
		dev_err(iodev->dev, "could not find pmic sub-node\n");
		return -ENODEV;
	}

	pdata->smpl_warn_vth = 0;

	/* If pmic revision number over 0x02, get 3 gpio values */
	if (SEC_PMIC_REV(iodev) > 0x02) {
		if (of_gpio_count(pmic_np) < 3) {
			dev_err(iodev->dev, "could not find pmic gpios\n");
			return -EINVAL;
		}
		pdata->smpl_warn = of_get_gpio(pmic_np, 0);
		pdata->g3d_pin = of_get_gpio(pmic_np, 1);
		pdata->dvs_pin = of_get_gpio(pmic_np, 2);

		ret = of_property_read_u32(pmic_np, "g3d_en", &val);
		if (ret)
			return -EINVAL;
		pdata->g3d_en = !!val;

		ret = of_property_read_u32(pmic_np, "dvs_en", &val);
		if (ret)
			return -EINVAL;
		pdata->dvs_en = !!val;

		ret = of_property_read_u32(pmic_np, "smpl_warn_en", &val);
		if (ret)
			return -EINVAL;
		pdata->smpl_warn_en = !!val;

		ret = of_property_read_u32(pmic_np, "smpl_warn_vth", &val);
		if (ret)
			return -EINVAL;
		pdata->smpl_warn_vth = val;
	} else {
		dev_err(iodev->dev, "cannot control g3d_en & dvs_en\n");
	}

	pdata->ap_buck_avp_en = false;
	pdata->sub_buck_avp_en = false;
	if (of_find_property(pmic_np, "ap-buck-avp-en", NULL))
		pdata->ap_buck_avp_en = true;

	if (of_find_property(pmic_np, "sub-buck-avp-en", NULL))
		pdata->sub_buck_avp_en = true;

	regulators_np = of_find_node_by_name(pmic_np, "regulators");
	if (!regulators_np) {
		dev_err(iodev->dev, "could not find regulators sub-node\n");
		return -EINVAL;
	}

	/* count the number of regulators to be supported in pmic */
	pdata->num_regulators = 0;
	for_each_child_of_node(regulators_np, reg_np) {
		pdata->num_regulators++;
	}

	rdata = devm_kzalloc(iodev->dev, sizeof(*rdata) *
				pdata->num_regulators, GFP_KERNEL);
	if (!rdata) {
		dev_err(iodev->dev,
			"could not allocate memory for regulator data\n");
		return -ENOMEM;
	}

	pdata->regulators = rdata;
	s2mps13_desc_type = SEC_PMIC_REV(iodev) ? S2MPS13_DESC_TYPE1 : S2MPS13_DESC_TYPE0;
	for_each_child_of_node(regulators_np, reg_np) {
		for (i = 0; i < ARRAY_SIZE(regulators[s2mps13_desc_type]); i++)
			if (!of_node_cmp(reg_np->name,
					regulators[s2mps13_desc_type][i].name))
				break;

		if (i == ARRAY_SIZE(regulators[s2mps13_desc_type])) {
			dev_warn(iodev->dev,
			"don't know how to configure regulator %s\n",
			reg_np->name);
			continue;
		}

		rdata->id = i;
		rdata->initdata = of_get_regulator_init_data(
						iodev->dev, reg_np);
		rdata->reg_node = reg_np;
		rdata++;
	}

	return 0;
}
#else
static int s2mps13_pmic_dt_parse_pdata(struct sec_pmic_dev *iodev,
					struct sec_platform_data *pdata)
{
	return 0;
}
#endif /* CONFIG_OF */

static int s2mps13_pmic_probe(struct platform_device *pdev)
{
	struct sec_pmic_dev *iodev = dev_get_drvdata(pdev->dev.parent);
	struct sec_platform_data *pdata = iodev->pdata;
	struct regulator_config config = { };
	struct s2mps13_info *s2mps13;
	int i, ret;
	unsigned int s2mps13_desc_type;

	ret = sec_reg_read(iodev, S2MPS13_REG_ID, &iodev->rev_num);
	if (ret < 0)
		return ret;
	s2mps13_desc_type = SEC_PMIC_REV(iodev) ? S2MPS13_DESC_TYPE1 : S2MPS13_DESC_TYPE0;

	if (iodev->dev->of_node) {
		ret = s2mps13_pmic_dt_parse_pdata(iodev, pdata);
		if (ret)
			return ret;
	}

	if (!pdata) {
		dev_err(pdev->dev.parent, "Platform data not supplied\n");
		return -ENODEV;
	}

	s2mps13 = devm_kzalloc(&pdev->dev, sizeof(struct s2mps13_info),
				GFP_KERNEL);
	if (!s2mps13)
		return -ENOMEM;

	s2mps13->iodev = iodev;
	static_info = s2mps13;

	if (SEC_PMIC_REV(iodev) > 0x02) {
		s2mps13->dvs_en = pdata->dvs_en;
		s2mps13->g3d_en = pdata->g3d_en;
		if (gpio_is_valid(pdata->dvs_pin)) {
			ret = devm_gpio_request(&pdev->dev, pdata->dvs_pin,
						"S2MPS13 DVS_PIN");
			if (ret < 0)
				return ret;
			/* Off DVS Control GPIO */
			gpio_direction_output(pdata->dvs_pin, 0);
			if (pdata->dvs_en) {
				/* Set DVS Regulator Voltage */
				ret = sec_reg_write(iodev, S2MPS13_REG_B6CTRL3, 0x30);
				if (ret < 0)
					return ret;
			}
			s2mps13->dvs_pin = pdata->dvs_pin;
		} else
			dev_err(&pdev->dev, "dvs pin is not valid\n");
	}

	platform_set_drvdata(pdev, s2mps13);

	for (i = 0; i < pdata->num_regulators; i++) {
		int id = pdata->regulators[i].id;
		config.dev = &pdev->dev;
		config.regmap = iodev->regmap;
		config.init_data = pdata->regulators[i].initdata;
		config.driver_data = s2mps13;
		config.of_node = pdata->regulators[i].reg_node;
		s2mps13->opmode[id] = regulators[s2mps13_desc_type][id].enable_mask;

		s2mps13->rdev[i] = regulator_register(
					&regulators[s2mps13_desc_type][id], &config);
		if (IS_ERR(s2mps13->rdev[i])) {
			ret = PTR_ERR(s2mps13->rdev[i]);
			dev_err(&pdev->dev, "regulator init failed for %d\n",
				i);
			s2mps13->rdev[i] = NULL;
			goto err;
		}
	}
	if (SEC_PMIC_REV(iodev) > 0x02) {
		if (gpio_is_valid(pdata->g3d_pin)) {
			ret = devm_gpio_request(&pdev->dev, pdata->g3d_pin,
						"S2MPS13 G3D_PIN");
			if (pdata->g3d_en) {
				gpio_direction_output(pdata->g3d_pin, 1);
				udelay(128);
				ret = sec_reg_update(iodev, S2MPS13_REG_B6CTRL1, 0x00, 0xC0);
				ret = sec_reg_update(iodev, S2MPS13_REG_LDO_DVS3, 0x02, 0x02);
			} else
				gpio_direction_output(pdata->g3d_pin, 0);

			s2mps13->g3d_pin = pdata->g3d_pin;
		} else
			dev_err(&pdev->dev, "g3d pin is not valid\n");
	}

	/* PMIC AVP(Adaptive Voltage Positioning) Configuration */
	if (pdata->ap_buck_avp_en) {
		sec_reg_write(iodev, 0x91, 0x4F);  /* Buck4 AVP level 11mV/A */
		sec_reg_write(iodev, 0x99, 0x4D);  /* Buck6 AVP level 7mV/A */
		sec_reg_update(iodev, S2MPS13_REG_B4CTRL1, 0x02, 0x02);  /* Buck4 AVP On */
		sec_reg_update(iodev, S2MPS13_REG_B6CTRL1, 0x02, 0x02);  /* Buck6 AVP On */
	}
	if (pdata->sub_buck_avp_en) {
		sec_reg_write(iodev, 0xBA, 0x4C);  /* Buck8 AVP level 90mV/A */
		sec_reg_write(iodev, 0xBB, 0x6A);  /* Buck9 AVP level 115mV/A */
		sec_reg_write(iodev, 0xB1, 0x0A);  /* Buck8 AVP amp offset code */
		sec_reg_write(iodev, 0xB5, 0x2A);  /* Buck9 AVP amp offset code */
		sec_reg_update(iodev, S2MPS13_REG_B8CTRL1, 0x02, 0x02);  /* Buck8 AVP On */
		sec_reg_update(iodev, S2MPS13_REG_B9CTRL1, 0x02, 0x02);  /* Buck9 AVP On */
	}
	sec_reg_update(iodev, S2MPS13_REG_CTRL2, pdata->smpl_warn_vth, 0xe0);
	pr_info("%s: smpl_warn vthreshold is 0x%x\n", __func__, pdata->smpl_warn_vth);

	return 0;
err:
	for (i = 0; i < S2MPS13_REGULATOR_MAX; i++)
		regulator_unregister(s2mps13->rdev[i]);

	return ret;
}

static int s2mps13_pmic_remove(struct platform_device *pdev)
{
	struct s2mps13_info *s2mps13 = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < S2MPS13_REGULATOR_MAX; i++)
		regulator_unregister(s2mps13->rdev[i]);

	return 0;
}

static const struct platform_device_id s2mps13_pmic_id[] = {
	{ "s2mps13-pmic", 0},
	{ },
};
MODULE_DEVICE_TABLE(platform, s2mps13_pmic_id);

static struct platform_driver s2mps13_pmic_driver = {
	.driver = {
		.name = "s2mps13-pmic",
		.owner = THIS_MODULE,
	},
	.probe = s2mps13_pmic_probe,
	.remove = s2mps13_pmic_remove,
	.id_table = s2mps13_pmic_id,
};

static int __init s2mps13_pmic_init(void)
{
	return platform_driver_register(&s2mps13_pmic_driver);
}
subsys_initcall(s2mps13_pmic_init);

static void __exit s2mps13_pmic_exit(void)
{
	platform_driver_unregister(&s2mps13_pmic_driver);
}
module_exit(s2mps13_pmic_exit);

/* Module information */
MODULE_AUTHOR("Sangbeom Kim <sbkim73@samsung.com>");
MODULE_DESCRIPTION("SAMSUNG S2MPS13 Regulator Driver");
MODULE_LICENSE("GPL");

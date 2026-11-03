/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *	      http://www.samsung.com/
 *
 * EXYNOS - CHIP ID support
 * Author: Pankaj Dubey <pankaj.dubey@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sys_soc.h>
#include <linux/soc/samsung/exynos-soc.h>

struct exynos_chipid_info exynos_soc_info;
EXPORT_SYMBOL(exynos_soc_info);

static const char *soc_ap_id;
	
static const char * __init product_id_to_name(unsigned int product_id)
{
	const char *soc_name;
	unsigned int soc_id = product_id & EXYNOS_SOC_MASK;

	switch (soc_id) {
	case EXYNOS3250_SOC_ID:
		soc_name = "EXYNOS3250";
		break;
	case EXYNOS4210_SOC_ID:
		soc_name = "EXYNOS4210";
		break;
	case EXYNOS4212_SOC_ID:
		soc_name = "EXYNOS4212";
		break;
	case EXYNOS4412_SOC_ID:
		soc_name = "EXYNOS4412";
		break;
	case EXYNOS4415_SOC_ID:
		soc_name = "EXYNOS4415";
		break;
	case EXYNOS5250_SOC_ID:
		soc_name = "EXYNOS5250";
		break;
	case EXYNOS5260_SOC_ID:
		soc_name = "EXYNOS5260";
		break;
	case EXYNOS5420_SOC_ID:
		soc_name = "EXYNOS5420";
		break;
	case EXYNOS5440_SOC_ID:
		soc_name = "EXYNOS5440";
		break;
	case EXYNOS5800_SOC_ID:
		soc_name = "EXYNOS5800";
		break;
	case EXYNOS8890_SOC_ID:
		soc_name = "EXYNOS8890";
		break;
	case EXYNOS8895_SOC_ID:
		soc_name = "EXYNOS8895";
		break;
	default:
		soc_name = "UNKNOWN";
	}
	return soc_name;
}
static const struct exynos_chipid_variant drv_data_exynos8890 = {
	.unique_id_reg	= 0x14,
	.rev_reg	= 0x0,
	/* Match the 8890 product ID revision byte used by the 3.18 driver. */
	.main_rev_bit	= 4,
	.sub_rev_bit	= 0,
};

static const struct exynos_chipid_variant drv_data_exynos8895 = {
	.unique_id_reg	= 0x04,
	.rev_reg	= 0x10,
	.main_rev_bit	= 20,
	.sub_rev_bit	= 16,
};

static const struct of_device_id of_exynos_chipid_ids[] = {
	{
		.compatible	= "samsung,exynos8890-chipid",
		.data		= &drv_data_exynos8890,
	},
	{
		.compatible	= "samsung,exynos8895-chipid",
		.data		= &drv_data_exynos8895,
	},
	{},
};

static void __init exynos_chipid_get_chipid_info(void)
{
	const struct exynos_chipid_variant *data = exynos_soc_info.drv_data;
	u64 val;

	val = __raw_readl(exynos_soc_info.reg);
	exynos_soc_info.product_id = val & EXYNOS_SOC_MASK;

	val = __raw_readl(exynos_soc_info.reg + data->rev_reg);
	exynos_soc_info.main_rev = (val >> data->main_rev_bit) & EXYNOS_REV_MASK;
	exynos_soc_info.sub_rev = (val >> data->sub_rev_bit) & EXYNOS_REV_MASK;
	exynos_soc_info.revision = (exynos_soc_info.main_rev << 4) | exynos_soc_info.sub_rev;

	val = __raw_readl(exynos_soc_info.reg + data->unique_id_reg);
	val |= (u64)__raw_readl(exynos_soc_info.reg + data->unique_id_reg + 4) << 32UL;
	exynos_soc_info.unique_id  = val;
	exynos_soc_info.lot_id = val & EXYNOS_LOTID_MASK;
}

/**
 *  exynos_chipid_early_init: Early chipid initialization
 *  @dev: pointer to chipid device
 */
void __init exynos_chipid_early_init(void)
{
	struct device_node *np;
	const struct of_device_id *match;

	if (exynos_soc_info.reg)
		return;

	np = of_find_matching_node_and_match(NULL, of_exynos_chipid_ids, &match);
	if (!np || !match)
		panic("%s, failed to find chipid node or match\n", __func__);

	exynos_soc_info.drv_data = (struct exynos_chipid_variant *)match->data;
	exynos_soc_info.reg = of_iomap(np, 0);
	if (!exynos_soc_info.reg)
		panic("%s: failed to map registers\n", __func__);

	exynos_chipid_get_chipid_info();
}

static int __init exynos_chipid_probe(struct platform_device *pdev)
{
	struct soc_device_attribute *soc_dev_attr;
	struct soc_device *soc_dev;
	struct device_node *root;
	int ret;

	soc_dev_attr = kzalloc(sizeof(*soc_dev_attr), GFP_KERNEL);
	if (!soc_dev_attr)
		return -ENODEV;

	soc_dev_attr->family = "Samsung Exynos";

	root = of_find_node_by_path("/");
	ret = of_property_read_string(root, "model", &soc_dev_attr->machine);
	of_node_put(root);
	if (ret)
		goto free_soc;

	soc_dev_attr->revision = kasprintf(GFP_KERNEL, "%d",
					exynos_soc_info.revision);
	if (!soc_dev_attr->revision)
		goto free_soc;

	soc_dev_attr->soc_id = product_id_to_name(exynos_soc_info.product_id);
	soc_ap_id = product_id_to_name(exynos_soc_info.product_id);
	soc_dev = soc_device_register(soc_dev_attr);
	if (IS_ERR(soc_dev))
		goto free_rev;

	soc_device_to_device(soc_dev);
	dev_info(&pdev->dev, "Exynos: CPU[%s] CPU_REV[0x%x] Detected\n",
			product_id_to_name(exynos_soc_info.product_id),
			exynos_soc_info.revision);
	return 0;
free_rev:
	kfree(soc_dev_attr->revision);
free_soc:
	kfree(soc_dev_attr);
	return -EINVAL;
}

static struct platform_driver exynos_chipid_driver __refdata = {
	.driver = {
		.name = "exynos-chipid",
		.of_match_table = of_exynos_chipid_ids,
	},
	.probe = exynos_chipid_probe,
};

static int __init exynos_chipid_init(void)
{
	exynos_chipid_early_init();
	return platform_driver_register(&exynos_chipid_driver);
}
core_initcall(exynos_chipid_init);

/*
 *  sysfs implementation for exynos-snapshot
 *  you can access the sysfs of exynos-snapshot to /sys/devices/system/chip-id
 *  path.
 */
static struct bus_type chipid_subsys = {
	.name = "chip-id",
	.dev_name = "chip-id",
};

static ssize_t chipid_product_id_show(struct kobject *kobj,
			         struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, 10, "%08X\n", exynos_soc_info.product_id);
}

// [BigData] For display of HRM Apk
static ssize_t chipid_ap_id_show(struct kobject *kobj,
			         struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, 30, "%s EVT%d.%d\n", soc_ap_id, exynos_soc_info.revision>>4, exynos_soc_info.revision%16);
}

static ssize_t chipid_unique_id_show(struct kobject *kobj,
			         struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, 20, "%010LX\n", exynos_soc_info.unique_id);
}

static ssize_t chipid_lot_id_show(struct kobject *kobj,
			         struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, 14, "%08X\n", exynos_soc_info.lot_id);
}

static ssize_t chipid_revision_show(struct kobject *kobj,
			         struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, 14, "%08X\n", exynos_soc_info.revision);
}

static ssize_t chipid_evt_ver_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	if (exynos_soc_info.revision == 0)
		return snprintf(buf, 14, "EVT0\n");
	else
		return snprintf(buf, 14, "EVT%1X.%1X\n",
				exynos_soc_info.main_rev,
				exynos_soc_info.sub_rev);
}

static struct kobj_attribute chipid_product_id_attr =
        __ATTR(product_id, 0644, chipid_product_id_show, NULL);

static struct kobj_attribute chipid_ap_id_attr =
        __ATTR(ap_id, 0644, chipid_ap_id_show, NULL);

static struct kobj_attribute chipid_unique_id_attr =
        __ATTR(unique_id, 0644, chipid_unique_id_show, NULL);

static struct kobj_attribute chipid_lot_id_attr =
        __ATTR(lot_id, 0644, chipid_lot_id_show, NULL);

static struct kobj_attribute chipid_revision_attr =
        __ATTR(revision, 0644, chipid_revision_show, NULL);

static struct kobj_attribute chipid_evt_ver_attr =
        __ATTR(evt_ver, 0644, chipid_evt_ver_show, NULL);

static struct attribute *chipid_sysfs_attrs[] = {
	&chipid_product_id_attr.attr,
	&chipid_ap_id_attr.attr,
	&chipid_unique_id_attr.attr,
	&chipid_lot_id_attr.attr,
	&chipid_revision_attr.attr,
	&chipid_evt_ver_attr.attr,
	NULL,
};

static struct attribute_group chipid_sysfs_group = {
	.attrs = chipid_sysfs_attrs,
};

static const struct attribute_group *chipid_sysfs_groups[] = {
	&chipid_sysfs_group,
	NULL,
};

static int __init chipid_sysfs_init(void)
{
	int ret = 0;

	ret = subsys_system_register(&chipid_subsys, chipid_sysfs_groups);
	if (ret)
		pr_err("fail to register exynos-snapshop subsys\n");

	return ret;
}
late_initcall(chipid_sysfs_init);


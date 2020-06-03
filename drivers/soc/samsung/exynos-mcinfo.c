/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *	      http://www.samsung.com/
 *
 * Exynos - Support Memory controller specific information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/debugfs.h>

struct mcinfo_data {
	struct device	*dev;
	void __iomem	**base;

	u32		basecnt;
	u32		irqcnt;
	u32		bit_array[2];

	struct notifier_block panic_nb;
};

#if defined(CONFIG_MCINFO_SYSFS)
static ssize_t show_exynos_ref_rate(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct mcinfo_data *data = dev_get_drvdata(dev);
	ssize_t count = 0;
	unsigned int tmp;
	int i = 0;

	count = snprintf(buf, PAGE_SIZE, "HW Refreshing rate\n");

	for (i = 0; i < data->basecnt; i++) {
		tmp = __raw_readl(data->base[i])
			<< (31 - data->bit_array[0] - data->bit_array[1])
			>> (31 - data->bit_array[1]);
		count += snprintf(buf + count, PAGE_SIZE,
			"HwTempRange#%d: 0x%x\n", i, tmp);
	}

	return count;
}
static DEVICE_ATTR(ref_rate, 0640, show_exynos_ref_rate, NULL);

static struct attribute *exynos_mcinfo_sysfs_entries[] = {
	&dev_attr_ref_rate.attr,
	NULL,
};

static struct attribute_group exynos_mcinfo_attr_group = {
	.name	= "ref_rate",
	.attrs	= exynos_mcinfo_sysfs_entries,
};
#endif /* MCINFO_SYSFS */

static irqreturn_t exynos_mc_irq_handler(int irq, void *p)
{
	struct mcinfo_data *data = p;
	unsigned int tmp;
	int i;

	for (i = 0; i < data->basecnt; i++) {
		tmp = __raw_readl(data->base[i])
			<< (31 - data->bit_array[0] - data->bit_array[1])
			>> (31 - data->bit_array[1]);
		pr_info("[SW Trip] HwTempRange#%d: 0x%x\n", i, tmp);
	}

	panic("[SW Trip] Memory temperature is too high (irqnum: %d)\n", irq);

	return IRQ_HANDLED;
}

static int exynos_mcinfo_notify_panic(struct notifier_block *nb,
		unsigned long event, void *unused)
{
	struct mcinfo_data *data = container_of(nb, struct mcinfo_data, panic_nb);
	unsigned int tmp;
	int i = 0;

	for (i = 0; i < data->basecnt; i++) {
		tmp = __raw_readl(data->base[i])
			<< (31 - data->bit_array[0] - data->bit_array[1])
			>> (31 - data->bit_array[1]);
		pr_info("HwTempRange#%d: 0x%x\n", i, tmp);
	}

	return NOTIFY_DONE;
}

#if defined(CONFIG_OF)
static int exynos_mcinfo_parse_dt(struct device_node *np, struct mcinfo_data *data)
{
	int i, ret = 0;
	unsigned int irqnum = 0;

	if (!np)
		return -ENODEV;

	ret = of_property_read_u32(np, "basecnt", &data->basecnt);
	if (ret) {
		dev_err(data->dev, "Failed to get basecnt value!\n");
		return ret;
	}

	ret = of_property_read_u32(np, "irqcnt", &data->irqcnt);
	if (ret) {
		dev_err(data->dev, "Failed to get irqcnt value!\n");
		return ret;
	}

	ret = of_property_read_u32_array(np, "bit_field", (u32 *)&data->bit_array,
				(size_t)(ARRAY_SIZE(data->bit_array)));
	if (ret) {
		dev_err(data->dev, "Failed to get bit field information!\n");
		return ret;
	}

	if (data->irqcnt) {
		/* Register IRQ for SW trip */
		for (i = 0; i < data->irqcnt; i++) {
			irqnum = irq_of_parse_and_map(data->dev->of_node, i);
			if (irqnum < 0) {
				dev_err(data->dev, "Failed to get IRQ map\n");
				return -EINVAL;
			}
			ret = devm_request_irq(data->dev, irqnum,
					exynos_mc_irq_handler,
					IRQF_SHARED, dev_name(data->dev), data);
			if (ret)
				return ret;
		}
	}

	return 0;
}
#else
static int exynos_mcinfo_parse_dt(struct device_node *np, struct mcinfo_data *data)
{
	return -EINVAL;
}
#endif /* OF */

static int __devinit exynos_mcinfo_probe(struct platform_device *pdev)
{
	struct mcinfo_data *data;
	struct resource *res;
	int i, ret = 0;

	data = devm_kzalloc(&pdev->dev, sizeof(struct mcinfo_data), GFP_KERNEL);
	if (!data) {
		pr_err("%s:Not enough memory\n", __func__);
		return -ENOMEM;
	}

	data->dev = &pdev->dev;
	dev_set_drvdata(data->dev, data);

	ret = exynos_mcinfo_parse_dt(data->dev->of_node, data);
	if (ret) {
		dev_err(data->dev, "Failed to parse device tree\n");
		return ret;
	}

	/* Allocate memory for Memory controller base address */
	if (data->basecnt) {
		data->base = kzalloc((sizeof(void __iomem *)) * data->basecnt,
					GFP_KERNEL);
		if (data->base == NULL) {
			dev_err(data->dev, "Failed to allocate memory\n");
			return -ENOMEM;
		}
		for (i = 0; i < data->basecnt; i++) {
			res = platform_get_resource(pdev, IORESOURCE_MEM, i);
			data->base[i] = devm_ioremap_resource(&pdev->dev, res);
			if (IS_ERR(data->base[i])) {
				ret = PTR_ERR(data->base[i]);
				kfree(data->base);
				return ret;
			}
		}
	}

#if defined(CONFIG_MCINFO_SYSFS)
	ret = sysfs_create_group(&data->dev->kobj,
					&exynos_mcinfo_attr_group);
	if (ret)
		dev_warn(data->dev, "Failed to create sysfs for MR4\n");
#endif /* MCINFO_SYSFS */

	/* Register Panic notifier */
	data->panic_nb.notifier_call = exynos_mcinfo_notify_panic;
	data->panic_nb.next = NULL;
	data->panic_nb.priority = 0;
	atomic_notifier_chain_register(&panic_notifier_list, &data->panic_nb);

	dev_info(data->dev, "probe finished!\n");
	return 0;
}

static int __devexit exynos_mcinfo_remove(struct platform_device *pdev)
{
	struct mcinfo_data *data = platform_get_drvdata(pdev);

#if defined(CONFIG_MCINFO_SYSFS)
	sysfs_remove_group(&data->dev->kobj,
				&exynos_mcinfo_attr_group);
#endif /* MCINFO_SYSFS */

	platform_set_drvdata(pdev, NULL);

	kfree(data->base);

	return 0;
}

static const struct of_device_id exynos_mcinfo_match[] = {
	{ .compatible	= "samsung,exynos-mcinfo", },
	{ },
};
MODULE_DEVICE_TABLE(of, exynos_mcinfo_match);

static struct platform_driver exynos_mcinfo_driver = {
	.probe		= exynos_mcinfo_probe,
	.remove		= exynos_mcinfo_remove,
	.driver	= {
		.name	= "exynos-mcinfo",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(exynos_mcinfo_match),
	},
};
module_platform_driver(exynos_mcinfo_driver);

MODULE_AUTHOR("Eunok Jo <eunok25.jo@samsung.com");
MODULE_DESCRIPTION("Samsung EXYNOS Memory controller specific information");
MODULE_LICENSE("GPU v2");

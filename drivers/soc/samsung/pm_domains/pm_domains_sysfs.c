/* linux/arch/arm/mach-exynos/dev-runtime_pm.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *              http://www.samsung.com
 *
 * EXYNOS - Runtime PM Test Driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/sched.h>

#include <soc/samsung/pm_domains-cal.h>

#if defined(CONFIG_SOC_EXYNOS5433)
char *pd_name[] = {"pd-maudio", "pd-mfc", "pd-hevc", "pd-gscl", "pd-g3d", "pd-disp", "pd-mscl", "pd-g2d", "pd-isp", "pd-cam0", "pd-cam1",};
#elif defined(CONFIG_SOC_EXYNOS7420)
char *pd_name[] = {"pd-g3d", "pd-cam0", "pd-cam1", "pd-isp0", "pd-isp1", "pd-vpp", "pd-disp", "pd-aud", "pd-mscl", "pd-mfc", };
#elif defined(CONFIG_SOC_EXYNOS7580)
char *pd_name[] = {"pd-aud", "pd-isp", "pd-g3d", "pd-disp", "pd-mfcmscl", };
#elif defined(CONFIG_SOC_EXYNOS8890)
char *pd_name[] = {"pd-isp0", "pd-isp1", "pd-cam1", "pd-cam0", "pd-mscl", "pd-g3d", "pd-disp0","pd-aud","pd-mfc","pd-disp1", };
#endif

struct platform_device exynos_device_runtime_pm = {
	.name	= "runtime_pm_test",
	.id	= -1,
};

static ssize_t show_power_domain(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct device_node *np;
	struct platform_device *pdev;
	int ret = 0, result = 0;

	for_each_compatible_node(np, NULL, "samsung,exynos-pd") {
		struct exynos_pm_domain *pd;

		/* skip unmanaged power domain */
		if (!of_device_is_available(np))
			continue;

		pdev = of_find_device_by_node(np);
		if (!pdev)
			continue;
		pd = platform_get_drvdata(pdev);
		if (strcmp(pd->name, dev_name(dev)))
			continue;

		if (pd->check_status(pd) == 1)
			result = 1;
		else if (pd->check_status(pd) == 0)
			result = 0;
		else
			result = -1;

		ret += snprintf(buf+ret, PAGE_SIZE-ret, "%d\n", result);
	}

	return ret;
}

static int exynos_pd_power_on(struct device *dev, const char * device_name)
{
	struct platform_device *pdev;
	struct device_node *np;
	int ret = 0;
	struct gpd_timing_data gpd_td = {
		.stop_latency_ns = 50000,
		.start_latency_ns = 50000,
		.save_state_latency_ns = 500000,
		.restore_state_latency_ns = 500000,
	};

	for_each_compatible_node(np, NULL, "samsung,exynos-pd") {
		struct exynos_pm_domain *pd;

		/* skip unmanaged power domain */
		if (!of_device_is_available(np))
			continue;

		pdev = of_find_device_by_node(np);
		if (!pdev)
			continue;
		pd = platform_get_drvdata(pdev);

		if (strcmp(pd->name, device_name))
			continue;

		if (pd->check_status(pd)) {
			pr_err("PM DOMAIN: %s is already on.\n", pd->name);
			break;
		}

		while (1) {
			ret = __pm_genpd_add_device(&pd->genpd, dev, &gpd_td);
			if (ret != -EAGAIN)
				break;
			cond_resched();
		}
		if (!ret) {
			pm_genpd_dev_need_restore(dev, true);
			pr_info("PM DOMAIN: %s, Device : %s Registered\n", pd->name, dev_name(dev));
		} else
			pr_err("PM DOMAIN: %s cannot add device %s\n", pd->name, dev_name(dev));

		pm_runtime_enable(dev);
		pm_runtime_get_sync(dev);
		if(pd->check_status(pd))
			pr_info("%s: power on.\n", pd->name);
		else
			pr_info("%s: power still off.\n", pd->name);
	}

	return ret;

}

static int exynos_pd_power_off(struct device *dev, const char * device_name)
{
	struct platform_device *pdev;
	struct device_node *np;
	int ret = 0;

	for_each_compatible_node(np, NULL, "samsung,exynos-pd") {
		struct exynos_pm_domain *pd;

		/* skip unmanaged power domain */
		if (!of_device_is_available(np))
			continue;

		pdev = of_find_device_by_node(np);
		if (!pdev)
			continue;
		pd = platform_get_drvdata(pdev);

		if (strcmp(pd->name, device_name))
			continue;

		if (!pd->check_status(pd)) {
			pr_err("PM DOMAIN: %s is already off.\n", pd->name);
			break;
		}

		pm_runtime_put_sync(dev);
		pm_runtime_disable(dev);

		while (1) {
			ret = pm_genpd_remove_device(&pd->genpd, dev);
			if (ret != -EAGAIN)
				break;
			cond_resched();
		}
		if (ret)
			pr_err("PM DOMAIN: %s cannot remove device %s\n", pd->name, dev_name(dev));
		if(!(pd->check_status(pd)))
			pr_info("%s: power off.\n", pd->name);
		else
			pr_info("%s: power still on.\n", pd->name);
	}

	return ret;

}

static int exynos_pd_longrun_test(struct device *dev, const char * device_name)
{
	struct platform_device *pdev;
	struct device_node *np;
	int ret = 0;
	struct gpd_timing_data gpd_td = {
		.stop_latency_ns = 50000,
		.start_latency_ns = 50000,
		.save_state_latency_ns = 500000,
		.restore_state_latency_ns = 500000,
	};

	for_each_compatible_node(np, NULL, "samsung,exynos-pd") {
		struct exynos_pm_domain *pd;
		int i;

		/* skip unmanaged power domain */
		if (!of_device_is_available(np))
			continue;

		pdev = of_find_device_by_node(np);
		if (!pdev)
			continue;
		pd = platform_get_drvdata(pdev);

		if (strcmp(pd->name, device_name))
			continue;

		if (pd->check_status(pd)) {
			pr_err("PM DOMAIN: %s is working. Stop testing\n", pd->genpd.name);
			break;
		}

		while (1) {
			ret = __pm_genpd_add_device(&pd->genpd, dev, &gpd_td);
			if (ret != -EAGAIN)
				break;
			cond_resched();
		}
		if (!ret) {
			pm_genpd_dev_need_restore(dev, true);
			pr_info("PM DOMAIN: %s, Device : %s Registered\n", pd->genpd.name, dev_name(dev));
		} else
			pr_err("PM DOMAIN: %s cannot add device %s\n", pd->genpd.name, dev_name(dev));

		pr_info("%s: test start.\n", pd->genpd.name);
		pm_runtime_enable(dev);
		for (i=0; i<100; i++) {
			pm_runtime_get_sync(dev);
			mdelay(50);
			pm_runtime_put_sync(dev);
			mdelay(50);
		}
		pr_info("%s: test done.\n", pd->genpd.name);
		pm_runtime_disable(dev);

		while (1) {
			ret = pm_genpd_remove_device(&pd->genpd, dev);
			if (ret != -EAGAIN)
				break;
			cond_resched();
		}
		if (ret)
			pr_err("PM DOMAIN: %s cannot remove device %s\n", pd->name, dev_name(dev));
	}

	return ret;
}

static ssize_t store_power_domain_test(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int test_name;

	if (!sscanf(buf, "%1d", &test_name))
		return -EINVAL;

	switch (test_name) {
	case 1:
		exynos_pd_power_on(dev, dev_name(dev));
		break;

	case 0:
		exynos_pd_power_off(dev, dev_name(dev));
		break;

	case 2:
		exynos_pd_longrun_test(dev, dev_name(dev));
		break;

	default:
		printk("echo \"test[0|1|2]\" > control\n");
	}

	return count;
}

static DEVICE_ATTR(control, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, show_power_domain, store_power_domain_test);

static struct attribute *control_device_attrs[] = {
	&dev_attr_control.attr,
	NULL,
};

static const struct attribute_group control_device_attr_group = {
	.attrs = control_device_attrs,
};

static int runtime_pm_test_probe(struct platform_device *pdev)
{
	struct class *runtime_pm_class;
	struct device *runtime_pm_dev;
	int ret, i;

	runtime_pm_class = class_create(THIS_MODULE, "runtime_pm");
#if defined(CONFIG_SOC_EXYNOS5433) || defined(CONFIG_SOC_EXYNOS7420) || defined(CONFIG_SOC_EXYNOS7580) || defined(CONFIG_SOC_EXYNOS8890)
	for (i = 0; i < ARRAY_SIZE(pd_name); i++) {
		runtime_pm_dev = device_create(runtime_pm_class, NULL, 0, NULL, pd_name[i]);
		ret = sysfs_create_group(&runtime_pm_dev->kobj, &control_device_attr_group);
		if (ret) {
			pr_err("Runtime PM Test : error to create sysfs\n");
			return -EINVAL;
		}
	}
#else
	runtime_pm_dev = device_create(runtime_pm_class, NULL, 0, NULL, "test");
	ret = sysfs_create_group(&runtime_pm_dev->kobj, &control_device_attr_group);
	if (ret) {
		pr_err("Runtime PM Test : error to create sysfs\n");
		return -EINVAL;
	}
#endif
	pm_runtime_enable(&pdev->dev);

	return 0;
}

static int runtime_pm_test_runtime_suspend(struct device *dev)
{
	pr_info("Runtime PM Test : Runtime_Suspend\n");
	return 0;
}

static int runtime_pm_test_runtime_resume(struct device *dev)
{
	pr_info("Runtime PM Test : Runtime_Resume\n");
	return 0;
}

static struct dev_pm_ops pm_ops = {
	.runtime_suspend = runtime_pm_test_runtime_suspend,
	.runtime_resume = runtime_pm_test_runtime_resume,
};

static struct platform_driver runtime_pm_test_driver = {
	.probe		= runtime_pm_test_probe,
	.driver		= {
		.name	= "runtime_pm_test",
		.owner	= THIS_MODULE,
		.pm	= &pm_ops,
	},
};

static int __init runtime_pm_test_driver_init(void)
{
	int ret;

	ret = platform_device_register(&exynos_device_runtime_pm);
	if (ret) {
		pr_err("Runtime PM Test : failed to register platform device.\n");
		return ret;
	}

	return platform_driver_register(&runtime_pm_test_driver);
}
arch_initcall_sync(runtime_pm_test_driver_init);

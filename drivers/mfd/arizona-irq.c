/*
 * Arizona interrupt support
 *
 * Copyright 2014 CirrusLogic, Inc.
 * Copyright 2012 Wolfson Microelectronics plc
 *
 * Author: Mark Brown <broonie@opensource.wolfsonmicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>

#include <linux/mfd/arizona/core.h>
#include <linux/mfd/arizona/registers.h>

#include "arizona.h"

int arizona_map_irq(struct arizona *arizona, int irq)
{
	int ret;

	if (arizona->aod_irq_chip) {
		ret = regmap_irq_get_virq(arizona->aod_irq_chip, irq);
		if (ret >= 0)
			return ret;
	}

	if (arizona->irq_chip)
		return regmap_irq_get_virq(arizona->irq_chip, irq);

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(arizona_map_irq);

int arizona_request_irq(struct arizona *arizona, int irq, const char *name,
			   irq_handler_t handler, void *data)
{
	irq = arizona_map_irq(arizona, irq);
	if (irq < 0)
		return irq;

	return request_threaded_irq(irq, NULL, handler, IRQF_ONESHOT,
				    name, data);
}
EXPORT_SYMBOL_GPL(arizona_request_irq);

void arizona_free_irq(struct arizona *arizona, int irq, void *data)
{
	irq = arizona_map_irq(arizona, irq);
	if (irq < 0)
		return;

	free_irq(irq, data);
}
EXPORT_SYMBOL_GPL(arizona_free_irq);

int arizona_set_irq_wake(struct arizona *arizona, int irq, int on)
{
	irq = arizona_map_irq(arizona, irq);
	if (irq < 0)
		return irq;

	return irq_set_irq_wake(irq, on);
}
EXPORT_SYMBOL_GPL(arizona_set_irq_wake);

static irqreturn_t arizona_boot_done(int irq, void *data)
{
	struct arizona *arizona = data;

	dev_dbg(arizona->dev, "Boot done\n");

	return IRQ_HANDLED;
}

static irqreturn_t arizona_ctrlif_err(int irq, void *data)
{
	struct arizona *arizona = data;

	/*
	 * For pretty much all potential sources a register cache sync
	 * won't help, we've just got a software bug somewhere.
	 */
	dev_err(arizona->dev, "Control interface error\n");

	return IRQ_HANDLED;
}

/*
 * Examine the IRQ pin status to see if we're really done
 * if the interrupt controller can't do it for us.
 */
static bool arizona_irq_still_pending(struct arizona *arizona)
{
	bool still_pending = false;

	if (arizona->pdata.irq_gpio) {
		if (arizona->pdata.irq_flags & IRQF_TRIGGER_RISING &&
		    gpio_get_value_cansleep(arizona->pdata.irq_gpio)) {
			still_pending = true;
		} else if (arizona->pdata.irq_flags & IRQF_TRIGGER_FALLING &&
			   !gpio_get_value_cansleep(arizona->pdata.irq_gpio)) {
			still_pending = true;
		}
	}
	return still_pending;
}

static irqreturn_t arizona_irq_thread(int irq, void *data)
{
	struct arizona *arizona = data;
	unsigned int val, nest_irq;
	int ret;

	ret = pm_runtime_get_sync(arizona->dev);
	if (ret < 0) {
		dev_err(arizona->dev, "Failed to resume device: %d\n", ret);
		return IRQ_NONE;
	}

	do {
		if (arizona->aod_irq_chip && arizona->irq_chip) {
			/* Only handle each domain if it has triggered an IRQ */
			ret = regmap_read(arizona->regmap, ARIZONA_AOD_IRQ1,
					  &val);
			if (ret == 0 && val != 0) {
				nest_irq = irq_find_mapping(arizona->virq, 0);
				handle_nested_irq(nest_irq);
			} else if (ret != 0) {
				dev_err(arizona->dev,
					"Failed to read AOD IRQ1 %d\n",
					ret);
			}

			ret = regmap_read(arizona->regmap,
					  ARIZONA_IRQ_PIN_STATUS,
					  &val);
			if (ret == 0 && val & ARIZONA_IRQ1_STS) {
				nest_irq = irq_find_mapping(arizona->virq, 1);
				handle_nested_irq(nest_irq);
			} else if (ret != 0) {
				dev_err(arizona->dev,
					"Failed to read main IRQ status: %d\n",
					ret);
			}
		} else if (arizona->aod_irq_chip) {
			handle_nested_irq(irq_find_mapping(arizona->virq, 0));
		} else if (arizona->irq_chip) {
			handle_nested_irq(irq_find_mapping(arizona->virq, 1));
		}
	} while (arizona_irq_still_pending(arizona));

	pm_runtime_mark_last_busy(arizona->dev);
	pm_runtime_put_autosuspend(arizona->dev);

	return IRQ_HANDLED;
}

static void arizona_irq_dummy(struct irq_data *data)
{
}

static int arizona_irq_set_wake(struct irq_data *data, unsigned int on)
{
	struct arizona *arizona = irq_data_get_irq_chip_data(data);

	return irq_set_irq_wake(arizona->irq, on);
}

static struct irq_chip arizona_irq_chip = {
	.name        	= "arizona",
	.irq_disable	= arizona_irq_dummy,
	.irq_enable 	= arizona_irq_dummy,
	.irq_ack    	= arizona_irq_dummy,
	.irq_mask   	= arizona_irq_dummy,
	.irq_unmask 	= arizona_irq_dummy,
	.irq_set_wake	= arizona_irq_set_wake,
};

static struct lock_class_key arizona_irq_lock_class;

static int arizona_irq_map(struct irq_domain *h, unsigned int virq,
			      irq_hw_number_t hw)
{
	struct arizona *data = h->host_data;

	irq_set_chip_data(virq, data);
	irq_set_lockdep_class(virq, &arizona_irq_lock_class);
	irq_set_chip_and_handler(virq, &arizona_irq_chip, handle_simple_irq);
	irq_set_nested_thread(virq, 1);

	/* ARM needs us to explicitly flag the IRQ as valid
	 * and will set them noprobe when we do so. */
#ifdef CONFIG_ARM
	set_irq_flags(virq, IRQF_VALID);
#else
	irq_set_noprobe(virq);
#endif

	return 0;
}

static struct irq_domain_ops arizona_domain_ops = {
	.map	= arizona_irq_map,
	.xlate	= irq_domain_xlate_twocell,
};

int arizona_irq_init(struct arizona *arizona)
{
	int flags = IRQF_ONESHOT;
	int ret, i;
	const struct regmap_irq_chip *aod, *irq;
	struct irq_data *irq_data;
	unsigned int irq_ctrl_reg = ARIZONA_IRQ_CTRL_1;

	arizona->ctrlif_error = true;

	switch (arizona->type) {
#ifdef CONFIG_MFD_WM5102
	case WM5102:
		aod = &wm5102_aod;
		irq = &wm5102_irq;

		arizona->ctrlif_error = false;
		break;
#endif
#ifdef CONFIG_MFD_FLORIDA
	case WM8280:
	case WM5110:
		aod = &florida_aod;

		switch (arizona->rev) {
		case 0 ... 2:
			irq = &florida_irq;
			break;
		default:
			irq = &florida_revd_irq;
			break;
		}

		arizona->ctrlif_error = false;
		break;
#endif
#ifdef CONFIG_MFD_CLEARWATER
	case WM8285:
	case WM1840:
		aod = &clearwater_irq;
		irq = NULL;

		arizona->ctrlif_error = false;
		irq_ctrl_reg = CLEARWATER_IRQ1_CTRL;
		break;
#endif
#ifdef CONFIG_MFD_LARGO
	case WM1831:
	case CS47L24:
		aod = NULL;
		irq = &largo_irq;

		arizona->ctrlif_error = false;
		break;
#endif
#ifdef CONFIG_MFD_WM8997
	case WM8997:
		aod = &wm8997_aod;
		irq = &wm8997_irq;

		arizona->ctrlif_error = false;
		break;
#endif
#ifdef CONFIG_MFD_VEGAS
	case WM8998:
	case WM1814:
		aod = &vegas_aod;
		irq = &vegas_irq;

		arizona->ctrlif_error = false;
		break;
#endif
#ifdef CONFIG_MFD_MARLEY
	case CS47L35:
		aod = &marley_irq;
		irq = NULL;

		arizona->ctrlif_error = false;
		irq_ctrl_reg = CLEARWATER_IRQ1_CTRL;
		break;
#endif
#ifdef CONFIG_MFD_MOON
	case CS47L90:
	case CS47L91:
		aod = &moon_irq;
		irq = NULL;

		arizona->ctrlif_error = false;
		irq_ctrl_reg = CLEARWATER_IRQ1_CTRL;
		break;
#endif
	default:
		BUG_ON("Unknown Arizona class device" == NULL);
		return -EINVAL;
	}

	switch (arizona->type) {
	case WM5102:
	case WM5110:
	case WM8997:
	case WM8998:
	case WM1814:
	case WM8280:
		/* Disable all wake sources by default */
		regmap_write(arizona->regmap, ARIZONA_WAKE_CONTROL, 0);
		break;
	default:
		break;
	}

	/* Read the flags from the interrupt controller if not specified */
	if (!arizona->pdata.irq_flags) {
		irq_data = irq_get_irq_data(arizona->irq);
		if (!irq_data) {
			dev_err(arizona->dev, "Invalid IRQ: %d\n",
				arizona->irq);
			return -EINVAL;
		}

		arizona->pdata.irq_flags = irqd_get_trigger_type(irq_data);
		switch (arizona->pdata.irq_flags) {
		case IRQF_TRIGGER_LOW:
		case IRQF_TRIGGER_HIGH:
		case IRQF_TRIGGER_RISING:
		case IRQF_TRIGGER_FALLING:
			break;

		case IRQ_TYPE_NONE:
		default:
			/* Device default */
			arizona->pdata.irq_flags = IRQF_TRIGGER_LOW;
			break;
		}
	}

	if (arizona->pdata.irq_flags & (IRQF_TRIGGER_HIGH |
					IRQF_TRIGGER_RISING)) {
		ret = regmap_update_bits(arizona->regmap, irq_ctrl_reg,
					 ARIZONA_IRQ_POL, 0);
		if (ret != 0) {
			dev_err(arizona->dev, "Couldn't set IRQ polarity: %d\n",
				ret);
			goto err;
		}
	}

	flags |= arizona->pdata.irq_flags;

	/* Allocate a virtual IRQ domain to distribute to the regmap domains */
	arizona->virq = irq_domain_add_linear(NULL, 2, &arizona_domain_ops,
					      arizona);
	if (!arizona->virq) {
		dev_err(arizona->dev, "Failed to add core IRQ domain\n");
		ret = -EINVAL;
		goto err;
	}

	if (aod) {
		ret = regmap_add_irq_chip(arizona->regmap,
					  irq_create_mapping(arizona->virq, 0),
					  IRQF_ONESHOT, 0, aod,
					  &arizona->aod_irq_chip);
		if (ret != 0) {
			dev_err(arizona->dev, "Failed to add AOD IRQs: %d\n", ret);
			goto err;
		}
	}

	if (irq) {
		ret = regmap_add_irq_chip(arizona->regmap,
					  irq_create_mapping(arizona->virq, 1),
					  IRQF_ONESHOT, 0, irq,
					  &arizona->irq_chip);
		if (ret != 0) {
			dev_err(arizona->dev, "Failed to add main IRQs: %d\n", ret);
			goto err_aod;
		}
	}

	/* Used to emulate edge trigger and to work around broken pinmux */
	if (arizona->pdata.irq_gpio) {
		if (gpio_to_irq(arizona->pdata.irq_gpio) != arizona->irq) {
			dev_warn(arizona->dev, "IRQ %d is not GPIO %d (%d)\n",
				 arizona->irq, arizona->pdata.irq_gpio,
				 gpio_to_irq(arizona->pdata.irq_gpio));
			arizona->irq = gpio_to_irq(arizona->pdata.irq_gpio);
		}

		ret = devm_gpio_request_one(arizona->dev,
					    arizona->pdata.irq_gpio,
					    GPIOF_IN, "arizona IRQ");
		if (ret != 0) {
			dev_err(arizona->dev,
				"Failed to request IRQ GPIO %d:: %d\n",
				arizona->pdata.irq_gpio, ret);
			arizona->pdata.irq_gpio = 0;
		}
	}

	ret = request_threaded_irq(arizona->irq, NULL, arizona_irq_thread,
				   flags, "arizona", arizona);

	if (ret != 0) {
		dev_err(arizona->dev, "Failed to request primary IRQ %d: %d\n",
			arizona->irq, ret);
		goto err_main_irq;
	}

	/* Make sure the boot done IRQ is unmasked for resumes */
	i = arizona_map_irq(arizona, ARIZONA_IRQ_BOOT_DONE);
	ret = request_threaded_irq(i, NULL, arizona_boot_done, IRQF_ONESHOT,
				   "Boot done", arizona);
	if (ret != 0) {
		dev_err(arizona->dev, "Failed to request boot done %d: %d\n",
			arizona->irq, ret);
		goto err_boot_done;
	}

	/* Handle control interface errors in the core */
	if (arizona->ctrlif_error) {
		i = arizona_map_irq(arizona, ARIZONA_IRQ_CTRLIF_ERR);
		ret = request_threaded_irq(i, NULL, arizona_ctrlif_err,
					   IRQF_ONESHOT,
					   "Control interface error", arizona);
		if (ret != 0) {
			dev_err(arizona->dev,
				"Failed to request CTRLIF_ERR %d: %d\n",
				arizona->irq, ret);
			goto err_ctrlif;
		}
	}

	return 0;

err_ctrlif:
	free_irq(arizona_map_irq(arizona, ARIZONA_IRQ_BOOT_DONE), arizona);
err_boot_done:
	free_irq(arizona->irq, arizona);
err_main_irq:
	regmap_del_irq_chip(irq_create_mapping(arizona->virq, 1),
			    arizona->irq_chip);
err_aod:
	regmap_del_irq_chip(irq_create_mapping(arizona->virq, 0),
			    arizona->aod_irq_chip);
err:
	return ret;
}

int arizona_irq_exit(struct arizona *arizona)
{
	if (arizona->ctrlif_error)
		free_irq(arizona_map_irq(arizona, ARIZONA_IRQ_CTRLIF_ERR),
			 arizona);
	free_irq(arizona_map_irq(arizona, ARIZONA_IRQ_BOOT_DONE), arizona);
	regmap_del_irq_chip(irq_create_mapping(arizona->virq, 1),
			    arizona->irq_chip);
	regmap_del_irq_chip(irq_create_mapping(arizona->virq, 0),
			    arizona->aod_irq_chip);
	free_irq(arizona->irq, arizona);

	return 0;
}

/*
 * drivers/trace/exynos-condbg.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Exynos-Console-Debugger for Exynos SoC
 * This codes are based on fiq_debugger of google
 * /driver/staging/android/fiq_debugger
 *
 * Author: Hosung Kim <hosung0.kim@samsung.com>
 *         Changki Kim <changki.kim@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/console.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/kernel_stat.h>
#include <linux/kmsg_dump.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/timer.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/wakelock.h>
#include <linux/clocksource.h>
#include <linux/bitops.h>
#include <linux/memblock.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/firmware.h>
#include <linux/exynos-ss.h>
#include <soc/samsung/exynos-condbg.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/notifier.h>
#include <soc/samsung/exynos-itmon.h>

#include <asm/debug-monitors.h>
#include <asm/system_misc.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/map.h>
#include <asm/smp_plat.h>

#include "exynos-condbg-dev.h"
#include "exynos-condbg-ringbuf.h"

#define MAX_DEBUGGER_PORTS	(1)
#define ECD_RC_PATH "/data/ecd.rc"
#define PR_ECD "[ECD]"

#ifdef TEST_BIN
#define FW_PATH "/data/"
#else
#define FW_PATH "/vendor/firmware/"
#endif

static struct ecd_interface *interface = NULL;
static bool initial_console_enable = false;
static bool initial_ecd_enable = false;
static bool initial_no_firmware = false;

extern int ecd_init_binary(unsigned long, unsigned long);
extern int ecd_start_binary(unsigned long);

extern struct irq_domain *gic_get_root_irqdomain(unsigned int gic_nr);
extern int gic_irq_domain_map(struct irq_domain *d,
				unsigned int irq, irq_hw_number_t hw);

static struct list_head ecd_ioremap_list;
static struct vm_struct ecd_early_vm;

struct ecd_ioremap_item {
	unsigned long vaddr;
	unsigned long paddr;
	unsigned int size;
	struct list_head list;
};

struct ecd_interface_ops {
	int (*do_bad)(unsigned long, struct pt_regs *);
	int (*do_breakpoint)(unsigned long, struct pt_regs *);
	int (*do_watchpoint)(unsigned long, struct pt_regs *);
	void (*do_break_now)(void);
	int (*get_console_enable)(void);
	int (*get_debug_mode)(void);
	int (*get_debug_panic)(void);
	int (*uart_irq_handler)(int irq, void *dev);

	int (*sysfs_profile_show)(char *);
	int (*sysfs_profile_store)(const char *, int);
	int (*sysfs_enable_show)(char *);
	int (*sysfs_enable_store)(const char *, int);
	int (*sysfs_break_now_store)(const char *, int);
	int (*sysfs_switch_dbg_store)(const char *, int);
};

struct ecd_rc {
	int				setup_idx;
	int				action_idx;
	char				setup[SZ_8][SZ_64];
	char				action[SZ_32][SZ_64];
};

struct ecd_param {
	unsigned int			console_enable;
	unsigned int			debug_panic;
	unsigned int			debug_mode;
	unsigned int			no_sleep;
	unsigned int			count_break;
	struct ecd_rc			rc;
};

struct ecd_interface {
	struct ecd_pdata		*pdata;
	const struct firmware		*fw;
	void				*fw_data;
	size_t				fw_size;
	size_t				fw_addr;
	struct ecd_interface_ops	ops;
	struct ecd_param		param;
	struct platform_device		*pdev;
	char				*output_buf;
	int				uart_irq;

	unsigned int			debug_count;
	bool				fw_loaded;
	bool				fw_ready;
	bool				unhandled_irq;

	spinlock_t			printf_lock;
	spinlock_t			work_lock;
	unsigned int			last_irqs[NR_IRQS];
	struct delayed_work		check_load_firmware;
#ifdef CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE
	spinlock_t			console_lock;
	struct console			console;
	struct tty_port			tty_port;
	struct ecd_ringbuf		*tty_rbuf;
	bool				syslog_dumping;
#endif

};

#ifdef CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE
static struct tty_driver *ecd_tty_driver;
#endif

bool ecd_get_debug_panic(void)
{
	if (interface && interface->fw_loaded) {
		return interface->ops.get_debug_panic();
	} else
		return false;
}

bool ecd_get_enable(void)
{
	if (interface) {
		return interface->fw_loaded;
	} else
		return false;
}

int ecd_get_debug_mode(void)
{
	if (interface && interface->fw_loaded)
		return interface->ops.get_debug_mode();
	else
		return 0;
}

int ecd_do_bad(unsigned long addr, struct pt_regs *regs)
{
	if (interface && interface->fw_loaded)
		return interface->ops.do_bad(addr, regs);
	else
		return 0;
}

int ecd_hook_ioremap(unsigned long paddr, unsigned long vaddr, unsigned int size)
{
	if (initial_ecd_enable) {
		struct ecd_ioremap_item *item =
			kmalloc(sizeof(struct ecd_ioremap_item), GFP_ATOMIC);

		item->paddr = paddr;
		item->vaddr = vaddr;
		item->size = size;

		list_add(&item->list, &ecd_ioremap_list);
	}
	return 0;
}

bool ecd_lookup_check_sfr(unsigned long vaddr)
{
	struct ecd_ioremap_item *item, *next_item;
	struct list_head *list_main = &ecd_ioremap_list;

	list_for_each_entry_safe(item, next_item, list_main, list) {
		if ((vaddr == item->vaddr) ||
			(vaddr > item->vaddr &&
			 vaddr < item->vaddr + item->size))
			return true;
	}
	return false;
}

void ecd_lookup_dump_sfr(unsigned long paddr)
{
	struct ecd_ioremap_item *item, *next_item;
	struct list_head *list_main = &ecd_ioremap_list;
	unsigned long vaddr = 0;

	if (!paddr) {
		list_for_each_entry_safe(item, next_item, list_main, list) {
			ecd_printf("  0x%8zx   |   0x%16zx  |  0x%8zx    |\n",
				item->paddr, item->vaddr, item->size);
		}
	} else {
		list_for_each_entry_safe(item, next_item, list_main, list) {
			if (paddr == item->paddr) {
				vaddr = item->vaddr;
			} else if (paddr > item->paddr &&
				paddr < item->paddr + item->size) {
				long sub = paddr - item->paddr;
				vaddr = item->vaddr + sub;
			} else
				vaddr = 0;

			if (vaddr) {
				ecd_printf("  0x%8zx   |   0x%16zx  |  0x%8zx    |\n",
					paddr, vaddr, item->size);
			}
		}
	}
}

#ifdef CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE
static void ecd_begin_syslog_dump(void)
{
	interface->syslog_dumping = true;
}

static void ecd_end_syslog_dump(void)
{
	interface->syslog_dumping = false;
}
#else
extern int do_syslog(int type, char __user *bug, int count);
static void ecd_begin_syslog_dump(void)
{
	do_syslog(5 /* clear */, NULL, 0);
}

static void ecd_end_syslog_dump(void)
{
	ecd_dump_kernel_log();
}
#endif

static void ecd_do_sysrq(char rq)
{
	ecd_begin_syslog_dump();
	handle_sysrq(rq);
	ecd_end_syslog_dump();
}

static void ecd_uart_putc(char c)
{
	if (interface && interface->pdata->uart_putc)
		interface->pdata->uart_putc(interface->pdev, c);
}

static void ecd_uart_puts(char *s)
{
	unsigned c;
	while ((c = *s++)) {
		if (c == '\n')
			ecd_uart_putc('\r');
		ecd_uart_putc(c);
	}
}

static int ecd_uart_getc(void)
{
	if (interface && interface->pdata->uart_getc)
		return interface->pdata->uart_getc(interface->pdev);
	else
		return -1;
}

static bool ecd_uart_check_break(void)
{
	int c = ecd_uart_getc();
	bool ret = false;

	if (c == 0x3) {
		ecd_uart_puts("BREAK\n");
		ret = true;
	}
	return ret;
}

static void ecd_uart_flush(void)
{
	if (interface && interface->pdata->uart_flush)
		interface->pdata->uart_flush(interface->pdev);
}

static void ecd_uart_init(void)
{
	if (interface && interface->pdata->uart_init)
		interface->pdata->uart_init(interface->pdev);
}

static void ecd_uart_enable(void)
{
	/* TODO: clk control */
	if (interface && interface->pdata->uart_enable)
		interface->pdata->uart_enable(interface->pdev);
}

static void ecd_uart_disable(void)
{
	if (interface && interface->pdata->uart_disable)
		interface->pdata->uart_disable(interface->pdev);
	/* TODO: clk control */
}

#if defined(CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE)
struct tty_driver *ecd_console_device(struct console *co, int *index)
{
	*index = co->index;
	return ecd_tty_driver;
}


static void ecd_console_write(struct console *co,
				const char *s, unsigned int count)
{
	unsigned long flags;

	if (!interface->fw_loaded) {
		if (!interface->param.console_enable)
			return;
	} else {
		if (!interface->ops.get_console_enable() &&
			!interface->syslog_dumping)
			return;
	}
	ecd_uart_enable();
	spin_lock_irqsave(&interface->console_lock, flags);
	while (count--) {
		if (*s == '\n')
			ecd_uart_putc('\r');
		ecd_uart_putc(*s++);
	}
	ecd_uart_flush();
	spin_unlock_irqrestore(&interface->console_lock, flags);
	ecd_uart_disable();
}

static struct console ecd_console = {
	.name = "ttyECD",
	.device = ecd_console_device,
	.write = ecd_console_write,
	.flags = CON_PRINTBUFFER | CON_ANYTIME | CON_ENABLED,
};

int ecd_tty_open(struct tty_struct *tty, struct file *filp)
{
	int line = tty->index;
	struct ecd_interface **interfaces = tty->driver->driver_state;
	struct ecd_interface *interface = interfaces[line];

	return tty_port_open(&interface->tty_port, tty, filp);
}

void ecd_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(tty->port, tty, filp);
}

int ecd_tty_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	int i;
	int line = tty->index;
	struct ecd_interface **interfaces = tty->driver->driver_state;
	struct ecd_interface *interface = interfaces[line];
	unsigned long flags;

	if (!interface->fw_loaded) {
		if (!interface->param.console_enable)
			return count;
	} else {
		if (!interface->ops.get_console_enable())
			return count;
	}

	ecd_uart_enable();
	spin_lock_irqsave(&interface->console_lock, flags);
	for (i = 0; i < count; i++)
		ecd_uart_putc(*buf++);

	spin_unlock_irqrestore(&interface->console_lock, flags);
	ecd_uart_disable();

	return count;
}

int  ecd_tty_write_room(struct tty_struct *tty)
{
	return 16;
}

static const struct tty_port_operations ecd_tty_port_ops;

static const struct tty_operations ecd_tty_driver_ops = {
	.write = ecd_tty_write,
	.write_room = ecd_tty_write_room,
	.open = ecd_tty_open,
	.close = ecd_tty_close,
};

static int ecd_tty_init(void)
{
	int ret;
	struct ecd_interface **interfaces = NULL;

	interfaces = kzalloc(sizeof(*interfaces) * MAX_DEBUGGER_PORTS, GFP_KERNEL);
	if (!interfaces) {
		pr_err("Failed to allocate console debugger state structres\n");
		return -ENOMEM;
	}

	ecd_tty_driver = alloc_tty_driver(MAX_DEBUGGER_PORTS);
	if (!ecd_tty_driver) {
		pr_err("Failed to allocate console debugger tty\n");
		ret = -ENOMEM;
		goto err_free_state;
	}

	ecd_tty_driver->owner = THIS_MODULE;
	ecd_tty_driver->driver_name	= "console-debugger";
	ecd_tty_driver->name		= "ttyECD";
	ecd_tty_driver->type		= TTY_DRIVER_TYPE_SERIAL;
	ecd_tty_driver->subtype	= SERIAL_TYPE_NORMAL;
	ecd_tty_driver->init_termios	= tty_std_termios;
	ecd_tty_driver->flags	= TTY_DRIVER_REAL_RAW |
					  TTY_DRIVER_DYNAMIC_DEV;
	ecd_tty_driver->driver_state	= interfaces;

	ecd_tty_driver->init_termios.c_cflag =
					B115200 | CS8 | CREAD | HUPCL | CLOCAL;
	ecd_tty_driver->init_termios.c_ispeed = 115200;
	ecd_tty_driver->init_termios.c_ospeed = 115200;

	tty_set_operations(ecd_tty_driver, &ecd_tty_driver_ops);

	ret = tty_register_driver(ecd_tty_driver);
	if (ret) {
		pr_err("Failed to register ECD tty: %d\n", ret);
		goto err_free_tty;
	}

	pr_info("Registered ECD tty driver\n");
	return 0;

err_free_tty:
	put_tty_driver(ecd_tty_driver);
	ecd_tty_driver = NULL;
err_free_state:
	kfree(interfaces);
	return ret;
}

static int ecd_tty_init_one(struct ecd_interface *interface)
{
	int ret;
	struct device *tty_dev;
	struct ecd_interface **interfaces = ecd_tty_driver->driver_state;

	interfaces[interface->pdev->id] = interface;

	interface->tty_rbuf = ecd_ringbuf_alloc(SZ_1K);
	if (!interface->tty_rbuf) {
		pr_err("Failed to allocate console debugger ringbuf\n");
		ret = -ENOMEM;
		goto err;
	}

	tty_port_init(&interface->tty_port);
	interface->tty_port.ops = &ecd_tty_port_ops;

	tty_dev = tty_port_register_device(&interface->tty_port, ecd_tty_driver,
					   interface->pdev->id, &interface->pdev->dev);
	if (IS_ERR(tty_dev)) {
		pr_err("Failed to register console debugger tty device\n");
		ret = PTR_ERR(tty_dev);
		goto err;
	}

	device_set_wakeup_capable(tty_dev, 1);

	pr_info("Registered console debugger ttyECD%d\n", interface->pdev->id);
	return 0;

err:
	ecd_ringbuf_free(interface->tty_rbuf);
	interface->tty_rbuf = NULL;
	return ret;
}
#endif

#define CONDBG_FW_ADDR		(VMALLOC_START + 0xF1000000)
#define CONDBG_FW_SIZE		(SZ_512K)
#define CONDBG_FW_TEXT_SIZE	(SZ_128K)

struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

static int ecd_change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr,
			void *data)
{
	struct page_change_data *cdata = data;
	pte_t pte = *ptep;

	pte = clear_pte_bit(pte, cdata->clear_mask);
	pte = set_pte_bit(pte, cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

static int ecd_change_memory_common(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr;
	unsigned long size = PAGE_SIZE*numpages;
	unsigned long end = start + size;
	int ret;
	struct page_change_data data;

	if (!PAGE_ALIGNED(addr)) {
		start &= PAGE_MASK;
		end = start + size;
		WARN_ON_ONCE(1);
	}

	if (!numpages)
		return 0;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret = apply_to_page_range(&init_mm, start, size, ecd_change_page_range,
					&data);

	flush_tlb_kernel_range(start, end);
	return ret;
}

static int ecd_set_memory_ro(unsigned long addr, int numpages)
{
	return ecd_change_memory_common(addr, numpages,
					__pgprot(PTE_RDONLY),
					__pgprot(PTE_WRITE));
}

static int ecd_set_memory_rw(unsigned long addr, int numpages)
{
	return ecd_change_memory_common(addr, numpages,
					__pgprot(PTE_WRITE),
					__pgprot(PTE_RDONLY));
}

static int ecd_set_memory_nx(unsigned long addr, int numpages)
{
	return ecd_change_memory_common(addr, numpages,
					__pgprot(PTE_PXN),
					__pgprot(0));
}

static int ecd_set_memory_x(unsigned long addr, int numpages)
{
	return ecd_change_memory_common(addr, numpages,
					__pgprot(0),
					__pgprot(PTE_PXN));
}

static noinline_for_stack long get_file_size(struct file *file)
{
	struct kstat st;

	if (vfs_getattr(&file->f_path, &st))
		return -1;
	if (!S_ISREG(st.mode))
		return -1;
	if (st.size != (long)st.size)
		return -1;

	return st.size;
}

static int get_filesystem_binary(const char *filename, struct ecd_interface *interface)
{
	struct file *fp;
	int ret = 0;
	long size;
	char *buf;

	fp = filp_open(filename, O_RDONLY, 0);
	if (!IS_ERR_OR_NULL(fp)) {
		size = get_file_size(fp);
		if (size <= 0) {
			ret = -EBADF;
			goto out;
		}

		/* if a buffer for interfaceary is already allocated */
		if (interface->fw_data) {
			if (!interface->fw_size) {
				ret = -EINVAL;
				goto out;
			}

			buf = interface->fw_data;

			/* shrink read size to fit the size of a given buffer */
			if (size > interface->fw_size) {
				pr_crit("%s: will read only %ld bytes from a file (%ld)",
					__func__, interface->fw_size, size);
				size = interface->fw_size;
			}
		} else {
			buf = vmalloc(size);
			if (!buf) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = kernel_read(fp, 0, buf, size);
		if (ret != size) {
			if (!interface->fw_data)
				vfree(buf);
			ret = -EBADF;
			goto out;
		} else
			ret = 0;

		interface->fw_data = buf;
		interface->fw_size = size;
		fput(fp);
	} else {
		ret = PTR_ERR(fp);
	}
out:
	return ret;
}

static int request_binary(struct ecd_interface *interface, const char *path,
			const char *name, struct device *device)
{
	char *filename;
	unsigned int retry_cnt = 2;
	int ret;

	interface->fw_data = NULL;
	interface->fw_size = 0;
	interface->fw = NULL;

	/* read the requested interfaceary from file system directly */
	if (path) {
		filename = __getname();
		if (unlikely(!filename))
			return -ENOMEM;

		snprintf(filename, PATH_MAX, "%s%s", path, name);
		ret = get_filesystem_binary(filename, interface);
		__putname(filename);
		/* read successfully or don't want to go further more */
		if (!ret || !device)
			return ret;
	}

	/* ask to 'request_firmware' */
	do {
		ret = request_firmware(&interface->fw, name, device);

		if (!ret && interface->fw) {
			interface->fw_data = (void *)interface->fw->data;
			interface->fw_size = interface->fw->size;
			break;
		}
	} while (!(retry_cnt--));

	return ret;
}

static void release_binary(struct ecd_interface *interface)
{
	if (interface->fw)
		release_firmware(interface->fw);
	else if (interface->fw_data)
		vfree(interface->fw_data);
}

static void ecd_writel(u32 val, volatile void __iomem *addr)
{
	asm volatile("str %w0, [%1]" : : "r" (val), "r" (addr));
}

static void ecd_writeq(u64 val, volatile void __iomem *addr)
{
	asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

static u64 ecd_readq(const volatile void __iomem *addr)
{
	u64 val;
	asm volatile(ALTERNATIVE("ldr %0, [%1]",
				 "ldar %0, [%1]",
				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
		     : "=r" (val) : "r" (addr));
	return val;
}

static u32 ecd_readl(const volatile void __iomem *addr)
{
	u32 val;
	asm volatile(ALTERNATIVE("ldr %w0, [%1]",
					"ldar %w0, [%1]",
					ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
			: "=r" (val) : "r" (addr));
	return val;
}

static void __iomem *ecd_ioremap(phys_addr_t phys_addr, size_t size)
{
	return __ioremap((phys_addr), (size), __pgprot(PROT_DEVICE_nGnRE));
}

static void ecd_iounmap(volatile void __iomem *io_addr)
{
	return __iounmap(io_addr);
}

static void *ecd_kzalloc(size_t size)
{
	return kmalloc(size, __GFP_ZERO | GFP_KERNEL);
}

static void ecd_kfree(const void *addr)
{
	kfree(addr);
}

static void ecd_spin_lock_irqsave(spinlock_t *lock, unsigned long flags)
{
	spin_lock_irqsave(lock, flags);
}

static void ecd_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	spin_unlock_irqrestore(lock, flags);
}

static void ecd_local_irq_save(unsigned long flags)
{
	local_irq_save(flags);
}

static void ecd_local_irq_restore(unsigned long flags)
{
	local_irq_restore(flags);
}

static void ecd_preempt_enable(void)
{
	preempt_enable();
}

static void ecd_preempt_disable(void)
{
	preempt_disable();
}

static const char *ecd_get_linux_banner(void)
{
	return linux_banner;
}

static int ecd_request_irq(unsigned int irq, irq_handler_t handler,
				unsigned int flags, char* name)
{
	struct irq_domain *domain = (struct irq_domain *)gic_get_root_irqdomain(0);
	int virq, ret;

	virq = irq_create_mapping(domain, irq);
	if (!virq) {
		pr_err("failed to irq_crete_mapping : %d\n", irq);
	}
	gic_irq_domain_map(domain, virq, irq);
	ret = request_irq(virq, handler, flags, name, interface);
	if (ret) {
		pr_err("failed to register interrupt : %d\n", irq);
	}

	return virq;
}

static int ecd_irq_force_affinity(unsigned int irq, int cpu)
{
	return irq_force_affinity(irq, cpumask_of(cpu));
}

static void ecd_init_work(struct work_struct **work, work_func_t fn)
{
	*work = kzalloc(sizeof(struct work_struct), GFP_KERNEL);
	INIT_WORK(*work, fn);
}

static void ecd_schedule_work(struct work_struct *work)
{
	schedule_work(work);
}

static void ecd_spin_lock_init(spinlock_t **lock)
{
	*lock = kzalloc(sizeof(spinlock_t), GFP_KERNEL);
	spin_lock_init(*lock);
}

static void ecd_wake_lock_init(struct wake_lock **lock, int type, const char *name)
{
	*lock = kzalloc(sizeof(struct wake_lock), GFP_KERNEL);
	wake_lock_init(*lock, type, name);
}

static int ecd_spin_trylock(spinlock_t *lock)
{
	return spin_trylock(lock);
}

static int ecd_cpu_online_func(int cpu)
{
	return cpu_online(cpu);
}

static int ecd_cpu_possible_func(int cpu)
{
	return cpu_possible(cpu);
}

static int ecd_num_online_cpus(void)
{
	return num_online_cpus();
}

static int ecd_num_possible_cpus(void)
{
	return num_possible_cpus();
}

static int ecd_raw_smp_processor_id(int cpu)
{
	return raw_smp_processor_id();
}

static char *mode_name(const struct pt_regs *regs)
{
	if (compat_user_mode(regs)) {
		return "USR";
	} else {
		switch (processor_mode(regs)) {
		case PSR_MODE_EL0t: return "EL0t";
		case PSR_MODE_EL1t: return "EL1t";
		case PSR_MODE_EL1h: return "EL1h";
		case PSR_MODE_EL2t: return "EL2t";
		case PSR_MODE_EL2h: return "EL2h";
		default: return "???";
		}
	}
}

void ecd_printf(const char *fmt, ...)
{
	char *buf;
	va_list ap;

	if (!interface || !interface->output_buf)
		return;

	buf = interface->output_buf;
	va_start(ap, fmt);
	vscnprintf(buf, SZ_1K, fmt, ap);
	va_end(ap);

	ecd_uart_puts(buf);
}

static void ecd_dump_pc(const struct pt_regs *regs)
{
	ecd_printf(" pc %016lx cpsr %08lx mode %s\n",
		regs->pc, regs->pstate, mode_name(regs));
}

static void ecd_dump_regs_aarch32(const struct pt_regs *regs)
{
	ecd_printf(" r0 %08x  r1 %08x  r2 %08x  r3 %08x\n",
			regs->compat_usr(0), regs->compat_usr(1),
			regs->compat_usr(2), regs->compat_usr(3));
	ecd_printf(" r4 %08x  r5 %08x  r6 %08x  r7 %08x\n",
			regs->compat_usr(4), regs->compat_usr(5),
			regs->compat_usr(6), regs->compat_usr(7));
	ecd_printf(" r8 %08x  r9 %08x r10 %08x r11 %08x\n",
			regs->compat_usr(8), regs->compat_usr(9),
			regs->compat_usr(10), regs->compat_usr(11));
	ecd_printf(" ip %08x  sp %08x  lr %08x  pc %08x\n",
			regs->compat_usr(12), regs->compat_sp,
			regs->compat_lr, regs->pc);
	ecd_printf(" cpsr %08x (%s)\n", regs->pstate, mode_name(regs));
}

static void ecd_dump_regs_aarch64(const struct pt_regs *regs)
{

	ecd_printf("  x0 %016lx   x1 %016lx\n",
			regs->regs[0], regs->regs[1]);
	ecd_printf("  x2 %016lx   x3 %016lx\n",
			regs->regs[2], regs->regs[3]);
	ecd_printf("  x4 %016lx   x5 %016lx\n",
			regs->regs[4], regs->regs[5]);
	ecd_printf("  x6 %016lx   x7 %016lx\n",
			regs->regs[6], regs->regs[7]);
	ecd_printf("  x8 %016lx   x9 %016lx\n",
			regs->regs[8], regs->regs[9]);
	ecd_printf(" x10 %016lx  x11 %016lx\n",
			regs->regs[10], regs->regs[11]);
	ecd_printf(" x12 %016lx  x13 %016lx\n",
			regs->regs[12], regs->regs[13]);
	ecd_printf(" x14 %016lx  x15 %016lx\n",
			regs->regs[14], regs->regs[15]);
	ecd_printf(" x16 %016lx  x17 %016lx\n",
			regs->regs[16], regs->regs[17]);
	ecd_printf(" x18 %016lx  x19 %016lx\n",
			regs->regs[18], regs->regs[19]);
	ecd_printf(" x20 %016lx  x21 %016lx\n",
			regs->regs[20], regs->regs[21]);
	ecd_printf(" x22 %016lx  x23 %016lx\n",
			regs->regs[22], regs->regs[23]);
	ecd_printf(" x24 %016lx  x25 %016lx\n",
			regs->regs[24], regs->regs[25]);
	ecd_printf(" x26 %016lx  x27 %016lx\n",
			regs->regs[26], regs->regs[27]);
	ecd_printf(" x28 %016lx  x29 %016lx\n",
			regs->regs[28], regs->regs[29]);
	ecd_printf(" x30 %016lx   sp %016lx\n",
			regs->regs[30], regs->sp);
	ecd_printf("  pc %016lx cpsr %08x (%s)\n",
			regs->pc, regs->pstate, mode_name(regs));
}

static void ecd_dump_regs(const struct pt_regs *regs)
{
	if (compat_user_mode(regs))
		ecd_dump_regs_aarch32(regs);
	else
		ecd_dump_regs_aarch64(regs);
}

#define READ_SPECIAL_REG(x) ({ \
	u64 val; \
	asm volatile ("mrs %0, " # x : "=r"(val)); \
	val; \
})

static void ecd_dump_allregs(const struct pt_regs *regs)
{
	u32 pstate = READ_SPECIAL_REG(CurrentEl);
	bool in_el2 = (pstate & PSR_MODE_MASK) >= PSR_MODE_EL2t;

	ecd_dump_regs(regs);

	ecd_printf(" sp_el0   %016lx\n",
			READ_SPECIAL_REG(sp_el0));

	if (in_el2)
		ecd_printf(" sp_el1   %016lx\n",
				READ_SPECIAL_REG(sp_el1));

	ecd_printf(" elr_el1  %016lx\n",
			READ_SPECIAL_REG(elr_el1));

	ecd_printf(" spsr_el1 %08lx\n",
			READ_SPECIAL_REG(spsr_el1));

	if (in_el2) {
		ecd_printf(" spsr_irq %08lx\n",
				READ_SPECIAL_REG(spsr_irq));
		ecd_printf(" spsr_abt %08lx\n",
				READ_SPECIAL_REG(spsr_abt));
		ecd_printf(" spsr_und %08lx\n",
				READ_SPECIAL_REG(spsr_und));
		ecd_printf(" spsr_fiq %08lx\n",
				READ_SPECIAL_REG(spsr_fiq));
		ecd_printf(" spsr_el2 %08lx\n",
				READ_SPECIAL_REG(elr_el2));
		ecd_printf(" spsr_el2 %08lx\n",
				READ_SPECIAL_REG(spsr_el2));
	}
}

static int report_trace(struct stackframe *frame, void *d)
{
	ecd_printf("%pF:\n", frame->pc);
	ecd_printf("  pc %016lx   sp %016lx   fp %016lx\n",
			frame->pc, frame->sp, frame->fp);
	return 0;
}

static void ecd_dump_stacktrace_task(struct pt_regs *regs, struct task_struct *tsk)
{
	struct stackframe frame;

	if (!tsk)
		tsk = current;

	if (regs) {
		frame.fp = regs->regs[29];
		frame.sp = regs->sp;
		frame.pc = regs->pc;
	} else if (tsk == current) {
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.sp = current_stack_pointer;
		frame.pc = (unsigned long)ecd_dump_stacktrace_task;
	} else {
		/*
		 * task blocked in __switch_to
		 */
		frame.fp = thread_saved_fp(tsk);
		frame.sp = thread_saved_sp(tsk);
		frame.pc = thread_saved_pc(tsk);
	}

	ecd_printf("Call trace:\n");
	walk_stackframe(NULL, &frame, report_trace, NULL);
}

#define THREAD_INFO(sp) ((struct thread_info *) \
		((unsigned long)(sp) & ~(THREAD_SIZE - 1)))

static void ecd_dump_stacktrace(const struct pt_regs *regs, void *ssp)
{
	struct thread_info *real_thread_info;
	struct thread_info flags;

	if (!ssp)
		real_thread_info = current_thread_info();
	else
		real_thread_info = THREAD_INFO(ssp);

	memcpy(&flags, current_thread_info(), sizeof(struct thread_info));
	*current_thread_info() = *real_thread_info;

	if (!current)
		ecd_printf("current NULL\n");
	else
		ecd_printf("comm: %s\n", current->comm);

	ecd_dump_regs(regs);

	if (!user_mode(regs)) {
		struct stackframe frame;
		frame.fp = regs->regs[29];
		frame.sp = regs->sp;
		frame.pc = regs->pc;
		ecd_printf("\n");
		walk_stackframe(NULL, &frame, report_trace, NULL);
	}
	memcpy(current_thread_info(), &flags, sizeof(struct thread_info));
}

static void ecd_dump_one_task(struct task_struct *tsk, bool is_main)
{
	char state_array[] = {'R', 'S', 'D', 'T', 't', 'Z', 'X', 'x', 'K', 'W'};
	unsigned char idx = 0;
	unsigned int status = (tsk->state & TASK_REPORT) | tsk->exit_state;
	unsigned long wchan;
	unsigned long pc = 0;
	char symname[KSYM_NAME_LEN];
	int permitted;
	struct mm_struct *mm;

	permitted = ptrace_may_access(tsk, PTRACE_MODE_READ_FSCREDS);
	mm = get_task_mm(tsk);
	if (mm) {
		if (permitted)
			pc = KSTK_EIP(tsk);
	}

	wchan = get_wchan(tsk);
	if (lookup_symbol_name(wchan, symname) < 0) {
		if (!ptrace_may_access(tsk, PTRACE_MODE_READ_FSCREDS))
			snprintf(symname, KSYM_NAME_LEN,  "_____");
		else
			snprintf(symname, KSYM_NAME_LEN, "%lu", wchan);
	}

	while (status) {
		idx++;
		status >>= 1;
	}

	touch_softlockup_watchdog();
	ecd_printf("%8d %8d %8d %16lld %c(%d) %3d  %16zx %16zx  %16zx %c %16s [%s]\n",
			tsk->pid, (int)(tsk->utime), (int)(tsk->stime),
			tsk->se.exec_start, state_array[idx], (int)(tsk->state),
			task_cpu(tsk), wchan, pc, (unsigned long)tsk,
			is_main ? '*' : ' ', tsk->comm, symname);

	if (tsk->state == TASK_RUNNING
			|| tsk->state == TASK_UNINTERRUPTIBLE
			|| tsk->mm == NULL) {
		ecd_dump_stacktrace_task(NULL, tsk);
		barrier();
	}
}

static inline struct task_struct *get_next_thread(struct task_struct *tsk)
{
	return container_of(tsk->thread_group.next,
				struct task_struct,
				thread_group);
}

static void ecd_dump_task(void)
{
	struct task_struct *frst_tsk;
	struct task_struct *curr_tsk;
	struct task_struct *frst_thr;
	struct task_struct *curr_thr;
	unsigned long flags;

	ecd_printf("\n");
	ecd_printf(" current proc : %d %s\n", current->pid, current->comm);
	ecd_printf(" ----------------------------------------------------------------------------------------------------------------------------\n");
	ecd_printf("     pid      uTime    sTime      exec(ns)  stat  cpu       wchan           user_pc        task_struct       comm   sym_wchan\n");
	ecd_printf(" ----------------------------------------------------------------------------------------------------------------------------\n");

	/* processes */
	frst_tsk = &init_task;
	curr_tsk = frst_tsk;
	while (curr_tsk != NULL) {
		spin_lock_irqsave(&interface->work_lock, flags);
		ecd_dump_one_task(curr_tsk,  true);
		if (ecd_uart_check_break()) {
			spin_unlock_irqrestore(&interface->work_lock, flags);
			break;
		} else {
			spin_unlock_irqrestore(&interface->work_lock, flags);
		}
		/* threads */
		if (curr_tsk->thread_group.next != NULL) {
			frst_thr = get_next_thread(curr_tsk);
			curr_thr = frst_thr;
			if (frst_thr != curr_tsk) {
				while (curr_thr != NULL) {
					ecd_dump_one_task(curr_thr, false);
					curr_thr = get_next_thread(curr_thr);
					if (curr_thr == curr_tsk)
						break;
				}
			}
		}
		curr_tsk = container_of(curr_tsk->tasks.next,
					struct task_struct, tasks);
		if (curr_tsk == frst_tsk)
			break;
	}
	ecd_printf("----------------------------------------------------------------------------------------------------------------------------\n");
}

static void ecd_dump_irqs(void)
{
	int n;
	struct irq_desc *desc;

	ecd_printf("irqnr       total  since-last   status  name\n");
	for_each_irq_desc(n, desc) {
		struct irqaction *act = desc->action;
		if (!act && !kstat_irqs(n))
			continue;
		ecd_printf("%5d: %10u %11u %8x  %s\n", n,
			kstat_irqs(n),
			kstat_irqs(n) - interface->last_irqs[n],
			desc->status_use_accessors,
			(act && act->name) ? act->name : "???");
		interface->last_irqs[n] = kstat_irqs(n);
	}
}

static void ecd_dump_ps(void)
{
	struct task_struct *g;
	struct task_struct *p;
	unsigned task_state;
	static const char stat_nam[] = "RSDTtZX";

	ecd_printf("pid   ppid  prio task            pc\n");
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		task_state = p->state ? __ffs(p->state) + 1 : 0;
		ecd_printf("%5d %5d %4d ", p->pid, p->parent->pid, p->prio);
		ecd_printf("%-13.13s %c", p->comm,
			     task_state >= sizeof(stat_nam) ? '?' : stat_nam[task_state]);
		if (task_state == TASK_RUNNING)
			ecd_printf(" running\n");
		else
			ecd_printf(" %08lx\n",
					thread_saved_pc(p));
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
}

static void ecd_dump_kernel_log(void)
{
	char buf[512];
	size_t len;
	struct kmsg_dumper dumper = { .active = true };
	unsigned long flags;

	kmsg_dump_rewind_nolock(&dumper);
	while (kmsg_dump_get_line_nolock(&dumper, true, buf, sizeof(buf) - 1, &len)) {
		buf[len] = 0;
		spin_lock_irqsave(&interface->work_lock, flags);
		ecd_uart_puts(buf);
		if (ecd_uart_check_break()) {
			spin_unlock_irqrestore(&interface->work_lock, flags);
			break;
		} else {
			spin_unlock_irqrestore(&interface->work_lock, flags);
		}
	}
}

static void ecd_tty_ringbuf_consume(void)
{
#if defined(CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE)
	int i, count = ecd_ringbuf_level(interface->tty_rbuf);

	for (i = 0; i < count; i++) {
		int c = ecd_ringbuf_peek(interface->tty_rbuf, 0);
		tty_insert_flip_char(&interface->tty_port, c, TTY_NORMAL);
		if (!ecd_ringbuf_consume(interface->tty_rbuf, 1))
			ecd_printf("ttyECD failed to consume byte\n");
	}
	tty_flip_buffer_push(&interface->tty_port);
#endif
}

static void ecd_tty_ringbuf_push(char c)
{
	ecd_ringbuf_push(interface->tty_rbuf, c);
}

static ktime_t ecd_ktime_sub(ktime_t lhs, ktime_t rhs)
{
	return ktime_sub(lhs, rhs);
}

static int ecd_register_hotcpu_notifier(void *nbp, notifier_fn_t func)
{
	struct notifier_block *nb = (struct notifier_block *)nbp;

	nb = kzalloc(sizeof(struct notifier_block), GFP_KERNEL);
	nb->notifier_call = func;
	return register_hotcpu_notifier((struct notifier_block *)nb);
}

static int ecd_register_lowpm_notifier(void *nbp, notifier_fn_t func)
{
	struct notifier_block *nb = (struct notifier_block *)nbp;

	nb = kzalloc(sizeof(struct notifier_block), GFP_KERNEL);
	nb->notifier_call = func;
	return cpu_pm_register_notifier((struct notifier_block *)nb);
}


static int ecd_do_breakpoint(unsigned long addr, unsigned int esr,
				      struct pt_regs *regs)
{
	if (interface && interface->fw_loaded)
		return interface->ops.do_breakpoint(addr, regs);
	else
		return 0;
}

static int ecd_do_watchpoint(unsigned long addr, unsigned int esr,
				      struct pt_regs *regs)
{
	if (interface && interface->fw_loaded)
		return interface->ops.do_watchpoint(addr, regs);
	else
		return 0;
}

void ecd_do_break_now(void)
{
	interface->ops.do_break_now();
}

static int __init add_exception_func(void)
{
	hook_debug_fault_code(DBG_ESR_EVT_HWBP, ecd_do_breakpoint, SIGTRAP,
			      TRAP_HWBKPT, "hw-breakpoint handler");
	hook_debug_fault_code(DBG_ESR_EVT_HWWP, ecd_do_watchpoint, SIGTRAP,
			      TRAP_HWBKPT, "hw-watchpoint handler");
	return 0;
}
arch_initcall(add_exception_func);

enum os_func {
	READL = 0,
	READQ,
	WRITEL,
	WRITEQ,

	IOREMAP = 10,
	IOUNMAP,
	KZALLOC,
	KFREE,

	SPIN_LOCK_INIT = 20,
	SPIN_LOCK,
	SPIN_TRYLOCK,
	SPIN_LOCK_IRQSAVE,
	SPIN_UNLOCK,
	SPIN_UNLOCK_IRQRESTORE,
	LOCAL_IRQ_SAVE,
	LOCAL_IRQ_RESTORE,
	PREEMPT_ENABLE,
	PREEMPT_DISABLE,

	KTIME_GET = 30,
	KTIME_TO_US,
	KTIME_SUB,
	CLOCKSOURCE_SUSPEND,
	CLOCKSOURCE_RESUME,
	TOUCH_ALL_SOFTLOCKUP_WATCHDOGS,

	STRNCMP = 40,
	STRNCPY,
	STRLEN,
	STRSEP,
	SCNPRINTF,
	VSCNPRINTF,
	KSTRTOUL,
	SIMPLE_STRTOUL,

	REGISTER_HOTCPU_NOTIFIER = 50,
	REGISTER_CPU_PM_NOTIFIER,
	PANIC,
	MACHINE_RESTART,
	KERNEL_RESTART,

	PRINTK = 60,
	KALLSYMS_LOOKUP,
	KALLSYMS_LOOKUP_NAME,
	SPRINT_SYMBOL,
	MEMCPY,
	MEMSET,

	REQUEST_IRQ = 70,
	IRQ_FORCE_AFFINITY,
	GET_IRQ_REGS,

	HOOK_DEBUG_FAULT_CODE = 90,
	SMP_CALL_FUNCTION,
	SMP_CALL_FUNCTION_SINGLE,
	ON_EACH_CPU,
	SCHEDULE_WORK,
	INIT_WORK,
	CUR_THD_INFO,
	LINUX_BANNER,

	CPU_LOGICAL_MAP = 100,
	CPU_ONLINE_FUNC,
	CPU_POSSIBLE_FUNC,
	NUM_ONLINE_CPUS,
	NUM_POSSIBLE_CPUS,
	SET_BIT,
	CLEAR_BIT,
	TEST_BIT,
	RAW_SMP_PROCESSOR_ID,

	ECD_DO_SYSRQ = 110,
	ECD_DUMP_PC,
	ECD_DUMP_REGS,
	ECD_DUMP_ALLREGS,
	ECD_DUMP_TASK,
	ECD_DUMP_KERNEL_LOG,
	ECD_DUMP_IRQS,
	ECD_DUMP_PS,
	ECD_DUMP_STACKTRACE,

	ECD_TTY_RINGBUF_PUSH = 120,
	ECD_TTY_RINGBUF_CONSUME,
	ECD_UART_INIT,
	ECD_UART_PUTS,
	ECD_UART_PUTC,
	ECD_UART_GETC,
	ECD_UART_FLUSH,
	ECD_UART_ENABLE,
	ECD_UART_DISABLE,
	ECD_UART_CHECK_BREAK,

	ECD_LOOKUP_DUMP_SFR = 130,
	ECD_LOOKUP_CHECK_SFR,

	ITMON_ENABLE = 140,
	EXYNOS_SS_DUMPER_ONE,
	WDT_SET_EMERGENCY_RESET,
	WAKE_LOCK_INIT,
	WAKE_LOCK,
	WAKE_UNLOCK,

	FUNC_END,
};

typedef void(*set_param_fn_t)(void);
typedef u32 (*base_fn_t)(void **func1, void *func2, void *func3);

static void set_param(set_param_fn_t *fn)
{
	fn[READL] = (set_param_fn_t)ecd_readl;
	fn[READQ] = (set_param_fn_t)ecd_readq;
	fn[WRITEL] = (set_param_fn_t)ecd_writel;
	fn[WRITEQ] = (set_param_fn_t)ecd_writeq;

	fn[IOREMAP] = (set_param_fn_t)ecd_ioremap;
	fn[IOUNMAP] = (set_param_fn_t)ecd_iounmap;

	fn[KZALLOC] = (set_param_fn_t)ecd_kzalloc;
	fn[KFREE] = (set_param_fn_t)ecd_kfree;

	fn[SPIN_LOCK_INIT] = (set_param_fn_t)ecd_spin_lock_init;
	fn[SPIN_LOCK] = (set_param_fn_t)spin_lock;
	fn[SPIN_UNLOCK] = (set_param_fn_t)spin_unlock;
	fn[SPIN_TRYLOCK] = (set_param_fn_t)ecd_spin_trylock;
	fn[SPIN_LOCK_IRQSAVE] = (set_param_fn_t)ecd_spin_lock_irqsave;
	fn[SPIN_UNLOCK_IRQRESTORE] = (set_param_fn_t)ecd_spin_unlock_irqrestore;

	fn[LOCAL_IRQ_SAVE] = (set_param_fn_t)ecd_local_irq_save;
	fn[LOCAL_IRQ_RESTORE] = (set_param_fn_t)ecd_local_irq_restore;

	fn[PREEMPT_ENABLE] = (set_param_fn_t)ecd_preempt_enable;
	fn[PREEMPT_DISABLE] = (set_param_fn_t)ecd_preempt_disable;

	fn[KTIME_GET] = (set_param_fn_t)ktime_get;
	fn[KTIME_TO_US] = (set_param_fn_t)ktime_to_us;
	fn[KTIME_SUB] = (set_param_fn_t)ecd_ktime_sub;

	fn[CLOCKSOURCE_SUSPEND] = (set_param_fn_t)clocksource_suspend;
	fn[CLOCKSOURCE_RESUME] = (set_param_fn_t)clocksource_resume;
	fn[TOUCH_ALL_SOFTLOCKUP_WATCHDOGS] = (set_param_fn_t)touch_softlockup_watchdog;

	fn[STRNCMP] = (set_param_fn_t)strncmp;
	fn[STRNCPY] = (set_param_fn_t)strncpy;
	fn[STRLEN] = (set_param_fn_t)strlen;
	fn[STRSEP] = (set_param_fn_t)strsep;
	fn[SCNPRINTF] = (set_param_fn_t)scnprintf;
	fn[VSCNPRINTF] = (set_param_fn_t)vscnprintf;
	fn[KSTRTOUL] = (set_param_fn_t)kstrtoul;
	fn[SIMPLE_STRTOUL] = (set_param_fn_t)simple_strtol;

	fn[REGISTER_HOTCPU_NOTIFIER] = (set_param_fn_t)ecd_register_hotcpu_notifier;
	fn[REGISTER_CPU_PM_NOTIFIER] = (set_param_fn_t)ecd_register_lowpm_notifier;
	fn[PANIC] = (set_param_fn_t)panic;
	fn[MACHINE_RESTART] = (set_param_fn_t)machine_restart;
	fn[KERNEL_RESTART] = (set_param_fn_t)kernel_restart;

	fn[PRINTK] = (set_param_fn_t)printk;
	fn[KALLSYMS_LOOKUP] = (set_param_fn_t)kallsyms_lookup;
	fn[KALLSYMS_LOOKUP_NAME] = (set_param_fn_t)kallsyms_lookup_name;
	fn[SPRINT_SYMBOL] = (set_param_fn_t)sprint_symbol;
	fn[MEMCPY] = (set_param_fn_t)memcpy;
	fn[MEMSET] = (set_param_fn_t)memset;

	fn[REQUEST_IRQ] = (set_param_fn_t)ecd_request_irq;
	fn[IRQ_FORCE_AFFINITY] = (set_param_fn_t)ecd_irq_force_affinity;
	fn[GET_IRQ_REGS] = (set_param_fn_t)get_irq_regs;

	fn[SMP_CALL_FUNCTION_SINGLE] = (set_param_fn_t)smp_call_function_single;
	fn[SMP_CALL_FUNCTION] = (set_param_fn_t)smp_call_function;
	fn[ON_EACH_CPU] = (set_param_fn_t)on_each_cpu;
	fn[SCHEDULE_WORK] = (set_param_fn_t)ecd_schedule_work;
	fn[INIT_WORK] = (set_param_fn_t)ecd_init_work;
	fn[LINUX_BANNER] = (set_param_fn_t)ecd_get_linux_banner;

	fn[CPU_LOGICAL_MAP] = (set_param_fn_t)__cpu_logical_map;
	fn[CPU_ONLINE_FUNC] = (set_param_fn_t)ecd_cpu_online_func;
	fn[CPU_POSSIBLE_FUNC] = (set_param_fn_t)ecd_cpu_possible_func;
	fn[NUM_ONLINE_CPUS] = (set_param_fn_t)ecd_num_online_cpus;
	fn[NUM_POSSIBLE_CPUS] = (set_param_fn_t)ecd_num_possible_cpus;
	fn[SET_BIT] = (set_param_fn_t)set_bit;
	fn[CLEAR_BIT] = (set_param_fn_t)clear_bit;
	fn[TEST_BIT] = (set_param_fn_t)test_bit;
	fn[RAW_SMP_PROCESSOR_ID] = (set_param_fn_t)ecd_raw_smp_processor_id;

	fn[ECD_DO_SYSRQ] = (set_param_fn_t)ecd_do_sysrq;
	fn[ECD_DUMP_PC] = (set_param_fn_t)ecd_dump_pc;
	fn[ECD_DUMP_REGS] = (set_param_fn_t)ecd_dump_regs;
	fn[ECD_DUMP_ALLREGS] = (set_param_fn_t)ecd_dump_allregs;
	fn[ECD_DUMP_TASK] = (set_param_fn_t)ecd_dump_task;
	fn[ECD_DUMP_KERNEL_LOG] = (set_param_fn_t)ecd_dump_kernel_log;
	fn[ECD_DUMP_IRQS] = (set_param_fn_t)ecd_dump_irqs;
	fn[ECD_DUMP_PS] = (set_param_fn_t)ecd_dump_ps;
	fn[ECD_DUMP_STACKTRACE] = (set_param_fn_t)ecd_dump_stacktrace;

	fn[ECD_TTY_RINGBUF_PUSH] = (set_param_fn_t)ecd_tty_ringbuf_push;
	fn[ECD_TTY_RINGBUF_CONSUME] = (set_param_fn_t)ecd_tty_ringbuf_consume;

	fn[ECD_UART_INIT] = (set_param_fn_t)ecd_uart_init;
	fn[ECD_UART_PUTS] = (set_param_fn_t)ecd_uart_puts;
	fn[ECD_UART_PUTC] = (set_param_fn_t)ecd_uart_putc;
	fn[ECD_UART_GETC] = (set_param_fn_t)ecd_uart_getc;
	fn[ECD_UART_FLUSH] = (set_param_fn_t)ecd_uart_flush;
	fn[ECD_UART_ENABLE] = (set_param_fn_t)ecd_uart_enable;
	fn[ECD_UART_DISABLE] = (set_param_fn_t)ecd_uart_disable;
	fn[ECD_UART_CHECK_BREAK] = (set_param_fn_t)ecd_uart_check_break;

	fn[ECD_LOOKUP_DUMP_SFR] = (set_param_fn_t)ecd_lookup_dump_sfr;
	fn[ECD_LOOKUP_CHECK_SFR] = (set_param_fn_t)ecd_lookup_check_sfr;

#ifdef CONFIG_EXYNOS_ITMON
	fn[ITMON_ENABLE] = (set_param_fn_t)itmon_enable;
#endif
	fn[EXYNOS_SS_DUMPER_ONE] = (set_param_fn_t)exynos_ss_dumper_one;
	fn[WDT_SET_EMERGENCY_RESET] = (set_param_fn_t)s3c2410wdt_set_emergency_reset;
	fn[WAKE_LOCK_INIT] = (set_param_fn_t)ecd_wake_lock_init;
	fn[WAKE_LOCK] = (set_param_fn_t)wake_lock;
	fn[WAKE_UNLOCK] = (set_param_fn_t)wake_unlock;
}

int ecd_start_binary(unsigned long jump_addr)
{
	/* address information */
	set_param_fn_t fn[SZ_256];

	/* Set/Get parameter */
	set_param(fn);

	/* Complete to load the firmware */
	interface->fw_loaded = ((base_fn_t)jump_addr)((void **)fn,
						      (void *)&interface->ops,
						      (void *)&interface->param);

	return interface->fw_loaded;
}

int ecd_init_binary(unsigned long fw_addr, unsigned long fw_size)
{
	int ret;

	ret = request_binary(interface, FW_PATH, "ecd_fw.bin", NULL);
	if (ret) {
		pr_err("failed to load ECD firmware - %d\n", ret);
		return ret;
	}

	fw_size = CONDBG_FW_TEXT_SIZE;
	fw_addr = CONDBG_FW_ADDR;

	/* Memory attributes => NX */
	ret = ecd_set_memory_nx(fw_addr, PFN_UP(fw_size));
	if (ret) {
		pr_err("failed to change memory attributes to NX - %d\n", ret);
		goto out;
	}
	/* Memory attributes => RW */
	ret = ecd_set_memory_rw(fw_addr, PFN_UP(fw_size));
	if (ret) {
		pr_err("failed to change memory attributes to RW - %d\n", ret);
		goto out;
	}
	memcpy((void *)fw_addr, interface->fw_data, interface->fw_size);
	flush_icache_range(fw_addr, fw_addr + interface->fw_size);
	release_binary(interface);

	/* Memory attributes => RO */
	ret = ecd_set_memory_ro(fw_addr, PFN_UP(fw_size));
	if (ret) {
		pr_err("failed to change memory attributes to RO - %d\n", ret);
		return ret;
	}
	/* Memory attributes => X */
	ret = ecd_set_memory_x(fw_addr, PFN_UP(fw_size));
	if (ret) {
		pr_err("failed to change memory attributes to X - %d\n", ret);
		goto out;
	}
out:
	return ret;
}

static irqreturn_t ecd_uart_irq(int irq, void *dev)
{
	int c, count = 0;
	irqreturn_t ret = IRQ_HANDLED;

	if (!interface->fw_loaded) {
		while (((c = ecd_uart_getc()) != DEBUGGER_NO_CHAR) && interface->tty_rbuf) {
			count++;
			if (interface->param.console_enable) {
				ecd_ringbuf_push(interface->tty_rbuf, c);
			} else if (c == 26) {
				/* CTRL + Z */
				ecd_uart_puts("console mode\n");
				ecd_uart_flush();
				interface->param.console_enable = true;
				interface->param.debug_mode = MODE_CONSOLE;
				ecd_ringbuf_push(interface->tty_rbuf, '\n');
			}
			/*
			else if ((c >= ' ') && (c < 127) && (c != 91)) {
				ecd_uart_putc(c);
			}
			*/
		};
		if (interface->param.console_enable)
			ecd_tty_ringbuf_consume();
	} else {
		ret = interface->ops.uart_irq_handler(irq, dev);
		if (ret == IRQ_NONE) {
			pr_err("ECD: No handled serial irq, Disable ECD\n");
			interface->unhandled_irq = true;
			disable_irq_nosync(irq);
		}
	}
	return ret;
}

static ssize_t profile_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	if (interface && interface->fw_loaded)
		interface->ops.sysfs_profile_store(buf, size);

	return size;
}

static ssize_t profile_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	if (interface && interface->fw_loaded)
		return interface->ops.sysfs_profile_show(buf);
	else
		return 0;
}

static ssize_t enable_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	if (interface && interface->fw_loaded)
		interface->ops.sysfs_enable_store(buf, size);

	return size;
}

static ssize_t enable_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	if (interface && interface->fw_loaded)
		return interface->ops.sysfs_enable_show(buf);
	else
		return 0;
}

static ssize_t break_now_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	if (interface && interface->fw_loaded)
		interface->ops.sysfs_break_now_store(buf, size);

	return size;
}

static ssize_t switch_debug_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	if (interface && interface->fw_loaded)
		interface->ops.sysfs_switch_dbg_store(buf, size);

	return size;
}

void read_ecd_rc(void)
{
	struct ecd_param *param = &interface->param;
	struct ecd_rc *rc = &param->rc;
	int fd, index = 0, data_type = 0;
	char ch[1], data[SZ_64] = {0, };
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = sys_open(ECD_RC_PATH, O_RDONLY, 0);
	if (fd < 0) {
		pr_err(PR_ECD "%s not found!!\n", ECD_RC_PATH);
		set_fs(old_fs);
		return;
	}

	while(sys_read(fd, ch, 1) == 1 && index < SZ_64) {
		data[index++] = ch[0];
		if (ch[0] != '\n')
			continue;

		index = 0;
		if (strnstr(data, "on property", strlen(data))) {
			data_type = 0;
			memset(data, 0, SZ_64);
			continue;
		} else if (strnstr(data, "on setup", strlen(data))) {
			data_type = 1;
			memset(data, 0, SZ_64);
			continue;
		} else if (strnstr(data, "on action", strlen(data))) {
			data_type = 2;
			memset(data, 0, SZ_64);
			continue;
		}

		if (data[0] == '\n')
			continue;

		strreplace(data, 13, 0);
		strreplace(data, 10, 0);
		switch (data_type) {
			char *p;
			unsigned long val;
		case 0:
			p = strnstr(data, "=", strlen(data));
			if (!p || kstrtoul(p + 1, 0, &val)) {
				memset(data, 0, SZ_64);
				continue;
			}
			if (strnstr(data, "console=", strlen(data)))
				param->console_enable = val;
			else if (strnstr(data, "panic=", strlen(data)))
				param->debug_panic = val;
			else if (strnstr(data, "sleep=", strlen(data)))
				param->no_sleep = val;
			else if (strnstr(data, "count=", strlen(data)))
				param->count_break = val;
			break;
		case 1:
			strncpy(rc->setup[rc->setup_idx++], data, SZ_64 - 1);
			break;
		case 2:
			strncpy(rc->action[rc->action_idx++], data, SZ_64 - 1);
			break;
		}
		memset(data, 0, SZ_64);
	}
	set_fs(old_fs);
	sys_close(fd);
}

static ssize_t load_firmware_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	unsigned long fw_addr = CONDBG_FW_ADDR;
	unsigned long fw_size = CONDBG_FW_SIZE;

	if (interface && !interface->fw_loaded) {
		if (!ecd_init_binary(fw_addr, fw_size)) {
			read_ecd_rc();
			ecd_start_binary(fw_addr);
		}
	}
	return size;
}


static DEVICE_ATTR_RW(profile);
static DEVICE_ATTR_RW(enable);
static DEVICE_ATTR_WO(break_now);
static DEVICE_ATTR_WO(switch_debug);
static DEVICE_ATTR_WO(load_firmware);

static struct attribute *ecd_sysfs_attrs[] = {
	&dev_attr_profile.attr,
	&dev_attr_enable.attr,
	&dev_attr_break_now.attr,
	&dev_attr_switch_debug.attr,
	&dev_attr_load_firmware.attr,
	NULL
};
ATTRIBUTE_GROUPS(ecd_sysfs);

int ecd_sysfs_init(struct device *dev)
{
	int ret = 0;
	char path[SZ_256];
	char *kobj_path;

	ret = sysfs_create_groups(&dev->kobj, ecd_sysfs_groups);
	if (ret) {
		dev_err(dev, "fail to register debugger sysfs.\n");
		return ret;
	}

	kobj_path = kobject_get_path(&dev->kobj, GFP_KERNEL);
	snprintf(path, SZ_256, "/sys%s/", kobj_path);
	kfree(kobj_path);

	if (!proc_symlink("ecd", NULL, path))
		dev_warn(dev, "Can't create symbolic link\n");

	return ret;
}

static void ecd_delayed_work_check_firmware(struct work_struct *work)
{
	if (interface && interface->fw_loaded)
		return;

	ecd_printf("Failed to loading ECD firmware\n");

	/* TODO: clean-up ecd's kernel driver if it needs */
}

static int ecd_probe(struct platform_device *pdev)
{
	struct ecd_interface *inf;
	struct ecd_pdata *pdata = dev_get_platdata(&pdev->dev);
	int uart_irq, ret;
	int page_size, i;
	struct page *page;
	struct page **pages;

	if (!initial_ecd_enable)
		return -EINVAL;

	inf = devm_kzalloc(&pdev->dev, sizeof(*inf), GFP_KERNEL);
	if (!inf) {
		dev_err(&pdev->dev, "failed to allocate memory for driver");
		return -ENOMEM;
	}

	page_size = ecd_early_vm.size / PAGE_SIZE;
	pages = kzalloc(sizeof(struct page*) * page_size, GFP_KERNEL);
	page = phys_to_page(ecd_early_vm.phys_addr);

	for (i = 0; i < page_size; i++)
		pages[i] = page++;

	ret = map_vm_area(&ecd_early_vm, PAGE_KERNEL, pages);
	if (ret) {
		dev_err(&pdev->dev, "failed to mapping between virt and phys for firmware");
		return -ENOMEM;
	}
	kfree(pages);

	if (pdev->id >= MAX_DEBUGGER_PORTS)
		return -EINVAL;

	if (!pdata->uart_getc || !pdata->uart_putc)
		return -EINVAL;

	if ((pdata->uart_enable && !pdata->uart_disable) ||
	    (!pdata->uart_enable && pdata->uart_disable))
		return -EINVAL;

	uart_irq = platform_get_irq_byname(pdev, "uart_irq");
	if (uart_irq < 0)
		return -EINVAL;

	inf->fw_loaded = false;
	inf->param.console_enable = initial_console_enable;
	if (inf->param.console_enable) {
		inf->param.debug_mode = MODE_CONSOLE;
	} else {
		inf->param.debug_mode = MODE_NORMAL;
	}
	inf->pdev = pdev;
	inf->pdata = pdata;
	inf->output_buf = devm_kzalloc(&pdev->dev, SZ_1K, GFP_KERNEL);
	inf->uart_irq = uart_irq;
	inf->unhandled_irq = false;
	interface = inf;

	spin_lock_init(&inf->printf_lock);
	spin_lock_init(&inf->work_lock);

	platform_set_drvdata(pdev, inf);

	if (pdata->uart_init) {
		ret = pdata->uart_init(pdev);
		if (ret)
			goto err_uart_init;
	}

	ret = devm_request_irq(&pdev->dev, uart_irq, ecd_uart_irq,
			IRQF_NO_SUSPEND, "ecd_uart", inf);
	if (ret) {
		pr_err("%s: could not install irq handler\n", __func__);
		goto err_register_irq;
	}

	spin_lock_init(&inf->console_lock);
	inf->console = ecd_console;
	inf->console.index = pdev->id;
	if (!console_set_on_cmdline)
		add_preferred_console(inf->console.name,
			inf->console.index, NULL);

	register_console(&inf->console);
	ecd_tty_init_one(inf);

	ecd_sysfs_init(&pdev->dev);

	INIT_DELAYED_WORK(&inf->check_load_firmware, ecd_delayed_work_check_firmware);
	schedule_delayed_work(&inf->check_load_firmware,
			msecs_to_jiffies(20 * MSEC_PER_SEC));

	ecd_printf(" > Exynos Console Debugger(ECD) is Loading, Wait\n"
		   " > Push CTRL + Z, You can switch kernel console, ");
	return 0;

err_register_irq:
	if (pdata->uart_free)
		pdata->uart_free(pdev);
err_uart_init:
	platform_set_drvdata(pdev, NULL);
	kfree(inf);
	return ret;
}

static int __init ecd_setup(char *str)
{
	char *move;
	char *console = NULL, *option = NULL;
	unsigned long paddr;

	if (!str)
		goto out;

	move = strchr((const char *)str, ',');
	if (!move) {
		console = str;
	} else {
		console = strsep(&str, ",");
		option = strsep(&str, " ");
	}

	if (console && !strncmp(console, "console", strlen("console")))
		initial_console_enable = true;
	if (option && strncmp(option, "no_firmare", strlen("no_firmare")))
		initial_no_firmware = true;

	if (!initial_no_firmware) {
		ecd_early_vm.phys_addr = memblock_alloc(CONDBG_FW_SIZE, SZ_4K);
		ecd_early_vm.addr = (void *)CONDBG_FW_ADDR;
		ecd_early_vm.size = CONDBG_FW_SIZE + PAGE_SIZE;

		/* Reserved fixed virtual memory within VMALLOC region */
		vm_area_add_early(&ecd_early_vm);

		pr_info("ECD reserved memory:%zx, %zx, for firmware\n",
						paddr, CONDBG_FW_ADDR);
		initial_ecd_enable = true;

		INIT_LIST_HEAD(&ecd_ioremap_list);
	}
out:
	return 0;
}
__setup("ecd_setup=", ecd_setup);

#ifdef CONFIG_PM_SLEEP
static int ecd_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);

	if (interface && interface->pdata->uart_dev_suspend)
		return interface->pdata->uart_dev_suspend(pdev);
	else
		return 0;
}

static int ecd_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);

	if (interface && interface->pdata->uart_dev_resume)
		return interface->pdata->uart_dev_resume(pdev);
	else
		return 0;
}

static const struct dev_pm_ops ecd_pm_ops = {
	.suspend	= ecd_suspend,
	.resume		= ecd_resume,
};
#endif

static struct platform_driver ecd_driver = {
	.probe	= ecd_probe,
	.driver	= {
		.name	= "console_debugger",
#ifdef CONFIG_PM_SLEEP
		.pm	= &ecd_pm_ops,
#endif
	},
};

static int __init ecd_init(void)
{
#if defined(CONFIG_EXYNOS_CONSOLE_DEBUGGER_INTERFACE)
	ecd_tty_init();
#endif
	return platform_driver_register(&ecd_driver);
}
postcore_initcall(ecd_init);

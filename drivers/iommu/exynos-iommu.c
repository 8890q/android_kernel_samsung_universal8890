/* linux/drivers/iommu/exynos_iommu.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/smc.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#include <dt-bindings/sysmmu/sysmmu.h>
#include <dt-bindings/soc/exynos8890-legacy.h>

#include "exynos-iommu.h"

#ifdef CONFIG_SEC_DEBUG
#include <linux/sec_debug.h>
#endif

/* Default IOVA region: [0x1000000, 0xD0000000) */
#define IOVA_START		0x10000000
#define IOVA_END		0xD0000000
#define IOVA_OVFL(addr, size)	((((addr) + (size)) > 0xFFFFFFFF) ||	\
				((addr) + (size) < (addr)))

struct _sysmmu_fi sysmmu_fi;

void display_sysmmu_fault_info(struct _sysmmu_fi *fi)
{
	dev_info(fi->sysmmu, "[%06ld.%06ld][%s] fault information\n",
			fi->fault_time.tv_sec, fi->fault_time.tv_usec,
			fi->is_secure ? "Secure" : "Normal");
	dev_info(fi->sysmmu, " fault addr: %#x\n", fi->fault_addr);
	dev_info(fi->sysmmu, " LV1 entry: %#x\n", fi->lv1_entry);
	if (fi->has_lv2)
		dev_info(fi->sysmmu, " LV2 entry: %#x\n", fi->lv2_entry);
	dev_info(fi->sysmmu, "TLB PPN: %#x, ATTR: %#x\n",
			fi->tlb_ppn, fi->tlb_attr);
	if (fi->has_lv2)
		dev_info(fi->sysmmu, "SBB LINK: %#x, ATTR: %#x\n",
			fi->sbb_link, fi->sbb_attr);
	dev_info(fi->sysmmu, "Flags: %#x\n", fi->flags);
	dev_info(fi->sysmmu, "Last mapp  : [%#010x, %#010x] @ %06ld.%06ld\n",
			fi->map_start, fi->map_end,
			fi->map_time.tv_sec, fi->map_time.tv_usec);
	dev_info(fi->sysmmu, "Last unmap : [%#010x, %#010x] @ %06ld.%06ld\n",
			fi->unmap_start, fi->unmap_end,
			fi->unmap_time.tv_sec, fi->unmap_time.tv_usec);
}

static struct kmem_cache *lv2table_kmem_cache;

static struct sysmmu_drvdata *sysmmu_drvdata_list;
static struct exynos_iommu_owner *sysmmu_owner_list;

struct sysmmu_list_data {
	struct device *sysmmu;
	struct list_head node;
};

struct exynos_client {
	struct list_head list;
	struct device_node *master_np;
	struct exynos_iovmm *vmm_data;
};
static LIST_HEAD(exynos_client_list);
static DEFINE_SPINLOCK(exynos_client_lock);

struct owner_fault_info {
	struct device *master;
	struct notifier_block nb;
};

static struct dentry *exynos_sysmmu_debugfs_root;

int exynos_client_add(struct device_node *np, struct exynos_iovmm *vmm_data)
{
	struct exynos_client *client = kzalloc(sizeof(*client), GFP_KERNEL);

	if (!client)
		return -ENOMEM;

	INIT_LIST_HEAD(&client->list);
	client->master_np = np;
	client->vmm_data = vmm_data;
	spin_lock(&exynos_client_lock);
	list_add_tail(&client->list, &exynos_client_list);
	spin_unlock(&exynos_client_lock);

	return 0;
}

static int iova_from_sent(sysmmu_pte_t *base, sysmmu_pte_t *sent)
{
	return ((unsigned long)sent - (unsigned long)base) *
				(SECT_SIZE / sizeof(sysmmu_pte_t));
}

#define has_sysmmu(dev)		((dev)->archdata.iommu != NULL)

/* For ARM64 only */
static inline void pgtable_flush(void *vastart, void *vaend)
{
	__dma_flush_range(vastart, vaend);
}

#define is_secure_info_fail(x)	((((x) >> 16) & 0xffff) == 0xdead)
static u32 __secure_info_read(unsigned int addr)
{
	u32 ret;

	ret = exynos_smc(SMC_DRM_SEC_SMMU_INFO, (unsigned long)addr,
			0, SEC_SMMU_SFR_READ);
	if (is_secure_info_fail(ret))
		pr_err("Invalid value returned, %#x\n", ret);

	return ret;
}

static bool has_sysmmu_capable_pbuf(void __iomem *sfrbase)
{
	unsigned long cfg = readl_relaxed(sfrbase + REG_MMU_CAPA);

	return MMU_HAVE_PB(cfg);
}

static bool has_sysmmu_set_associative_tlb(void __iomem *sfrbase)
{
	u32 cfg = readl_relaxed(sfrbase + REG_MMU_CAPA_1);

	return MMU_IS_TLB_CONFIGURABLE(cfg);
}

static void __sysmmu_set_tlb_line_size(void __iomem *sfrbase)
{
	u32 cfg =  readl_relaxed(sfrbase + REG_L2TLB_CFG);
	cfg &= ~MMU_MASK_LINE_SIZE;
	cfg |= MMU_DEFAULT_LINE_SIZE;
	writel_relaxed(cfg, sfrbase + REG_L2TLB_CFG);
}

/* SysMMU v5/v6 prefetch registers and LMM presets from the 8890 driver. */
#define REG_PB_LMM	0x300
#define REG_PB_INDICATE	0x308
#define REG_PB_CFG	0x310
#define REG_PB_AXI_ID	0x330
#define REG_PB_INFO	0x350

static bool sysmmu_has_8890_pb(struct sysmmu_drvdata *data)
{
	return IS_ENABLED(CONFIG_SOC_EXYNOS8890) &&
		MMU_MAJ_VER(data->version) == 6 &&
		has_sysmmu_capable_pbuf(data->sfrbase);
}

static int sysmmu_pb_lmm(unsigned int nr_hw, unsigned int nr_ids)
{
	static const s8 presets[4][6] = {
		{ 1, 1, 0, -1, -1, -1 }, /* three buffers */
		{ 3, 2, 1, 0, -1, -1 }, /* four buffers */
		{ -1, -1, -1, -1, -1, -1 },
		{ 5, 5, 4, 2, 1, 0 },   /* six buffers */
	};

	if (nr_hw < 3 || nr_hw > 6 || !nr_ids || nr_ids > 6)
		return -EINVAL;
	return presets[nr_hw - 3][nr_ids - 1];
}

static void sysmmu_program_pb(struct sysmmu_drvdata *data,
			     const struct sysmmu_pb *pb)
{
	void __iomem *base = data->sfrbase;
	unsigned int i, nr_ids = pb->nr_read + pb->nr_write;
	unsigned int nr_hw, nr_slots;
	int lmm;

	if (!nr_ids)
		return;
	if (pb->group >= ((readl_relaxed(base + REG_MMU_CAPA) >> 20) & 0xf))
		return;

	writel_relaxed(pb->group << 8, base + REG_PB_INDICATE);
	nr_hw = readl_relaxed(base + REG_PB_INFO) & 0xff;
	lmm = sysmmu_pb_lmm(nr_hw, nr_ids);
	if (lmm < 0) {
		dev_warn_once(data->sysmmu, "Invalid prefetch layout: %u/%u\n",
			      nr_ids, nr_hw);
		return;
	}

	/* The LMM combines physical buffers into this many logical slots. */
	if (nr_hw == 3)
		nr_slots = lmm ? 2 : 3;
	else if (nr_hw == 4)
		nr_slots = 4 - lmm;
	else {
		static const u8 slots[] = { 6, 5, 4, 3, 3, 2 };

		nr_slots = slots[lmm];
	}
	/* Disable unused slots too: a group may be shared by several masters. */
	writel_relaxed(lmm, base + REG_PB_LMM);
	for (i = 0; i < nr_slots; i++) {
		u32 config, id;

		writel_relaxed((pb->group << 8) | i, base + REG_PB_INDICATE);
		writel_relaxed(0, base + REG_PB_CFG);
		if (i >= nr_ids)
			continue;
		if (i < pb->nr_read) {
			id = pb->read_id[i];
			config = SYSMMU_PBUFCFG_DEFAULT_INPUT;
		} else {
			id = pb->write_id[i - pb->nr_read];
			config = SYSMMU_PBUFCFG_DEFAULT_OUTPUT;
		}
		writel_relaxed(0xffff0000 | id, base + REG_PB_AXI_ID);
		writel_relaxed(config | 0x100001, base + REG_PB_CFG);
	}
}

static void __exynos_sysmmu_set_prefbuf_axi_id(struct sysmmu_drvdata *data)
{
	struct sysmmu_pb *pb;

	if (!sysmmu_has_8890_pb(data))
		return;
	list_for_each_entry(pb, &data->pb_groups, node)
		sysmmu_program_pb(data, pb);
}

static int sysmmu_parse_pb(struct sysmmu_drvdata *data)
{
	struct device_node *info, *group;
	unsigned int group_id = 0;
	int ret = 0;

	INIT_LIST_HEAD(&data->pb_groups);
	if (!IS_ENABLED(CONFIG_SOC_EXYNOS8890) ||
	    MMU_MAJ_VER(data->version) != 6)
		return 0;
	info = of_get_child_by_name(data->sysmmu->of_node, "pb-info");
	if (!info)
		return 0;

	for_each_child_of_node(info, group) {
		int i, count = of_count_phandle_with_args(group,
				"master_axi_id_list", "#pb-id-cells");

		if (count < 0) {
			ret = count;
			goto out_group;
		}
		for (i = 0; i < count; i++) {
			struct of_phandle_args args;
			struct sysmmu_pb *pb;
			unsigned int j;

			ret = of_parse_phandle_with_args(group, "master_axi_id_list",
					"#pb-id-cells", i, &args);
			if (ret)
				goto out_group;
			pb = devm_kzalloc(data->sysmmu, sizeof(*pb), GFP_KERNEL);
			if (!pb) {
				of_node_put(args.np);
				ret = -ENOMEM;
				goto out_group;
			}
			pb->master_phandle = args.np->phandle;
			pb->group = group_id;
			of_node_put(args.np);
			for (j = 0; j < args.args_count; j++) {
				u32 id = args.args[j];

				if (!is_axi_id(id))
					continue;
				if (id > 0xffff || pb->nr_read + pb->nr_write == SYSMMU_MAX_PBUFS) {
					ret = -EINVAL;
					goto out_group;
				}
				if (is_ar_axi_id(id))
					pb->read_id[pb->nr_read++] = id;
				else
					pb->write_id[pb->nr_write++] = id & AXIID_MASK;
			}
			list_add_tail(&pb->node, &data->pb_groups);
		}
		group_id++;
	}
	of_node_put(info);
	return 0;

out_group:
	of_node_put(group);
	of_node_put(info);
	return ret;
}

static void __sysmmu_tlb_invalidate_all(void __iomem *sfrbase)
{
	writel(0x1, sfrbase + REG_MMU_FLUSH);
}

static void __sysmmu_tlb_invalidate(struct sysmmu_drvdata *drvdata,
				dma_addr_t iova, size_t size)
{
	void * __iomem sfrbase = drvdata->sfrbase;

	__raw_writel(iova, sfrbase + REG_FLUSH_RANGE_START);
	__raw_writel(size - 1 + iova, sfrbase + REG_FLUSH_RANGE_END);
	writel(0x1, sfrbase + REG_MMU_FLUSH_RANGE);
	SYSMMU_EVENT_LOG_TLB_INV_RANGE(SYSMMU_DRVDATA_TO_LOG(drvdata),
					iova, iova + size);
}

static void __sysmmu_set_ptbase(struct sysmmu_drvdata *drvdata,
					phys_addr_t pfn_pgtable)
{
	void * __iomem sfrbase = drvdata->sfrbase;

	writel_relaxed(pfn_pgtable, sfrbase + REG_PT_BASE_PPN);

	__sysmmu_tlb_invalidate_all(sfrbase);
	SYSMMU_EVENT_LOG_TLB_INV_ALL(
			SYSMMU_DRVDATA_TO_LOG(drvdata));
}

void exynos_sysmmu_tlb_invalidate(struct iommu_domain *iommu_domain,
					dma_addr_t d_start, size_t size)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	struct exynos_iommu_owner *owner;
	struct sysmmu_list_data *list;
	sysmmu_iova_t start = (sysmmu_iova_t)d_start;
	unsigned long flags;

	spin_lock_irqsave(&domain->lock, flags);
	list_for_each_entry(owner, &domain->clients_list, client) {
		list_for_each_entry(list, &owner->sysmmu_list, node) {
			struct sysmmu_drvdata *drvdata = dev_get_drvdata(list->sysmmu);

			spin_lock(&drvdata->lock);
			if (!is_sysmmu_active(drvdata) ||
					!is_sysmmu_runtime_active(drvdata)) {
				spin_unlock(&drvdata->lock);
				dev_dbg(drvdata->sysmmu,
					"Skip TLB invalidation %#zx@%#x\n",
							size, start);
				exynos_ss_printk("Skip TLB invalidation %s: %#zx@%#x\n",
						dev_name(drvdata->sysmmu), size, start);
				continue;
			}

			dev_dbg(drvdata->sysmmu,
				"TLB invalidation %#zx@%#x\n", size, start);
			exynos_ss_printk("TLB invalidation %s: %#zx@%#x\n",
					dev_name(drvdata->sysmmu), size, start);

			__sysmmu_tlb_invalidate(drvdata, start, size);

			spin_unlock(&drvdata->lock);
		}
	}
	spin_unlock_irqrestore(&domain->lock, flags);
}


#define is_tlb_entry_for_addr(addr, entry)	\
				(((addr) >> 12) == ((entry) & 0xFFFFF))
#define is_sbb_entry_for_addr(addr, entry)	\
				(((addr) >> 20) == (((entry) >> 8) & 0xFFF))
static unsigned int dump_set_associative_tlb(void __iomem *sfrbase,
						int idx_way, int idx_set)
{
	if (MMU_TLB_ENTRY_VALID(__raw_readl(sfrbase + REG_TLB_ATTR))) {
		u32 vpn = __raw_readl(sfrbase + REG_TLB_VPN);
		u32 ppn = __raw_readl(sfrbase + REG_TLB_PPN);
		u32 attr = __raw_readl(sfrbase + REG_TLB_ATTR);
		pr_crit("[%02d][%02d] VPN: %#010x, PPN: %#010x, ATTR: %#010x\n",
			idx_way, idx_set, vpn, ppn, attr);
		if (is_tlb_entry_for_addr(sysmmu_fi.fault_addr, vpn)) {
			sysmmu_fi.tlb_ppn = ppn;
			sysmmu_fi.tlb_attr = attr;
			sysmmu_fi.flags |= SYSMMU_FI_VALID_TLB;
		}
		return 1;
	}
	return 0;
}

#define MMU_NUM_TLB_SUBLINE		4
static void dump_sysmmu_tlb(void __iomem *sfrbase)
{
	int i, j, k;
	u32 capa = __raw_readl(sfrbase + REG_MMU_CAPA_V7);
	u32 vpn, link, attr;
	unsigned int cnt;

	pr_auto(ASL4, "TLB has %d way, %d set. SBB has %d entries.\n",
			MMU_CAPA_NUM_TLB_WAY(capa),
			(1 << MMU_CAPA_NUM_TLB_SET(capa)),
			(1 << MMU_CAPA_NUM_SBB_ENTRY(capa)));
	pr_auto(ASL4, "------------- TLB[WAY][SET][ENTRY] -------------\n");
	for (i = 0, cnt = 0; i < MMU_CAPA_NUM_TLB_WAY(capa); i++) {
		for (j = 0; j < (1 << MMU_CAPA_NUM_TLB_SET(capa)); j++) {
			for (k = 0; k < MMU_NUM_TLB_SUBLINE; k++) {
				__raw_writel(MMU_SET_TLB_READ_ENTRY(j, i, k),
					sfrbase + REG_TLB_READ);
				cnt += dump_set_associative_tlb(sfrbase, i, j);
			}
		}
	}
	if (!cnt)
		pr_auto(ASL4, ">> No Valid TLB Entries\n");

	pr_auto(ASL4, "--- SBB(Second-Level Page Table Base Address Buffer ---\n");
	for (i = 0, cnt = 0; i < (1 << MMU_CAPA_NUM_SBB_ENTRY(capa)); i++) {
		__raw_writel(i, sfrbase + REG_SBB_READ);
		if (MMU_SBB_ENTRY_VALID(__raw_readl(sfrbase + REG_SBB_VPN))) {
			vpn = __raw_readl(sfrbase + REG_SBB_VPN);
			link = __raw_readl(sfrbase + REG_SBB_LINK);
			attr = __raw_readl(sfrbase + REG_SBB_ATTR);
			pr_auto(ASL4, "[%02d] VPN: %#010x, PPN: %#010x, ATTR: %#010x\n",
				i, vpn, link, attr);
			cnt++;
			if (is_sbb_entry_for_addr(sysmmu_fi.fault_addr, vpn)) {
				sysmmu_fi.sbb_link = link;
				sysmmu_fi.sbb_attr = attr;
				sysmmu_fi.flags |= SYSMMU_FI_VALID_SBB;
			}
		}
	}
	if (!cnt)
		pr_auto(ASL4, ">> No Valid SBB Entries\n");
}

static char *sysmmu_fault_name[SYSMMU_FAULTS_NUM] = {
	"PTW ACCESS FAULT",
	"PAGE FAULT",
	"L1TLB MULTI-HIT FAULT",
	"ACCESS FAULT",
	"SECURITY FAULT",
	"UNKNOWN FAULT"
};

void dump_sysmmu_status(void __iomem *sfrbase)
{
	int info;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t phys;

	pgd = pgd_offset_k((unsigned long)sfrbase);
	if (!pgd) {
		pr_crit("Invalid virtual address %p\n", sfrbase);
		return;
	}

	pud = pud_offset(pgd, (unsigned long)sfrbase);
	if (!pud) {
		pr_crit("Invalid virtual address %p\n", sfrbase);
		return;
	}

	pmd = pmd_offset(pud, (unsigned long)sfrbase);
	if (!pmd) {
		pr_crit("Invalid virtual address %p\n", sfrbase);
		return;
	}

	pte = pte_offset_kernel(pmd, (unsigned long)sfrbase);
	if (!pte) {
		pr_crit("Invalid virtual address %p\n", sfrbase);
		return;
	}

	info = MMU_RAW_VER(__raw_readl(sfrbase + REG_MMU_VERSION));

	phys = pte_pfn(*pte) << PAGE_SHIFT;
	pr_crit("ADDR: %pa(VA: %p), MMU_CTRL: %#010x, PT_BASE: %#010x\n",
		&phys, sfrbase,
		__raw_readl(sfrbase + REG_MMU_CTRL),
		__raw_readl(sfrbase + REG_PT_BASE_PPN));
	pr_crit("VERSION %d.%d.%d, MMU_CFG: %#010x, MMU_STATUS: %#010x\n",
		MMU_MAJ_VER(info), MMU_MIN_VER(info), MMU_REV_VER(info),
		__raw_readl(sfrbase + REG_MMU_CFG),
		__raw_readl(sfrbase + REG_MMU_STATUS));

	dump_sysmmu_tlb(sfrbase);
}

static void show_secure_fault_information(struct sysmmu_drvdata *drvdata,
				   int flags, unsigned long fault_addr)
{
	unsigned int info;
	phys_addr_t pgtable;
	int fault_id = SYSMMU_FAULT_ID(flags);
	unsigned int sfrbase = drvdata->securebase;
	const char *port_name = NULL;
#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
	char temp_buf[SZ_128];
#endif

	sysmmu_fi.fault_time = ktime_to_timeval(ktime_get());
	sysmmu_fi.sysmmu = drvdata->sysmmu;
	sysmmu_fi.is_secure = true;
	sysmmu_fi.fault_addr = (u32)fault_addr;

	pgtable = __secure_info_read(sfrbase + REG_PT_BASE_PPN);
	pgtable <<= PAGE_SHIFT;

	info = __secure_info_read(sfrbase + REG_FAULT_TRANS_INFO);

	of_property_read_string(drvdata->sysmmu->of_node,
					"port-name", &port_name);

	pr_auto_once(4);
	pr_auto(ASL4, "----------------------------------------------------------\n");
	pr_auto(ASL4, "From [%s], SysMMU %s %s at %#010lx (page table @ %pa)\n",
		port_name ? port_name : dev_name(drvdata->sysmmu),
		(flags & IOMMU_FAULT_WRITE) ? "WRITE" : "READ",
		sysmmu_fault_name[fault_id], fault_addr, &pgtable);

#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
	snprintf(temp_buf, SZ_128, "%s %s %s at %#010lx (%pa)",
		port_name ? port_name : dev_name(drvdata->sysmmu),
		(flags & IOMMU_FAULT_WRITE) ? "WRITE" : "READ",
		sysmmu_fault_name[fault_id], fault_addr, &pgtable);
	sec_debug_set_extra_info_sysmmu(temp_buf);	
#endif

	if (fault_id == SYSMMU_FAULT_UNKNOWN) {
		pr_auto(ASL4, "The fault is not caused by this System MMU.\n");
		pr_auto(ASL4, "Please check IRQ and SFR base address.\n");
		goto finish;
	}

	pr_auto(ASL4, "AxID: %#x, AxLEN: %#x\n", info & 0xFFFF, (info >> 16) & 0xF);

	if (fault_id == SYSMMU_FAULT_PTW_ACCESS)
		pr_auto(ASL4, "System MMU has failed to access page table\n");

	if (!pfn_valid(pgtable >> PAGE_SHIFT)) {
		pr_auto(ASL4, "Page table base is not in a valid memory region\n");
	} else {
		sysmmu_pte_t *ent;
		ent = section_entry(phys_to_virt(pgtable), fault_addr);
		pr_auto(ASL4, "Lv1 entry: %#010x\n", *ent);
		sysmmu_fi.lv1_entry = (u32)*ent;
		sysmmu_fi.flags |= SYSMMU_FI_VALID_PGTABLE;

		if (lv1ent_page(ent)) {
			ent = page_entry(ent, fault_addr);
			pr_auto(ASL4, "Lv2 entry: %#010x\n", *ent);
			sysmmu_fi.has_lv2 = true;
			sysmmu_fi.lv2_entry = (u32)*ent;
		}
	}

	info = MMU_RAW_VER(__secure_info_read(sfrbase + REG_MMU_VERSION));

	pr_auto(ASL4, "ADDR: %#x, MMU_CTRL: %#010x, PT_BASE: %#010x\n",
		sfrbase,
		__secure_info_read(sfrbase + REG_MMU_CTRL),
		__secure_info_read(sfrbase + REG_PT_BASE_PPN));
	pr_auto(ASL4, "VERSION %d.%d.%d, MMU_CFG: %#010x, MMU_STATUS: %#010x\n",
		MMU_MAJ_VER(info), MMU_MIN_VER(info), MMU_REV_VER(info),
		__secure_info_read(sfrbase + REG_MMU_CFG),
		__secure_info_read(sfrbase + REG_MMU_STATUS));

finish:
	pr_auto(ASL4, "----------------------------------------------------------\n");
	pr_auto_disable(4);
}

static void show_fault_information(struct sysmmu_drvdata *drvdata,
				   int flags, unsigned long fault_addr)
{
	unsigned int info;
	phys_addr_t pgtable;
	int fault_id = SYSMMU_FAULT_ID(flags);
	const char *port_name = NULL;
#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
	char temp_buf[SZ_128];
#endif

	sysmmu_fi.fault_time = ktime_to_timeval(ktime_get());
	sysmmu_fi.sysmmu = drvdata->sysmmu;
	sysmmu_fi.is_secure = false;
	sysmmu_fi.fault_addr = (u32)fault_addr;

	pgtable = __raw_readl(drvdata->sfrbase + REG_PT_BASE_PPN);
	pgtable <<= PAGE_SHIFT;

	if (MMU_MAJ_VER(drvdata->version) >= 7) {
		info = __raw_readl(drvdata->sfrbase + REG_FAULT_TRANS_INFO);
	} else {
		/* TODO: Remove me later */
		info = __raw_readl(drvdata->sfrbase +
			((flags & IOMMU_FAULT_WRITE) ?
			 REG_FAULT_AW_TRANS_INFO : REG_FAULT_AR_TRANS_INFO));
	}

	of_property_read_string(drvdata->sysmmu->of_node,
					"port-name", &port_name);

	pr_auto_once(4);
	pr_auto(ASL4, "----------------------------------------------------------\n");
	pr_auto(ASL4, "From [%s], SysMMU %s %s at %#010lx (page table @ %pa)\n",
		port_name ? port_name : dev_name(drvdata->sysmmu),
		(flags & IOMMU_FAULT_WRITE) ? "WRITE" : "READ",
		sysmmu_fault_name[fault_id], fault_addr, &pgtable);

#ifdef CONFIG_SEC_DEBUG_EXTRA_INFO
	snprintf(temp_buf, SZ_128, "%s %s %s at %#010lx (%pa)",
		port_name ? port_name : dev_name(drvdata->sysmmu),
		(flags & IOMMU_FAULT_WRITE) ? "WRITE" : "READ",
		sysmmu_fault_name[fault_id], fault_addr, &pgtable);
	sec_debug_set_extra_info_sysmmu(temp_buf);	
#endif

	if (fault_id == SYSMMU_FAULT_UNKNOWN) {
		pr_auto(ASL4, "The fault is not caused by this System MMU.\n");
		pr_auto(ASL4, "Please check IRQ and SFR base address.\n");
		goto finish;
	}

	pr_auto(ASL4, "AxID: %#x, AxLEN: %#x\n", info & 0xFFFF, (info >> 16) & 0xF);

	if (pgtable != drvdata->pgtable)
		pr_auto(ASL4, "Page table base of driver: %pa\n",
			&drvdata->pgtable);

	if (fault_id == SYSMMU_FAULT_PTW_ACCESS)
		pr_auto(ASL4, "System MMU has failed to access page table\n");

	if (!pfn_valid(pgtable >> PAGE_SHIFT)) {
		pr_auto(ASL4, "Page table base is not in a valid memory region\n");
	} else {
		sysmmu_pte_t *ent;
		ent = section_entry(phys_to_virt(pgtable), fault_addr);
		pr_auto(ASL4, "Lv1 entry: %#010x\n", *ent);
		sysmmu_fi.lv1_entry = (u32)*ent;
		sysmmu_fi.flags |= SYSMMU_FI_VALID_PGTABLE;

		if (lv1ent_page(ent)) {
			ent = page_entry(ent, fault_addr);
			pr_auto(ASL4, "Lv2 entry: %#010x\n", *ent);
			sysmmu_fi.has_lv2 = true;
			sysmmu_fi.lv2_entry = (u32)*ent;
		}
	}

	dump_sysmmu_status(drvdata->sfrbase);

finish:
	pr_auto(ASL4, "----------------------------------------------------------\n");
	pr_auto_disable(4);
}

#define REG_INT_STATUS_WRITE_BIT 16

irqreturn_t exynos_sysmmu_irq_secure(int irq, void *dev_id)
{
	struct sysmmu_drvdata *drvdata = dev_id;
	unsigned int itype = 0;
	unsigned long addr = -1;
	int flags = 0;

	dev_err(drvdata->sysmmu, "Secure irq occured!\n");
	if (!drvdata->securebase) {
		dev_err(drvdata->sysmmu, "Unknown interrupt occurred\n");
		BUG();
	} else {
		dev_err(drvdata->sysmmu, "Secure base = %#lx\n",
				(unsigned long)drvdata->securebase);
	}

	itype =  __ffs(__secure_info_read(drvdata->securebase + REG_INT_STATUS));
	if (itype >= REG_INT_STATUS_WRITE_BIT) {
		itype -= REG_INT_STATUS_WRITE_BIT;
		flags = IOMMU_FAULT_WRITE;
	}

	addr = __secure_info_read(drvdata->securebase + REG_FAULT_ADDR);
	flags |= SYSMMU_FAULT_FLAG(itype);

	show_secure_fault_information(drvdata, flags, addr);

	atomic_notifier_call_chain(&drvdata->fault_notifiers, addr, &sysmmu_fi);

	BUG();

	return IRQ_HANDLED;
}

static irqreturn_t exynos_sysmmu_irq(int irq, void *dev_id)
{
	struct sysmmu_drvdata *drvdata = dev_id;
	unsigned int itype;
	unsigned long addr = -1;
	int flags = 0;
	int ret;

	dev_info(drvdata->sysmmu, "%s:%d: irq(%d) happened\n", __func__, __LINE__, irq);

	WARN(!is_sysmmu_active(drvdata),
		"Fault occurred while System MMU %s is not enabled!\n",
		dev_name(drvdata->sysmmu));

	if (MMU_MAJ_VER(drvdata->version) >= 7) {
		u32 info;

		itype =  __ffs(__raw_readl(drvdata->sfrbase + REG_INT_STATUS));
		if (WARN_ON(!(itype < SYSMMU_FAULT_UNKNOWN)))
			itype = SYSMMU_FAULT_UNKNOWN;
		else
			addr = __raw_readl(drvdata->sfrbase + REG_FAULT_ADDR);

		info = __raw_readl(drvdata->sfrbase + REG_FAULT_TRANS_INFO);
		flags = MMU_IS_READ_FAULT(info) ?
			IOMMU_FAULT_READ : IOMMU_FAULT_WRITE;
		flags |= SYSMMU_FAULT_FLAG(itype);
	} else {
		/* TODO: Remove me later */
		itype =  __ffs(__raw_readl(drvdata->sfrbase + REG_INT_STATUS));
		if (itype >= REG_INT_STATUS_WRITE_BIT) {
			itype -= REG_INT_STATUS_WRITE_BIT;
			flags = IOMMU_FAULT_WRITE;
		}

		if (WARN_ON(!(itype < SYSMMU_FAULT_UNKNOWN)))
			itype = SYSMMU_FAULT_UNKNOWN;
		else
			addr = __raw_readl(drvdata->sfrbase +
					((flags & IOMMU_FAULT_WRITE) ?
					 REG_FAULT_AW_ADDR : REG_FAULT_AR_ADDR));
		flags |= SYSMMU_FAULT_FLAG(itype);
	}

	show_fault_information(drvdata, flags, addr);
	ret = atomic_notifier_call_chain(&drvdata->fault_notifiers, addr, &sysmmu_fi);
	ret = atomic_notifier_call_chain(&drvdata->fault_notifiers, addr, &flags);
	if (ret == -EAGAIN) {
		u32 clear_mask = __raw_readl(drvdata->sfrbase + REG_INT_STATUS);

		__raw_writel(clear_mask, drvdata->sfrbase + REG_INT_CLEAR);
		pr_err("Fault occurred, but try again!\n");
		return IRQ_HANDLED;
	}

	panic("Unrecoverable System MMU Fault!!");

	return IRQ_HANDLED;
}

static int get_hw_version(struct device *dev, void __iomem *sfrbase)
{
	int ret;

	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		dev_err(dev, "Failed to runtime pm get(%d)\n", ret);
		return ret;
	}
	ret = MMU_RAW_VER(__raw_readl(sfrbase + REG_MMU_VERSION));
	pm_runtime_put(dev);

	return ret;
}

static int __init __sysmmu_secure_irq_init(struct device *sysmmu,
				     struct sysmmu_drvdata *drvdata)
{
	struct platform_device *pdev = to_platform_device(sysmmu);
	u32 secure_reg;
	int ret;

	ret = platform_get_irq(pdev, 1);
	if (ret <= 0) {
		dev_err(sysmmu, "Unable to find secure IRQ resource\n");
		return -EINVAL;
	}
	dev_info(sysmmu, "Registering secure irq %d\n", ret);

	ret = devm_request_irq(sysmmu, ret, exynos_sysmmu_irq_secure, 0,
			dev_name(sysmmu), drvdata);
	if (ret) {
		dev_err(sysmmu, "Failed to register secure irq handler\n");
		return ret;
	}

	ret = of_property_read_u32(sysmmu->of_node,
				"sysmmu,secure_base", &secure_reg);
	if (!ret) {
		drvdata->securebase = secure_reg;
		dev_info(sysmmu, "Secure base = %#x\n", drvdata->securebase);
	} else {
		dev_err(sysmmu, "Failed to get secure register\n");
		return ret;
	}

	return ret;
}

static int __init sysmmu_parse_dt(struct device *sysmmu,
				struct sysmmu_drvdata *drvdata)
{
	const char *props_name = "sysmmu,tlb_property";
	struct tlb_props *tlb_props = &drvdata->tlb_props;
	struct tlb_priv_id *priv_id_cfg = NULL;
	struct tlb_priv_addr *priv_addr_cfg = NULL;
	unsigned int qos = DEFAULT_QOS_VALUE;
	unsigned int prop;
	int ret;
	int i, cnt, priv_id_cnt = 0, priv_addr_cnt = 0;
	unsigned int priv_id_idx = 0, priv_addr_idx = 0;

	/* Parsing QoS */
	ret = of_property_read_u32_index(sysmmu->of_node, "qos", 0, &qos);
	if (!ret && (qos > 15)) {
		dev_err(sysmmu, "Invalid QoS value %d, use default.\n", qos);
		qos = DEFAULT_QOS_VALUE;
	}
	drvdata->qos = qos;
	drvdata->block_when_stop = of_property_read_bool(sysmmu->of_node,
						"sysmmu,block-when-stop");

	/* Secure IRQ */
	if (of_find_property(sysmmu->of_node, "sysmmu,secure-irq", NULL)) {
		ret = __sysmmu_secure_irq_init(sysmmu, drvdata);
		if (ret) {
			dev_err(sysmmu, "Failed to init secure irq\n");
			return ret;
		}
	}

	if (of_property_read_bool(sysmmu->of_node, "sysmmu,no-suspend"))
		dev_pm_syscore_device(sysmmu, true);

	/* Parsing TLB properties */
	cnt = of_property_count_u32_elems(sysmmu->of_node, props_name);
	for (i = 0; i < cnt; i+=2) {
		ret = of_property_read_u32_index(sysmmu->of_node,
			props_name, i, &prop);
		if (ret) {
			dev_err(sysmmu, "failed to get property."
				       "cnt = %d, ret = %d\n", i, ret);
			return -EINVAL;
		}

		switch (prop & WAY_TYPE_MASK) {
		case _PRIVATE_WAY_ID:
			priv_id_cnt++;
			tlb_props->flags |= TLB_WAY_PRIVATE_ID;
			break;
		case _PRIVATE_WAY_ADDR:
			priv_addr_cnt++;
			tlb_props->flags |= TLB_WAY_PRIVATE_ADDR;
			break;
		case _PUBLIC_WAY:
			tlb_props->flags |= TLB_WAY_PUBLIC;
			tlb_props->public_cfg = (prop & ~WAY_TYPE_MASK);
			break;
		default:
			dev_err(sysmmu, "Undefined properties!: %#x\n", prop);
			break;
		}
	}

	if (priv_id_cnt) {
		priv_id_cfg = kzalloc(sizeof(*priv_id_cfg) * priv_id_cnt,
								GFP_KERNEL);
		if (!priv_id_cfg)
			return -ENOMEM;
	}

	if (priv_addr_cnt) {
		priv_addr_cfg = kzalloc(sizeof(*priv_addr_cfg) * priv_addr_cnt,
								GFP_KERNEL);
		if (!priv_addr_cfg) {
			ret = -ENOMEM;
			goto err_priv_id;
		}
	}

	for (i = 0; i < cnt; i+=2) {
		ret = of_property_read_u32_index(sysmmu->of_node,
			props_name, i, &prop);
		if (ret) {
			dev_err(sysmmu, "failed to get property again? "
				       "cnt = %d, ret = %d\n", i, ret);
			ret = -EINVAL;
			goto err_priv_addr;
		}

		switch (prop & WAY_TYPE_MASK) {
		case _PRIVATE_WAY_ID:
			BUG_ON(!priv_id_cfg || priv_id_idx >= priv_id_cnt);

			priv_id_cfg[priv_id_idx].cfg = prop & ~WAY_TYPE_MASK;
			ret = of_property_read_u32_index(sysmmu->of_node,
				props_name, i+1, &priv_id_cfg[priv_id_idx].id);
			if (ret) {
				dev_err(sysmmu, "failed to get id property"
						"cnt = %d, ret = %d\n", i, ret);
				goto err_priv_addr;
			}
			priv_id_idx++;
			break;
		case _PRIVATE_WAY_ADDR:
			BUG_ON(!priv_addr_cfg || priv_addr_idx >= priv_addr_cnt);

			priv_addr_cfg[priv_addr_idx].cfg = prop & ~WAY_TYPE_MASK;
			priv_addr_idx++;
			break;
		case _PUBLIC_WAY:
			break;
		}
	}

	tlb_props->priv_id_cfg = priv_id_cfg;
	tlb_props->priv_id_cnt = priv_id_cnt;

	tlb_props->priv_addr_cfg = priv_addr_cfg;
	tlb_props->priv_addr_cnt = priv_addr_cnt;

	return 0;

err_priv_addr:
	if (priv_addr_cfg)
		kfree(priv_addr_cfg);
err_priv_id:
	if (priv_id_cfg)
		kfree(priv_id_cfg);

	return ret;
}

static int __init exynos_sysmmu_probe(struct platform_device *pdev)
{
	int irq, ret;
	struct device *dev = &pdev->dev;
	struct sysmmu_drvdata *data;
	struct resource *res;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "Failed to get resource info\n");
		return -ENOENT;
	}

	data->sfrbase = devm_ioremap_resource(dev, res);
	if (IS_ERR(data->sfrbase))
		return PTR_ERR(data->sfrbase);

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(dev, "Unable to find IRQ resource\n");
		return irq;
	}

	ret = devm_request_irq(dev, irq, exynos_sysmmu_irq, 0,
				dev_name(dev), data);
	if (ret) {
		dev_err(dev, "Unabled to register handler of irq %d\n", irq);
		return ret;
	}

	data->clk = devm_clk_get(dev, "aclk");
	if (IS_ERR(data->clk)) {
		dev_err(dev, "Failed to get clock!\n");
		return PTR_ERR(data->clk);
	} else  {
		ret = clk_prepare(data->clk);
		if (ret) {
			dev_err(dev, "Failed to prepare clk\n");
			return ret;
		}
	}

	data->sysmmu = dev;
	spin_lock_init(&data->lock);
	ATOMIC_INIT_NOTIFIER_HEAD(&data->fault_notifiers);

	platform_set_drvdata(pdev, data);

	pm_runtime_enable(dev);

	ret = exynos_iommu_init_event_log(SYSMMU_DRVDATA_TO_LOG(data),
				SYSMMU_LOG_LEN);
	if (!ret)
		sysmmu_add_log_to_debugfs(exynos_sysmmu_debugfs_root,
				SYSMMU_DRVDATA_TO_LOG(data), dev_name(dev));
	else
		return ret;

	data->version = get_hw_version(dev, data->sfrbase);

	ret = sysmmu_parse_pb(data);
	if (ret)
		return ret;

	ret = sysmmu_parse_dt(data->sysmmu, data);
	if (ret) {
		dev_err(dev, "Failed to parse DT\n");
		return ret;
	}

	if (!sysmmu_drvdata_list) {
		sysmmu_drvdata_list = data;
	} else {
		data->next = sysmmu_drvdata_list->next;
		sysmmu_drvdata_list->next = data;
	}

	dev_info(data->sysmmu, "is probed. Version %d.%d.%d\n",
			MMU_MAJ_VER(data->version),
			MMU_MIN_VER(data->version),
			MMU_REV_VER(data->version));

	return 0;
}

static void __sysmmu_disable_nocount(struct sysmmu_drvdata *drvdata)
{

	writel_relaxed(0, drvdata->sfrbase + REG_MMU_CFG);
	if (IS_ENABLED(CONFIG_SOC_EXYNOS8890) &&
	    MMU_MAJ_VER(drvdata->version) == 6) {
		u32 ctrl = drvdata->block_when_stop ?
				CTRL_BLOCK_DISABLE : CTRL_DISABLE;

		/* Exynos8890 v6 uses the original direct-disable handshake. */
		writel_relaxed(ctrl, drvdata->sfrbase + REG_MMU_CTRL);
		BUG_ON(readl_relaxed(drvdata->sfrbase + REG_MMU_CTRL) != ctrl);
	} else {
		sysmmu_control(drvdata->sfrbase, false);
	}

	clk_disable(drvdata->clk);

	SYSMMU_EVENT_LOG_DISABLE(SYSMMU_DRVDATA_TO_LOG(drvdata));
}

static bool __sysmmu_disable(struct sysmmu_drvdata *drvdata)
{
	bool disabled;
	unsigned long flags;

	spin_lock_irqsave(&drvdata->lock, flags);

	disabled = set_sysmmu_inactive(drvdata);

	if (disabled) {
		drvdata->pgtable = 0;

		if (is_sysmmu_runtime_active(drvdata))
			__sysmmu_disable_nocount(drvdata);

		dev_dbg(drvdata->sysmmu, "Disabled\n");
	} else  {
		dev_dbg(drvdata->sysmmu, "%d times left to disable\n",
					drvdata->activations);
	}

	spin_unlock_irqrestore(&drvdata->lock, flags);

	return disabled;
}

static void sysmmu_disable_from_master(struct device *master)
{
	unsigned long flags;
	struct exynos_iommu_owner *owner = master->archdata.iommu;
	struct sysmmu_list_data *list;
	struct sysmmu_drvdata *drvdata;

	BUG_ON(!has_sysmmu(master));

	spin_lock_irqsave(&owner->lock, flags);
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		drvdata = dev_get_drvdata(list->sysmmu);
		__sysmmu_disable(drvdata);
	}
	spin_unlock_irqrestore(&owner->lock, flags);
}

static void __sysmmu_set_public_way(struct sysmmu_drvdata *drvdata,
						unsigned int public_cfg)
{
	u32 cfg = __raw_readl(drvdata->sfrbase + REG_PUBLIC_WAY_CFG);
	cfg &= ~MMU_PUBLIC_WAY_MASK;
	cfg |= public_cfg;

	writel_relaxed(cfg, drvdata->sfrbase + REG_PUBLIC_WAY_CFG);

	dev_dbg(drvdata->sysmmu, "public_cfg : %#x\n", cfg);
}

static void __sysmmu_set_private_way_id(struct sysmmu_drvdata *drvdata,
						unsigned int way_idx)
{
	struct tlb_priv_id *priv_cfg = drvdata->tlb_props.priv_id_cfg;
	u32 cfg = __raw_readl(drvdata->sfrbase + REG_PRIVATE_WAY_CFG(way_idx));

	cfg &= ~MMU_PRIVATE_WAY_MASK;
	cfg |= MMU_WAY_CFG_ID_MATCHING | MMU_WAY_CFG_PRIVATE_ENABLE |
						priv_cfg[way_idx].cfg;

	writel_relaxed(cfg, drvdata->sfrbase + REG_PRIVATE_WAY_CFG(way_idx));
	writel_relaxed(priv_cfg[way_idx].id,
			drvdata->sfrbase + REG_PRIVATE_ID(way_idx));

	dev_dbg(drvdata->sysmmu, "priv ID way[%d] cfg : %#x, id : %#x\n",
					way_idx, cfg, priv_cfg[way_idx].id);
}

static void __sysmmu_set_private_way_addr(struct sysmmu_drvdata *drvdata,
						unsigned int priv_addr_idx)
{
	struct tlb_priv_addr *priv_cfg = drvdata->tlb_props.priv_addr_cfg;
	unsigned int way_idx = drvdata->tlb_props.priv_id_cnt + priv_addr_idx;
	u32 cfg = __raw_readl(drvdata->sfrbase + REG_PRIVATE_WAY_CFG(way_idx));

	cfg &= ~MMU_PRIVATE_WAY_MASK;
	cfg |= MMU_WAY_CFG_ADDR_MATCHING | MMU_WAY_CFG_PRIVATE_ENABLE |
						priv_cfg[priv_addr_idx].cfg;

	writel_relaxed(cfg, drvdata->sfrbase + REG_PRIVATE_WAY_CFG(way_idx));

	dev_dbg(drvdata->sysmmu, "priv ADDR way[%d] cfg : %#x\n", way_idx, cfg);
}

static void __sysmmu_init_config(struct sysmmu_drvdata *drvdata)
{
	unsigned long cfg = 0;

	writel_relaxed(CTRL_BLOCK, drvdata->sfrbase + REG_MMU_CTRL);

	if (drvdata->qos != DEFAULT_QOS_VALUE)
		cfg |= CFG_QOS_OVRRIDE | CFG_QOS(drvdata->qos);

	if (MMU_MAJ_VER(drvdata->version) >= 7) {
		u32 cfg = __raw_readl(drvdata->sfrbase + REG_MMU_CAPA_V7);
		u32 tlb_way_num = MMU_CAPA_NUM_TLB_WAY(cfg);
		u32 set_cnt = 0;
		struct tlb_props *tlb_props = &drvdata->tlb_props;
		unsigned int i;
		int priv_id_cnt = tlb_props->priv_id_cnt;
		int priv_addr_cnt = tlb_props->priv_addr_cnt;

		if (tlb_props->flags & TLB_WAY_PUBLIC)
			__sysmmu_set_public_way(drvdata,
					tlb_props->public_cfg);

		if (tlb_props->flags & TLB_WAY_PRIVATE_ID) {
			for (i = 0; i < priv_id_cnt &&
					set_cnt < tlb_way_num; i++, set_cnt++)
				__sysmmu_set_private_way_id(drvdata, i);
		}

		if (tlb_props->flags & TLB_WAY_PRIVATE_ADDR) {
			for (i = 0; i < priv_addr_cnt &&
					set_cnt < tlb_way_num; i++, set_cnt++)
				__sysmmu_set_private_way_addr(drvdata, i);
		}

		if (priv_id_cnt + priv_addr_cnt > tlb_way_num) {
			dev_warn(drvdata->sysmmu,
				"Too many values than TLB way count %d,"
				" so ignored!\n", tlb_way_num);
			dev_warn(drvdata->sysmmu,
				"Number of private way id/addr = %d/%d\n",
					priv_id_cnt, priv_addr_cnt);
		}
	} else {
		__exynos_sysmmu_set_prefbuf_axi_id(drvdata);
		if (has_sysmmu_set_associative_tlb(drvdata->sfrbase))
			__sysmmu_set_tlb_line_size(drvdata->sfrbase);
		cfg |= CFG_FLPDCACHE | CFG_ACGEN;
	}

	cfg |= __raw_readl(drvdata->sfrbase + REG_MMU_CFG) & ~CFG_MASK;
	writel_relaxed(cfg, drvdata->sfrbase + REG_MMU_CFG);
}

static void __sysmmu_enable_nocount(struct sysmmu_drvdata *drvdata)
{
	clk_enable(drvdata->clk);

	__sysmmu_init_config(drvdata);

	__sysmmu_set_ptbase(drvdata, drvdata->pgtable / PAGE_SIZE);

	sysmmu_control(drvdata->sfrbase, true);

	SYSMMU_EVENT_LOG_ENABLE(SYSMMU_DRVDATA_TO_LOG(drvdata));
}

static int __sysmmu_enable(struct sysmmu_drvdata *drvdata, phys_addr_t pgtable)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&drvdata->lock, flags);
	if (set_sysmmu_active(drvdata)) {
		drvdata->pgtable = pgtable;

		if (is_sysmmu_runtime_active(drvdata))
			__sysmmu_enable_nocount(drvdata);

		dev_dbg(drvdata->sysmmu, "Enabled\n");
	} else {
		ret = (pgtable == drvdata->pgtable) ? 1 : -EBUSY;

		dev_dbg(drvdata->sysmmu, "already enabled\n");
	}

	if (WARN_ON(ret < 0))
		set_sysmmu_inactive(drvdata); /* decrement count */

	spin_unlock_irqrestore(&drvdata->lock, flags);

	return ret;
}

static int sysmmu_enable_from_master(struct device *master,
				struct exynos_iommu_domain *domain)
{
	int ret = 0;
	unsigned long flags;
	struct exynos_iommu_owner *owner = master->archdata.iommu;
	struct sysmmu_list_data *list;
	struct sysmmu_drvdata *drvdata;
	phys_addr_t pgtable = virt_to_phys(domain->pgtable);

	spin_lock_irqsave(&owner->lock, flags);
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		drvdata = dev_get_drvdata(list->sysmmu);
		ret = __sysmmu_enable(drvdata, pgtable);

		/* rollback if enable is failed */
		if (ret < 0) {
			list_for_each_entry_continue_reverse(list,
						&owner->sysmmu_list, node) {
				drvdata = dev_get_drvdata(list->sysmmu);
				__sysmmu_disable(drvdata);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&owner->lock, flags);

	return ret;
}

#ifdef CONFIG_PM_SLEEP
static int exynos_sysmmu_suspend(struct device *dev)
{
	unsigned long flags;
	struct sysmmu_drvdata *drvdata = dev_get_drvdata(dev);

	spin_lock_irqsave(&drvdata->lock, flags);
	if (is_sysmmu_active(drvdata) &&
			is_sysmmu_runtime_active(drvdata)) {
		__sysmmu_disable_nocount(drvdata);
		drvdata->is_suspended = true;
	}
	spin_unlock_irqrestore(&drvdata->lock, flags);

	return 0;
}

static int exynos_sysmmu_resume(struct device *dev)
{
	unsigned long flags;
	struct sysmmu_drvdata *drvdata = dev_get_drvdata(dev);

	spin_lock_irqsave(&drvdata->lock, flags);
	if (drvdata->is_suspended) {
		__sysmmu_enable_nocount(drvdata);
		drvdata->is_suspended = false;
	}
	spin_unlock_irqrestore(&drvdata->lock, flags);

	return 0;
}
#endif

static const struct dev_pm_ops sysmmu_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(exynos_sysmmu_suspend, exynos_sysmmu_resume)
};

static const struct of_device_id sysmmu_of_match[] = {
	{ .compatible	= "samsung,exynos-sysmmu", },
	{ },
};

static struct platform_driver exynos_sysmmu_driver __refdata = {
	.probe	= exynos_sysmmu_probe,
	.driver	= {
		.name		= "exynos-sysmmu",
		.of_match_table	= sysmmu_of_match,
		.pm		= &sysmmu_pm_ops,
		.suppress_bind_attrs = true,
	}
};

static struct iommu_domain *exynos_iommu_domain_alloc(unsigned type)
{
	struct exynos_iommu_domain *domain;

	if (type != IOMMU_DOMAIN_UNMANAGED)
		return NULL;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	domain->pgtable = (sysmmu_pte_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!domain->pgtable)
		goto err_pgtable;

	domain->lv2entcnt = (atomic_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!domain->lv2entcnt)
		goto err_counter;

	if (exynos_iommu_init_event_log(IOMMU_PRIV_TO_LOG(domain), IOMMU_LOG_LEN))
		goto err_init_event_log;

	pgtable_flush(domain->pgtable, domain->pgtable + NUM_LV1ENTRIES);

	spin_lock_init(&domain->lock);
	spin_lock_init(&domain->pgtablelock);
	INIT_LIST_HEAD(&domain->clients_list);

	/* TODO: get geometry from device tree */
	domain->domain.geometry.aperture_start = 0;
	domain->domain.geometry.aperture_end   = ~0UL;
	domain->domain.geometry.force_aperture = true;

	return &domain->domain;

err_init_event_log:
	free_pages((unsigned long)domain->lv2entcnt, 2);
err_counter:
	free_pages((unsigned long)domain->pgtable, 2);
err_pgtable:
	kfree(domain);
	return NULL;
}

static void exynos_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	struct exynos_iommu_owner *owner;
	unsigned long flags;
	int i;

	WARN_ON(!list_empty(&domain->clients_list));

	spin_lock_irqsave(&domain->lock, flags);

	list_for_each_entry(owner, &domain->clients_list, client)
		sysmmu_disable_from_master(owner->master);

	while (!list_empty(&domain->clients_list))
		list_del_init(domain->clients_list.next);

	spin_unlock_irqrestore(&domain->lock, flags);

	for (i = 0; i < NUM_LV1ENTRIES; i++)
		if (lv1ent_page(domain->pgtable + i))
			kmem_cache_free(lv2table_kmem_cache,
				phys_to_virt(lv2table_base(domain->pgtable + i)));

	free_pages((unsigned long)domain->pgtable, 2);
	free_pages((unsigned long)domain->lv2entcnt, 2);
	kfree(domain);
}

static int exynos_iommu_attach_device(struct iommu_domain *iommu_domain,
				   struct device *master)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	struct exynos_iommu_owner *owner;
	phys_addr_t pagetable = virt_to_phys(domain->pgtable);
	unsigned long flags;
	int ret = -ENODEV;

	if (!has_sysmmu(master)) {
		dev_err(master, "has no sysmmu device.\n");
		return -ENODEV;
	}

	spin_lock_irqsave(&domain->lock, flags);
	list_for_each_entry(owner, &domain->clients_list, client) {
		if (owner->master == master) {
			dev_err(master, "is already attached!\n");
			spin_unlock_irqrestore(&domain->lock, flags);
			return -EEXIST;
		}
	}
	/* owner is under domain. */
	owner = master->archdata.iommu;
	list_add_tail(&owner->client, &domain->clients_list);
	spin_unlock_irqrestore(&domain->lock, flags);

	ret = sysmmu_enable_from_master(master, domain);
	if (ret < 0) {
		dev_err(master, "%s: Failed to attach IOMMU with pgtable %pa\n",
					__func__, &pagetable);
		return ret;
	}

	dev_dbg(master, "%s: Attached IOMMU with pgtable %pa %s\n",
		__func__, &pagetable, (ret == 0) ? "" : ", again");
	SYSMMU_EVENT_LOG_IOMMU_ATTACH(IOMMU_PRIV_TO_LOG(domain), master);

	return 0;
}

static void exynos_iommu_detach_device(struct iommu_domain *iommu_domain,
				    struct device *master)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	phys_addr_t pagetable = virt_to_phys(domain->pgtable);
	struct exynos_iommu_owner *owner, *tmp_owner;
	unsigned long flags;
	bool found = false;

	if (!has_sysmmu(master))
		return;

	spin_lock_irqsave(&domain->lock, flags);
	list_for_each_entry_safe(owner, tmp_owner,
				&domain->clients_list, client) {
		if (owner->master == master) {
			sysmmu_disable_from_master(master);
			list_del_init(&owner->client);
			found = true;
		}
	}
	spin_unlock_irqrestore(&domain->lock, flags);

	if (found) {
		dev_dbg(master, "%s: Detached IOMMU with pgtable %pa\n",
					__func__, &pagetable);
		SYSMMU_EVENT_LOG_IOMMU_DETACH(IOMMU_PRIV_TO_LOG(domain), master);
	} else {
		dev_err(master, "%s: No IOMMU is attached\n", __func__);
	}
}

static sysmmu_pte_t *alloc_lv2entry(struct exynos_iommu_domain *domain,
				sysmmu_pte_t *sent, sysmmu_iova_t iova,
				atomic_t *pgcounter, gfp_t gfpmask)
{
	if (lv1ent_section(sent)) {
		WARN(1, "Trying mapping on %#08x mapped with 1MiB page", iova);
		return ERR_PTR(-EADDRINUSE);
	}

	if (lv1ent_fault(sent)) {
		unsigned long flags;
		sysmmu_pte_t *pent = NULL;

		if (!(gfpmask & __GFP_ATOMIC)) {
			pent = kmem_cache_zalloc(lv2table_kmem_cache, gfpmask);
			if (!pent)
				return ERR_PTR(-ENOMEM);
		}

		spin_lock_irqsave(&domain->pgtablelock, flags);
		if (lv1ent_fault(sent)) {
			if (!pent) {
				pent = kmem_cache_zalloc(lv2table_kmem_cache, gfpmask);
				if (!pent) {
					spin_unlock_irqrestore(&domain->pgtablelock, flags);
					return ERR_PTR(-ENOMEM);
				}
			}

			*sent = mk_lv1ent_page(virt_to_phys(pent));
			kmemleak_ignore(pent);
			atomic_set(pgcounter, NUM_LV2ENTRIES);
			pgtable_flush(pent, pent + NUM_LV2ENTRIES);
			pgtable_flush(sent, sent + 1);
			SYSMMU_EVENT_LOG_IOMMU_ALLOCSLPD(IOMMU_PRIV_TO_LOG(domain),
					iova & SECT_MASK);
		} else {
			/* Pre-allocated entry is not used, so free it. */
			kmem_cache_free(lv2table_kmem_cache, pent);
		}
		spin_unlock_irqrestore(&domain->pgtablelock, flags);
	}

	return page_entry(sent, iova);
}
static void clear_lv2_page_table(sysmmu_pte_t *ent, int n)
{
	if (n > 0)
		memset(ent, 0, sizeof(*ent) * n);
}

static int lv1set_section(struct exynos_iommu_domain *domain,
			  sysmmu_pte_t *sent, sysmmu_iova_t iova,
			  phys_addr_t paddr, int prot, atomic_t *pgcnt)
{
	bool shareable = !!(prot & IOMMU_CACHE);

	if (lv1ent_section(sent)) {
		WARN(1, "Trying mapping on 1MiB@%#08x that is mapped",
			iova);
		return -EADDRINUSE;
	}

	if (lv1ent_page(sent)) {
		if (WARN_ON(atomic_read(pgcnt) != NUM_LV2ENTRIES)) {
			WARN(1, "Trying mapping on 1MiB@%#08x that is mapped",
				iova);
			return -EADDRINUSE;
		}
		/* TODO: for v7, free lv2 page table */
	}

	*sent = mk_lv1ent_sect(paddr);
	if (shareable)
		set_lv1ent_shareable(sent);
	pgtable_flush(sent, sent + 1);

	return 0;
}

static int lv2set_page(sysmmu_pte_t *pent, phys_addr_t paddr, size_t size,
						int prot, atomic_t *pgcnt)
{
	bool shareable = !!(prot & IOMMU_CACHE);

	if (size == SPAGE_SIZE) {
		if (WARN_ON(!lv2ent_fault(pent)))
			return -EADDRINUSE;

		*pent = mk_lv2ent_spage(paddr);
		if (shareable)
			set_lv2ent_shareable(pent);
		pgtable_flush(pent, pent + 1);
		atomic_dec(pgcnt);
	} else { /* size == LPAGE_SIZE */
		int i;

		for (i = 0; i < SPAGES_PER_LPAGE; i++, pent++) {
			if (WARN_ON(!lv2ent_fault(pent))) {
				clear_lv2_page_table(pent - i, i);
				return -EADDRINUSE;
			}

			*pent = mk_lv2ent_lpage(paddr);
			if (shareable)
				set_lv2ent_shareable(pent);
		}
		pgtable_flush(pent - SPAGES_PER_LPAGE, pent);
		atomic_sub(SPAGES_PER_LPAGE, pgcnt);
	}

	return 0;
}
static int exynos_iommu_map(struct iommu_domain *iommu_domain,
			    unsigned long l_iova, phys_addr_t paddr, size_t size,
			    int prot)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	sysmmu_pte_t *entry;
	sysmmu_iova_t iova = (sysmmu_iova_t)l_iova;
	int ret = -ENOMEM;

	BUG_ON(domain->pgtable == NULL);

	entry = section_entry(domain->pgtable, iova);

	if (size == SECT_SIZE) {
		ret = lv1set_section(domain, entry, iova, paddr, prot,
				     &domain->lv2entcnt[lv1ent_offset(iova)]);
	} else {
		sysmmu_pte_t *pent;

		pent = alloc_lv2entry(domain, entry, iova,
			      &domain->lv2entcnt[lv1ent_offset(iova)], GFP_KERNEL);

		if (IS_ERR(pent))
			ret = PTR_ERR(pent);
		else
			ret = lv2set_page(pent, paddr, size, prot,
				       &domain->lv2entcnt[lv1ent_offset(iova)]);
	}

	if (ret)
		pr_err("%s: Failed(%d) to map %#zx bytes @ %#x\n",
			__func__, ret, size, iova);

	return ret;
}

static size_t exynos_iommu_unmap(struct iommu_domain *iommu_domain,
				 unsigned long l_iova, size_t size)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	sysmmu_iova_t iova = (sysmmu_iova_t)l_iova;
	sysmmu_pte_t *sent, *pent;
	size_t err_pgsize;
	atomic_t *lv2entcnt = &domain->lv2entcnt[lv1ent_offset(iova)];

	BUG_ON(domain->pgtable == NULL);

	sent = section_entry(domain->pgtable, iova);

	if (lv1ent_section(sent)) {
		if (WARN_ON(size < SECT_SIZE)) {
			err_pgsize = SECT_SIZE;
			goto err;
		}

		*sent = 0;
		pgtable_flush(sent, sent + 1);
		size = SECT_SIZE;
		goto done;
	}

	if (unlikely(lv1ent_fault(sent))) {
		if (size > SECT_SIZE)
			size = SECT_SIZE;
		goto done;
	}

	/* lv1ent_page(sent) == true here */

	pent = page_entry(sent, iova);

	if (unlikely(lv2ent_fault(pent))) {
		size = SPAGE_SIZE;
		goto done;
	}

	if (lv2ent_small(pent)) {
		*pent = 0;
		size = SPAGE_SIZE;
		pgtable_flush(pent, pent + 1);
		atomic_inc(lv2entcnt);
		goto unmap_flpd;
	}

	/* lv1ent_large(pent) == true here */
	if (WARN_ON(size < LPAGE_SIZE)) {
		err_pgsize = LPAGE_SIZE;
		goto err;
	}

	clear_lv2_page_table(pent, SPAGES_PER_LPAGE);
	pgtable_flush(pent, pent + SPAGES_PER_LPAGE);
	size = LPAGE_SIZE;
	atomic_add(SPAGES_PER_LPAGE, lv2entcnt);

unmap_flpd:
	/* TODO: for v7, remove all */
	if (atomic_read(lv2entcnt) == NUM_LV2ENTRIES) {
		unsigned long flags;
		spin_lock_irqsave(&domain->pgtablelock, flags);
		if (atomic_read(lv2entcnt) == NUM_LV2ENTRIES) {
			kmem_cache_free(lv2table_kmem_cache,
					page_entry(sent, 0));
			atomic_set(lv2entcnt, 0);
			*sent = 0;

			SYSMMU_EVENT_LOG_IOMMU_FREESLPD(
					IOMMU_PRIV_TO_LOG(domain),
					iova_from_sent(domain->pgtable, sent));
		}
		spin_unlock_irqrestore(&domain->pgtablelock, flags);
	}

done:
	/* TLB invalidation is performed by IOVMM */

	return size;
err:
	pr_err("%s: Failed: size(%#zx) @ %#x is smaller than page size %#zx\n",
		__func__, size, iova, err_pgsize);

	return 0;
}

static phys_addr_t exynos_iommu_iova_to_phys(struct iommu_domain *iommu_domain,
					  dma_addr_t d_iova)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(iommu_domain);
	sysmmu_iova_t iova = (sysmmu_iova_t)d_iova;
	sysmmu_pte_t *entry;
	phys_addr_t phys = 0;

	entry = section_entry(domain->pgtable, iova);

	if (lv1ent_section(entry)) {
		phys = section_phys(entry) + section_offs(iova);
	} else if (lv1ent_page(entry)) {
		entry = page_entry(entry, iova);

		if (lv2ent_large(entry))
			phys = lpage_phys(entry) + lpage_offs(iova);
		else if (lv2ent_small(entry))
			phys = spage_phys(entry) + spage_offs(iova);
	}

	return phys;
}

static int exynos_iommu_of_xlate(struct device *master,
				 struct of_phandle_args *spec)
{
	struct exynos_iommu_owner *owner = master->archdata.iommu;
	struct platform_device *sysmmu_pdev = of_find_device_by_node(spec->np);
	struct sysmmu_drvdata *data;
	struct device *sysmmu;
	struct exynos_client *client, *buf_client;
	struct sysmmu_list_data *list_data;

	if (!sysmmu_pdev)
		return -ENODEV;

	data = platform_get_drvdata(sysmmu_pdev);
	if (!data)
		return -ENODEV;

	sysmmu = data->sysmmu;
	if (!owner) {
		owner = kzalloc(sizeof(*owner), GFP_KERNEL);
		if (!owner)
			return -ENOMEM;

		INIT_LIST_HEAD(&owner->sysmmu_list);
		INIT_LIST_HEAD(&owner->client);
		master->archdata.iommu = owner;
		owner->master = master;
		spin_lock_init(&owner->lock);

		list_for_each_entry_safe(client, buf_client,
					&exynos_client_list, list) {
			if (client->master_np == master->of_node) {
				owner->domain = client->vmm_data->domain;
				owner->vmm_data = client->vmm_data;
				list_del(&client->list);
				kfree(client);
			}
		}

		/* HACK: Make relationship between group and master */
		master->iommu_group = owner->vmm_data->group;

		if (!sysmmu_owner_list) {
			sysmmu_owner_list = owner;
		} else {
			owner->next = sysmmu_owner_list->next;
			sysmmu_owner_list->next = owner;
		}
	}

	list_for_each_entry(list_data, &owner->sysmmu_list, node)
		if (list_data->sysmmu == sysmmu)
			return 0;

	list_data = devm_kzalloc(sysmmu, sizeof(*list_data), GFP_KERNEL);
	if (!list_data)
		return -ENOMEM;

	INIT_LIST_HEAD(&list_data->node);
	list_data->sysmmu = sysmmu;

	/*
	 * System MMUs are attached in the order of the presence
	 * in device tree
	 */
	list_add_tail(&list_data->node, &owner->sysmmu_list);
	dev_info(master, "is owner of %s\n", dev_name(sysmmu));

	return 0;
}

static struct iommu_ops exynos_iommu_ops = {
	.domain_alloc = exynos_iommu_domain_alloc,
	.domain_free = exynos_iommu_domain_free,
	.attach_dev = exynos_iommu_attach_device,
	.detach_dev = exynos_iommu_detach_device,
	.map = exynos_iommu_map,
	.unmap = exynos_iommu_unmap,
	.map_sg = default_iommu_map_sg,
	.iova_to_phys = exynos_iommu_iova_to_phys,
	.pgsize_bitmap = SECT_SIZE | LPAGE_SIZE | SPAGE_SIZE,
	.of_xlate = exynos_iommu_of_xlate,
};

void exynos_sysmmu_show_status(struct device *master)
{
	struct exynos_iommu_owner *owner;
	struct sysmmu_list_data *list;

	if (!has_sysmmu(master)) {
		dev_err(master, "has no sysmmu!\n");
		return;
	}

	owner = master->archdata.iommu;
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		unsigned long flags;
		struct sysmmu_drvdata *drvdata;

		drvdata = dev_get_drvdata(list->sysmmu);

		spin_lock_irqsave(&drvdata->lock, flags);
		if (!is_sysmmu_active(drvdata) ||
				!is_sysmmu_runtime_active(drvdata)) {
			dev_info(drvdata->sysmmu,
				"%s: SysMMU is not active\n", __func__);
			spin_unlock_irqrestore(&drvdata->lock, flags);
			continue;
		}

		dev_info(drvdata->sysmmu, "Dumping status.\n");
		dump_sysmmu_status(drvdata->sfrbase);

		spin_unlock_irqrestore(&drvdata->lock, flags);
	}
}

static int sysmmu_fault_notifier(struct notifier_block *nb,
				     unsigned long fault_addr, void *data)
{
	struct owner_fault_info *info;
	struct exynos_iommu_owner *owner = NULL;
	int ret = 0;

	info = container_of(nb, struct owner_fault_info, nb);
	owner = info->master->archdata.iommu;

	if (owner && owner->fault_handler)
		ret = owner->fault_handler(owner->domain, owner->master,
			fault_addr, (unsigned long)data,
			owner->token ? owner->token : data);

	return ret;
}

int exynos_iommu_add_fault_handler(struct device *master,
			     iommu_fault_handler_t handler, void *token)
{
	struct exynos_iommu_owner *owner = master->archdata.iommu;
	struct sysmmu_list_data *list;
	struct sysmmu_drvdata *drvdata;
	struct owner_fault_info *info;
	unsigned long flags;

	if (!has_sysmmu(master)) {
		dev_info(master, "%s doesn't have sysmmu\n", dev_name(master));
		return -ENODEV;
	}

	spin_lock_irqsave(&owner->lock, flags);

	owner->fault_handler = handler;
	owner->token = token;

	list_for_each_entry(list, &owner->sysmmu_list, node) {
		info = kzalloc(sizeof(*info), GFP_ATOMIC);
		if (!info) {
			spin_unlock_irqrestore(&owner->lock, flags);
			return -ENOMEM;
		}
		info->master = master;
		info->nb.notifier_call = sysmmu_fault_notifier;

		drvdata = dev_get_drvdata(list->sysmmu);

		atomic_notifier_chain_register(
				&drvdata->fault_notifiers, &info->nb);
		dev_info(master, "Fault handler is registered for %s\n",
						dev_name(list->sysmmu));
	}

	spin_unlock_irqrestore(&owner->lock, flags);

	return 0;
}

int sysmmu_set_prefetch_buffer_property(struct device *dev,
			unsigned int inplanes, unsigned int onplanes,
			unsigned int ipoption[], unsigned int opoption[])
{
	struct exynos_iommu_owner *owner = dev->archdata.iommu;
	struct sysmmu_list_data *list;
	unsigned long flags;

	if (!owner || !dev->of_node)
		return -EINVAL;
	if (inplanes > SYSMMU_MAX_PBUFS || onplanes > SYSMMU_MAX_PBUFS)
		return -EINVAL;

	spin_lock_irqsave(&owner->lock, flags);
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		struct sysmmu_drvdata *data = dev_get_drvdata(list->sysmmu);
		struct sysmmu_pb *pb;

		spin_lock(&data->lock);
		if (!is_sysmmu_active(data) || !is_sysmmu_runtime_active(data) ||
		    !sysmmu_has_8890_pb(data))
			goto unlock;
		list_for_each_entry(pb, &data->pb_groups, node) {
			unsigned int i;

			if (pb->master_phandle != dev->of_node->phandle)
				continue;
			/* Keep the LMM/AXI-ID layout installed at enable time. */
			for (i = 0; i < min(inplanes, pb->nr_read); i++) {
				u32 config = ipoption ? ipoption[i] :
						SYSMMU_PBUFCFG_DEFAULT_INPUT;

				writel_relaxed((pb->group << 8) | i,
					       data->sfrbase + REG_PB_INDICATE);
				writel_relaxed(config | 0x100001,
					       data->sfrbase + REG_PB_CFG);
			}
			for (i = 0; i < min(onplanes, pb->nr_write); i++) {
				u32 config = opoption ? opoption[i] :
						SYSMMU_PBUFCFG_DEFAULT_OUTPUT;

				writel_relaxed((pb->group << 8) | (pb->nr_read + i),
					       data->sfrbase + REG_PB_INDICATE);
				writel_relaxed(config | 0x100001,
					       data->sfrbase + REG_PB_CFG);
			}
		}
unlock:
		spin_unlock(&data->lock);
	}
	spin_unlock_irqrestore(&owner->lock, flags);
	return 0;
}

static int __init exynos_iommu_create_domain(void)
{
	struct device_node *domain_np;
	int ret;

	for_each_compatible_node(domain_np, NULL, "samsung,exynos-iommu-bus") {
		struct device_node *np;
		struct exynos_iovmm *vmm = NULL;
		struct exynos_iommu_domain *domain;
		unsigned int start = IOVA_START, end = IOVA_END;
		dma_addr_t d_addr;
		size_t d_size;
		int i = 0;

		ret = of_get_dma_window(domain_np, NULL, 0, NULL, &d_addr, &d_size);
		if (!ret) {
			if (d_addr == 0 || IOVA_OVFL(d_addr, d_size)) {
				pr_err("Failed to get valid dma ranges,\n");
				pr_err("Domain %s, range %pad++%#zx]\n",
					domain_np->name, &d_addr, d_size);
				of_node_put(domain_np);
				return -EINVAL;
			}
			start = d_addr;
			end = d_addr + d_size;
		}
		pr_info("DMA ranges for domain %s. [%#x..%#x]\n",
					domain_np->name, start, end);

		while ((np = of_parse_phandle(domain_np, "domain-clients", i++))) {
			if (!vmm) {
				vmm = exynos_create_single_iovmm(np->name,
								start, end);
				if (IS_ERR(vmm)) {
					pr_err("%s: Failed to create IOVM space\
							of %s\n",
							__func__, np->name);
					of_node_put(np);
					of_node_put(domain_np);
					return -ENOMEM;
				}

				/* HACK: Make one group for one domain */
				domain = to_exynos_domain(vmm->domain);
				vmm->group = iommu_group_alloc();
				iommu_attach_group(vmm->domain, vmm->group);
			}
			/* Relationship between domain and client is added. */
			ret = exynos_client_add(np, vmm);
			if (ret) {
				pr_err("Failed to adding client[%s] to domain %s\n",
						np->name, domain_np->name);
				of_node_put(np);
				of_node_put(domain_np);
				return -ENOMEM;
			} else {
				pr_info("Added client.%d[%s] into domain %s\n",
						i, np->name, domain_np->name);
			}
			of_node_put(np);
		}
		of_node_put(domain_np);
	}

	return 0;
}

int exynos_iommu_runtime_suspend(struct device *master)
{
	int ret;
	struct exynos_iommu_owner *owner;
	struct sysmmu_list_data *list;

	ret = pm_generic_runtime_suspend(master);
	if (!has_sysmmu(master) || ret)
		return ret;

	exynos_ss_printk("Runtime suspend %s\n", dev_name(master));

	owner = master->archdata.iommu;
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		unsigned long flags;
		struct sysmmu_drvdata *drvdata;

		drvdata = dev_get_drvdata(list->sysmmu);

		SYSMMU_EVENT_LOG_POWEROFF(SYSMMU_DRVDATA_TO_LOG(drvdata));
		spin_lock_irqsave(&drvdata->lock, flags);
		if (put_sysmmu_runtime_active(drvdata) && is_sysmmu_active(drvdata))
			__sysmmu_disable_nocount(drvdata);
		spin_unlock_irqrestore(&drvdata->lock, flags);
	}

	return ret;
}

int exynos_iommu_runtime_resume(struct device *master)
{
	struct exynos_iommu_owner *owner;
	struct sysmmu_list_data *list;

	if (!has_sysmmu(master))
		return pm_generic_runtime_resume(master);

	exynos_ss_printk("Runtime resume %s\n", dev_name(master));

	owner = master->archdata.iommu;
	list_for_each_entry(list, &owner->sysmmu_list, node) {
		unsigned long flags;
		struct sysmmu_drvdata *drvdata;

		drvdata = dev_get_drvdata(list->sysmmu);

		SYSMMU_EVENT_LOG_POWERON(SYSMMU_DRVDATA_TO_LOG(drvdata));

		spin_lock_irqsave(&drvdata->lock, flags);
		if (get_sysmmu_runtime_active(drvdata) && is_sysmmu_active(drvdata))
			__sysmmu_enable_nocount(drvdata);
		spin_unlock_irqrestore(&drvdata->lock, flags);
	}

	return pm_generic_runtime_resume(master);
}

static const struct dev_pm_ops exynos_iommu_dev_pm_ops = {
	.runtime_suspend = exynos_iommu_runtime_suspend,
	.runtime_resume = exynos_iommu_runtime_resume,
	USE_PLATFORM_PM_SLEEP_OPS
};

static void set_exynos_iommu_pm_ops(struct bus_type *bus)
{
	bus->pm = &exynos_iommu_dev_pm_ops;
}

static int __init exynos_iommu_init(void)
{
	int ret;

	if (lv2table_kmem_cache)
		return 0;

	lv2table_kmem_cache = kmem_cache_create("exynos-iommu-lv2table",
				LV2TABLE_SIZE, LV2TABLE_SIZE, 0, NULL);
	if (!lv2table_kmem_cache) {
		pr_err("%s: Failed to create kmem cache\n", __func__);
		return -ENOMEM;
	}

	exynos_sysmmu_debugfs_root = debugfs_create_dir("sysmmu", NULL);
	if (!exynos_sysmmu_debugfs_root)
		pr_err("%s: Failed to create debugfs entry\n", __func__);

	ret = platform_driver_register(&exynos_sysmmu_driver);
	if (ret) {
		pr_err("%s: Failed to register driver\n", __func__);
		goto err_reg_driver;
	}

	ret = bus_set_iommu(&platform_bus_type, &exynos_iommu_ops);
	if (ret) {
		pr_err("%s: Failed to register exynos-iommu driver.\n",
								__func__);
		goto err_set_iommu;
	}
	ret = exynos_iommu_create_domain();
	if (ret) {
		pr_err("%s: Failed to create domain\n", __func__);
		goto err_create_domain;
	}

	set_exynos_iommu_pm_ops(&platform_bus_type);

	return 0;

err_create_domain:
	bus_set_iommu(&platform_bus_type, NULL);
err_set_iommu:
	platform_driver_unregister(&exynos_sysmmu_driver);
err_reg_driver:
	kmem_cache_destroy(lv2table_kmem_cache);
	return ret;
}

static int __init exynos_iommu_of_setup(struct device_node *np)
{
	struct platform_device *pdev;

	exynos_iommu_init();

	pdev = of_platform_device_create(np, NULL, platform_bus_type.dev_root);
	if (!pdev)
		return -ENODEV;

	of_iommu_set_ops(np, &exynos_iommu_ops);
	return 0;
}

IOMMU_OF_DECLARE(exynos_iommu_of, "samsung,exynos-sysmmu",
		 exynos_iommu_of_setup);

static int mm_fault_translate(int fault)
{
	if (fault & VM_FAULT_OOM)
		return -ENOMEM;
	else if (fault & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
		return -EBUSY;
	else if (fault & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
		return -EFAULT;
	else if (fault & VM_FAULT_FALLBACK)
		return -EAGAIN;

	return -EFAULT;
}

static sysmmu_pte_t *alloc_lv2entry_userptr(struct exynos_iommu_domain *domain,
						sysmmu_iova_t iova)
{
	return alloc_lv2entry(domain, section_entry(domain->pgtable, iova),
			iova, &domain->lv2entcnt[lv1ent_offset(iova)], GFP_ATOMIC);
}

static int sysmmu_map_pte(struct mm_struct *mm,
		pmd_t *pmd, unsigned long addr, unsigned long end,
		struct exynos_iommu_domain *domain, sysmmu_iova_t iova, int prot)
{
	pte_t *pte;
	int ret = 0;
	spinlock_t *ptl;
	bool write = !!(prot & IOMMU_WRITE);
	bool pfnmap = !!(prot & IOMMU_PFNMAP);
	bool shareable = !!(prot & IOMMU_CACHE);
	unsigned int fault_flag = write ? FAULT_FLAG_WRITE : 0;
	sysmmu_pte_t *ent, *ent_beg;

	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		return -ENOMEM;

	ent = alloc_lv2entry_userptr(domain, iova);
	if (IS_ERR(ent)) {
		ret = PTR_ERR(ent);
		goto err;
	}

	ent_beg = ent;

	do {
		if (pte_none(*pte) || !pte_present(*pte) ||
					(write && !pte_write(*pte))) {
			int cnt = 0;
			int maxcnt = 1;

			if (pfnmap) {
				ret = -EFAULT;
				goto err;
			}

			while (cnt++ < maxcnt) {
				spin_unlock(ptl);
				/* find_vma() always successes */
				ret = handle_mm_fault(mm, find_vma(mm, addr),
						addr, fault_flag);
				spin_lock(ptl);
				if (ret & VM_FAULT_ERROR) {
					ret = mm_fault_translate(ret);
					goto err;
				} else {
					ret = 0;
				}
				/*
				 * the racing between handle_mm_fault() and the
				 * page reclamation may cause handle_mm_fault()
				 * to return 0 even though it failed to page in.
				 * This behavior expect the process to access
				 * the paged out entry again then give
				 * handle_mm_fault() a chance again to page in
				 * the entry.
				 */
				if (is_swap_pte(*pte)) {
					BUG_ON(maxcnt > 8);
					maxcnt++;
				}
			}
		}

		BUG_ON(!lv2ent_fault(ent));

		*ent = mk_lv2ent_spage(pte_pfn(*pte) << PAGE_SHIFT);

		if (!pfnmap)
			get_page(pte_page(*pte));
		else
			mk_lv2ent_pfnmap(ent);

		if (shareable)
			set_lv2ent_shareable(ent);

		ent++;
		iova += PAGE_SIZE;

		if ((iova & SECT_MASK) != ((iova - 1) & SECT_MASK)) {
			pgtable_flush(ent_beg, ent);

			ent = alloc_lv2entry_userptr(domain, iova);
			if (IS_ERR(ent)) {
				ret = PTR_ERR(ent);
				goto err;
			}
			ent_beg = ent;
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);

	pgtable_flush(ent_beg, ent);
err:
	pte_unmap_unlock(pte - 1, ptl);
	return ret;
}

static inline int sysmmu_map_pmd(struct mm_struct *mm,
		pud_t *pud, unsigned long addr, unsigned long end,
		struct exynos_iommu_domain *domain, sysmmu_iova_t iova, int prot)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;

	do {
		next = pmd_addr_end(addr, end);
		if (sysmmu_map_pte(mm, pmd, addr, next, domain, iova, prot))
			return -ENOMEM;
		iova += (next - addr);
	} while (pmd++, addr = next, addr != end);
	return 0;
}
static inline int sysmmu_map_pud(struct mm_struct *mm,
		pgd_t *pgd, unsigned long addr, unsigned long end,
		struct exynos_iommu_domain *domain, sysmmu_iova_t iova, int prot)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (sysmmu_map_pmd(mm, pud, addr, next, domain, iova, prot))
			return -ENOMEM;
		iova += (next - addr);
	} while (pud++, addr = next, addr != end);
	return 0;
}
int exynos_iommu_map_userptr(struct iommu_domain *dom, unsigned long addr,
			      dma_addr_t d_iova, size_t size, int prot)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(dom);
	struct mm_struct *mm = current->mm;
	unsigned long end = addr + size;
	dma_addr_t start = d_iova;
	sysmmu_iova_t iova = (sysmmu_iova_t)d_iova;
	unsigned long next;
	pgd_t *pgd;
	int ret;

	BUG_ON(!!((iova | addr | size) & ~PAGE_MASK));

	pgd = pgd_offset(mm, addr);

	do {
		next = pgd_addr_end(addr, end);
		ret = sysmmu_map_pud(mm, pgd, addr, next, domain, iova, prot);
		if (ret)
			goto err;
		iova += (next - addr);
	} while (pgd++, addr = next, addr != end);

	return 0;
err:
	/* unroll */
	exynos_iommu_unmap_userptr(dom, start, size);
	return ret;
}

#define sect_offset(iova)	((iova) & ~SECT_MASK)
#define lv2ents_within(iova)	((SECT_SIZE - sect_offset(iova)) >> SPAGE_ORDER)

void exynos_iommu_unmap_userptr(struct iommu_domain *dom,
				dma_addr_t d_iova, size_t size)
{
	struct exynos_iommu_domain *domain = to_exynos_domain(dom);
	sysmmu_iova_t iova = (sysmmu_iova_t)d_iova;
	sysmmu_pte_t *sent = section_entry(domain->pgtable, iova);
	unsigned int entries = size >> SPAGE_ORDER;
	dma_addr_t start = d_iova;

	while (entries > 0) {
		unsigned int lv2ents, i;
		sysmmu_pte_t *pent;

		/* ignore fault entries */
		if (lv1ent_fault(sent)) {
			lv2ents = min_t(unsigned int, entries, NUM_LV1ENTRIES);
			entries -= lv2ents;
			iova += lv2ents << SPAGE_ORDER;
			sent++;
			continue;
		}

		BUG_ON(!lv1ent_page(sent));

		lv2ents = min_t(unsigned int, lv2ents_within(iova), entries);

		pent = page_entry(sent, iova);
		for (i = 0; i < lv2ents; i++, pent++) {
			/* ignore fault entries */
			if (lv2ent_fault(pent))
				continue;

			BUG_ON(!lv2ent_small(pent));

			if (!lv2ent_pfnmap(pent))
				put_page(phys_to_page(spage_phys(pent)));

			*pent = 0;
		}

		pgtable_flush(pent - lv2ents, pent);

		entries -= lv2ents;
		iova += lv2ents << SPAGE_ORDER;
		sent++;
	}

	exynos_sysmmu_tlb_invalidate(dom, start, size);
}

typedef void (*syncop)(const void *, size_t, int);

static size_t sysmmu_dma_sync_page(phys_addr_t phys, off_t off,
				  size_t pgsize, size_t size,
				  syncop op, enum dma_data_direction dir)
{
	size_t len;
	size_t skip_pages = off >> PAGE_SHIFT;
	struct page *page;

	off = off & ~PAGE_MASK;
	page = phys_to_page(phys) + skip_pages;
	len = min(pgsize - off, size);
	size = len;

	while (len > 0) {
		size_t sz;

		sz = min(PAGE_SIZE, len + off) - off;
		op(kmap(page) + off, sz, dir);
		kunmap(page++);
		len -= sz;
		off = 0;
	}

	return size;
}

static void exynos_iommu_sync(sysmmu_pte_t *pgtable, dma_addr_t iova,
			size_t len, syncop op, enum dma_data_direction dir)
{
	while (len > 0) {
		sysmmu_pte_t *entry;
		size_t done;

		entry = section_entry(pgtable, iova);
		switch (*entry & FLPD_FLAG_MASK) {
		case SECT_FLAG:
			done = sysmmu_dma_sync_page(section_phys(entry),
					section_offs(iova), SECT_SIZE,
					len, op, dir);
			break;
		case SLPD_FLAG:
			entry = page_entry(entry, iova);
			switch (*entry & SLPD_FLAG_MASK) {
			case LPAGE_FLAG:
				done = sysmmu_dma_sync_page(lpage_phys(entry),
						lpage_offs(iova), LPAGE_SIZE,
						len, op, dir);
				break;
			case SPAGE_FLAG:
				done = sysmmu_dma_sync_page(spage_phys(entry),
						spage_offs(iova), SPAGE_SIZE,
						len, op, dir);
				break;
			default: /* fault */
				return;
			}
			break;
		default: /* fault */
			return;
		}

		iova += done;
		len -= done;
	}
}

static sysmmu_pte_t *sysmmu_get_pgtable(struct device *dev)
{
	struct exynos_iommu_owner *owner = dev->archdata.iommu;
	struct exynos_iommu_domain *domain = to_exynos_domain(owner->domain);

	return domain->pgtable;
}

void exynos_iommu_sync_for_device(struct device *dev, dma_addr_t iova,
				  size_t len, enum dma_data_direction dir)
{
	exynos_iommu_sync(sysmmu_get_pgtable(dev),
			iova, len, __dma_map_area, dir);
}

void exynos_iommu_sync_for_cpu(struct device *dev, dma_addr_t iova, size_t len,
				enum dma_data_direction dir)
{
	if (dir == DMA_TO_DEVICE)
		return;

	exynos_iommu_sync(sysmmu_get_pgtable(dev),
			iova, len, __dma_unmap_area, dir);
}

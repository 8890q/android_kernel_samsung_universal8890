#if defined(CONFIG_OF_RESERVED_MEM) && defined(CONFIG_DMA_CMA)

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/memblock.h>
#include <linux/dma-contiguous.h>
#include <linux/cma.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/genalloc.h>
#include <linux/exynos_ion.h>
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
#include <linux/smc.h>
#endif

#include <asm/dma-contiguous.h>

#include <linux/exynos_ion.h>

#include "../ion.h"
#include "../ion_priv.h"
#include "ion_hpa_heap.h"

static struct ion_device *ion_exynos;

#define ION_SECURE_DMA_BASE	0x10000000
#define ION_SECURE_DMA_END	0xE0000000

/* starting from index=1 regarding default index=0 for system heap */
static int nr_heaps = 1;

struct exynos_ion_platform_heap {
	struct ion_platform_heap heap_data;
	struct reserved_mem *rmem;
	unsigned int id;
	unsigned int compat_ids;
	bool secure;
	bool reusable;
	bool recyclable;
	bool protected;
	bool noprot;
	atomic_t secure_ref;
	struct device dev;
	struct ion_heap *heap;
};

static struct ion_platform_heap ion_noncontig_heap __initdata = {
	.name = "ion_noncontig_heap",
	.type = ION_HEAP_TYPE_SYSTEM,
	.id = EXYNOS_ION_HEAP_SYSTEM_ID,
};

struct exynos_ion_platform_heap ion_hpa_heaps[] __initdata = {
#ifdef CONFIG_HPA
	{
		.heap_data = {
			.name = "crypto_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_CRYPTO,
		},
		.id = ION_EXYNOS_HEAP_ID_CRYPTO,
		.secure = true,
	}, {
		.heap_data = {
			.name = "vfw_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_VIDEO_FW,
		},
		.id = ION_EXYNOS_HEAP_ID_VIDEO_FW,
		.compat_ids = (1 << 24),
		.secure = true,
	}, {
		.heap_data = {
			.name = "vnfw_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_VIDEO_NFW,
		},
		.id = ION_EXYNOS_HEAP_ID_VIDEO_NFW,
		.compat_ids = (1 << 20),
	}, {
		.heap_data = {
			.name = "vstream_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_VIDEO_STREAM,
		},
		.id = ION_EXYNOS_HEAP_ID_VIDEO_STREAM,
		.compat_ids = (1 << 25) | (1 << 31),
		.secure = true,
	}, {
		.heap_data = {
			.name = "vframe_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_VIDEO_FRAME,
		},
		.id = ION_EXYNOS_HEAP_ID_VIDEO_FRAME,
		.compat_ids = (1 << 26) | (1 << 29),
		.secure = true,
	}, {
		.heap_data = {
			.name = "vscaler_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = ION_EXYNOS_HEAP_ID_VIDEO_SCALER,
		},
		.id = ION_EXYNOS_HEAP_ID_VIDEO_SCALER,
		.compat_ids = (1 << 28),
		.secure = true,
	}, {
		.heap_data = {
			.name = "gpu_heap",
			.type = ION_HEAP_TYPE_HPA,
			.id = 9, /* 9 but it is not defined in exynos_ion.h */
		},
		.id = 9, /* 9 but it is not defined in exynos_ion.h */
		.secure = true,
	},
#endif /* CONFIG_HPA */
};

static struct exynos_ion_platform_heap plat_heaps[ION_NUM_HEAPS];

#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION

static struct gen_pool *secure_iova_pool;
static DEFINE_SPINLOCK(siova_pool_lock);

#define MAX_IOVA_ALIGNMENT	12
static unsigned long find_first_fit_with_align(unsigned long *map,
				unsigned long size, unsigned long start,
				unsigned int nr, void *data)
{
	unsigned long align = ((*(unsigned long *)data) >> PAGE_SHIFT);

	if (align > (1 << MAX_IOVA_ALIGNMENT))
		align = (1 << MAX_IOVA_ALIGNMENT);

	return bitmap_find_next_zero_area(map, size, start, nr, (align - 1));
}

int ion_secure_iova_alloc(unsigned long *addr, unsigned long size,
				unsigned int align)
{
	spin_lock(&siova_pool_lock);
	if (align > PAGE_SIZE) {
		gen_pool_set_algo(secure_iova_pool,
				find_first_fit_with_align, &align);
		*addr = gen_pool_alloc(secure_iova_pool, size);
		gen_pool_set_algo(secure_iova_pool, NULL, NULL);
	} else {
		*addr = gen_pool_alloc(secure_iova_pool, size);
	}
	spin_unlock(&siova_pool_lock);

	if (*addr == 0) {
		pr_err("%s: failed to allocate secure iova.\
				Used %zu B / Available %zu B\n",
				__func__, gen_pool_size(secure_iova_pool),
				gen_pool_avail(secure_iova_pool));
		return -ENOMEM;
	}
	return 0;
}

void ion_secure_iova_free(unsigned long addr, unsigned long size)
{
	spin_lock(&siova_pool_lock);
	gen_pool_free(secure_iova_pool, addr, size);
	spin_unlock(&siova_pool_lock);
}

int __init ion_secure_iova_pool_create(void)
{
	secure_iova_pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!secure_iova_pool) {
		pr_err("%s: failed to create Secure IOVA pool\n", __func__);
		return -ENOMEM;
	}

	if (gen_pool_add(secure_iova_pool, ION_SECURE_DMA_BASE,
				ION_SECURE_DMA_END - ION_SECURE_DMA_BASE, -1)) {
		pr_err("%s: failed to set address range of Secure IOVA pool\n",
			__func__);
		return -ENOMEM;
	}

	return 0;
}

static int __find_platform_heap_id(unsigned int heap_id)
{
	int i;

	for (i = 0; i < nr_heaps; i++) {
		if (heap_id == plat_heaps[i].id)
			break;
	}

	if (i == nr_heaps)
		return -EINVAL;

	return i;
}

static int __ion_secure_protect_buffer(struct exynos_ion_platform_heap *pdata,
					struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct ion_buffer_info *info = buffer->priv_virt;
	struct ion_buffer_prot_info *prot = &info->prot_desc;
	unsigned long dma_addr = 0;
	int ret = 0;

	BUG_ON(heap->type != ION_HEAP_TYPE_HPA && prot->chunk_count != 1);

	ret = ion_secure_iova_alloc(&dma_addr,
			(prot->chunk_count * prot->chunk_size), PAGE_SIZE);
	if (ret)
		return ret;
	prot->dma_addr = dma_addr;

	__flush_dcache_area(prot, sizeof(struct ion_buffer_prot_info));
	if (prot->chunk_count > 1)
		__flush_dcache_area(phys_to_virt(prot->bus_address),
			sizeof(unsigned long) * prot->chunk_count);

	ret = exynos_smc(SMC_DRM_PPMP_PROT, virt_to_phys(prot), 0, 0);
	if (ret != DRMDRV_OK)
		pr_crit("%s: smc call failed, err=%d\n", __func__, ret);

	return ret;
}

#ifdef CONFIG_SOC_EXYNOS8890
/* Exynos8890 firmware implements SECBUF, without the 8895 secure IOVA ABI. */
static int exynos8890_ion_secure_buffer(struct exynos_ion_platform_heap *pdata,
				      struct ion_buffer *buffer, bool protect)
{
	ion_phys_addr_t addr;
	size_t len;
	int ret;

	if (pdata->reusable) {
		if (!buffer->heap->ops->phys ||
		    buffer->heap->ops->phys(buffer->heap, buffer, &addr, &len))
			return -EFAULT;
	} else {
		addr = pdata->rmem->base;
		len = pdata->rmem->size;
		if (protect) {
			if (atomic_inc_return(&pdata->secure_ref) > 1)
				return 0;
		} else if (!atomic_dec_and_test(&pdata->secure_ref)) {
			return 0;
		}
	}

	ret = exynos_smc(protect ? SMC_DRM_SECBUF_PROT : SMC_DRM_SECBUF_UNPROT,
			 addr, len, pdata->id);
	if (ret != DRMDRV_OK) {
		pr_crit("%s: %s heap %s failed, err=%d\n", __func__,
			protect ? "protect" : "unprotect", buffer->heap->name, ret);
		if (!pdata->reusable) {
			if (protect)
				atomic_dec(&pdata->secure_ref);
			else
				atomic_inc(&pdata->secure_ref);
		}
		return -EFAULT;
	}
	return 0;
}
#endif

int ion_secure_protect(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct exynos_ion_platform_heap *pdata;
	int id;

	id = __find_platform_heap_id(heap->id);
	if (id < 0) {
		pr_err("%s: invalid heap id(%d) for %s\n", __func__,
						heap->id, heap->name);
		return -EINVAL;
	}

	pdata = &plat_heaps[id];
	if (!pdata->secure) {
		pr_err("%s: heap %s is not secure heap\n", __func__,
						heap->name);
		return -EPERM;
	}

	if (pdata->noprot)
		return 0;

#ifdef CONFIG_SOC_EXYNOS8890
	return exynos8890_ion_secure_buffer(pdata, buffer, true);
#else
	return __ion_secure_protect_buffer(pdata, buffer);
#endif
}

static int __ion_secure_unprotect_buffer(struct exynos_ion_platform_heap *pdata,
					struct ion_buffer *buffer)
{
	struct ion_buffer_info *info = buffer->priv_virt;
	unsigned int size = 0;
	int ret = 0;

	ret = exynos_smc(SMC_DRM_PPMP_UNPROT,
			virt_to_phys(&info->prot_desc), 0, 0);
	if (ret != DRMDRV_OK)
		pr_crit("%s: smc call failed, err=%d\n", __func__, ret);

	size = info->prot_desc.chunk_count * info->prot_desc.chunk_size;
	ion_secure_iova_free(info->prot_desc.dma_addr, size);

	return ret;
}

int ion_secure_unprotect(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct exynos_ion_platform_heap *pdata;
	int id;

	id = __find_platform_heap_id(heap->id);
	if (id < 0) {
		pr_err("%s: invalid heap id(%d) for %s\n", __func__,
						heap->id, heap->name);
		return -EINVAL;
	}

	pdata = &plat_heaps[id];
	if (!pdata->secure) {
		pr_err("%s: heap %s is not secure heap\n", __func__, heap->name);
		return -EPERM;
	}

	if (pdata->noprot)
		return 0;

#ifdef CONFIG_SOC_EXYNOS8890
	return exynos8890_ion_secure_buffer(pdata, buffer, false);
#else
	return __ion_secure_unprotect_buffer(pdata, buffer);
#endif
}
#endif

struct ion_client *exynos_ion_client_create(const char *name)
{
	return ion_client_create(ion_exynos, name);
}

bool ion_is_heap_available(struct ion_heap *heap,
				unsigned long flags, void *data)
{
	return true;
}

unsigned int ion_parse_heap_id(unsigned int heap_id_mask, unsigned int flags)
{
	unsigned int heap_id = 1;
	int i;

	pr_debug("%s: heap_id_mask=%#x, flags=%#x\n",
			__func__, heap_id_mask, flags);

	if (heap_id_mask != EXYNOS_ION_HEAP_EXYNOS_CONTIG_MASK)
		return heap_id_mask;

	if (flags & EXYNOS_ION_CONTIG_ID_MASK)
		heap_id = __fls(flags & EXYNOS_ION_CONTIG_ID_MASK);

	for (i = 1; i < nr_heaps; i++) {
		if ((plat_heaps[i].id == heap_id) ||
			(plat_heaps[i].compat_ids & (1 << heap_id)))
			break;
	}

	if (i == nr_heaps) {
		pr_err("%s: bad heap flags %#x\n", __func__, flags);
		return 0;
	}

	pr_debug("%s: found new heap id %d for %s\n", __func__,
			plat_heaps[i].id, plat_heaps[i].heap_data.name);

	return (1 << plat_heaps[i].id);
}

static int exynos_ion_rmem_device_init(struct reserved_mem *rmem,
						struct device *dev)
{
	WARN(1, "%s() should never be called!", __func__);
	return 0;
}

static void exynos_ion_rmem_device_release(struct reserved_mem *rmem,
						struct device *dev)
{
}

/*
 * The below rmem device ops are never called because the the device is not
 * associated with the rmem in the flattened device tree
 */
static const struct reserved_mem_ops exynos_ion_rmem_ops = {
	.device_init	= exynos_ion_rmem_device_init,
	.device_release	= exynos_ion_rmem_device_release,
};

static int __init exynos_ion_reserved_mem_setup(struct reserved_mem *rmem)
{
	struct exynos_ion_platform_heap *pdata;
	struct ion_platform_heap *heap_data;
	int len = 0;
	const __be32 *prop;

	BUG_ON(nr_heaps >= ION_NUM_HEAPS);

	pdata = &plat_heaps[nr_heaps];
	pdata->secure = !!of_get_flat_dt_prop(rmem->fdt_node, "ion,secure", NULL);
	pdata->reusable = !!of_get_flat_dt_prop(rmem->fdt_node, "ion,reusable", NULL);
#ifdef CONFIG_ION_RBIN_HEAP
	pdata->recyclable = !!of_get_flat_dt_prop(rmem->fdt_node, "ion,recyclable", NULL);
#else
	pdata->recyclable = false;
#endif
	pdata->noprot = !!of_get_flat_dt_prop(rmem->fdt_node, "ion,noprot", NULL);

	prop = of_get_flat_dt_prop(rmem->fdt_node, "id", &len);
	if (!prop) {
		pr_err("%s: no <id> found\n", __func__);
		return -EINVAL;
	}

	len /= sizeof(int);
	if (len != 1) {
		pr_err("%s: wrong <id> field format\n", __func__);
		return -EINVAL;
	}

	/*
	 * id=0: system heap
	 * id=1 ~: contig heaps
	 */
	pdata->id = be32_to_cpu(prop[0]);
	if (pdata->id >= ION_NUM_HEAPS) {
		pr_err("%s: bad <id> number\n", __func__);
		return -EINVAL;
	}

	prop = of_get_flat_dt_prop(rmem->fdt_node, "compat-id", &len);
	if (prop) {
		len /= sizeof(int);
		while (len > 0)
			pdata->compat_ids |= (1 << be32_to_cpu(prop[--len]));
	}

	rmem->ops = &exynos_ion_rmem_ops;
	pdata->rmem = rmem;

	heap_data = &pdata->heap_data;
	heap_data->id = pdata->id;
	heap_data->name = rmem->name;
	heap_data->base = rmem->base;
	heap_data->size = rmem->size;

	prop = of_get_flat_dt_prop(rmem->fdt_node, "alignment", &len);
	if (!prop)
		heap_data->align = PAGE_SIZE;
	else
		heap_data->align = be32_to_cpu(prop[0]);

	if (pdata->reusable || pdata->recyclable) {
		int ret;
		struct cma *cma;

		if (pdata->reusable)
			heap_data->type = ION_HEAP_TYPE_DMA;
		else
			heap_data->type = ION_HEAP_TYPE_RBIN;
		heap_data->priv = &pdata->dev;

		/* set as non-coherent device */
		arch_setup_dma_ops(&pdata->dev, 0, 0, NULL, 0);
		ret = cma_init_reserved_mem(
				heap_data->base, heap_data->size, 0, &cma);
		if (ret) {
			pr_err("%s: failed to declare cma region %s (%d)\n",
			       __func__, heap_data->name, ret);
			return ret;
		}
		if (pdata->recyclable) {
			cma_set_rbin(cma);
			totalrbin_pages += (heap_data->size / PAGE_SIZE);
			/*
			 * # of cma pages was increased by this RBIN memory in
			 * cma_init_reserved_mem_with_name(). Need to deduct.
			 */
			totalcma_pages -= (heap_data->size / PAGE_SIZE);
		}

		dma_contiguous_early_fixup(heap_data->base, heap_data->size);

		dev_set_cma_area(&pdata->dev, cma);

		if (pdata->reusable)
			pr_info("CMA memory[%d]: %s:%#lx\n", heap_data->id,
				heap_data->name, (unsigned long)rmem->size);
		else
			pr_info("rbin CMA memory[%d]: %s:%#lx\n", heap_data->id,
				heap_data->name, (unsigned long)rmem->size);
	} else {
		heap_data->type = ION_HEAP_TYPE_CARVEOUT;
		heap_data->priv = rmem;
		pr_info("Reserved memory[%d]: %s:%#lx\n", heap_data->id,
				heap_data->name, (unsigned long)rmem->size);
	}

	atomic_set(&pdata->secure_ref, 0);
	nr_heaps++;

	return 0;
}

#define DECLARE_EXYNOS_ION_RESERVED_REGION(compat, name) \
RESERVEDMEM_OF_DECLARE(name, compat#name, exynos_ion_reserved_mem_setup)

DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", crypto);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", vfw);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", vnfw);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", vstream);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", vframe);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", vscaler);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", camera);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", secure_camera);
DECLARE_EXYNOS_ION_RESERVED_REGION("exynos8890-ion,", tui);

int ion_exynos_contig_heap_info(int region_id, phys_addr_t *phys, size_t *size)
{
	int i;

	if (region_id >= nr_heaps) {
		pr_err("%s: wrong region id %d\n", __func__, region_id);
		return -EINVAL;
	}

	for (i = 1; i < nr_heaps; i++) {
		if (plat_heaps[i].id == region_id) {
			if (plat_heaps[i].reusable) {
				pr_err("%s: operation not permitted for the"
						"cma region %s(%d)\n", __func__,
						plat_heaps[i].heap_data.name,
						region_id);
				return -EPERM;
			}

			if (phys)
				*phys = plat_heaps[i].rmem->base;
			if (size)
				*size = plat_heaps[i].rmem->size;
			break;
		}
	}

	return 0;
}
EXPORT_SYMBOL(ion_exynos_contig_heap_info);

#ifdef CONFIG_DMA_CMA
static struct class *ion_cma_class;

static int __init exynos_ion_create_cma_class(void)
{
	ion_cma_class = class_create(THIS_MODULE, "ion_cma");
	if (IS_ERR(ion_cma_class)) {
		pr_err("%s: failed to create 'ion_cma' class - %ld\n",
			__func__, PTR_ERR(ion_cma_class));
		return PTR_ERR(ion_cma_class);
	}

	return 0;
}
static ssize_t region_name_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct exynos_ion_platform_heap *pdata = dev_get_drvdata(dev);
	return scnprintf(buf, PAGE_SIZE, "%s\n", pdata->heap_data.name);
}

static ssize_t region_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct exynos_ion_platform_heap *pdata = dev_get_drvdata(dev);
	return scnprintf(buf, PAGE_SIZE, "%d\n", pdata->id);
}

static struct device_attribute cma_regname_attr = __ATTR_RO(region_name);
static struct device_attribute cma_regid_attr = __ATTR_RO(region_id);

static int __init exynos_ion_create_cma_devices(
				struct exynos_ion_platform_heap *pdata)
{
	struct device *dev;
	int ret;

	if (!pdata) {
		pr_err("%s: heap_data must be given\n", __func__);
		return -EINVAL;
	}

	dev = device_create(ion_cma_class, NULL, 0, pdata, "ion_%s",
						pdata->heap_data.name);
	if (IS_ERR(dev)) {
		pr_err("%s: failed to create device of %s\n", __func__,
						pdata->heap_data.name);
		return -EINVAL;
	}

	dev_dbg(dev, "%s: Registered (region %d)\n", __func__, pdata->id);

	dev_set_cma_area(dev, dev_get_cma_area(&pdata->dev));

	ret = device_create_file(dev, &cma_regid_attr);
	if (ret)
		dev_err(dev, "%s: failed to create %s file (%d)\n",
				__func__, cma_regid_attr.attr.name, ret);

	ret = device_create_file(dev, &cma_regname_attr);
	if (ret)
		dev_err(dev, "%s: failed to create %s file (%d)\n",
				__func__, cma_regname_attr.attr.name, ret);

	return 0;
}
#else
static int __init exynos_ion_create_cma_class(void)
{
	return 0;
}

static int __init exynos_ion_create_cma_devices(
			struct exynos_ion_platform_heap *pdata)
{
	pr_err("%s: CMA should be configured for '%s'\n",
		__func__, pdata->heap_data.name);

	return 0;
}
#endif


static int __init exynos_ion_populate_heaps(struct ion_device *ion_dev)
{
	int i, ret, num;

	plat_heaps[0].reusable = false;
	memcpy(&plat_heaps[0].heap_data, &ion_noncontig_heap,
				sizeof(struct ion_platform_heap));

	ret = ion_secure_iova_pool_create();
	if (ret)
		return ret;

	num = nr_heaps;
	for (i = 0; i < ARRAY_SIZE(ion_hpa_heaps); i++) {
		int j;
		for (j = 1; j < num; j++)
			if (ion_hpa_heaps[i].heap_data.id == plat_heaps[j].id)
				break;

		if (j == num)
			memcpy(&plat_heaps[nr_heaps++], &ion_hpa_heaps[i],
				sizeof(plat_heaps[0]));
	}

	for (i = 0; i < nr_heaps; i++) {
		plat_heaps[i].heap = ion_heap_create(&plat_heaps[i].heap_data);
		if (IS_ERR(plat_heaps[i].heap)) {
			pr_err("%s: failed to create heap %s[%d]\n", __func__,
					plat_heaps[i].heap_data.name,
					plat_heaps[i].id);
			ret = PTR_ERR(plat_heaps[i].heap);
			goto err;
		}

		ion_device_add_heap(ion_exynos, plat_heaps[i].heap);

		if (plat_heaps[i].reusable)
			exynos_ion_create_cma_devices(&plat_heaps[i]);
	}

	return 0;

err:
	while (i-- > 0)
		ion_heap_destroy(plat_heaps[i].heap);

	return ret;
}

static int __init exynos_ion_init(void)
{
	int ret;

	ion_exynos = ion_device_create(NULL);
	if (IS_ERR(ion_exynos)) {
		pr_err("%s: failed to create ion device\n", __func__);
		return PTR_ERR(ion_exynos);
	}

	ret = exynos_ion_create_cma_class();
	if (ret)
		return ret;

	return exynos_ion_populate_heaps(ion_exynos);
}

subsys_initcall(exynos_ion_init);
#endif

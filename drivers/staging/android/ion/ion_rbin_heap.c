/*
 * drivers/staging/android/ion/ion_rbin_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include "ion.h"
#include "ion_priv.h"

#define NUM_ORDERS ARRAY_SIZE(orders)

static const unsigned int orders[] = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

static int order_to_index(unsigned int order)
{
	int i;
	for (i = 0; i < NUM_ORDERS; i++)
		if (order == orders[i])
			return i;
	BUG();
	return -1;
}

struct ion_rbin_heap {
	struct ion_heap heap;
	struct device *dev;
	struct cma *cma;
	unsigned long   base_pfn;
	unsigned long   count;
	wait_queue_head_t waitqueue;
	struct task_struct *task;
	bool prereclaim_run;
	struct task_struct *task_shrink;
	bool shrink_run;
	struct ion_page_pool *pools[NUM_ORDERS];
};

static struct page *alloc_rbin_page(struct ion_rbin_heap *heap,
				    struct ion_buffer *buffer,
				    unsigned long size_org)
{
	struct device *dev = heap->dev;
	unsigned long size = PAGE_ALIGN(size_org);
	int order = get_order(size);
	struct page *page = NULL;
	void *addr;

	trace_ion_rbin_partial_alloc_start(heap->heap.name, buffer, size, NULL);

	if (size >= (MAX_ORDER_NR_PAGES << PAGE_SHIFT)) {
		page = dma_alloc_from_contiguous(dev, MAX_ORDER_NR_PAGES, MAX_ORDER - 1);
		if (page) {
			size = MAX_ORDER_NR_PAGES << PAGE_SHIFT;
			goto done;
		}
		order = MAX_ORDER - 2;
	} else if (size < (PAGE_SIZE << order)) {
		page = dma_alloc_from_contiguous(dev, size >> PAGE_SHIFT, 0);
		if (page)
			goto done;
		order--;
	}

	for ( ; order >= 0; order--) {
		page = dma_alloc_from_contiguous(dev, 1 << order, 0);
		if (page) {
			size = PAGE_SIZE << order;
			goto done;
		}
	}

done:
	/* CAUTION!! : we assume page->private is not touched by anyone. */
	if (page) {
		addr = page_address(page);
		/*
		 * alloc_rbin_page() can be called by pre-reclaimer.
		 * In that case, buffer will be NULL.
		 * Let the pre-reclaimer zero the region in default.
		 */
		if (!buffer || !(buffer->flags & ION_FLAG_NOZEROED))
			memset(addr, 0, size);
		set_page_private(page, size);
		__flush_dcache_area(addr, size);
	}

	trace_ion_rbin_partial_alloc_end(heap->heap.name, buffer,
					 page ? page_private(page) : 0, page);
	return page;
}

static void free_rbin_page(struct ion_rbin_heap *heap,
			   struct ion_buffer *buffer, struct page *page)
{
	struct device *dev = heap->dev;
	unsigned int size = page_private(page);

	trace_ion_rbin_partial_free_start(heap->heap.name, buffer, size, page);
	dma_release_from_contiguous(dev, page, (PAGE_ALIGN(size) >> PAGE_SHIFT));
	trace_ion_rbin_partial_free_end(heap->heap.name, buffer, size, NULL);
}

static inline void do_expand(struct ion_rbin_heap *heap, struct page *page,
			     unsigned int nr_pages)
{
	unsigned int rem_nr_pages;
	unsigned int order;
	unsigned int total_nr_pages;
	unsigned int free_nr_page;
	struct page *free_page;
	struct ion_page_pool *pool;

	total_nr_pages = page_private(page) >> PAGE_SHIFT;
	rem_nr_pages = total_nr_pages - nr_pages;
	free_page = page + total_nr_pages;

	while (rem_nr_pages) {
		order = ilog2(rem_nr_pages);
		free_nr_page = 1 << order;
		free_page -= free_nr_page;
		set_page_private(free_page, free_nr_page << PAGE_SHIFT);
		pool = heap->pools[order_to_index(order)];
		ion_page_pool_free(pool, free_page);
		rem_nr_pages -= free_nr_page;
	}
	set_page_private(page, nr_pages << PAGE_SHIFT);
}

static struct page *alloc_rbin_page_from_pool(struct ion_rbin_heap *heap,
					      struct ion_buffer *buffer,
					      unsigned long size)
{
	struct page *page = NULL;
	unsigned int size_order;
	unsigned int nr_pages;
	int i;

	trace_ion_rbin_pool_alloc_start(heap->heap.name, buffer, size, NULL);
	size_order = get_order(size);
	nr_pages = size >> PAGE_SHIFT;

	/* try the same or higher order */
	for (i = NUM_ORDERS - 1; i >= 0; i--) {
		if (orders[i] < size_order)
			continue;
		page = ion_page_pool_alloc(heap->pools[i]);
		if (!page)
			continue;
		if (nr_pages < (1 << orders[i]))
			do_expand(heap, page, nr_pages);
		atomic_sub(nr_pages, &rbin_pool_pages);
		goto done;
	}

	/* try lower order */
	for (i = 0; i < NUM_ORDERS; i++) {
		if (orders[i] >= size_order)
			continue;
		page = ion_page_pool_alloc(heap->pools[i]);
		if (!page)
			continue;
		atomic_sub(1 << orders[i], &rbin_pool_pages);
		goto done;
	}

done:
	trace_ion_rbin_pool_alloc_end(heap->heap.name, buffer,
				      page ? page_private(page) : 0, page);
	return page;
}

static int ion_rbin_heap_allocate(struct ion_heap *heap,
				     struct ion_buffer *buffer,
				     unsigned long size_org, unsigned long align,
				     unsigned long flags)
{
	struct ion_rbin_heap *rbin_heap = container_of(heap,
							struct ion_rbin_heap,
							heap);
	struct sg_table *table;
	struct scatterlist *sg;
	struct list_head pages;
	struct page *page, *tmp_page;
	int i = 0;
	unsigned long size, size_remaining;
	unsigned int pagesize;
	unsigned long nr_total;
	long nr_alloc;
	unsigned long from_pool_size = 0;

	/* actually does not support align like system heap or carveout heap */
	if (align > PAGE_SIZE)
		return -EINVAL;

	size_remaining = size = PAGE_ALIGN(size_org);
	nr_total = rbin_heap->count << PAGE_SHIFT;

	nr_alloc = atomic_read(&rbin_allocated_pages) << PAGE_SHIFT;
	if (size > (nr_total - nr_alloc))
		return -ENOMEM;
	nr_alloc = atomic_add_return(size >> PAGE_SHIFT, &rbin_allocated_pages);
	if (nr_alloc > nr_total) {
		atomic_sub(size >> PAGE_SHIFT, &rbin_allocated_pages);
		return -ENOMEM;
	}

	trace_printk("start. len %lu\n", size);
	trace_ion_rbin_alloc_start(heap->name, buffer, size, NULL);

	INIT_LIST_HEAD(&pages);
	while (size_remaining > 0) {
		page = alloc_rbin_page_from_pool(rbin_heap, buffer,
						 size_remaining);
		if (page)
			from_pool_size += page_private(page);
		else
			page = alloc_rbin_page(rbin_heap, buffer,
					       size_remaining);
		if (!page)
			goto free_pages;
		list_add_tail(&page->lru, &pages);
		pagesize = page_private(page);
		size_remaining -= pagesize;
		i++;
	}
	table = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table)
		goto free_pages;

	if (sg_alloc_table(table, i, GFP_KERNEL))
		goto free_table;

	sg = table->sgl;
	list_for_each_entry_safe(page, tmp_page, &pages, lru) {
		unsigned int len;

		pagesize = page_private(page);
		len = pagesize;
		sg_set_page(sg, page, len, 0);
		sg = sg_next(sg);
		list_del(&page->lru);
	}

	buffer->priv_virt = table;
	buffer->sg_table = table;
	trace_printk("end success %9lu %9lu\n",
		     from_pool_size, size - from_pool_size);
	trace_ion_rbin_alloc_end(heap->name, buffer, size, NULL);
	return 0;

free_table:
	kfree(table);
free_pages:
	list_for_each_entry_safe(page, tmp_page, &pages, lru)
		free_rbin_page(rbin_heap, buffer, page);

	atomic_sub(size >> PAGE_SHIFT, &rbin_allocated_pages);
	trace_printk("end fail %ld %ld %lu\n", nr_total, nr_alloc, size);
	trace_ion_rbin_alloc_end(heap->name, buffer, size, (void *)-1UL);
	return -ENOMEM;
}

static void ion_rbin_heap_free(struct ion_buffer *buffer)
{
	struct ion_rbin_heap *rbin_heap = container_of(buffer->heap,
							struct ion_rbin_heap,
							heap);
	struct sg_table *table = buffer->sg_table;
	struct scatterlist *sg;
	unsigned long size = PAGE_ALIGN(buffer->size);
	int i;

	trace_ion_rbin_free_start(buffer->heap->name, buffer, buffer->size, NULL);
	for_each_sg(table->sgl, sg, table->nents, i)
		free_rbin_page(rbin_heap, buffer, sg_page(sg));
	sg_free_table(table);
	kfree(table);
	atomic_sub(size >> PAGE_SHIFT, &rbin_allocated_pages);
	trace_ion_rbin_free_end(buffer->heap->name, buffer, buffer->size, NULL);
}

static struct sg_table *ion_rbin_heap_map_dma(struct ion_heap *heap,
		struct ion_buffer *buffer)
{
	return buffer->priv_virt;
}

static void ion_rbin_heap_unmap_dma(struct ion_heap *heap,
		struct ion_buffer *buffer)
{
}

static struct ion_heap_ops rbin_heap_ops = {
	.allocate = ion_rbin_heap_allocate,
	.free = ion_rbin_heap_free,
	.map_dma = ion_rbin_heap_map_dma,
	.unmap_dma = ion_rbin_heap_unmap_dma,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
	.map_user = ion_heap_map_user,
};

static int ion_rbin_heap_debug_show(struct ion_heap *heap, struct seq_file *s,
				      void *unused)
{
	struct ion_rbin_heap *rbin_heap = container_of(heap,
						       struct ion_rbin_heap,
						       heap);
	int i;
	struct ion_page_pool *pool;
	unsigned long total = 0;

	if (!s)
		return -EINVAL;

	for (i = 0; i < NUM_ORDERS; i++) {
		pool = rbin_heap->pools[i];

		total += (1 << pool->order) * PAGE_SIZE * pool->high_count;
		total += (1 << pool->order) * PAGE_SIZE * pool->low_count;
		seq_printf(s, "%d order %u highmem pages uncached %lu total\n",
				pool->high_count, pool->order,
				(PAGE_SIZE << pool->order) * pool->high_count);
		seq_printf(s, "%d order %u lowmem pages uncached %lu total\n",
				pool->low_count, pool->order,
				(PAGE_SIZE << pool->order) * pool->low_count);
	}
	seq_puts(s, "--------------------------------------------\n");
	seq_printf(s, "total pool %lu Bytes ( %ld.%06ld MB ) \n", total,
		       total >> 20, total % (1 << 20));
	return 0;
}

//TODO: currently, we assume there is only one rbin..
static struct ion_rbin_heap *rbin_heap;

bool is_ion_rbin_page(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	return (rbin_heap->base_pfn <= pfn)
		&& (pfn < rbin_heap->base_pfn + rbin_heap->count);
}

void wake_ion_rbin_heap_prereclaim(void)
{
	if (rbin_heap) {
		rbin_heap->prereclaim_run = 1;
		wake_up(&rbin_heap->waitqueue);
	}
}

void wake_ion_rbin_heap_shrink(void)
{
	if (rbin_heap) {
		rbin_heap->shrink_run = 1;
		wake_up(&rbin_heap->waitqueue);
	}
}

static int ion_rbin_heap_prereclaim(void *data)
{
	struct ion_rbin_heap *heap = data;
	struct page *page;
	unsigned long totalsize;
	unsigned long pagesize;
	unsigned int max_pool_order = orders[0];
	unsigned int order;
	struct ion_page_pool *pool;

	if (!heap || !heap->dev)
		return -EINVAL;

	while (true) {
		wait_event_freezable(heap->waitqueue,
				     heap->prereclaim_run);

		trace_printk("start\n");
		reclaim_contig_migrate_range(heap->base_pfn,
				heap->base_pfn + heap->count, 0);
		totalsize = 0;
		while (true) {
			page = alloc_rbin_page(heap, NULL,
					       PAGE_SIZE << max_pool_order);
			if (!page)
				break;
			pagesize = page_private(page);
			totalsize += pagesize;
			order = get_order(pagesize);
			pool = heap->pools[order_to_index(order)];
			ion_page_pool_free(pool, page);
			atomic_add(1 << order, &rbin_pool_pages);
		}
		trace_printk("end %lu\n", totalsize);
		heap->prereclaim_run = 0;
	}

	return 0;
}

static int ion_page_pool_shrink_dev(struct device *dev, struct ion_page_pool *pool,
				    int nr_to_scan)
{
	int freed = 0;

	if (nr_to_scan == 0)
		return ion_page_pool_total(pool, 1);

	while (freed < nr_to_scan) {
		struct page *page;
		int page_count = 1 << pool->order;

		spin_lock(&pool->lock);
		if (pool->low_count) {
			page = ion_page_pool_remove(pool, false);
		} else if (pool->high_count) {
			page = ion_page_pool_remove(pool, true);
		} else {
			spin_unlock(&pool->lock);
			break;
		}
		spin_unlock(&pool->lock);
		dma_release_from_contiguous(dev, page, page_count);
		freed += page_count;
	}

	return freed;
}

static int ion_rbin_heap_shrink_all(void *data)
{
	struct ion_rbin_heap *heap = data;
	struct ion_page_pool *pool;
	int nr_scan, nr_freed;
	unsigned long total_freed;
	int i;

	if (!heap || !heap->dev)
		return -EINVAL;

	while (true) {
		wait_event_freezable(heap->waitqueue,
				     heap->shrink_run);

		trace_printk("start\n");
		total_freed = 0;
		for (i = 0; i < NUM_ORDERS; i++) {
			pool = heap->pools[i];
			nr_scan = ion_page_pool_shrink_dev(heap->dev, pool, 0);
			if (nr_scan) {
				nr_freed = ion_page_pool_shrink_dev(heap->dev,
								pool, nr_scan);
				atomic_sub(nr_freed, &rbin_pool_pages);
				total_freed += nr_freed;
			}
		}
		heap->shrink_run = 0;
		trace_printk("%lu\n", total_freed);
	}

	return 0;
}

static void ion_rbin_heap_destroy_pools(struct ion_page_pool **pools)
{
	int i;

	for (i = 0; i < NUM_ORDERS; i++)
		if (pools[i])
			ion_page_pool_destroy(pools[i]);
}

static int ion_rbin_heap_create_pools(struct ion_page_pool **pools)
{
	int i;
	for (i = 0; i < NUM_ORDERS; i++) {
		struct ion_page_pool *pool;

		pool = ion_page_pool_create(GFP_KERNEL, orders[i]);
		if (!pool)
			goto err_create_pool;
		pools[i] = pool;
	}
	return 0;

err_create_pool:
	ion_rbin_heap_destroy_pools(pools);
	return -ENOMEM;
}

/*
 * Affinity setting of RBIN pre-reclaim thread on big cores.
 * While the big core set varies depending on chipsets,
 * Exynos9810 uses CPU4~7.
 * (By the way, is there an API detecting big cores?)
 */
#define BIG_CORE_NUM_FIRST 4
#define BIG_CORE_NUM_LAST 7

static int ion_rbin_heap_cpu_callback(struct notifier_block *nfb,
				      unsigned long action, void *hcpu)
{
	int i;
	struct cpumask cpu_mask;

	if (!rbin_heap)
		return NOTIFY_OK;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		cpumask_clear(&cpu_mask);
		for (i = BIG_CORE_NUM_FIRST; i <= BIG_CORE_NUM_LAST; i++)
			cpumask_set_cpu(i, &cpu_mask);
		if (cpumask_any_and(cpu_online_mask, &cpu_mask) >= nr_cpu_ids)
			cpumask_setall(&cpu_mask);
		set_cpus_allowed_ptr(rbin_heap->task, &cpu_mask);
	}

	return NOTIFY_OK;
}

struct ion_heap *ion_rbin_heap_create(struct ion_platform_heap *data)
{
	struct ion_rbin_heap *heap;
	struct sched_param param = { .sched_priority = 0 };

	heap = kzalloc(sizeof(struct ion_rbin_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->heap.ops = &rbin_heap_ops;
	heap->heap.type = ION_HEAP_TYPE_RBIN;

	heap->dev = data->priv;
	heap->cma = dev_get_cma_area(heap->dev);
	if (heap->cma) {
		heap->base_pfn = dev_get_cma_base_pfn(heap->cma);
		heap->count = dev_get_cma_count(heap->cma);
		pr_info("%s %lu %lu\n", __func__, heap->base_pfn, heap->count);
	}

	if (ion_rbin_heap_create_pools(heap->pools))
		goto error_create_pools;
	heap->heap.debug_show = ion_rbin_heap_debug_show;

	init_waitqueue_head(&heap->waitqueue);
	heap->task = kthread_run(ion_rbin_heap_prereclaim, heap,
				 "%s", "rbin");
	heap->task_shrink = kthread_run(ion_rbin_heap_shrink_all, heap,
					"%s", "rbin_shrink");
	rbin_heap = heap;

	sched_setscheduler(heap->task, SCHED_NORMAL, &param);
	ion_rbin_heap_cpu_callback(NULL, CPU_UP_PREPARE, NULL);
	hotcpu_notifier(ion_rbin_heap_cpu_callback, 0);

	return &heap->heap;

error_create_pools:
	kfree(heap);
	return ERR_PTR(-ENOMEM);
}

void ion_rbin_heap_destroy(struct ion_heap *heap)
{
	struct ion_rbin_heap *rbin_heap = container_of(heap,
							struct ion_rbin_heap,
							heap);
	kfree(rbin_heap);
}


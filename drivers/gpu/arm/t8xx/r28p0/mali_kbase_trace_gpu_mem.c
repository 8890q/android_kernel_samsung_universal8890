// SPDX-License-Identifier: GPL-2.0
/*
 * GPU memory tracing backport for the Midgard driver.
 *
 * Based on Arm's Mali GPU memory tracing and process/DMA-BUF tracking:
 * (C) COPYRIGHT 2020 ARM Limited. All rights reserved.
 * Adapted to R28P0 native counters and Linux 4.4.
 */
#include <linux/dma-buf.h>
#include <mali_kbase.h>
#include <mali_kbase_trace_gpu_mem.h>
#include <trace/events/gpu_mem.h>

struct kbase_gpu_mem_process {
	struct rb_node node;
	pid_t tgid;
	unsigned int contexts;
	u64 pages;
	struct rb_root dma_bufs;
};

struct kbase_gpu_mem_dma_buf {
	struct rb_node node;
	struct dma_buf *buf;
	unsigned int refs;
	size_t pages;
};

void kbase_gpu_mem_init(struct kbase_device *kbdev)
{
	kbdev->gpu_mem_processes = RB_ROOT;
	kbdev->gpu_mem_dma_bufs = RB_ROOT;
	mutex_init(&kbdev->gpu_mem_dma_buf_lock);
	spin_lock_init(&kbdev->gpu_mem_usage_lock);
}

int kbase_gpu_mem_context_init(struct kbase_context *kctx)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct rb_node **link, *parent = NULL;
	struct kbase_gpu_mem_process *process;
	int ret = 0;

	mutex_lock(&kbdev->kctx_list_lock);
	link = &kbdev->gpu_mem_processes.rb_node;
	while (*link) {
		parent = *link;
		process = rb_entry(parent, struct kbase_gpu_mem_process, node);
		if (kctx->tgid == process->tgid)
			goto found;
		link = kctx->tgid < process->tgid ?
			&parent->rb_left : &parent->rb_right;
	}
	process = kzalloc(sizeof(*process), GFP_KERNEL);
	if (!process) {
		ret = -ENOMEM;
		goto out;
	}
	process->tgid = kctx->tgid;
	process->dma_bufs = RB_ROOT;
	rb_link_node(&process->node, parent, link);
	rb_insert_color(&process->node, &kbdev->gpu_mem_processes);
found:
	process->contexts++;
	kctx->gpu_mem_process = process;
out:
	mutex_unlock(&kbdev->kctx_list_lock);
	return ret;
}

/* Caller holds gpu_mem_usage_lock, including while emitting the events.
 * This prevents a later counter update being overwritten by a stale event.
 * GPU 0 is the sole Midgard device; PID 0 denotes its global total.
 */
static void kbase_gpu_mem_trace(struct kbase_device *kbdev,
		struct kbase_gpu_mem_process *process)
{
	lockdep_assert_held(&kbdev->gpu_mem_usage_lock);
	trace_gpu_mem_total(0, 0, kbdev->gpu_mem_pages << PAGE_SHIFT);
	if (process)
		trace_gpu_mem_total(0, process->tgid, process->pages << PAGE_SHIFT);
}

void kbase_gpu_mem_context_term(struct kbase_context *kctx)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbase_gpu_mem_process *process = kctx->gpu_mem_process;
	unsigned long flags;

	if (!process)
		return;
	mutex_lock(&kbdev->kctx_list_lock);
	if (!--process->contexts) {
		spin_lock_irqsave(&kbdev->gpu_mem_usage_lock, flags);
		WARN_ON(process->pages);
		/* Remove a possibly stale BPF entry after the final context. */
		trace_gpu_mem_total(0, process->tgid, 0);
		spin_unlock_irqrestore(&kbdev->gpu_mem_usage_lock, flags);
		WARN_ON(!RB_EMPTY_ROOT(&process->dma_bufs));
		rb_erase(&process->node, &kbdev->gpu_mem_processes);
		kfree(process);
	}
	kctx->gpu_mem_process = NULL;
	mutex_unlock(&kbdev->kctx_list_lock);
}

void kbase_gpu_mem_account(struct kbase_device *kbdev,
		struct kbase_context *kctx, long pages)
{
	struct kbase_gpu_mem_process *process =
		kctx ? kctx->gpu_mem_process : NULL;
	unsigned long flags;

	spin_lock_irqsave(&kbdev->gpu_mem_usage_lock, flags);
	kbdev->gpu_mem_pages += pages;
	if (process)
		process->pages += pages;
	kbase_gpu_mem_trace(kbdev, process);
	spin_unlock_irqrestore(&kbdev->gpu_mem_usage_lock, flags);
}

#ifdef CONFIG_DMA_SHARED_BUFFER
/* The DMA-BUF mutex protects both trees and their reference counts. */
static struct kbase_gpu_mem_dma_buf *find_dma_buf(struct rb_root *root,
		struct dma_buf *buf)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct kbase_gpu_mem_dma_buf *entry =
			rb_entry(node, struct kbase_gpu_mem_dma_buf, node);

		if (entry->buf == buf)
			return entry;
		node = (unsigned long)buf < (unsigned long)entry->buf ?
			node->rb_left : node->rb_right;
	}
	return NULL;
}

static void insert_dma_buf(struct rb_root *root,
		struct kbase_gpu_mem_dma_buf *entry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;

	while (*link) {
		struct kbase_gpu_mem_dma_buf *other;

		parent = *link;
		other = rb_entry(parent, struct kbase_gpu_mem_dma_buf, node);
		link = (unsigned long)entry->buf < (unsigned long)other->buf ?
			&parent->rb_left : &parent->rb_right;
	}
	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, root);
}

void kbase_add_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbase_gpu_mem_process *process = kctx->gpu_mem_process;
	struct dma_buf *buf = alloc->imported.umm.dma_buf;
	struct kbase_gpu_mem_dma_buf *global, *local;
	struct kbase_gpu_mem_dma_buf *new_global = NULL, *new_local = NULL;
	unsigned long flags;

	mutex_lock(&kbdev->gpu_mem_dma_buf_lock);
	global = find_dma_buf(&kbdev->gpu_mem_dma_bufs, buf);
	local = find_dma_buf(&process->dma_bufs, buf);
	/* Allocate both nodes before changing either tree. On OOM leave the
	 * import functional, but do not account or later remove a partial pair.
	 */
	if (!global) {
		new_global = kzalloc(sizeof(*new_global), GFP_KERNEL);
		if (!new_global)
			goto out;
		global = new_global;
	}
	if (!local) {
		new_local = kzalloc(sizeof(*new_local), GFP_KERNEL);
		if (!new_local)
			goto out;
		local = new_local;
	}
	if (new_global) {
		global->buf = buf;
		global->pages = PFN_UP(buf->size);
		insert_dma_buf(&kbdev->gpu_mem_dma_bufs, global);
	}
	if (new_local) {
		local->buf = buf;
		local->pages = PFN_UP(buf->size);
		insert_dma_buf(&process->dma_bufs, local);
	}
	spin_lock_irqsave(&kbdev->gpu_mem_usage_lock, flags);
	if (!global->refs++)
		kbdev->gpu_mem_pages += global->pages;
	if (!local->refs++)
		process->pages += local->pages;
	kbase_gpu_mem_trace(kbdev, process);
	spin_unlock_irqrestore(&kbdev->gpu_mem_usage_lock, flags);
	alloc->imported.umm.gpu_mem_accounted = true;
	new_global = NULL;
	new_local = NULL;
out:
	mutex_unlock(&kbdev->gpu_mem_dma_buf_lock);
	kfree(new_global);
	kfree(new_local);
}

void kbase_remove_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbase_gpu_mem_process *process = kctx->gpu_mem_process;
	struct dma_buf *buf = alloc->imported.umm.dma_buf;
	struct kbase_gpu_mem_dma_buf *global, *local;
	unsigned long flags;

	if (!alloc->imported.umm.gpu_mem_accounted)
		return;
	mutex_lock(&kbdev->gpu_mem_dma_buf_lock);
	global = find_dma_buf(&kbdev->gpu_mem_dma_bufs, buf);
	local = find_dma_buf(&process->dma_bufs, buf);
	if (WARN_ON(!global || !local))
		goto out;
	spin_lock_irqsave(&kbdev->gpu_mem_usage_lock, flags);
	if (!--global->refs)
		kbdev->gpu_mem_pages -= global->pages;
	if (!--local->refs)
		process->pages -= local->pages;
	kbase_gpu_mem_trace(kbdev, process);
	spin_unlock_irqrestore(&kbdev->gpu_mem_usage_lock, flags);
	if (!global->refs) {
		rb_erase(&global->node, &kbdev->gpu_mem_dma_bufs);
		kfree(global);
	}
	if (!local->refs) {
		rb_erase(&local->node, &process->dma_bufs);
		kfree(local);
	}
	alloc->imported.umm.gpu_mem_accounted = false;
out:
	mutex_unlock(&kbdev->gpu_mem_dma_buf_lock);
}
#endif

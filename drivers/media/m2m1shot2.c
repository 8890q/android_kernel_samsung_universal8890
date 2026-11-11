/*
 * drivers/media/m2m1shot2.c
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *
 * Contact: Cho KyongHo <pullip.cho@samsung.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/compat.h>

#include <linux/ion.h>
#include <linux/exynos_ion.h>
#include <linux/exynos_iovmm.h>

#include <media/m2m1shot2.h>

#include <asm/cacheflush.h>

#define M2M1SHOT2_NEED_CACHEFLUSH_ALL (10 * SZ_1M)
#define M2M1SHOT2_FENCE_MASK (M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE |		\
					M2M1SHOT2_IMGFLAG_RELEASE_FENCE)

static void m2m1shot2_fence_callback(struct sync_fence *fence,
					struct sync_fence_waiter *waiter);

static void m2m1shot2_timeout_handler(unsigned long arg);

/*
 * STATE TRANSITION of m2m1shot2_context:
 * - PROCESSING:
 *     # set in m2m1shot2_start_processing() after the context is moved to
 *       active_contexts.
 *     # clear in __m2m1shot2_finish_context() inside m2m1shot2_finish_context()
 *       that is called by the client driver when IRQ occurs.
 * - PENDING:
 *     # set in m2m1shot2_start_context() along with PROCESSING.
 *     # clear in m2m1shot2_schedule() before calling .device_run().
 * - WAITING:
 *     # set at the entry of m2m1shot2_wait_process()
 *     # clear in m2m1shot2_ioctl() before returning to user
 * - PROCESSED:
 *     # set in __m2m1shot2_finish_context() along with clearing PROCESSING.
 *     # clear in m2m1shot2_ioctl() before returning to user
 * - ERROR:
 *     # set in __m2m1shot2_finish_context() on an error
 *     # clear in m2m1shot2_ioctl() before returning to user
 */
static int m2m1shot2_open(struct inode *inode, struct file *filp)
{
	struct m2m1shot2_device *m21dev = container_of(filp->private_data,
						struct m2m1shot2_device, misc);
	struct m2m1shot2_context *ctx;
	unsigned long flags;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->timeline = sw_sync_timeline_create(dev_name(m21dev->dev));
	if (!ctx->timeline) {
		dev_err(m21dev->dev, "Failed to create timeline\n");
		ret = -ENOMEM;
		goto err_timeline;
	}

	INIT_LIST_HEAD(&ctx->node);

	spin_lock_irqsave(&m21dev->lock_ctx, flags);
	list_add_tail(&ctx->node, &m21dev->contexts);
	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	ctx->m21dev = m21dev;
	mutex_init(&ctx->mutex);
	init_completion(&ctx->complete);
	complete_all(&ctx->complete); /* prevent to wait for completion */

	filp->private_data = ctx;

	for (ret = 0; ret < M2M1SHOT2_MAX_IMAGES; ret++) {
		ctx->source[ret].img.index = ret;
		sync_fence_waiter_init(&ctx->source[ret].img.waiter,
					m2m1shot2_fence_callback);
	}
	ctx->target.index = M2M1SHOT2_MAX_IMAGES;
	sync_fence_waiter_init(&ctx->target.waiter, m2m1shot2_fence_callback);

	ret = m21dev->ops->init_context(ctx);
	if (ret)
		goto err_init;

	spin_lock(&m21dev->lock_priority);
	ctx->priority = M2M1SHOT2_DEFAULT_PRIORITY;
	m21dev->prior_stats[ctx->priority] += 1;
	spin_unlock(&m21dev->lock_priority);

	spin_lock_init(&ctx->fence_timeout_lock);

	setup_timer(&ctx->timer, m2m1shot2_timeout_handler,
						(unsigned long)ctx);

	return 0;
err_init:
	sync_timeline_destroy(&ctx->timeline->obj);
err_timeline:
	kfree(ctx);
	return ret;

}

/*
 * m2m1shot2_current_context - get the current m2m1shot2_context
 *
 * return the current context pointer.
 * This function should not be called other places than the function that
 * finishes the current context.
 */
struct m2m1shot2_context *m2m1shot2_current_context(
				const struct m2m1shot2_device *m21dev)
{
	return m21dev->current_ctx;
}

static void m2m1shot2_put_userptr(struct device *dev,
				 struct m2m1shot2_dma_buffer *plane)
{
	struct vm_area_struct *vma = plane->userptr.vma;
	struct mm_struct *mm;

	BUG_ON((vma == NULL) || (plane->userptr.addr == 0));

	mm = vma->vm_mm;

	exynos_iovmm_unmap_userptr(dev, plane->dma_addr);

	down_read(&mm->mmap_sem);

	while (vma) {
		struct vm_area_struct *tvma;

		if (vma->vm_ops && vma->vm_ops->close)
			vma->vm_ops->close(vma);

		if (vma->vm_file)
			fput(vma->vm_file);

		tvma = vma;
		vma = vma->vm_next;

		kfree(tvma);
	}

	up_read(&mm->mmap_sem);

	mmput(mm);

	plane->userptr.vma = NULL;
	plane->userptr.addr = 0;
}

static void m2m1shot2_put_dmabuf(struct m2m1shot2_dma_buffer *plane)
{
	ion_iovmm_unmap(plane->dmabuf.attachment,
			plane->dma_addr - plane->dmabuf.offset);
	dma_buf_detach(plane->dmabuf.dmabuf, plane->dmabuf.attachment);
	dma_buf_put(plane->dmabuf.dmabuf);
	plane->dmabuf.dmabuf = NULL;
	plane->dmabuf.attachment = NULL;
}

static void m2m1shot2_put_buffer(struct m2m1shot2_context *ctx, u32 memory,
				 struct m2m1shot2_dma_buffer plane[],
				 unsigned int num_planes)
{
	unsigned int i;

	if (memory == M2M1SHOT2_BUFTYPE_DMABUF) {
		for (i = 0; i < num_planes; i++)
			m2m1shot2_put_dmabuf(&plane[i]);
	} else if (memory == M2M1SHOT2_BUFTYPE_USERPTR) {
		for (i = 0; i < num_planes; i++)
			m2m1shot2_put_userptr(ctx->m21dev->dev, &plane[i]);
	}
}

static void m2m1shot2_put_image(struct m2m1shot2_context *ctx,
				struct m2m1shot2_context_image *img)
{
	if (!!(img->flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE)) {
		/*
		 * confirm the fence callback is not called after img->fence is
		 * cleared by the deferred behavior of sync_fence_put().
		 */
		sync_fence_cancel_async(img->fence, &img->waiter);
		sync_fence_put(img->fence);
		img->flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
	}

	m2m1shot2_put_buffer(ctx, img->memory, img->plane, img->num_planes);

	img->memory = M2M1SHOT2_BUFTYPE_NONE;
}

static void m2m1shot2_put_source_images(struct m2m1shot2_context *ctx)
{
	unsigned int i;

	for (i = 0; i < ctx->num_sources; i++)
		m2m1shot2_put_image(ctx, &ctx->source[i].img);

	ctx->num_sources = 0;
}

static void m2m1shot2_put_images(struct m2m1shot2_context *ctx)
{
	m2m1shot2_put_source_images(ctx);
	m2m1shot2_put_image(ctx, &ctx->target);
}

static void __m2m1shot2_finish_context(struct m2m1shot2_context *ctx,
					bool success)
{
	struct m2m1shot2_device *m21dev = ctx->m21dev;
	unsigned long flags;

	sw_sync_timeline_inc(ctx->timeline, 1);

	spin_lock_irqsave(&m21dev->lock_ctx, flags);

	/* effective only to the current processing context */
	if (WARN_ON(ctx != m21dev->current_ctx)) {
		spin_unlock_irqrestore(&m21dev->lock_ctx, flags);
		return;
	}

	m21dev->current_ctx = NULL;
	list_add_tail(&ctx->node, &m21dev->contexts);

	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	if (!success)
		set_bit(M2M1S2_CTXSTATE_ERROR, &ctx->state);

	set_bit(M2M1S2_CTXSTATE_PROCESSED, &ctx->state);
	clear_bit(M2M1S2_CTXSTATE_PROCESSING, &ctx->state);

	complete_all(&ctx->complete);
}

/**
 * m2m1shot2_schedule() - pick a context to process
 *
 * pick a context that is at the front of m2m1shot2_device.active_contexts
 * and provide it to the client to process that context.
 * If the client returns error then pick the next context.
 */
static void m2m1shot2_schedule(struct m2m1shot2_device *m21dev)
{
	struct m2m1shot2_context *ctx;
	unsigned long flags;

retry:
	spin_lock_irqsave(&m21dev->lock_ctx, flags);

	if (m21dev->current_ctx != NULL) {
		/* the client is currently processing a context */
		spin_unlock_irqrestore(&m21dev->lock_ctx, flags);
		return;
	}

	if (list_empty(&m21dev->active_contexts)) {
		/* no context to process */
		spin_unlock_irqrestore(&m21dev->lock_ctx, flags);
		return;
	}

	ctx = list_first_entry(&m21dev->active_contexts,
				struct m2m1shot2_context, node);
	m21dev->current_ctx = ctx;
	list_del_init(&ctx->node);

	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	clear_bit(M2M1S2_CTXSTATE_PENDING, &ctx->state);

	if (m21dev->ops->device_run(ctx) < 0) {
		__m2m1shot2_finish_context(ctx, false);
		goto retry;
	}
}

#define is_vma_cached(vma)						      \
	((pgprot_noncached((vma)->vm_page_prot) != (vma)->vm_page_prot) &&    \
	   (pgprot_writecombine((vma)->vm_page_prot) != (vma)->vm_page_prot))

static void m2m1shot2_unmap_image(struct m2m1shot2_device *m21dev,
				struct m2m1shot2_context_image *img,
				enum dma_data_direction dir,
				bool skip_inv)
{
	bool inv = !skip_inv && !(img->flags & M2M1SHOT2_IMGFLAG_NO_CACHEINV) &&
			!(m21dev->attr & M2M1SHOT2_DEVATTR_COHERENT);
	unsigned int i;

	/* dma_buf_map_attachment() is not called */
	if (img->plane[0].sgt == NULL)
		return;

	if (img->memory == M2M1SHOT2_BUFTYPE_USERPTR) {
		for (i = 0; i < img->num_planes; i++)
			if (is_vma_cached(img->plane[i].userptr.vma) && inv)
				exynos_iommu_sync_for_cpu(m21dev->dev,
						img->plane[i].dma_addr,
						img->plane[i].payload, dir);
	} else if (img->memory == M2M1SHOT2_BUFTYPE_DMABUF) {
		for (i = 0; i < img->num_planes; i++) {
			if (inv)
				exynos_ion_sync_dmabuf_for_cpu(m21dev->dev,
						img->plane[i].dmabuf.dmabuf,
						img->plane[i].payload, dir);
			dma_buf_unmap_attachment(
					img->plane[i].dmabuf.attachment,
					img->plane[i].sgt, dir);
			/* not to call unmap again */
			img->plane[i].sgt = NULL;
		}
	}
}

static void m2m1shot2_unmap_images(struct m2m1shot2_context *ctx)
{
	bool flush_all = test_bit(M2M1S2_CTXSTATE_CACHEINVALALL, &ctx->state);
	unsigned int i;

	for (i = 0; i < ctx->num_sources; i++)
		m2m1shot2_unmap_image(ctx->m21dev,
				&ctx->source[i].img, DMA_TO_DEVICE, flush_all);

	m2m1shot2_unmap_image(ctx->m21dev,
				&ctx->target, DMA_FROM_DEVICE, flush_all);

	if (flush_all && !(ctx->m21dev->attr & M2M1SHOT2_DEVATTR_COHERENT))
		flush_all_cpu_caches();
}

static int m2m1shot2_map_image(struct m2m1shot2_device *m21dev,
				struct m2m1shot2_context_image *img,
				enum dma_data_direction dir)
{
	unsigned int i;

	/* nothing to do for userptr and empty buffer types */
	if (img->memory != M2M1SHOT2_BUFTYPE_DMABUF)
		return 0;

	for (i = 0; i < img->num_planes; i++) {
		img->plane[i].sgt = dma_buf_map_attachment(
					img->plane[i].dmabuf.attachment, dir);
		if (IS_ERR(img->plane[i].sgt)) {
			int ret = PTR_ERR(img->plane[i].sgt);

			dev_err(m21dev->dev, "failed to map dmabuf-attachment");
			img->plane[i].sgt = NULL;
			while (i-- > 0) {
				dma_buf_unmap_attachment(
						img->plane[i].dmabuf.attachment,
						img->plane[i].sgt, dir);
				img->plane[i].sgt = NULL;
			}
			return ret;
		}
	}

	return 0;
}

static bool m2m1shot2_need_shareable_flush(struct dma_buf *dmabuf, bool clear)
{
	return dma_buf_get_privflag(dmabuf, clear) &&
				ion_may_hwrender_dmabuf(dmabuf);

}

static void m2m1shot2_cachesync_image(struct m2m1shot2_context *ctx,
				      struct m2m1shot2_context_image *img,
				      enum dma_data_direction dir)
{
	int i;

	if (!!(img->flags & M2M1SHOT2_IMGFLAG_NO_CACHECLEAN))
		return;

	if (img->memory == M2M1SHOT2_BUFTYPE_USERPTR) {
		for (i = 0; i < img->num_planes; i++) {
			if (is_vma_cached(img->plane[i].userptr.vma))
				exynos_iommu_sync_for_device(ctx->m21dev->dev,
						img->plane[i].dma_addr,
						img->plane[i].payload, dir);
		}

		return;
	}

	if (img->memory != M2M1SHOT2_BUFTYPE_DMABUF)
		return;

	for (i = 0; i < img->num_planes; i++) {
		if (m2m1shot2_need_shareable_flush(
					img->plane[i].dmabuf.dmabuf, true))
			exynos_ion_flush_dmabuf_for_device(ctx->m21dev->dev,
				img->plane[i].dmabuf.dmabuf,
				img->plane[i].payload);
		else
			exynos_ion_sync_dmabuf_for_device(ctx->m21dev->dev,
				img->plane[i].dmabuf.dmabuf,
				img->plane[i].payload, dir);
	}
}

static void m2m1shot2_cachesync_images(struct m2m1shot2_context *ctx)
{
	int i;

	if (!!(ctx->m21dev->attr & M2M1SHOT2_DEVATTR_COHERENT) &&
			!test_bit(M2M1S2_CTXSTATE_CACHEFLUSH, &ctx->state))
		return;

	if (test_bit(M2M1S2_CTXSTATE_CACHECLEANALL, &ctx->state) ||
			test_bit(M2M1S2_CTXSTATE_CACHEFLUSHALL, &ctx->state)) {
		flush_all_cpu_caches();
		return;
	}

	for (i = 0; i < ctx->num_sources; i++)
		m2m1shot2_cachesync_image(ctx,
					  &ctx->source[i].img, DMA_TO_DEVICE);

	m2m1shot2_cachesync_image(ctx, &ctx->target, DMA_FROM_DEVICE);
}

static int m2m1shot2_map_images(struct m2m1shot2_context *ctx)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ctx->num_sources; i++) {
		ret = m2m1shot2_map_image(ctx->m21dev,
					  &ctx->source[i].img, DMA_TO_DEVICE);
		if (ret) {
			while (i-- > 0)
				m2m1shot2_unmap_image(ctx->m21dev,
					&ctx->source[i].img, DMA_TO_DEVICE,
					true);
			return ret;
		}
	}

	ret = m2m1shot2_map_image(ctx->m21dev, &ctx->target, DMA_FROM_DEVICE);
	if (ret) {
		for (i = 0; i < ctx->num_sources; i++)
			m2m1shot2_unmap_image(ctx->m21dev,
				&ctx->source[i].img, DMA_TO_DEVICE, true);
	}

	return ret;
}

/*
 * m2m1shot2_wait_process() - wait until processing the context is finished
 *
 * This function should be called under ctx->mutex held.
 */
static bool m2m1shot2_wait_process(struct m2m1shot2_device *m21dev,
				   struct m2m1shot2_context *ctx)
{
	bool success = true;

	set_bit(M2M1S2_CTXSTATE_WAITING, &ctx->state);

	wait_for_completion(&ctx->complete);

	clear_bit(M2M1S2_CTXSTATE_WAITING, &ctx->state);

	if ((ctx->state & ((1 << M2M1S2_CTXSTATE_PENDING) |
				 (1 << M2M1S2_CTXSTATE_PROCESSING)))) {
		pr_err("m2m1shot finish state : %lx\n", ctx->state);
		BUG();
	}

	clear_bit(M2M1S2_CTXSTATE_PROCESSED, &ctx->state);

	if (test_bit(M2M1S2_CTXSTATE_ERROR, &ctx->state)) {
		success = false;
		clear_bit(M2M1S2_CTXSTATE_ERROR, &ctx->state);
	}

	m2m1shot2_unmap_images(ctx);

	return success;
}

static void m2m1shot2_schedule_context(struct m2m1shot2_context *ctx)
{
	struct m2m1shot2_device *m21dev = ctx->m21dev;
	unsigned long flags;

	del_timer(&ctx->timer);

	m2m1shot2_cachesync_images(ctx);

	spin_lock_irqsave(&ctx->m21dev->lock_ctx, flags);

	BUG_ON(list_empty(&ctx->node));

	/* move ctx from m21dev->contexts to m21dev->active_contexts */
	list_move_tail(&ctx->node, &ctx->m21dev->active_contexts);

	set_bit(M2M1S2_CTXSTATE_PROCESSING, &ctx->state);

	spin_unlock_irqrestore(&ctx->m21dev->lock_ctx, flags);

	m2m1shot2_schedule(m21dev);
}

static void m2m1shot2_context_schedule_work(struct work_struct *work)
{
	m2m1shot2_schedule_context(
			container_of(work, struct m2m1shot2_context, work));
}

static void m2m1shot2_context_schedule_start(struct kref *kref)
{
	m2m1shot2_schedule_context(
			container_of(kref, struct m2m1shot2_context, starter));
}

static void m2m1shot2_schedule_queuework(struct kref *kref)
{
	struct m2m1shot2_context *ctx =
			container_of(kref, struct m2m1shot2_context, starter);
	bool failed;

	failed = !queue_work(ctx->m21dev->schedule_workqueue, &ctx->work);

	BUG_ON(failed);
}

/* NOTE that this function is called under irq disabled context */
static void m2m1shot2_fence_callback(struct sync_fence *fence,
					struct sync_fence_waiter *waiter)
{
	struct m2m1shot2_context_image *img =
		container_of(waiter, struct m2m1shot2_context_image, waiter);
	unsigned long ptr = (unsigned long)img;
	struct m2m1shot2_context *ctx;
	unsigned long flags;

	BUG_ON(img->index > M2M1SHOT2_MAX_IMAGES);

	ptr -= sizeof(struct m2m1shot2_source_image) * img->index;
	ptr -= offsetof(struct m2m1shot2_context, source);
	ctx = (struct m2m1shot2_context *)ptr;

	spin_lock_irqsave(&ctx->fence_timeout_lock, flags);

	/*
	 * m2m1shot2_timeout_handler() cancels waiters of all acquire fences and
	 * releases the fences. It should be avoided to release fences that are
	 * alreayd released in the timeout handler.
	 */
	if (!(img->flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE)) {
		spin_unlock_irqrestore(&ctx->fence_timeout_lock, flags);
		return;
	}

	img->flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
	sync_fence_put(img->fence);

	kref_put(&ctx->starter, m2m1shot2_schedule_queuework);

	spin_unlock_irqrestore(&ctx->fence_timeout_lock, flags);
}

static void m2m1shot2_timeout_handler(unsigned long arg)
{
	struct m2m1shot2_context *ctx = (struct m2m1shot2_context *)arg;
	struct m2m1shot2_source_image *image = ctx->source;
	unsigned long flags;
	char name[32];
	int i;

	pr_err("%s: %d Fence(s) timed out after %d msec.\n", __func__,
		atomic_read(&ctx->starter.refcount), M2M1S2_TIMEOUT_INTERVAL);

	for (i = 0; i < ctx->num_sources; i++) {
		if (image[i].img.fence) {
			memcpy(name, image[i].img.fence->name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
			pr_err("%s:    SOURCE[%d]: [%p] %s\n",
				__func__, i, image[i].img.fence, name);
		}
	}

	if (ctx->target.fence) {
		memcpy(name, ctx->target.fence->name,  sizeof(name));
		name[sizeof(name) - 1] = '\0';
		pr_err("%s:    TARGET:    [%p] %s\n",
			__func__, ctx->target.fence, name);
	}

	if (ctx->release_fence)
		pr_err("%s:    Pending release fence: %p\n",
			__func__, ctx->release_fence);

	sync_dump();

	/*
	 * Give up waiting the acquire fences that are not currently signaled
	 * and force pushing this pending task to the H/W to avoid indefinite
	 * wait for the fences to be signaled.
	 * The spinlock is required to prevent racing about releasing the
	 * acqure fences between this time handler and the fence callback.
	 */
	spin_lock_irqsave(&ctx->fence_timeout_lock, flags);

	/*
	 * Make sure if there is really a unsigned fences. ctx->starter is
	 * decremented under fence_timeout_lock held if it is done by fence
	 * signal.
	*/
	if (atomic_read(&ctx->starter.refcount) == 0) {
		spin_unlock_irqrestore(&ctx->fence_timeout_lock, flags);
		pr_err("All fences have been signaled. (work_busy? %d)\n",
			work_busy(&ctx->work));
		/* If this happens again, the problem is obviously caused by the
		 * workqueue that does not schedule the work of this context.
		 */
		mod_timer(&ctx->timer,
			  jiffies + msecs_to_jiffies(M2M1S2_TIMEOUT_INTERVAL));
		return;
	}

	for (i = 0; i < ctx->num_sources; i++) {
		if (image[i].img.flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE) {
			sync_fence_cancel_async(image[i].img.fence,
						&image[i].img.waiter);
			image[i].img.flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
			sync_fence_put(image[i].img.fence);
		}
	}

	if (!!(ctx->target.flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE)) {
		sync_fence_cancel_async(ctx->target.fence, &ctx->target.waiter);
		ctx->target.flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
		sync_fence_put(ctx->target.fence);
	}

	 m2m1shot2_schedule_queuework(&ctx->starter);

	spin_unlock_irqrestore(&ctx->fence_timeout_lock, flags);
};

/**
 * m2m1shot2_start_context() - add a context to the queue
 *
 * Given a valid context ready for processing, add it to
 * m2m1shot2_device.active_list that is the queue of ready contexts.
 * The state of the given context becomes PROCESSING|PENDING.
 * Then pick the next context to process from the queue. If there was no context
 * in the queue before this function call, the given context will be pick for
 * the context to process.
 */
static void m2m1shot2_start_context(struct m2m1shot2_device *m21dev,
				    struct m2m1shot2_context *ctx)
{
	int refcount;

	m2m1shot2_map_images(ctx);

	INIT_WORK(&ctx->work, m2m1shot2_context_schedule_work);

	reinit_completion(&ctx->complete);

	clear_bit(M2M1S2_CTXSTATE_PROCESSED, &ctx->state);
	set_bit(M2M1S2_CTXSTATE_PENDING, &ctx->state);
	/*
	 * if there is no fence to wait for, workqueue is not used to push a
	 * task
	 */
	refcount = atomic_read(&ctx->starter.refcount);
	if (refcount > 1)
		mod_timer(&ctx->timer,
			jiffies + msecs_to_jiffies(M2M1S2_TIMEOUT_INTERVAL));

	kref_put(&ctx->starter, m2m1shot2_schedule_queuework);
}

void m2m1shot2_finish_context(struct m2m1shot2_context *ctx, bool success)
{
	struct m2m1shot2_device *m21dev = ctx->m21dev;

	__m2m1shot2_finish_context(ctx, success);
	/* NOTE that ctx may be being freed during finishing ctx */
	m2m1shot2_schedule(m21dev);
}

static void m2m1shot2_cancel_context(struct m2m1shot2_context *ctx)
{
	unsigned long flags;

	/*
	 * wait until the H/W finishes the processing about the context if
	 * the context is being serviced by H/W. This should be the only waiter
	 * for the context. If nothing is to be waited for,
	 * m2m1shot2_wait_process() returns immediately.
	 */
	m2m1shot2_wait_process(ctx->m21dev, ctx);

	/*
	 * this context is added to m2m1shot2_device.contexts by
	 * m2m1shot2_finish_context() called by the client device driver
	 */
	spin_lock_irqsave(&ctx->m21dev->lock_ctx, flags);
	BUG_ON(list_empty(&ctx->node));
	list_del_init(&ctx->node);
	spin_unlock_irqrestore(&ctx->m21dev->lock_ctx, flags);

	/* signal all possible release fences */
	sw_sync_timeline_inc(ctx->timeline, 1);

	/* to confirm if no reference to a resource exists */
	if (!!(ctx->flags & M2M1SHOT2_FLAG_NONBLOCK))
		m2m1shot2_put_images(ctx);

	WARN(!M2M1S2_CTXSTATE_IDLE(ctx),
		"state should be IDLE but %#lx\n", ctx->state);
}

static void m2m1shot2_destroy_context(struct work_struct *work)
{
	struct m2m1shot2_context *ctx =
		container_of(work, struct m2m1shot2_context, dwork);

	mutex_lock(&ctx->mutex);

	m2m1shot2_cancel_context(ctx);

	sync_timeline_destroy(&ctx->timeline->obj);

	spin_lock(&ctx->m21dev->lock_priority);
	ctx->m21dev->prior_stats[ctx->priority] -= 1;
	spin_unlock(&ctx->m21dev->lock_priority);

	if (ctx->m21dev->ops->prepare_perf)
		ctx->m21dev->ops->prepare_perf(ctx, NULL);

	ctx->m21dev->ops->free_context(ctx);

	mutex_unlock(&ctx->mutex);

	kfree(ctx);
}

/*
 * m2m1shot2_release() may be called during the context to be destroyed is ready
 * for processing or currently waiting for completion of processing due to the
 * non-blocking interface. Therefore it should remove the context from
 * m2m1shot2_device.active_contexts if the context is in the list. If it is
 * currently being processed by H/W, this function should wait until the H/W
 * finishes.
 */
static int m2m1shot2_release(struct inode *inode, struct file *filp)
{
	struct m2m1shot2_context *ctx = filp->private_data;

	INIT_WORK(&ctx->dwork, m2m1shot2_destroy_context);
	/* always success */
	queue_work(ctx->m21dev->destroy_workqueue, &ctx->dwork);

	return 0;
}

static int m2m1shot2_get_userptr(struct m2m1shot2_device *m21dev,
				 struct m2m1shot2_dma_buffer *plane,
				 unsigned long addr, u32 length,
				 enum dma_data_direction dir)
{
	unsigned long end = addr + length;
	struct vm_area_struct *vma;
	struct vm_area_struct *tvma;
	struct mm_struct *mm;
	int ret = -EINVAL;
	int prot = IOMMU_READ;

	/*
	 * release the previous buffer whatever the userptr is previously used.
	 * the pages mapped to the given user addr can be different even though
	 * the user addr is the same if the addr is mmapped again.
	 */
	if (plane->userptr.vma != NULL)
		m2m1shot2_put_userptr(m21dev->dev, plane);

	mm = get_task_mm(current);

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, addr);
	if (!vma || (addr < vma->vm_start)) {
		dev_err(m21dev->dev,
			"%s: invalid address %#lx\n", __func__, addr);
		goto err_novma;
	}

	tvma = kmemdup(vma, sizeof(*vma), GFP_KERNEL);
	if (!tvma) {
		dev_err(m21dev->dev, "%s: failed to allocate vma\n", __func__);
		ret = -ENOMEM;
		goto err_novma;
	}

	if (dir != DMA_TO_DEVICE)
		prot |= IOMMU_WRITE;
	if (is_vma_cached(vma) && !!(m21dev->attr & M2M1SHOT2_DEVATTR_COHERENT))
		prot |= IOMMU_CACHE;

	plane->userptr.vma = tvma;

	tvma->vm_next = NULL;
	tvma->vm_prev = NULL;
	tvma->vm_mm = mm;

	while (end > vma->vm_end) {
		if (!!(vma->vm_flags & VM_PFNMAP)) {
			dev_err(m21dev->dev,
				"%s: non-linear pfnmap is not supported\n",
				__func__);
			goto err_vma;
		}

		if ((vma->vm_next == NULL) ||
				(vma->vm_end != vma->vm_next->vm_start)) {
			dev_err(m21dev->dev, "%s: invalid size %u\n",
					__func__, length);
			goto err_vma;
		}

		vma = vma->vm_next;
		tvma->vm_next = kmemdup(vma, sizeof(*vma), GFP_KERNEL);
		if (tvma->vm_next == NULL) {
			dev_err(m21dev->dev, "%s: failed to allocate vma\n",
				__func__);
			ret = -ENOMEM;
			goto err_vma;
		}
		tvma->vm_next->vm_prev = tvma;
		tvma->vm_next->vm_next = NULL;
		tvma = tvma->vm_next;
	}

	for (vma = plane->userptr.vma; vma != NULL; vma = vma->vm_next) {
		if (vma->vm_file)
			get_file(vma->vm_file);
		if (vma->vm_ops && vma->vm_ops->open)
			vma->vm_ops->open(vma);
	}

	plane->dma_addr = exynos_iovmm_map_userptr(
				m21dev->dev, addr, length, prot);
	if (IS_ERR_VALUE(plane->dma_addr))
		goto err_map;

	up_read(&mm->mmap_sem);

	plane->userptr.addr = addr;
	plane->userptr.length = length;

	return 0;
err_map:
	plane->dma_addr = 0;

	for (vma = plane->userptr.vma; vma != NULL; vma = vma->vm_next) {
		if (vma->vm_file)
			fput(vma->vm_file);
		if (vma->vm_ops && vma->vm_ops->close)
			vma->vm_ops->close(vma);
	}
err_vma:
	while (tvma) {
		vma = tvma;
		tvma = tvma->vm_prev;
		kfree(vma);
	}

	plane->userptr.vma = NULL;
err_novma:
	up_read(&mm->mmap_sem);

	mmput(mm);

	return ret;
}

static int m2m1shot2_get_dmabuf(struct m2m1shot2_device *m21dev,
				struct m2m1shot2_dma_buffer *plane,
				int fd, u32 off, size_t payload,
				enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = dma_buf_get(fd);
	int ret = -EINVAL;
	int prot = IOMMU_READ;

	if (IS_ERR(dmabuf)) {
		dev_err(m21dev->dev, "%s: failed to get dmabuf from fd %d\n",
			__func__, fd);
		return PTR_ERR(dmabuf);
	}

	if (dmabuf->size < off) {
		dev_err(m21dev->dev,
			"%s: too large offset %u for dmabuf of %zu\n",
			__func__, off, dmabuf->size);
		goto err;
	}

	if ((dmabuf->size - off) < payload) {
		dev_err(m21dev->dev,
			"%s: too small dmabuf %zu/%u but reqiured %zu\n",
			__func__, dmabuf->size, off, payload);
		goto err;
	}

	if ((dmabuf == plane->dmabuf.dmabuf) &&
			(dmabuf->size == plane->dmabuf.dmabuf->size) &&
				(dmabuf->file == plane->dmabuf.dmabuf->file)) {
		/* Reuse the mapping, but honor this image's buffer offset. */
		plane->dma_addr = plane->dma_addr - plane->dmabuf.offset + off;
		plane->dmabuf.offset = off;
		dma_buf_put(dmabuf);
		return 0;
	}

	if (dir != DMA_TO_DEVICE)
		prot |= IOMMU_WRITE;
	if (!!(m21dev->attr & M2M1SHOT2_DEVATTR_COHERENT))
		prot |= IOMMU_CACHE;

	/* release the previous buffer */
	if (plane->dmabuf.dmabuf != NULL)
		m2m1shot2_put_dmabuf(plane);

	plane->dmabuf.attachment = dma_buf_attach(dmabuf, m21dev->dev);
	if (IS_ERR(plane->dmabuf.attachment)) {
		dev_err(m21dev->dev,
			"%s: failed to attach to dmabuf\n", __func__);
		ret = PTR_ERR(plane->dmabuf.attachment);
		goto err;
	}

	/* NOTE: ion_iovmm_map() ignores offset in the second argument */
	plane->dma_addr = ion_iovmm_map(plane->dmabuf.attachment,
					0, payload, dir, prot);
	if (IS_ERR_VALUE(plane->dma_addr))
		goto err_map;

	plane->dmabuf.dmabuf = dmabuf;
	plane->dmabuf.offset = off;
	plane->dma_addr += off;

	return 0;
err_map:
	dma_buf_detach(dmabuf, plane->dmabuf.attachment);
	plane->dma_addr = 0;
	plane->dmabuf.attachment = NULL;
err:
	dma_buf_put(dmabuf);
	return ret;
}

static int m2m1shot2_get_buffer(struct m2m1shot2_context *ctx,
				struct m2m1shot2_context_image *img,
				struct m2m1shot2_image *src,
				size_t payload[],
				enum dma_data_direction dir)
{
	unsigned int num_planes = src->num_planes;
	int ret = 0;
	unsigned int i;

	if (src->memory != img->memory)
		m2m1shot2_put_buffer(ctx, img->memory,
					img->plane, img->num_planes);

	img->memory = M2M1SHOT2_BUFTYPE_NONE;

	if (src->memory == M2M1SHOT2_BUFTYPE_DMABUF) {
		for (i = 0; i < src->num_planes; i++) {
			ret = m2m1shot2_get_dmabuf(ctx->m21dev,
					&img->plane[i], src->plane[i].fd,
					src->plane[i].offset, payload[i], dir);
			if (ret) {
				while (i-- > 0)
					m2m1shot2_put_dmabuf(&img->plane[i]);
				return ret;
			}

			img->plane[i].payload = payload[i];

			if (!(img->flags & M2M1SHOT2_IMGFLAG_NO_CACHECLEAN) &&
				ion_cached_needsync_dmabuf(
					img->plane[i].dmabuf.dmabuf) > 0)
				ctx->ctx_private += img->plane[i].payload;
			if (m2m1shot2_need_shareable_flush(
						img->plane[i].dmabuf.dmabuf, false))
				ctx->ctx_private2 += img->plane[i].payload;
		}
	} else if (src->memory == M2M1SHOT2_BUFTYPE_USERPTR) {
		for (i = 0; i < src->num_planes; i++) {
			if (src->plane[i].offset != 0) {
				dev_err(ctx->m21dev->dev,
					"%s: offset should be 0 with userptr\n",
					__func__);
				ret = -EINVAL;
			} else {
				ret = m2m1shot2_get_userptr(ctx->m21dev,
					&img->plane[i], src->plane[i].userptr,
					src->plane[i].length, dir);
			}

			if (ret) {
				while (i-- > 0)
					m2m1shot2_put_userptr(ctx->m21dev->dev,
								&img->plane[i]);
				return ret;
			}

			img->plane[i].payload = payload[i];

			if (!(img->flags & M2M1SHOT2_IMGFLAG_NO_CACHECLEAN) &&
				is_vma_cached(img->plane[i].userptr.vma))
				ctx->ctx_private += img->plane[i].payload;
		}
	} else {
		dev_err(ctx->m21dev->dev,
			"%s: invalid memory type %d\n", __func__, src->memory);
		return -EINVAL;
	}

	img->num_planes = num_planes;
	img->memory = src->memory;

	return 0;
}

/*
 * check fence_count fences configured in the previous images in the same
 * context. If it does not find the same fence with the given, register the
 * fence waiter.
 * If registering the fence waiter for an unique fence fails, it releases it
 * immediately. The caller should handle the case.
 *
 */
static bool m2m1shot2_check_fence_wait(struct m2m1shot2_context *ctx,
					unsigned int fence_count,
					struct sync_fence *fence,
					struct sync_fence_waiter *waiter)
{
	unsigned int i;
	int ret;

	for (i = 0; i < fence_count; i++) {
		if (ctx->source[i].img.fence == fence)
			return false;
	}

	/*
	 * Always increase ctx->starter before sync_fence_wait_async().
	 * If waiter registration is failed (ret < 0)
	 * or already signaled (ret == 1). it will be just decreased.
	 */
	kref_get(&ctx->starter);
	ret = sync_fence_wait_async(fence, waiter);
	if (ret < 0 || ret == 1) {
		if (ret < 0)
			dev_err(ctx->m21dev->dev,
					"Error occurred in an acquire fence\n");
		kref_put(&ctx->starter, m2m1shot2_context_schedule_start);
		sync_fence_put(fence);
		return false;
	}

	return true;
}

static int m2m1shot2_get_source(struct m2m1shot2_context *ctx,
				unsigned int index,
				struct m2m1shot2_source_image *img,
				struct m2m1shot2_image *src)
{
	struct device *dev = ctx->m21dev->dev;
	size_t payload[M2M1SHOT2_MAX_PLANES];
	unsigned int i, num_planes;
	int ret;

	if (!M2M1SHOT2_BUFTYPE_VALID(src->memory)) {
		dev_err(dev,
			"%s: invalid memory type %u specified for image %u\n",
			__func__, src->memory, index);
		return -EINVAL;
	}

	img->img.fmt.fmt = src->fmt;
	img->img.flags = src->flags;
	img->ext = src->ext;
	img->img.fmt.colorspace = src->colorspace;

	ret = ctx->m21dev->ops->prepare_format(&img->img.fmt, index,
				DMA_TO_DEVICE, payload, &num_planes);
	if (ret) {
		dev_err(dev, "%s: invalid format specified for image %u\n",
			__func__, index);
		return ret;
	}

	if (src->memory == M2M1SHOT2_BUFTYPE_EMPTY) {
		m2m1shot2_put_image(ctx, &img->img);
		img->img.memory = src->memory;
		img->img.num_planes = 0;
		/* no buffer, no fence */
		img->img.flags &= ~(M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE |
					M2M1SHOT2_IMGFLAG_RELEASE_FENCE);
		return 0;
	}

	BUG_ON((num_planes < 1) || (num_planes > M2M1SHOT2_MAX_PLANES));

	if (num_planes != src->num_planes) {
		dev_err(dev, "%s: wrong number of planes %u of image %u.\n",
			__func__, src->num_planes, index);
		return -EINVAL;
	}

	for (i = 0; i < num_planes; i++) {
		if (src->plane[i].length < payload[i]) {
			dev_err(dev,
				"%s: too small size %u (plane %u / image %u)\n",
				__func__, src->plane[i].length, i, index);
			return -EINVAL;
		}
	}

	return m2m1shot2_get_buffer(ctx, &img->img,
				    src, payload, DMA_TO_DEVICE);
}

static int m2m1shot2_get_sources(struct m2m1shot2_context *ctx,
				 struct m2m1shot2_image __user *usersrc,
				 bool blocking)
{
	struct device *dev = ctx->m21dev->dev;
	struct m2m1shot2_source_image *image = ctx->source;
	unsigned int i;
	int ret;

	for (i = 0; i < ctx->num_sources; i++, usersrc++) {
		struct m2m1shot2_image source;

		if (copy_from_user(&source, usersrc, sizeof(source))) {
			dev_err(dev,
				"%s: Failed to read source[%u] image data\n",
				__func__, i);
			ret = -EFAULT;
			goto err;
		}

		/* blocking mode does not allow fences */
		if (blocking && !!(source.flags & M2M1SHOT2_FENCE_MASK)) {
			dev_err(dev, "%s: fence set for blocking mode\n",
				__func__);
			ret = -EINVAL;
			goto err;
		}

		ret = m2m1shot2_get_source(ctx, i, &image[i], &source);
		if (ret)
			goto err;

		ret = ctx->m21dev->ops->prepare_source(ctx, i, &image[i]);
		if (ret) {
			m2m1shot2_put_image(ctx, &image[i].img);
			goto err;
		}

		image[i].img.fence = NULL;

		if (!!(image[i].img.flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE)) {
			image[i].img.fence = sync_fence_fdget(source.fence);
			if (image[i].img.fence == NULL) {
				dev_err(dev, "%s: invalid acquire fence %d\n",
					__func__, source.fence);
				ret = -EINVAL;
				image[i].img.flags &=
					~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
				m2m1shot2_put_image(ctx, &image[i].img);
				goto err;
			}

			if (!m2m1shot2_check_fence_wait(ctx, i,
						image[i].img.fence,
						&image[i].img.waiter))
				image[i].img.flags &=
					~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
		}
	}

	return 0;
err:
	while (i-- > 0)
		m2m1shot2_put_image(ctx, &ctx->source[i].img);

	ctx->num_sources = 0;

	return ret;

}

static struct sync_fence *m2m1shot2_create_fence(struct m2m1shot2_context *ctx)
{
	struct device *dev = ctx->m21dev->dev;
	struct sync_fence *fence;
	struct sync_pt *pt;

	pt = sw_sync_pt_create(ctx->timeline, ctx->timeline_max + 1);
	if (!pt) {
		dev_err(dev,
			"%s: failed to create sync_pt\n", __func__);
		return NULL;
	}

	fence = sync_fence_create("m2m1shot2", pt);
	if (!fence) {
		dev_err(dev, "%s: failed to create fence\n", __func__);
		sync_pt_free(pt);
	}

	return fence;
}

static int m2m1shot2_get_target(struct m2m1shot2_context *ctx,
				struct m2m1shot2_image *dst)
{
	struct device *dev = ctx->m21dev->dev;
	struct m2m1shot2_context_image *img = &ctx->target;
	size_t payload[M2M1SHOT2_MAX_PLANES];
	unsigned int i, num_planes;
	int ret;

	if (!M2M1SHOT2_BUFTYPE_VALID(dst->memory)) {
		dev_err(dev,
			"%s: invalid memory type %u specified for target\n",
			__func__, dst->memory);
		return -EINVAL;
	}

	if (dst->memory == M2M1SHOT2_BUFTYPE_EMPTY) {
		dev_err(dev,
			"%s: M2M1SHOT2_BUFTYPE_EMPTY is not valid for target\n",
			__func__);
		return -EINVAL;
	}

	img->fmt.fmt = dst->fmt;
	img->fmt.colorspace = dst->colorspace;

	/*
	 * The client driver may configure 0 to payload if it is not able to
	 * determine the payload before image processing especially when the
	 * result is a compressed data
	 */
	ret = ctx->m21dev->ops->prepare_format(&img->fmt, 0,
				DMA_FROM_DEVICE, payload, &num_planes);
	if (ret) {
		dev_err(dev, "%s: invalid format specified for target\n",
			__func__);
		return ret;
	}

	BUG_ON((num_planes < 1) || (num_planes > M2M1SHOT2_MAX_PLANES));

	if (num_planes != dst->num_planes) {
		dev_err(dev, "%s: wrong number of planes %u for target\n",
			__func__, dst->num_planes);
		return -EINVAL;
	}

	for (i = 0; i < num_planes; i++) {
		if ((payload[i] != 0) && (dst->plane[i].length < payload[i])) {
			dev_err(dev,
				"%s: too small size %u (plane %u)\n",
				__func__, dst->plane[i].length, i);
			return -EINVAL;
		}
	}

	ret = m2m1shot2_get_buffer(ctx, img, dst, payload, DMA_FROM_DEVICE);
	if (ret)
		return ret;

	img->flags = dst->flags;
	img->fence = NULL;

	if (!!(img->flags & M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE)) {
		img->fence = sync_fence_fdget(dst->fence);
		if (img->fence == NULL) {
			dev_err(dev, "%s: invalid acquire fence %d\n",
				__func__, dst->fence);
			img->flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
			m2m1shot2_put_buffer(ctx, dst->memory,
						img->plane, img->num_planes);
			img->memory = M2M1SHOT2_BUFTYPE_NONE;
			return -EINVAL;
		}

		if (!m2m1shot2_check_fence_wait(ctx, ctx->num_sources,
					   img->fence, &img->waiter))
			img->flags &= ~M2M1SHOT2_IMGFLAG_ACQUIRE_FENCE;
	}

	return 0;
}

static int m2m1shot2_get_userdata(struct m2m1shot2_context *ctx,
				  struct m2m1shot2 *data)
{
	struct device *dev = ctx->m21dev->dev;
	struct m2m1shot2_image __user *usersrc = data->sources;
	unsigned int len_src, len_dst;
	bool blocking;
	int ret;

	if ((data->num_sources < 1) ||
			(data->num_sources > M2M1SHOT2_MAX_IMAGES)) {
		dev_err(dev, "%s: Invalid number of source images %u\n",
			__func__, data->num_sources);
		return -EINVAL;
	}

	blocking = !(data->flags & M2M1SHOT2_FLAG_NONBLOCK);

	while (ctx->num_sources > data->num_sources) {
		ctx->num_sources--;
		m2m1shot2_put_image(ctx, &ctx->source[ctx->num_sources].img);
	}

	ctx->ctx_private = 0;
	ctx->ctx_private2 = 0;
	ctx->num_sources = data->num_sources;
	ctx->flags = data->flags;

	ret = m2m1shot2_get_sources(ctx, usersrc, blocking);
	if (ret)
		return ret;

	if (blocking && !!(data->target.flags & M2M1SHOT2_FENCE_MASK)) {
		dev_err(dev, "%s: fence set for blocking mode\n", __func__);
		ret = -EINVAL;
		goto err;
	}

	len_src = ctx->ctx_private;

	ret = m2m1shot2_get_target(ctx, &data->target);
	if (ret)
		goto err;

	ret = ctx->m21dev->ops->prepare_target(ctx, &ctx->target);
	if (ret)
		goto err;

	len_dst = ctx->ctx_private - len_src;

	if (ctx->ctx_private < M2M1SHOT2_NEED_CACHEFLUSH_ALL)
		clear_bit(M2M1S2_CTXSTATE_CACHECLEANALL, &ctx->state);
	else
		set_bit(M2M1S2_CTXSTATE_CACHECLEANALL, &ctx->state);

	if (ctx->ctx_private2 > 0)
		set_bit(M2M1S2_CTXSTATE_CACHEFLUSH, &ctx->state);
	else
		clear_bit(M2M1S2_CTXSTATE_CACHEFLUSH, &ctx->state);

	if (ctx->ctx_private2 < M2M1SHOT2_NEED_CACHEFLUSH_ALL)
		clear_bit(M2M1S2_CTXSTATE_CACHEFLUSHALL, &ctx->state);
	else
		set_bit(M2M1S2_CTXSTATE_CACHEFLUSHALL, &ctx->state);

	if (!(ctx->target.flags & M2M1SHOT2_IMGFLAG_NO_CACHEINV) &&
				(len_dst < M2M1SHOT2_NEED_CACHEFLUSH_ALL))
		clear_bit(M2M1S2_CTXSTATE_CACHEINVALALL, &ctx->state);
	else
		set_bit(M2M1S2_CTXSTATE_CACHEINVALALL, &ctx->state);

	return 0;
err:
	m2m1shot2_put_source_images(ctx);
	return ret;
}

static int m2m1shot2_install_fence(struct m2m1shot2_context *ctx,
				   struct sync_fence *fence,
				   s32 __user *pfd)
{
	int fd = get_unused_fd_flags(O_CLOEXEC);

	if (fd < 0) {
		dev_err(ctx->m21dev->dev, "%s: failed to allocated unused fd\n",
			__func__);
		return fd;
	}

	if (put_user(fd, pfd)) {
		dev_err(ctx->m21dev->dev,
			"%s: failed to put release fence to user\n", __func__);
		put_unused_fd(fd);
		return -EFAULT;
	}

	sync_fence_install(fence, fd);

	return fd;
}

static int m2m1shot2_create_release_fence(struct m2m1shot2_context *ctx,
					struct m2m1shot2_image __user *usertgt,
					struct m2m1shot2_image __user usersrc[],
					unsigned int num_sources)
{
	struct sync_fence *fence = NULL;
	struct m2m1shot2_context_image *img;
	unsigned int i, ifd = 0;
	int fds[M2M1SHOT2_MAX_IMAGES + 1];
	unsigned int num_fences = 0;
	int ret = 0;

	if (!!(ctx->target.flags & M2M1SHOT2_IMGFLAG_RELEASE_FENCE))
		num_fences++;

	for (i = 0; i < ctx->num_sources; i++) {
		if (!!(ctx->source[i].img.flags &
					M2M1SHOT2_IMGFLAG_RELEASE_FENCE))
			num_fences++;
	}

	if (num_fences == 0)
		return 0;

	fence = m2m1shot2_create_fence(ctx);
	if (!fence)
		return -ENOMEM;

	for (i = 0; i < ctx->num_sources; i++) {
		img = &ctx->source[i].img;
		if (!!(img->flags & M2M1SHOT2_IMGFLAG_RELEASE_FENCE)) {
			ret = m2m1shot2_install_fence(ctx,
					fence, &usersrc[i].fence);
			if (ret < 0)
				goto err;

			get_file(fence->file);
			fds[ifd++] = ret;
		}
	}

	img = &ctx->target;
	if (!!(ctx->target.flags & M2M1SHOT2_IMGFLAG_RELEASE_FENCE)) {
		ret = m2m1shot2_install_fence(ctx, fence,
						&usertgt->fence);
		if (ret < 0)
			goto err;

		get_file(fence->file);
		fds[ifd++] = ret;
	}

	/* release a reference of the fence that is increased on creation */
	sync_fence_put(fence);

	ctx->timeline_max++;
	ctx->release_fence = fence;

	return 0;
err:
	while (ifd-- > 0) {
		put_unused_fd(fds[ifd]);
		sync_fence_put(fence);
	}

	sync_fence_put(fence);

	return ret;
}

static int m2m1shot2_wait_put_user(struct m2m1shot2_context *ctx,
				   struct m2m1shot2 __user *uptr, u32 userflag)
{
	int ret = 0;

	if (!m2m1shot2_wait_process(ctx->m21dev, ctx)) {
		userflag |= M2M1SHOT2_FLAG_ERROR;
		ret = put_user(userflag, &uptr->flags);
	} else {
		unsigned int i;

		for (i = 0; i < ctx->target.num_planes; i++)
			ret = put_user(ctx->target.plane[i].payload,
					&uptr->target.plane[i].payload);
		put_user(ctx->work_delay_in_nsec, &uptr->work_delay_in_nsec);
	}

	return ret;
}

/*
 * find the previous requested context which has lower priority.
 * if it find that context, we have to return error to avoid
 * for the higher context to wait finishing the lower context job
 */
static int m2m1shot2_prepare_priority_context(struct m2m1shot2_context *ctx)
{
	struct m2m1shot2_device *m21dev = ctx->m21dev;
	struct m2m1shot2_context *pctx;
	unsigned long flags;
	int cond = ctx->priority;

	spin_lock_irqsave(&m21dev->lock_ctx, flags);
	list_for_each_entry(pctx, &m21dev->active_contexts, node) {
		if (pctx->priority < cond)
			goto err_busy;
	}

	list_for_each_entry(pctx, &m21dev->contexts, node) {
		if ((pctx->priority < cond) && M2M1S2_CTXSTATE_BUSY(pctx))
			goto err_busy;
	}

	pctx = m2m1shot2_current_context(m21dev);
	if (pctx && (pctx->priority < cond))
		goto err_busy;

	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	return 0;

err_busy:
	spin_unlock_irqrestore(&m21dev->lock_ctx, flags);

	return -EBUSY;
}

static long m2m1shot2_ioctl(struct file *filp,
			    unsigned int cmd, unsigned long arg)
{
	struct m2m1shot2_context *ctx = filp->private_data;
	struct m2m1shot2_device *m21dev = ctx->m21dev;
	int ret = 0;

	mutex_lock(&ctx->mutex);

	switch (cmd) {
	case M2M1SHOT2_IOC_REQUEST_PERF:
	{
		struct m2m1shot2_performance_data data;
		int i;

		if (!ctx->m21dev->ops->prepare_perf) {
			dev_err(ctx->m21dev->dev,
				"%s: it doesn't exist the prepare performance\n", __func__);
			ret = -ENOTTY;
			break;
		}

		if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
			dev_err(ctx->m21dev->dev,
				"%s: Failed to performance data\n", __func__);
			ret = -EFAULT;
			break;
		}

		if (data.num_frames >= M2M1SHOT2_PERF_MAX_FRAMES) {
			ret = -EINVAL;
			break;
		}

		for (i = 0; i < data.num_frames; i++) {
			if (data.frame[i].num_layers >= M2M1SHOT2_MAX_IMAGES) {
				ret = -EINVAL;
				break;
			}
		}
		if (!ret)
			ret = ctx->m21dev->ops->prepare_perf(ctx, &data);

		break;
	}
	case M2M1SHOT2_IOC_SET_PRIORITY:
	{
		enum m2m1shot2_priority data;

		get_user(data, (enum m2m1shot2_priority __user *)arg);

		if ((data < M2M1SHOT2_LOW_PRIORITY) ||
					(data >= M2M1SHOT2_PRIORITY_END)) {
			dev_err(m21dev->dev,
				"%s: m2m1shot2 does not allow %d priority\n",
				__func__, data);
			ret = -EINVAL;
			break;
		}

		/* update current priority */
		if (data != ctx->priority) {
			spin_lock(&m21dev->lock_priority);
			m21dev->prior_stats[ctx->priority] -= 1;
			m21dev->prior_stats[data] += 1;
			ctx->priority = data;
			spin_unlock(&m21dev->lock_priority);
		}

		ret = m2m1shot2_prepare_priority_context(ctx);
		if (ret < 0)
			break;

		break;
	}
	case M2M1SHOT2_IOC_PROCESS:
	{
		struct m2m1shot2 __user *uptr = (struct m2m1shot2 __user *)arg;
		struct m2m1shot2 data;
		int i;

		if (copy_from_user(&data, uptr, sizeof(data))) {
			dev_err(ctx->m21dev->dev,
				"%s: Failed to read userdata\n", __func__);
			ret = -EFAULT;
			break;
		}

		/* wait for completion of the previous task */
		if (!M2M1S2_CTXSTATE_IDLE(ctx))
			m2m1shot2_wait_process(m21dev, ctx);

		/*
		 * A new process request with the lower priority than the
		 * heighest priority currently configured is not allowed
		 * to be executed and m2m1shot2 simply returns -EBUSY
		 */
		spin_lock(&m21dev->lock_priority);
		for (i = ctx->priority + 1; i < M2M1SHOT2_PRIORITY_END; i++) {
			if (m21dev->prior_stats[i] > 0)
				break;
		}
		spin_unlock(&m21dev->lock_priority);

		if (i < M2M1SHOT2_PRIORITY_END) {
			ret = -EBUSY;
			break;
		}

		kref_init(&ctx->starter);

		ret = m2m1shot2_get_userdata(ctx, &data);
		if (ret < 0)
			break;

		ctx->release_fence = NULL;
		if (!!(data.flags & M2M1SHOT2_FLAG_NONBLOCK)) {
			ret = m2m1shot2_create_release_fence(ctx, &uptr->target,
						data.sources, data.num_sources);
			if (ret < 0) {
				m2m1shot2_put_images(ctx);
				break;
			}
		}

		m2m1shot2_start_context(ctx->m21dev, ctx);

		if (!(data.flags & M2M1SHOT2_FLAG_NONBLOCK)) {
			ret = m2m1shot2_wait_put_user(ctx, uptr, data.flags);
			m2m1shot2_put_images(ctx);
		}

		break;
	}
	case M2M1SHOT2_IOC_WAIT_PROCESS:
	{
		struct m2m1shot2 __user *uptr = (void __user *)arg;
		struct m2m1shot2 data;

		if (M2M1S2_CTXSTATE_IDLE(ctx)) {
			ret = -EAGAIN;
			break;
		}

		if (copy_from_user(&data, uptr, sizeof(data))) {
			dev_err(ctx->m21dev->dev,
				"%s: Failed to read userdata\n", __func__);
			ret = -EFAULT;
			break;
		}

		ret = m2m1shot2_wait_put_user(ctx, uptr, data.flags);

		break;
	}
	case M2M1SHOT2_IOC_CUSTOM:
	{
		struct m2m1shot2_custom_data data;

		if (!ctx->m21dev->ops->custom_ioctl) {
			dev_err(ctx->m21dev->dev,
				"%s: it doesn't exist the custom ioctl\n", __func__);
			ret = -ENOTTY;
			break;
		}
		if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
			dev_err(ctx->m21dev->dev,
				"%s: Failed to read userdata\n", __func__);
			ret = -EFAULT;
			break;
		}
		ret = ctx->m21dev->ops->custom_ioctl(ctx, data.cmd, data.arg);
		break;
	}
	default:
	{
		dev_err(ctx->m21dev->dev,
			"%s: unknown ioctl command %#x\n", __func__, cmd);
		ret = -EINVAL;
		break;
	}
	} /* switch */

	mutex_unlock(&ctx->mutex);

	return ret;
}

#ifdef CONFIG_COMPAT
struct compat_m2m1shot2_buffer {
	union {
		compat_ulong_t	userptr;
		__s32		fd;
	};
	__u32		offset;
	__u32		length;
	__u32		payload;
	compat_ulong_t	reserved;
};

struct compat_m2m1shot2_image {
	__u32				flags;
	__s32				fence;
	__u8				memory;
	__u8				num_planes;
	struct compat_m2m1shot2_buffer	plane[M2M1SHOT2_MAX_PLANES];
	struct m2m1shot2_format		fmt;
	struct m2m1shot2_extra		ext;
	__u32				reserved[4];
};

struct compat_m2m1shot2 {
	compat_uptr_t			sources;
	struct compat_m2m1shot2_image	target;
	__u8				num_sources;
	__u32				flags;
	__u32				reserved1;
	__u32				reserved2;
	compat_ulong_t			work_delay_in_nsec;
	compat_ulong_t			reserved4;
};

#define COMPAT_M2M1SHOT2_IOC_PROCESS	  _IOWR('M', 4, struct compat_m2m1shot2)
#define COMPAT_M2M1SHOT2_IOC_WAIT_PROCESS _IOR('M', 5, struct compat_m2m1shot2)

static int m2m1shot2_compat_get_imagedata(struct device *dev,
				struct m2m1shot2_image __user *img,
				struct compat_m2m1shot2_image __user *cimg)
{
	__u32 uw;
	__s32 sw;
	__u8 b;
	compat_ulong_t l;
	unsigned int i;
	int ret;

	ret =  get_user(uw, &cimg->flags);
	ret |= put_user(uw, &img->flags);
	ret |= get_user(sw, &cimg->fence);
	ret |= put_user(sw, &img->fence);
	ret |= get_user(b, &cimg->memory);
	ret |= put_user(b, &img->memory);
	ret |= get_user(b, &cimg->num_planes);
	ret |= put_user(b, &img->num_planes);
	if (b > M2M1SHOT2_MAX_PLANES) {
		dev_err(dev, "%s: too many plane count %u\n", __func__, b);
		return -EINVAL;
	}
	for (i = 0; i < b; i++) { /* b contains num_planes */
		/* userptr is not smaller than fd */
		ret |= get_user(l, &cimg->plane[i].userptr);
		ret |= put_user(l, &img->plane[i].userptr);
		ret |= get_user(uw, &cimg->plane[i].offset);
		ret |= put_user(uw, &img->plane[i].offset);
		ret |= get_user(uw, &cimg->plane[i].length);
		ret |= put_user(uw, &img->plane[i].length);
		ret |= get_user(uw, &cimg->plane[i].payload);
		ret |= put_user(uw, &img->plane[i].payload);
		ret |= get_user(l, &cimg->plane[i].reserved);
		ret |= put_user(l, &img->plane[i].reserved);
	}

	ret |= copy_in_user(&img->fmt, &cimg->fmt,
			sizeof(struct m2m1shot2_format) +
			sizeof(struct m2m1shot2_extra) + sizeof(__u32) * 4);

	return ret ? -EFAULT : 0;
}

static int m2m1shot2_compat_put_imagedata(struct m2m1shot2_image __user *img,
				struct compat_m2m1shot2_image __user *cimg)
{
	__u32 uw;
	__s32 sw;
	__u8 b;
	compat_ulong_t l;
	unsigned int i;
	int ret;

	ret  = get_user(uw, &img->flags);
	ret |= put_user(uw, &cimg->flags);
	if (!!(uw & M2M1SHOT2_IMGFLAG_RELEASE_FENCE)) {
		ret |= get_user(sw, &img->fence);
		ret |= put_user(sw, &cimg->fence);
	}
	ret |= get_user(b, &img->num_planes);
	for (i = 0; i < b; i++) { /* b contains num_planes */
		ret |= get_user(uw, &img->plane[i].payload);
		ret |= put_user(uw, &cimg->plane[i].payload);
		ret |= get_user(l, &img->plane[i].reserved);
		ret |= put_user(l, &cimg->plane[i].reserved);
	}

	return ret;
}

static int m2m1shot2_compat_put_fence(struct m2m1shot2_image __user *img,
				struct compat_m2m1shot2_image __user *cimg)
{
	__u32 uw = 0;
	__s32 sw;
	int ret;

	ret =  get_user(uw, &img->flags);
	if (!!(uw & M2M1SHOT2_IMGFLAG_RELEASE_FENCE)) {
		ret |= get_user(sw, &img->fence);
		ret |= put_user(sw, &cimg->fence);
	}

	return ret;
}

static long m2m1shot2_compat_ioctl32(struct file *filp,
				unsigned int cmd, unsigned long arg)
{
	struct m2m1shot2_context *ctx = filp->private_data;
	struct device *dev = ctx->m21dev->dev;
	struct compat_m2m1shot2 __user *cdata = compat_ptr(arg);
	struct m2m1shot2 __user *data;
	struct m2m1shot2_image __user *src;
	int ret;
	compat_ulong_t l;
	compat_uptr_t sources;
	__u32 w;
	__u8 num_sources;

	switch (cmd) {
	case COMPAT_M2M1SHOT2_IOC_PROCESS:
		cmd = M2M1SHOT2_IOC_PROCESS;
		break;
	case COMPAT_M2M1SHOT2_IOC_WAIT_PROCESS:
		cmd = M2M1SHOT2_IOC_WAIT_PROCESS;
		break;
	case M2M1SHOT2_IOC_CUSTOM:
	case M2M1SHOT2_IOC_SET_PRIORITY:
	case M2M1SHOT2_IOC_REQUEST_PERF:
		if (!filp->f_op->unlocked_ioctl)
			return -ENOTTY;

		return filp->f_op->unlocked_ioctl(filp, cmd,
						(unsigned long)compat_ptr(arg));
	default:
		dev_err(dev, "%s: unknown ioctl command %#x\n", __func__, cmd);
		return -EINVAL;
	}

	data = compat_alloc_user_space(sizeof(*data));

	ret  = get_user(num_sources, &cdata->num_sources);
	ret |= put_user(num_sources, &data->num_sources);
	ret |= get_user(w, &cdata->flags);
	ret |= put_user(w, &data->flags);
	ret |= get_user(w, &cdata->reserved1);
	ret |= put_user(w, &data->reserved1);
	ret |= get_user(w, &cdata->reserved2);
	ret |= put_user(w, &data->reserved2);
	ret |= get_user(l, &cdata->work_delay_in_nsec);
	ret |= put_user(l, &data->work_delay_in_nsec);
	ret |= get_user(l, &cdata->reserved4);
	ret |= put_user(l, &data->reserved4);
	ret |= get_user(sources, &cdata->sources);
	if (ret) {
		dev_err(dev, "%s: failed to read m2m1shot2 data\n", __func__);
		return -EFAULT;
	}

	ret = m2m1shot2_compat_get_imagedata(
				dev, &data->target, &cdata->target);
	if (ret) {
		dev_err(dev, "%s: failed to read the target image data\n",
			__func__);
		return ret;
	}

	if (cmd == M2M1SHOT2_IOC_PROCESS) {
		struct compat_m2m1shot2_image __user *csc = compat_ptr(sources);

		src = compat_alloc_user_space(
				sizeof(*data) + sizeof(*src) * num_sources);
		if (w > M2M1SHOT2_MAX_IMAGES) {
			dev_err(dev, "%s: too many source images %u\n",
				__func__, w);
			return -EINVAL;
		}

		for (w = 0; w < num_sources; w++) {
			ret = m2m1shot2_compat_get_imagedata(
						dev, &src[w], &csc[w]);
			if (ret) {
				dev_err(dev,
				"%s: failed to read %dth source image data\n",
					__func__, w);
				return ret;
			}
		}


		if (put_user(src, &data->sources)) {
			dev_err(dev, "%s: failed to handle source image data\n",
				__func__);
			return -EFAULT;
		}
	}

	ret = m2m1shot2_ioctl(filp, cmd, (unsigned long)data);
	if (ret)
		return ret;

	ret  = get_user(w, &data->flags);
	ret |= put_user(w, &cdata->flags);
	ret |= get_user(w, &data->reserved1);
	ret |= put_user(w, &cdata->reserved1);
	ret |= get_user(w, &data->reserved2);
	ret |= put_user(w, &cdata->reserved2);
	ret |= get_user(l, &data->work_delay_in_nsec);
	ret |= put_user(l, &cdata->work_delay_in_nsec);
	ret |= get_user(l, &data->reserved4);
	ret |= put_user(l, &cdata->reserved4);
	ret |= m2m1shot2_compat_put_imagedata(&data->target, &cdata->target);

	if (cmd == M2M1SHOT2_IOC_PROCESS) {
		struct compat_m2m1shot2_image __user *csc = compat_ptr(sources);

		for (w = 0; w < num_sources; w++)
			ret |= m2m1shot2_compat_put_fence(&src[w], &csc[w]);
	}

	if (ret)
		dev_err(dev, "%s: failed to write userdata\n", __func__);

	return ret;
}
#endif

static const struct file_operations m2m1shot2_fops = {
	.owner          = THIS_MODULE,
	.open           = m2m1shot2_open,
	.release        = m2m1shot2_release,
	.unlocked_ioctl	= m2m1shot2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= m2m1shot2_compat_ioctl32,
#endif
};

struct m2m1shot2_device *m2m1shot2_create_device(struct device *dev,
					const struct m2m1shot2_devops *ops,
					const char *nodename, int id,
					unsigned long attr)
{
	struct m2m1shot2_device *m21dev;
	char *name;
	size_t name_size;
	int ret = -ENOMEM;

	if (!ops || !ops->init_context || !ops->free_context ||
			!ops->prepare_format || !ops->device_run) {
		dev_err(dev,
			"%s: m2m1shot2_devops is insufficient\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	if (!nodename) {
		dev_err(dev, "%s: node name is not specified\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	name_size = strlen(nodename) + 1;

	if (id >= 0)
		name_size += 3; /* instance number: maximum 3 digits */

	name = kmalloc(name_size, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);

	if (id < 0)
		strncpy(name, nodename, name_size);
	else
		scnprintf(name, name_size, "%s%d", nodename, id);

	m21dev = kzalloc(sizeof(*m21dev), GFP_KERNEL);
	if (!m21dev)
		goto err_m21dev;

	m21dev->misc.minor = MISC_DYNAMIC_MINOR;
	m21dev->misc.name = name;
	m21dev->misc.fops = &m2m1shot2_fops;
	ret = misc_register(&m21dev->misc);
	if (ret)
		goto err_misc;

	m21dev->schedule_workqueue =
		create_singlethread_workqueue("m2m1shot2-scheduler");
	if (!m21dev->schedule_workqueue) {
		dev_err(dev, "failed to create workqueue for scheduling\n");
		ret = -ENOMEM;
		goto err_workqueue;
	}

	m21dev->destroy_workqueue =
		create_singlethread_workqueue("m2m1shot2-destructor");
	if (!m21dev->schedule_workqueue) {
		dev_err(dev, "failed to create workqueue for context destruction\n");
		ret = -ENOMEM;
		goto err_workqueue2;
	}

	spin_lock_init(&m21dev->lock_ctx);
	spin_lock_init(&m21dev->lock_priority);
	INIT_LIST_HEAD(&m21dev->contexts);
	INIT_LIST_HEAD(&m21dev->active_contexts);

	m21dev->dev = dev;
	m21dev->ops = ops;
	m21dev->attr = attr;

	dev_info(dev, "registered as m2m1shot2 device");

	return m21dev;
err_workqueue2:
	destroy_workqueue(m21dev->schedule_workqueue);
err_workqueue:
	misc_deregister(&m21dev->misc);
err_misc:
	kfree(m21dev);
err_m21dev:
	kfree(name);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL(m2m1shot2_create_device);

void m2m1shot2_destroy_device(struct m2m1shot2_device *m21dev)
{
	destroy_workqueue(m21dev->destroy_workqueue);
	destroy_workqueue(m21dev->schedule_workqueue);
	misc_deregister(&m21dev->misc);
	kfree(m21dev->misc.name);
	kfree(m21dev);
	/* TODO: something forgot to release? */
}
EXPORT_SYMBOL(m2m1shot2_destroy_device);

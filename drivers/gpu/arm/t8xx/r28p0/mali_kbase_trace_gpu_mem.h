/* SPDX-License-Identifier: GPL-2.0 */
/* Adapted from Arm's Mali GPU memory tracing interface (2020). */
#ifndef _KBASE_TRACE_GPU_MEM_H_
#define _KBASE_TRACE_GPU_MEM_H_

#ifdef CONFIG_TRACE_GPU_MEM
void kbase_gpu_mem_init(struct kbase_device *kbdev);
int kbase_gpu_mem_context_init(struct kbase_context *kctx);
void kbase_gpu_mem_context_term(struct kbase_context *kctx);
void kbase_gpu_mem_account(struct kbase_device *kbdev,
		struct kbase_context *kctx, long pages);
void kbase_add_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc);
void kbase_remove_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc);
#else
static inline void kbase_gpu_mem_init(struct kbase_device *kbdev) {}
static inline int kbase_gpu_mem_context_init(struct kbase_context *kctx)
{
	return 0;
}
static inline void kbase_gpu_mem_context_term(struct kbase_context *kctx) {}
static inline void kbase_gpu_mem_account(struct kbase_device *kbdev,
		struct kbase_context *kctx, long pages) {}
static inline void kbase_add_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc) {}
static inline void kbase_remove_dma_buf_usage(struct kbase_context *kctx,
		struct kbase_mem_phy_alloc *alloc) {}
#endif

#endif

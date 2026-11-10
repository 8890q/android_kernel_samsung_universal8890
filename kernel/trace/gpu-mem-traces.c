// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>

#define CREATE_TRACE_POINTS
#include <trace/events/gpu_mem.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(gpu_mem_total);

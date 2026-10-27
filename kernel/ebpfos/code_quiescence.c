// SPDX-License-Identifier: GPL-2.0-only
#include <linux/export.h>
#include "code_quiescence.h"
#include "function_lifetime.h"

struct stopped_code_ranges {
 const struct ebpfos_code_range *ranges;
 unsigned int count;
};
static bool stopped_code_contains(void *opaque, unsigned long ip)
{
 struct stopped_code_ranges *code = opaque;
 unsigned int i;
 for (i = 0; i < code->count; ++i)
  if (ip >= code->ranges[i].begin && ip < code->ranges[i].end) return true;
 return false;
}
int ebpfos_code_stopped_ranges(const struct ebpfos_code_range *ranges, unsigned int count)
{
 struct stopped_code_ranges code = { .ranges = ranges, .count = count };
 unsigned int i;
 if (!ranges || !count) return -EINVAL;
 for (i = 0; i < count; ++i)
  if (ranges[i].begin >= ranges[i].end) return -EINVAL;
 return ebpfos_code_stopped(stopped_code_contains, &code);
}
EXPORT_SYMBOL_GPL(ebpfos_code_stopped_ranges);

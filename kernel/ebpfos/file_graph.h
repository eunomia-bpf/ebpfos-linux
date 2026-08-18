/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_FILE_GRAPH_H
#define _EBPFOS_FILE_GRAPH_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define EBPFOS_FILE_GRAPH_MAX_SLOTS 2U
#define EBPFOS_FILE_GRAPH_RIGHT_READ (1U << 0)
#define EBPFOS_FILE_GRAPH_RIGHT_APPEND (1U << 1)

enum ebpfos_file_graph_shape {
	EBPFOS_FILE_GRAPH_COMBINED = 1,
	EBPFOS_FILE_GRAPH_SPLIT = 2,
};

struct ebpfos_file_graph_slot {
	u64 provider_id;
	u64 schema_hash;
	u32 provider_kind;
	u32 rights;
};

/*
 * Immutable after publication.  Mutable reader/writer progress lives in the
 * route; publish_frontier is the equal frontier proved by the graph rewrite.
 */
struct ebpfos_file_graph {
	u64 epoch;
	u64 publish_frontier;
	u32 shape;
	u32 slot_count;
	u32 read_slot;
	u32 append_slot;
	struct ebpfos_file_graph_slot slots[EBPFOS_FILE_GRAPH_MAX_SLOTS];
};

static inline bool
ebpfos_file_graph_slot_valid(const struct ebpfos_file_graph_slot *slot)
{
	return slot && slot->provider_id && slot->rights;
}

static inline bool
ebpfos_file_graph_valid(const struct ebpfos_file_graph *graph)
{
	const struct ebpfos_file_graph_slot *reader;
	const struct ebpfos_file_graph_slot *writer;

	if (!graph || !graph->slot_count ||
	    graph->slot_count > EBPFOS_FILE_GRAPH_MAX_SLOTS ||
	    graph->read_slot >= graph->slot_count ||
	    graph->append_slot >= graph->slot_count)
		return false;
	reader = &graph->slots[graph->read_slot];
	writer = &graph->slots[graph->append_slot];
	if (!ebpfos_file_graph_slot_valid(reader) ||
	    !ebpfos_file_graph_slot_valid(writer))
		return false;

	switch (graph->shape) {
	case EBPFOS_FILE_GRAPH_COMBINED:
		return graph->slot_count == 1 && graph->read_slot == 0 &&
		       graph->append_slot == 0 &&
		       reader->rights == (EBPFOS_FILE_GRAPH_RIGHT_READ |
					  EBPFOS_FILE_GRAPH_RIGHT_APPEND);
	case EBPFOS_FILE_GRAPH_SPLIT:
		return graph->epoch && graph->slot_count == 2 &&
		       graph->read_slot != graph->append_slot &&
		       reader->provider_id != writer->provider_id &&
		       reader->rights == EBPFOS_FILE_GRAPH_RIGHT_READ &&
		       writer->rights == EBPFOS_FILE_GRAPH_RIGHT_APPEND;
	default:
		return false;
	}
}

static inline int ebpfos_file_graph_init_combined(
	struct ebpfos_file_graph *graph, u64 epoch, u64 publish_frontier,
	u64 provider_id, u64 schema_hash, u32 provider_kind)
{
	if (!graph || !provider_id)
		return -EINVAL;
	memset(graph, 0, sizeof(*graph));
	graph->epoch = epoch;
	graph->publish_frontier = publish_frontier;
	graph->shape = EBPFOS_FILE_GRAPH_COMBINED;
	graph->slot_count = 1;
	graph->read_slot = 0;
	graph->append_slot = 0;
	graph->slots[0].provider_id = provider_id;
	graph->slots[0].schema_hash = schema_hash;
	graph->slots[0].provider_kind = provider_kind;
	graph->slots[0].rights = EBPFOS_FILE_GRAPH_RIGHT_READ |
				 EBPFOS_FILE_GRAPH_RIGHT_APPEND;
	return 0;
}

static inline int ebpfos_file_graph_init_split(
	struct ebpfos_file_graph *graph, u64 epoch, u64 publish_frontier,
	const struct ebpfos_file_graph_slot *reader,
	const struct ebpfos_file_graph_slot *writer)
{
	if (!graph || !reader || !writer || !epoch || !reader->provider_id ||
	    !writer->provider_id || reader->provider_id == writer->provider_id ||
	    reader->rights != EBPFOS_FILE_GRAPH_RIGHT_READ ||
	    writer->rights != EBPFOS_FILE_GRAPH_RIGHT_APPEND)
		return -EINVAL;
	memset(graph, 0, sizeof(*graph));
	graph->epoch = epoch;
	graph->publish_frontier = publish_frontier;
	graph->shape = EBPFOS_FILE_GRAPH_SPLIT;
	graph->slot_count = 2;
	graph->read_slot = 0;
	graph->append_slot = 1;
	graph->slots[0] = *reader;
	graph->slots[1] = *writer;
	return 0;
}

static inline const struct ebpfos_file_graph_slot *
ebpfos_file_graph_select(const struct ebpfos_file_graph *graph, bool append)
{
	u32 slot;

	if (!ebpfos_file_graph_valid(graph))
		return NULL;
	slot = append ? graph->append_slot : graph->read_slot;
	return &graph->slots[slot];
}

#endif /* _EBPFOS_FILE_GRAPH_H */

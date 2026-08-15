/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_H
#define _UAPI_EBPFOS_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define EBPFOS_UAPI_VERSION 2
#define EBPFOS_IOC_MAGIC 0xe7
#define EBPFOS_MAX_ARGS 6
#define EBPFOS_MAX_STATE_SLOTS 16
enum ebpfos_hook_id { EBPFOS_HOOK_SYSCALL_ENTER=0, EBPFOS_HOOK_SYSCALL_EXIT, EBPFOS_HOOK_VFS_LOOKUP, EBPFOS_HOOK_VFS_READDIR, EBPFOS_HOOK_SCHED_SELECT, EBPFOS_HOOK_SCHED_ENQUEUE, EBPFOS_HOOK_MM_RECLAIM, EBPFOS_HOOK_BLOCK_SUBMIT, EBPFOS_HOOK_NET_RX, EBPFOS_HOOK_NET_TX, EBPFOS_HOOK_SECURITY, EBPFOS_HOOK_DRIVER_PROBE, EBPFOS_HOOK_DRIVER_LIFECYCLE, EBPFOS_HOOK_MAX };
enum ebpfos_verdict { EBPFOS_VERDICT_CONTINUE=0, EBPFOS_VERDICT_DENY=1, EBPFOS_VERDICT_REDIRECT=2, EBPFOS_VERDICT_OVERRIDE=3, EBPFOS_VERDICT_FALLBACK=4 };
#define EBPFOS_ABI_SYSCALL_ENTER 0x6d23c2ef91efa8b9ULL
#define EBPFOS_ABI_SYSCALL_EXIT 0xccaea0a5c69ba3b3ULL
#define EBPFOS_ABI_VFS_LOOKUP 0x15ad64cb3a2fddd5ULL
#define EBPFOS_ABI_VFS_READDIR 0x76a4934657508e52ULL
#define EBPFOS_ABI_SCHED_SELECT 0xe9bf4388fce4d2d3ULL
#define EBPFOS_ABI_SCHED_ENQUEUE 0x27b841226676ba43ULL
#define EBPFOS_ABI_MM_RECLAIM 0xe1137d1be95f0529ULL
#define EBPFOS_ABI_BLOCK_SUBMIT 0xbdcaa660e509145bULL
#define EBPFOS_ABI_NET_RX 0x702a869a2a96a073ULL
#define EBPFOS_ABI_NET_TX 0xf9d9b7dfcf0fb589ULL
#define EBPFOS_ABI_SECURITY 0x8fa27536eeabab62ULL
#define EBPFOS_ABI_DRIVER_PROBE 0x087fa77d3aa0d222ULL
#define EBPFOS_ABI_DRIVER_LIFECYCLE 0x8a7fbda2b451c51cULL
#define EBPFOS_ACTION_SHIFT 28U
#define EBPFOS_ACTION_PAYLOAD_MASK 0x0fffffffU
#define EBPFOS_ACTION(_v,_p) (((__u32)(_v)<<EBPFOS_ACTION_SHIFT)|((__u32)(_p)&EBPFOS_ACTION_PAYLOAD_MASK))
#define EBPFOS_ACTION_VERDICT(_a) ((__u32)(_a)>>EBPFOS_ACTION_SHIFT)
#define EBPFOS_ACTION_PAYLOAD(_a) ((__u32)(_a)&EBPFOS_ACTION_PAYLOAD_MASK)
struct ebpfos_ioc_version { __u32 uapi_version; __u32 hook_count; };
struct ebpfos_ioc_set_hook { __u32 hook_id; __s32 prog_fd; __u64 abi_hash; __u64 flags; };
#define EBPFOS_STATE_F_MIGRATED (1ULL<<0)
struct ebpfos_ioc_set_state { __u32 slot; __s32 map_fd; __u64 schema_hash; __u64 previous_schema_hash; __u64 flags; };
struct ebpfos_ioc_commit { __u64 expected_generation; __u64 new_generation; };
struct ebpfos_ioc_status { __u64 generation; __u64 hook_mask; __u64 state_mask; };
struct ebpfos_ioc_run { __u32 hook_id; __u32 nr_args; __u64 args[EBPFOS_MAX_ARGS]; __u32 result; __u32 reserved; };
#define EBPFOS_IOC_VERSION _IOR(EBPFOS_IOC_MAGIC,0x00,struct ebpfos_ioc_version)
#define EBPFOS_IOC_BEGIN _IO(EBPFOS_IOC_MAGIC,0x01)
#define EBPFOS_IOC_SET_HOOK _IOW(EBPFOS_IOC_MAGIC,0x02,struct ebpfos_ioc_set_hook)
#define EBPFOS_IOC_COMMIT _IOWR(EBPFOS_IOC_MAGIC,0x03,struct ebpfos_ioc_commit)
#define EBPFOS_IOC_ABORT _IO(EBPFOS_IOC_MAGIC,0x04)
#define EBPFOS_IOC_STATUS _IOR(EBPFOS_IOC_MAGIC,0x05,struct ebpfos_ioc_status)
#define EBPFOS_IOC_RUN _IOWR(EBPFOS_IOC_MAGIC,0x06,struct ebpfos_ioc_run)
#define EBPFOS_IOC_SET_STATE _IOW(EBPFOS_IOC_MAGIC,0x07,struct ebpfos_ioc_set_state)
#endif

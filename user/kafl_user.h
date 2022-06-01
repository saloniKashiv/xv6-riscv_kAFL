#ifndef KAFL_USER_H
#define KAFL_USER_H

#include "kernel/types.h"

#define HYPERCALL_KAFL_RAX_ID			0x01f
#define HYPERCALL_KAFL_ACQUIRE			0
#define HYPERCALL_KAFL_GET_PAYLOAD		1
#define HYPERCALL_KAFL_GET_PROGRAM		2
#define HYPERCALL_KAFL_GET_ARGV			3
#define HYPERCALL_KAFL_RELEASE			4
#define HYPERCALL_KAFL_SUBMIT_CR3		5
#define HYPERCALL_KAFL_SUBMIT_PANIC		6
#define HYPERCALL_KAFL_SUBMIT_KASAN		7
#define HYPERCALL_KAFL_PANIC			8
#define HYPERCALL_KAFL_KASAN			9
#define HYPERCALL_KAFL_LOCK				10
#define HYPERCALL_KAFL_INFO				11
#define HYPERCALL_KAFL_NEXT_PAYLOAD		12

#define PAYLOAD_SIZE					(128 << 10)				/* up to 128KB payloads */
#define PROGRAM_SIZE					(16  << 20)				/* kAFL supports 16MB programm data */
#define INFO_SIZE                       (128 << 10)				/* 128KB info string */
#define TARGET_FILE						"fuzzing_engine"	/* default target for the userspace component */	

typedef struct{
	int size;
	uint8 data[PAYLOAD_SIZE-4];
} kAFL_payload;

static inline void kAFL_hypercall(uint64 rbx, uint64 rcx){
	uint64 rax = HYPERCALL_KAFL_RAX_ID;
	asm volatile ("mv %0, %%ecx;" : : "r"(rcx));
	asm volatile ("mv %0, %%ebx;" : : "r"(rbx));
    asm volatile ("mv %0, %%eax;" : : "r"(rax));
    asm volatile ("vmcall");
}

#endif
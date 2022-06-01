/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "user/kafl_user.h"

static inline void load_programm(void* buf){
	int payload_file;
	char* newargv[] = {TARGET_FILE, 0};

	payload_file = open(TARGET_FILE, O_CREATE|O_RDWR);
	write(payload_file, buf, PROGRAM_SIZE);
	close(payload_file);
	payload_file = open(TARGET_FILE, O_RDONLY);
	exec(TARGET_FILE, newargv);
}

int main(int argc, char** argv)
{
	uint64 panic_handler = 0x0;
	void* program_buffer;

	panic_handler = get_panic_addr();
	printf("Kernel Panic Handler Address:\t%lx\n", panic_handler);

	/* allocate 4MB contiguous virtual memory to hold fuzzer program; data is provided by the fuzzer */
	program_buffer = malloc(PROGRAM_SIZE);
	/* ensure that the virtual memory is *really* present in physical memory... */
	memset(program_buffer, 0xff, PROGRAM_SIZE);

	/* this hypercall will generate a VM snapshot for the fuzzer and subsequently terminate QEMU */
	kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);


	/***** Fuzzer Entrypoint *****/


	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	/* submit panic address */
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
	/* submit virtual address of program buffer and wait for data (*blocking*) */
	kAFL_hypercall(HYPERCALL_KAFL_GET_PROGRAM, (uint64)program_buffer);
	/* execute fuzzer program */
	load_programm(program_buffer);
	/* bye */ 
	return 0;
}
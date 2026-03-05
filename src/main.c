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

#define DEBUG 1
#define _USE_KSTUFF 1
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


extern uint64_t kmem_alloc(size_t size);
extern int kproc_create(uint64_t addr, uint64_t args, uint64_t kproc_name);
extern int kstuff_check();


r0gdb_functions r0gdb;
int kstuff_loaded;
int fw_version;

uint32_t get_fw_version()
{
    int mib[2] = {1, 46};
    unsigned long size = sizeof(mib);
    unsigned int version = 0;
    sysctl(mib, 2, &version, &size, 0, 0);
    return version >> 16;
}


int is_kstuff_unsupported()
{
    uint64_t exec_code = kmem_alloc(0x100);
    pid_t ppid = getppid();
    printf("[debug] kmem_alloc(0x100) raw = %#lx, getppid() = %d\n", exec_code, ppid);
    printf("[debug] (exec_code & 0xff) = %#lx vs ppid = %d\n", exec_code & 0xff, ppid);
    fflush(stdout);

    // A real kernel address should be in the 0xffffff80... range
    // and should NOT have its low byte coincidentally match getppid()
    // Also do a second allocation to confirm consistency
    uint64_t exec_code2 = kmem_alloc(0x100);
    printf("[debug] kmem_alloc(0x100) #2 = %#lx\n", exec_code2);
    fflush(stdout);

    // If both allocations return the same value, it's likely just getpid() echoing back
    // A real allocator would return different addresses
    if (exec_code == exec_code2) {
        printf("[debug] both allocs identical -> kekcall nr=6 NOT working\n");
        fflush(stdout);
        return 1;
    }

    printf("[debug] allocs differ -> kekcall nr=6 IS working\n");
    fflush(stdout);
    return 0;
}

void _kldload(int fd, void* data, ssize_t data_size)
{
    //
    // perform a kekcall to alloc the executable code area
    //
    uint64_t exec_code;
    uint64_t kproc_name;
    uint64_t kthread_args;

    printf("[debug] _kldload called, data_size=%ld, kstuff_loaded=%d\n", data_size, kstuff_loaded);
    printf("[debug] r0gdb_kmem_alloc=%p, r0gdb_kproc_create=%p\n",
        (void*)r0gdb.r0gdb_kmem_alloc, (void*)r0gdb.r0gdb_kproc_create);
    fflush(stdout);

    if (!kstuff_loaded)
    {
        printf("[debug] calling r0gdb_kmem_alloc(%ld)...\n", data_size);
        fflush(stdout);
        exec_code = r0gdb.r0gdb_kmem_alloc(data_size);
        printf("[debug] exec_code = %#lx\n", exec_code);
        fflush(stdout);

        kproc_name = r0gdb.r0gdb_kmem_alloc(0x100);
        printf("[debug] kproc_name = %#lx\n", kproc_name);
        fflush(stdout);

        kthread_args = r0gdb.r0gdb_kmem_alloc(sizeof(kproc_args));
        printf("[debug] kthread_args = %#lx\n", kthread_args);
        fflush(stdout);
    }
    else
    {
        exec_code = kmem_alloc(data_size);
        kproc_name = kmem_alloc(0x100);
        kthread_args = kmem_alloc(sizeof(kproc_args));
    }

    payload_args_t* payload_args = payload_get_args();
    kproc_args args;
    args.kdata_base = payload_args->kdata_base_addr;
    args.fw_ver = fw_version;

    printf("[debug] kdata_base=%#lx fw_ver=%u\n", args.kdata_base, args.fw_ver);
    fflush(stdout);

    puts("[debug] kernel_copyin exec_code...");
    fflush(stdout);
    kernel_copyin(data, exec_code, data_size);

    puts("[debug] kernel_copyin kproc_name...");
    fflush(stdout);
    kernel_copyin(KTHREAD_NAME, kproc_name, sizeof(KTHREAD_NAME));

    puts("[debug] kernel_copyin kthread_args...");
    fflush(stdout);
    kernel_copyin(&args, kthread_args, sizeof(args));

    printf("[debug] launching kthread at %#lx...\n", exec_code);
    fflush(stdout);

    if (kstuff_loaded)
        kproc_create(exec_code, kthread_args, kproc_name);
    else
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

    kstuff_loaded = !kstuff_check();

    if (kstuff_loaded && is_kstuff_unsupported())
    {
        puts("kstuff loaded but kekcall nr=6 unsupported, falling back to r0gdb...");
        notify_send("kstuff unsupported kekcalls, using r0gdb fallback");
        kstuff_loaded = 0;  // Force r0gdb path for kmem_alloc/kproc_create
    }

    load_r0gdb(&r0gdb);
    if (r0gdb.r0gdb_init_ptr(args->sys_dynlib_dlsym, (int) args->rwpair[0], (int) args->rwpair[1], 0, args->kdata_base_addr))
    {
        notify_send("Failed to start r0gdb, aborting kldload loading...");
        return 1;
    }

    
    if (start_server(PORT, _kldload) <= 0)
    {
        notify_send("Unable to initialize kldload server on port %d! Aborting...", PORT);
        return 1;
    }

    // while (1);
    return 0;
}
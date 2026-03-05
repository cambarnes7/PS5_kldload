/*
 * apic_ops - PS5 Kernel Module: APIC Ops Table Reader
 *
 * Loaded via PS5_kldload (kstuff kekcall or r0gdb).
 * Reads the apic_ops function pointer table from the kernel's RW
 * data segment and prints all entries via kprintf.
 *
 * The apic_ops table is the key data structure for flatz's HV defeat
 * method: overwrite a function pointer (e.g. xapic_mode at slot[2])
 * with a ROP gadget, trigger suspend/resume, and the code executes
 * before the hypervisor restarts.
 *
 * FW 4.03 specific. Uses kprintf for output (visible via UART/klog).
 *
 * Entry: module_start(kproc_args *args)
 */

#include "../include/firmware/offsets.h"

#define MSR_LSTAR    0xC0000082
#define MSR_EFER     0xC0000080
#define MSR_APIC_BASE 0x0000001B

typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;

/* ── Inline assembly helpers ── */

static inline uint64_t __readmsr(uint32_t msr) {
    uint32_t low, high;
    __asm__("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return (low | ((uint64_t)high << 32));
}

static inline uint64_t __readcr0(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline uint64_t __readcr3(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline uint64_t __readcr4(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

/* ── Args from kldload loader ── */

typedef struct __kproc_args {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* ── Kernel function pointers ── */
/* Must be static so -fpie uses direct RIP-relative access (no GOT) */

static void (*kprintf)(char *fmt, ...);
static uint64_t kdata_address;

/* apic_ops slot names (from FreeBSD lapic.c)
 * Use 2D char array instead of pointer array to avoid needing
 * R_X86_64_RELATIVE relocations (flat binary has no dynamic linker) */
static const char apic_op_names[][25] = {
    "create", "init", "xapic_mode", "is_x2apic",
    "setup", "dump", "disable", "eoi",
    "id", "set_id", "ipi_raw", "ipi_vectored",
    "ipi_wait", "ipi_alloc", "ipi_free", "set_lvt_mask",
    "set_lvt_mode", "set_lvt_polarity", "set_lvt_triggermode",
    "lvt_eoi_clear", "set_tpr", "get_timer_freq",
    "timer_enable_intr", "timer_disable_intr", "timer_set_divisor",
    "timer_initial_count", "timer_current_count", "self_ipi",
};

void init_kernel(void) {
    kprintf = (void (*)(char *, ...))((char *)kdata_address + kprintf_offset);
}

int module_start(kproc_args *args) {
    kdata_address = args->kdata_base;
    init_kernel();

    kprintf("\n");
    kprintf("==============================================\n");
    kprintf("  PS5 APIC Ops Reader (kldload module)\n");
    kprintf("  FW: 0x%x  kdata: %#02lx\n", args->fw_ver, kdata_address);
    kprintf("==============================================\n\n");

    /* Read MSRs */
    uint64_t lstar = __readmsr(MSR_LSTAR);
    uint64_t efer = __readmsr(MSR_EFER);
    uint64_t apic_base = __readmsr(MSR_APIC_BASE);
    uint64_t cr0 = __readcr0();
    uint64_t cr3 = __readcr3();
    uint64_t cr4 = __readcr4();

    kprintf("[*] MSR/CR values:\n");
    kprintf("    LSTAR     = %#02lx\n", lstar);
    kprintf("    EFER      = %#02lx\n", efer);
    kprintf("    APIC_BASE = %#02lx\n", apic_base);
    kprintf("    CR0       = %#02lx\n", cr0);
    kprintf("    CR3       = %#02lx\n", cr3);
    kprintf("    CR4       = %#02lx\n", cr4);

    /* Compute ktext base from kdata */
    uint64_t ktext_base = kdata_address - 0xA00000; /* ~10MB delta on FW 4.03 */
    kprintf("    ktext_base (est) = %#02lx\n", ktext_base);

    /* Read apic_ops table */
    uint64_t apic_ops_addr = kdata_address + apic_ops_offset;
    kprintf("\n[*] apic_ops at %#02lx (kdata+0x%x):\n",
            apic_ops_addr, apic_ops_offset);

    volatile uint64_t *ops = (volatile uint64_t *)apic_ops_addr;

    for (int i = 0; i < apic_ops_count; i++) {
        uint64_t ptr = ops[i];
        const char *name = (i < 28) ? apic_op_names[i] : "???";

        /* Check if it's a valid ktext pointer */
        int in_ktext = (ptr >= ktext_base && ptr < ktext_base + 0x2000000);

        kprintf("    [%2d] %-24s  %#02lx  %s  ktext+0x%lx\n",
                i, name, ptr,
                in_ktext ? "[ktext]" : "[????]",
                ptr - ktext_base);
    }

    /* Highlight the key slot for HV defeat */
    kprintf("\n[*] Key slot for APIC-based HV defeat (flatz method):\n");
    kprintf("    xapic_mode (slot[2]) = %#02lx\n", ops[2]);
    kprintf("    This pointer is in RW kernel data at %#02lx\n",
            apic_ops_addr + 2 * 8);
    kprintf("    With KRW: overwrite it -> suspend/resume -> code runs before HV\n");

    /* Note about the confirmed blockers from PROGRESS.md research */
    kprintf("\n[*] Research notes (from hv_research sessions):\n");
    kprintf("    - kdata code execution PANICS during suspend (NPT NX enforced)\n");
    kprintf("    - kmod .text also PANICS during suspend (same NX enforcement)\n");
    kprintf("    - Only ktext is executable during suspend/resume\n");
    kprintf("    - apic_ops[2] value persists across suspend/resume\n");
    kprintf("    - Need ktext ROP gadgets for actual HV defeat\n");

    kprintf("\n[+] APIC ops reader complete.\n");

    return 1;
}

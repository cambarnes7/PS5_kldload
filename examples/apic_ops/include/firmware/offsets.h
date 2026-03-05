/*
 * PS5 FW 4.03 offsets for apic_ops kernel module
 *
 * These offsets are relative to kernel .data base (kdata_base).
 * Negative offsets point into kernel .text (ktext).
 */

#pragma once

/* kprintf: kernel printf for debug output */
#define kprintf_offset -0x972588

/* apic_ops: function pointer table in RW kernel data
 * 28 entries (LAPIC operation function pointers)
 * slot[2] = xapic_mode - key target for flatz HV defeat method */
#define apic_ops_offset 0x170650

/* Number of apic_ops entries (FW 4.03) */
#define apic_ops_count 28

/* IDT base in kernel data */
#define idt_offset 0x64cdc80

/* PCPU array base */
#define pcpu_offset 0x64d2280

/* sysent table (native) */
#define sysents_offset 0x1709c0

/* sysentvec (native) */
#define sysentvec_offset 0xd11bb8

/* allproc: linked list of all processes */
#define allproc_offset 0x27edcb8

/* kernel_pmap_store: kernel page map pointer */
#define kernel_pmap_store_offset 0x3257a78

/* security_flags */
#define security_flags_offset 0x6506474

/* qa_flags */
#define qa_flags_offset 0x6506498

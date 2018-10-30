/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SLAUNCH_H
#define _ASM_X86_SLAUNCH_H

/*
 * Secure Launch main definitions file.
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#define __SL32_CS	0x0008
#define __SL32_DS	0x0010

#define SL_CPU_AMD	1
#define SL_CPU_INTEL	2

#define INTEL_CPUID_MFGID_EBX	0x756e6547 /* Genu */
#define INTEL_CPUID_MFGID_EDX	0x49656e69 /* ineI */
#define INTEL_CPUID_MFGID_ECX	0x6c65746e /* ntel */

#define AMD_CPUID_MFGID_EBX	0x68747541 /* Auth */
#define AMD_CPUID_MFGID_EDX	0x69746e65 /* enti */
#define AMD_CPUID_MFGID_ECX	0x444d4163 /* cAMD */

/*
 * Intel Safer Mode Extensions (SMX)
 *
 * Intel SMX provides a programming interface to establish a Measured Launched
 * Environment (MLE). The measurement and protection mechanisms supported by the
 * capabilities of an Intel Trusted Execution Technology (TXT) platform. SMX is
 * the processor’s programming interface in an Intel TXT platform.
 *
 * See Intel SDM Volume 2 - 6.1 "Safer Mode Extensions Reference"
 */

/*
 * SMX GETSEC Leaf Functions
 */
#define SMX_X86_GETSEC_SMCTRL	7
#define SMX_X86_GETSEC_WAKEUP	8

/*
 * Intel Trusted Execution Technology MMIO Registers Banks
 */
#define TXT_PUB_CONFIG_REGS_BASE	0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000
#define TXT_NR_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE - \
				  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

/*
 * Intel Trusted Execution Technology (TXT) Registers
 */
#define TXTCR_STS			0x0000
#define TXTCR_ESTS			0x0008
#define TXTCR_ERRORCODE			0x0030
#define TXTCR_CMD_RESET			0x0038
#define TXTCR_DIDVID			0x0110
#define TXTCR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXTCR_SINIT_BASE		0x0270
#define TXTCR_SINIT_SIZE		0x0278
#define TXTCR_MLE_JOIN			0x0290
#define TXTCR_HEAP_BASE			0x0300
#define TXTCR_HEAP_SIZE			0x0308
#define TXTCR_CMD_OPEN_LOCALITY1	0x0380
#define TXTCR_CMD_CLOSE_LOCALITY1	0x0388
#define TXTCR_CMD_OPEN_LOCALITY2	0x0390
#define TXTCR_CMD_CLOSE_LOCALITY2	0x0398
#define TXTCR_CMD_SECRETS		0x08e0
#define TXTCR_CMD_NO_SECRETS		0x08e8
#define TXTCR_E2STS			0x08f0

/* TXTCR_STS status bits */
#define TXT_SENTER_DONE_STS		(1<<0)
#define TXT_SEXIT_DONE_STS		(1<<1)

/*
 * SINIT/MLE Capabilities Field Bit Definitions
 */
#define TXT_SINIT_MLE_CAP_WAKE_GETSEC	0
#define TXT_SINIT_MLE_CAP_WAKE_MONITOR	1

/*
 * OS/MLE Secure Launch Specific Definitions
 */
#define TXT_MAX_EVENT_LOG_SIZE		(5*4*1024)   /* 4k*5 */
#define TXT_MAX_VARIABLE_MTRRS		32
#define TXT_OS_MLE_STRUCT_VERSION	1

/*
 * TXT Heap BIOS Table Field Offsets
 */
#define TXT_BIOS_NUM_LOG_PROCS		0x18

/*
 * TXT Heap OS/SINIT Table Field Offsets
 */
#define TXT_OS_SINIT_LO_PMR_BASE	0x20
#define TXT_OS_SINIT_LO_PMR_SIZE	0x28
#define TXT_OS_SINIT_HI_PMR_BASE	0x30
#define TXT_OS_SINIT_HI_PMR_SIZE	0x38
#define TXT_OS_SINIT_CAPABILITIES	0x50

/*
 * TXT Heap SINIT/MLE Table Field Offsets
 */
#define TXT_SINIT_MLE_RLP_WAKEUP_ADDR	0x78
#define TXT_SINIT_MLE_NUMBER_MDRS	0x80
#define TXT_SINIT_MLE_MDRS_OFFSET	0x84
#define TXT_SINIT_MLE_DMAR_TABLE_SIZE	0x88
#define TXT_SINIT_MLE_DMAR_TABLE_OFFSET	0x8c

/*
 * TXT Heap Table Enumeration
 */
#define TXT_BIOS_DATA_TABLE		1
#define TXT_OS_MLE_DATA_TABLE		2
#define TXT_OS_SINIT_DATA_TABLE		3
#define TXT_SINIT_MLE_DATA_TABLE	4

/*
 * Secure Launch Defined Error Codes
 * Used in MLE-initiated TXT resets
 */
#define TXT_SLERROR_GENERIC		0xc0008001
#define TXT_SLERROR_TPM_INIT		0xc0008002
#define TXT_SLERROR_TPM_GET_LOC		0xc0008003
#define TXT_SLERROR_TPM_EXTEND		0xc0008004
#define TXT_SLERROR_MTRR_INV_VCNT	0xc0008005
#define TXT_SLERROR_MTRR_INV_DEF_TYPE	0xc0008006
#define TXT_SLERROR_MTRR_INV_BASE	0xc0008007
#define TXT_SLERROR_MTRR_INV_MASK	0xc0008008
#define TXT_SLERROR_MSR_INV_MISC_EN	0xc0008009
#define TXT_SLERROR_INV_AP_INTERRUPT	0xc000800a
#define TXT_SLERROR_RESERVE_AP_WAKE	0xc000800b
#define TXT_SLERROR_HEAP_WALK		0xc000800c
#define TXT_SLERROR_HEAP_MAP		0xc000800d
#define TXT_SLERROR_HEAP_MDR_VALS	0xc000800e
#define TXT_SLERROR_HEAP_MDRS_MAP	0xc000800f
#define TXT_SLERROR_HEAP_DMAR_VALS	0xc0008010
#define TXT_SLERROR_HEAP_INVALID_DMAR	0xc0008011
#define TXT_SLERROR_HEAP_DMAR_SIZE	0xc0008012
#define TXT_SLERROR_HEAP_DMAR_MAP	0xc0008013
#define TXT_SLERROR_PMR_VALS		0xc0008014
#define TXT_SLERROR_HI_PMR_BASE		0xc0008015
#define TXT_SLERROR_HI_PMR_SIZE		0xc0008016
#define TXT_SLERROR_LO_PMR_BASE		0xc0008017
#define TXT_SLERROR_LO_PMR_MLE		0xc0008018
#define TXT_SLERROR_HEAP_ZERO_OFFSET	0xc0008019
#define TXT_SLERROR_AP_WAKE_BLOCK_VAL	0xc000801a

/*
 * Secure Launch Defined Limits
 */
#define TXT_MAX_CPUS			512
#define TXT_BOOT_STACK_SIZE		24

/*
 * TODO this will change when patch 0001 changes
 */
#define SLAUNCH_INFO_OFFSET	0x268

/*
 * Measured Launch PCRs
 */
#define SL_IMAGE_PCR17		17
#define SL_CONFIG_PCR18		18

/*
 * Secure Launch Defined Flags
 */
#define SL_FLAG_ACTIVE		0x00000001
#define SL_FLAG_ARCH_SKINIT	0x00000002
#define SL_FLAG_ARCH_TXT	0x00000004

#ifndef __ASSEMBLY__

/*
 * TXT data structure used by a responsive local processor (RLP) to start
 * execution in response to a GETSEC[WAKEUP].
 */
struct txt_mle_join {
	u32	ap_gdt_limit;
	u32	ap_gdt_base;
	u32	ap_seg_sel;	/* cs (ds, es, ss are seg_sel+8) */
	u32	ap_entry_point;	/* phys addr */
} __packed;

/*
 * Secure Launch defined MTRR saving structures
 */
struct txt_mtrr_pair {
	u64	mtrr_physbase;
	u64	mtrr_physmask;
} __packed;

struct txt_mtrr_state {
	u64	default_type_reg;
	u64	mtrr_vcnt;
	struct txt_mtrr_pair mtrr_pair[TXT_MAX_VARIABLE_MTRRS];
} __packed;

/*
 * Secure Launch defined OS/MLE TXT Heap table
 */
struct txt_os_mle_data {
	u32	version;
	u32	zero_page_addr;
	u8	msb_key_hash[20];
	u64	saved_misc_enable_msr;
	struct	txt_mtrr_state saved_bsp_mtrrs;
	u64	lo_pmr_min;
	u64	ap_wake_ebp;
	u64	ap_wake_block;
	u8	event_log_buffer[TXT_MAX_EVENT_LOG_SIZE];
} __packed;

/*
 * TXT data reporting structure for memory types
 */
struct txt_memory_descriptor_record {
	u64	address;
	u64	length;
	u8	type;
	u8	reserved[7];
} __packed;

#include <asm/io.h>

/*
 * Functions to extract data from the Intel TXT Heap Memory
 */
static inline u64 txt_bios_data_size(void __iomem *heap)
{
	u64 val;

	memcpy_fromio(&val, heap, sizeof(u64));
	return val;
}

static inline void __iomem *txt_bios_data_start(void __iomem *heap)
{
	return heap + sizeof(u64);
}

static inline u64 txt_os_mle_data_size(void __iomem *heap)
{
	u64 val;

	memcpy_fromio(&val, heap + txt_bios_data_size(heap), sizeof(u64));
	return val;
}

static inline void __iomem *txt_os_mle_data_start(void __iomem *heap)
{
	return heap + txt_bios_data_size(heap) + sizeof(u64);
}

static inline u64 txt_os_sinit_data_size(void __iomem *heap)
{
	u64 val;

	memcpy_fromio(&val, heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap), sizeof(u64));
	return val;
}

static inline void __iomem *txt_os_sinit_data_start(void __iomem *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) + sizeof(u64);
}

static inline u64 txt_sinit_mle_data_size(void __iomem *heap)
{
	u64 val;

	memcpy_fromio(&val, heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap) +
			txt_os_sinit_data_size(heap), sizeof(u64));
	return val;
}

static inline void __iomem *txt_sinit_mle_data_start(void __iomem *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) +
		txt_sinit_mle_data_size(heap) + sizeof(u64);
}

/*
 * External functions
 */
void slaunch_setup(void);
u32 slaunch_get_flags(void);
u32 slaunch_get_ap_wake_block(void);
struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar);

#endif

#endif /* _ASM_X86_SLAUNCH_H */

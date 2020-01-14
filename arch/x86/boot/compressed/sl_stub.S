/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */
	.code32
	.text
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/irq_vectors.h>
#include <linux/slaunch.h>

/* Can't include apiddef.h in asm */
#define XAPIC_ENABLE	(1 << 11)
#define X2APIC_ENABLE	(1 << 10)

/* Can't include traps.h in asm */
#define X86_TRAP_NMI	2

/* Can't include mtrr.h in asm */
#define MTRRphysBase0	0x200

#define IDT_VECTOR_LO_BITS	0
#define IDT_VECTOR_HI_BITS	6

.macro GETSEC leaf
	xorl	%ebx, %ebx
	movl	\leaf, %eax	/* Leaf function */
	.byte 	0x0f, 0x37	/* GETSEC opcode */
.endm

	/*
	 * The MLE Header per the TXT Specification, section 2.1
	 * MLE capabilities, see table 2.
	 */
GLOBAL(mle_header)
	.long	0x9082ac5a    /* UUID0 */
	.long	0x74a7476f    /* UUID1 */
	.long	0xa2555c0f    /* UUID2 */
	.long	0x42b651cb    /* UUID3 */
	.long	0x00000034    /* MLE header size */
	.long	0x00020002    /* MLE version 2.2 */
	.long	sl_stub_entry /* Linear entry point of MLE (virt. address) */
	.long	0x00000000    /* First valid page of MLE */
	.long	0x00000000    /* Offset within binary of first byte of MLE */
	.long	0x00000000    /* Offset within binary of last byte + 1 of MLE */
	.long	0x00000223    /* Bit vector of MLE-supported capabilities */
	.long	0x00000000    /* Starting linear address of command line */
	.long	0x00000000    /* Ending linear address of command line */

	.code32
ENTRY(sl_stub)
	/*
	 * On entry, %ebp has the base address from head_64.S
	 * and only %cs is known good
	 */
	cli
	cld

	/*
	 * Take the first stack for the BSP. The AP stacks are only used
	 * on Intel.
	 */
	leal	sl_stacks_end(%ebp), %esp

	/* Load GDT, set segment regs and lret to __SL32_CS */
	addl	%ebp, (sl_gdt_desc + 2)(%ebp)
	lgdt	sl_gdt_desc(%ebp)

	movl	$(__SL32_DS), %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	leal	.Lsl_cs(%ebp), %eax
	pushl	$(__SL32_CS)
	pushl	%eax
	lret

.Lsl_cs:
	/* Assume unknown CPU start */
	xorl	%edi, %edi

	/* Now see if it is GenuineIntel. CPUID 0 returns the manufacturer */
	xorl	%eax, %eax
	cpuid
	cmpl	$(INTEL_CPUID_MFGID_EBX), %ebx
	jnz	.Ldo_unkown_cpu
	cmpl	$(INTEL_CPUID_MFGID_EDX), %edx
	jnz	.Ldo_unkown_cpu
	cmpl	$(INTEL_CPUID_MFGID_ECX), %ecx
	jnz	.Ldo_unkown_cpu
	movl	$(SL_CPU_INTEL), %edi

	/* Know it is Intel */
	movl	$(SL_CPU_INTEL), sl_cpu_type(%ebp)

	/* Increment CPU count for BSP */
	incl	sl_txt_cpu_count(%ebp)

	/* Enable SMI with GETSEC[SMCTRL] */
	GETSEC	$(SMX_X86_GETSEC_SMCTRL)

	/* IRET-to-self can be used to enable NMIs which SENTER disabled */
	leal	.Lnmi_enabled(%ebp), %eax
	pushfl
	pushl	$(__SL32_CS)
	pushl	%eax
	iret

.Lnmi_enabled:
	/* Clear the TXT error registers for a clean start of day */
	movl	$0, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ERRORCODE)
	movl	$0xffffffff, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ESTS)

	/* On Intel, the zero page address is passed in the TXT heap */
	/* Read physical base of heap into EAX */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* Read the size of the BIOS data into ECX (first 8 bytes) */
	movl	(%eax), %ecx
	/* Skip over BIOS data and size of OS to MLE data section */
	leal	8(%eax, %ecx), %eax

	/* Get the zero page address from the heap.
	 *
	 * Note %esi and %ebp MUST be preserved across calls and
	 * operations.
	 */
	movl	SL_zero_page_addr(%eax), %esi

	/* Save ebp so the APs can find their way home */
	movl	%ebp, (SL_mle_scratch + SL_SCRATCH_AP_EBP)(%eax)

	/* Fetch the AP wake code block address from the heap */
	movl	SL_ap_wake_block(%eax), %edi
	movl	%edi, sl_txt_ap_wake_block(%ebp)

	/* Store the offset in the AP wake block to the jmp address */
	movl	$(sl_ap_jmp_offset - sl_txt_ap_wake_begin), \
		(SL_mle_scratch + SL_SCRATCH_AP_JMP_OFFSET)(%eax)

	/* %eax still is the base of the OS-MLE block, save it */
	pushl	%eax

	/* Relocate the AP wake code to the safe block */
	pushl	%esi
	call	sl_txt_reloc_ap_wake
	popl	%esi

	/*
	 * Wake up all APs and wait for them to halt. This should be done
	 * before restoring the MTRRs so the ACM is still properly in WB
	 * memory.
	 */
	call	sl_txt_wake_aps

	/* Pop OS-MLE base address for call to load MTRRs/MISC MSR */
	popl	%edi
	call	sl_txt_load_regs

	jmp	.Lcpu_setup_done

.Ldo_unkown_cpu:
	/* AMD is not yet supported */
	ud2

	/* On AMD %esi is set up by the Landing Zone, just go on */

.Lcpu_setup_done:
	/*
	 * Don't enable MCE at this point. The kernel will enable
	 * it on the BSP later when it is ready.
	 */

	/* Keep SL segments for the early portion of the kernel boot */
	orb	$(KEEP_SEGMENTS), BP_loadflags(%esi)

	/* Done, jump to normal 32b pm entry */
	jmp	startup_32
ENDPROC(sl_stub)

ENTRY(sl_txt_ap_entry)
	cli
	cld

	/*
	 * The code segment is known good. The data segments are
	 * fine too so we can get to our stack before loading the
	 * GDT.
	 *
	 * First order of business is to find where we are and
	 * save it in ebp.
	 */

	/* Read physical base of heap into EAX */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* Read the size of the BIOS data into ECX (first 8 bytes) */
	movl	(%eax), %ecx
	/* Skip over BIOS data and size of OS to MLE data section */
	leal	8(%eax, %ecx), %eax

	/* Saved ebp from the BSP and stash OS-MLE pointer */
	movl	(SL_mle_scratch + SL_SCRATCH_AP_EBP)(%eax), %ebp
	movl	%eax, %edi

	/* Lock and get our stack index */
	movl	$1, %ecx
.Lspin:
	xorl	%eax, %eax
	lock cmpxchgl	%ecx, sl_txt_spin_lock(%ebp)
	jnz	.Lspin

	/* Increment the stack index and use the next value inside lock */
	incl	sl_txt_stack_index(%ebp)
	movl	sl_txt_stack_index(%ebp), %eax

	/* Unlock */
	movl	$0, sl_txt_spin_lock(%ebp)

	/* Load our AP stack */
	movl	$(TXT_BOOT_STACK_SIZE), %edx
	mull	%edx
	leal	sl_stacks_end(%ebp), %esp
	subl	%eax, %esp

	/* Load reloc GDT, set segment regs and lret to __SL32_CS */
	movl	sl_txt_ap_wake_block(%ebp), %eax
	lgdt	(sl_ap_gdt_desc - sl_txt_ap_wake_begin)(%eax)

	movl	$(__SL32_DS), %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	leal	.Lsl_ap_cs(%ebp), %eax
	pushl	$(__SL32_CS)
	pushl	%eax
	lret

.Lsl_ap_cs:
	/* Load the relocated AP IDT */
	movl	sl_txt_ap_wake_block(%ebp), %eax
	lidt	(sl_ap_idt_desc - sl_txt_ap_wake_begin)(%eax)

	/* Fixup MTRRs and misc enable MSR on APs too */
	call	sl_txt_load_regs

	/* Enable SMI with GETSEC[SMCTRL] */
	GETSEC $(SMX_X86_GETSEC_SMCTRL)

	/* IRET-to-self can be used to enable NMIs which SENTER disabled */
	leal	.Lnmi_enabled_ap(%ebp), %eax
	pushfl
	pushl	$(__SL32_CS)
	pushl	%eax
	iret

.Lnmi_enabled_ap:
	/* Put APs in X2APIC mode like the BSP */
	movl	$(MSR_IA32_APICBASE), %ecx
	rdmsr
	orl	$(XAPIC_ENABLE | X2APIC_ENABLE), %eax
	wrmsr

	/*
	 * Basically done, increment the CPU count and jump off to the AP
	 * wake block to wait.
	 */
	lock incl	sl_txt_cpu_count(%ebp)

	movl	sl_txt_ap_wake_block(%ebp), %eax
	jmp	*%eax
ENDPROC(sl_txt_ap_entry)

ENTRY(sl_txt_reloc_ap_wake)
	movl	sl_txt_ap_wake_block(%ebp), %edi

	/* Fixup AP IDT and GDT descriptor before relocating */
	addl	%edi, (sl_ap_idt_desc + 2)(%ebp)
	addl	%edi, (sl_ap_gdt_desc + 2)(%ebp)

	/*
	 * Copy the AP wake code and AP GDT/IDT to the protected wake block
	 * provided by the loader. Destination already in %edi.
	 */
	movl	$(sl_txt_ap_wake_end - sl_txt_ap_wake_begin), %ecx
	leal	sl_txt_ap_wake_begin(%ebp), %esi
	rep movsb

	/* Setup the IDT for the APs to use in the relocation block */
	movl	sl_txt_ap_wake_block(%ebp), %ecx
	addl	$(sl_ap_idt - sl_txt_ap_wake_begin), %ecx
	xorl	%edx, %edx

	/* Form the default reset vector relocation address */
	movl	sl_txt_ap_wake_block(%ebp), %ebx
	addl	$(sl_txt_int_reset - sl_txt_ap_wake_begin), %ebx

1:
	cmpw	$(NR_VECTORS), %dx
	jz	.Lap_idt_done

	cmpw	$(X86_TRAP_NMI), %dx
	jz	2f

	/* Load all other fixed vectors with reset handler */
	movl	%ebx, %eax
	movw	%ax, (IDT_VECTOR_LO_BITS)(%ecx)
	shrl	$16, %eax
	movw	%ax, (IDT_VECTOR_HI_BITS)(%ecx)
	jmp	3f

2:
	/* Load single wake NMI IPI vector at the relocation address */
	movl	sl_txt_ap_wake_block(%ebp), %eax
	addl	$(sl_txt_int_ipi_wake - sl_txt_ap_wake_begin), %eax
	movw	%ax, (IDT_VECTOR_LO_BITS)(%ecx)
	shrl	$16, %eax
	movw	%ax, (IDT_VECTOR_HI_BITS)(%ecx)

3:
	incw	%dx
	addl	$8, %ecx
	jmp	1b

.Lap_idt_done:
	ret

ENDPROC(sl_txt_reloc_ap_wake)

ENTRY(sl_txt_load_regs)
	/*
	 * On Intel, the original variable MTRRs and Misc Enable MSR are
	 * restored on the BSP at early boot. Each AP will also restore
	 * its MTRRs and Misc Enable MSR.
	 */
	pushl	%edi
	addl	$(SL_saved_bsp_mtrrs), %edi
	movl	(%edi), %ebx
	pushl	%ebx /* default_mem_type lo */
	addl	$4, %edi
	movl	(%edi), %ebx
	pushl	%ebx /* default_mem_type hi */
	addl	$4, %edi
	movl	(%edi), %ebx /* mtrr_vcnt lo, don't care about hi part */
	addl	$8, %edi /* now at MTRR pair array */
	/* Write the variable MTRRs */
	movl	$(MTRRphysBase0), %ecx
1:
	cmpl	$0, %ebx
	jz	2f

	movl	(%edi), %eax /* MTRRphysBaseX lo */
	addl	$4, %edi
	movl	(%edi), %edx /* MTRRphysBaseX hi */
	wrmsr
	addl	$4, %edi
	incl	%ecx
	movl	(%edi), %eax /* MTRRphysMaskX lo */
	addl	$4, %edi
	movl	(%edi), %edx /* MTRRphysMaskX hi */
	wrmsr
	addl	$4, %edi
	incl	%ecx

	decl	%ebx
	jmp	1b
2:
	/* Write the default MTRR register */
	popl	%edx
	popl	%eax
	movl	$(MSR_MTRRdefType), %ecx
	wrmsr

	/* Return to beginning and write the misc enable msr */
	popl	%edi
	addl	$(SL_saved_misc_enable_msr), %edi
	movl	(%edi), %eax /* saved_misc_enable_msr lo */
	addl	$4, %edi
	movl	(%edi), %edx /* saved_misc_enable_msr hi */
	movl	$(MSR_IA32_MISC_ENABLE), %ecx
	wrmsr

	ret
ENDPROC(sl_txt_load_regs)

ENTRY(sl_txt_wake_aps)
	/* First setup the MLE join structure and load it into TXT reg */
	leal	sl_gdt(%ebp), %eax
	leal	sl_txt_ap_entry(%ebp), %ecx
	leal	sl_smx_rlp_mle_join(%ebp), %edx
	movl	%eax, SL_rlp_gdt_base(%edx)
	movl	%ecx, SL_rlp_entry_point(%edx)
	movl	%edx, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_MLE_JOIN)

	/* Another TXT heap walk to find various values needed to wake APs */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* At BIOS data size, find the number of logical processors */
	movl	(SL_num_logical_procs + 8)(%eax), %edx
	/* Skip over BIOS data */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* Skip over OS to MLE */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* At OS-SNIT size, get capabilities to know how to wake up the APs */
	movl	(SL_capabilities + 8)(%eax), %ebx
	/* Skip over OS to SNIT */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* At SNIT-MLE size, get the AP wake MONITOR address */
	movl	(SL_rlp_wakeup_addr + 8)(%eax), %edi

	/* Determine how to wake up the APs */
	testl	$(1 << TXT_SINIT_MLE_CAP_WAKE_MONITOR), %ebx
	jz	.Lwake_getsec

	/* Wake using MWAIT MONITOR */
	movl	$1, (%edi)
	jmp	.Laps_awake

.Lwake_getsec:
	/* Wake using GETSEC(WAKEUP) */
	GETSEC	$(SMX_X86_GETSEC_WAKEUP)

.Laps_awake:
	/*
	 * All of the APs are woken up and rendesvous in the relocated wake
	 * block starting at sl_txt_ap_wake_begin. Wait for all of them to
	 * halt.
	 */
1:
	pause
	cmpl	sl_txt_cpu_count(%ebp), %edx
	jne	1b

	ret
ENDPROC(sl_txt_wake_aps)

/* This is the beginning of the relocated AP wake code block */
ENTRY(sl_txt_ap_wake_begin)
	/*
	 * Wait for NMI IPI in the relocated AP wake block which was provided
	 * and protected in the memory map by the prelaunch code. Leave all
	 * other interrupts masked since we do not expect anything but an NMI.
	 */
	xorl	%ebx, %ebx

1:
	hlt
	testl	%ebx, %ebx
	jz	1b

	/*
	 * This is the long absolute jump to the 32b Secure Launch protected
	 * mode stub code in the rmpiggy. The jump address will be fixed in
	 * the SMP boot code when the first AP is brought up. This whole area
	 * is provided and protected in the memory map by the prelaunch code.
	 */
	.byte	0xea
sl_ap_jmp_offset:
	.long	0x00000000
	.word	__SL32_CS
ENDPROC(sl_txt_ap_wake_begin)

ENTRY(sl_txt_int_ipi_wake)
	movl	$1, %ebx

	/* NMI context, just IRET */
	iret
ENDPROC(sl_txt_int_ipi_wake)

ENTRY(sl_txt_int_reset)
	/* Set a sticky error value and reset */
	movl	$(SL_ERROR_INV_AP_INTERRUPT), (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ERRORCODE)
	/* The movs to %eax act as TXT register barriers */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_E2STS), %eax
	movl	$1, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_CMD_UNLOCK_MEM_CONFIG)
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_E2STS), %eax
	movl	$1, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_CMD_RESET)
	hlt
ENDPROC(sl_txt_int_reset)

	.balign 16
sl_ap_idt_desc:
	.word	sl_ap_idt_end - sl_ap_idt - 1		/* Limit */
	.long	sl_ap_idt - sl_txt_ap_wake_begin	/* Base */
sl_ap_idt_desc_end:

	.balign 16
sl_ap_idt:
	.rept	NR_VECTORS
	.word	0x0000		/* Offset 15 to 0 */
	.word	__SL32_CS	/* Segment selector */
	.word	0x8e00		/* Present, DPL=0, 32b Vector, Interrupt */
	.word	0x0000		/* Offset 31 to 16 */
	.endr
sl_ap_idt_end:

	.balign 16
sl_ap_gdt_desc:
	.word	sl_ap_gdt_end - sl_ap_gdt - 1
	.long	sl_ap_gdt - sl_txt_ap_wake_begin
sl_ap_gdt_desc_end:

	.balign	16
sl_ap_gdt:
	.quad	0x0000000000000000	/* NULL */
	.quad	0x00cf9a000000ffff	/* __SL32_CS */
	.quad	0x00cf92000000ffff	/* __SL32_DS */
sl_ap_gdt_end:
GLOBAL(sl_txt_ap_wake_end)

	.data
	.balign 16
sl_gdt_desc:
	.word	sl_gdt_end - sl_gdt - 1
	.long	sl_gdt
sl_gdt_desc_end:

	.balign	16
sl_gdt:
	.quad	0x0000000000000000	/* NULL */
	.quad	0x00cf9a000000ffff	/* __SL32_CS */
	.quad	0x00cf92000000ffff	/* __SL32_DS */
sl_gdt_end:

	.balign 16
sl_smx_rlp_mle_join:
	.long	sl_gdt_end - sl_gdt - 1	/* GDT limit */
	.long	0x00000000		/* GDT base */
	.long	__SL32_CS	/* Seg Sel - CS (DS, ES, SS = seg_sel+8) */
	.long	0x00000000	/* Entry point physical address */

GLOBAL(sl_cpu_type)
	.long	0x00000000

sl_txt_spin_lock:
	.long	0x00000000

sl_txt_stack_index:
	.long	0x00000000

sl_txt_cpu_count:
	.long	0x00000000

sl_txt_ap_wake_block:
	.long	0x00000000

	/* Small stacks for BSP and APs to work with */
	.balign 4
sl_stacks:
	.fill (TXT_MAX_CPUS * TXT_BOOT_STACK_SIZE), 1, 0
sl_stacks_end:

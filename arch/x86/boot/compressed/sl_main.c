// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/efi.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/tpm.h>
#include <asm/bootparam.h>
#include <asm/efi.h>
#include <asm/slaunch.h>
#ifdef CONFIG_SECURE_LAUNCH_SHA256
#include <linux/sha256.h>
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
#include <linux/sha512.h>
#endif

#include "early_sha1.h"

extern u32 sl_cpu_type;

static u64 sl_txt_read(u32 reg)
{
	void *addr = (void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg);
	u64 val;

	barrier();
	val = *(u64 *)(addr);
	/* Memory barrier for MMIO read as done in readb() */
	rmb();

	return val;
}

static void sl_txt_write(u32 reg, u64 val)
{
	void *addr = (void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg);

	barrier();
	*(u64 *)(addr) = val;
	/* Memory barrier for MMIO read as done in readb() */
	wmb();
	barrier();
}

static void sl_txt_reset(u64 error)
{
	/* Reading the E2STS register acts as a barrier for TXT registers */
	sl_txt_write(TXTCR_ERRORCODE, error);
	sl_txt_read(TXTCR_E2STS);
	sl_txt_write(TXTCR_CMD_UNLOCK_MEM_CONFIG, 1);
	sl_txt_read(TXTCR_E2STS);
	sl_txt_write(TXTCR_CMD_RESET, 1);
	for ( ; ; )
		__asm__ __volatile__ ("pause");
}

static u64 sl_rdmsr(u32 reg)
{
	u64 lo, hi;

	__asm__ __volatile__ ("rdmsr"  : "=a" (lo), "=d" (hi) : "c" (reg));

	return (hi << 32) | lo;
}

static void sl_txt_validate_msrs(struct txt_os_mle_data *os_mle_data)
{
#define CAPS_VARIABLE_MTRR_COUNT_MASK   0xff
	u64 mtrr_caps, mtrr_def_type, mtrr_var, misc_en_msr;
	u32 vcnt, i;
	struct txt_mtrr_state *saved_bsp_mtrrs =
		&(os_mle_data->saved_bsp_mtrrs);

	mtrr_caps = sl_rdmsr(MSR_MTRRcap);
	vcnt = (u32)(mtrr_caps & CAPS_VARIABLE_MTRR_COUNT_MASK);

	if (saved_bsp_mtrrs->mtrr_vcnt > vcnt)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_VCNT);
	if (saved_bsp_mtrrs->mtrr_vcnt > TXT_MAX_VARIABLE_MTRRS)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_VCNT);

	mtrr_def_type = sl_rdmsr(MSR_MTRRdefType);
	if (saved_bsp_mtrrs->default_mem_type != mtrr_def_type)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_DEF_TYPE);

	for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; i++) {
		mtrr_var = sl_rdmsr(MTRRphysBase_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase != mtrr_var)
			sl_txt_reset(TXT_SLERROR_MTRR_INV_BASE);
		mtrr_var = sl_rdmsr(MTRRphysMask_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask != mtrr_var)
			sl_txt_reset(TXT_SLERROR_MTRR_INV_MASK);
	}

	misc_en_msr = sl_rdmsr(MSR_IA32_MISC_ENABLE);
	if (os_mle_data->saved_misc_enable_msr != misc_en_msr)
		sl_txt_reset(TXT_SLERROR_MSR_INV_MISC_EN);
}

void sl_tpm_extend_pcr(struct tpm *tpm, u32 pcr, const u8 *data, u32 len)
{
	struct sha1_state sctx = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE];
	int ret;

	if (tpm->family == TPM20) {
#ifdef CONFIG_SECURE_LAUNCH_SHA256
		struct sha256_state sctx = {0};
		u8 sha256_hash[SHA256_DIGEST_SIZE];

		memset(&sha256_hash[0], 0, SHA256_DIGEST_SIZE);
		sha256_init(&sctx);
		sha256_update(&sctx, data, len);
		sha256_final(&sctx, &sha256_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_HASH_ALG_SHA256, &sha256_hash[0]);
		if (!ret)
			return;
		else
			sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
		struct sha512_state sctx = {0};
		u8 sha512_hash[SHA512_DIGEST_SIZE];

		memset(&sha512_hash[0], 0, SHA512_DIGEST_SIZE);
		sha512_init(&sctx);
		sha512_update(&sctx, data, len);
		sha512_final(&sctx, &sha512_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_HASH_ALG_SHA512, &sha512_hash[0]);
		if (!ret)
			return;
		else
			sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
#endif
	}

	memset(&sha1_hash[0], 0, SHA1_DIGEST_SIZE);
	early_sha1_init(&sctx);
	early_sha1_update(&sctx, data, len);
	early_sha1_final(&sctx, &sha1_hash[0]);
	ret = tpm_extend_pcr(tpm, pcr, TPM_HASH_ALG_SHA1, &sha1_hash[0]);
out:
	if (ret)
		sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
}

void sl_main(u8 *bootparams)
{
	struct tpm *tpm;
	struct boot_params *bp;
	struct setup_data *data;
	struct txt_os_mle_data *os_mle_data;
	const char *signature;
	unsigned long mmap = 0;
	u64 *txt_heap;
	u64 bios_data_size;
	u32 data_count;
	u32 os_mle_len;

	/*
	 * Currently only Intel TXT is supported for Secure Launch. Testing this value
	 * also indicates that the kernel was booted successfully through the Secure
	 * Launch entry point and is in SMX mode.
	 */
	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	/*
	 * If enable_tpm fails there is no point going on. The entire secure
	 * environment depends on this and the other TPM operations succeeding.
	 */
	tpm = enable_tpm();
	if (!tpm)
		sl_txt_reset(TXT_SLERROR_TPM_INIT);

	if (tpm_request_locality(tpm, 2) == TPM_NO_LOCALITY)
		sl_txt_reset(TXT_SLERROR_TPM_GET_LOC);

	/* Measure the zero page/boot params */
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, bootparams, PAGE_SIZE);

	/* Now safe to use boot params */
	bp = (struct boot_params *)bootparams;

	/* Measure the command line */
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18,
			  (u8 *)((unsigned long)bp->hdr.cmd_line_ptr),
			  bp->hdr.cmdline_size);

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)bp->hdr.setup_data;
	while (data) {
		sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18,
				  ((u8 *)data) + sizeof(struct setup_data),
				  data->len);

		data = (struct setup_data *)(unsigned long)data->next;
	}

	/* If bootloader was EFI, measure the memory map passed across */
	signature =
		(const char *)(unsigned long)bp->efi_info.efi_loader_signature;

	if (!strncmp(signature, EFI32_LOADER_SIGNATURE, 4))
		mmap =  bp->efi_info.efi_memmap;
	else if (!strncmp(signature, EFI64_LOADER_SIGNATURE, 4))
		mmap = (bp->efi_info.efi_memmap |
			((u64)bp->efi_info.efi_memmap_hi << 32));

	if (mmap)
		sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, (void *)mmap,
				  bp->efi_info.efi_memmap_size);

	/* Measure any external initrd */
	if (bp->hdr.ramdisk_image != 0 && bp->hdr.ramdisk_size != 0)
		sl_tpm_extend_pcr(tpm, SL_IMAGE_PCR17,
				  (u8 *)((u64)bp->hdr.ramdisk_image),
				  bp->hdr.ramdisk_size);
	/*
	 * Some extra work to do on Intel, have to measure the OS-MLE
	 * heap area.
	 */
	txt_heap = (void *)sl_txt_read(TXTCR_HEAP_BASE);
	bios_data_size = *txt_heap;
	os_mle_data = (struct txt_os_mle_data *)
			((u8 *)txt_heap + bios_data_size + sizeof(u64));

	/*
	 * Don't want to measure the value of the ap_wake_ebp field,
	 * it only used by sl_stub
	 */
	os_mle_data->ap_wake_ebp = 0;

	/* Measure OS-MLE data up to the TPM log into 18 */
	os_mle_len = offsetof(struct txt_os_mle_data, event_log_buffer);
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, (u8 *)os_mle_data, os_mle_len);

	/*
	 * Now that the OS-MLE data is measured, ensure the MTRR and
	 * misc enable MSRs are what we expect.
	 */
	sl_txt_validate_msrs(os_mle_data);

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);
}

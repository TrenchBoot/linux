// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <linux/efi.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/efi.h>
#include <linux/slaunch.h>
#ifdef CONFIG_SECURE_LAUNCH_SHA256
#include <linux/sha256.h>
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
#include <linux/sha512.h>
#endif

#include "early_sha1.h"
#include "tpm/tpm_common.h"
#include "tpm/tpm2_constants.h"
#include "tpm/tpm.h"

#define SL_MAX_EVENT_DATA	64
#define SL_TPM12_LOG_SIZE	(sizeof(struct tpm12_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM20_LOG_SIZE	(sizeof(struct tpm20_ha) + \
				SHA512_SIZE + \
				sizeof(struct tpm20_digest_values) + \
				sizeof(struct tpm20_pcr_event_head) + \
				sizeof(struct tpm20_pcr_event_tail) + \
				SL_MAX_EVENT_DATA)

static void *evtlog_base;
static struct txt_heap_event_log_pointer2_1_element *log20_elem;

extern u32 sl_cpu_type;

static u64 sl_txt_read(u32 reg)
{
	return readq((void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void sl_txt_write(u32 reg, u64 val)
{
	writeq(val, (void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void sl_txt_reset(u64 error)
{
	/* Reading the E2STS register acts as a barrier for TXT registers */
	sl_txt_write(TXT_CR_ERRORCODE, error);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_UNLOCK_MEM_CONFIG, 1);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_RESET, 1);
	asm volatile ("hlt");
}

static u64 sl_rdmsr(u32 reg)
{
	u64 lo, hi;

	asm volatile ("rdmsr"  : "=a" (lo), "=d" (hi) : "c" (reg));

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
		sl_txt_reset(SL_ERROR_MTRR_INV_VCNT);
	if (saved_bsp_mtrrs->mtrr_vcnt > TXT_MAX_VARIABLE_MTRRS)
		sl_txt_reset(SL_ERROR_MTRR_INV_VCNT);

	mtrr_def_type = sl_rdmsr(MSR_MTRRdefType);
	if (saved_bsp_mtrrs->default_mem_type != mtrr_def_type)
		sl_txt_reset(SL_ERROR_MTRR_INV_DEF_TYPE);

	for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; i++) {
		mtrr_var = sl_rdmsr(MTRRphysBase_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase != mtrr_var)
			sl_txt_reset(SL_ERROR_MTRR_INV_BASE);
		mtrr_var = sl_rdmsr(MTRRphysMask_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask != mtrr_var)
			sl_txt_reset(SL_ERROR_MTRR_INV_MASK);
	}

	misc_en_msr = sl_rdmsr(MSR_IA32_MISC_ENABLE);
	if (os_mle_data->saved_misc_enable_msr != misc_en_msr)
		sl_txt_reset(SL_ERROR_MSR_INV_MISC_EN);
}

static void sl_find_event_log(struct tpm *tpm)
{
	struct txt_os_mle_data *os_mle_data;
	void *os_sinit_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);

	os_mle_data = txt_os_mle_data_start(txt_heap);
	evtlog_base = (void *)&os_mle_data->event_log_buffer[0];

	if (tpm->family != TPM20)
		return;

	/*
	 * For TPM 2.0, the event log 2.1 extended data structure has to also
	 * be located and fixed up.
	 */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	/* Find the TPM2.0 logging extended heap element */
	log20_elem = tpm20_find_log2_1_element(os_sinit_data);

	if (!log20_elem)
		sl_txt_reset(SL_ERROR_TPM_INVALID_LOG20);
}

static void sl_tpm12_log_event(u32 pcr, u8 *digest,
			       const u8 *event_data, u32 event_size)
{
	struct tpm12_pcr_event *pcr_event;
	u32 total_size;
	u8 log_buf[SL_TPM12_LOG_SIZE];

	memset(log_buf, 0, SL_TPM12_LOG_SIZE);
	pcr_event = (struct tpm12_pcr_event *)log_buf;
	pcr_event->pcr_index = pcr;
	pcr_event->type = TXT_EVTYPE_SLAUNCH;
	memcpy(&pcr_event->digest[0], digest, SHA1_SIZE);
	pcr_event->size = event_size;
	memcpy((u8 *)pcr_event + sizeof(struct tpm12_pcr_event),
	       event_data, event_size);

	total_size = sizeof(struct tpm12_pcr_event) + event_size;

	if (tpm12_log_event(evtlog_base, total_size, pcr_event))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm20_log_event(u32 pcr, u8 *digest, u16 algo,
			       const u8 *event_data, u32 event_size)
{
	struct tpm20_pcr_event_head *head;
	struct tpm20_digest_values *dvs;
	struct tpm20_ha *ha;
	struct tpm20_pcr_event_tail *tail;
	u8 *dptr;
	u32 total_size;
	u8 log_buf[SL_TPM20_LOG_SIZE];

	memset(log_buf, 0, SL_TPM20_LOG_SIZE);
	head = (struct tpm20_pcr_event_head *)log_buf;
	head->pcr_index = pcr;
	head->event_type = TXT_EVTYPE_SLAUNCH;
	dvs = (struct tpm20_digest_values *)
		((u8 *)head + sizeof(struct tpm20_pcr_event_head));
	dvs->count = 1;
	ha = (struct tpm20_ha *)
		((u8 *)dvs + sizeof(struct tpm20_digest_values));
	ha->algorithm_id = algo;
	dptr = (u8 *)ha + sizeof(struct tpm20_ha);

	switch (algo) {
	case TPM_ALG_SHA512:
		memcpy(dptr, digest, SHA512_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA512_SIZE);
		break;
	case TPM_ALG_SHA256:
		memcpy(dptr, digest, SHA256_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA256_SIZE);
		break;
	case TPM_ALG_SHA1:
	default:
		memcpy(dptr, digest, SHA1_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA1_SIZE);
	};

	tail->event_size = event_size;
	memcpy((u8 *)tail + sizeof(struct tpm20_pcr_event_tail),
	       event_data, event_size);

	total_size = (u32)((u8 *)tail - (u8 *)head) +
		sizeof(struct tpm20_pcr_event_tail) + event_size;

	if (tpm20_log_event(log20_elem, evtlog_base, total_size, &log_buf[0]))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

void sl_tpm_extend_pcr(struct tpm *tpm, u32 pcr, const u8 *data, u32 length,
		       const char *desc)
{
	struct sha1_state sctx = {0};
	u8 sha1_hash[SHA1_SIZE] = {0};
	int ret;

	if (tpm->family == TPM20) {
#ifdef CONFIG_SECURE_LAUNCH_SHA256
		struct sha256_state sctx = {0};
		u8 sha256_hash[SHA256_SIZE] = {0};

		sha256_init(&sctx);
		sha256_update(&sctx, data, length);
		sha256_final(&sctx, &sha256_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA256, &sha256_hash[0]);
		if (!ret) {
			sl_tpm20_log_event(pcr, &sha256_hash[0],
					   TPM_ALG_SHA256,
					   (const u8 *)desc, strlen(desc));
			return;
		} else
			sl_txt_reset(SL_ERROR_TPM_EXTEND);
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
		struct sha512_state sctx = {0};
		u8 sha512_hash[SHA512_SIZE] = {0};

		sha512_init(&sctx);
		sha512_update(&sctx, data, length);
		sha512_final(&sctx, &sha512_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA512, &sha512_hash[0]);
		if (!ret) {
			sl_tpm20_log_event(pcr, &sha512_hash[0],
					   TPM_ALG_SHA512,
					   (const u8 *)desc, strlen(desc));
			return;
		} else
			sl_txt_reset(SL_ERROR_TPM_EXTEND);
#endif
	}

	early_sha1_init(&sctx);
	early_sha1_update(&sctx, data, length);
	early_sha1_final(&sctx, &sha1_hash[0]);
	ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA1, &sha1_hash[0]);
	if (ret)
		sl_txt_reset(SL_ERROR_TPM_EXTEND);

	if (tpm->family == TPM20)
		sl_tpm20_log_event(pcr, &sha1_hash[0], TPM_ALG_SHA1,
				   (const u8 *)desc, strlen(desc));
	else
		sl_tpm12_log_event(pcr, &sha1_hash[0],
				   (const u8 *)desc, strlen(desc));
}

void sl_main(u8 *bootparams)
{
	struct tpm *tpm;
	struct boot_params *bp;
	struct setup_data *data;
	struct txt_os_mle_data *os_mle_data;
	const char *signature;
	unsigned long mmap = 0;
	void *txt_heap;
	u32 data_count, os_mle_len;

	/*
	 * Currently only Intel TXT is supported for Secure Launch. Testing
	 * this value also indicates that the kernel was booted successfully
	 * through the Secure Launch entry point and is in SMX mode.
	 */
	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	/*
	 * If enable_tpm fails there is no point going on. The entire secure
	 * environment depends on this and the other TPM operations succeeding.
	 */
	tpm = enable_tpm();
	if (!tpm)
		sl_txt_reset(SL_ERROR_TPM_INIT);

	/* Locate the TPM event log. */
	sl_find_event_log(tpm);

	/*
	 * Locality 2 is being opened so that the DRTM PCRs can be updated,
	 * specifically 17 and 18.
	 */
	if (tpm_request_locality(tpm, 2) == TPM_NO_LOCALITY)
		sl_txt_reset(SL_ERROR_TPM_GET_LOC);

	/* Measure the zero page/boot params */
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, bootparams, PAGE_SIZE,
			  "Measured boot parameters into PCR18");

	/* Now safe to use boot params */
	bp = (struct boot_params *)bootparams;

	/* Measure the command line */
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18,
			  (u8 *)((unsigned long)bp->hdr.cmd_line_ptr),
			  bp->hdr.cmdline_size,
			  "Measured Kernel command line into PCR18");

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)bp->hdr.setup_data;
	while (data) {
		sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18,
				  ((u8 *)data) + sizeof(struct setup_data),
				  data->len,
				  "Measured Kernel setup_data into PCR18");

		data = (struct setup_data *)(unsigned long)data->next;
	}

	/* If bootloader was EFI, measure the memory map passed across */
	signature =
		(const char *)&bp->efi_info.efi_loader_signature;

	if (!strncmp(signature, EFI32_LOADER_SIGNATURE, 4))
		mmap =  bp->efi_info.efi_memmap;
	else if (!strncmp(signature, EFI64_LOADER_SIGNATURE, 4))
		mmap = (bp->efi_info.efi_memmap |
			((u64)bp->efi_info.efi_memmap_hi << 32));

	if (mmap)
		sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, (void *)mmap,
				  bp->efi_info.efi_memmap_size,
				  "Measured EFI memory map into PCR18");

	/* Measure any external initrd */
	if (bp->hdr.ramdisk_image != 0 && bp->hdr.ramdisk_size != 0)
		sl_tpm_extend_pcr(tpm, SL_IMAGE_PCR17,
				  (u8 *)((u64)bp->hdr.ramdisk_image),
				  bp->hdr.ramdisk_size,
				  "Measured initramfs into PCR17");

	/*
	 * Some extra work to do on Intel, have to measure the OS-MLE
	 * heap area.
	 */
	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	/*
	 * Measure OS-MLE data up to the MLE scratch field. The MLE scratch
	 * field and the TPM logging should not be measured.
	 */
	os_mle_len = offsetof(struct txt_os_mle_data, mle_scratch);
	sl_tpm_extend_pcr(tpm, SL_CONFIG_PCR18, (u8 *)os_mle_data, os_mle_len,
			  "Measured TXT OS-MLE data into PCR18");

	/*
	 * Now that the OS-MLE data is measured, ensure the MTRR and
	 * misc enable MSRs are what we expect.
	 */
	sl_txt_validate_msrs(os_mle_data);

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);
}

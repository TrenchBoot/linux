// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early measurement and validation routines.
 *
 * Copyright (c) 2024, Oracle and/or its affiliates.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/bootparam_utils.h>
#include <asm/svm.h>
#include <linux/slr_table.h>
#include <linux/slaunch.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>

#define CAPS_VARIABLE_MTRR_COUNT_MASK	0xff

#define SL_TPM_LOG		1
#define SL_TPM2_LOG		2

#define SL_TPM2_MAX_ALGS	2

#define SL_MAX_EVENT_DATA	64
#define SL_TPM_LOG_SIZE		(sizeof(struct tcg_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM2_LOG_SIZE	(sizeof(struct tcg_pcr_event2_head) + \
				SHA1_DIGEST_SIZE + SHA256_DIGEST_SIZE + \
				sizeof(struct tcg_event_field) + \
				SL_MAX_EVENT_DATA)

static void *evtlog_base;
static u32 evtlog_size;
static struct txt_heap_event_log_pointer2_1_element *log21_elem;
static u32 tpm_log_ver = SL_TPM_LOG;
static struct tcg_efi_specid_event_algs tpm_algs[SL_TPM2_MAX_ALGS] = {0};

extern u32 sl_cpu_type;
extern u32 sl_mle_start;

void __cold __noreturn __fortify_panic(const u8 reason, const size_t avail, const size_t size)
{
	asm volatile ("ud2");

	unreachable();
}

static u64 sl_txt_read(u32 reg)
{
	return readq((void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void sl_txt_write(u32 reg, u64 val)
{
	writeq(val, (void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void __noreturn sl_txt_reset(u64 error)
{
	/* Reading the E2STS register acts as a barrier for TXT registers */
	sl_txt_write(TXT_CR_ERRORCODE, error);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_UNLOCK_MEM_CONFIG, 1);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_RESET, 1);

	for ( ; ; )
		asm volatile ("hlt");

	unreachable();
}

static void __noreturn sl_skinit_reset(void)
{
	/* AMD does not have a reset mechanism or an error register */
	asm volatile ("ud2");

	unreachable();
}

static void __noreturn sl_reset(u64 error)
{
	if (sl_cpu_type & SL_CPU_INTEL)
		sl_txt_reset(error);
	else if (sl_cpu_type & SL_CPU_AMD)
		sl_skinit_reset();
	else
		unreachable();
}

static u64 sl_rdmsr(u32 reg)
{
	u64 lo, hi;

	asm volatile ("rdmsr" : "=a" (lo), "=d" (hi) : "c" (reg));

	return (hi << 32) | lo;
}

static struct slr_table *sl_locate_and_validate_slrt(void)
{
	struct txt_os_mle_data *os_mle_data;
	struct slr_table *slrt = NULL;
	struct skinit_sl_header *sl_header;
	void *txt_heap;

	if (sl_cpu_type & SL_CPU_INTEL) {
		txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
		os_mle_data = txt_os_mle_data_start(txt_heap);

		slrt = (struct slr_table *)os_mle_data->slrt;
	}
	if (sl_cpu_type & SL_CPU_AMD) {
		sl_header = (struct sl_header *)sl_skl_base;

		/* Bootloader's data is SLRT. */
		slrt = (void *)sl_skl_base + sl_header->bootloader_data_offset;
	}

	if (!slrt)
		sl_reset(SL_ERROR_INVALID_SLRT);

	if (slrt->magic != SLR_TABLE_MAGIC) {
		// hanged
		sl_reset(SL_ERROR_INVALID_SLRT);
	}

	if (sl_cpu_type & SL_CPU_INTEL) {
		if (slrt->architecture != SLR_INTEL_TXT)
			sl_reset(SL_ERROR_INVALID_SLRT);
	}
	if (sl_cpu_type & SL_CPU_AMD) {
		if (slrt->architecture != SLR_AMD_SKINIT)
			sl_reset(SL_ERROR_INVALID_SLRT);
	}

	return slrt;
}

static void sl_check_pmr_coverage(void *base, u32 size, bool allow_hi)
{
	struct txt_os_sinit_data *os_sinit_data;
	void *end = base + size;
	void *txt_heap;

	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	if ((u64)end >= SZ_4G && (u64)base < SZ_4G)
		sl_reset(SL_ERROR_REGION_STRADDLE_4GB);

	/*
	 * Note that the late stub code validates that the hi PMR covers
	 * all memory above 4G. At this point the code can only check that
	 * regions are within the hi PMR but that is sufficient.
	 */
	if ((u64)end > SZ_4G && (u64)base >= SZ_4G) {
		if (allow_hi) {
			if (end >= (void *)(os_sinit_data->vtd_pmr_hi_base +
					   os_sinit_data->vtd_pmr_hi_size))
				sl_reset(SL_ERROR_BUFFER_BEYOND_PMR);
		} else {
			sl_reset(SL_ERROR_REGION_ABOVE_4GB);
		}
	}

	if (end >= (void *)os_sinit_data->vtd_pmr_lo_size)
		sl_reset(SL_ERROR_BUFFER_BEYOND_PMR);
}

/*
 * Some MSRs are modified by the pre-launch code including the MTRRs.
 * The early MLE code has to restore these values. This code validates
 * the values after they are measured.
 */
static void sl_txt_validate_msrs(struct txt_os_mle_data *os_mle_data)
{
	struct slr_txt_mtrr_state *saved_bsp_mtrrs;
	u64 mtrr_caps, mtrr_def_type, mtrr_var;
	struct slr_entry_intel_info *txt_info;
	u64 misc_en_msr;
	u32 vcnt, i;

	txt_info = (struct slr_entry_intel_info *)os_mle_data->txt_info;
	saved_bsp_mtrrs = &txt_info->saved_bsp_mtrrs;

	mtrr_caps = sl_rdmsr(MSR_MTRRcap);
	vcnt = (u32)(mtrr_caps & CAPS_VARIABLE_MTRR_COUNT_MASK);

	if (saved_bsp_mtrrs->mtrr_vcnt > vcnt)
		sl_reset(SL_ERROR_MTRR_INV_VCNT);
	if (saved_bsp_mtrrs->mtrr_vcnt > TXT_OS_MLE_MAX_VARIABLE_MTRRS)
		sl_reset(SL_ERROR_MTRR_INV_VCNT);

	mtrr_def_type = sl_rdmsr(MSR_MTRRdefType);
	if (saved_bsp_mtrrs->default_mem_type != mtrr_def_type)
		sl_reset(SL_ERROR_MTRR_INV_DEF_TYPE);

	for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; i++) {
		mtrr_var = sl_rdmsr(MTRRphysBase_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase != mtrr_var)
			sl_reset(SL_ERROR_MTRR_INV_BASE);
		mtrr_var = sl_rdmsr(MTRRphysMask_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask != mtrr_var)
			sl_reset(SL_ERROR_MTRR_INV_MASK);
	}

	misc_en_msr = sl_rdmsr(MSR_IA32_MISC_ENABLE);
	if (txt_info->saved_misc_enable_msr != misc_en_msr)
		sl_reset(SL_ERROR_MSR_INV_MISC_EN);
}

/*
 * In order to simplify adding new entries and to minimize the number of
 * differences between AMD and Intel, the event logs have actually two headers,
 * both for TPM 1.2 and 2.0.
 *
 * For TPM 1.2 this is TCG_PCClientSpecIDEventStruct [1] with Intel's own
 * TXT-specific header embedded inside its 'vendorInfo' field. The offset to
 * this field is added to the base address in AMD path, making the code for
 * adding new events the same for both vendors.
 *
 * TPM 2.0 in TXT uses HEAP_EVENT_LOG_POINTER_ELEMENT2_1 structure, which is
 * normally constructed on the TXT stack [2]. For AMD, this structure is put
 * inside TCG_EfiSpecIdEvent [3], also in 'vendorInfo' field. The actual offset
 * to this field depends on number of hash algorithms supported by the event
 * log.
 *
 * [1] https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
 * [2] http://www.intel.com/content/dam/www/public/us/en/documents/guides/intel-txt-software-development-guide.pdf
 * [3] https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
 */
static void sl_find_drtm_event_log(struct slr_table *slrt)
{
	struct txt_os_sinit_data *os_sinit_data;
	struct slr_entry_log_info *log_info;
	void *txt_heap;

	log_info = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_LOG_INFO);
	if (!log_info) {
		/* No hope without an event log */
		sl_reset(SL_ERROR_SLRT_MISSING_ENTRY);
	}

	evtlog_base = (void *)log_info->addr;
	evtlog_size = log_info->size;

	if (sl_cpu_type & SL_CPU_AMD) {
		/* Check if it is TPM 2.0 event log */
		if (!memcmp(evtlog_base + sizeof(struct tcg_pcr_event),
			    TCG_SPECID_SIG, sizeof(TCG_SPECID_SIG))) {
			log21_elem = evtlog_base + sizeof(struct tcg_pcr_event)
				+ TCG_EfiSpecIdEvent_SIZE(
				  TPM20_HASH_COUNT(evtlog_base
					+ sizeof(struct tcg_pcr_event)));
			tpm_log_ver = SL_TPM2_LOG;
		} else {
			evtlog_base += sizeof(struct tcg_pcr_event)
				+ TCG_PCClientSpecIDEventStruct_SIZE;
			evtlog_size -= sizeof(struct tcg_pcr_event)
				+ TCG_PCClientSpecIDEventStruct_SIZE;
		}

		return;
	}

	/* Else it is Intel and TXT */

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);

	/*
	 * For TPM 2.0, the event log 2.1 extended data structure has to also
	 * be located and fixed up.
	 */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	/*
	 * Only support version 6 and later that properly handle the
	 * list of ExtDataElements in the OS-SINIT structure.
	 */
	if (os_sinit_data->version < 6)
		sl_reset(SL_ERROR_OS_SINIT_BAD_VERSION);

	/* Find the TPM2.0 logging extended heap element */
	log21_elem = tpm2_find_log2_1_element(os_sinit_data);

	/* If found, this implies TPM2 log and family */
	if (log21_elem)
		tpm_log_ver = SL_TPM2_LOG;
}

static bool sl_check_buffer_overlap(void *a_base, void *a_end,
				    void *b_base, void *b_end)
{
	if (a_base >= b_end && a_end > b_end)
		return false; /* above */

	if (a_end <= b_base && a_base < b_base)
		return false; /* below */

	return true;
}

static void sl_txt_validate_event_log_buffer(void)
{
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap, *txt_end;
	void *mle_base, *mle_end;
	void *evtlog_end;

	if ((u64)evtlog_size > (LLONG_MAX - (u64)evtlog_base))
		sl_reset(SL_ERROR_INTEGER_OVERFLOW);
	evtlog_end = evtlog_base + evtlog_size;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	txt_end = txt_heap + sl_txt_read(TXT_CR_HEAP_SIZE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	mle_base = (void *)(u64)sl_mle_start;
	mle_end = mle_base + os_sinit_data->mle_size;

	/*
	 * This check is to ensure the event log buffer does not overlap with
	 * the MLE image.
	 */
	if (sl_check_buffer_overlap(evtlog_base, evtlog_end,
				    mle_base, mle_end))
		sl_reset(SL_ERROR_MLE_BUFFER_OVERLAP);

	/*
	 * The TXT heap is protected by the DPR. If the TPM event log is
	 * inside the TXT heap, there is no need for a PMR check.
	 */
	if ((sl_cpu_type & SL_CPU_INTEL) &&
	    (evtlog_base <= txt_heap || evtlog_end > txt_end))
		sl_check_pmr_coverage(evtlog_base, evtlog_size, true);
}

static void sl_skinit_validate_buffers(void *bootparams)
{
	struct boot_params *bp = (struct boot_params *)bootparams;
	void *evtlog_end, *kernel_end;

	/* On AMD, all the buffers should be below 4 GiB */
	if ((u64)(evtlog_base + evtlog_size) > UINT_MAX)
		sl_skinit_reset();

	evtlog_end = evtlog_base + evtlog_size;
	kernel_end = (void *)(bp->hdr.code32_start +
			      (u64)bp->hdr.syssize * 16ULL);

	/*
	 * This check is to ensure the event log buffer and the bootparams do
	 * overlap with the kernel image.
	 */
	if (sl_check_buffer_overlap(bootparams, bootparams + PAGE_SIZE,
				    (void *)(u64)bp->hdr.code32_start,
				    kernel_end))
		sl_skinit_reset();

	if (sl_check_buffer_overlap(evtlog_base, evtlog_end,
				    (void *)(u64)bp->hdr.code32_start,
				    kernel_end))
		sl_skinit_reset();
}

static void sl_find_event_log_algorithms(void)
{
	struct tcg_efi_specid_event_head *efi_head =
		(struct tcg_efi_specid_event_head *)(evtlog_base +
					log21_elem->first_record_offset +
					sizeof(struct tcg_pcr_event));

	if (efi_head->num_algs == 0 || efi_head->num_algs > SL_TPM2_MAX_ALGS)
		sl_reset(SL_ERROR_TPM_NUMBER_ALGS);

	memcpy(&tpm_algs[0], &efi_head->digest_sizes[0],
	       sizeof(struct tcg_efi_specid_event_algs) * efi_head->num_algs);
}

static void sl_tpm_log_event(u32 pcr, u32 event_type,
			     const u8 *data, u32 length,
			     const u8 *event_data, u32 event_size)
{
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};
	u8 log_buf[SL_TPM_LOG_SIZE] = {0};
	struct tcg_pcr_event *pcr_event;
	u32 total_size;

	pcr_event = (struct tcg_pcr_event *)log_buf;
	pcr_event->pcr_idx = pcr;
	pcr_event->event_type = event_type;
	if (length > 0) {
		sha1(data, length, &sha1_hash[0]);
		memcpy(&pcr_event->digest[0], &sha1_hash[0], SHA1_DIGEST_SIZE);
	}
	pcr_event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)pcr_event + sizeof(*pcr_event),
		       event_data, event_size);

	total_size = sizeof(*pcr_event) + event_size;

	if (tpm_log_event(evtlog_base, evtlog_size, total_size, pcr_event))
		sl_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm2_log_event(u32 pcr, u32 event_type,
			      const u8 *data, u32 length,
			      const u8 *event_data, u32 event_size)
{
	u8 sha256_hash[SHA256_DIGEST_SIZE] = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};
	u8 log_buf[SL_TPM2_LOG_SIZE] = {0};
	struct sha256_state sctx256 = {0};
	struct tcg_pcr_event2_head *head;
	struct tcg_event_field *event;
	u32 total_size, alg_idx;
	u16 *alg_ptr;
	u8 *dgst_ptr;

	head = (struct tcg_pcr_event2_head *)log_buf;
	head->pcr_idx = pcr;
	head->event_type = event_type;
	total_size = sizeof(*head);
	alg_ptr = (u16 *)(log_buf + sizeof(*head));

	for (alg_idx = 0; alg_idx < SL_TPM2_MAX_ALGS; alg_idx++) {
		if (!tpm_algs[alg_idx].alg_id)
			break;

		*alg_ptr = tpm_algs[alg_idx].alg_id;
		dgst_ptr = (u8 *)alg_ptr + sizeof(u16);

		if (tpm_algs[alg_idx].alg_id == TPM_ALG_SHA256) {
			sha256_init(&sctx256);
			sha256_update(&sctx256, data, length);
			sha256_final(&sctx256, &sha256_hash[0]);
			memcpy(dgst_ptr, &sha256_hash[0], SHA256_DIGEST_SIZE);
			total_size += SHA256_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA256_DIGEST_SIZE + sizeof(u16));
		} else if (tpm_algs[alg_idx].alg_id == TPM_ALG_SHA1) {
			sha1(data, length, &sha1_hash[0]);
			memcpy(dgst_ptr, &sha1_hash[0], SHA1_DIGEST_SIZE);
			total_size += SHA1_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA1_DIGEST_SIZE + sizeof(u16));
		} else {
			sl_reset(SL_ERROR_TPM_UNKNOWN_DIGEST);
		}

		head->count++;
	}

	event = (struct tcg_event_field *)(log_buf + total_size);
	event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)event + sizeof(*event), event_data, event_size);
	total_size += sizeof(*event) + event_size;

	if (tpm2_log_event(log21_elem, evtlog_base, evtlog_size, total_size, &log_buf[0]))
		sl_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm_extend_evtlog(u32 pcr, u32 type,
				 const u8 *data, u32 length, const char *desc)
{
	if (tpm_log_ver == SL_TPM2_LOG)
		sl_tpm2_log_event(pcr, type, data, length,
				  (const u8 *)desc, strlen(desc));
	else
		sl_tpm_log_event(pcr, type, data, length,
				 (const u8 *)desc, strlen(desc));
}

static struct setup_data *sl_handle_setup_data(struct setup_data *curr,
					       struct slr_policy_entry *entry)
{
	struct setup_indirect *ind;
	struct setup_data *next;

	if (!curr)
		return NULL;

	next = (struct setup_data *)(unsigned long)curr->next;

	/* SETUP_INDIRECT instances have to be handled differently */
	if (curr->type == SETUP_INDIRECT) {
		ind = (struct setup_indirect *)((u8 *)curr + offsetof(struct setup_data, data));

		sl_check_pmr_coverage((void *)ind->addr, ind->len, true);

		sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)ind->addr, ind->len,
				     entry->evt_info);

		return next;
	}

	sl_check_pmr_coverage(((u8 *)curr) + sizeof(*curr),
			      curr->len, true);

	sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
			     ((u8 *)curr) + sizeof(*curr),
			     curr->len,
			     entry->evt_info);

	return next;
}

static void sl_extend_setup_data(struct slr_policy_entry *entry)
{
	struct setup_data *data;

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)entry->entity;
	while (data)
		data = sl_handle_setup_data(data, entry);
}

static void sl_extend_slrt(struct slr_policy_entry *entry)
{
	struct slr_table *slrt = (struct slr_table *)entry->entity;
	struct slr_entry_intel_info *intel_info;

	/*
	 * In revision one of the SLRT, the only table that needs to be
	 * measured is the Intel info table. Everything else is meta-data,
	 * addresses and sizes. Note the size of what to measure is not set.
	 * The flag SLR_POLICY_IMPLICIT_SIZE leaves it to the measuring code
	 * to sort out.
	 */
	if (slrt->revision == 1 && (sl_cpu_type & SL_CPU_INTEL)) {
		intel_info = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
		if (!intel_info)
			sl_reset(SL_ERROR_SLRT_MISSING_ENTRY);

		sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)entry->entity, sizeof(*intel_info),
				     entry->evt_info);
	}
}

static void sl_extend_txt_os2mle(struct slr_policy_entry *entry)
{
	struct txt_os_mle_data *os_mle_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	/*
	 * Version 1 of the OS-MLE heap structure has no fields to measure. It just
	 * has addresses and sizes and a scratch buffer.
	 */
	if (os_mle_data->version == 1)
		return;
}

/*
 * Process all policy entries and extend the measurements to the evtlog
 */
static void sl_process_extend_policy(struct slr_table *slrt)
{
	struct slr_entry_policy *policy;
	u16 i;

	policy = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_ENTRY_POLICY);
	if (!policy)
		sl_reset(SL_ERROR_SLRT_MISSING_ENTRY);

	for (i = 0; i < policy->nr_entries; i++) {
		switch (policy->policy_entries[i].entity_type) {
		case SLR_ET_SETUP_DATA:
			sl_extend_setup_data(&policy->policy_entries[i]);
			break;
		case SLR_ET_SLRT:
			sl_extend_slrt(&policy->policy_entries[i]);
			break;
		case SLR_ET_TXT_OS2MLE:
			sl_extend_txt_os2mle(&policy->policy_entries[i]);
			break;
		case SLR_ET_UNUSED:
			continue;
		default:
			sl_tpm_extend_evtlog(policy->policy_entries[i].pcr, TXT_EVTYPE_SLAUNCH,
					     (void *)policy->policy_entries[i].entity,
					     policy->policy_entries[i].size,
					     policy->policy_entries[i].evt_info);
		}
	}
}

/*
 * Process all EFI config entries and extend the measurements to the evtlog
 */
static void sl_process_extend_uefi_config(struct slr_table *slrt)
{
	struct slr_entry_uefi_config *uefi_config;
	u16 i;

	uefi_config = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_UEFI_CONFIG);

	/* Optionally here depending on how SL kernel was booted */
	if (!uefi_config)
		return;

	for (i = 0; i < uefi_config->nr_entries; i++) {
		sl_tpm_extend_evtlog(uefi_config->uefi_cfg_entries[i].pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)uefi_config->uefi_cfg_entries[i].cfg,
				     uefi_config->uefi_cfg_entries[i].size,
				     uefi_config->uefi_cfg_entries[i].evt_info);
	}
}

asmlinkage __visible void sl_check_region(void *base, u32 size)
{
	sl_check_pmr_coverage(base, size, false);
}

asmlinkage __visible void sl_main(void *bootparams)
{
	struct boot_params *bp  = (struct boot_params *)bootparams;
	struct txt_os_mle_data *os_mle_data;
	struct slr_table *slrt;
	void *txt_heap;

	/*
	 * Ensure loadflags do not indicate a secure launch was done
	 * unless it really was.
	 */
	bp->hdr.loadflags &= ~SLAUNCH_FLAG;

	/*
	 * Testing this value indicates that the kernel was booted successfully
	 * through the Secure Launch entry point and is the CPU is in a suitable
	 * mode.
	 */
	if (!(sl_cpu_type & (SL_CPU_INTEL | SL_CPU_AMD)))
		return;

	slrt = sl_locate_and_validate_slrt();

	/* Locate the TPM event log. */
	sl_find_drtm_event_log(slrt);

	/*
	 * Sanitize them before measuring. Set the SLAUNCH_FLAG early since if
	 * anything fails, the system will reset anyway.
	 */
	sanitize_boot_params(bp);

	/*
	 * On a TXT launch, validate the logging buffer for overlaps with the
	 * MLE and proper PMR coverage before using it. On an SKINIT launch,
	 * the boot params have to be used here to find the base and extent of
	 * the launched kernel. These values can then be used to make sure the
	 * boot params and logging buffer do not overlap the kernel.
	 */
	if (sl_cpu_type & SL_CPU_INTEL)
		sl_txt_validate_event_log_buffer();
	else
		sl_skinit_validate_buffers(bootparams);

	/*
	 * Find the TPM hash algorithms used by the ACM and recorded in the
	 * event log. XXX ACM?
	 */
	if (tpm_log_ver == SL_TPM2_LOG)
		sl_find_event_log_algorithms();

	bp->hdr.loadflags |= SLAUNCH_FLAG;

	sl_check_pmr_coverage(bootparams, PAGE_SIZE, false);

	/* Place event log SL specific tags before and after measurements */
	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_START, NULL, 0, "");

	sl_process_extend_policy(slrt);

	sl_process_extend_uefi_config(slrt);

	/* Final end event for TPM log */
	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_END, NULL, 0, "");

	if (sl_cpu_type & SL_CPU_INTEL) {
		/* No PMR check is needed, the TXT heap is covered by the DPR */
		txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
		os_mle_data = txt_os_mle_data_start(txt_heap);

		/*
		 * Now that the OS-MLE data is measured, ensure the MTRR and
		 * misc enable MSRs are what we expect.
		 */
		sl_txt_validate_msrs(os_mle_data);
	}
}

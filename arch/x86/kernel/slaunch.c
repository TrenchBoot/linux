// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019 Apertus Solutions, LLC
 *
 * Author(s):
 *     Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/e820/api.h>
#include <asm/bootparam.h>
#include <asm/setup.h>
#include <linux/slaunch.h>

#define PREFIX	"SLAUNCH: "

static u32 sl_flags;
static struct sl_ap_wake_info ap_wake_info;

/* This should be plenty of room */
static u8 txt_dmar[PAGE_SIZE] __aligned(16);

u32 slaunch_get_flags(void)
{
	return sl_flags;
}

struct sl_ap_wake_info *slaunch_get_ap_wake_info(void)
{
	return &ap_wake_info;
}

struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar)
{
	/* The DMAR is only stashed and provided via TXT on Intel systems */
	if (memcmp(txt_dmar, "DMAR", 4))
		return dmar;

	return (struct acpi_table_header *)(&txt_dmar[0]);
}

static void __init slaunch_txt_reset(void __iomem *txt,
				     const char *msg, u64 error)
{
	u64 one = 1, val;

	printk(KERN_ERR PREFIX "%s", msg);

	/*
	 * This performs a TXT reset with a sticky error code. The reads of
	 * TXT_CR_E2STS act as barriers.
	 */
	memcpy_toio(txt + TXT_CR_ERRORCODE, &error, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(txt + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(txt + TXT_CR_CMD_RESET, &one, sizeof(u64));

	asm volatile ("hlt");
}

/*
 * The TXT heap is too big to map all at once with early_ioremap
 * so it is done a table at a time.
 */
static void __init *txt_early_get_heap_table(void __iomem *txt, u32 type, u32 bytes)
{
	void *heap;
	u64 base, size, offset = 0;
	int i;

	if (type > TXT_SINIT_MLE_DATA_TABLE)
		slaunch_txt_reset(txt,
			"Error invalid table type for early heap walk\n",
			SL_ERROR_HEAP_WALK);

	memcpy_fromio(&base, txt + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&size, txt + TXT_CR_HEAP_SIZE, sizeof(u64));

	/* Iterate over heap tables looking for table of "type" */
	for (i = 0; i < type; i++) {
		base += offset;
		heap = early_memremap(base, sizeof(u64));
		if (!heap)
			slaunch_txt_reset(txt,
				"Error early_memremap of heap for heap walk\n",
				SL_ERROR_HEAP_WALK);

		offset = *((u64 *)heap);

		/*
		 * After the first iteration, any offset of zero is invalid and
		 * implies the TXT heap is corrupted.
		 */
		if (!offset)
			slaunch_txt_reset(txt,
				"Error invalid 0 offset in heap walk\n",
				SL_ERROR_HEAP_ZERO_OFFSET);

		early_memunmap(heap, sizeof(u64));
	}

	/* Skip the size field at the head of each table */
	base += sizeof(u64);
	heap = early_memremap(base, bytes);
	if (!heap)
		slaunch_txt_reset(txt,
				  "Error early_memremap of heap section\n",
				  SL_ERROR_HEAP_MAP);

	return heap;
}

/*
 * TXT uses a special set of VTd registers to protect all of memory from DMA
 * until the IOMMU can be programmed to protect memory. There is the low
 * memory PMR that can protect all memory up to 4G. The high memory PRM can
 * be setup to protect all memory beyond 4Gb. Validate that these values cover
 * what is expected.
 */
static void __init slaunch_verify_pmrs(void __iomem *txt)
{
	struct txt_os_sinit_data *os_sinit_data;
	unsigned long last_pfn;
	u32 field_offset, err = 0;
	const char *errmsg = "";

	field_offset = offsetof(struct txt_os_sinit_data, lcp_po_base);
	os_sinit_data = txt_early_get_heap_table(txt, TXT_OS_SINIT_DATA_TABLE,
						 field_offset);

	last_pfn = e820__end_of_ram_pfn();

	/*
	 * First make sure the hi PMR covers all memory above 4G. In the
	 * unlikely case where there is < 4G on the system, the hi PMR will
	 * not be set.
	 */
	if (os_sinit_data->vtd_pmr_hi_base != 0x0ULL) {
		if (os_sinit_data->vtd_pmr_hi_base != 0x100000000ULL) {
			err = SL_ERROR_HI_PMR_BASE;
			errmsg =  "Error hi PMR base\n";
			goto out;
		}

		if (last_pfn << PAGE_SHIFT >
		    os_sinit_data->vtd_pmr_hi_base +
		    os_sinit_data->vtd_pmr_hi_size) {
			err = SL_ERROR_HI_PMR_SIZE;
			errmsg = "Error hi PMR size\n";
			goto out;
		}
	}

	/* Lo PMR base should always be 0 */
	if (os_sinit_data->vtd_pmr_lo_base != 0x0ULL) {
		err = SL_ERROR_LO_PMR_BASE;
		errmsg = "Error lo PMR base\n";
		goto out;
	}

	/*
	 * Check that if the kernel was loaded below 4G, that it is protected
	 * by the lo PMR.
	 */
	if ((__pa_symbol(_end) < 0x100000000ULL) &&
	    (__pa_symbol(_end) > os_sinit_data->vtd_pmr_lo_size)) {
		err = SL_ERROR_LO_PMR_MLE;
		errmsg = "Error lo PMR does not cover MLE kernel\n";
		goto out;
	}

	/* Check that the AP wake block is protected by the lo PMR. */
	if (ap_wake_info.ap_wake_block + PAGE_SIZE >
	    os_sinit_data->vtd_pmr_lo_size) {
		err = SL_ERROR_LO_PMR_MLE;
		errmsg = "Error lo PMR does not cover AP wake block\n";
	}

out:
	early_memunmap(os_sinit_data, field_offset);

	if (err)
		slaunch_txt_reset(txt, errmsg, err);
}

static int __init slaunch_txt_reserve_range(u64 base, u64 size)
{
	int type;

	type = e820__get_entry_type(base, base + size - 1);
	if (type == E820_TYPE_RAM) {
		e820__range_update(base, size, E820_TYPE_RAM,
				   E820_TYPE_RESERVED);
		return 1;
	}

	return 0;
}

/*
 * For Intel, certain reqions of memory must be marked as reserved in the e820
 * memory map if they are not already. This includes the TXT HEAP, the ACM area,
 * the TXT private register bank. Normally these are properly reserved by
 * firmware but if it was not done, do it now.
 *
 * Also the Memory Descriptor Ranges that are passed to the MLE (see TXT
 * specification) may need to be reserved depeding on their type.
 */
static void __init slaunch_txt_reserve(void __iomem *txt)
{
	struct txt_sinit_memory_descriptor_record *mdr;
	struct txt_sinit_mle_data *sinit_mle_data;
	void *mdrs;
	u64 base, size;
	u32 field_offset, mdrnum, mdroffset, mdrslen, i;
	int updated = 0;

	base = TXT_PRIV_CONFIG_REGS_BASE;
	size = TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE;
	updated += slaunch_txt_reserve_range(base, size);

	memcpy_fromio(&base, txt + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&size, txt + TXT_CR_HEAP_SIZE, sizeof(u64));
	updated += slaunch_txt_reserve_range(base, size);

	memcpy_fromio(&base, txt + TXT_CR_SINIT_BASE, sizeof(u64));
	memcpy_fromio(&size, txt + TXT_CR_SINIT_SIZE, sizeof(u64));
	updated += slaunch_txt_reserve_range(base, size);

	field_offset = offsetof(struct txt_sinit_mle_data,
				sinit_vtd_dmar_table_size);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					field_offset);

	mdrnum = sinit_mle_data->num_of_sinit_mdrs;
	mdroffset = sinit_mle_data->sinit_mdrs_table_offset;

	early_memunmap(sinit_mle_data, field_offset);

	if (!mdrnum)
		goto out;

	mdrslen = (mdrnum * sizeof(struct txt_sinit_memory_descriptor_record));

	mdrs = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					mdroffset + mdrslen - 8);

	mdr = (struct txt_sinit_memory_descriptor_record *)
			(mdrs + mdroffset - 8);

	for (i = 0; i < mdrnum; i++, mdr++) {
		/* Spec says some entries can have length 0, ignore them */
		if (mdr->type > 0 && mdr->length > 0)
			updated += slaunch_txt_reserve_range(mdr->address,
							     mdr->length);
	}

	early_memunmap(mdrs, mdroffset + mdrslen - 8);

out:
	if (updated) {
		e820__update_table(e820_table);
		pr_info("TXT altered physical RAM map:\n");
		e820__print_table("TXT-reserve");
	}
}

/*
 * TXT stashes a safe copy of the DMAR ACPI table to prevent tampering.
 * It is stored in the TXT heap. Fetch it from there and make it available
 * to the IOMMU driver.
 */
static void __init slaunch_copy_dmar_table(void __iomem *txt)
{
	struct txt_sinit_mle_data *sinit_mle_data;
	void *dmar;
	u32 field_offset, dmar_size, dmar_offset;

	memset(&txt_dmar, 0, PAGE_SIZE);

	field_offset = offsetof(struct txt_sinit_mle_data,
				processor_scrtm_status);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
						  field_offset);

	dmar_size = sinit_mle_data->sinit_vtd_dmar_table_size;
	dmar_offset = sinit_mle_data->sinit_vtd_dmar_table_offset;

	early_memunmap(sinit_mle_data, field_offset);

	if (!dmar_size || !dmar_offset)
		slaunch_txt_reset(txt,
				  "Error invalid DMAR table values\n",
				  SL_ERROR_HEAP_INVALID_DMAR);

	if (unlikely(dmar_size > PAGE_SIZE))
		slaunch_txt_reset(txt,
				  "Error DMAR too big to store\n",
				  SL_ERROR_HEAP_DMAR_SIZE);


	dmar = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					dmar_offset + dmar_size - 8);
	if (!dmar)
		slaunch_txt_reset(txt,
				  "Error early_ioremap of DMAR\n",
				  SL_ERROR_HEAP_DMAR_MAP);

	memcpy(&txt_dmar[0], dmar + dmar_offset - 8, dmar_size);

	early_memunmap(dmar, dmar_offset + dmar_size - 8);
}

/*
 * The location of the safe AP wake code block is stored in the TXT heap.
 * Fetch it here in the early init code for later use in SMP startup.
 */
static void __init slaunch_fetch_ap_wake_block(void __iomem *txt)
{
	struct txt_os_mle_data *os_mle_data;
	u8 *jmp_offset;
	u32 field_offset;

	field_offset = offsetof(struct txt_os_mle_data, event_log_buffer);
	os_mle_data = txt_early_get_heap_table(txt, TXT_OS_MLE_DATA_TABLE,
					       field_offset);

	ap_wake_info.ap_wake_block = os_mle_data->ap_wake_block;

	jmp_offset = ((u8 *)&os_mle_data->mle_scratch)
			+ SL_SCRATCH_AP_JMP_OFFSET;
	ap_wake_info.ap_jmp_offset = *((u32 *)jmp_offset);

	early_memunmap(os_mle_data, field_offset);
}

/*
 * Intel specific late stub setup and validation.
 */
static void __init slaunch_setup_intel(void)
{
	void __iomem *txt;
	u64 val = 0x1ULL;

	/*
	 * First see if SENTER was done and not by TBOOT by reading the status
	 * register in the public space.
	 */
	txt = early_ioremap(TXT_PUB_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		/* This is really bad, no where to go from here */
		panic("Error early_ioremap of TXT pub registers\n");
	}

	memcpy_fromio(&val, txt + TXT_CR_STS, sizeof(u64));
	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	/* Was SENTER done? */
	if (!(val & TXT_SENTER_DONE_STS))
		return;

	/* Was it done by TBOOT? */
	if (boot_params.tboot_addr)
		return;

	/* Now we want to use the private register space */
	txt = early_ioremap(TXT_PRIV_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		/* This is really bad, no where to go from here */
		panic("Error early_ioremap of TXT priv registers\n");
	}

	/*
	 * Try to read the Intel VID from the TXT private registers to see if
	 * TXT measured launch happened properly and the private space is
	 * available.
	 */
	memcpy_fromio(&val, txt + TXT_CR_DIDVID, sizeof(u64));
	if ((u16)(val & 0xffff) != 0x8086) {
		/*
		 * Can't do a proper TXT reset since it appears something is
		 * wrong even though SENTER happened and it should be in SMX
		 * mode.
		 */
		panic("Invalid TXT vendor ID, not in SMX mode\n");
	}

	/* Set flags so subsequent code knows the status of the launch */
	sl_flags |= (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT);

	/*
	 * Reading the proper DIDVID from the private register space means we
	 * are in SMX mode and private registers are open for read/write.
	 */

	/* On Intel, have to handle TPM localities via TXT */
	val = 0x1ULL;
	memcpy_toio(txt + TXT_CR_CMD_SECRETS, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	val = 0x1ULL;
	memcpy_toio(txt + TXT_CR_CMD_OPEN_LOCALITY1, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));

	slaunch_fetch_ap_wake_block(txt);

	slaunch_verify_pmrs(txt);

	slaunch_txt_reserve(txt);

	slaunch_copy_dmar_table(txt);

	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	pr_info("Intel TXT setup complete\n");
}

void __init slaunch_setup(void)
{
	u32 vendor[4];

	/* Get manufacturer string with CPUID 0 */
	cpuid(0, &vendor[0], &vendor[1], &vendor[2], &vendor[3]);

	/* Only Intel TXT is supported at this point */
	if (vendor[1] == INTEL_CPUID_MFGID_EBX &&
	    vendor[2] == INTEL_CPUID_MFGID_ECX &&
	    vendor[3] == INTEL_CPUID_MFGID_EDX)
		slaunch_setup_intel();
}

/*
 * Securityfs exposure
 */
struct memfile {
	char *name;
	void __iomem *addr;
	size_t size;
};

static struct memfile sl_evtlog = {"eventlog", 0, 0};
static void __iomem *txt_heap;
static struct txt_heap_event_log_pointer2_1_element __iomem *evtlog20;

static DEFINE_MUTEX(sl_evt_write_mutex);

static ssize_t sl_evtlog_read(struct file *file, char __user *buf,
			      size_t count, loff_t *pos)
{
	return simple_read_from_buffer(buf, count, pos,
		sl_evtlog.addr, sl_evtlog.size);
}

static ssize_t sl_evtlog_write(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	data = memdup_user(buf, datalen);
	if (IS_ERR(data)) {
		result = PTR_ERR(data);
		goto out;
	}

	mutex_lock(&sl_evt_write_mutex);
	if (evtlog20)
		result = tpm20_log_event(evtlog20, sl_evtlog.addr,
					 datalen, data);
	else
		result = tpm12_log_event(sl_evtlog.addr, datalen, data);
	mutex_unlock(&sl_evt_write_mutex);

	kfree(data);
out:
	return result;
}

static const struct file_operations sl_evtlog_ops = {
	.read = sl_evtlog_read,
	.write = sl_evtlog_write,
	.llseek	= default_llseek,
};

#define SL_DIR_ENTRY	1 /* directoy node must be last */
#define SL_FS_ENTRIES	2

static struct dentry *fs_entries[SL_FS_ENTRIES];

static long slaunch_expose_securityfs(void)
{
	long ret = 0;
	int entry = SL_DIR_ENTRY;

	fs_entries[entry] = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(fs_entries[entry])) {
		pr_err("Error creating securityfs sl_evt_log directory\n");
		ret = PTR_ERR(fs_entries[entry]);
		goto err;
	}

	if (sl_evtlog.addr > 0) {
		entry--;
		fs_entries[entry] = securityfs_create_file(sl_evtlog.name,
					   S_IRUSR | S_IRGRP,
					   fs_entries[SL_DIR_ENTRY], NULL,
					   &sl_evtlog_ops);
		if (IS_ERR(fs_entries[entry])) {
			pr_err("Error creating securityfs %s file\n",
				sl_evtlog.name);
			ret = PTR_ERR(fs_entries[entry]);
			goto err_dir;
		}
	}

	return 0;

err_dir:
	securityfs_remove(fs_entries[SL_DIR_ENTRY]);
err:
	return ret;
}

static void slaunch_teardown_securityfs(void)
{
	int i;

	for (i = 0; i < SL_FS_ENTRIES; i++)
		securityfs_remove(fs_entries[i]);

	if (sl_flags & SL_FLAG_ARCH_TXT) {
		if (txt_heap) {
			memunmap(txt_heap);
			txt_heap = NULL;
		}
	}

	sl_evtlog.addr = 0;
	sl_evtlog.size = 0;
}

static void slaunch_intel_evtlog(void)
{
	void __iomem *config;
	struct txt_os_mle_data *params;
	void *os_sinit_data;
	u64 base, size;

	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_err("Error failed to ioremap TXT reqs\n");
		return;
	}

	memcpy_fromio(&base, config + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&size, config + TXT_CR_HEAP_SIZE, sizeof(u64));
	iounmap(config);

	/* now map TXT heap */
	txt_heap = memremap(base, size, MEMREMAP_WB);
	if (!txt_heap) {
		pr_err("Error failed to memremap TXT heap\n");
		return;
	}

	params = (struct txt_os_mle_data *)txt_os_mle_data_start(txt_heap);

	sl_evtlog.size = TXT_MAX_EVENT_LOG_SIZE;
	sl_evtlog.addr = (void __iomem *)&params->event_log_buffer[0];

	/* Determine if this is TPM 1.2 or 2.0 event log */
	if (memcmp(sl_evtlog.addr + sizeof(struct tpm12_pcr_event),
		    TPM20_EVTLOG_SIGNATURE, sizeof(TPM20_EVTLOG_SIGNATURE)))
		return; /* looks like it is not 2.0 */

	/* For TPM 2.0 logs, the extended heap element must be located */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	evtlog20 = tpm20_find_log2_1_element(os_sinit_data);

	/*
	 * If this fails, things are in really bad shape. Any attempt to write
	 * events to the log will fail.
	 */
	if (!evtlog20)
		pr_err("Error failed to find TPM20 event log element\n");
}

static int __init slaunch_late_init(void)
{
	/* Check to see if Secure Launch happened */
	if (!(sl_flags & (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT)))
		return 0;

	/* Only Intel TXT is supported at this point */
	slaunch_intel_evtlog();

	return slaunch_expose_securityfs();
}

static void __exit slaunch_exit(void)
{
	slaunch_teardown_securityfs();
}

late_initcall(slaunch_late_init);

__exitcall(slaunch_exit);

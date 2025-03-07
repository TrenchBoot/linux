/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024, Oracle and/or its affiliates.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/cpu/relocator.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/linux.h>
#include <grub/i386/txt.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define OFFSET_OF(x, y) ((grub_size_t)((grub_uint8_t *)(&(y)->x) - (grub_uint8_t *)(y)))

grub_err_t
grub_sl_find_kernel_info (struct grub_slaunch_params *slparams, grub_file_t kernel_file,
                          struct linux_i386_kernel_header *lh, grub_size_t real_size)

{
  struct linux_kernel_info *linux_info;
  struct grub_txt_mle_header mle_hdr;

  /* Not a Secure Launch, do nothing */
  if (grub_slaunch_platform_type () == SLP_NONE)
    return GRUB_ERR_NONE;

  if (grub_le_to_cpu16 (lh->version) < 0x020f)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("not an slaunch kernel: boot protocol too old"));
      goto fail;
    }


  if (grub_file_seek (kernel_file, grub_le_to_cpu32 (lh->kernel_info_offset) +
                      real_size + GRUB_DISK_SECTOR_SIZE) == ((grub_off_t) -1))
    goto fail;

  linux_info = grub_malloc (GRUB_KERNEL_INFO_MIN_SIZE_TOTAL);

  if (!linux_info)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot allocate memory for kernel_info"));
      goto fail;
    }

  /* Load minimal kernel_info struct. */
  if (grub_file_read (kernel_file, linux_info,
                      GRUB_KERNEL_INFO_MIN_SIZE_TOTAL) != GRUB_KERNEL_INFO_MIN_SIZE_TOTAL)
    {
      if (!grub_errno)
        grub_error (GRUB_ERR_BAD_OS, N_("premature end of kernel file"));
      goto fail;
    }

  if (grub_memcmp (&linux_info->header, GRUB_KERNEL_INFO_HEADER, sizeof (linux_info->header)))
    {
      grub_error (GRUB_ERR_BAD_OS, N_("incorrect kernel_info header"));
      goto fail;
    }

  linux_info->size_total = grub_le_to_cpu32 (linux_info->size_total);

  linux_info = grub_realloc (linux_info, linux_info->size_total);

  if (!linux_info)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot reallocate memory for kernel_info"));
      goto fail;
    }

  /* Load the rest of kernel_info struct. */
  if (grub_file_read (kernel_file, &linux_info->setup_type_max,
                      linux_info->size_total - GRUB_KERNEL_INFO_MIN_SIZE_TOTAL) !=
                      (grub_ssize_t)(linux_info->size_total - GRUB_KERNEL_INFO_MIN_SIZE_TOTAL))
    {
      if (!grub_errno)
        grub_error (GRUB_ERR_BAD_OS, N_("premature end of kernel file"));
      goto fail;
    }

  /* Fetch the MLE header offset so Secure Launch can locate it */
  if (OFFSET_OF (mle_header_offset, linux_info) >= grub_le_to_cpu32 (linux_info->size))
    {
      if (!grub_errno)
        grub_error (GRUB_ERR_BAD_OS, N_("not an slaunch kernel: lack of mle_header_offset"));
      goto fail;
    }

  slparams->mle_header_offset = grub_le_to_cpu32 (linux_info->mle_header_offset);

  if (grub_file_seek (kernel_file, slparams->mle_header_offset + real_size +
                      GRUB_DISK_SECTOR_SIZE) == ((grub_off_t) -1))
    goto fail;
  if (grub_file_read (kernel_file, &mle_hdr, sizeof (mle_hdr)) != sizeof (mle_hdr))
    {
      if (!grub_errno)
        grub_error (GRUB_ERR_BAD_OS, N_("premature end of kernel file"));
      goto fail;
    }

  if (grub_memcmp (mle_hdr.uuid, GRUB_TXT_MLE_UUID, 16) != 0)
    {
      grub_dprintf ("linux", "Not an MLE header at %llu\n",
                    (unsigned long long)slparams->mle_header_offset + real_size + GRUB_DISK_SECTOR_SIZE);
      grub_error (GRUB_ERR_BAD_OS, N_("failed to locate MLE header"));
      goto fail;
    }

  slparams->mle_entry = mle_hdr.entry_point;

  return GRUB_ERR_NONE;

fail:
  return grub_errno;
}

grub_err_t
grub_sl_txt_prepare_mle_ptab (struct grub_slaunch_params *slparams, grub_size_t *prot_size,
                              grub_uint64_t *preferred_address)
{
  *prot_size = ALIGN_UP (*prot_size, GRUB_TXT_PMR_ALIGN);

  if (*prot_size > GRUB_TXT_MLE_MAX_SIZE)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
                  N_("slaunch kernel: protected size out of range"));
      return GRUB_ERR_OUT_OF_RANGE;
    }

  slparams->mle_ptab_size = grub_txt_get_mle_ptab_size (*prot_size);
  slparams->mle_ptab_size = ALIGN_UP (slparams->mle_ptab_size, GRUB_TXT_PMR_ALIGN);

  /* Do not go below GRUB_TXT_PMR_ALIGN */
  *preferred_address = (*preferred_address > slparams->mle_ptab_size) ?
                       (*preferred_address - slparams->mle_ptab_size) : GRUB_TXT_PMR_ALIGN;
  *preferred_address = ALIGN_UP (*preferred_address, GRUB_TXT_PMR_ALIGN);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_sl_txt_setup_linux (struct grub_slaunch_params *slparams, struct grub_relocator *relocator,
                         grub_size_t total_size, grub_size_t prot_size,
                         void **prot_mode_mem, grub_addr_t *prot_mode_target)
{
  grub_relocator_chunk_t ch;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_LINUX;
  slparams->relocator = relocator;

  /* Zero out memory to get stable MLE measurements. */
  grub_memset (*prot_mode_mem, 0, total_size);

  slparams->mle_ptab_mem = *prot_mode_mem;
  slparams->mle_ptab_target = *prot_mode_target;

  *prot_mode_mem = (char *)*prot_mode_mem + slparams->mle_ptab_size;
  *prot_mode_target += slparams->mle_ptab_size;

  slparams->mle_start = *prot_mode_target;
  slparams->mle_size = prot_size;

  grub_dprintf ("linux", "mle_ptab_mem = %p, mle_ptab_target = %lx, mle_ptab_size = %x\n",
                slparams->mle_ptab_mem, (unsigned long) slparams->mle_ptab_target,
		      (unsigned) slparams->mle_ptab_size);

  if (grub_relocator_alloc_chunk_align (relocator, &ch, 0x1000000,
                                        0xffffffff - GRUB_PAGE_SIZE,
                                        GRUB_PAGE_SIZE, GRUB_PAGE_SIZE,
                                        GRUB_RELOCATOR_PREFERENCE_NONE, 1))
    goto fail;

  slparams->slr_table_base = get_physical_target_address (ch);
  slparams->slr_table_size = GRUB_PAGE_SIZE;
  slparams->slr_table_mem = get_virtual_current_address (ch);

  grub_memset (slparams->slr_table_mem, 0, slparams->slr_table_size);

  grub_dprintf ("linux", "slr_table_base = %lx, slr_table_size = %x\n",
                (unsigned long) slparams->slr_table_base,
                (unsigned) slparams->slr_table_size);

  if (grub_relocator_alloc_chunk_align (relocator, &ch, 0x1000000,
                                        0xffffffff - GRUB_SLAUNCH_TPM_EVT_LOG_SIZE,
                                        GRUB_SLAUNCH_TPM_EVT_LOG_SIZE, GRUB_PAGE_SIZE,
                                        GRUB_RELOCATOR_PREFERENCE_NONE, 1))
    goto fail;

  slparams->tpm_evt_log_base = get_physical_target_address (ch);
  slparams->tpm_evt_log_size = GRUB_SLAUNCH_TPM_EVT_LOG_SIZE;
  grub_txt_init_tpm_event_log (get_virtual_current_address (ch),
                               slparams->tpm_evt_log_size);

  grub_dprintf ("linux", "tpm_evt_log_base = %lx, tpm_evt_log_size = %x\n",
                (unsigned long) slparams->tpm_evt_log_base,
                (unsigned) slparams->tpm_evt_log_size);

  if (grub_relocator_alloc_chunk_align (relocator, &ch, 0x1000000,
                                        0xffffffff - GRUB_MLE_AP_WAKE_BLOCK_SIZE,
                                        GRUB_MLE_AP_WAKE_BLOCK_SIZE, GRUB_PAGE_SIZE,
                                        GRUB_RELOCATOR_PREFERENCE_NONE, 1))
    goto fail;

  slparams->ap_wake_block = get_physical_target_address (ch);
  slparams->ap_wake_block_size = GRUB_MLE_AP_WAKE_BLOCK_SIZE;

  grub_memset (get_virtual_current_address (ch), 0, slparams->ap_wake_block_size);

  grub_dprintf ("linux", "ap_wake_block = %lx, ap_wake_block_size = %lx\n",
                (unsigned long) slparams->ap_wake_block,
                (unsigned long) slparams->ap_wake_block_size);

  return GRUB_ERR_NONE;

fail:
  return grub_errno;
}

grub_err_t
grub_sl_skinit_setup_linux (struct grub_slaunch_params *slparams, struct grub_relocator *relocator,
                            grub_size_t total_size, grub_size_t prot_file_size,
                            void *prot_mode_mem, grub_addr_t prot_mode_target)
{
  grub_relocator_chunk_t ch;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_LINUX;
  slparams->relocator = relocator;

  /* Zero out memory to get stable MLE measurements. */
  grub_memset (prot_mode_mem, 0, total_size);

  slparams->mle_start = prot_mode_target;
  slparams->mle_size = prot_file_size;

  /* Less to do on AMD. Just need to setup an event log buffer and some values */
  if (grub_relocator_alloc_chunk_align (relocator, &ch, 0x1000000,
                                        0xffffffff - GRUB_SLAUNCH_TPM_EVT_LOG_SIZE,
                                        GRUB_SLAUNCH_TPM_EVT_LOG_SIZE, GRUB_PAGE_SIZE,
                                        GRUB_RELOCATOR_PREFERENCE_NONE, 1))
    goto fail;

  slparams->tpm_evt_log_base = get_physical_target_address (ch);
  slparams->tpm_evt_log_size = GRUB_SLAUNCH_TPM_EVT_LOG_SIZE;
  /* It's OK to call this for AMD SKINIT because SKL erases the log before use. */
  grub_txt_init_tpm_event_log (get_virtual_current_address (ch),
                               slparams->tpm_evt_log_size);

  grub_dprintf ("linux", "tpm_evt_log_base = %lx, tpm_evt_log_size = %x\n",
                (unsigned long) slparams->tpm_evt_log_base,
                (unsigned) slparams->tpm_evt_log_size);

  /* The SLRT is located in the SKL image and the wake block is not needed on AMD */

  return GRUB_ERR_NONE;

fail:
  return grub_errno;
}

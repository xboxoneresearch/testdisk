/*

    File: file_xvd.c

    Copyright (C) 2023 tuxuser

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xvd)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

#define XVD_HEADER_INCL_SIGNATURE 0x3000

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_xvd(file_stat_t *file_stat);

const file_hint_t file_hint_xvd= {
  .extension="xvd",
  .description="Xbox Virtual Disk files",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xvd
};

struct xvd_header
{
  char rsa_signature[0x200];      // 0x000
  char magic[8];                  // 0x200
  uint32_t flags;                 // 0x208
  uint32_t format_version;        // 0x20C
  uint64_t creation_time;         // 0x210
  uint64_t drive_size;            // 0x218
  char content_id[0x10];          // 0x220
  char user_id[0x10];             // 0x230
  char top_hash[0x20];            // 0x240
  char xvc_hash[0x20];            // 0x260
  uint32_t xvd_type;              // 0x280
  uint32_t content_type;          // 0x284
  uint32_t embedded_xvd_length;   // 0x288
  uint32_t user_data_length;      // 0x28C
  uint32_t xvc_data_length;       // 0x290
  uint32_t dynamic_header_length; // 0x294
  uint32_t block_size;            // 0x298
  // ... rest of the header is not important in this scenario ...
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_xvd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct xvd_header *xvd=(const struct xvd_header *)buffer;
  // Check if xvd type is dynamic or fixed
  if (xvd->xvd_type != 0 && xvd->xvd_type != 1)
    return 0;
  
  if (xvd->block_size != 0xAA000)
    return 0;

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xvd.extension;

  // Filesize + 50MB buffer
  // TODO: Add Hashtree size
  uint64_t filesize = (
    XVD_HEADER_INCL_SIGNATURE + xvd->embedded_xvd_length + xvd->user_data_length + xvd->xvc_data_length + xvd->dynamic_header_length + xvd->drive_size + (50 * 1024 * 1024)
  );
  // Just hardcode 70 MB, that should be fine to dump updater.xvd
  file_recovery_new->calculated_file_size=filesize;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_xvd(file_stat_t *file_stat)
{
  static const unsigned char xvd_header[8]=  { 'm' , 's' , 'f' , 't', '-', 'x', 'v', 'd' };
  register_header_check(0x200, xvd_header, sizeof(xvd_header), &header_check_xvd, file_stat);
}
#endif

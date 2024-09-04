/*

    File: file_xb1_bootcap.c
    Definitions for the Xbox One Boot Capability certificate fileformat
    
    Copyright (C) 2024 TorusHyperV & tuxuser

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xb1_bootcap)
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

#define max(x,y) (((int)((x)<(y)) * (y)) + ((int)((y)<=(x)) * (x)))

#define XB1_BOOTCAP_MAXSIZE 0x400 

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_xb1_bootcap(file_stat_t *file_stat);

const file_hint_t file_hint_xb1_bootcap= {
  .extension="certkeys.bin",
  .description="Xbox One Boot Capability Certificate file",
  .max_filesize=max(XB1_BOOTCAP_MAXSIZE, PHOTOREC_MAX_FILE_SIZE),
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xb1_bootcap
};

struct xb1_bootcap_header
{
  uint16_t bootcap_magic; // 0x000
  uint16_t size;          // 0x002

  // Rest of the header is not important in this scenario:
  // Apart from the RSA signature, there's nothing else that can be used
  // to check the integrity of the boot capability file.
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_xb1_bootcap(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct xb1_bootcap_header *bootcap=(const struct xb1_bootcap_header *)buffer;
  // Check if xvd type is dynamic or fixed
  if (bootcap->bootcap_magic != 0x4350) // "CP"
    return 0;
  
  if (bootcap->size > XB1_BOOTCAP_MAXSIZE) // TODO: Is it possible to add some informative error in this return path, as to why we ditch this file?
    return 0;

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xb1_bootcap.extension;

  // Filesize is the maximum possible size for a capability cert, including signature
  uint64_t filesize = XB1_BOOTCAP_MAXSIZE;

  file_recovery_new->calculated_file_size=filesize;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_xb1_bootcap(file_stat_t *file_stat)
{
  static const unsigned char xb1_bootcap_header[2]=  { 'C' , 'P'};
  register_header_check(0x200, xb1_bootcap_header, sizeof(xb1_bootcap_header), &header_check_xb1_bootcap, file_stat);
}
#endif

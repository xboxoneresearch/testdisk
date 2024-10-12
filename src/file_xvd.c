/*
    File: file_xvd.c

    Copyright (C) 2024 tuxuser, TorusHyperV

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
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

#define XVD_HEADER_INCL_SIGNATURE 0x3000
#define XVD_PAGE_SIZE             0x1000
#define XVD_INVALID_BLOCK         0xFFFFFFFF
#define XVD_BLOCK_SIZE            0xAA000      // 680 Kbytes
#define BAT_ENTRY_SIZE            0x4          // BAT Entry is just uint32_t, like in VHD


///////////////////////////////////////
// PhotoRec DEFINITIONS
///////////////////////////////////////

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

//////////////////////////////////////////
// AUXILIARY METHODS                    //
//////////////////////////////////////////
uint32_t BytesToPages(uint64_t size_bytes)
{
    // e.g.
    // 4096 bytes == 1 page needed
    // 4097 bytes == 2 pages needed
    return ((size_bytes + XVD_PAGE_SIZE - 1)/ XVD_PAGE_SIZE); 
}

uint64_t PagesToBytes(uint64_t num_pages)
{
    return num_pages * XVD_PAGE_SIZE;
}

uint64_t BytesToBlocks(uint64_t size_bytes)
{
    return (size_bytes + XVD_BLOCK_SIZE -1) / XVD_BLOCK_SIZE;
}

uint64_t BlocksToBytes(uint64_t num_blocks)
{
    return num_blocks * XVD_BLOCK_SIZE;
}

uint64_t PagesToBlocks(uint32_t num_pages)
{
    return (PagesToBytes(num_pages) + XVD_BLOCK_SIZE -1) / XVD_BLOCK_SIZE;
}

uint64_t AlignSizeToPageBoundary(uint64_t size_bytes)
{
    uint64_t quotient  = size_bytes / XVD_PAGE_SIZE;
    uint64_t remainder = size_bytes % XVD_PAGE_SIZE;
    if(remainder != 0)
    {
        uint64_t aligned_size = (quotient + 1) * XVD_PAGE_SIZE;
        return aligned_size;
    }
    else
        return size_bytes;
}

//////////////////////////////////////////
// XVD STRUCTS AND TYPES                //
//////////////////////////////////////////
enum XvdType 
{
    FIXED   = 0,
    DYNAMIC = 1
};

typedef struct XvdFlags
{
    uint32_t ro                    : 1;
    uint32_t EncryptionDisabled    : 1;
    uint32_t DataIntegrityDisabled : 1;
    uint32_t legacy_sector_len     : 1;
    uint32_t resiliency_en         : 1;
    uint32_t sra_ro                : 1;
    uint32_t region_id_xts         : 1;
    uint32_t title_specific        : 1;
    uint32_t whatever0             : 1;
    uint32_t whatever1             : 1;
    uint32_t whatever2             : 1;
    uint32_t whatever3             : 1;
    uint32_t whatever4             : 1;
    uint32_t whatever5             : 1;
    uint32_t whatever6             : 1;
    uint32_t unused                : 17;
} XvdFlags;

typedef struct __attribute__((gcc_struct, __packed__)) xvd_header
{
  char     rsa_signature[0x200];  // 0x000
  char     magic[8];              // 0x200
  XvdFlags flags;                 // 0x208
  uint32_t format_version;        // 0x20C
  uint64_t creation_time;         // 0x210
  uint64_t drive_size;            // 0x218
  char     content_id[0x10];      // 0x220
  char     user_id[0x10];         // 0x230
  char     top_hash[0x20];        // 0x240
  char     xvc_hash[0x20];        // 0x260
  uint32_t xvd_type;              // 0x280
  uint32_t content_type;          // 0x284
  uint32_t embedded_xvd_length;   // 0x288
  uint32_t user_data_length;      // 0x28C
  uint32_t xvc_data_length;       // 0x290
  uint32_t dynamic_header_length; // 0x294
  uint32_t block_size;            // 0x298
  // ... rest of the header is not needed for XVD recovery scenario ...
} xvd_header;

///////////////////////////////////////
// METHOD PREDEFINITIONS
///////////////////////////////////////
uint64_t FindEmbeddedXVDSize(const xvd_header* header, const char* filename);
uint64_t FindMDUSize(const xvd_header* header, const char* filename);
uint64_t FindHashTreeSize(const xvd_header* header, const char* filename);
uint64_t FindUserDataSize(const xvd_header* header, const char* filename);
uint64_t FindXVCSize(const xvd_header* header, const char* filename);
uint64_t FindDynHeaderSize(const xvd_header* header, const char* filename);
uint64_t FindDriveSize(const xvd_header* header, const char* filename);
uint64_t FindDynamicOccupancy(const xvd_header* header, const char* filename);
uint64_t HashTreeSizeFromPageNum(uint64_t num_pages_to_hash, bool resilient);

//////////////////////////////////////////
// XVD Header parsing methods           //
//////////////////////////////////////////
// These methods return the file offset //
// at which the regions starts. Usually //
// this is computed as, the position of //
// the previous region, plus the size   //
// of this region. We get the size of   //
// the region mostly from the header,   //
// except in the cases where it's a tad //
// more complex and the size is unknown //
//////////////////////////////////////////

//////////////////////////////////////////
// eXVD                                 //
//////////////////////////////////////////
uint64_t FindEmbeddedXVDPosition(const xvd_header* header)
{
    // Embedded XVD, if existing, is always the first thing after
    // the header. Header is a fixed max size of 0x3000, so the eXVD
    // will always be at that offset. (if it is present)
    return 0x3000;
}

uint64_t FindEmbeddedXVDSize(const xvd_header* header)
{
    // If the header says eXVD length is 0, it means the XVD does
    // not come with an embedded XVD.
    return AlignSizeToPageBoundary(header->embedded_xvd_length);
}

//////////////////////////////////////////
// MDU                                  //
//////////////////////////////////////////
uint64_t FindMDUPosition(const xvd_header* header)
{
    // Mutable Data always comes after EmbeddedXVD. Thus
    // It will be found immediately after the EmbeddedXVD

    // Otherwise, mutable starts at the end of EmbeddedXVD
    return FindEmbeddedXVDPosition(header) + FindEmbeddedXVDSize(header);
}

uint64_t FindMDUSize(const xvd_header* header)
{
    // If header says there are no mutable pages, then there
    // is no mutable data region.
    return PagesToBytes(header->mutable_page_num); 
}

//////////////////////////////////////////
// HashTree                             //
//////////////////////////////////////////
uint64_t FindHashTreePosition(const xvd_header* header)
{
    // HashTree always comes after MDU. Thus it will be found
    // immediately after the mutable data region.
    return FindMDUPosition(header) + FindMDUSize(header);
}

uint64_t FindHashTreeSize(const xvd_header* header, const char* filename)
{
    // If data integrity is disabled, resiliency doesn't make any sense
    bool data_integrity_en  = !(header->flags.DataIntegrityDisabled);
    bool has_resiliency_en  = header->flags.resiliency_en;
    bool     exact_division = false;
    uint32_t hashed_pages  = 0;
    uint64_t bat_entries   = 0;
    uint64_t total_blocks_mapped = 0;
    uint64_t size_bytes    = 0;
    uint64_t size_in_pages = 0;

    // If data integrity isn't enabled, there isn't a HashTree! Duh!
    if(!data_integrity_en)
        return 0;

    // The size of the HashTree depends pretty much on the size of
    // the data that it hashes. In other words, the more data pages
    // that need to be hashed, the bigger the HashTree will be.

    // Most specifically, the following regions seem to be being hashed:
    // - Drive
    // - UserData
    // - XVC INFO
    // - Dynamic Header

    // So the first step is to find the size of each region (in disk) in
    // pages. For a static XVD we can just read them from the headers:
    if(header->xvd_type == FIXED)
    {
        hashed_pages = BytesToPages(
                                FindDriveSize(header, filename)    
                                + FindUserDataSize(header, filename)
                                + FindXVCSize(header, filename)
                                + FindDynHeaderSize(header, filename));
        //printf("#hashed_pages: %ld\n", hashed_pages);

        // Compute the size that the HashTree will have
        return HashTreeSizeFromPageNum(hashed_pages, has_resiliency_en);
    }
    else
    {
        // In the case of a Dynamic XVD, we have to "estimate" the sizes
        // of the BAT+UserData+XVC+Drive, since we cannot trust the values in the
        // header as the 'drive_size' represent the maximum storage, not the current occupancy.

        // Compute the size of drive + userdata + xvc from the DynHeader size in the header
        bat_entries = header->dynamic_header_length / BAT_ENTRY_SIZE;
        total_blocks_mapped = bat_entries;

        // 2. Compute the estimated size of the HashTree given the BAT size.
        //    In disk, the computed space must end up being page aligned!
        size_bytes = BlocksToBytes(total_blocks_mapped); 
        size_bytes = AlignSizeToPageBoundary(size_bytes);

        exact_division = (size_bytes % XVD_PAGE_SIZE) == 0;
        size_in_pages = (size_bytes) / XVD_PAGE_SIZE + (exact_division ? 0 : 1);
        return HashTreeSizeFromPageNum(size_in_pages, has_resiliency_en);
    }
}

uint64_t HashTreeSizeFromPageNum(uint64_t num_pages_to_hash, bool resilient)
{
    // Computes the size of an XVD HashTree given a number of pages
    // For a writeup of how this work check the XVDLith project (coming soon)

    // Count of how many pages each tree will be in size. See explanation above
    size_t total_hashtree_pages = 0;
    size_t pages_of_level[4] = {0, 0, 0, 0};
    #define LVL_0 0
    #define LVL_1 1
    #define LVL_2 2
    #define LVL_3 3

    #define HASHES_PER_PAGE 170
    
    // Compute the size of level 0, the leaf/data level
    bool is_exact_division = (num_pages_to_hash % 170) == 0;
    pages_of_level[LVL_0]  = (num_pages_to_hash / 170) + (is_exact_division ? 0 : 1);

    // If this level is already enough, down to one page, it's possible to compute the root hash so the HashTree ends here.
    total_hashtree_pages += pages_of_level[LVL_0];
    if(pages_of_level[LVL_0] <= 1)
    {
        goto done;
    }

    // Compute the size of level 1 
    is_exact_division     = (pages_of_level[LVL_0] % 170) == 0;
    pages_of_level[LVL_1] = (pages_of_level[LVL_0] / 170) + (is_exact_division ? 0 : 1);

    // If this level is already enough, down to one page, it's possible to compute the root hash so the HashTree ends here.
    total_hashtree_pages += pages_of_level[LVL_1];
    if(pages_of_level[LVL_1] <= 1)
    {
        goto done;
    }

    // Compute the size of level 2
    is_exact_division     = (pages_of_level[LVL_1] % 170) == 0;
    pages_of_level[LVL_2] = (pages_of_level[LVL_1] / 170) + (is_exact_division ? 0 : 1);

    // If this level is already enough, down to one page, it's possible to compute the root hash so the HashTree ends here.
    total_hashtree_pages += pages_of_level[LVL_2];
    if(pages_of_level[LVL_2] <= 1)
    {
        goto done;
    }

    // Compute the size of level 3
    is_exact_division     = (pages_of_level[LVL_2] % 170) == 0;
    pages_of_level[LVL_3] = (pages_of_level[LVL_2] / 170) + (is_exact_division ? 0 : 1);

    // XVD Does not really support more than 3 levels, so if there exists a level 3, it MUST be finally only one page in size.
    // Let's actually check for that, to make sure nothing went wrong.
    total_hashtree_pages += pages_of_level[LVL_3];
    if(pages_of_level[LVL_3] != 1) [[unlikely]]
    {
        printf("Here be dragons!!! BUG!\n");
    }

done:
    // Final check: If the resiliency flag was enabled, the size of the tree is just doubled
    if(resilient)
    {
        total_hashtree_pages = 2 * total_hashtree_pages;

        // No actual resilient xvd has ever been found so let's print something
        printf("Call the engineers, a rare resilient XVD has been found!\n");
    }

    // I know, I know... this code could be a little more optimal, sure. But it can't
    // get more readable or easier to understand! That's what we want when documenting
    // obscure formats for which there aren't public standards. Aren't you with me?

    // Return the size in bytes
    return total_hashtree_pages * XVD_PAGE_SIZE;
}

//////////////////////////////////////////
// UserData                             //
//////////////////////////////////////////
uint64_t FindUserDataPosition(const xvd_header* header, const char* filename)
{
    return FindHashTreePosition(header) + FindHashTreeSize(header, filename);
}

uint64_t FindUserDataSize(const xvd_header* header, const char* filename)
{
    return AlignSizeToPageBoundary(header->user_data_length); // UserData seemed to require alignment for the computations, yep
}

//////////////////////////////////////////
// XVC Region(s)                        //
//////////////////////////////////////////
uint64_t FindXVCPosition(const xvd_header* header, const char* filename)
{
    return FindUserDataPosition(header, filename) + FindUserDataSize(header, filename);
}

uint64_t FindXVCSize(const xvd_header* header, const char* filename)
{

    if(AlignSizeToPageBoundary(header->xvc_data_length) != header->xvc_data_length)
    {
        printf("INFO: xvc_data_length alignment problem - should probably not use alignment\n");
    }

    return AlignSizeToPageBoundary(header->xvc_data_length); // Alignment here might or might not be needed, but adding it just in case
}

// The XVC Region is itself divided in multiple regions (XVC_INFO, XVC_*****, etc)
// FindXVCSegmentsPositions?

//////////////////////////////////////////
// DynHeader                            //
//////////////////////////////////////////
uint64_t FindDynHeaderPosition(const xvd_header* header, const char* filename)
{
    return FindXVCPosition(header, filename) + FindXVCSize(header, filename);
}

uint64_t FindDynHeaderSize(const xvd_header* header, const char* filename)
{
    return header->dynamic_header_length; // NO Alignment 
}

//////////////////////////////////////////
// Drive                                //
//////////////////////////////////////////
uint64_t FindDrivePosition(const xvd_header* header, const char* filename)
{
    // If dynamic XVD, the drive will be after the DynHeader
    if(header->xvd_type == DYNAMIC)
        return FindDynHeaderPosition(header, filename) + FindDynHeaderSize(header, filename);

    // If static XVD, the drive will be after the XVC_REGION
    return FindXVCPosition(header, filename) + FindXVCSize(header, filename);
}

uint64_t FindDriveSize(const xvd_header* header, const char* filename)
{
    // Test stuff
    if(AlignSizeToPageBoundary(header->drive_size) != header->drive_size)
    {
        printf("found alignment problem - working w/o alignment\n");
        return header->drive_size;
    }

    if(header->xvd_type == FIXED)
        return AlignSizeToPageBoundary(header->drive_size);
    else
        return ComputeUsedDriveSizeInDynamicXVD(header, filename); // a whole ordeal
}

uint64_t FindDynamicOccupancy(const xvd_header* header, const char* filename)
{
    // Local variables
    char*    bat_data;
    FILE*    f;
    uint64_t bat_size  = header->dynamic_header_length;

    uint32_t entry               = 0;
    uint32_t max_entry           = 0;
    size_t   unallocated_entries = 0;
    size_t   allocated_entries   = 0;
    int      curr_entry          = 0;
    uint64_t bat_entries         = bat_size / 4;

    // This will actually return just the max, since it takes into account the drive_size which is a maximum
    //return ((header->dynamic_header_length / BAT_ENTRY_SIZE) * 0xAA000);

    // TODO PHOTOREC: Move this logic elsewhere

    // 1. Find the BAT offset. This is now possible since we know the sizes of all previous regions (especially the HashTree)
    //     HashTree comes always after MDU and then we have user data, XVC, and finally we'd reach the BAT start offset.
    uint64_t bat_start = FindHashTreePosition(header) + FindHashTreeSize(header, filename) + 
                    + header->user_data_length 
                    + header->xvc_data_length;

    // 2. Iterate through the BAT entries and find the biggest valid entry. This basically maps the latest (bigger) block of the physical file.
    f = fopen(filename, "rb");
    if (f == NULL) {
        fprintf(stderr, "ERR: Failed to open file '%s'!\n", filename);
        return 2;
    }
    // Allocate a buffer to read the BAT
    bat_data = (char *)calloc(1, bat_size);
    fseek(f, bat_start, SEEK_SET);
    fread(bat_data, 1, bat_size, f);
    fclose(f);

    // Start iterating until last valid BAT entry is found.
    // Each block is mapped by one entry. There are as many entries as blocks
    for(curr_entry; curr_entry < bat_entries; curr_entry++)
    {
        // Invalid entry found. Ignore it
        uint32_t entry = ((uint32_t*)bat_data)[curr_entry];
        if(entry == (uint32_t)XVD_INVALID_BLOCK)
        {
            unallocated_entries++;
            continue;
        }
        
        // Save the latest found valid entry that is a bigger offset than what previously found
        allocated_entries++;
        if(max_entry < entry)
            max_entry = entry;        
    }

    free(bat_data);
    
    // I have not figured exactly why I have to add +1 to the number of BAT entries unfortunately. 
    // The count of allocated entries is correct, so the +1 shouldn't be needed, but it is.
    return (allocated_entries+1) * XVD_BLOCK_SIZE;
}

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_xvd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  // Local variables
  uint64_t computed_filesize = 0;
  const xvd_header *xvd=(const xvd_header *)buffer;

  // Check if xvd type is either dynamic or fixed
  if (xvd->xvd_type != FIXED && xvd->xvd_type != DYNAMIC)
    return 0;
  
  // Check the block size is standard
  if (xvd->block_size != 0xAA000)
    return 0;

  // PhotoRec setup
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xvd.extension;

  // TODO/IMPROVEMENT: We might be able to set the filename to the XVD's PDUID instead of the random filename PhotoRec assigns
  //file_recovery->filename 

  // TODO/IMPROVEMENT: We might be able to set the filename extension to .xvd
  //file_recovery->extension 

  // Compute the expected XVD size
  if(xvd->xvd_type == FIXED)
  {
      computed_filesize = 
      (
          XVD_HEADER_INCL_SIGNATURE           +  // Header + Sig
          FindEmbeddedXVDSize(xvd)            +  // Size of the embedded XVD
          FindMDUSize(xvd)                    +  // Size of mutable XVC info
          FindHashTreeSize(xvd, filename)     +  // Size of the HashTree
          FindUserDataSize(xvd, filename)     +  // Size of user data region
          FindXVCSize(xvd, filename)          +  // Size of XVC Region
          FindDynHeaderSize(xvd, filename)    +  // This will be 0 anyways since it's a fixed XVD...
          FindDriveSize(xvd, filename)           // Size of the static Drive
      );
  }
  else
  {
      computed_filesize = 
      (
          XVD_HEADER_INCL_SIGNATURE           +  // Header + Sig
          FindEmbeddedXVDSize(xvd)            +  // Size of the embedded XVD
          FindMDUSize(xvd)                    +  // Size of mutable XVC info
          FindHashTreeSize(xvd, filename)        // Size of the HashTree (in this case it'll be computed differently)
      );

      // On Dynamic XVDs, data can be added or deleted, thus changing the container size.
      // This affects the UserData, XVC and Drive regions, but also the BAT/DynamicHeader,
      // which keeps tracks of the mappings for the previously mentioned regions, thus it
      // also changes.
      computed_filesize += FindDynamicOccupancy(xvd, filename);
  }

  // Just hardcode 70 MB, that should be fine to dump updater.xvd
  file_recovery_new->calculated_file_size=computed_filesize;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_xvd(file_stat_t *file_stat)
{
  static const unsigned char xvd_magic[8]=  { 'm' , 's' , 'f' , 't', '-', 'x', 'v', 'd' };
  
  //TODO: Figure how to pass the BAT offset to the function that parses the header
  // Can we do a pre-parse in this method, compute the BAT address, and pass a buffer
  // big enough to contain it? For dynamic XVDs we need it to discover the actual file
  // size, which is based on occupancy.

  register_header_check(0x200, xvd_magic, sizeof(xvd_magic), &header_check_xvd, file_stat);
}
#endif

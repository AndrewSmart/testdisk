/*

    File: file_flv.c

    Copyright (C) 2007,2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "log.h"

static void register_header_check_flv(file_stat_t *file_stat);

const file_hint_t file_hint_flv= {
  .extension="flv",
  .description="Macromedia",
  .max_filesize=200*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_flv
};

struct flv_header
{
  char 		signature[3]; //Always 'FLV'
  uint8_t	version;
  uint8_t	type_flags;
  //uint8_t	type_flags_reserved:5; //Must be 0
  //uint8_t	type_flags_audio:1; //Audio tags are present
  //uint8_t	type_flags_reserved2:1; //Must be 0
  //uint8_t	type_flags_video:1; //Video tags are present
  uint32_t	data_offset; //Size of header (usually 9 for FLV v1).
} __attribute__ ((gcc_struct, __packed__));

struct flv_tag
{
  uint32_t	prev_tag_size; //Always 0 for first tag in file.
  uint8_t	info;
  uint8_t	data_size[3];
  uint8_t	timestamp[3]; //In ms relative to first tag, which is always 0.
  uint8_t	timestamp_ext; //Extension of timestamp to form SI32. This is upper 8 bits.
  uint8_t	streamID[3]; //Always 0
} __attribute__ ((gcc_struct, __packed__));

static data_check_t resume_check_flv(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  //Search for 3 contiguous zero bytes, then if found then use flv_tag lens to verify remainder.
  unsigned int i = 10; //offset to streamID zeros
  for(; i < buffer_size; i+=3)
  {
    if(buffer[i]==0 && buffer[i+1]==0 && buffer[i+2]==0)
    {
      //Now check flv_tag
      const struct flv_tag *tag=(const struct flv_tag *)&buffer[i-10];
      if((tag->info&0xc0)==0 && tag->prev_tag_size != 0)
      {
        uint32_t datasize=(tag->data_size[0]<<16) | (tag->data_size[1]<<8) | tag->data_size[2];
        uint32_t timestamp=(tag->timestamp_ext << 24) | (tag->timestamp[0]<<16) | (tag->timestamp[1]<<8) | tag->timestamp[2];
        //We for sure didn't hit end tag in the middle of nowhere, so datasize won't be zero (as last flv tag will have datasize of zero with no datachunk).
        //And assume this new tag is within a half hour of the last known tag's timestamp.
        if(datasize != 0 && timestamp > file_recovery->last_flvpacket_unixtimestamp && timestamp <= (file_recovery->last_flvpacket_unixtimestamp + 1800000))
        {
          return DC_CONTINUE; // Found a timestamp at offset i into buffer. How to get data_check_flv to resume here?
        }
      }
    }
  }
  return DC_ERROR; //No matches in this buffer.
}

static data_check_t data_check_flv(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  static uint32_t datasize=0;
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 15 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct flv_tag *tag=(const struct flv_tag *)&buffer[i];
#ifdef DEBUG_FLV
    log_info("cfs=0x%llx datasize=%u\n", (long long unsigned)file_recovery->calculated_file_size, datasize);
#endif
    if((be32(tag->prev_tag_size)==0 && file_recovery->calculated_file_size < buffer_size/2) ||
      be32(tag->prev_tag_size)==11+datasize)
    {
      datasize=(tag->data_size[0]<<16) | (tag->data_size[1]<<8) | tag->data_size[2];
      if((tag->info&0xc0)!=0 || datasize==0
	  || tag->streamID[0]!=0 || tag->streamID[1]!=0 || tag->streamID[2]!=0 )
      {
	file_recovery->calculated_file_size+=4;
#ifdef DEBUG_FLV
	log_info("data_check_flv DC_STOP datasize:%u taginfo 0xc0:%u tagStreamId0:%u tagStreamId1:%u tagStreamId2:%u\n", datasize, tag->info&0xc0, tag->streamID[0], tag->streamID[1], tag->streamID[2]);
#endif
	return DC_STOP;
      }
      file_recovery->last_flvpacket_unixtimestamp =(tag->timestamp_ext << 24) | (tag->timestamp[0]<<16) | (tag->timestamp[1]<<8) | tag->timestamp[2];
      file_recovery->calculated_file_size+=4+11+datasize;
    }
    else
    {
#ifdef DEBUG_FLV
      log_info("data_check_flv DC_ERROR datasize:%u tag->prev_tag_size:%u tag->info:%u tagStreamId0:%u tagStreamId1:%u tagStreamId2:%u\n", datasize, tag->prev_tag_size, tag->info, tag->streamID[0], tag->streamID[1], tag->streamID[2]);
#endif
      return DC_ERROR;
    }
  }
  return DC_CONTINUE;
}

static int header_check_flv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct flv_header *flv=(const struct flv_header *)buffer;
  if((flv->type_flags & 0xfa)==0 && be32(flv->data_offset)>=9)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_flv.extension;
    if(file_recovery_new->blocksize < 15)
      return 1;
    file_recovery_new->calculated_file_size=be32(flv->data_offset);
    file_recovery_new->resume_check=&resume_check_flv;
    file_recovery_new->data_check=&data_check_flv;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_flv(file_stat_t *file_stat)
{
  static const unsigned char flv_header[4]= {'F', 'L', 'V', 0x01};
  register_header_check(0, flv_header,sizeof(flv_header), &header_check_flv, file_stat);
}

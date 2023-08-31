#ifndef RHASH_TEST_DATA_H
#define RHASH_TEST_DATA_H

#include "rc_export.h"

#include <stdint.h>
#include <stddef.h>

RC_BEGIN_C_DECLS

uint8_t* generate_generic_file(size_t size);

uint8_t* convert_to_2352(uint8_t* input, size_t* input_size, uint32_t first_sector);

uint8_t* generate_3do_bin(uint32_t root_directory_sectors, uint32_t binary_size, size_t* image_size);
uint8_t* generate_dreamcast_bin(uint32_t track_first_sector, uint32_t binary_size, size_t* image_size);
uint8_t* generate_jaguarcd_bin(uint32_t header_offset, uint32_t binary_size, int byteswapped, size_t* image_size);
uint8_t* generate_pce_cd_bin(uint32_t binary_sectors, size_t* image_size);
uint8_t* generate_pcfx_bin(uint32_t binary_sectors, size_t* image_size);
uint8_t* generate_psx_bin(const char* binary_name, uint32_t binary_size, size_t* image_size);
uint8_t* generate_ps2_bin(const char* binary_name, uint32_t binary_size, size_t* image_size);

uint8_t* generate_atari_7800_file(size_t kb, int with_header, size_t* image_size);
uint8_t* generate_nes_file(size_t kb, int with_header, size_t* image_size);
uint8_t* generate_fds_file(size_t sides, int with_header, size_t* image_size);
uint8_t* generate_nds_file(size_t mb, uint32_t arm9_size, uint32_t arm7_size, size_t* image_size);
uint8_t* generate_gamecube_iso(size_t mb, size_t* image_size);

uint8_t* generate_iso9660_bin(uint32_t binary_sectors, const char* volume_label, size_t* image_size);
uint8_t* generate_iso9660_file(uint8_t* image, const char* filename, const uint8_t* contents, size_t contents_size);

uint8_t* generate_zip_file(size_t* image_size);
uint8_t* generate_zip64_file(size_t* image_size);

extern uint8_t test_rom_z64[64];
extern uint8_t test_rom_n64[64];
extern uint8_t test_rom_v64[64];
extern uint8_t test_rom_ndd[64];

RC_END_C_DECLS

#endif /* RHASH_TEST_DATA_H */

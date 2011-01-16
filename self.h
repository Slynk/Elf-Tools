#ifndef SELF_H
#define SELF_H

#include <inttypes.h>
 
typedef struct
{
uint32_t magic;                   // "SCE\0"
uint32_t version;                 // 2
uint16_t flags;               // 0x8000 - fself
uint16_t header_type;
uint32_t meta_offset;
uint64_t fileOffset;
uint64_t fileSize;
uint64_t unknown;
uint64_t app_info_offset;
uint64_t elf_offset;
uint64_t phdr_offset;
uint64_t shdr_offset;
uint64_t sInfoOffset;
uint64_t sceversion;
uint64_t digest;
uint64_t digest_size;
} Self_Hdr;
 
typedef struct
{
uint64_t authid;
uint32_t vendorid;
uint32_t app_type;
uint64_t app_version;
} Self_Appinfo;

typedef struct
{
uint64_t sectionoffset;                   // Location of the section data
uint64_t sizeofsection;                   // Size of the section data
uint64_t unknown;                        // Not quite sure what this is
uint64_t encryptionflag;                 // 0x0000000000000001 = Encrypted, 0x0000000000000002 == Unencrypted
} sInfoEntry;

typedef struct {
  uint8_t version[0x10];
} Self_SDKversion;

typedef struct {
  uint8_t cflags1[0x10];
  uint8_t cflags2[0x20];
  uint8_t cflags3[0x10];
  uint8_t hashes[0x30];
} Self_Cflags;

typedef struct {
  uint64_t pm_offset;
  uint64_t pm_size;
  uint32_t pm_compressed; // 2 for compressed, 1 for pt
  uint32_t pm_unknown2;
  uint32_t pm_unknown3;
  uint32_t pm_encrypted;  // 1 for encrypted
} Self_PMhdr;   // phdr map

typedef struct  {
	uint32_t idx;
	uint64_t offset;
	uint64_t size;
	uint32_t compressed;
	uint32_t encrypted;
	uint64_t next;
} Self_Sec;

typedef uint8_t METADATAKEY_t[16];

typedef struct
{
  uint8_t unknown00[32];
  uint8_t key[32];
  uint8_t ivec[32];
} Metadata_Info;

typedef struct
{
  uint32_t unknown00;
  uint32_t size;
  uint32_t unknown02;
  uint32_t sectionCount;
  uint32_t keyCount;
  uint32_t unknown05;
  uint32_t unknown06;
  uint32_t unknown07;
} Metadata_Hdr;

typedef struct
{
  uint64_t dataOffset;
  uint64_t dataSize;
  uint32_t unknown02;
  uint32_t programIndex;
  uint32_t unknown04;
  uint32_t sha1Index;
  uint32_t encrypted;  //1:NO, 3:YES
  uint32_t keyIndex;
  uint32_t ivecIndex;
  uint32_t compressed; //1:NO, 2:YES
} Metadata_Sec_Hdr;


#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "self.h"
#include "elf32.h"
#include "elf64.h"
#include "common.h"

#define	MAX_SECTIONS	255

static uint8_t *self = NULL;
static uint8_t *elf = NULL;
static FILE *out = NULL;
static uint8_t *bfr = NULL;
static uint8_t *program_sections = NULL;
static uint8_t *section_segments = NULL;
static uint8_t *program_headers = NULL;
static uint8_t *section_headers = NULL;

static int decrypted = -1;

int elf_size = 0;

Self_Hdr Self_Header;
Self_Appinfo Self_App_Info;
sInfoEntry Info_Area;
Metadata_Info Meta_Info;
Metadata_Hdr Meta_Header;
Metadata_Sec_Hdr Meta_Section_Header[30];
METADATAKEY_t Meta_Keys[100];


Elf64_Ehdr Elf_Header;

static struct keylist *self_load_keys(void)
{
	enum sce_key id;

	switch (get_u32(&Self_App_Info.app_type)) {
		case 1:
			id = KEY_LV0;
			break;
	 	case 2:
			id = KEY_LV1;
			break;
		case 3:
			id = KEY_LV2;
			break;
		case 4:	
			id = KEY_APP;
			break;
		case 5:
			id = KEY_ISO;
			break;
		case 6:
			id = KEY_LDR;
			break;
		case 8:
			return NULL;
			break;
		default:
			fail("invalid type: %08x", Self_App_Info.app_type);	
	}

	return keys_get(id);
}

void read_headers(void)
{
    memcpy(&Self_Header, self, sizeof(Self_Header));
    memcpy(&Self_App_Info, self + get_u64(&Self_Header.app_info_offset), sizeof(Self_App_Info));
    memcpy(&Elf_Header, self + get_u64(&Self_Header.elf_offset), sizeof(Elf_Header));
    memcpy(&Info_Area, self + get_u64(&Self_Header.sInfoOffset), sizeof(Info_Area));
    
    decrypt_metadata();
    
    
    memcpy(&Meta_Info, self + get_u32(&Self_Header.meta_offset),sizeof(Meta_Info));
    
    
    memcpy(&Meta_Header, self + get_u32(&Self_Header.meta_offset) + sizeof(Meta_Info),sizeof(Meta_Header));
    
}

void decrypt_metadata(void)
{
	struct keylist *klist;

	klist = self_load_keys();
	if (klist == NULL)
		return;

	decrypted = sce_decrypt_header(self, klist);
	free(klist);
}

void grab_metadata_section_headers(void)
{
    int i;
    
    int section_offset = get_u32(&Self_Header.meta_offset) + sizeof(Meta_Info) + sizeof(Meta_Header);
    
    for(i = 0; i < get_u32(&Meta_Header.sectionCount); i++)
    {
	memcpy(&Meta_Section_Header[i], self + section_offset + (i * sizeof(Meta_Section_Header[i])), sizeof(Meta_Section_Header[i])); 
    }
}

void grab_metadata_keys(void)
{
    int i;
    
    int key_offset = get_u32(&Self_Header.meta_offset) + sizeof(Meta_Info) + sizeof(Meta_Header) + (get_u32(&Meta_Header.sectionCount) *  sizeof(Meta_Section_Header[0]));
    
    for(i = 0; i < get_u32(&Meta_Header.keyCount); i++)
    {
	memcpy(&Meta_Keys[i], self + key_offset + (i * sizeof(Meta_Keys[i])), sizeof(Meta_Keys[i]));
    }
}

void copy_program_headers(void)
{    
    int size = get_u16(&Elf_Header.e_phnum) * sizeof(Elf64_Phdr);
    program_headers =(uint8_t*)malloc(size);
    
    memcpy(program_headers, self + get_u64(&Self_Header.phdr_offset), size);
}

void decrypt_program_sections(void)
{
      int i;
      
      int bfr_size = get_u16(&Elf_Header.e_phentsize);
      int size = get_u32(&Meta_Header.sectionCount) *get_u16(&Elf_Header.e_phentsize);
      
      bfr = (uint8_t*)malloc(bfr_size + 1);
      program_sections =(uint8_t*)malloc(size + 1);
      memset(program_sections, 0, size);
      
      for(i = 0; i < get_u32(&Meta_Header.sectionCount); i++)
      {
	 printf("Pass %i\nSection Address %i\nSection Csize %i\nSection Size %i\n", i, self + get_u64(&Meta_Section_Header[i].dataOffset), get_u64(&Meta_Section_Header[i].dataSize), get_u16(&Elf_Header.e_phentsize)); //Debug
	 if(get_u32(&Meta_Section_Header[i].encrypted) == 3)
	    aes128ctr(&Meta_Keys[get_u32(&Meta_Section_Header[i].keyIndex)], &Meta_Keys[get_u32(&Meta_Section_Header[i].ivecIndex)], self + get_u64(&Meta_Section_Header[i].dataOffset), get_u64(&Meta_Section_Header[i].dataSize), self + get_u64(&Meta_Section_Header[i].dataOffset));
	 
	 if((get_u64(&Meta_Section_Header[i].dataSize) != 0) && (get_u32(&Meta_Section_Header[i].compressed) == 2))
	    decompress(self + get_u64(&Meta_Section_Header[i].dataOffset), get_u64(&Meta_Section_Header[i].dataSize), program_sections + (i * get_u16(&Elf_Header.e_phentsize)), get_u16(&Elf_Header.e_phentsize));
	 else
	   memcpy(program_sections + (i * bfr_size), self + get_u64(&Meta_Section_Header[i].dataOffset), bfr_size);	 
      }
      
      free(bfr);
      
      sort_program_sections();
}

void sort_program_sections(void)
{
    int i;
    int size = get_u32(&Meta_Header.sectionCount) *get_u16(&Elf_Header.e_phentsize);
  
    uint8_t *temp = (uint8_t*)malloc(size);
    
    for(i = 0; i < get_u32(&Meta_Header.sectionCount); i++)
    {
	memcpy(temp + (i * get_u16(&Elf_Header.e_phentsize)), program_sections + (get_u32(&Meta_Section_Header[i].programIndex) * get_u16(&Elf_Header.e_phentsize)), get_u16(&Elf_Header.e_phentsize));
    }
    
    memcpy(program_sections, temp, size);
}

void copy_section_headers(void)
{
    int size = get_u16(&Elf_Header.e_shnum) * sizeof(Elf64_Shdr);
  
    section_headers =(uint8_t*)malloc(size);
    
    memcpy(section_headers, self + get_u64(&Self_Header.shdr_offset), size);
}

void copy_section_segments(void)
{
    int i;
    int offset = get_u64(&Info_Area.sectionoffset);
    int bfr_size = get_u16(&Elf_Header.e_shentsize);
    int size = get_u16(&Elf_Header.e_shnum) * bfr_size;
    
    bfr = (uint8_t*)malloc(bfr_size);
    section_segments =(uint8_t*)malloc(size);
    
    for(i = 0; i < get_u16(&Elf_Header.e_shnum); i++)
    {
	///Find Segment area of SELF
	memcpy(bfr, self + offset + (i * bfr_size), bfr_size);
	
	memcpy(section_segments + (i * bfr_size), bfr, bfr_size);	
    }
}

void write_elf(void)
{
    int i;
    int offset = 0;
    int p_size = get_u16(&Elf_Header.e_phentsize);
    int s_size = get_u16(&Elf_Header.e_shentsize);
    
    Elf64_Shdr tmp;
    Elf64_Phdr tmp2;
    
    memcpy(&tmp, section_headers + ((get_u16(&Elf_Header.e_shnum) - 1) * sizeof(Elf64_Shdr)), sizeof(Elf64_Shdr)); /// Last header of the file for sizing
  
    ///Create Virtual Elf
    elf_size = get_u64(&tmp.sh_offset) + get_u16(&Elf_Header.e_shentsize);
    elf = (uint8_t*)malloc(elf_size);
    memset(elf, 0, elf_size);
    
    ///Copy Elf Header
    memcpy(elf, &Elf_Header, sizeof(Elf64_Ehdr)); 
    
    ///Copy Program Headers and Data
    offset = get_u64(&Elf_Header.e_phoff);
    
    int prev = 0;
    int cur = 0;
    
    for(i = 0; i < get_u16(&Elf_Header.e_phnum); i++)
    {
	memcpy(&tmp2, program_headers + (i * sizeof(Elf64_Phdr)), sizeof(Elf64_Phdr));
	memcpy(elf + offset, &tmp2, sizeof(Elf64_Phdr));
	
	offset = get_u64(&tmp2.p_offset);
	cur = offset;
	printf("Program Padding %d: %d\n", i, (cur - prev - sizeof(tmp2)));
	if(get_u64(&tmp2.p_offset) != 0)
	  memcpy(elf + offset, program_sections + (i * p_size), p_size);
	
	offset = get_u64(&Elf_Header.e_phoff) + (sizeof(Elf64_Phdr) * (i + 1));
	
	prev = cur;
    }
    printf("\n\n");
    ///Copy Section Headers and Data
    offset = get_u64(&Elf_Header.e_shoff);
    
    for(i = 0; i < get_u16(&Elf_Header.e_shnum); i++)
    {
	memcpy(&tmp, section_headers + (i * sizeof(Elf64_Shdr)), sizeof(Elf64_Shdr));
	memcpy(elf + offset, &tmp, sizeof(Elf64_Shdr));
	
	offset = get_u64(&tmp.sh_offset);
	cur = offset;
	printf("Program Padding %d: %d\n", i, (cur - prev - sizeof(tmp)));
	if(get_u64(&tmp.sh_offset) != 0)
	  memcpy(elf + offset, section_segments + (i * s_size), s_size);
	
	offset = get_u64(&Elf_Header.e_shoff) + (sizeof(Elf64_Shdr) * (i + 1));	
	
	prev = cur;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
      fail("usage: extract_elf in.self out.elf\n");
    
    FILE *input;
    input = fopen(argv[1], "rb");
    
    fseek(input, 0, SEEK_END);
    int self_length = ftell(input);
    fseek(input, 0, SEEK_SET);
    self = (uint8_t*)malloc(self_length);
    fread(self, 1, self_length, input);
    fclose(input);
    
    read_headers();
    
    grab_metadata_section_headers();
    
    grab_metadata_keys();
    
    decrypt_program_sections();
    
    copy_program_headers();
    
    copy_section_headers();
    
    copy_section_segments();
    
    write_elf();
    
    out = fopen(argv[2], "wb");
    fseek(out, 0, SEEK_SET);
    fwrite(elf, sizeof(elf), elf_size, out);
    fclose(out);
    
    free(elf);
    free(bfr);
    free(program_sections);
    free(section_segments);
    free(program_headers);
    free(section_headers);

}
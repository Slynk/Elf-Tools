#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf32.h"
#include "elf64.h"
#include "common.h"

///Global Variables
static int arch = -1;
static u_int8_t *elf = NULL;

Elf32_Ehdr Elf_Header32;
Elf32_Phdr Elf_Program_Header32;
Elf32_Shdr Elf_Section_Header32;

Elf64_Ehdr Elf_Header64;
Elf64_Phdr Elf_Program_Header64;
Elf64_Shdr Elf_Section_Header64;


///Header Idnentity Checks
void test_identity(void)
{
  ///Copy the identity array
  memcpy(&e_ident, elf, sizeof(e_ident));
  
  printf("\nTesting the Identity array\n");
  printf("--------------------------\n");
  ///Test for magic
  if(e_ident[EI_MAG0] != ELFMAG0 ||
     e_ident[EI_MAG1] != ELFMAG1 ||
     e_ident[EI_MAG2] != ELFMAG2 ||
     e_ident[EI_MAG3] != ELFMAG3)
    printf("Wow... you didn't even set the Elf magic correctly...\n");
  else
    printf("Magic --- Check!\n");
  
  
  ///Test Archetecture
  switch(e_ident[EI_CLASS]){
      case ELFCLASSNONE:
	  arch = 0;
	  printf("Archetecture: Unkown\n");
	  break;
      case ELFCLASS32:
	  arch = 32;
	  printf("Archetecture: 32 bit\n");
	  break;
      case ELFCLASS64:
	  arch = 64;
	  printf("Archetecture: 64 bit\n");
	  break;
      default:
	  printf("What the hell did you set the Archetecture to?\n");
  }
    
  ///Test Data Format
  switch(e_ident[EI_DATA]){
      case ELFDATANONE:
	  printf("Data format: Unkown\n");
	  break;
      case ELFDATA2LSB:
	  printf("Data format: 2's complement little-endian\n");
	  break;
      case ELFDATA2MSB:
	  printf("Data format: 2's complement big-endian\n");
	  break;
      default:
	  printf("Data format is borken...\n");
  }
  
  ///Test Elf Format Version
  switch(e_ident[EI_VERSION]){
      case EV_NONE:
	  printf("Elf Format Version: None\n");
	  break;
      case EV_CURRENT:
	  printf("Elf Format Version: Current\n");
	  break;
      default:
	  printf("Your elf format version is incorrect <.<\n");
  }
  
  ///Test Operating System
  switch(e_ident[EI_OSABI]){
      case ELFOSABI_SYSV:
	  printf("Operating Systm: UNIX System V ABI\n");
	  break;
      case ELFOSABI_HPUX:
	  printf("Operating Systm: HP-UX operating system\n");
	  break;
      case ELFOSABI_NETBSD:
	  printf("Operating Systm: NetBSD\n");
	  break;
      case ELFOSABI_LINUX:
	  printf("Operating Systm: GNU/Linux\n");
	  break;
      case ELFOSABI_HURD:
	  printf("Operating Systm: GNU/Hurd\n");
	  break;
      case ELFOSABI_86OPEN:
	  printf("Operating Systm: 86Open common IA32 ABI\n");
	  break;
      case ELFOSABI_SOLARIS:
	  printf("Operating Systm: Solaris\n");
	  break;
      case ELFOSABI_MONTEREY:
	  printf("Operating Systm: Monterey\n");
	  break;
      case ELFOSABI_IRIX:
	  printf("Operating Systm: IRIX n");
	  break;
      case ELFOSABI_FREEBSD:
	  printf("Operating Systm: FreeBSD\n");
	  break;
      case ELFOSABI_TRU64:
	  printf("Operating Systm: TRU64 UNIX\n");
	  break;
      case ELFOSABI_MODESTO:
	  printf("Operating Systm: Novell Modesto\n");
	  break;
      case ELFOSABI_OPENBSD:
	  printf("Operating Systm: OpenBSD\n");
	  break;
      case ELFOSABI_ARM:
	  printf("Operating Systm: ARM\n");
	  break;
      case ELFOSABI_STANDALONE:
	  printf("Operating Systm: Standalone (embedded) application \n");
	  break;
      default:
	  printf("Operating System is invalid type...\n");
  }
  
  ///Test ABI Version
  printf("ABI Version: %d\n", e_ident[EI_ABIVERSION]);
  
  ///Test Old Elf Input Brand
  printf("Old Brand: %d\n", e_ident[OLD_EI_BRAND]);
  
  ///Test Padding
  printf("Padding: %d\n", e_ident[EI_PAD]);
  
  printf("\n\n");
}

void test_header32(void)
{
  //Elf32_Ehdr Elf_Header32;
  memcpy(&Elf_Header32, elf, sizeof(Elf_Header32));
  
  printf("\nTesting Elf Header\n");
  printf("------------------\n");
  
  ///Test File Type  
  switch(get_u16(&Elf_Header32.e_type))
  {
    case ET_NONE:
      printf("File Type: Unknown Type\n");
      break;
    case ET_REL:
      printf("File Type: Relocatable\n");
      break;
    case ET_EXEC:
      printf("File Type: Executable\n");
      break;
    case ET_DYN:
      printf("File Type: Shared Object\n");
      break;
    case ET_CORE:
      printf("File Type: Core File\n");
      break;
    default:
      printf("Incorrect File Type Set");
  }
  
  ///Test Machine Architecture
  switch(get_u16(&Elf_Header32.e_machine)){
      case EM_NONE:
	  printf("Machine Architecture: Unkown\n");
	  break;
      case EM_M32:
	  printf("Machine Architecture: AT&T WE32100\n");
	  break;
      case EM_SPARC:
	  printf("Machine Architecture: Sun SPARC\n");
	  break;
      case EM_386:
	  printf("Machine Architecture: Intel i386\n");
	  break;
      case EM_68K:
	  printf("Machine Architecture: Motorola 68000\n");
	  break;
      case EM_88K:
	  printf("Machine Architecture: Motorola 88000\n");
	  break;
      case EM_486:
	  printf("Machine Architecture: Intel i486\n");
	  break;
      case EM_860:
	  printf("Machine Architecture: Intel i860\n");
	  break;
      case EM_MIPS:
	  printf("Machine Architecture: MIPS R3000 Big-Endian only\n");
	  break;
      case EM_S370:
	  printf("Machine Architecture: IBM System/370\n");
	  break;
      case EM_MIPS_RS4_BE:
	  printf("Machine Architecture: MIPS R4000 Big-Endian\n");
	  break;
      case EM_PARISC:
	  printf("Machine Architecture: HPPA\n");
	  break;
      case EM_SPARC32PLUS:
	  printf("Machine Architecture: SPARC v8plus\n");
	  break;
      case EM_PPC:
	  printf("Machine Architecture: PowerPC 32-bit\n");
	  break;
      case EM_PPC64:
	  printf("Machine Architecture: PowerPC 64-bit\n");
	  break;
      case EM_ARM:
	  printf("Machine Architecture: ARM \n");
	  break;
      case EM_SPARCV9:
	  printf("Machine Architecture: SPARC v9 64-bit\n");
	  break;
      case EM_IA_64:
	  printf("Machine Architecture: Intel IA-46 Processor\n");
	  break;
      case EM_X86_64:
	  printf("Machine Architecture: Advanced Micro Devices x86-64\n");
	  break;
      default:
	  printf("Machine Architecture is invalid type...\n");
  }
  
  ///Test Elf Format Version
  if(get_u32(&Elf_Header32.e_version) == EV_NONE)
    printf("Elf Format Version: None\n");
  else if(get_u32(&Elf_Header32.e_version) == EV_CURRENT)
    printf("Elf Format Version: Current\n");
  else
    printf("Incorrect Elf Format");
  
  
  ///Test Entry Point
  printf("Entry Point: %d\n", get_u32(&Elf_Header32.e_entry));
  
  ///Test Program Header File Offset
  printf("Program Header File Offset: %d\n", get_u32(&Elf_Header32.e_phoff));
  
  ///Test Section Header File Offset
  printf("Section Header File Offset: %d\n", get_u32(&Elf_Header32.e_shoff));
  
  ///Test Flags
  printf("Flags: %d\n", get_u32(&Elf_Header32.e_flags));
  
  ///Test Size of Header in Bytes
  printf("Size of Header: %d\n", get_u16(&Elf_Header32.e_ehsize));
  
  ///Test Size of Program Header Entry
  printf("Size of Program Header Entry: %d\n", get_u16(&Elf_Header32.e_phentsize));
  
  ///Test Number of Program Header Entries
  printf("Program Header Entries: %d\n",get_u16(&Elf_Header32.e_phnum));
  
  ///Test Size of Section Header Entry
  printf("Size of Section Header Entry: %d\n", get_u16(&Elf_Header32.e_shentsize));
  
  ///Test Number of Section Header Entries
  printf("Number of Section Header Entries: %d\n", get_u16(&Elf_Header32.e_shnum));
  
  ///Test Section Name Strings Section
  printf("Section Name Strings Section: %d\n", get_u16(&Elf_Header32.e_shstrndx));
  
  printf("\n\n");
}

void test_header64(void)
{
 // Elf64_Ehdr Elf_Header64;
  memcpy(&Elf_Header64, elf, sizeof(Elf_Header64));
  
  printf("\nTesting Elf Header\n");
  printf("------------------\n");
  
  ///Test File Type
  switch(get_u16(&Elf_Header64.e_type))
  {
    case ET_NONE:
      printf("File Type: Unknown Type\n");
      break;
    case ET_REL:
      printf("File Type: Relocatable\n");
      break;
    case ET_EXEC:
      printf("File Type: Executable\n");
      break;
    case ET_DYN:
      printf("File Type: Shared Object\n");
      break;
    case ET_CORE:
      printf("File Type: Core File\n");
      break;
    default:
      printf("Incorrect File Type Set");
  } 
  
  ///Test Machine Architecture
  switch(get_u16(&Elf_Header64.e_machine)){
      case EM_NONE:
	  printf("Machine Architecture: Unkown\n");
	  break;
      case EM_M32:
	  printf("Machine Architecture: AT&T WE32100\n");
	  break;
      case EM_SPARC:
	  printf("Machine Architecture: Sun SPARC\n");
	  break;
      case EM_386:
	  printf("Machine Architecture: Intel i386\n");
	  break;
      case EM_68K:
	  printf("Machine Architecture: Motorola 68000\n");
	  break;
      case EM_88K:
	  printf("Machine Architecture: Motorola 88000\n");
	  break;
      case EM_486:
	  printf("Machine Architecture: Intel i486\n");
	  break;
      case EM_860:
	  printf("Machine Architecture: Intel i860\n");
	  break;
      case EM_MIPS:
	  printf("Machine Architecture: MIPS R3000 Big-Endian only\n");
	  break;
      case EM_S370:
	  printf("Machine Architecture: IBM System/370\n");
	  break;
      case EM_MIPS_RS4_BE:
	  printf("Machine Architecture: MIPS R4000 Big-Endian\n");
	  break;
      case EM_PARISC:
	  printf("Machine Architecture: HPPA\n");
	  break;
      case EM_SPARC32PLUS:
	  printf("Machine Architecture: SPARC v8plus\n");
	  break;
      case EM_PPC:
	  printf("Machine Architecture: PowerPC 32-bit\n");
	  break;
      case EM_PPC64:
	  printf("Machine Architecture: PowerPC 64-bit\n");
	  break;
      case EM_ARM:
	  printf("Machine Architecture: ARM \n");
	  break;
      case EM_SPARCV9:
	  printf("Machine Architecture: SPARC v9 64-bit\n");
	  break;
      case EM_IA_64:
	  printf("Machine Architecture: Intel IA-46 Processor\n");
	  break;
      case EM_X86_64:
	  printf("Machine Architecture: Advanced Micro Devices x86-64\n");
	  break;
      default:
	  printf("Machine Architecture is invalid type...\n");
  }
  
  ///Test Elf Format Version
  ///Test Elf Format Version
  if(get_u32(&Elf_Header64.e_version) == EV_NONE)
    printf("Elf Format Version: None\n");
  else if(get_u32(&Elf_Header64.e_version) == EV_CURRENT)
    printf("Elf Format Version: Current\n");
  else
    printf("Incorrect Elf Format Version");
  
  ///Test Entry Point
  printf("Entry Point: %d\n", get_u64(&Elf_Header64.e_entry));
  
  ///Test Program Header File Offset
  printf("Program Header File Offset: %d\n", get_u64(&Elf_Header64.e_phoff));
  
  ///Test Section Header File Offset
  printf("Section Header File Offset: %d\n", get_u64(&Elf_Header64.e_shoff));
  
  ///Test Flags
  printf("Flags: %d\n", get_u32(&Elf_Header64.e_flags));
  
  ///Test Size of Header in Bytes
  printf("Size of Header: %d\n", get_u16(&Elf_Header64.e_ehsize));
  
  ///Test Size of Program Header Entry
  printf("Size of Program Header Entry: %d\n", get_u16(&Elf_Header64.e_phentsize));
  
  ///Test Number of Program Header Entries
  printf("Program Header Entries: %d\n",get_u16(&Elf_Header64.e_phnum));
  
  ///Test Size of Section Header Entry
  printf("Size of Section Header Entry: %d\n", get_u16(&Elf_Header64.e_shentsize));
  
  ///Test Number of Section Header Entries
  printf("Number of Section Header Entries: %d\n", get_u16(&Elf_Header64.e_shnum));
  
  ///Test Section Name Strings Section
  printf("Section Name Strings Section: %d\n", get_u16(&Elf_Header64.e_shstrndx));
  
  printf("\n\n");
  
}

void test_program_header32(int index)
{
  memcpy(&Elf_Program_Header32, (elf + get_u32(&Elf_Header32.e_phoff) + (index * sizeof(Elf_Program_Header32))), sizeof(Elf_Program_Header32));
  
  printf("\nTesting Program Header %d\n", index);
  printf("----------------------\n");
  
  /// Entry Type
  switch(get_u32(&Elf_Program_Header32.p_type))
  {
    case PT_NULL:
      printf("Entry Type: Unsused\n");
      break;
    case PT_LOAD:
      printf("Entry Type: Loadable Segment\n");
      break;
    case PT_DYNAMIC:
      printf("Entry Type: Dynamic Linking Information Segment\n");
      break;
    case PT_INTERP:
      printf("Entry Type: Pathname of Interpreter\n");
      break;
    case PT_NOTE:
      printf("Entry Type: Auxiliary Information\n");
      break;
    case PT_SHLIB:
      printf("Entry Type: Reserved (not used)\n");
      break;
    case PT_PHDR:
      printf("Entry Type: Location of Program Header Itself\n");
      break;
    default:
      printf("Entry Type is Unknown\n");
  }
  
  /// File Offset of Contents
  printf("File Offset of Contents: %d\n", get_u32(&Elf_Program_Header32.p_offset));
  
  /// Virtual Address in memory image
  printf("Virtual Address: %d\n", get_u32(&Elf_Program_Header32.p_vaddr));
  
  /// Physical address (not used)
  printf("Physical address: %d\n", get_u32(&Elf_Program_Header32.p_paddr));
  
  /// Size of contents in file
  printf("Size of contents in file: %d\n", get_u32(&Elf_Program_Header32.p_filesz));
  
  /// Size of contents in memory
  printf("Size of contents in memory: %d\n", get_u32(&Elf_Program_Header32.p_memsz));
  
  /// Access permission flags.  
  switch(get_u32(&Elf_Program_Header32.p_flags))
  {
    case PF_X:
      printf("Access permission: Executable\n");
      break;
    case PF_W:
      printf("Access permission: Writable\n");
      break;
    case PF_R:
      printf("Access permission: Readable\n");
      break;
    case (PF_X + PF_W):
      printf("Access permission: Executable and Writable\n");
      break;
    case (PF_X + PF_R):
      printf("Access permission: Executable and Readable\n");
      break;
    case (PF_W + PF_R):
      printf("Access permission: Writable and Readable\n");
      break;
    case (PF_X + PF_W + PF_R):
      printf("Access permission: Executabl, Writable, and Readable\n");
    default:
      printf("Access Permission is Unknown");
  }
  
  /// Alignment in memory and file
  printf("Alignment in memory and file: %d\n", get_u32(&Elf_Program_Header32.p_align));
  
  printf("\n\n");
  
}

void test_program_header64(int index)
{
  memcpy(&Elf_Program_Header64, (elf + get_u64(&Elf_Header64.e_phoff) + (index * sizeof(Elf_Program_Header64))), sizeof(Elf_Program_Header64));
  
  printf("\nTesting Program Header %d\n", index);
  printf("----------------------\n");
  
  /// Entry Type
  switch(get_u32(&Elf_Program_Header64.p_type))
  {
    case PT_NULL:
      printf("Entry Type: Unsused\n");
      break;
    case PT_LOAD:
      printf("Entry Type: Loadable Segment\n");
      break;
    case PT_DYNAMIC:
      printf("Entry Type: Dynamic Linking Information Segment\n");
      break;
    case PT_INTERP:
      printf("Entry Type: Pathname of Interpreter\n");
      break;
    case PT_NOTE:
      printf("Entry Type: Auxiliary Information\n");
      break;
    case PT_SHLIB:
      printf("Entry Type: Reserved (not used)\n");
      break;
    case PT_PHDR:
      printf("Entry Type: Location of Program Header Itself\n");
      break;
    default:
      printf("Entry Type is Unknown\n");
  }
  
  /// Access permission flags.
  switch(get_u32(&Elf_Program_Header64.p_flags))
  {
    case PF_X:
      printf("Access permission: Executable\n");
      break;
    case PF_W:
      printf("Access permission: Writable\n");
      break;
    case PF_R:
      printf("Access permission: Readable\n");
      break;
    case (PF_X + PF_W):
      printf("Access permission: Executable and Writable\n");
      break;
    case (PF_X + PF_R):
      printf("Access permission: Executable and Readable\n");
      break;
    case (PF_W + PF_R):
      printf("Access permission: Writable and Readable\n");
      break;
    case (PF_X + PF_W + PF_R):
      printf("Access permission: Executabl, Writable, and Readable\n");
    default:
      printf("Access Permission is Unknown %d\n", get_u32(&Elf_Program_Header64.p_flags));
  }
  
  /// File Offset of Contents
  printf("File Offset of Contents: %d\n", get_u64(&Elf_Program_Header64.p_offset));
  
  /// Virtual Address in memory image
  printf("Virtual Address: %d\n", get_u64(&Elf_Program_Header64.p_vaddr));
  
  /// Physical address (not used)
  printf("Physical address: %d\n", get_u64(&Elf_Program_Header64.p_paddr));
  
  /// Size of contents in file
  printf("Size of contents in file: %d\n", get_u64(&Elf_Program_Header64.p_filesz));
  
  /// Size of contents in memory
  printf("Size of contents in memory: %d\n", get_u64(&Elf_Program_Header64.p_memsz));

  /// Alignment in memory and file
  printf("Alignment in memory and file: %d\n", get_u64(&Elf_Program_Header64.p_align));
  
  printf("\n\n");
  
}

void test_program_headers(void)
{
  int i;
  if (arch == 32)
    for(i=0; i < get_u16(&Elf_Header32.e_phnum); i++)
    {test_program_header32(i);}
  else
    for(i=0; i < get_u16(&Elf_Header64.e_phnum); i++)
    {test_program_header64(i);}
}

void test_section_header32(int index)
{
  memcpy(&Elf_Section_Header32, (elf + get_u32(&Elf_Header32.e_shoff) + (index * sizeof(Elf_Section_Header32))), sizeof(Elf_Section_Header32));
  
  printf("\nTesting Section Header %d\n", index);
  printf("----------------------\n");
  
  ///Section Name
  printf("Section Name: %d\n", get_u32(&Elf_Section_Header32.sh_name));
  
  ///Section Type
  switch(get_u32(&Elf_Section_Header32.sh_type))
  {
    case SHT_NULL:
      printf("Section Type: Inactive\n");
      break;
    case SHT_PROGBITS:
      printf("Section Type: Program Defined Information\n");
      break;
    case SHT_SYMTAB:
      printf("Section Type: Symbol Table Section\n");
      break;
  case SHT_STRTAB:
      printf("Section Type: String Table Section\n");
      break;
  case SHT_RELA:
      printf("Section Type: Relocation Section with Appends\n");
      break;
  case SHT_HASH:
      printf("Section Type: Symbol Hash Table Section\n");
      break;
  case SHT_DYNAMIC:
      printf("Section Type: Dynamic Section\n");
      break;
  case SHT_NOTE:
      printf("Section Type: Note Section\n");
      break;
  case SHT_NOBITS:
      printf("Section Type: No Space Section\n");
      break;
  case SHT_REL:
      printf("Section Type: Relation Section Without Appends\n");
      break;
  case SHT_SHLIB:
      printf("Section Type: Reserved\n");
      break;
  case SHT_DYNSYM:
      printf("Section Type: Dynamic Symbol Table Section\n");
      break;
  case SHT_LOPROC:
      printf("Section Type: Reserved Range for Processor\n");
      break;
  case SHT_HIPROC:
      printf("Section Type: Specific Section Header Types\n");
      break;
  case SHT_LOUSER:
      printf("Section Type: Reserved Range for Application\n");
      break;
  case SHT_HIUSER:
      printf("Section Type: Specifc Indexes\n");
      break;
    default:
      printf("Incorrect Section Type\n");
  }
  
  ///Section Flags
  switch(get_u32(&Elf_Section_Header32.sh_flags))
  {
    case 0:
       printf("No Section Flags Set\n");
       break;
    case SHF_WRITE:
       printf("Section Flags: Contains Writable Data\n");
       break;
    case SHF_ALLOC:
       printf("Section Flags: Occupies Memory\n");
       break;
     case SHF_EXECINSTR:
       printf("Section Flags: Contains Instructions\n");
       break;
     case SHF_MASKPROC:
       printf("Section Flags: Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC):
       printf("Section Flags: Contains Writable Data and Occupies Memory\n");
       break;
     case (SHF_WRITE + SHF_EXECINSTR):
       printf("Section Flags: Contains Writable Data and Instructions\n");
       break;
     case (SHF_WRITE + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_ALLOC + SHF_EXECINSTR):
       printf("Section Flags: Occupies Memory and Contains Instructions\n");
       break;
     case (SHF_ALLOC + SHF_MASKPROC):
       printf("Section Flags: Occupies Memory and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Contains Instructions and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_EXECINSTR):
       printf("Section Flags: Contains Writable Data, Occupies Memory, and Contains Instructions\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data, Occupies Memory, and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_ALLOC + SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Occupies Memory, Contains Instructions, and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data, Occupies Memory, Contains Instructions, and is Reserved for Processor-Specific things\n");
       break;
    default:
      printf("Section Flags are Unknown\n");
  }
  
  ///Address in Memory
  printf("Address in Memory: %d\n", get_u32(&Elf_Section_Header32.sh_addr));
  
  ///Offset in File
  printf("Offset in File: %d\n", get_u32(&Elf_Section_Header32.sh_offset));
  
  ///Size in bytes
  printf("Size in Bytes: %d\n", get_u32(&Elf_Section_Header32.sh_size));
  
  ///Index of a related section
  printf("Index of Related Section: %d\n", get_u32(&Elf_Section_Header32.sh_link));
  
  ///Info dependent on Section Type
  printf("Info: %d\n", get_u32(&Elf_Section_Header32.sh_info));
  
  ///Alignment in bytes
  printf("Alignment in Bytes: %d\n", get_u32(&Elf_Section_Header32.sh_addralign));
  
  ///Size of Each Entry in Section
  printf("Size of Each Entry: %d\n", get_u32(&Elf_Section_Header32.sh_entsize));
  
  printf("\n\n");
}

void test_section_header64(int index)
{
  memcpy(&Elf_Section_Header64, (elf + get_u64(&Elf_Header64.e_shoff) + (index * sizeof(Elf_Section_Header64))), sizeof(Elf_Section_Header64));
  
  printf("\nTesting Section Header %d\n", index);
  printf("----------------------\n");
  
  ///Section Name
  printf("Section Name: %d\n", get_u32(&Elf_Section_Header64.sh_name));
  
  ///Section Type
  switch(get_u32(&Elf_Section_Header64.sh_type))
  {
    case SHT_NULL:
      printf("Section Type: Inactive\n");
      break;
    case SHT_PROGBITS:
      printf("Section Type: Program Defined Information\n");
      break;
    case SHT_SYMTAB:
      printf("Section Type: Symbol Table Section\n");
      break;
  case SHT_STRTAB:
      printf("Section Type: String Table Section\n");
      break;
  case SHT_RELA:
      printf("Section Type: Relocation Section with Appends\n");
      break;
  case SHT_HASH:
      printf("Section Type: Symbol Hash Table Section\n");
      break;
  case SHT_DYNAMIC:
      printf("Section Type: Dynamic Section\n");
      break;
  case SHT_NOTE:
      printf("Section Type: Note Section\n");
      break;
  case SHT_NOBITS:
      printf("Section Type: No Space Section\n");
      break;
  case SHT_REL:
      printf("Section Type: Relation Section Without Appends\n");
      break;
  case SHT_SHLIB:
      printf("Section Type: Reserved\n");
      break;
  case SHT_DYNSYM:
      printf("Section Type: Dynamic Symbol Table Section\n");
      break;
  case SHT_LOPROC:
      printf("Section Type: Reserved Range for Processor\n");
      break;
  case SHT_HIPROC:
      printf("Section Type: Specific Section Header Types\n");
      break;
  case SHT_LOUSER:
      printf("Section Type: Reserved Range for Application\n");
      break;
  case SHT_HIUSER:
      printf("Section Type: Specifc Indexes\n");
      break;
    default:
      printf("Incorrect Section Type\n");
  }
  
  ///Section Flags
  switch(get_u64(&Elf_Section_Header64.sh_flags))
  {
     case 0:
       printf("No Section Flags Set\n");
       break;
     case SHF_WRITE:
       printf("Section Flags: Contains Writable Data\n");
       break;
     case SHF_ALLOC:
       printf("Section Flags: Occupies Memory\n");
       break;
     case SHF_EXECINSTR:
       printf("Section Flags: Contains Instructions\n");
       break;
     case SHF_MASKPROC:
       printf("Section Flags: Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC):
       printf("Section Flags: Contains Writable Data and Occupies Memory\n");
       break;
     case (SHF_WRITE + SHF_EXECINSTR):
       printf("Section Flags: Contains Writable Data and Instructions\n");
       break;
     case (SHF_WRITE + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_ALLOC + SHF_EXECINSTR):
       printf("Section Flags: Occupies Memory and Contains Instructions\n");
       break;
     case (SHF_ALLOC + SHF_MASKPROC):
       printf("Section Flags: Occupies Memory and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Contains Instructions and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_EXECINSTR):
       printf("Section Flags: Contains Writable Data, Occupies Memory, and Contains Instructions\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data, Occupies Memory, and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_ALLOC + SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Occupies Memory, Contains Instructions, and is Reserved for Processor-Specific things\n");
       break;
     case (SHF_WRITE + SHF_ALLOC + SHF_EXECINSTR + SHF_MASKPROC):
       printf("Section Flags: Contains Writable Data, Occupies Memory, Contains Instructions, and is Reserved for Processor-Specific things\n");
       break;
    default:
      printf("Section Flags are Uknown\n");
  }
  
  ///Address in Memory
  printf("Address in Memory: %d\n", get_u64(&Elf_Section_Header64.sh_addr));
  
  ///Offset in File
  printf("Offset in File: %d\n", get_u64(&Elf_Section_Header64.sh_offset));
  
  ///Size in bytes
  printf("Size in Bytes: %d\n", get_u64(&Elf_Section_Header64.sh_size));
  
  ///Index of a related section
  printf("Index of Related Section: %d\n", get_u32(&Elf_Section_Header64.sh_link));
  
  ///Info dependent on Section Type
  printf("Info: %d\n", get_u32(&Elf_Section_Header64.sh_info));
  
  ///Alignment in bytes
  printf("Alignment in Bytes: %d\n", get_u64(&Elf_Section_Header64.sh_addralign));
  
  ///Size of Each Entry in Section
  printf("Size of Each Entry: %d\n", get_u64(&Elf_Section_Header64.sh_entsize));
  
  printf("\n\n");
}

void test_section_headers(void)
{
  int i;
  if (arch == 32)
    for(i=0; i < get_u16(&Elf_Header32.e_shnum); i++)
    {test_section_header32(i);}
  else
    for(i=0; i < get_u16(&Elf_Header64.e_shnum); i++)
    {test_section_header64(i);}
}

int main(int argc, char *argv[])
{
  if (argc != 2)
	printf("usage: testelf file.elf");
  
  FILE *input;
  input = fopen(argv[1], "rb");
  
  fseek(input, 0, SEEK_END);
  int elf_length = ftell(input);
  fseek(input, 0, SEEK_SET);
  elf = (u_int8_t*)malloc(elf_length);
  fread(elf, 1, elf_length, input);
  fclose(input);
  
  test_identity();
  
  if(arch == 32)
  {
    test_header32();
    if(Elf_Header32.e_phoff != 0)
      test_program_headers();     
    if(Elf_Header32.e_shoff != 0)
      test_section_headers();
  }
  else
  {
    test_header64();
    if(Elf_Header64.e_phoff != 0)
      test_program_headers();      
    if(Elf_Header64.e_shoff != 0)
      test_section_headers();
  }
}

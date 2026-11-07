/*
 * ELF Autopsy — ELF parser & byte-annotation engine.
 * Pure JavaScript, no dependencies. Works in browsers and Node.
 *
 * The parser produces, besides the usual ELF structures, a flat list of
 * non-overlapping byte "annotations" (segments) that explain what every byte
 * of the file means. The UI renders these annotations directly.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ElfParser = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   * Constants
   * ------------------------------------------------------------------ */

  const SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3,
    SHT_RELA = 4, SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7, SHT_NOBITS = 8,
    SHT_REL = 9, SHT_SHLIB = 10, SHT_DYNSYM = 11, SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY = 15, SHT_PREINIT_ARRAY = 16, SHT_GROUP = 17,
    SHT_SYMTAB_SHNDX = 18, SHT_GNU_HASH = 0x6ffffff6, SHT_GNU_VERDEF = 0x6ffffffd,
    SHT_GNU_VERNEED = 0x6ffffffe, SHT_GNU_VERSYM = 0x6fffffff;

  const SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4, SHF_MERGE = 0x10,
    SHF_STRINGS = 0x20, SHF_INFO_LINK = 0x40, SHF_LINK_ORDER = 0x80,
    SHF_OS_NONCONFORMING = 0x100, SHF_GROUP = 0x200, SHF_TLS = 0x400,
    SHF_COMPRESSED = 0x800, SHF_GNU_RETAIN = 0x200000, SHF_EXCLUDE = 0x80000000;

  const PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4,
    PT_SHLIB = 5, PT_PHDR = 6, PT_TLS = 7, PT_GNU_EH_FRAME = 0x6474e550,
    PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552,
    PT_GNU_PROPERTY = 0x6474e553, PT_OPENBSD_RANDOMIZE = 0x65a3dbe6,
    PT_OPENBSD_WXNEEDED = 0x65a3dbe7, PT_OPENBSD_BOOTDATA = 0x65a41be6;

  const PF_X = 0x1, PF_W = 0x2, PF_R = 0x4;

  const SHN_UNDEF = 0, SHN_LORESERVE = 0xff00, SHN_ABS = 0xfff1,
    SHN_COMMON = 0xfff2, SHN_XINDEX = 0xffff;

  const ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4;

  const SHT = {
    0: 'SHT_NULL', 1: 'SHT_PROGBITS', 2: 'SHT_SYMTAB', 3: 'SHT_STRTAB',
    4: 'SHT_RELA', 5: 'SHT_HASH', 6: 'SHT_DYNAMIC', 7: 'SHT_NOTE',
    8: 'SHT_NOBITS', 9: 'SHT_REL', 10: 'SHT_SHLIB', 11: 'SHT_DYNSYM',
    14: 'SHT_INIT_ARRAY', 15: 'SHT_FINI_ARRAY', 16: 'SHT_PREINIT_ARRAY',
    17: 'SHT_GROUP', 18: 'SHT_SYMTAB_SHNDX',
    0x6ffffff5: 'SHT_GNU_ATTRIBUTES', 0x6ffffff6: 'SHT_GNU_HASH',
    0x6ffffff7: 'SHT_GNU_LIBLIST', 0x6ffffff8: 'SHT_CHECKSUM',
    0x6ffffffd: 'SHT_GNU_VERDEF', 0x6ffffffe: 'SHT_GNU_VERNEED',
    0x6fffffff: 'SHT_GNU_VERSYM',
    0x70000001: 'SHT_ARM_EXIDX', 0x70000002: 'SHT_ARM_PREEMPTMAP',
    0x70000003: 'SHT_ARM_ATTRIBUTES', 0x70000004: 'SHT_ARM_DEBUGOVERLAY',
    0x70000005: 'SHT_ARM_OVERLAYSECTION',
    0x70000000: 'SHT_LOPROC', 0x7fffffff: 'SHT_HIPROC',
    0x80000000: 'SHT_LOUSER', 0xffffffff: 'SHT_HIUSER'
  };

  const PT = {
    0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP', 4: 'PT_NOTE',
    5: 'PT_SHLIB', 6: 'PT_PHDR', 7: 'PT_TLS',
    0x6474e550: 'PT_GNU_EH_FRAME', 0x6474e551: 'PT_GNU_STACK',
    0x6474e552: 'PT_GNU_RELRO', 0x6474e553: 'PT_GNU_PROPERTY',
    0x65a3dbe6: 'PT_OPENBSD_RANDOMIZE', 0x65a3dbe7: 'PT_OPENBSD_WXNEEDED',
    0x65a41be6: 'PT_OPENBSD_BOOTDATA',
    0x60000000: 'PT_LOOS', 0x6fffffff: 'PT_HIOS',
    0x70000000: 'PT_LOPROC', 0x7fffffff: 'PT_HIPROC'
  };

  const ET = {
    0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'
  };
  const ET_LABEL = {
    0: '无类型', 1: '可重定位目标文件', 2: '可执行文件',
    3: '共享对象 / 位置无关可执行文件', 4: '核心转储文件'
  };

  const MACHINES = {
    0: 'EM_NONE', 1: 'EM_M32', 2: 'EM_SPARC', 3: 'EM_386', 4: 'EM_68K',
    5: 'EM_88K', 7: 'EM_860', 8: 'EM_MIPS', 9: 'EM_S370', 10: 'EM_MIPS_RS3_LE',
    15: 'EM_PARISC', 17: 'EM_VPP500', 18: 'EM_SPARC32PLUS', 19: 'EM_960',
    20: 'EM_PPC', 21: 'EM_PPC64', 22: 'EM_S390', 23: 'EM_SPU', 36: 'EM_V800',
    37: 'EM_FR20', 38: 'EM_RH32', 39: 'EM_RCE', 40: 'EM_ARM', 41: 'EM_ALPHA',
    42: 'EM_SH', 43: 'EM_SPARCV9', 44: 'EM_TRICORE', 45: 'EM_ARC', 46: 'EM_H8_300',
    47: 'EM_H8_300H', 48: 'EM_H8S', 49: 'EM_H8_500', 50: 'EM_IA_64',
    51: 'EM_MIPS_X', 52: 'EM_COLDFIRE', 53: 'EM_68HC12', 54: 'EM_MMA',
    55: 'EM_PCP', 56: 'EM_NCPU', 57: 'EM_NDR1', 58: 'EM_STARCORE',
    59: 'EM_ME16', 60: 'EM_ST100', 61: 'EM_TINYJ', 62: 'EM_X86_64',
    63: 'EM_PDSP', 64: 'EM_PDP10', 65: 'EM_PDP11', 66: 'EM_FX66',
    67: 'EM_ST9PLUS', 68: 'EM_ST7', 69: 'EM_68HC16', 70: 'EM_68HC11',
    71: 'EM_68HC08', 72: 'EM_68HC05', 73: 'EM_SVX', 74: 'EM_ST19',
    75: 'EM_VAX', 76: 'EM_CRIS', 77: 'EM_JAVELIN', 78: 'EM_FIREPATH',
    79: 'EM_ZSP', 80: 'EM_MMIX', 81: 'EM_HUANY', 82: 'EM_PRISM',
    83: 'EM_AVR', 84: 'EM_FR30', 85: 'EM_D10V', 86: 'EM_D30V', 87: 'EM_V850',
    88: 'EM_M32R', 89: 'EM_MN10300', 90: 'EM_MN10200', 91: 'EM_PJ',
    92: 'EM_OPENRISC', 93: 'EM_ARC_COMPACT', 94: 'EM_XTENSA',
    95: 'EM_VIDEOCORE', 96: 'EM_TMM_GPP', 97: 'EM_NS32K', 98: 'EM_TPC',
    99: 'EM_SNP1K', 100: 'EM_ST200', 101: 'EM_IP2K', 102: 'EM_MAX',
    103: 'EM_CR', 104: 'EM_F2MC16', 105: 'EM_MSP430', 106: 'EM_BLACKFIN',
    107: 'EM_SE_C33', 108: 'EM_SEP', 109: 'EM_ARCA', 110: 'EM_UNICORE',
    111: 'EM_EXCESS', 112: 'EM_DXP', 113: 'EM_ALTERA_NIOS2', 114: 'EM_CRX',
    115: 'EM_XGATE', 116: 'EM_C166', 117: 'EM_M16C', 118: 'EM_DSPIC30F',
    119: 'EM_CE', 120: 'EM_M32C', 131: 'EM_TSK3000', 132: 'EM_RS08',
    133: 'EM_SHARC', 134: 'EM_ECOG2', 135: 'EM_SCORE7', 136: 'EM_DSP24',
    137: 'EM_VIDEOCORE3', 138: 'EM_LATTICEMICO32', 139: 'EM_SE_C17',
    140: 'EM_TI_C6000', 141: 'EM_TI_C2000', 142: 'EM_TI_C5500',
    143: 'EM_TI_ARP32', 144: 'EM_TI_PRU', 160: 'EM_MMDSP_PLUS',
    161: 'EM_CYPRESS_M8C', 162: 'EM_R32C', 163: 'EM_TRIMEDIA', 164: 'EM_QDSP6',
    165: 'EM_8051', 166: 'EM_STXP7X', 167: 'EM_NDS32', 168: 'EM_ECOG1',
    169: 'EM_ECOG1X', 170: 'EM_MAXQ30', 171: 'EM_XIMO16', 172: 'EM_MANIK',
    173: 'EM_CRAYNV2', 174: 'EM_RX', 175: 'EM_METAG', 176: 'EM_MCST_ELBRUS',
    177: 'EM_ECOG16', 178: 'EM_CR16', 179: 'EM_ETPU', 180: 'EM_SLE9X',
    181: 'EM_L10M', 182: 'EM_K10M', 183: 'EM_AARCH64', 185: 'EM_AVR32',
    186: 'EM_STM8', 187: 'EM_TILE64', 188: 'EM_TILEPRO', 189: 'EM_MICROBLAZE',
    190: 'EM_CUDA', 191: 'EM_TILEGX', 192: 'EM_CLOUDSHIELD',
    193: 'EM_COREA_1ST', 194: 'EM_COREA_2ND', 195: 'EM_ARC_COMPACT2',
    196: 'EM_OPEN8', 197: 'EM_RL78', 198: 'EM_VIDEOCORE5', 199: 'EM_78KOR',
    200: 'EM_56800EX', 201: 'EM_BA1', 202: 'EM_BA2', 203: 'EM_XCORE',
    204: 'EM_MCHP_PIC', 205: 'EM_KM32', 206: 'EM_KMX32', 207: 'EM_EMX16',
    208: 'EM_EMX8', 209: 'EM_KVARC', 210: 'EM_CDP', 211: 'EM_COGE',
    212: 'EM_COOL', 213: 'EM_NORC', 214: 'EM_CSR_KALIMBA', 215: 'EM_Z80',
    216: 'EM_VISIUM', 217: 'EM_FT32', 218: 'EM_MOXIE', 219: 'EM_AMDGPU',
    243: 'EM_RISCV', 244: 'EM_LANAI', 245: 'EM_CEVA', 246: 'EM_CEVA_X2',
    247: 'EM_BPF', 248: 'EM_GRAPHCORE_IPU', 249: 'EM_IMG1', 250: 'EM_NFP',
    251: 'EM_VE', 252: 'EM_CSKY', 253: 'EM_ARC_COMPACT3_64', 254: 'EM_MCS6502',
    255: 'EM_ARC_COMPACT3', 256: 'EM_KVX', 257: 'EM_65816', 258: 'EM_LOONGARCH',
    259: 'EM_KFX', 260: 'EM_PUPPET', 261: 'EM_SATURN', 262: 'EM_S1C33',
    263: 'EM_S1C6X', 264: 'EM_S1C', 265: 'EM_S1C_II', 266: 'EM_S1C_III',
    267: 'EM_S1C_IV', 268: 'EM_S1C_V', 269: 'EM_S1C_VI', 270: 'EM_S1C_VII',
    271: 'EM_S1C_VIII', 272: 'EM_S1C_IX', 273: 'EM_S1C_X', 274: 'EM_S1C_XI',
    275: 'EM_S1C_XII', 276: 'EM_S1C_XIII', 277: 'EM_S1C_XIV', 278: 'EM_S1C_XV',
    279: 'EM_S1C_XVI', 280: 'EM_S1C_XVII', 281: 'EM_S1C_XVIII',
    282: 'EM_S1C_XIX', 283: 'EM_S1C_XX', 284: 'EM_S1C_XXI', 285: 'EM_S1C_XXII'
  };

  const OSABI = {
    0: 'UNIX - System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux', 4: 'GNU Hurd',
    6: 'Solaris', 7: 'AIX', 8: 'IRIX', 9: 'FreeBSD', 10: 'Tru64',
    11: 'Novell Modesto', 12: 'OpenBSD', 13: 'OpenVMS', 14: 'NonStop Kernel',
    15: 'AROS', 16: 'FenixOS', 17: 'CloudABI', 18: 'OpenVOS',
    64: 'ARM EABI', 97: 'ARM', 255: 'Standalone (embedded)'
  };

  const SYM_BIND = {
    0: 'STB_LOCAL', 1: 'STB_GLOBAL', 2: 'STB_WEAK',
    10: 'STB_GNU_UNIQUE', 13: 'STB_GNU_IFUNC'
  };
  const SYM_TYPE = {
    0: 'STT_NOTYPE', 1: 'STT_OBJECT', 2: 'STT_FUNC', 3: 'STT_SECTION',
    4: 'STT_FILE', 5: 'STT_COMMON', 6: 'STT_TLS', 10: 'STT_GNU_IFUNC'
  };
  const SYM_VIS = {
    0: 'STV_DEFAULT', 1: 'STV_INTERNAL', 2: 'STV_HIDDEN', 3: 'STV_PROTECTED'
  };

  const DYN_TAGS = {
    0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT',
    4: 'DT_HASH', 5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA',
    8: 'DT_RELASZ', 9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT',
    12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH',
    16: 'DT_SYMBOLIC', 17: 'DT_REL', 18: 'DT_RELSZ', 19: 'DT_RELENT',
    20: 'DT_PLTREL', 21: 'DT_DEBUG', 22: 'DT_TEXTREL', 23: 'DT_JMPREL',
    24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY',
    27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ', 29: 'DT_RUNPATH',
    30: 'DT_FLAGS', 32: 'DT_PREINIT_ARRAY', 33: 'DT_PREINIT_ARRAYSZ',
    34: 'DT_SYMTAB_SHNDX', 35: 'DT_RELRSZ', 36: 'DT_RELR', 37: 'DT_RELRENT',
    0x6ffffef5: 'DT_GNU_HASH', 0x6ffffef6: 'DT_TLSDESC_PLT',
    0x6ffffef7: 'DT_TLSDESC_GOT', 0x6ffffef8: 'DT_GNU_CONFLICT',
    0x6ffffef9: 'DT_GNU_LIBLIST', 0x6ffffefa: 'DT_CONFIG',
    0x6ffffefb: 'DT_DEPAUDIT', 0x6ffffefc: 'DT_AUDIT', 0x6ffffefd: 'DT_PLTPAD',
    0x6ffffefe: 'DT_MOVETAB', 0x6ffffeff: 'DT_SYMINFO',
    0x6ffffff0: 'DT_VERSYM', 0x6ffffff9: 'DT_RELACOUNT',
    0x6ffffffa: 'DT_RELCOUNT', 0x6ffffffb: 'DT_FLAGS_1',
    0x6ffffffc: 'DT_VERDEF', 0x6ffffffd: 'DT_VERDEFNUM',
    0x6ffffffe: 'DT_VERNEED', 0x6fffffff: 'DT_VERNEEDNUM',
    0x7ffffffd: 'DT_AUXILIARY', 0x7fffffff: 'DT_FILTER'
  };

  const DYN_STRING_TAGS = new Set([1, 14, 15, 29, 0x6ffffefa, 0x6ffffefb,
    0x6ffffefc, 0x7ffffffd, 0x7fffffff]);

  const DT_FLAGS_1 = {
    0x1: 'DF_1_NOW', 0x2: 'DF_1_GLOBAL', 0x4: 'DF_1_GROUP',
    0x8: 'DF_1_NODELETE', 0x10: 'DF_1_LOADFLTR', 0x20: 'DF_1_INITFIRST',
    0x40: 'DF_1_NOOPEN', 0x80: 'DF_1_ORIGIN', 0x100: 'DF_1_DIRECT',
    0x200: 'DF_1_TRANS', 0x400: 'DF_1_INTERPOSE', 0x800: 'DF_1_NODEFLIB',
    0x1000: 'DF_1_NODUMP', 0x2000: 'DF_1_CONFALT', 0x4000: 'DF_1_ENDFILTEE',
    0x8000: 'DF_1_DISPRELDNE', 0x10000: 'DF_1_DISPRELPND',
    0x20000: 'DF_1_NODIRECT', 0x40000: 'DF_1_IGNMULDEF',
    0x80000: 'DF_1_NOKSYMS', 0x100000: 'DF_1_NOHDR',
    0x200000: 'DF_1_EDITED', 0x400000: 'DF_1_NORELOC',
    0x800000: 'DF_1_SYMINTPOSE', 0x1000000: 'DF_1_GLOBAUDIT',
    0x2000000: 'DF_1_SINGLETON', 0x4000000: 'DF_1_STUB',
    0x8000000: 'DF_1_PIE'
  };

  const NOTE_TYPES = {
    GNU: {
      1: 'NT_GNU_ABI_TAG', 2: 'NT_GNU_HWCAP', 3: 'NT_GNU_BUILD_ID',
      4: 'NT_GNU_GOLD_VERSION', 5: 'NT_GNU_PROPERTY_TYPE_0'
    },
    Go: { 1: 'NT_GO_BUILD_ID', 2: 'NT_GO_REVISION' },
    CORE: { 1: 'NT_PRSTATUS', 2: 'NT_FPREGSET', 3: 'NT_PRPSINFO', 4: 'NT_TASKSTRUCT' }
  };

  const RELOC_TYPES = {
    62: { // x86-64
      0: 'R_X86_64_NONE', 1: 'R_X86_64_64', 2: 'R_X86_64_PC32',
      3: 'R_X86_64_GOT32', 4: 'R_X86_64_PLT32', 5: 'R_X86_64_COPY',
      6: 'R_X86_64_GLOB_DAT', 7: 'R_X86_64_JUMP_SLOT', 8: 'R_X86_64_RELATIVE',
      9: 'R_X86_64_GOTPCREL', 10: 'R_X86_64_32', 11: 'R_X86_64_32S',
      12: 'R_X86_64_16', 13: 'R_X86_64_PC16', 14: 'R_X86_64_8',
      15: 'R_X86_64_PC8', 16: 'R_X86_64_DTPMOD64', 17: 'R_X86_64_DTPOFF64',
      18: 'R_X86_64_TPOFF64', 19: 'R_X86_64_TLSGD', 20: 'R_X86_64_TLSLD',
      21: 'R_X86_64_DTPOFF32', 22: 'R_X86_64_GOTTPOFF',
      23: 'R_X86_64_TPOFF32', 24: 'R_X86_64_PC64', 25: 'R_X86_64_GOTOFF64',
      26: 'R_X86_64_GOTPC32', 32: 'R_X86_64_SIZE32', 33: 'R_X86_64_SIZE64',
      34: 'R_X86_64_GOTPC32_TLSDESC', 35: 'R_X86_64_TLSDESC_CALL',
      36: 'R_X86_64_TLSDESC', 37: 'R_X86_64_IRELATIVE',
      38: 'R_X86_64_RELATIVE64', 41: 'R_X86_64_GOTPCRELX',
      42: 'R_X86_64_REX_GOTPCRELX'
    },
    3: { // i386
      0: 'R_386_NONE', 1: 'R_386_32', 2: 'R_386_PC32', 3: 'R_386_GOT32',
      4: 'R_386_PLT32', 5: 'R_386_COPY', 6: 'R_386_GLOB_DAT',
      7: 'R_386_JMP_SLOT', 8: 'R_386_RELATIVE', 9: 'R_386_GOTOFF',
      10: 'R_386_GOTPC', 14: 'R_386_TLS_TPOFF', 15: 'R_386_TLS_IE',
      16: 'R_386_TLS_GOTIE', 17: 'R_386_TLS_LE', 18: 'R_386_TLS_GD',
      19: 'R_386_TLS_LDM', 20: 'R_386_16', 21: 'R_386_PC16', 22: 'R_386_8',
      23: 'R_386_PC8', 24: 'R_386_TLS_GD_32', 25: 'R_386_TLS_GD_PUSH',
      26: 'R_386_TLS_GD_CALL', 27: 'R_386_TLS_GD_POP',
      28: 'R_386_TLS_LDM_32', 29: 'R_386_TLS_LDM_PUSH',
      30: 'R_386_TLS_LDM_CALL', 31: 'R_386_TLS_LDM_POP',
      32: 'R_386_TLS_LDO_32', 33: 'R_386_TLS_IE_32',
      34: 'R_386_TLS_LE_32', 35: 'R_386_TLS_DTPMOD32',
      36: 'R_386_TLS_DTPOFF32', 37: 'R_386_TLS_TPOFF32',
      38: 'R_386_SIZE32', 39: 'R_386_TLS_GOTDESC', 40: 'R_386_TLS_DESC_CALL',
      41: 'R_386_TLS_DESC', 42: 'R_386_IRELATIVE',
      43: 'R_386_GOT32X'
    },
    183: { // AArch64
      0: 'R_AARCH64_NONE', 257: 'R_AARCH64_ABS64', 258: 'R_AARCH64_ABS32',
      259: 'R_AARCH64_ABS16', 260: 'R_AARCH64_PREL64', 261: 'R_AARCH64_PREL32',
      262: 'R_AARCH64_PREL16', 263: 'R_AARCH64_MOVW_UABS_G0',
      264: 'R_AARCH64_MOVW_UABS_G0_NC', 265: 'R_AARCH64_MOVW_UABS_G1',
      266: 'R_AARCH64_MOVW_UABS_G1_NC', 267: 'R_AARCH64_MOVW_UABS_G2',
      268: 'R_AARCH64_MOVW_UABS_G2_NC', 269: 'R_AARCH64_MOVW_UABS_G3',
      270: 'R_AARCH64_MOVW_SABS_G0', 271: 'R_AARCH64_MOVW_SABS_G1',
      272: 'R_AARCH64_MOVW_SABS_G2', 273: 'R_AARCH64_LD_PREL_LO19',
      274: 'R_AARCH64_ADR_PREL_LO21', 275: 'R_AARCH64_ADR_PREL_PG_HI21',
      276: 'R_AARCH64_ADR_PREL_PG_HI21_NC', 277: 'R_AARCH64_ADD_ABS_LO12_NC',
      278: 'R_AARCH64_LDST8_ABS_LO12_NC', 282: 'R_AARCH64_TSTBR14',
      283: 'R_AARCH64_CONDBR19', 285: 'R_AARCH64_JUMP26',
      286: 'R_AARCH64_CALL26', 287: 'R_AARCH64_LDST16_ABS_LO12_NC',
      288: 'R_AARCH64_LDST32_ABS_LO12_NC', 289: 'R_AARCH64_LDST64_ABS_LO12_NC',
      299: 'R_AARCH64_ADR_GOT_PAGE', 300: 'R_AARCH64_LD64_GOT_LO12_NC',
      1024: 'R_AARCH64_COPY', 1025: 'R_AARCH64_GLOB_DAT',
      1026: 'R_AARCH64_JUMP_SLOT', 1027: 'R_AARCH64_RELATIVE',
      1028: 'R_AARCH64_TLS_DTPMOD64', 1029: 'R_AARCH64_TLS_DTPREL64',
      1030: 'R_AARCH64_TLS_TPREL64', 1031: 'R_AARCH64_TLSDESC',
      1032: 'R_AARCH64_IRELATIVE'
    },
    40: { // ARM
      0: 'R_ARM_NONE', 1: 'R_ARM_PC24', 2: 'R_ARM_ABS32', 3: 'R_ARM_REL32',
      4: 'R_ARM_PC13', 5: 'R_ARM_ABS16', 6: 'R_ARM_ABS12', 7: 'R_ARM_THM_ABS5',
      8: 'R_ARM_ABS8', 9: 'R_ARM_SBREL32', 10: 'R_ARM_THM_PC22',
      11: 'R_ARM_THM_PC8', 17: 'R_ARM_TLS_DTPMOD32', 18: 'R_ARM_TLS_DTPOFF32',
      19: 'R_ARM_TLS_TPOFF32', 20: 'R_ARM_COPY', 21: 'R_ARM_GLOB_DAT',
      22: 'R_ARM_JUMP_SLOT', 23: 'R_ARM_RELATIVE', 24: 'R_ARM_GOTOFF32',
      25: 'R_ARM_BASE_PREL', 26: 'R_ARM_GOT_BREL', 27: 'R_ARM_PLT32',
      28: 'R_ARM_CALL', 29: 'R_ARM_JUMP24', 30: 'R_ARM_THM_JUMP24',
      38: 'R_ARM_TARGET1', 39: 'R_ARM_SBREL31', 40: 'R_ARM_V4BX',
      42: 'R_ARM_PREL31', 43: 'R_ARM_MOVW_ABS_NC', 44: 'R_ARM_MOVT_ABS',
      45: 'R_ARM_MOVW_PREL_NC', 46: 'R_ARM_MOVT_PREL',
      47: 'R_ARM_THM_MOVW_ABS_NC', 48: 'R_ARM_THM_MOVT_ABS',
      49: 'R_ARM_THM_MOVW_PREL_NC', 50: 'R_ARM_THM_MOVT_PREL',
      103: 'R_ARM_THM_PC12', 104: 'R_ARM_ABS32_NOI', 105: 'R_ARM_REL32_NOI',
      160: 'R_ARM_IRELATIVE', 249: 'R_ARM_RXPC25',
      250: 'R_ARM_RSBREL32', 251: 'R_ARM_THM_RPC22', 252: 'R_ARM_RREL32',
      253: 'R_ARM_RABS32', 254: 'R_ARM_RPC24', 255: 'R_ARM_RBASE'
    },
    243: { // RISC-V
      0: 'R_RISCV_NONE', 1: 'R_RISCV_32', 2: 'R_RISCV_64', 3: 'R_RISCV_RELATIVE',
      4: 'R_RISCV_COPY', 5: 'R_RISCV_JUMP_SLOT', 6: 'R_RISCV_TLS_DTPMOD32',
      7: 'R_RISCV_TLS_DTPMOD64', 8: 'R_RISCV_TLS_DTPREL32',
      9: 'R_RISCV_TLS_DTPREL64', 10: 'R_RISCV_TLS_TPREL32',
      11: 'R_RISCV_TLS_TPREL64', 12: 'R_RISCV_BRANCH', 13: 'R_RISCV_JAL',
      14: 'R_RISCV_CALL', 15: 'R_RISCV_CALL_PLT', 16: 'R_RISCV_GOT_HI20',
      17: 'R_RISCV_TLS_GOT_HI20', 18: 'R_RISCV_TLS_GD_HI20',
      19: 'R_RISCV_PCREL_HI20', 20: 'R_RISCV_PCREL_LO12_I',
      21: 'R_RISCV_PCREL_LO12_S', 22: 'R_RISCV_HI20', 23: 'R_RISCV_LO12_I',
      24: 'R_RISCV_LO12_S', 25: 'R_RISCV_TPREL_HI20', 26: 'R_RISCV_TPREL_LO12_I',
      27: 'R_RISCV_TPREL_LO12_S', 28: 'R_RISCV_TPREL_ADD',
      29: 'R_RISCV_ADD8', 30: 'R_RISCV_ADD16', 31: 'R_RISCV_ADD32',
      32: 'R_RISCV_ADD64', 33: 'R_RISCV_SUB8', 34: 'R_RISCV_SUB16',
      35: 'R_RISCV_SUB32', 36: 'R_RISCV_SUB64', 43: 'R_RISCV_ALIGN',
      44: 'R_RISCV_RVC_BRANCH', 45: 'R_RISCV_RVC_JUMP', 51: 'R_RISCV_RELAX',
      52: 'R_RISCV_SUB6', 53: 'R_RISCV_SET6', 54: 'R_RISCV_SET8',
      55: 'R_RISCV_SET16', 56: 'R_RISCV_SET32', 57: 'R_RISCV_32_PCREL'
    },
    258: { // LoongArch (rough)
      0: 'R_LARCH_NONE', 1: 'R_LARCH_32', 2: 'R_LARCH_64', 3: 'R_LARCH_RELATIVE',
      4: 'R_LARCH_COPY', 5: 'R_LARCH_JUMP_SLOT', 6: 'R_LARCH_TLS_DTPMOD32',
      7: 'R_LARCH_TLS_DTPMOD64', 8: 'R_LARCH_TLS_DTPREL32',
      9: 'R_LARCH_TLS_DTPREL64', 10: 'R_LARCH_TLS_TPREL32',
      11: 'R_LARCH_TLS_TPREL64', 12: 'R_LARCH_IRELATIVE'
    }
  };

  const KIND_INFO = {
    ehdr: { label: 'ELF 头', color: '#a78bfa', desc: '文件头：魔数、架构、入口点与各表位置' },
    phdr: { label: '程序头表', color: '#60a5fa', desc: '运行时内存段描述（装载器使用）' },
    shdr: { label: '节头表', color: '#34d399', desc: '文件中各节的元信息' },
    code: { label: '代码', color: '#4ade80', desc: '可执行的机器指令' },
    rodata: { label: '只读数据', color: '#fbbf24', desc: '常量、字符串等只读数据' },
    data: { label: '可写数据', color: '#fb923c', desc: '可读写的已初始化数据' },
    bss: { label: 'BSS', color: '#94a3b8', desc: '未初始化数据，不占用文件字节' },
    symbols: { label: '符号表', color: '#f472b6', desc: '函数/变量符号及其地址信息' },
    strings: { label: '字符串表', color: '#38bdf8', desc: '以 NUL 结尾的字符串集合' },
    relocs: { label: '重定位', color: '#c084fc', desc: '链接/装载时需要修补的位置' },
    dynamic: { label: '动态链接', color: '#f87171', desc: '动态链接器需要的元信息' },
    notes: { label: '备注 Note', color: '#22d3ee', desc: '构建 ID、ABI、属性等附注信息' },
    got: { label: 'GOT / PLT', color: '#facc15', desc: '全局偏移表与跳转桩' },
    hash: { label: '哈希表', color: '#a8a29e', desc: '符号查找用的哈希表' },
    version: { label: '符号版本', color: '#93c5fd', desc: '符号版本定义与索引' },
    arrays: { label: '初始化数组', color: '#fda4af', desc: '构造/析构函数指针数组' },
    debug: { label: '调试信息', color: '#cbd5e1', desc: 'DWARF 等调试数据' },
    unwind: { label: '栈展开', color: '#f59e0b', desc: '异常处理与栈展开信息' },
    comment: { label: '注释', color: '#a3e635', desc: '编译器/链接器写入的注释' },
    other: { label: '其他节', color: '#64748b', desc: '其他类型的节' },
    gap: { label: '填充 / 未映射', color: '#334155', desc: '对齐填充或不属于任何节的数据' }
  };

  const ROLE_INFO = {
    ident: { label: '魔数 / 标识', color: '#e879f9', desc: '标识文件为 ELF 的魔数字节' },
    meta: { label: '类型 / 元数据', color: '#a78bfa', desc: '描述文件或条目的类型信息' },
    address: { label: '地址', color: '#60a5fa', desc: '虚拟内存地址' },
    offset: { label: '文件偏移', color: '#38bdf8', desc: '指回文件中的位置' },
    size: { label: '大小', color: '#34d399', desc: '字节长度或内存大小' },
    count: { label: '数量', color: '#2dd4bf', desc: '条目/段/节的个数' },
    flags: { label: '标志位', color: '#fbbf24', desc: '权限或属性位' },
    align: { label: '对齐', color: '#f59e0b', desc: '内存/文件对齐要求' },
    index: { label: '索引 / 链接', color: '#c084fc', desc: '引用其他表项的下标' },
    string: { label: '字符串', color: '#7dd3fc', desc: 'NUL 结尾的文本内容' },
    stringoff: { label: '字符串偏移', color: '#93c5fd', desc: '指向字符串表的偏移' },
    pad: { label: '保留 / 填充', color: '#475569', desc: '保留位或对齐填充' },
    code: { label: '机器码', color: '#4ade80', desc: '可执行的指令字节' },
    rodata: { label: '只读数据', color: '#fbbf24', desc: '只读常量数据' },
    data: { label: '可写数据', color: '#fb923c', desc: '可写数据' },
    symbol: { label: '符号', color: '#f472b6', desc: '符号表条目' },
    reloc: { label: '重定位', color: '#c084fc', desc: '重定位表条目' },
    dynamic: { label: '动态链接', color: '#f87171', desc: '动态链接表条目' },
    note: { label: '备注', color: '#22d3ee', desc: 'Note 段内容' },
    debug: { label: '调试', color: '#cbd5e1', desc: '调试信息' },
    unwind: { label: '栈展开', color: '#f59e0b', desc: '异常展开信息' },
    hash: { label: '哈希', color: '#a8a29e', desc: '哈希表数据' },
    version: { label: '版本', color: '#93c5fd', desc: '符号版本信息' },
    array: { label: '数组', color: '#fda4af', desc: '函数指针数组' },
    comment: { label: '注释', color: '#a3e635', desc: '注释文本' },
    got: { label: 'GOT/PLT', color: '#facc15', desc: '跳转表/偏移表' },
    other: { label: '其他', color: '#64748b', desc: '其他内容' },
    gap: { label: '填充 / 未映射', color: '#334155', desc: '未归属的字节' }
  };

  const ELF_LAYOUTS = {
    symbol: {
      32: [
        { key: 'st_name', label: 'st_name', off: 0, size: 4, role: 'stringoff' },
        { key: 'st_value', label: 'st_value', off: 4, size: 4, role: 'address' },
        { key: 'st_size', label: 'st_size', off: 8, size: 4, role: 'size' },
        { key: 'st_info', label: 'st_info', off: 12, size: 1, role: 'meta' },
        { key: 'st_other', label: 'st_other', off: 13, size: 1, role: 'meta' },
        { key: 'st_shndx', label: 'st_shndx', off: 14, size: 2, role: 'index' }
      ],
      64: [
        { key: 'st_name', label: 'st_name', off: 0, size: 4, role: 'stringoff' },
        { key: 'st_info', label: 'st_info', off: 4, size: 1, role: 'meta' },
        { key: 'st_other', label: 'st_other', off: 5, size: 1, role: 'meta' },
        { key: 'st_shndx', label: 'st_shndx', off: 6, size: 2, role: 'index' },
        { key: 'st_value', label: 'st_value', off: 8, size: 8, role: 'address' },
        { key: 'st_size', label: 'st_size', off: 16, size: 8, role: 'size' }
      ]
    },
    rel: {
      32: [
        { key: 'r_offset', label: 'r_offset', off: 0, size: 4, role: 'address' },
        { key: 'r_info', label: 'r_info', off: 4, size: 4, role: 'meta' }
      ],
      64: [
        { key: 'r_offset', label: 'r_offset', off: 0, size: 8, role: 'address' },
        { key: 'r_info', label: 'r_info', off: 8, size: 8, role: 'meta' }
      ]
    },
    rela: {
      32: [
        { key: 'r_offset', label: 'r_offset', off: 0, size: 4, role: 'address' },
        { key: 'r_info', label: 'r_info', off: 4, size: 4, role: 'meta' },
        { key: 'r_addend', label: 'r_addend', off: 8, size: 4, role: 'meta' }
      ],
      64: [
        { key: 'r_offset', label: 'r_offset', off: 0, size: 8, role: 'address' },
        { key: 'r_info', label: 'r_info', off: 8, size: 8, role: 'meta' },
        { key: 'r_addend', label: 'r_addend', off: 16, size: 8, role: 'meta' }
      ]
    },
    dyn: {
      32: [
        { key: 'd_tag', label: 'd_tag', off: 0, size: 4, role: 'meta' },
        { key: 'd_val', label: 'd_val', off: 4, size: 4, role: 'meta' }
      ],
      64: [
        { key: 'd_tag', label: 'd_tag', off: 0, size: 8, role: 'meta' },
        { key: 'd_val', label: 'd_val', off: 8, size: 8, role: 'meta' }
      ]
    }
  };

  /* ------------------------------------------------------------------ *
   * Helpers
   * ------------------------------------------------------------------ */

  const decoder = new TextDecoder('utf-8', { fatal: false });

  function hex(n, width) {
    if (typeof n === 'bigint') {
      let s = n.toString(16);
      if (width) s = s.padStart(width, '0');
      return '0x' + s;
    }
    if (!Number.isFinite(n)) return String(n);
    let s = Math.trunc(n).toString(16);
    if (width) s = s.padStart(width, '0');
    return '0x' + s;
  }

  function hexBytes(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  }

  function quote(s, max = 80) {
    s = String(s == null ? '' : s);
    if (s.length > max) s = s.slice(0, max - 1) + '…';
    return JSON.stringify(s);
  }

  function align4(n) { return (n + 3) & ~3; }

  function toArrayBuffer(buf) {
    if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
    if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    return new Uint8Array(buf);
  }

  function safeNumber(big) {
    if (big <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(big);
    return Number.MAX_SAFE_INTEGER;
  }

  /* ------------------------------------------------------------------ *
   * Parser
   * ------------------------------------------------------------------ */

  class ElfParser {
    constructor(input) {
      this.bytes = toArrayBuffer(input);
      this.len = this.bytes.length;
      this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
      this.warnings = [];
      this.errors = [];
      this.littleEndian = true;
      this.classBits = 64;
      this.is64 = true;
      this.symbols = [];
      this.symbolTables = new Map();
      this.relocs = [];
      this.dynamic = [];
      this.notes = [];
      this.needed = [];
      this.secByName = new Map();
      this.ident = null;
      this.header = null;
      this.programHeaders = [];
      this.sections = [];
    }

    warn(msg) {
      if (this.warnings.length < 200) this.warnings.push(msg);
    }

    has(off, size) {
      return Number.isFinite(off) && Number.isFinite(size) && off >= 0 && size >= 0 && off + size <= this.len;
    }

    u8(off) { return this.has(off, 1) ? this.bytes[off] : 0; }
    u16(off) { return this.has(off, 2) ? this.view.getUint16(off, this.littleEndian) : 0; }
    u32(off) { return this.has(off, 4) ? this.view.getUint32(off, this.littleEndian) : 0; }
    s32(off) { return this.has(off, 4) ? this.view.getInt32(off, this.littleEndian) : 0; }
    u64(off) {
      if (!this.has(off, 8)) return 0;
      const lo = this.view.getUint32(this.littleEndian ? off : off + 4, this.littleEndian);
      const hi = this.view.getUint32(this.littleEndian ? off + 4 : off, this.littleEndian);
      return lo + hi * 4294967296;
    }
    big64(off) {
      if (!this.has(off, 8)) return 0n;
      return this.view.getBigUint64(off, this.littleEndian);
    }
    readCString(start, end) {
      if (!Number.isFinite(start) || start < 0 || start >= this.len) return '';
      end = Math.min(end == null ? this.len : end, this.len);
      if (start >= end) return '';
      let e = start;
      while (e < end && this.bytes[e] !== 0) e++;
      return decoder.decode(this.bytes.subarray(start, e));
    }

    parse() {
      const model = {
        valid: false, warnings: this.warnings, errors: this.errors,
        fileSize: this.len, littleEndian: true, classBits: 64,
        ident: null, header: null, programHeaders: [], sections: [],
        symbols: [], relocs: [], dynamic: [], notes: [], needed: [],
        annotations: [], headerFields: [], stats: { kinds: {}, roles: {} },
        shstr: null, layoutBlocks: [], isStripped: null
      };

      if (this.len < 4) {
        this.errors.push('文件太小，连 ELF 魔数都不完整。');
        return Object.assign(model, { bytes: this.bytes });
      }
      const magicOk = this.bytes[0] === 0x7f && this.bytes[1] === 0x45 &&
        this.bytes[2] === 0x4c && this.bytes[3] === 0x46;
      if (!magicOk) {
        this.errors.push('不是 ELF 文件：开头不是 7F 45 4C 46 (\\x7fELF)。');
        return Object.assign(model, { bytes: this.bytes });
      }
      if (this.len < 16) {
        this.errors.push('ELF 标识不完整（文件被截断）。');
        return Object.assign(model, { bytes: this.bytes });
      }

      const classByte = this.bytes[4];
      const dataByte = this.bytes[5];
      if (classByte !== 1 && classByte !== 2) {
        this.errors.push(`不支持的 EI_CLASS=${classByte}（应为 1=32 位或 2=64 位）。`);
        return Object.assign(model, { bytes: this.bytes });
      }
      if (dataByte !== 1 && dataByte !== 2) {
        this.errors.push(`不支持的 EI_DATA=${dataByte}（应为 1=小端或 2=大端）。`);
        return Object.assign(model, { bytes: this.bytes });
      }
      this.is64 = classByte === 2;
      this.classBits = this.is64 ? 64 : 32;
      this.littleEndian = dataByte === 1;

      const identVersion = this.bytes[6];
      const osabi = this.bytes[7];
      const abiversion = this.bytes[8];
      const pad = this.bytes.slice(9, 16);

      if (this.len < (this.is64 ? 64 : 52)) {
        this.warn('ELF 头不完整，文件可能被截断；后续解析结果可能不可靠。');
      }

      this.ident = {
        magicOk, classByte, dataByte, version: identVersion, osabi, abiversion,
        pad, padHex: hexBytes(pad)
      };

      this.parseHeader();
      this.parseSections();
      this.parseProgramHeaders();
      this.parseSymbols();
      this.parseRelocations();
      this.parseDynamic();
      this.parseNotes();
      this.buildAnnotations();

      const h = this.header;
      const kindStats = model.stats.kinds;
      for (const seg of this.annotations) {
        kindStats[seg.kind] = (kindStats[seg.kind] || 0) + (seg.end - seg.start);
      }
      const bss = this.sections.filter(s => s.type === SHT_NOBITS)
        .reduce((a, s) => a + s.size, 0);
      if (bss) model.stats.bssBytes = bss;

      model.valid = true;
      model.littleEndian = this.littleEndian;
      model.classBits = this.classBits;
      model.ident = this.ident;
      model.header = h;
      model.headerFields = this.headerFields;
      model.programHeaders = this.programHeaders;
      model.sections = this.sections;
      model.symbols = this.symbols;
      model.relocs = this.relocs;
      model.dynamic = this.dynamic;
      model.notes = this.notes;
      model.needed = this.needed;
      model.annotations = this.annotations;
      model.shstr = this.shstr;
      model.layoutBlocks = this.buildLayoutBlocks();
      model.isStripped = !this.sections.some(s => s.name === '.symtab');
      model.bytes = this.bytes;
      model.machineName = MACHINES[h.machine] || ('EM_' + h.machine);
      model.typeName = ET[h.type] || ('ET_' + h.type);
      model.typeLabel = ET_LABEL[h.type] || '未知类型';
      model.osabiName = OSABI[this.ident.osabi] || ('OSABI_' + this.ident.osabi);
      model.entryVa = h.entry;
      model.entrySection = this.sectionAtVaddr(h.entry);
      model.needed = this.needed;

      // Entry point sanity check.
      if (h.type !== ET_CORE && h.entry) {
        const entrySeg = this.programHeaderAtVaddr(h.entry, true);
        if (!entrySeg) this.warn('入口点不在任何 PT_LOAD 内存段内。');
      }
      return model;
    }

    parseHeader() {
      const is64 = this.is64;
      const h = {};
      h.type = this.u16(16);
      h.machine = this.u16(18);
      h.version = this.u32(20);
      h.entry = is64 ? this.u64(24) : this.u32(24);
      h.phoff = is64 ? this.u64(32) : this.u32(28);
      h.shoff = is64 ? this.u64(40) : this.u32(32);
      h.flags = is64 ? this.u32(48) : this.u32(36);
      h.ehsize = this.u16(is64 ? 52 : 40);
      h.phentsize = this.u16(is64 ? 54 : 42);
      h.phnum = this.u16(is64 ? 56 : 44);
      h.shentsize = this.u16(is64 ? 58 : 46);
      h.shnum = this.u16(is64 ? 60 : 48);
      h.shstrndx = this.u16(is64 ? 62 : 50);

      // Extended numbering (see ELF spec: section 0 holds the real values).
      let extShnum = false, extShstr = false, extPhnum = false;
      if (h.shoff && h.shoff < this.len) {
        const shSizeOff = is64 ? 32 : 20;
        const shLinkOff = is64 ? 40 : 24;
        const shInfoOff = is64 ? 44 : 28;
        if (h.shnum === 0) {
          const n = is64 ? this.u64(h.shoff + shSizeOff) : this.u32(h.shoff + shSizeOff);
          if (n > 0) {
            if (n > 1000000) {
              this.warn('节数量异常巨大，已忽略扩展计数。');
            } else {
              h.shnum = n;
              extShnum = true;
            }
          }
        }
        if (h.shstrndx === SHN_XINDEX) {
          h.shstrndx = is64 ? this.u64(h.shoff + shLinkOff) : this.u32(h.shoff + shLinkOff);
          extShstr = true;
        }
        if (h.phnum === 0xffff) {
          h.phnum = this.u32(h.shoff + shInfoOff);
          extPhnum = true;
        }
      }
      h.extended = { extShnum, extShstr, extPhnum };
      this.header = h;

      const expectedPh = is64 ? 56 : 32;
      const expectedSh = is64 ? 64 : 40;
      if (h.phentsize && h.phentsize !== expectedPh) {
        this.warn(`e_phentsize=${h.phentsize}，与标准值 ${expectedPh} 不同。`);
      }
      if (h.shentsize && h.shentsize !== expectedSh) {
        this.warn(`e_shentsize=${h.shentsize}，与标准值 ${expectedSh} 不同。`);
      }
      if (h.ehsize && h.ehsize !== (is64 ? 64 : 52)) {
        this.warn(`e_ehsize=${h.ehsize}，与标准值 ${is64 ? 64 : 52} 不同。`);
      }
    }

    parseProgramHeaders() {
      const h = this.header;
      if (!h.phnum) return;
      if (!h.phoff || !this.has(h.phoff, 1)) {
        this.warn('程序头表偏移无效，无法读取程序头。');
        return;
      }
      const expected = this.is64 ? 56 : 32;
      let entsize = h.phentsize || expected;
      if (entsize < expected) {
        this.warn(`e_phentsize=${entsize} 小于标准值 ${expected}，按标准大小解析。`);
        entsize = expected;
      }
      let count = h.phnum;
      if (count > 100000) {
        this.warn(`程序头数量 ${count} 异常，已截断为 100000。`);
        count = 100000;
      }
      const available = Math.floor((this.len - h.phoff) / entsize);
      if (count > available) {
        this.warn(`程序头表超出文件末尾：声明 ${count} 条，仅有 ${available} 条可读。`);
        count = Math.max(0, available);
      }
      const phs = [];
      for (let i = 0; i < count; i++) {
        const base = h.phoff + i * entsize;
        const p = { index: i, base, entsize };
        if (this.is64) {
          p.type = this.u32(base);
          p.flags = this.u32(base + 4);
          p.offset = this.u64(base + 8);
          p.vaddr = this.u64(base + 16);
          p.paddr = this.u64(base + 24);
          p.filesz = this.u64(base + 32);
          p.memsz = this.u64(base + 40);
          p.align = this.u64(base + 48);
        } else {
          p.type = this.u32(base);
          p.offset = this.u32(base + 4);
          p.vaddr = this.u32(base + 8);
          p.paddr = this.u32(base + 12);
          p.filesz = this.u32(base + 16);
          p.memsz = this.u32(base + 20);
          p.flags = this.u32(base + 24);
          p.align = this.u32(base + 28);
        }
        p.typeName = PT[p.type] || ('PT_0x' + p.type.toString(16));
        p.flagsText = phFlagsText(p.flags);
        p.filesz = Math.min(p.filesz, Math.max(0, this.len - p.offset));
        if (p.offset + p.filesz > this.len) {
          this.warn(`程序头 #${i} 的文件范围超出文件末尾。`);
        }
        phs.push(p);
      }
      this.programHeaders = phs;
    }

    parseSections() {
      const h = this.header;
      if (!h.shoff || !h.shnum) {
        if (!h.shoff) this.warn('没有节头表（文件可能被剥离或为极简 ELF）。');
        this.shstr = null;
        return;
      }
      if (!this.has(h.shoff, 1)) {
        this.warn('节头表偏移超出文件范围。');
        return;
      }
      const expected = this.is64 ? 64 : 40;
      let entsize = h.shentsize || expected;
      if (entsize < expected) {
        this.warn(`e_shentsize=${entsize} 小于标准值 ${expected}，按标准大小解析。`);
        entsize = expected;
      }
      let count = h.shnum;
      if (count > 200000) {
        this.warn(`节数量 ${count} 异常，已截断为 200000。`);
        count = 200000;
      }
      const available = Math.floor((this.len - h.shoff) / entsize);
      if (count > available) {
        this.warn(`节头表超出文件末尾：声明 ${count} 节，仅有 ${available} 节可读。`);
        count = Math.max(0, available);
      }

      const sections = [];
      for (let i = 0; i < count; i++) {
        const base = h.shoff + i * entsize;
        const s = { index: i, base, entsize, headerOffset: base };
        if (this.is64) {
          s.nameOff = this.u32(base);
          s.type = this.u32(base + 4);
          s.flags = this.u64(base + 8);
          s.addr = this.u64(base + 16);
          s.offset = this.u64(base + 24);
          s.size = this.u64(base + 32);
          s.link = this.u32(base + 40);
          s.info = this.u32(base + 44);
          s.addralign = this.u64(base + 48);
          s.entsize = this.u64(base + 56);
        } else {
          s.nameOff = this.u32(base);
          s.type = this.u32(base + 4);
          s.flags = this.u32(base + 8);
          s.addr = this.u32(base + 12);
          s.offset = this.u32(base + 16);
          s.size = this.u32(base + 20);
          s.link = this.u32(base + 24);
          s.info = this.u32(base + 28);
          s.addralign = this.u32(base + 32);
          s.entsize = this.u32(base + 36);
        }
        s.typeName = SHT[s.type] || ('SHT_0x' + s.type.toString(16));
        s.flagsText = shFlagsText(s.flags);
        s.name = '';
        sections.push(s);
      }

      this.sections = sections;
      const shstrIndex = h.shstrndx;
      let shstr = null;
      if (shstrIndex > 0 && shstrIndex < sections.length) {
        const s = sections[shstrIndex];
        if (s.type === SHT_STRTAB) {
          shstr = { section: s, start: s.offset, size: Math.min(s.size, Math.max(0, this.len - s.offset)) };
        } else {
          this.warn(`e_shstrndx 指向的节 [${shstrIndex}] 不是字符串表。`);
        }
      } else if (shstrIndex >= sections.length && sections.length) {
        this.warn(`e_shstrndx=${shstrIndex} 超出节数量。`);
      }
      this.shstr = shstr;

      for (const s of sections) {
        if (shstr && s.nameOff < shstr.size) {
          s.name = this.readCString(shstr.start + s.nameOff, shstr.start + shstr.size);
        }
        if (!s.name) s.name = s.index === 0 ? '' : `[${s.index}]`;
        if (s.name && !this.secByName.has(s.name)) this.secByName.set(s.name, s);
        const info = classifySection(s);
        s.kind = info.kind;
        s.role = info.role;
        if (s.type !== SHT_NOBITS && s.size > 0) {
          if (s.offset + s.size > this.len) {
            this.warn(`节 ${s.name || '[' + s.index + ']'} 的范围超出文件末尾（已裁剪显示）。`);
          }
          const end = Math.min(s.offset + s.size, this.len);
          s.fileRange = s.offset < end ? { start: s.offset, end } : null;
        } else {
          s.fileRange = null;
        }
      }

      if (this.header.type === ET_REL) {
        // ET_REL symbols are section-relative; nothing extra needed here.
      }
    }

    parseSymbols() {
      for (const sec of this.sections) {
        if (sec.type !== SHT_SYMTAB && sec.type !== SHT_DYNSYM) continue;
        const expected = this.is64 ? 24 : 16;
        let entsize = sec.entsize || expected;
        if (entsize < expected) {
          this.warn(`节 ${sec.name} 的 sh_entsize=${entsize} 小于标准值 ${expected}。`);
          entsize = expected;
        }
        if (!sec.size || !this.has(sec.offset, 1)) continue;
        const strtab = this.sections[sec.link];
        const strStart = strtab && strtab.type === SHT_STRTAB ? strtab.offset : 0;
        const strSize = strtab ? Math.min(strtab.size, Math.max(0, this.len - strStart)) : 0;
        if (!strtab) this.warn(`符号表 ${sec.name} 的 sh_link=${sec.link} 未指向字符串表。`);
        const count = Math.floor(sec.size / entsize);
        const available = Math.floor((this.len - sec.offset) / entsize);
        if (count > available) {
          this.warn(`符号表 ${sec.name} 声明的条目数超出文件末尾。`);
        }
        const n = Math.min(count, available, 300000);
        const tableSymbols = [];
        for (let i = 0; i < n; i++) {
          const base = sec.offset + i * entsize;
          const sym = { index: i, base, table: sec.name, tableIndex: sec.index };
          let rawValue, rawSize;
          if (this.is64) {
            sym.nameOff = this.u32(base);
            sym.info = this.u8(base + 4);
            sym.other = this.u8(base + 5);
            sym.shndx = this.u16(base + 6);
            rawValue = this.u64(base + 8);
            rawSize = this.u64(base + 16);
          } else {
            sym.nameOff = this.u32(base);
            rawValue = this.u32(base + 4);
            rawSize = this.u32(base + 8);
            sym.info = this.u8(base + 12);
            sym.other = this.u8(base + 13);
            sym.shndx = this.u16(base + 14);
          }
          sym.bind = sym.info >> 4;
          sym.symbolType = sym.info & 0xf;
          sym.vis = sym.other & 0x3;
          sym.bindName = SYM_BIND[sym.bind] || ('STB_' + sym.bind);
          sym.typeName = SYM_TYPE[sym.symbolType] || ('STT_' + sym.symbolType);
          sym.visName = SYM_VIS[sym.vis] || ('STV_' + sym.vis);
          sym.value = rawValue;
          sym.size = rawSize;
          sym.name = (strtab && sym.nameOff < strSize)
            ? this.readCString(strStart + sym.nameOff, strStart + strSize) : '';
          sym.defined = sym.shndx !== SHN_UNDEF;
          sym.section = null;
          sym.shndxName = '';
          if (sym.shndx === SHN_UNDEF) sym.shndxName = 'SHN_UNDEF';
          else if (sym.shndx === SHN_ABS) sym.shndxName = 'SHN_ABS';
          else if (sym.shndx === SHN_COMMON) sym.shndxName = 'SHN_COMMON';
          else if (sym.shndx >= SHN_LORESERVE) sym.shndxName = 'SHN_0x' + sym.shndx.toString(16);
          else if (sym.shndx < this.sections.length) {
            sym.section = this.sections[sym.shndx];
            sym.shndxName = sym.section.name;
          } else {
            sym.shndxName = '#' + sym.shndx;
          }
          sym.fileOffset = null;
          if (sym.section && sym.section.type !== SHT_NOBITS) {
            sym.fileOffset = this.symbolValueToOffset(sym.value, sym.section);
          }
          sym.globalIndex = this.symbols.length;
          this.symbols.push(sym);
          tableSymbols.push(sym);
        }
        this.symbolTables.set(sec.index, tableSymbols);
      }
    }

    symbolValueToOffset(value, sec) {
      if (!sec || sec.type === SHT_NOBITS || !sec.size) return null;
      let rel = value - sec.addr;
      if (rel < 0 || rel >= sec.size) {
        if (value >= 0 && value < sec.size) rel = value;
        else return null;
      }
      const off = sec.offset + rel;
      return off < this.len ? off : null;
    }

    parseRelocations() {
      for (const sec of this.sections) {
        if (sec.type !== SHT_REL && sec.type !== SHT_RELA) continue;
        const isRela = sec.type === SHT_RELA;
        const expected = this.is64 ? (isRela ? 24 : 16) : (isRela ? 12 : 8);
        let entsize = sec.entsize || expected;
        if (entsize < expected) {
          this.warn(`节 ${sec.name} 的 sh_entsize=${entsize} 小于标准值 ${expected}。`);
          entsize = expected;
        }
        const symtab = this.symbolTables.get(sec.link) || [];
        const targetSec = this.sections[sec.info] || null;
        if (!sec.size) continue;
        const count = Math.floor(sec.size / entsize);
        const available = Math.floor((this.len - sec.offset) / entsize);
        const n = Math.min(count, available, 300000);
        for (let i = 0; i < n; i++) {
          const base = sec.offset + i * entsize;
          const rel = {
            index: i, base, table: sec.name, tableIndex: sec.index,
            rela: isRela, targetSection: targetSec
          };
          let infoBig, addend = null;
          if (this.is64) {
            rel.offset = this.u64(base);
            infoBig = this.big64(base + 8);
            rel.symIndex = Number(infoBig >> 32n);
            rel.type = Number(infoBig & 0xffffffffn);
            if (isRela) {
              addend = this.big64(base + 16);
              rel.addendBig = BigInt.asIntN(64, addend);
              rel.addend = safeNumber(rel.addendBig);
            }
          } else {
            rel.offset = this.u32(base);
            const info = this.u32(base + 4);
            rel.symIndex = info >>> 8;
            rel.type = info & 0xff;
            if (isRela) {
              addend = this.s32(base + 8);
              rel.addend = addend;
              rel.addendBig = BigInt(addend);
            }
          }
          rel.info = infoBig != null ? infoBig : BigInt(rel.symIndex * 256 + rel.type);
          rel.typeName = relocTypeName(this.header.machine, rel.type);
          rel.symbol = symtab[rel.symIndex] || null;
          rel.symbolName = rel.symbol && rel.symbol.name ? rel.symbol.name : '';
          if (targetSec && this.header.type === ET_REL) {
            rel.target = { kind: 'section', section: targetSec, vaddr: targetSec.addr + rel.offset };
          } else {
            rel.target = { kind: 'vaddr', vaddr: rel.offset, section: this.sectionAtVaddr(rel.offset) };
          }
          rel.globalIndex = this.relocs.length;
          this.relocs.push(rel);
        }
      }
    }

    parseDynamic() {
      for (const sec of this.sections) {
        if (sec.type !== SHT_DYNAMIC) continue;
        const expected = this.is64 ? 16 : 8;
        let entsize = sec.entsize || expected;
        if (entsize < expected) entsize = expected;
        const strtab = this.sections[sec.link];
        const strStart = strtab ? strtab.offset : 0;
        const strSize = strtab ? Math.min(strtab.size, Math.max(0, this.len - strStart)) : 0;
        const count = Math.floor(sec.size / entsize);
        const available = Math.floor((this.len - sec.offset) / entsize);
        const n = Math.min(count, available, 100000);
        let ended = false;
        for (let i = 0; i < n; i++) {
          const base = sec.offset + i * entsize;
          let tag, value;
          if (this.is64) {
            tag = this.big64(base);
            value = this.u64(base + 8);
          } else {
            tag = BigInt(this.s32(base));
            value = this.u32(base + 4);
          }
          const entry = {
            index: i, base, table: sec.name, baseTable: sec,
            tag, tagSigned: safeNumber(tag), value, d_ptr: value,
            afterNull: ended
          };
          entry.tagName = DYN_TAGS[entry.tagSigned] || ('0x' + tag.toString(16));
          if (tag > BigInt(Number.MAX_SAFE_INTEGER)) {
            entry.tagName = 'DT_0x' + tag.toString(16);
          }
          entry.stringValue = null;
          if (DYN_STRING_TAGS.has(entry.tagSigned) && strtab && value < strSize) {
            entry.stringValue = this.readCString(strStart + value, strStart + strSize);
            if (entry.tagSigned === 1 && entry.stringValue) this.needed.push(entry.stringValue);
          } else if (entry.tagSigned === 0x6ffffffb && strtab) {
            const parts = [];
            for (const bit of Object.keys(DT_FLAGS_1)) {
              if (value & Number(bit)) parts.push(DT_FLAGS_1[bit]);
            }
            entry.flags1 = parts;
          }
          if (entry.tagSigned === 0) ended = true;
          entry.globalIndex = this.dynamic.length;
          this.dynamic.push(entry);
        }
      }
    }

    parseNotes() {
      for (const sec of this.sections) {
        if (sec.type !== SHT_NOTE) continue;
        const end = Math.min(sec.offset + sec.size, this.len);
        let p = sec.offset;
        let guard = 0;
        while (p + 12 <= end && guard++ < 10000) {
          const namesz = this.u32(p);
          const descsz = this.u32(p + 4);
          const type = this.u32(p + 8);
          const nameStart = p + 12;
          const nameEnd = nameStart + namesz;
          const descStart = align4(nameEnd);
          const descEnd = descStart + descsz;
          if (namesz > 0x100000 || descsz > 0x1000000 || nameEnd > end || descEnd > end) {
            this.warn(`节 ${sec.name} 中的 Note 结构越界，停止解析。`);
            break;
          }
          const name = this.readCString(nameStart, nameEnd).replace(/\0+$/, '');
          const note = {
            index: this.notes.length, section: sec.name, sectionIndex: sec.index,
            offset: p, namesz, descsz, type, name,
            nameStart, nameEnd, descStart, descEnd,
            typeName: (NOTE_TYPES[name] && NOTE_TYPES[name][type]) ||
              (name === 'GNU' ? ('NT_GNU_' + type) : ('NOTE_' + type)),
            descHex: hexBytes(this.bytes.subarray(descStart, Math.min(descStart + 32, descEnd))),
            descText: null
          };
          if (name === 'GNU' && type === 3) {
            note.descText = hexBytes(this.bytes.subarray(descStart, descEnd));
          } else if (name === 'GNU' && type === 1 && descsz >= 16) {
            note.descText = [this.u32(descStart), this.u32(descStart + 4),
              this.u32(descStart + 8), this.u32(descStart + 12)].join(' . ');
          } else if (descsz && descsz <= 64) {
            let s = '';
            for (let i = descStart; i < descEnd; i++) {
              const c = this.bytes[i];
              s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
            }
            note.descText = s;
          }
          this.notes.push(note);
          const next = align4(descEnd);
          if (next <= p) break;
          p = next;
        }
      }
    }

    /* ------------------------- lookups ------------------------- */

    sectionAtOffset(off) {
      for (const s of this.sections) {
        if (!s.fileRange) continue;
        if (off >= s.fileRange.start && off < s.fileRange.end) return s;
      }
      return null;
    }

    sectionAtVaddr(addr) {
      if (!Number.isFinite(addr) || !addr) return null;
      for (const s of this.sections) {
        if (s.type === SHT_NOBITS || !s.size) {
          if (s.type === SHT_NOBITS && addr >= s.addr && addr < s.addr + s.size) return s;
          continue;
        }
        if (addr >= s.addr && addr < s.addr + s.size) return s;
      }
      return null;
    }

    programHeaderAtVaddr(addr, loadOnly) {
      for (const p of this.programHeaders) {
        if (loadOnly && p.type !== PT_LOAD) continue;
        if (addr >= p.vaddr && addr < p.vaddr + Math.max(p.memsz, p.filesz)) return p;
      }
      return null;
    }

    /* ------------------------- annotations ------------------------- */

    buildAnnotations() {
      const segs = [];
      const add = (s) => {
        if (!s || !Number.isFinite(s.start) || !Number.isFinite(s.end)) return;
        s.start = Math.max(0, Math.min(this.len, s.start));
        s.end = Math.max(0, Math.min(this.len, s.end));
        if (s.end <= s.start) return;
        if (!s.priority) s.priority = 10;
        segs.push(s);
      };

      this.buildHeaderFields();
      for (const f of this.headerFields) {
        add({
          start: f.start, end: f.start + f.size, kind: 'ehdr', role: f.role,
          title: f.label, field: f.label, valueText: f.valueText, desc: f.desc,
          priority: 100
        });
      }

      this.addProgramHeaderAnnotations(add);
      this.addSectionHeaderAnnotations(add);
      this.addSectionContentAnnotations(add);

      segs.sort((a, b) => (a.start - b.start) || (b.priority - a.priority));

      const clipped = [];
      let cursor = 0;
      for (const s of segs) {
        let start = s.start;
        let end = s.end;
        if (end <= cursor) continue;
        if (start < cursor) start = cursor;
        if (start >= end) continue;
        clipped.push(Object.assign({}, s, { start, end }));
        cursor = end;
      }

      // Fill the holes: headers/tables and sections rarely cover every byte.
      const filled = [];
      let pos = 0;
      for (const s of clipped) {
        if (s.start > pos) filled.push(this.makeGapSegment(pos, s.start));
        filled.push(s);
        pos = s.end;
      }
      if (pos < this.len) filled.push(this.makeGapSegment(pos, this.len));

      filled.sort((a, b) => a.start - b.start);
      filled.forEach((s, i) => { s.id = i; });
      this.annotations = filled;
    }

    makeGapSegment(start, end) {
      const mid = start + Math.floor((end - start) / 2);
      const sec = this.sectionAtOffset(mid);
      if (sec) {
        return {
          start, end, kind: sec.kind, role: sec.role, priority: 0,
          title: `${sec.name} · 未标注区间`, sectionIndex: sec.index,
          desc: '该区间属于节内容，但没有更细的结构信息。'
        };
      }
      const inside = this.programHeaders.some(p =>
        p.type === PT_LOAD && mid >= p.offset && mid < p.offset + p.filesz);
      return {
        start, end, kind: 'gap', role: 'gap', priority: 0,
        title: inside ? '段内填充 / 未归节字节' : '文件未映射区域',
        desc: inside
          ? '位于某个 PT_LOAD 段内，但不属于任何节；通常是页对齐填充。'
          : '不属于任何节或表的数据；可能是附加数据、签名或对齐填充。'
      };
    }

    buildHeaderFields() {
      const h = this.header;
      const is64 = this.is64;
      const typeName = ET[h.type] || ('ET_0x' + h.type.toString(16));
      const typeLabel = ET_LABEL[h.type] || '未知类型';
      const osabiName = OSABI[this.ident.osabi] || ('OSABI_' + this.ident.osabi);
      const fields = [];
      const push = (label, start, size, role, valueText, desc, key) => {
        fields.push({ key: key || label, label, start, size, role, valueText, desc });
      };
      const magic = hexBytes(this.bytes.subarray(0, 4));
      push('EI_MAG0-3', 0, 4, 'ident', magic,
        'ELF 魔数：7F 45 4C 46，即 DEL + “ELF”，用于识别 ELF 文件。', 'ident');
      push('EI_CLASS', 4, 1, 'ident', `${is64 ? 'ELF64' : 'ELF32'} (${this.ident.classByte})`,
        `文件类别：1 = 32 位，2 = 64 位。当前为 ${is64 ? '64' : '32'} 位格式。`);
      push('EI_DATA', 5, 1, 'ident',
        `${this.littleEndian ? '2\'s complement, little endian' : '2\'s complement, big endian'} (${this.ident.dataByte})`,
        '字节序：1 = 小端序（低位字节在前），2 = 大端序（高位字节在前）。');
      push('EI_VERSION', 6, 1, 'ident', `1 (current) [${this.ident.version}]`,
        'ELF 标识版本，标准值为 1。');
      push('EI_OSABI', 7, 1, 'ident', `${osabiName} (${this.ident.osabi})`,
        '目标操作系统 / ABI。0 表示 System V ABI，3 表示 GNU/Linux。');
      push('EI_ABIVERSION', 8, 1, 'ident', String(this.ident.abiversion),
        'ABI 版本号，通常为 0。');
      push('EI_PAD', 9, 7, 'pad', `00 ×7`,
        '保留填充字节，按规范应为 0。');
      push('e_type', 16, 2, 'meta',
        `${typeName} (${h.type}) — ${typeLabel}`,
        'ELF 文件类型：ET_REL 可重定位目标、ET_EXEC 可执行、ET_DYN 共享对象/PIE、ET_CORE 核心转储。');
      push('e_machine', 18, 2, 'meta',
        `${MACHINES[h.machine] || 'EM_UNKNOWN'} (${h.machine})`,
        '目标指令集架构（EM_X86_64=62、EM_386=3、EM_AARCH64=183、EM_ARM=40、EM_RISCV=243 等）。');
      push('e_version', 20, 4, 'meta', `1 [${h.version}]`,
        'ELF 版本号，标准值为 1。');
      push('e_entry', 24, is64 ? 8 : 4, 'address', hex(h.entry, is64 ? 16 : 8),
        '程序入口点的虚拟地址；装载完成后 CPU 从此处开始执行。');
      push('e_phoff', is64 ? 32 : 28, is64 ? 8 : 4, 'offset', hex(h.phoff, is64 ? 16 : 8),
        `程序头表在文件中的偏移。${h.phnum ? `其后是 ${h.phnum} 个程序头。` : '（本文件没有程序头）'}`);
      push('e_shoff', is64 ? 40 : 32, is64 ? 8 : 4, 'offset', hex(h.shoff, is64 ? 16 : 8),
        `节头表在文件中的偏移。${h.shnum ? `其后是 ${h.shnum} 个节头。` : '（本文件没有节头表）'}`);
      push('e_flags', is64 ? 48 : 36, 4, 'flags', hex(h.flags, 8),
        '处理器相关的标志位（不同架构含义不同，通常为 0）。');
      push('e_ehsize', is64 ? 52 : 40, 2, 'size', `${h.ehsize} B`,
        'ELF 头本身的大小（标准值：ELF64=64，ELF32=52）。');
      push('e_phentsize', is64 ? 54 : 42, 2, 'size', `${h.phentsize} B`,
        '每个程序头条目的大小（标准值：ELF64=56，ELF32=32）。');
      push('e_phnum', is64 ? 56 : 44, 2, 'count', String(h.phnum),
        '程序头（内存段描述）的数量。0 表示没有程序头表。');
      push('e_shentsize', is64 ? 58 : 46, 2, 'size', `${h.shentsize} B`,
        '每个节头条目的大小（标准值：ELF64=64，ELF32=40）。');
      push('e_shnum', is64 ? 60 : 48, 2, 'count', String(h.shnum),
        '节头（section header）的数量。若为 0 且存在节头表，真实数量存放在第 0 个节头中。');
      push('e_shstrndx', is64 ? 62 : 50, 2, 'index',
        `${h.shstrndx}${this.shstr && this.shstr.section ? ' → ' + this.shstr.section.name : ''}`,
        '节名字符串表（.shstrtab）在节头表中的索引。');
      this.headerFields = fields;
    }

    addProgramHeaderAnnotations(add) {
      const is64 = this.is64;
      for (const p of this.programHeaders) {
        const base = p.base;
        const tag = `程序头 #${p.index} · ${p.typeName}`;
        const entries = is64 ? [
          ['p_type', 0, 4, 'meta', `${p.typeName} (${hex(p.type, 4)})`],
          ['p_flags', 4, 4, 'flags', `${p.flagsText} (${hex(p.flags, 8)})`],
          ['p_offset', 8, 8, 'offset', hex(p.offset, 16)],
          ['p_vaddr', 16, 8, 'address', hex(p.vaddr, 16)],
          ['p_paddr', 24, 8, 'address', hex(p.paddr, 16)],
          ['p_filesz', 32, 8, 'size', `${p.filesz} B`],
          ['p_memsz', 40, 8, 'size', `${p.memsz} B`],
          ['p_align', 48, 8, 'align', hex(p.align, 16)]
        ] : [
          ['p_type', 0, 4, 'meta', `${p.typeName} (${hex(p.type, 4)})`],
          ['p_offset', 4, 4, 'offset', hex(p.offset, 8)],
          ['p_vaddr', 8, 4, 'address', hex(p.vaddr, 8)],
          ['p_paddr', 12, 4, 'address', hex(p.paddr, 8)],
          ['p_filesz', 16, 4, 'size', `${p.filesz} B`],
          ['p_memsz', 20, 4, 'size', `${p.memsz} B`],
          ['p_flags', 24, 4, 'flags', `${p.flagsText} (${hex(p.flags, 8)})`],
          ['p_align', 28, 4, 'align', hex(p.align, 8)]
        ];
        for (const [name, off, size, role, valueText] of entries) {
          add({
            start: base + off, end: base + off + size, kind: 'phdr', role,
            title: `${tag} · ${name}`, field: name, valueText,
            desc: phFieldDesc(name, p),
            sectionIndex: null, priority: 90
          });
        }
      }
    }

    addSectionHeaderAnnotations(add) {
      const is64 = this.is64;
      for (const s of this.sections) {
        const base = s.headerOffset;
        const tag = `节头 [${s.index}] ${s.name || '(无名节)'}`;
        const entries = is64 ? [
          ['sh_name', 0, 4, 'stringoff', s.nameOff],
          ['sh_type', 4, 4, 'meta', `${s.typeName} (${hex(s.type, 8)})`],
          ['sh_flags', 8, 8, 'flags', s.flagsText],
          ['sh_addr', 16, 8, 'address', hex(s.addr, 16)],
          ['sh_offset', 24, 8, 'offset', hex(s.offset, 16)],
          ['sh_size', 32, 8, 'size', `${s.size} B`],
          ['sh_link', 40, 4, 'index', indexLinkText(s.link, this.sections)],
          ['sh_info', 44, 4, 'index', String(s.info)],
          ['sh_addralign', 48, 8, 'align', String(s.addralign)],
          ['sh_entsize', 56, 8, 'size', s.entsize ? `${s.entsize} B` : '0']
        ] : [
          ['sh_name', 0, 4, 'stringoff', s.nameOff],
          ['sh_type', 4, 4, 'meta', `${s.typeName} (${hex(s.type, 8)})`],
          ['sh_flags', 8, 4, 'flags', s.flagsText],
          ['sh_addr', 12, 4, 'address', hex(s.addr, 8)],
          ['sh_offset', 16, 4, 'offset', hex(s.offset, 8)],
          ['sh_size', 20, 4, 'size', `${s.size} B`],
          ['sh_link', 24, 4, 'index', indexLinkText(s.link, this.sections)],
          ['sh_info', 28, 4, 'index', String(s.info)],
          ['sh_addralign', 32, 4, 'align', String(s.addralign)],
          ['sh_entsize', 36, 4, 'size', s.entsize ? `${s.entsize} B` : '0']
        ];
        for (const [name, off, size, role, valueText] of entries) {
          add({
            start: base + off, end: base + off + size, kind: 'shdr', role,
            title: `${tag} · ${name}`, field: name, valueText,
            desc: shFieldDesc(name, s),
            sectionIndex: null, priority: 80
          });
        }
      }
    }

    addSectionContentAnnotations(add) {
      for (const sec of this.sections) {
        if (!sec.fileRange) continue;
        const start = sec.fileRange.start;
        const end = sec.fileRange.end;
        const base = {
          sectionIndex: sec.index, kind: sec.kind, role: sec.role
        };
        if (sec.type === SHT_SYMTAB || sec.type === SHT_DYNSYM) {
          const arr = this.symbolTables.get(sec.index) || [];
          let cursor = start;
          const entSize = sec.entsize || (this.is64 ? 24 : 16);
          for (const sym of arr) {
            if (sym.base < cursor) continue;
            const e = Math.min(sym.base + entSize, end);
            if (sym.base >= end) break;
            add(Object.assign({}, base, {
              start: sym.base, end: e, title: symbolTitle(sym),
              ref: sym, entryType: 'symbol', entryIndex: sym.index,
              entryBase: sym.base, entrySize: entSize, priority: 40
            }));
            cursor = e;
          }
          this.addRemainder(add, cursor, end, sec, base);
          continue;
        }
        if (sec.type === SHT_REL || sec.type === SHT_RELA) {
          const arr = this.relocs.filter(r => r.tableIndex === sec.index);
          let cursor = start;
          const entSize = sec.entsize || (this.is64 ? (sec.type === SHT_RELA ? 24 : 16) : (sec.type === SHT_RELA ? 12 : 8));
          for (const rel of arr) {
            if (rel.base < cursor) continue;
            const e = Math.min(rel.base + entSize, end);
            if (rel.base >= end) break;
            add(Object.assign({}, base, {
              start: rel.base, end: e,
              title: `重定位 #${rel.index} · ${rel.typeName}`,
              ref: rel, entryType: sec.type === SHT_RELA ? 'rela' : 'rel',
              entryIndex: rel.index, entryBase: rel.base, entrySize: entSize, priority: 40
            }));
            cursor = e;
          }
          this.addRemainder(add, cursor, end, sec, base);
          continue;
        }
        if (sec.type === SHT_DYNAMIC) {
          const arr = this.dynamic.filter(d => d.baseTable === sec);
          let cursor = start;
          const entSize = sec.entsize || (this.is64 ? 16 : 8);
          for (const d of arr) {
            if (d.base < cursor) continue;
            const e = Math.min(d.base + entSize, end);
            if (d.base >= end) break;
            if (d.afterNull) {
              add(Object.assign({}, base, {
                start: d.base, end: e, role: 'pad',
                title: `${sec.name} · DT_NULL 之后填充`,
                desc: '动态链接表在 DT_NULL 之后结束；这些槽位通常被填充为 0，不参与链接。',
                priority: 40
              }));
            } else {
              add(Object.assign({}, base, {
                start: d.base, end: e,
                title: `动态项 #${d.index} · ${d.tagName}`,
                ref: d, entryType: 'dyn', entryIndex: d.index,
                entryBase: d.base, entrySize: entSize, priority: 40
              }));
            }
            cursor = e;
          }
          this.addRemainder(add, cursor, end, sec, base);
          continue;
        }
        if (sec.type === SHT_NOTE) {
          this.addNoteContent(add, sec, start, end, base);
          continue;
        }
        if (sec.type === SHT_STRTAB) {
          this.addStringContent(add, sec, start, end, base);
          continue;
        }
        if (sec.type === SHT_GNU_VERSYM) {
          let cursor = start;
          for (let i = 0; cursor + 2 <= end; i++, cursor += 2) {
            const v = this.u16(cursor);
            add(Object.assign({}, base, {
              start: cursor, end: cursor + 2,
              title: `版本索引 #${i} · ${v === 0 ? 'local' : v === 1 ? 'global' : '#' + v}`,
              valueText: String(v), priority: 40
            }));
          }
          this.addRemainder(add, cursor, end, sec, base);
          continue;
        }
        if (sec.type === SHT_GNU_HASH || sec.type === SHT_HASH) {
          this.addHashContent(add, sec, start, end, base);
          continue;
        }

        // Code / data sections: annotate by symbol when possible, and make
        // sure every byte in between is annotated as well.
        const syms = this.symbolsForSection(sec);
        if (syms.length) {
          let cursor = start;
          for (const sym of syms) {
            let sStart = Math.max(sym.fileOffset, start);
            let sEnd = Math.min(sym.fileOffset + sym.rangeSize, end);
            if (sStart < cursor) sStart = cursor;
            if (sEnd <= sStart) continue;
            if (sStart > cursor) {
              add(Object.assign({}, base, {
                start: cursor, end: sStart,
                title: `${sec.name} · 未归属符号的字节`,
                desc: '该区间不属于任何已知符号（或符号没有大小信息）。',
                priority: 30
              }));
            }
            add(Object.assign({}, base, {
              start: sStart, end: sEnd,
              title: sym.name || '(未命名符号)',
              ref: sym, entryType: 'symbol-range', sectionIndex: sec.index,
              priority: 30
            }));
            cursor = sEnd;
          }
          this.addRemainder(add, cursor, end, sec, base);
        } else {
          add(Object.assign({}, base, {
            start, end, title: sec.name || '[无名节]',
            desc: sectionDesc(sec), priority: 30
          }));
        }
      }
    }

    addRemainder(add, cursor, end, sec, base) {
      if (cursor < end) {
        add(Object.assign({}, base, {
          start: cursor, end, title: `${sec.name} · 剩余 / 填充`,
          desc: '该节中未被更小结构覆盖的字节（条目补齐或尾部填充）。', priority: 20
        }));
      }
    }

    addNoteContent(add, sec, start, end, base) {
      const notes = this.notes.filter(n => n.sectionIndex === sec.index);
      if (!notes.length) {
        add(Object.assign({}, base, {
          start, end, title: sec.name, desc: sectionDesc(sec), priority: 30
        }));
        return;
      }
      for (const n of notes) {
        const nStart = n.offset;
        const nEnd = Math.min(align4(n.descEnd), end);
        const tag = `Note #${n.index} · ${n.name || '(未命名)'}`;
        add(Object.assign({}, base, {
          start: nStart, end: Math.min(nStart + 4, nEnd),
          title: `${tag} · namesz`, field: 'namesz', valueText: `${n.namesz} B`,
          desc: 'Note 名称的字节长度（包含结尾 NUL）。', priority: 50
        }));
        add(Object.assign({}, base, {
          start: nStart + 4, end: Math.min(nStart + 8, nEnd),
          title: `${tag} · descsz`, field: 'descsz', valueText: `${n.descsz} B`,
          desc: 'Note 描述数据的字节长度。', priority: 50
        }));
        add(Object.assign({}, base, {
          start: nStart + 8, end: Math.min(nStart + 12, nEnd),
          title: `${tag} · type`, field: 'type', valueText: `${n.typeName} (${hex(n.type, 8)})`,
          desc: 'Note 类型，含义由名称空间（如 GNU/Go/CORE）约定。', priority: 50
        }));
        add(Object.assign({}, base, {
          start: n.nameStart, end: Math.min(n.nameEnd, nEnd),
          title: `${tag} · name`, field: 'name', valueText: quote(n.name),
          desc: 'Note 名称空间（例如 GNU、Go）。', priority: 50
        }));
        if (n.descEnd > n.descStart) {
          add(Object.assign({}, base, {
            start: n.descStart, end: Math.min(n.descEnd, nEnd),
            title: `${tag} · desc`, field: 'desc',
            valueText: n.typeName + (n.descText ? ' — ' + n.descText : ''),
            desc: 'Note 的描述数据：构建 ID、ABI 标签、属性串等。', priority: 50
          }));
        }
        const padStart = Math.min(n.descEnd, nEnd);
        if (padStart < nEnd) {
          add(Object.assign({}, base, {
            start: padStart, end: nEnd, title: `${tag} · 填充`,
            desc: 'Note 条目按 4 字节对齐所需的填充。', priority: 40
          }));
        }
      }
      const last = notes.reduce((a, n) => Math.max(a, align4(n.descEnd)), start);
      this.addRemainder(add, Math.min(last, end), end, sec, base);
    }

    addStringContent(add, sec, start, end, base) {
      let p = start;
      let count = 0;
      let cursor = start;
      const addPadding = (from, to) => {
        if (to <= from) return;
        add(Object.assign({}, base, {
          start: from, end: to, title: `${sec.name} · 字符串表填充`,
          desc: '字符串表中未被引用的 NUL 字节 / 对齐填充。',
          priority: 25
        }));
      };
      while (p < end && count < 60000) {
        if (this.bytes[p] === 0) {
          p++;
          continue;
        }
        const s = p;
        while (p < end && this.bytes[p] !== 0) p++;
        const e = Math.min(p + 1, end);
        addPadding(cursor, s);
        const text = decoder.decode(this.bytes.subarray(s, Math.min(p, end)));
        add(Object.assign({}, base, {
          start: s, end: e,
          title: quote(text, 60),
          valueText: quote(text, 80),
          desc: `字符串表 ${sec.name} 中的一个以 NUL 结尾的字符串（偏移 +${hex(s - start, 4)}）。`,
          priority: 30
        }));
        cursor = e;
        p = e;
        count++;
      }
      if (cursor < end) addPadding(cursor, end);
    }

    addHashContent(add, sec, start, end, base) {
      const secStart = start;
      const pushField = (name, off, size, valueText, desc) => {
        if (secStart + off + size <= end) {
          add(Object.assign({}, base, {
            start: secStart + off, end: secStart + off + size,
            title: `${sec.name} · ${name}`, field: name, valueText, desc, priority: 40
          }));
        }
      };
      if (sec.type === SHT_HASH) {
        pushField('nbucket', 0, 4, String(this.u32(start)), '哈希桶的数量。');
        pushField('nchain', 4, 4, String(this.u32(start + 4)), '符号链的数量。');
        const cursor = start + 8;
        if (cursor < end) {
          add(Object.assign({}, base, {
            start: cursor, end, title: `${sec.name} · 桶与链`,
            desc: '哈希桶数组与冲突链，用于按名称查找符号。', priority: 30
          }));
        }
      } else {
        pushField('nbuckets', 0, 4, String(this.u32(start)), 'GNU 哈希表的桶数量。');
        pushField('symoffset', 4, 4, String(this.u32(start + 4)), '第一个参与哈希的符号索引。');
        pushField('bloom_size', 8, 4, String(this.u32(start + 8)), 'Bloom 过滤器字数。');
        pushField('bloom_shift', 12, 4, String(this.u32(start + 12)), 'Bloom 过滤器位移。');
        const cursor = start + 16;
        if (cursor < end) {
          add(Object.assign({}, base, {
            start: cursor, end, title: `${sec.name} · Bloom 过滤器 / 桶 / 链`,
            desc: 'GNU 哈希表的其余数据（Bloom 位图、桶、冲突链）。', priority: 30
          }));
        }
      }
    }

    symbolsForSection(sec) {
      if (!sec || !sec.fileRange) return [];
      const table = this.symbols.filter(s =>
        s.section === sec && s.fileOffset != null &&
        s.name && s.symbolType !== 3 && s.symbolType !== 4 &&
        (s.symbolType === 1 || s.symbolType === 2 || s.symbolType === 6 || s.symbolType === 10) &&
        s.size < 0x10000000
      );
      // Deduplicate aliases at the same address, preferring the largest size.
      const byOff = new Map();
      for (const s of table) {
        const prev = byOff.get(s.fileOffset);
        if (!prev || (s.size || 0) > (prev.size || 0) ||
          ((s.size || 0) === (prev.size || 0) && s.bind === 1 && prev.bind !== 1)) {
          byOff.set(s.fileOffset, s);
        }
      }
      const arr = [];
      const secEnd = sec.fileRange.end;
      for (const s of byOff.values()) {
        if (s.fileOffset < sec.fileRange.start || s.fileOffset >= secEnd) continue;
        let end = s.fileOffset + (s.size || 0);
        if (!s.size || end > secEnd) end = secEnd;
        if (end <= s.fileOffset) end = Math.min(s.fileOffset + 1, secEnd);
        s.rangeSize = end - s.fileOffset;
        s.rangeEnd = end;
        arr.push(s);
      }
      arr.sort((a, b) => a.fileOffset - b.fileOffset || b.rangeSize - a.rangeSize);
      return arr;
    }

    buildLayoutBlocks() {
      const blocks = [];
      const add = (start, end, kind, label, sectionIndex) => {
        start = Math.max(0, Math.min(this.len, start));
        end = Math.max(0, Math.min(this.len, end));
        if (end > start) blocks.push({ start, end, kind, label, sectionIndex });
      };
      const h = this.header;
      add(0, h.ehsize || (this.is64 ? 64 : 52), 'ehdr', 'ELF 头');
      if (h.phoff && h.phnum) {
        add(h.phoff, h.phoff + h.phnum * (h.phentsize || (this.is64 ? 56 : 32)),
          'phdr', '程序头表');
      }
      if (h.shoff && h.shnum) {
        add(h.shoff, h.shoff + h.shnum * (h.shentsize || (this.is64 ? 64 : 40)),
          'shdr', '节头表');
      }
      for (const s of this.sections) {
        if (s.fileRange) {
          // Prefer the section's declared range (including clipped tail).
          add(s.offset, s.offset + s.size, s.kind, s.name || `[${s.index}]`, s.index);
        }
      }
      blocks.sort((a, b) => a.start - b.start || b.end - a.end);
      const out = [];
      let cursor = 0;
      for (const b of blocks) {
        if (b.end <= cursor) continue;
        const start = Math.max(b.start, cursor);
        if (start >= b.end) continue;
        out.push({ start, end: b.end, kind: b.kind, label: b.label, sectionIndex: b.sectionIndex });
        cursor = b.end;
      }
      // Fill gaps between structural blocks so the map is continuous.
      const filled = [];
      let pos = 0;
      for (const b of out) {
        if (b.start > pos) {
          filled.push({ start: pos, end: b.start, kind: 'gap', label: '填充 / 未映射', sectionIndex: null });
        }
        filled.push(b);
        pos = Math.max(pos, b.end);
      }
      if (pos < this.len) {
        filled.push({ start: pos, end: this.len, kind: 'gap', label: '未映射', sectionIndex: null });
      }
      // Merge adjacent gaps.
      const merged = [];
      for (const b of filled) {
        const prev = merged[merged.length - 1];
        if (prev && prev.kind === 'gap' && b.kind === 'gap') prev.end = b.end;
        else merged.push(b);
      }
      return merged;
    }
  }

  /* ------------------------------------------------------------------ *
   * Small text helpers
   * ------------------------------------------------------------------ */

  function phFlagsText(flags) {
    const p = [];
    if (flags & PF_R) p.push('R');
    if (flags & PF_W) p.push('W');
    if (flags & PF_X) p.push('E');
    return p.length ? p.join(' ') : '—';
  }

  function shFlagsText(flags) {
    const p = [];
    if (flags & SHF_WRITE) p.push('W');
    if (flags & SHF_ALLOC) p.push('A');
    if (flags & SHF_EXECINSTR) p.push('X');
    if (flags & SHF_MERGE) p.push('M');
    if (flags & SHF_STRINGS) p.push('S');
    if (flags & SHF_INFO_LINK) p.push('I');
    if (flags & SHF_LINK_ORDER) p.push('L');
    if (flags & SHF_OS_NONCONFORMING) p.push('O');
    if (flags & SHF_GROUP) p.push('G');
    if (flags & SHF_TLS) p.push('T');
    if (flags & SHF_COMPRESSED) p.push('C');
    if (flags & SHF_GNU_RETAIN) p.push('R');
    return p.length ? p.join(' ') : '—';
  }

  function shFlagsDetail(flags) {
    const p = [];
    if (flags & SHF_WRITE) p.push('可写');
    if (flags & SHF_ALLOC) p.push('运行时分配内存');
    if (flags & SHF_EXECINSTR) p.push('可执行');
    if (flags & SHF_MERGE) p.push('可合并');
    if (flags & SHF_STRINGS) p.push('字符串表');
    if (flags & SHF_TLS) p.push('线程局部');
    if (flags & SHF_COMPRESSED) p.push('已压缩');
    return p.join('、') || '无';
  }

  function indexLinkText(idx, sections) {
    if (!idx) return '0';
    const s = sections[idx];
    return s ? `${idx} → ${s.name || '[' + idx + ']'}` : String(idx);
  }

  function phFieldDesc(name, p) {
    switch (name) {
      case 'p_type': return '程序头类型：PT_LOAD=可装载段，PT_DYNAMIC=动态链接信息，PT_INTERP=解释器路径，PT_NOTE=附注，PT_GNU_STACK=栈权限。';
      case 'p_flags': return '段的内存权限：R=可读，W=可写，E=可执行（PF_R=4, PF_W=2, PF_X=1）。';
      case 'p_offset': return '该段内容在文件中的起始偏移。';
      case 'p_vaddr': return '该段被装载到的虚拟地址。';
      case 'p_paddr': return '物理地址（在大多数现代系统中未使用，与 p_vaddr 相同）。';
      case 'p_filesz': return '该段在文件中占用的字节数；可以为 0。';
      case 'p_memsz': return '该段在内存中占用的字节数；大于 p_filesz 的部分由 0 填充（.bss）。';
      case 'p_align': return '段在文件和内存中的对齐要求（0/1 表示无对齐约束）。';
      default: return '';
    }
  }

  function shFieldDesc(name, s) {
    switch (name) {
      case 'sh_name': return '节名称在 .shstrtab 中的偏移（不是直接的名字）。';
      case 'sh_type': return '节类型：PROGBITS 数据、SYMTAB 符号表、STRTAB 字符串表、RELA 重定位、NOBITS 不占文件等。';
      case 'sh_flags': return `节属性：${shFlagsDetail(s.flags)}。`;
      case 'sh_addr': return '节在运行时内存中的虚拟地址（未分配内存的节通常为 0）。';
      case 'sh_offset': return '节内容在文件中的起始偏移；NOBITS 节无文件内容。';
      case 'sh_size': return '节的大小（字节）。对 NOBITS 节而言是运行时占用的内存大小。';
      case 'sh_link': return '关联节的索引，含义取决于节类型（如符号表→字符串表、重定位→符号表）。';
      case 'sh_info': return '附加信息，含义取决于节类型（如重定位节→目标节索引）。';
      case 'sh_addralign': return '节内容的地址对齐要求（必须是 2 的幂，0/1 表示无约束）。';
      case 'sh_entsize': return '若节由固定大小的条目组成，表示每条大小（如符号表、重定位表）。';
      default: return '';
    }
  }

  function classifySection(s) {
    if (s.type === SHT_NOBITS) {
      return { kind: 'bss', role: 'data' };
    }
    switch (s.type) {
      case SHT_SYMTAB:
      case SHT_DYNSYM:
        return { kind: 'symbols', role: 'symbol' };
      case SHT_STRTAB:
        return { kind: 'strings', role: 'string' };
      case SHT_RELA:
      case SHT_REL:
        return { kind: 'relocs', role: 'reloc' };
      case SHT_DYNAMIC:
        return { kind: 'dynamic', role: 'dynamic' };
      case SHT_NOTE:
        return { kind: 'notes', role: 'note' };
      case SHT_HASH:
      case SHT_GNU_HASH:
        return { kind: 'hash', role: 'hash' };
      case SHT_GNU_VERSYM:
      case SHT_GNU_VERDEF:
      case SHT_GNU_VERNEED:
        return { kind: 'version', role: 'version' };
      case SHT_INIT_ARRAY:
      case SHT_FINI_ARRAY:
      case SHT_PREINIT_ARRAY:
        return { kind: 'arrays', role: 'array' };
    }
    const n = s.name || '';
    if (n.startsWith('.debug') || n.startsWith('.zdebug')) return { kind: 'debug', role: 'debug' };
    if (n === '.comment' || n.startsWith('.comment.')) return { kind: 'comment', role: 'comment' };
    if (n.startsWith('.eh_frame') || n.startsWith('.gcc_except_table') ||
      n === '.ARM.exidx' || n === '.ARM.extab') return { kind: 'unwind', role: 'unwind' };
    if (n === '.got' || n === '.got.plt' || n.startsWith('.got.') ||
      n === '.plt.got' || n === '.plt.sec') return { kind: 'got', role: 'got' };
    if (s.flags & SHF_EXECINSTR) return { kind: 'code', role: 'code' };
    if (s.flags & SHF_WRITE) return { kind: 'data', role: 'data' };
    if (s.flags & SHF_ALLOC) return { kind: 'rodata', role: 'rodata' };
    return { kind: 'other', role: 'other' };
  }

  function sectionDesc(s) {
    return `节 ${s.name || '[' + s.index + ']'}：${s.typeName}，${s.size} 字节，文件偏移 ${hex(s.offset)}。权限标志：${shFlagsText(s.flags)}。`;
  }

  function symbolTitle(sym) {
    const name = sym.name || '(未命名)';
    if (sym.symbolType === 2) return `函数 ${name}`;
    if (sym.symbolType === 1) return `数据 ${name}`;
    return `符号 ${name}`;
  }

  function relocTypeName(machine, type) {
    const t = RELOC_TYPES[machine];
    if (t && t[type]) return t[type];
    return 'R_' + (MACHINES[machine] || machine) + '_' + type;
  }

  function layoutFor(entryType, classBits) {
    const l = ELF_LAYOUTS[entryType];
    if (!l) return null;
    return l[classBits] || null;
  }

  function fieldForEntryOffset(entryType, classBits, relOffset) {
    const layout = layoutFor(entryType, classBits);
    if (!layout) return null;
    for (const f of layout) {
      if (relOffset >= f.off && relOffset < f.off + f.size) return f;
    }
    return null;
  }

  /* ------------------------------------------------------------------ *
   * Public API
   * ------------------------------------------------------------------ */

  function parse(input) {
    try {
      const p = new ElfParser(input);
      return p.parse();
    } catch (err) {
      return {
        valid: false,
        errors: ['解析失败：' + (err && err.message ? err.message : String(err))],
        warnings: [],
        fileSize: input && input.byteLength != null ? input.byteLength : 0,
        bytes: input instanceof ArrayBuffer ? new Uint8Array(input) :
          (ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(0)),
        annotations: [], sections: [], programHeaders: [], symbols: [],
        relocs: [], dynamic: [], notes: [], headerFields: [],
        stats: { kinds: {}, roles: {} }
      };
    }
  }

  return {
    parse,
    KIND_INFO,
    ROLE_INFO,
    SHT,
    PT,
    ET,
    MACHINES,
    OSABI,
    hex,
    layoutFor,
    fieldForEntryOffset,
    relocTypeName,
    shFlagsDetail
  };
});

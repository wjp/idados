
#ifdef __AMD64__
//#define Eax Rax
//#define Ebx Rbx
//#define Ecx Rcx
//#define Edx Rdx
//#define Esi Rsi
//#define Edi Rdi
//#define Ebp Rbp
//#define Esp Rsp
#define Eip Rip
typedef DWORD64 cpuregtype_t;
#else
typedef ulong cpuregtype_t;
#endif


#define MEMORY_PAGE_SIZE 0x1000
#define BPT_CODE         { 0xCC }
#define FPU_REGS_COUNT 8        // number of FPU registers
#define MAX_BPT 4               // maximal number of hardware breakpoints

enum register_class_x86_t
{
  RC_GENERAL          = 0x01,
  RC_SEGMENTS         = 0x02,
  RC_FPU              = 0x04, // Floating Point Unit registers
  // RC_MMX              = 0x08
};

enum register_x86_t
{
  // FPU registers
  R_ST0,
  R_ST1,
  R_ST2,
  R_ST3,
  R_ST4,
  R_ST5,
  R_ST6,
  R_ST7,
  R_CTRL,
  R_STAT,
  R_TAGS,
  // segment registers
  R_CS,
  R_DS,
  R_ES,
  R_FS,
  R_GS,
  R_SS,
  // general registers
  R_EAX,
  R_EBX,
  R_ECX,
  R_EDX,
  R_ESI,
  R_EDI,
  R_EBP,
  R_ESP,
  R_EIP,
#ifdef __EA64__
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
#endif
  R_EFLAGS,
};



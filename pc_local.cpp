#include <dbg.hpp>

#include "deb_pc.hpp"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTIONS INFORMATIONS
//
//--------------------------------------------------------------------------

char* register_classes[] =
{
  "General registers",
  "Segment registers",
  "FPU registers",
  // "XMM",
  // "MMX",
  NULL
};


char* eflags[] =
{
  "CF",
  NULL,
  "PF",
  NULL,
  "AF",
  NULL,
  "ZF",
  "SF",
  "TF",
  "IF",
  "DF",
  "OF",
  "IOPL",
  "IOPL",
  "NT",
  NULL,
  "RF",
  "VM",
  "AC",
  "VIF",
  "VIP",
  "ID",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

char *ctrlflags[] =
{
  "IM",
  "DM",
  "ZM",
  "OM",
  "UM",
  "PM",
  NULL,
  NULL,
  "PC",
  "PC",
  "RC",
  "RC",
  "X",
  NULL,
  NULL,
  NULL
};

char *statflags[] =
{
  "IE",
  "DE",
  "ZE",
  "OE",
  "UE",
  "PE",
  "SF",
  "ES",
  "C0",
  "C1",
  "C2",
  "TOP",
  "TOP",
  "TOP",
  "C3",
  "B"
};

char *tagsflags[] =
{
  "TAG0",
  "TAG0",
  "TAG1",
  "TAG1",
  "TAG2",
  "TAG2",
  "TAG3",
  "TAG3",
  "TAG4",
  "TAG4",
  "TAG5",
  "TAG5",
  "TAG6",
  "TAG6",
  "TAG7",
  "TAG7"
};

register_info_t registers[] =
{
  // FPU registers
  { "ST0",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST1",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST2",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST3",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST4",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST5",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST6",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST7",    0,                            RC_FPU,      dt_tbyte, NULL,   0 },
  { "CTRL",   0,                            RC_FPU,      dt_word,  ctrlflags, 0x1F3F },
  { "STAT",   0,                            RC_FPU,      dt_word,  statflags, 0xFFFF },
  { "TAGS",   0,                            RC_FPU,      dt_word,  tagsflags, 0xFFFF },
  // segment registers
  { "CS",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  { "DS",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  { "ES",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  { "FS",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  { "GS",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  { "SS",     REGISTER_READONLY,            RC_SEGMENTS, dt_word,  NULL,   0 },
  // general registers
#ifdef __EA64__
  { "RAX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RBX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RCX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RDX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RSI",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RDI",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "RBP",    REGISTER_ADDRESS|REGISTER_FP, RC_GENERAL,  dt_qword, NULL,   0 },
  { "RSP",    REGISTER_ADDRESS|REGISTER_SP, RC_GENERAL,  dt_qword, NULL,   0 },
  { "RIP",    REGISTER_ADDRESS|REGISTER_IP, RC_GENERAL,  dt_qword, NULL,   0 },
  { "R8",     REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R9",     REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R10",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R11",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R12",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R13",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R14",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
  { "R15",    REGISTER_ADDRESS,             RC_GENERAL,  dt_qword, NULL,   0 },
#else
  { "EAX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "EBX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "ECX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "EDX",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "ESI",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "EDI",    REGISTER_ADDRESS,             RC_GENERAL,  dt_dword, NULL,   0 },
  { "EBP",    REGISTER_ADDRESS|REGISTER_FP, RC_GENERAL,  dt_dword, NULL,   0 },
  { "ESP",    REGISTER_ADDRESS|REGISTER_SP, RC_GENERAL,  dt_dword, NULL,   0 },
  { "EIP",    REGISTER_ADDRESS|REGISTER_IP, RC_GENERAL,  dt_dword, NULL,   0 },
#endif
  { "EFL",    0,                            RC_GENERAL,  dt_dword, eflags, 0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
};

static bool inited;
static bool is_dll;

//--------------------------------------------------------------------------
#if 0
static void DEBUG_REGVALS(regval_t *values)
{
  for (int i = 0; i < qnumber(registers); i++)
  {
    msg("%s = ", registers[i].name);
    switch (registers[i].dtyp)
    {
      case dt_qword: msg("%016LX\n", values[i].ival); break;
      case dt_dword: msg("%08X\n", values[i].ival); break;
      case dt_word:  msg("%04X\n", values[i].ival); break;
      case dt_tbyte:
      {
        for (int j = 0; j < sizeof(regval_t); j++)
        {
          if (j == 10) msg(" - "); // higher bytes are not used by x86 floats
          msg("%02X ", ((unsigned char*)&values[i])[j]);
        }
          // msg("%02X ", (unsigned short)values[i].fval[j]);
        msg("\n");
        break;
      }
    }
  }
  msg("\n");
}
#endif

//--------------------------------------------------------------------------
int idaapi thread_read_registers(thread_id_t thread_id, regval_t *values, int count)
{
  int code = r_thread_read_registers(thread_id, values, count);
  if ( code > 0 )
  {
    // FPU related registers
    if ( ph.realcvt != NULL )
    {
      for ( int i = 0; i < FPU_REGS_COUNT; i++ )
      {
        long double fpu_float = *(long double *)&values[R_ST0+i].fval;
        ph.realcvt(&fpu_float, values[R_ST0+i].fval, 004); // load long double
      }
    }
  }
  return code;
}

//--------------------------------------------------------------------------
int idaapi thread_write_register(thread_id_t thread_id, int reg_idx, const regval_t *value)
{
  regval_t rv = *value;
  // FPU related registers
  if (ph.realcvt != NULL && reg_idx >= R_ST0 && reg_idx < R_ST0+FPU_REGS_COUNT)
  {
    long double fn;
    ph.realcvt(&fn, rv.fval, 014); // store long double
    *(long double *)&rv.fval = fn;
  }
  return r_thread_write_register(thread_id, reg_idx, &rv);
}

//--------------------------------------------------------------------------
int is_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_SOFT )
  {
    if ( type != BPT_RDWR         // type is good?
      && type != BPT_WRITE
      && type != BPT_EXEC)
        return BPT_BAD_TYPE;

    if ( len != 1                 // length is good?
      && (type == BPT_EXEC        // remark: instruction hardware breakpoint only accepts the len of one byte
        || (len != 2 && len != 4)))
          return BPT_BAD_LEN;

    if ( (ea & (len-1)) != 0 )    // alignment is good?
      return BPT_BAD_ALIGN;
  }
  return BPT_OK;
}


#ifndef __NT__
#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
#define CONTROL_C_EXIT                      STATUS_CONTROL_C_EXIT
#define DBG_CONTROL_C                    0x40010005L
#define DBG_CONTROL_BREAK                0x40010008L
#define STATUS_GUARD_PAGE_VIOLATION      0x80000001L
#define STATUS_DATATYPE_MISALIGNMENT     0x80000002L
#define STATUS_BREAKPOINT                0x80000003L
#define STATUS_SINGLE_STEP               0x80000004L
#define STATUS_ACCESS_VIOLATION          0xC0000005L
#define STATUS_IN_PAGE_ERROR             0xC0000006L
#define STATUS_INVALID_HANDLE            0xC0000008L
#define STATUS_NO_MEMORY                 0xC0000017L
#define STATUS_ILLEGAL_INSTRUCTION       0xC000001DL
#define STATUS_NONCONTINUABLE_EXCEPTION  0xC0000025L
#define STATUS_INVALID_DISPOSITION       0xC0000026L
#define STATUS_ARRAY_BOUNDS_EXCEEDED     0xC000008CL
#define STATUS_FLOAT_DENORMAL_OPERAND    0xC000008DL
#define STATUS_FLOAT_DIVIDE_BY_ZERO      0xC000008EL
#define STATUS_FLOAT_INEXACT_RESULT      0xC000008FL
#define STATUS_FLOAT_INVALID_OPERATION   0xC0000090L
#define STATUS_FLOAT_OVERFLOW            0xC0000091L
#define STATUS_FLOAT_STACK_CHECK         0xC0000092L
#define STATUS_FLOAT_UNDERFLOW           0xC0000093L
#define STATUS_INTEGER_DIVIDE_BY_ZERO    0xC0000094L
#define STATUS_INTEGER_OVERFLOW          0xC0000095L
#define STATUS_PRIVILEGED_INSTRUCTION    0xC0000096L
#define STATUS_STACK_OVERFLOW            0xC00000FDL
#define STATUS_CONTROL_C_EXIT            0xC000013AL
#define STATUS_FLOAT_MULTIPLE_FAULTS     0xC00002B4L
#define STATUS_FLOAT_MULTIPLE_TRAPS      0xC00002B5L
#define STATUS_REG_NAT_CONSUMPTION       0xC00002C9L
#endif

#include <string.h>
#include <loader.hpp>
#include "../../ldr/pe/pe.h"

//--------------------------------------------------------------------------
// Initialize Win32 debugger plugin
static bool init_plugin(void)
{
  if ( !netnode::inited() || is_miniidb() )
  {
#ifdef __NT__
    // local debugger is available if we are running under Windows
    return true;
#else
    // for other systems only the remote debugger is available
    return debugger.is_remote();
#endif
  }
msg("ok\n");

  uchar buf[sizeof(ulong)+1];

  memset(buf,0, sizeof(ulong)+1);
						
  uchar *ptr = buf;
  ptr = pack_dd(ptr, buf + sizeof(buf), 127);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 128);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);
  
  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 129);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 256);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);
  
  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 512);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  /*
  if ( inf.filetype != f_EXE_old) return false; // only MSDOS EXE files
  else
	msg("we have an MSDOS exe.");
  */
#ifdef USE_ASYNC        // connection to PocketPC device
  if ( ph.id != PLFM_ARM ) return false; // only ARM
#else
  if ( ph.id != PLFM_386 ) return false; // only IBM PC
#endif

  is_dll = false;

 /* we don't need PE checks.. :)
  * 
  // find out the pe header
  netnode penode;
  penode.create(PE_NODE);
  peheader_t pe;
  if ( penode.valobj(&pe, sizeof(pe)) <= 0 )
    return false;

  is_dll = (pe.flags & PEF_DLL) != 0;

  if ( pe.subsys != PES_UNKNOWN )  // Unknown
  {
#ifdef USE_ASYNC        // connection to PocketPC device
    // debug only wince applications
    if ( pe.subsys != PES_WINCE )  // Windows CE
      return false;
#else
    // debug only gui or console applications
    if ( pe.subsys != PES_WINGUI && pe.subsys != PES_WINCHAR )
      return false;
#endif
  }

*/
  
  return true;
}

//--------------------------------------------------------------------------
char comment[] = "Userland win32 debugger plugin.";

char help[] =
        "A sample Userland win32 debugger plugin\n"
        "\n"
        "This module shows you how to create debugger plugins.\n";


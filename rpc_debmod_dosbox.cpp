#include "typeinf.hpp"

#include "deb_pc.hpp"

#include "rpc_debmod_dosbox.h"

static const char *get_reg_name(int reg_idx);

ea_t idaapi rpc_debmod_dosbox_t::map_address(ea_t ea, const regval_t *regs, int regnum)
{
 ea_t mapped_ea = ea;

// warning("ICON ERROR\nAUTOHIDE NONE\n"
//      "testing");
 if(regs)
 {
   switch(regnum)
   {
     case R_EIP : 
                  mapped_ea = (regs[R_CS].ival<<4) + regs[R_EIP].ival;
                  break;
     case R_ESP : mapped_ea = (regs[R_SS].ival<<4) + regs[R_ESP].ival; break;
     case R_EBP : mapped_ea = (regs[R_SS].ival<<4) + regs[R_EBP].ival; break;

     case R_CS : mapped_ea = (regs[R_CS].ival<<4); break;
     case R_DS : mapped_ea = (regs[R_DS].ival<<4); break;
     case R_SS : mapped_ea = (regs[R_SS].ival<<4); break;
     case R_ES : mapped_ea = (regs[R_ES].ival<<4); break;
   }
  // msg("map_address(%a,res[%s]) %a %x\n", ea, get_reg_name(regnum), mapped_ea, regs[regnum].ival);
 }

  return mapped_ea;
}

static const char *get_reg_name(int reg_idx)
{
	switch(reg_idx)
	{
		case R_EAX : return "AX";
		case R_EBX : return "BX";
		case R_ECX : return "CX";
		case R_EDX : return "DX";
		case R_ESI : return "SI";
		case R_EDI : return "DI";
		case R_EBP : return "BP";
		case R_ESP : return "SP";
		case R_EIP : return "EIP";
		case R_EFLAGS : return "FLAGS";

		case R_CS : return "CS";
		case R_DS : return "DS";
		case R_ES : return "ES";
		case R_FS : return "FS";
		case R_GS : return "GS";
		case R_SS : return "SS";
	}
	
	return "??";
}

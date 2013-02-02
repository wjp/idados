#include <idd.hpp>
#include "rpc_debmod.h"

class rpc_debmod_dosbox_t: public rpc_debmod_t
{
  public:
  virtual ea_t idaapi map_address(ea_t ea, const regval_t *regs, int regnum);

};

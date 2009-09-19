#include <idd.hpp>
#include "rpc_debmod.h"

class rpc_debmod_dosbox_t: public rpc_debmod_t
{
  event_id_t last_event;

  public:
  virtual int  idaapi map_address(ea_t ea, const regval_t *regs, int regnum);
  virtual int dbg_init(bool _debug_debugger);
  virtual int  idaapi dbg_get_debug_event(debug_event_t *event, bool ida_is_idle);

};

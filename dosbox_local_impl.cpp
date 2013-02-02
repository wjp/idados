#include <segment.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
  }

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  ea_t currentbase = new_base;
  ea_t imagebase = inf.baseaddr<<4; 

  msg("imagebase = %a newbase=%a\n", imagebase, new_base);

  if ( imagebase != currentbase )
  {
    adiff_t delta = currentbase - imagebase;
    delta /= 16;
    msg("delta = %d\n", delta);

    int code = rebase_program(currentbase - imagebase, MSF_FIXONCE);
    if ( code != MOVE_SEGM_OK )
    {
      msg("Failed to rebase program, error code %d\n", code);
      warning("IDA failed to rebase the program.\n"
              "Most likely it happened because of the debugger\n"
              "segments created to reflect the real memory state.\n\n"
              "Please stop the debugger and rebase the program manually.\n"
              "For that, please select the whole program and\n"
              "use Edit, Segments, Rebase program with delta 0x%08a",
                                        currentbase - imagebase);
    }

    warning("Database rebased to %ah\n", new_base);

  }

}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
#ifndef RPC_CLIENT
  if (!init_subsystem())
    return false;
#endif
  if ( !netnode::inited() || is_miniidb() || inf.is_snapshot() )
  {
    //dosbox is always remote.
    return debugger.is_remote();
  }

  if ( inf.filetype != f_EXE && inf.filetype != f_COM )
    return false; // only MSDOS EXE or COM files
  if ( ph.id != PLFM_386 )
    return false; // only IBM PC

  return true;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
}

//--------------------------------------------------------------------------
char comment[] = "Userland dosbox debugger plugin.";

char help[] =
        "Userland dosbox debugger plugin.\n"
        "\n"
        "This module lets you debug programs running in DOSBox.\n";


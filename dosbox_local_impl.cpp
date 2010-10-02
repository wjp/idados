#include <segment.hpp>
#include <srarea.hpp>
#include <loader.hpp>
#include <fixup.hpp>
#include <exehdr.h>

bool rebase_exe(adiff_t delta)
{
 exehdr E;
 sel_t dseg_sel = 0;

 char exe_name[QMAXPATH];
 
 get_input_file_path(exe_name, sizeof(exe_name));
 
 msg("exe = %s\n", exe_name);

 FILE *fp = fopenRB(exe_name);
 if(fp == NULL)
 {
   char *user_exe = askfile_c(0, "*.*", "Please select the exe for this db.", exe_name);

   if(user_exe == NULL)
     return false;

   fp = fopenRB(user_exe);

   if(fp == NULL)
     return false;
 }

 qfread(fp, &E, sizeof(E));

 msg("E.ReloCnt = %d\n", E.ReloCnt);

 if(E.ReloCnt)
 {

   fixup_data_t fd;


   fd.type         = FIXUP_SEG16;
   fd.off          = 0;
   fd.displacement = 0;


   qfseek(fp, E.TablOff, SEEK_SET);
   for(int i = 0; i < E.ReloCnt; i++) 
   {
     unsigned short buf[2];

     qfread(fp, buf, sizeof(buf));

     ea_t xEA = toEA((ushort)(inf.baseaddr+buf[1]), buf[0]); //i we need ushort() here!
     ushort old_word = get_word(xEA);
     ushort new_word = ushort((int32)old_word + delta);
     //msg("Reloc: %a delta = %d : %x => %xh\n",xEA, delta, old_word, new_word);
     put_word(xEA, new_word);

     del_fixup(xEA);
     fd.sel = new_word;
     set_fixup(xEA, &fd);
   }
 }

 qfclose(fp);

 return true;
}

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
  }

//FIXUP offsets.
//-------------------------------------------------------------------------
static bool idaapi has_offset(flags_t F, void *)
{
 return isHead(F) && isOff(F, -1);
}

static void move_nalt_info(ea_t from, ea_t to, asize_t size, int flags)
{
 ea_t ea = 0;
 do
 {
   flags_t F = get_flags_novalue(ea);
   if ( (flags & MSF_FIXONCE) != 0 && isOff(F, -1) && ea >= to) //ERIC  && ea < to+size )
   {
     for ( int i=0; i < 2; i++ )
     {
       if ( !isOff(F, i) )
         continue;
       refinfo_t ri;
       if ( get_refinfo(ea, i, &ri) && ri.base != 0 && ri.base != BADADDR )
       {
         ri.base += to - from;
         set_refinfo_ex(ea, i, &ri);
         //msg("fixup offset %a, ri.base = %x\n", ea, ri.base);
       }
     }
   }
   ea = nextthat(ea, BADADDR, has_offset, NULL);
 } while ( ea != BADADDR );
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
/*
    if(inf.filetype == f_EXE)
    {
      if(rebase_exe(delta) == false)
      {
        warning("Failed to relocate EXE offsets!");
        return; 
      }
    }
*/
    int code = rebase_program(currentbase - imagebase, MSF_FIXONCE);
    if ( code != MOVE_SEGM_OK )
    {
      msg("Failed to rebase program, error code %d\n", code);
      warning("IDA Pro failed to rebase the program.\n"
              "Most likely it happened because of the debugger\n"
              "segments created to reflect the real memory state.\n\n"
              "Please stop the debugger and rebase the program manually.\n"
              "For that, please select the whole program and\n"
              "use Edit, Segments, Rebase program with delta 0x%08lX",
                                        currentbase - imagebase);
    }
    else
    {
       move_nalt_info(imagebase, currentbase, 0, MSF_FIXONCE);
    }

  // set_imagebase(0);
  // inf.baseaddr = new_base >> 4;

   warning("Database rebased to %ah\n", new_base);

  }

}
/*
bool rebase_exe(adiff_t delta)
{
 exehdr E;

 FILE *fp = fopenRB("BLOCKS.EXE");
 qfread(fp, &E, sizeof(E));

 if(E.ReloCnt)
 {
   qfseek(fp, E.TablOff, SEEK_SET);
   for(int i = 0; i < E.ReloCnt; i++) 
   {
     unsigned short buf[2];

     qfread(fp, buf, sizeof(buf));

     ea_t xEA = toEA((ushort)(inf.baseaddr+buf[1]), buf[0]); //i we need ushort() here!
     ushort old_word = get_word(xEA);
     ushort new_word = ushort((int32)old_word + delta);
     //msg("Reloc: %a delta = %d : %x => %xh\n",xEA, delta, old_word, new_word);
     put_word(xEA, new_word);

   }
   segment_t *seg;
   sel_t dseg = 0;
   for(int i = 0;i < get_segm_qty();i++)
   {
     seg = getnseg(i);
     if(seg->is_debugger_segm() == false)
     {
       seg->sel = seg->startEA>>4;
       if(seg->type == SEG_DATA)
        dseg = seg->sel;
     }
   }

   if(dseg != 0)
     set_default_dataseg(dseg);
 }

 qfclose(fp);
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  ea_t currentbase = new_base;//0x1a70;
  ea_t imagebase = inf.beginEA;//inf.baseaddr<<4; 

  msg("imagebase = %a newbase=%a\n", imagebase, currentbase);

  //currentbase = 0x1a70;
  //imagebase = inf.baseaddr<<4; 

  if ( imagebase != currentbase )
  {
    warning("Please rebase or perferably recreate your database at the following base addr %a", new_base);
/ *
    adiff_t delta = currentbase - imagebase;
    delta /= 16;
    msg("delta = %d\n", delta);
 
    int code = rebase_program(currentbase - imagebase, MSF_FIXONCE);
    if ( code != MOVE_SEGM_OK )
    {
      msg("Failed to rebase program, error code %d\n", code);
      warning("IDA Pro failed to rebase the program.\n"
              "Most likely it happened because of the debugger\n"
              "segments created to reflect the real memory state.\n\n"
              "Please stop the debugger and rebase the program manually.\n"
              "For that, please select the whole program and\n"
              "use Edit, Segments, Rebase program with delta 0x%08lX",
                                        currentbase - imagebase);
    }

    if(inf.filetype == f_EXE)
      rebase_exe(delta);
* /
  }
}
*/
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

  is_dll = false; // FIXME!

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


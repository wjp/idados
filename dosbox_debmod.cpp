/*

*/
#include <ida.hpp>
#include <err.h>
#include <idp.hpp>
#include <srarea.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include "consts.h"
#include "dosbox_debmod.h"

#include "dosbox.h"
#include "cpu.h"
#include "mem.h"


inline ea_t find_app_base();

//defined in debug.cpp
Bit32u GetAddress(Bit16u seg, Bit32u offset);
bool DEBUG_AddBreakPoint(Bit32u address, bool once);
bool DEBUG_AddMemBreakPoint(Bit32u address);
bool DEBUG_DelBreakPoint(PhysPt address);
int DEBUG_Continue(void);
Bits DEBUG_RemoteStep(void);

//server.cpp
void idados_running();
void idados_stopped();

extern debugger_t debugger;
bool debug_debugger;

//--------------------------------------------------------------------------
// Initialize static members
// TODO: Can we support this?
bool dosbox_debmod_t::reuse_broken_connections = false;


static const int T = 20;

//--------------------------------------------------------------------------
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4355)
#endif
dosbox_debmod_t::dosbox_debmod_t(void) 
{
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

//--------------------------------------------------------------------------
dosbox_debmod_t::~dosbox_debmod_t(void)
{
}

//--------------------------------------------------------------------------
bool idaapi dosbox_debmod_t::close_remote(void)
{
//  trk.term();
  return true;
}

//--------------------------------------------------------------------------
bool idaapi dosbox_debmod_t::open_remote(const char * /*hostname*/, int port_number, const char * /*password*/)
{
 // if ( trk.init(port_number) )
    return true;
 // warning("Could not open serial port: %s", winerr(GetLastError()));
 // return false;
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::cleanup(void)
{
  inherited::cleanup();
  //proclist.clear();
  dlls_to_import.clear();
  dlls.clear();
  stepping.clear();
  //threads.clear();
  events.clear();
  bpts.clear();
  process_name.clear();
  exited = false;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  bpts_t::iterator p = bpts.find(ea);
  if ( p != bpts.end() )
  {
    // already has a bpt at the specified address
    // unfortunately the kernel may ask to set several bpts at the same addr
    // FIXME: Handle 'type' here too
    p->second.cnt++;
    return 1;
  }

 printf("new breakpoint at 0x%x.\n", ea);
 
 //ea += r_debug.base;
 switch(type)
 {
   case BPT_EXEC :
   case BPT_SOFT : DEBUG_AddBreakPoint((Bit32u)ea, false); break;
   case BPT_RDWR :
   case BPT_WRITE : DEBUG_AddMemBreakPoint((Bit32u)ea); break;
   case BPT_READ :
     // Unsupported
     return 0; // failed
 }

  bpts.insert(std::make_pair(ea, bpt_info_t(1, 1)));

  return 1; // ok
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_del_bpt(bpttype_t /*type*/, ea_t ea, const uchar * /*orig_bytes*/, int /*len*/)
{
  // FIXME: Handle 'type' argument!
  bpts_t::iterator p = bpts.find(ea);
  if ( p == bpts.end() )
    return 0; // failed
  if ( --p->second.cnt == 0 )
  {
    int bid = p->second.bid;
    bpts.erase(p);

//    if ( !trk.del_bpt(bid) )
//      return 0; // failed? odd
    DEBUG_DelBreakPoint((PhysPt)ea);
  }
  return 1; // ok
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_init(bool _debug_debugger)
{
  cleanup();
  debug_debugger = ::debug_debugger = _debug_debugger;
  return 1; //trk.ping() && trk.connect();
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_term(void)
{
  //trk.disconnect();
  return; //trk.term();
}

//--------------------------------------------------------------------------
// input is valid only if n==0
int idaapi dosbox_debmod_t::dbg_process_get_info(int n, const char * /*input*/, process_info_t *info)
{
  if ( n == 0 ) // initialize the list
  {

//    if ( !trk.get_process_list(proclist) )
      return 0;


#if 0 // commented out because we can not match file names with process names
    if ( input != NULL )
    { // remove all unmatching processes from the list
      qstring inpbuf;
      input = qbasename(input);
      const char *end = strchr(input, '.');
      if ( end != NULL )
      { // ignore everything after '.' (remove extension)
        inpbuf = qstring(input, end-input);
        input = inpbuf.c_str();
      }
      for ( int i=proclist.size()-1; i >= 0; i-- )
        if ( strstr(proclist[i].name.c_str(), input) == NULL )
          proclist.erase(proclist.begin()+i);
    }
#endif
  }
/*
  if ( n >= proclist.size() )
    return 0;
  if ( info != NULL )
  {
    proclist_entry_t &pe = proclist[n];
    info->pid = pe.pid;
    qstrncpy(info->name, pe.name.c_str(), sizeof(info->name));
  }
*/
  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_detach_process(void)
{
  return 0; // can not detach
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_start_process(
  const char *path,
  const char *args,
  const char * /*startdir*/,
  int /* flags */,
  const char * /*input_path*/,
  uint32 /* input_file_crc32 */)
{

  entry_point = (ea_t)GetAddress(SegValue(cs), reg_eip);
  printf("entry_point = %x\n", entry_point);
  app_base = find_app_base();
  printf("app_base = %x\n", app_base);
  stack = SegValue(ss);
printf("name %s \n",path);
  create_process_start_event(path);
  return 1;
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::create_process_start_event(const char *path)
{
  ea_t base;
  debug_event_t ev;

  base = find_app_base();

  ev.eid = PROCESS_START;
  ev.pid = NO_PROCESS;//pi.pid;
  ev.tid = NO_PROCESS;//pi.tid;
  ev.ea = BADADDR;
  ev.handled = false;
  qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
  process_name = path;
  ev.modinfo.base = app_base + 0x100; //base + PSP //entry_point; //pi.codeaddr;
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = app_base + 0x100; //base + PSP //entry_point;
  events.enqueue(ev, IN_BACK);
}

//--------------------------------------------------------------------------
const exception_info_t *dosbox_debmod_t::find_exception_by_desc(const char *desc) const
{
  qvector<exception_info_t>::const_iterator p;
  for ( p=exceptions.begin(); p != exceptions.end(); ++p )
  {
    const char *tpl = p->desc.c_str();
    size_t len = p->desc.length();
    if ( strstr(tpl, "panic") != NULL )
      len = strchr(tpl, ' ') - tpl; // just first word
    if ( strnicmp(tpl, desc, len) == 0 )
      return &*p;
  }
  return NULL;
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::add_dll(const image_info_t &ii)
{
  //dlls.insert(std::make_pair(ii.codeaddr, ii));
  //dlls_to_import.insert(ii.codeaddr);
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::del_dll(const char *name)
{
/*
  for ( images_t::iterator p=dlls.begin(); p != dlls.end(); ++p )
  {
    if ( strcmp(p->second.name.c_str(), name) == 0 )
    {
      dlls_to_import.erase(p->first);
      dlls.erase(p);
      return;
    }
  }
  msg("Unknown DLL %s got unloaded\n", name);
*/
}

//--------------------------------------------------------------------------
/*
bool metrotrk_t::handle_notification(uchar seq, void *ud) // plugin version
{
  dosbox_debmod_t &dm = *(dosbox_debmod_t *)ud;
  int i = 0;
  bool suspend = true;
  debug_event_t ev;

  uchar type = extract_byte(i);
  switch ( type )
  {
    case TrkOSNotifyCreated:
      {
        image_info_t ii;
        uint16 item = extract_int16(i);
        QASSERT(item == TrkOSDLLItem);
        qnotused(item);
        ii.pid       = extract_int32(i);
        ii.tid       = extract_int32(i);
        ii.codeaddr  = extract_int32(i);
        ii.dataaddr  = extract_int32(i);
        ii.name      = extract_pstr(i);
        ev.eid = LIBRARY_LOAD;
        ev.pid = ii.pid;
        ev.tid = ii.tid;
        ev.ea = BADADDR;
        ev.handled = false;
        qstrncpy(ev.modinfo.name, ii.name.c_str(), sizeof(ev.modinfo.name));
        ev.modinfo.base = ii.codeaddr;
        ev.modinfo.size = 0;
        ev.modinfo.rebase_to = BADADDR;
        dm.add_dll(ii);
      }
      break;

    case TrkOSNotifyDeleted:
      {
        uint16 item = extract_int16(i);
        if ( debug_debugger )
          msg("NotifyDeleted Item: %s\n", get_os_item_name(item));
        switch ( item )
        {
          case TrkOSProcessItem:
            {
              uint32 exitcode = extract_int32(i);
              uint32 pid      = extract_int32(i);
              ev.eid = PROCESS_EXIT;
              ev.pid = pid;
              ev.tid = -1;
              ev.ea = BADADDR;
              ev.handled = false;
              ev.exit_code = exitcode;
              tpi.pid = -1;
              dm.exited = true;
            }
            break;
          case TrkOSDLLItem:
            {
              int32 pid = extract_int32(i);
              int32 tid = extract_int32(i);
              qstring name = extract_pstr(i);
              ev.eid = LIBRARY_UNLOAD;
              ev.pid = pid;
              ev.tid = tid;
              ev.ea = BADADDR;
              ev.handled = false;
              qstrncpy(ev.info, name.c_str(), sizeof(ev.info));
              dm.del_dll(name.c_str());
            }
            break;
          default:
            INTERR(); // not implemented
        }
      }
      break;

    case TrkNotifyStopped:
      {
        ev.ea  = extract_int32(i);
        ev.pid = extract_int32(i);
        ev.tid = extract_int32(i);
        qstring desc = extract_pstr(i);
        if ( debug_debugger )
        {
          msg("  Current PC: %08X\n", ev.ea);
          msg("  Process ID: %08X\n", ev.pid);
          msg("  Thread ID : %08X\n", ev.tid);
          msg("  Name      : %s\n", desc.c_str());
        }
        ev.handled = false;
        // there are various reasons why the app may stop
        if ( desc.empty() ) // bpt
        {
          // bpt exists?
          if ( dm.bpts.find(ev.ea) != dm.bpts.end() )
          {
            ev.eid = BREAKPOINT;
            ev.bpt.hea = BADADDR;
            ev.bpt.kea = BADADDR;
          }
          else // no, this must be a single step
          {
            ev.eid = STEP;
          }
          break;
        }
        // an exception
        ev.eid = EXCEPTION;
        ev.exc.ea = BADADDR;
        qstrncpy(ev.exc.info, desc.c_str(), sizeof(ev.exc.info));
        // trk returns the exception description, but no code.
        // convert the description to the code
        const exception_info_t *ei = dm.find_exception_by_desc(desc.c_str());
        if ( ei != NULL )
        {
          int code = ei->code;
          ev.exc.code = code;
          ev.exc.can_cont = code != 20        // abort
                         && code != 21        // kill
                         && code < 25;        // regular exception
          ev.handled = ei->handle();
          suspend = ei->break_on();
        }
        else
        {
          ev.exc.code = 25; // just something
          ev.exc.can_cont = true;
        }
      }
      break;

    default:
      // unexpected packet?!
//      msg("Unexpected packet %d\n", type);
      return false;
  }
  // send reply
  if ( !dm.exited )
    send_reply_ok(seq);
  if ( !suspend )
    dm.dbg_continue_after_event(&ev);
  else
    dm.events.enqueue(ev, IN_BACK);

  return true;
}
*/


//--------------------------------------------------------------------------
gdecode_t idaapi dosbox_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  if ( event == NULL )
    return GDE_NO_EVENT;

  while ( true )
  {
    // are there any pending events?
    if ( events.retrieve(event) )
    {
      debdeb("GDE: %s\n", debug_event_str(event));
      return GDE_ONE_EVENT;
    }
    // no pending events, check the target
//    trk.poll_for_event(ida_is_idle ? TIMEOUT : 0);
    if ( events.empty() )
      break;
  }

  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_attach_process(pid_t pid, int /*event_id*/)
{
/*
  if ( !trk.attach_process(pid) )
    return 0;

  // get information on the existing threads
  thread_list_t tlist;
  trk.get_thread_list(pid, tlist);
  if ( tlist.empty() )
  {
    trk.disconnect();
    return 0;       // something is wrong
  }

  pi.pid = pid;
  pi.tid = tlist[0].tid;
  pi.codeaddr = (uint32)BADADDR; // unknown :(
  pi.dataaddr = (uint32)BADADDR;
  trk.tpi = pi;
  create_process_start_event(tlist[0].name.c_str());
  // create fake PROCESS_ATTACH/THREAD_START event for each thread
  for ( ssize_t i=tlist.size()-1; i >= 0; i-- )
  {
    debug_event_t ev;
    ev.eid = THREAD_START;
    ev.pid = pid;
    ev.tid = tlist[i].tid;
    ev.ea = BADADDR;
    ev.handled = false;
    if ( i == 0 )
    {
      ev.eid = PROCESS_ATTACH;
      qstrncpy(ev.modinfo.name, tlist[i].name.c_str(), sizeof(ev.modinfo.name));
      process_name = ev.modinfo.name;
      ev.modinfo.base = BADADDR; // unknown :(
      ev.modinfo.size = 0;
      ev.modinfo.rebase_to = BADADDR;
    }
    events.enqueue(ev, IN_BACK);
  }
*/
  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_prepare_to_pause_process(void)
{
  debug_event_t ev;
 
  ev.eid = NO_EVENT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.bpt.hea = BADADDR; //addr; //BADADDR; //r_debug.base - addr; //BADADDR; //addr;//r_debug.base - addr;
  ev.bpt.kea = BADADDR;//(ea_t)reg_eip;
  ev.ea = (ea_t)GetAddress(SegValue(cs), reg_eip);
  ev.handled = true;
  ev.exc.code = 0;
  ev.exc.can_cont = true;
  ev.exc.ea = BADADDR;

  events.enqueue(ev, IN_BACK);

  idados_stopped();

  return 1; //trk.suspend_thread(pi.pid, pi.tid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_exit_process(void)
{
//  if ( trk.current_pid() == -1 )
//    return true; // already terminated
  debug_event_t ev;

  ev.eid = PROCESS_EXIT;
  ev.tid = NO_PROCESS;
  ev.pid = NO_PROCESS;
  ev.ea = BADADDR;
  ev.handled = false;
  ev.exit_code = 0;

  events.enqueue(ev, IN_BACK);
  
  
  return 1; //trk.terminate_process(pi.pid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( exited
    || event->eid == LIBRARY_UNLOAD   // TRK doesn't need this?
    || event->eid == THREAD_START     // fake event - btw, how do we detect thread creation?
    || event->eid == PROCESS_EXIT )   // After EXIT TRK does not accept 'continue'
  {
printf("bad event->eid\n");
    return 1;
  }

  // if there are pending events, do not resume the app
  // in fact, the whole debugger logic is flawed.
  // it must be ready for a bunch of events, process all of them
  // and only after that resume the whole application or part of it.
  // fixme: rewrite event handling in the debugger
  if ( !events.empty() )
  {
    printf("Events in the event queue.\n");
    return 1;
  }

/*  
  // was single stepping asked?
  stepping_t::iterator p = stepping.find(event->tid);
  if ( p != stepping.end() )
  {
    stepping.erase(p);
    ea_t end = event->ea + 0;//get_item_size(event->ea);
    printf("stepping.\n");
    return 1; //trk.step_thread(event->pid, event->tid, (int32)event->ea, (int32)end, true);
  }
  //int tid = event->tid == -1 ? pi.tid : event->tid;
*/

  
  //DEBUG_Continue();
  idados_running();
  return 1; //trk.resume_thread(event->pid, tid);
}

//--------------------------------------------------------------------------
// currently this function doesn't work because the dlls are usually
// not present. besides, we will have to implement the import_dll() function
bool dosbox_debmod_t::import_dll_to_database(ea_t imagebase)
{
/*
  images_t::iterator p = dlls.find(imagebase);
  if ( p == dlls.end() )
  {
    derror("import_dll_to_database: can't find dll name");
    return false;
  }

  if ( imagebase >= 0x80000000 )
    return false; // we have no access to system memory anyway

  const char *dllname = p->second.name.c_str();
  linput_t *li = open_linput(dllname, false);
  if ( li == NULL )
  {
    return false;
  }

  // prepare nice name prefix for exported functions names
  char prefix[MAXSTR];
  qstrncpy(prefix, qbasename(dllname), sizeof(prefix));
  char *ptr = strrchr(prefix, '.');
  if (ptr != NULL)
    *ptr = '\0';

  bool ok = false;
//  bool ok = import_dll(prefix, li, imagebase, (void *)this);
  close_linput(li);
*/
  return false; //ok;
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_stopped_at_debug_event(void)
{
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
/*
  clear_debug_names();

  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    import_dll_to_database(*p);
    dlls_to_import.erase(p++);
  }
*/
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return 1; //trk.suspend_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_continue(thid_t tid)
{
  return 1; //trk.resume_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return 0; // not supported

  stepping[tid] = true;
  dosbox_step_ret = DEBUG_RemoteStep(); //fixme step return.

  debug_event_t ev;
    ev.eid = STEP;
    ev.pid = NO_PROCESS;
    ev.tid = NO_PROCESS;
    ev.ea =(ea_t)GetAddress(SegValue(cs),reg_ip);
    ev.handled = false;

  events.enqueue(ev, IN_BACK);
  
  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
//  uint32 rvals[17];
//  QASSERT(n > 0 && n <= qnumber(rvals));

//  memset(values, 0, n * sizeof(regval_t)); // force null bytes at the end of floating point registers.
                                               // we need this to properly detect register modifications,
                                               // as we compare the whole regval_t structure !

  if ( (clsmask & X86_RC_GENERAL) != 0 ) {

  values[R_EAX   ].ival = (uint64)reg_eax;
  values[R_EBX   ].ival = (uint64)reg_ebx;
  values[R_ECX   ].ival = (uint64)reg_ecx;
  values[R_EDX   ].ival = (uint64)reg_edx;//GetAddress(SegValue(ds), (ulong)reg_edx);//(ulong)reg_edx;
  values[R_ESI   ].ival = (uint64)reg_esi;
  values[R_EDI   ].ival = (uint64)reg_edi;
  values[R_EBP   ].ival = (uint64)reg_ebp;
  values[R_ESP   ].ival = (uint64)reg_esp;
  values[R_EIP   ].ival = (uint64)reg_eip;
//  values[R_ESP   ].ival = GetAddress(SegValue(ss), (Bit32u)reg_esp);
//  values[R_EIP   ].ival = GetAddress(SegValue(cs), (Bit32u)reg_eip);
  values[R_EFLAGS].ival = (uint64)reg_flags;

  }

  if ( (clsmask & X86_RC_SEGMENTS) != 0 ) {

  values[R_CS    ].ival = (uint64)SegValue(cs);
  values[R_DS    ].ival = (uint64)SegValue(ds);
  values[R_ES    ].ival = (uint64)SegValue(es);
  values[R_FS    ].ival = (uint64)SegValue(fs);
  values[R_GS    ].ival = (uint64)SegValue(gs);
  values[R_SS    ].ival = (uint64)SegValue(ss);

  }

  // TODO: clear registers for X86_RC_XMM, X86_RC_FPU, X86_RC_MMX

  printf("AX = %08x",(uint64)values[R_EAX   ].ival);
  printf(" BX = %08x",(uint64)values[R_EBX   ].ival);
  printf(" CX = %08x",(uint64)values[R_ECX   ].ival);
  printf(" DX = %08x\n",(uint64)values[R_EDX   ].ival);
  printf("SI = %08x",(uint64)values[R_ESI   ].ival);
  printf(" DI = %08x",(uint64)values[R_EDI   ].ival);
  printf(" BP = %08x",(uint64)values[R_EBP   ].ival);
  printf(" SP = %08x\n",(uint64)values[R_ESP   ].ival);
  printf("IP = %08x",(uint64)values[R_EIP   ].ival);
  printf(" Flags = %08x\n",(uint64)values[R_EFLAGS].ival);
  printf("CS = %08x",(uint64)values[R_CS    ].ival);
  printf(" SS = %08x",(uint64)values[R_SS    ].ival);
  printf(" DS = %08x",(uint64)values[R_DS    ].ival);
  printf(" ES = %08x\n",(uint64)values[R_ES    ].ival);
  printf("FS = %08x",(uint64)values[R_FS    ].ival);
  printf(" GS = %08x\n",(uint64)values[R_GS    ].ival);

/*
  if ( exited || !trk.read_regs(pi.pid, tid, 0, n, rvals) )
    return 0;

  for ( int i=0; i < n; i++ )
  {
    debdeb("%cR%d: %08X", i==8 ? '\n' : ' ', i, rvals[i]);
    values[i].ival = rvals[i];
  }
  debdeb("\n");

  // if we read the PC and PSW values, check that our virtual register T
  // and real PSW at that address are the same. If not, copy real T to our
  // virtual register T
  if ( n == qnumber(rvals) ) // PC and PSW are read?
  {
    ea_t pc = rvals[15];
    int real_t = (rvals[16] & 0x20) != 0;
    int virt_t = getSR(pc, T) != 0;
    if ( real_t != virt_t )
      splitSRarea1(pc, T, real_t, SR_autostart);
  }
*/
  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  uint32 v = (uint32)value->ival;
  printf("write_reg R%d <- %08X\n", reg_idx, v);

  switch(reg_idx)
  {
    case R_EAX : reg_eax = value->ival; break;

    case R_EBX : reg_ebx = value->ival; break;
    case R_ECX : reg_ecx = value->ival; break;
    case R_EDX : reg_edx = value->ival; break;
    case R_ESI : reg_esi = value->ival; break;
    case R_EDI : reg_edi = value->ival; break;
    case R_EBP : reg_ebp = value->ival; break;
    case R_ESP : reg_esp = value->ival; break;
    //case R_EIP : reg_eip = value->ival; break;
    case R_EFLAGS : reg_flags = value->ival; break;

    case R_CS : SegSet16(cs, value->ival); break;
    case R_DS : SegSet16(ds, value->ival); break;
    case R_ES : SegSet16(es, value->ival); break;
    case R_FS : SegSet16(fs, value->ival); break;
    case R_GS : SegSet16(gs, value->ival); break;
    case R_SS : SegSet16(ss, value->ival); break;

    default : break;
  }

  return 1;//trk.write_regs(pi.pid, tid, reg_idx, 1, &v);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_get_memory_info(meminfo_vec_t &miv)
{
/*
   miv->startEA = 0x0; //0;//r_debug.base; //(ea_t)GetAddress(0,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->endEA--;
   strcpy(miv->name, "ROM");
   miv->sclass[0] = '\0'; 
   miv->perm = 0 | SEGPERM_READ;
   miv++;
 
   miv->startEA = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->endEA = (ea_t)GetAddress(SegValue(cs),0); // 0x1a70; //(ea_t)GetAddress(SegValue(ds),0);
   miv->endEA--;
   strcpy(miv->name, "PSP");
   miv->sclass[0] = '\0'; 
   miv->perm = 0 | SEGPERM_READ;
   miv++;

   miv->startEA = (ea_t)GetAddress(SegValue(cs),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ss), 0); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->endEA--;
   strcpy(miv->name, ".text");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   miv++;

   miv->startEA = (ea_t)GetAddress(SegValue(ss),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ss), 0xffff); //reg_sp); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->endEA--;
   strcpy(miv->name, ".stack");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   miv++;

   miv->startEA = (ea_t)GetAddress(0xf100,0); 
   miv->endEA = (ea_t)GetAddress(0xf100, 0x1000); 
   miv->endEA--;
   strcpy(miv->name, ".callbacks");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   miv++;
*/

static bool first_run = true;

if(!first_run)
  return -2;

   // Read from PSP
   int last_user_seg = mem_readw(GetAddress(app_base>>4, 0x2));
   printf("last user seg = %d\n", last_user_seg);

   memory_info_t *mi = &miv.push_back();
   mi->startEA = 0x0;
   mi->endEA = 0x400;
   mi->endEA--;
   mi->name = "INT_TABLE";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = 0; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

   mi = &miv.push_back();
   mi->startEA = 0x400;
   mi->endEA = 0x600;
   mi->endEA--;
   mi->name = "BIOS";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0x40; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);
   mi = &miv.push_back();
   mi->startEA = 0x600;
   mi->endEA = app_base;
   mi->endEA--;
   mi->name = "DOS?";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0x60;
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

   mi = &miv.push_back();
   mi->startEA = app_base;
   mi->endEA = app_base + 0x100;
   mi->endEA--;
   mi->name = "PSP";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = app_base>>4;
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

   mi = &miv.push_back();
   mi->startEA = app_base + 0x200;
   mi->endEA = (ea_t)GetAddress(last_user_seg, 0x10);
   mi->endEA--;
   mi->name = ".text"; // Not the best name; it also covers data/stack/...
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   mi->sbase = app_base>>4;
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

/*
   // IDA seems to take care of this itself
   mi = &miv.push_back();
   mi->startEA = (ea_t)GetAddress(SegValue(ss),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   mi->endEA = (ea_t)GetAddress(SegValue(ss), 0xffff); //reg_sp); // 0x1c20; //GetAddress(0xf000,0) - 1;
   mi->endEA--;
   mi->name = ".stack";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = SegValue(ss);
printf("mi = %x,%x\n",mi->startEA, mi->endEA);
*/
   mi = &miv.push_back();
   mi->startEA = 0xA0000;
   mi->endEA = 0xB0000;
   mi->endEA--;
   mi->name = "A000";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0xa000; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

   mi = &miv.push_back();
   mi->startEA = 0xB0000;
   mi->endEA = 0xB8000;
   mi->endEA--;
   mi->name = "B000";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = 0xb000; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);
   mi = &miv.push_back();
   mi->startEA = 0xB8000;
   mi->endEA = 0xC0000;
   mi->endEA--;
   mi->name = "B800";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ |SEGPERM_WRITE;
   mi->sbase = 0xb800; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);
   mi = &miv.push_back();
   mi->startEA = 0xC0000;
   mi->endEA = 0xC1000;
   mi->endEA--;
   mi->name = "VIDBIOS";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_EXEC;
   mi->sbase = 0xc000; 
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

   mi = &miv.push_back();
   mi->startEA = (ea_t)GetAddress(0xf100,0); 
   mi->endEA = (ea_t)GetAddress(0xf100, 0x1000); 
   mi->endEA--;
   mi->name = ".callbacks";
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   mi->sbase = 0xf100;
printf("mi = %x,%x\n",mi->startEA, mi->endEA);

printf("CS:IP = %04x:%04x\n",SegValue(cs), reg_eip); 

  first_run = false;

  return 1;
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
 int i;
 PhysPt addr = (PhysPt)ea;
 uchar *buf;
 
 buf = (uchar *)buffer;
 //addr = addr + r_debug.base;
 
 for(i=0;i<size;i++)
  {
   buf[i] = mem_readb(addr);
   // printf("%02x,",buf[i]);
   addr++;
  }

 printf("dbg_read_memory @ %x, size=%d\n", ea, size);
 return size;
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  if ( ea == 0 )
    return 0;

  for(int i=0;i<size;i++)
    mem_writeb(ea + i, ((Bit8u *)buffer)[i]);

  return size;
}

//--------------------------------------------------------------------------
int  idaapi dosbox_debmod_t::dbg_open_file(const char *file, uint32 *fsize, bool readonly)
{
/*
  if ( fsize != NULL )
    *fsize = 0;
  int h = trk.open_file(file, readonly ? TrkFileOpenRead : TrkFileOpenCreate);
  if ( h > 0 )
  {
    if ( readonly && fsize != NULL )
    {
      // problem: trk does not have the ftell call
      // we will have to find the file size using the binary search
      // it seems the read_file() doesn't work at all!
      size_t size = 0x100000; // assume big file
      size_t delta = size;
      while ( (delta>>=1) > 0 )
      {
        uchar dummy;
        if ( dbg_read_file(h, uint32(size-1), &dummy, 1) == 1 )
          size += delta;
        else
          size -= delta;
      }
      *fsize = uint32(size - 1);
    }
  }
  else
  {
    qerrno = eOS;
    // fixme: set errno
  }
  return h;
*/
 return 0;
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_close_file(int fn)
{
  //trk.close_file(fn, 0);
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_read_file(int fn, uint32 off, void *buf, size_t size)
{
/*
  if ( !trk.seek_file(fn, off, SEEK_SET) )
    return -1;
  return trk.read_file(fn, buf, size);
*/
  return -1;
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_write_file(int fn, uint32 off, const void *buf, size_t size)
{
/*
  if ( !trk.seek_file(fn, off, SEEK_SET) )
    return -1;
  return trk.write_file(fn, buf, size);
*/
  return -1; 
}

//--------------------------------------------------------------------------
int dosbox_debmod_t::get_system_specific_errno(void) const
{
  return errno;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_get_sreg_base(
        thid_t tid,
        int sreg_value,
        ea_t *pe)
{
  *pe = sreg_value<<4;

  return 1;
}

//--------------------------------------------------------------------------
bool dosbox_debmod_t::refresh_hwbpts(void)
{
  return 0; // not implemented
}

//--------------------------------------------------------------------------
HANDLE dosbox_debmod_t::get_thread_handle(thid_t tid)
{
  return (HANDLE)tid; // there are no thread handles
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_is_ok_bpt(bpttype_t /*type*/, ea_t /*ea*/, int /*len*/)
{
  //return BPT_BAD_ADDR; // not supported
  printf("GET HERE is_ok_bpt\n");
  return BPT_OK;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new dosbox_debmod_t();
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
//  tdb_term();
//  qmutex_free(g_mutex);
  return true;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
//  if ((g_mutex = qmutex_create()) == NULL)
//    return false;

//  tdb_init();
  return true;
}

bool dosbox_debmod_t::hit_breakpoint(PhysPt addr)
{
  printf("hit breakpoint! 0x%x\n", addr);
  debug_event_t ev;
 
  ev.eid = BREAKPOINT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.bpt.hea = BADADDR; //addr; //BADADDR; //r_debug.base - addr; //BADADDR; //addr;//r_debug.base - addr;
  ev.bpt.kea = BADADDR;//(ea_t)reg_eip;
  ev.ea = addr;
  ev.handled = false;

/*
  ev.eid = NO_EVENT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.ea = addr;
  ev.handled = true;
  ev.exc.code = 0;
  ev.exc.can_cont = true;
  ev.exc.ea = BADADDR;
*/

  events.enqueue(ev, IN_BACK);

  return 1;
}


inline ea_t find_app_base()
{
  ea_t base = (ea_t)GetAddress(SegValue(cs), 0);
  ea_t addr;

  addr = (ea_t)GetAddress(SegValue(ds), 0);

  if(addr < base)
   base = addr;

  addr = (ea_t)GetAddress(SegValue(ss), 0);

  if(addr < base)
   base = addr;

 return base;
}



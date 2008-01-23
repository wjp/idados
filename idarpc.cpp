#ifdef __NT__
#include <windows.h>
#endif

// IDA RPC implementation

#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <err.h>
#include <idd.hpp>
#include <diskio.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include "idarpc.hpp"

//--------------------------------------------------------------------------
// DEBUGGING:

//#define DEBUG_NETWORK
#ifdef DEBUGGER_SERVER
#define verb(x)  do { if ( verbose ) msg x; } while(0)
#else
#define verb(x)  //msg x
#endif
#define verbev(x)  //msg x

#ifdef REMOTE_DEBUGGER

static debug_event_t pending_event;
static ssize_t network_error_code;     // 0 means everything is ok
bool has_pending_event;
bool poll_debug_events;
static idarpc_stream_t *irs;

// bidirectional codes (client <-> server)
#define RPC_OK    0      // response: function call succeeded
#define RPC_UNK   1      // response: unknown function code
#define RPC_MEM   2      // response: no memory

#define RPC_OPEN  3      // server->client: i'm ready, the very first packet

#define RPC_EVENT 4      // server->client: debug event ready, followed by debug_event
#define RPC_EVOK  5      // client->server: event processed (in response to RPC_EVENT)
                         // we need EVOK to handle the situation when the debug
                         // event was detected by the server during polling and
                         // was sent to the client using RPC_EVENT but client has not received it yet
                         // and requested GET_DEBUG_EVENT. In this case we should not
                         // call remote_get_debug_event() but instead force the client
                         // to use the event sent by RPC_EVENT.
                         // In other words, if the server has sent RPC_EVENT but has not
                         // received RPC_EVOK, it should fail all GET_DEBUG_EVENTS.



// codes client->server
#define RPC_INIT                      10
#define RPC_TERM                      11
#define RPC_GET_PROCESS_INFO          12
#define RPC_DETACH_PROCESS            13
#define RPC_START_PROCESS             14
#define RPC_GET_DEBUG_EVENT           15
#define RPC_ATTACH_PROCESS            16
#define RPC_PREPARE_TO_PAUSE_PROCESS  17
#define RPC_EXIT_PROCESS              18
#define RPC_CONTINUE_AFTER_EVENT      19
#define RPC_STOPPED_AT_DEBUG_EVENT    20
#define RPC_TH_SUSPEND                21
#define RPC_TH_CONTINUE               22
#define RPC_TH_SET_STEP               23
#define RPC_READ_REGS                 24
#define RPC_GET_MEMORY_INFO           25
#define RPC_READ_MEMORY               26
#define RPC_WRITE_MEMORY              27
#define RPC_ISOK_BPT                  28
#define RPC_ADD_BPT                   29
#define RPC_DEL_BPT                   30
#define RPC_WRITE_REG                 31
#define RPC_GET_SREG_BASE             32
#define RPC_SET_EXCEPTION_INFO        33

#define RPC_OPEN_FILE                 34
#define RPC_CLOSE_FILE                35
#define RPC_READ_FILE                 36
#define RPC_WRITE_FILE                38

#define RPC_IOCTL                     39

// codes server->client
#define RPC_SET_DEBUG_NAMES           50
#define RPC_SYNC_STUB                 51
#define RPC_ERROR                     52
#define RPC_MSG                       53
#define RPC_WARNING                   54

static int poll_events(bool idling);
static string perform_request(const rpc_packet_t *rp);
static void extract_debug_event(const uchar **ptr, debug_event_t *ev);
static uchar *sync_stub(const char *fname, ulong crc, size_t *psize);
//--------------------------------------------------------------------------
const char *get_rpc_name(int code)
{
  switch ( code )
  {
    case RPC_OK                      : return "RPC_OK";
    case RPC_UNK                     : return "RPC_UNK";
    case RPC_MEM                     : return "RPC_MEM";
    case RPC_OPEN                    : return "RPC_OPEN";
    case RPC_EVENT                   : return "RPC_EVENT";
    case RPC_EVOK                    : return "RPC_EVOK";
    case RPC_INIT                    : return "RPC_INIT";
    case RPC_TERM                    : return "RPC_TERM";
    case RPC_GET_PROCESS_INFO        : return "RPC_GET_PROCESS_INFO";
    case RPC_DETACH_PROCESS          : return "RPC_DETACH_PROCESS";
    case RPC_START_PROCESS           : return "RPC_START_PROCESS";
    case RPC_GET_DEBUG_EVENT         : return "RPC_GET_DEBUG_EVENT";
    case RPC_ATTACH_PROCESS          : return "RPC_ATTACH_PROCESS";
    case RPC_PREPARE_TO_PAUSE_PROCESS: return "RPC_PREPARE_TO_PAUSE_PROCESS";
    case RPC_EXIT_PROCESS            : return "RPC_EXIT_PROCESS";
    case RPC_CONTINUE_AFTER_EVENT    : return "RPC_CONTINUE_AFTER_EVENT";
    case RPC_STOPPED_AT_DEBUG_EVENT  : return "RPC_STOPPED_AT_DEBUG_EVENT";
    case RPC_TH_SUSPEND              : return "RPC_TH_SUSPEND";
    case RPC_TH_CONTINUE             : return "RPC_TH_CONTINUE";
    case RPC_TH_SET_STEP             : return "RPC_TH_SET_STEP";
    case RPC_READ_REGS               : return "RPC_READ_REGS";
    case RPC_WRITE_REG               : return "RPC_WRITE_REG";
    case RPC_GET_MEMORY_INFO         : return "RPC_GET_MEMORY_INFO";
    case RPC_READ_MEMORY             : return "RPC_READ_MEMORY";
    case RPC_WRITE_MEMORY            : return "RPC_WRITE_MEMORY";
    case RPC_ISOK_BPT                : return "RPC_ISOK_BPT";
    case RPC_ADD_BPT                 : return "RPC_ADD_BPT";
    case RPC_DEL_BPT                 : return "RPC_DEL_BPT";
    case RPC_GET_SREG_BASE           : return "RPC_GET_SREG_BASE";
    case RPC_SET_EXCEPTION_INFO      : return "RPC_SET_EXCEPTION_INFO";
    case RPC_OPEN_FILE               : return "RPC_OPEN_FILE";
    case RPC_CLOSE_FILE              : return "RPC_CLOSE_FILE";
    case RPC_READ_FILE               : return "RPC_READ_FILE";
    case RPC_WRITE_FILE              : return "RPC_WRITE_FILE";
    case RPC_IOCTL                   : return "RPC_IOCTL";
    case RPC_SET_DEBUG_NAMES         : return "RPC_SET_DEBUG_NAMES";
    case RPC_SYNC_STUB               : return "RPC_SYNC_STUB";
    case RPC_ERROR                   : return "RPC_ERROR";
    case RPC_MSG                     : return "RPC_MSG";
    case RPC_WARNING                 : return "RPC_WARNING";
  }
  return "?";
}

//--------------------------------------------------------------------------
static void finalize_packet(string &cmd)
{
  rpc_packet_t *rp = (rpc_packet_t *)&cmd[0];
  rp->length = qhtonl(ulong(cmd.length() - sizeof(rpc_packet_t)));
}

//--------------------------------------------------------------------------
int send_request(string &s)     // returns error code
{
   // if nothing is initialized yet or error occurred, silently fail
  if ( irs == NULL || network_error_code != 0 )
    return -1;

  finalize_packet(s);
  const char *ptr = s.c_str();
  int left = int(s.length());
#ifdef DEBUG_NETWORK
  rpc_packet_t *rp = (rpc_packet_t *)ptr;
  int len = qntohl(rp->length);
  show_hex(rp+1, len, "SEND %s %d bytes:\n", get_rpc_name(rp->code), len);
//  msg("SEND %s\n", get_rpc_name(rp->code));
#endif
  while ( left > 0 )
  {
    ssize_t code = irs_send(irs, ptr, left);
    if ( code == -1 )
    {
      code = irs_error(irs);
      network_error_code = code;
      warning("irs_send: %s", winerr(code));
      return code;
    }
    left -= code;
    ptr += code;
  }
  return 0;
}

//-------------------------------------------------------------------------
static int recv_all(void *ptr, int left, bool idling, bool poll)
{
  int code;
  while ( true )
  {
    code = 0;
    if ( left <= 0 )
      break;
    // since we have to poll the debugged program from the same thread as ours,
    // we poll it here when waiting for the client to send commands
#ifdef DEBUGGER_SERVER
    if ( poll && irs_ready(irs) == 0 )
    {
      code = poll_events(idling);
      if ( code != 0 )
        break;
      continue;
    }
#else
    qnotused(idling);
    qnotused(poll);
#endif
    code = irs_recv(irs, ptr, left);
    if ( code == -1 )
    {
      code = irs_error(irs);
      network_error_code = code;
      warning("irs_recv: %s", winerr(code));
      break;
    }
    left -= code;
    // visual studio 64 does not like simple
    // (char*)ptr += code;
    char *p2 = (char *)ptr;
    p2 += code;
    ptr = p2;
  }
  return code;
}

//-------------------------------------------------------------------------
rpc_packet_t *recv_request(bool idling)
{
   // if nothing is initialized yet or error occurred, silently fail
  if ( irs == NULL || network_error_code != 0 )
    return NULL;

  rpc_packet_t p;
  int code = recv_all(&p, sizeof(rpc_packet_t), idling, poll_debug_events);
  if ( code != 0 )
    return NULL;

  int size = p.length = qntohl(p.length);
  if ( size < 0 )
    error("rpc: bad packet length");
  size += sizeof(rpc_packet_t);
  uchar *urp = (uchar *)qalloc(size);
  if ( urp == NULL )
    error("rpc: no local memory");

  memcpy(urp, &p, sizeof(rpc_packet_t));
  int left = size - sizeof(rpc_packet_t);
  uchar *ptr = urp + sizeof(rpc_packet_t);
  code = recv_all(ptr, left, idling, false);
  if ( code != 0 )
    return NULL;

  rpc_packet_t *rp = (rpc_packet_t *)urp;
#ifdef DEBUG_NETWORK
  int len = rp->length;
  show_hex(rp+1, len, "RECV %s %d bytes:\n", get_rpc_name(rp->code), len);
//  msg("RECV %s\n", get_rpc_name(rp->code));
#endif
  return rp;
}

//--------------------------------------------------------------------------
static rpc_packet_t *process_request(string &cmd, bool ida_is_idle=false)
{
  bool only_events = cmd.empty();
  while ( true )
  {
    if ( !cmd.empty() )
    {
      int code = send_request(cmd);
      if ( code != 0 )
        return NULL;
      rpc_packet_t *rp = (rpc_packet_t *)cmd.c_str();
      if ( only_events && rp->code == RPC_EVOK )
        return NULL;
      if ( rp->code == RPC_ERROR )
        qexit(1);
    }
    rpc_packet_t *rp = recv_request(ida_is_idle);
    if ( rp == NULL )
      return NULL;
    switch ( rp->code )
    {
      case RPC_UNK:
        error("rpc: remote did not understand our request");
      case RPC_MEM:
        error("rpc: no remote memory");
      case RPC_OK:
        return rp;
    }
    cmd = perform_request(rp);
    qfree(rp);
  }
}

//--------------------------------------------------------------------------
inline string prepare_rpc_packet(uchar code)
{
  rpc_packet_t rp;
  rp.length = 0;
  rp.code   = code;
  return string((char *)&rp, sizeof(rp));
}

//--------------------------------------------------------------------------
static void append_long(string &s, ulong x)
{
  uchar buf[sizeof(ulong)+1];
  uchar *ptr = buf;
  ptr = pack_dd(ptr, buf + sizeof(buf), x);
  s.append((char *)buf, ptr-buf);
}

//--------------------------------------------------------------------------
inline ulong extract_long(const uchar **ptr, const uchar *end)
{
  return unpack_dd(ptr, end);
}

//--------------------------------------------------------------------------
inline ulonglong extract_longlong(const uchar **ptr, const uchar *end)
{
  return unpack_dq(ptr, end);
}

//--------------------------------------------------------------------------
inline ushort extract_short(const uchar **ptr, const uchar *end)
{
  return unpack_dw(ptr, end);
}

//--------------------------------------------------------------------------
inline void append_str(string &s, const char *str)
{
  if ( str == NULL ) str = "";
  size_t len = strlen(str) + 1;
  s.append(str, len);
}

//--------------------------------------------------------------------------
static char *extract_str(const uchar **ptr, const uchar *end)
{
  char *str = (char *)*ptr;
  *ptr = (const uchar *)strchr(str, '\0') + 1;
  if ( *ptr > end )
    *ptr = end;
  return str;
}

//--------------------------------------------------------------------------
static void append_ea(string &s, ea_t x)
{
  uchar buf[ea_packed_size];
  uchar *ptr = buf;
  ptr = pack_ea(ptr, buf+sizeof(buf), x+1);
  s.append((char *)buf, ptr-buf);
}

//--------------------------------------------------------------------------
inline ea_t extract_ea(const uchar **ptr, const uchar *end)
{
  return unpack_ea(ptr, end) - 1;
}

//--------------------------------------------------------------------------
static void append_memory_info(string &s, const memory_info_t *info)
{
  append_ea(s, info->startEA);
  append_ea(s, info->size());
  append_long(s, info->perm);
  append_str(s, info->name);
  append_str(s, info->sclass);
}

//--------------------------------------------------------------------------
static void extract_memory_info(const uchar **ptr, const uchar *end, memory_info_t *info)
{
  info->startEA = extract_ea(ptr, end);
  info->endEA   = info->startEA + extract_ea(ptr, end);
  info->perm    = uchar(extract_long(ptr, end));
  char *name    = extract_str(ptr, end);
  char *sclass  = extract_str(ptr, end);
  qstrncpy(info->name, name, sizeof(info->name));
  qstrncpy(info->sclass, sclass, sizeof(info->sclass));
}

//--------------------------------------------------------------------------
static void append_process_info(string &s, const process_info_t *info)
{
  append_long(s, info->pid);
  append_str(s, info->name);
}

//--------------------------------------------------------------------------
static void extract_process_info(const uchar **ptr, const uchar *end, process_info_t *info)
{
  info->pid = extract_long(ptr, end);
  char *name = extract_str(ptr, end);
  qstrncpy(info->name, name, sizeof(info->name));
}

//--------------------------------------------------------------------------
static void append_module_info(string &s, const module_info_t *info)
{
  append_str(s, info->name);
  append_ea(s, info->base);
  append_ea(s, info->size);
  append_ea(s, info->rebase_to);
}

//--------------------------------------------------------------------------
static void extract_module_info(const uchar **ptr, const uchar *end, module_info_t *info)
{
  char *name = extract_str(ptr, end);
  info->base = extract_ea(ptr, end);
  info->size = extract_ea(ptr, end);
  info->rebase_to = extract_ea(ptr, end);
  qstrncpy(info->name, name, sizeof(info->name));
}

//--------------------------------------------------------------------------
inline void extract_breakpoint(const uchar **ptr, const uchar *end, e_breakpoint_t *info)
{
  info->hea = extract_ea(ptr, end);
  info->kea = extract_ea(ptr, end);
}

//--------------------------------------------------------------------------
inline void append_breakpoint(string &s, const e_breakpoint_t *info)
{
  append_ea(s, info->hea);
  append_ea(s, info->kea);
}

//--------------------------------------------------------------------------
static void append_exception(string &s, const e_exception_t *e)
{
  append_long(s, e->code);
  append_long(s, e->can_cont);
  append_ea(s, e->ea);
  append_str(s, e->info);
}

//--------------------------------------------------------------------------
static void extract_exception(const uchar **ptr, const uchar *end, e_exception_t *exc)
{
  exc->code     = extract_long(ptr, end);
  exc->can_cont = extract_long(ptr, end);
  exc->ea       = extract_ea(ptr, end);
  char *info    = extract_str(ptr, end);
  qstrncpy(exc->info, info, sizeof(exc->info));
}

//--------------------------------------------------------------------------
static void extract_debug_event(const uchar **ptr, const uchar *end, debug_event_t *ev)
{
  ev->eid     = event_id_t(extract_long(ptr, end));
  ev->pid     = extract_long(ptr, end);
  ev->tid     = extract_long(ptr, end);
  ev->ea      = extract_ea(ptr, end);
  ev->handled = extract_long(ptr, end);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      extract_module_info(ptr, end, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      ev->exit_code = extract_long(ptr, end);
      break;
    case BREAKPOINT:     // Breakpoint reached
      extract_breakpoint(ptr, end, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      extract_exception(ptr, end, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      qstrncpy(ev->info, extract_str(ptr, end), sizeof(ev->info));
      break;
  }
}

//--------------------------------------------------------------------------
static void append_debug_event(string &s, const debug_event_t *ev)
{
  append_long(s, ev->eid);
  append_long(s, ev->pid);
  append_long(s, ev->tid);
  append_ea  (s, ev->ea);
  append_long(s, ev->handled);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      append_module_info(s, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      append_long(s, ev->exit_code);
      break;
    case BREAKPOINT:     // Breakpoint reached
      append_breakpoint(s, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      append_exception(s, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      append_str(s, ev->info);
      break;
  }
}

//--------------------------------------------------------------------------
inline void append_regvals(string &s, const regval_t *values, int n)
{
  s.append((char *)values, sizeof(regval_t)*n);
}

//--------------------------------------------------------------------------
inline void extract_regvals(const uchar **ptr, const uchar *end, regval_t *values, int n)
{
 regval_t *reg_ptr = values;
 
 for(int i = 0;i < n; i++)
 {
	reg_ptr->ival = extract_longlong(ptr, end);
	for(int j=0;j<6;j++)
	{
	 // reg_ptr->fval[j] = 20;
	  extract_short(ptr, end);
	}
	reg_ptr++;
 }
 
/*
  size_t size = sizeof(regval_t) * n;
  memcpy(values, *ptr, size);
  *ptr += size;
  if ( *ptr > end )
    *ptr = end;
*/
}

//--------------------------------------------------------------------------
inline void append_memory(string &s, const void *buf, size_t size)
{
  if ( size != 0 )
    s.append((char *)buf, size);
}

//--------------------------------------------------------------------------
inline void extract_memory(const uchar **ptr, const uchar *end, void *buf, size_t size)
{
  if ( buf != NULL )
    memcpy(buf, *ptr, size);
  *ptr += size;
  if ( *ptr > end )
    *ptr = end;
}

//--------------------------------------------------------------------------
static exception_info_t *extract_exception_info(const uchar **ptr,
                                                const uchar *end,
                                                int qty)
{
  exception_info_t *extable = NULL;
  if ( qty > 0 )
  {
    extable = new exception_info_t[qty];
    if ( extable != NULL )
    {
      for ( int i=0; i < qty; i++ )
      {
        extable[i].code  = extract_long(ptr, end);
        extable[i].flags = extract_long(ptr, end);
        extable[i].name  = extract_str(ptr, end);
        extable[i].desc  = extract_str(ptr, end);
      }
    }
  }
  return extable;
}

//--------------------------------------------------------------------------
static void append_exception_info(string &s, const exception_info_t *table, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    append_long(s, table[i].code);
    append_long(s, table[i].flags);
    append_str(s, table[i].name.c_str());
    append_str(s, table[i].desc.c_str());
  }
}

//--------------------------------------------------------------------------
static string perform_request(const rpc_packet_t *rp)
{
  const uchar *ptr = (const uchar *)(rp + 1);
  const uchar *end = ptr + rp->length;
  string cmd = prepare_rpc_packet(RPC_OK);
  switch ( rp->code )
  {
#ifdef DEBUGGER_SERVER
    case RPC_INIT:
      {
        bool debug_debugger = extract_long(&ptr, end);
        //ERIC if ( debug_debugger )
          verbose = true;
        int result = remote_init(debug_debugger);
        verb(("init(debug_debugger=%d) => %d\n", debug_debugger, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TERM:
      remote_term();
      verb(("term()\n"));
      break;

    case RPC_GET_PROCESS_INFO:
      {
        process_info_t info;
        int n = extract_long(&ptr, end);
        char *input = NULL;
        if ( n == 0 )
          input = extract_str(&ptr, end);
        bool result = remote_process_get_info(n, input, &info);
        append_long(cmd, result);
        if ( result )
          append_process_info(cmd, &info);
        verb(("get_process_info(n=%d) => %d\n", n, result));
      }
      break;

    case RPC_DETACH_PROCESS:
      {
        bool result = remote_detach_process();
        append_long(cmd, result);
        verb(("detach_process() => %d\n", result));
      }
      break;

    case RPC_START_PROCESS:
      {
        char *path = extract_str(&ptr, end);
        char *args = extract_str(&ptr, end);
        char *sdir = extract_str(&ptr, end);
        int flags  = extract_long(&ptr, end);
        char *input= extract_str(&ptr, end);
        ulong crc32= extract_long(&ptr, end);
        int result = remote_start_process(path, args, sdir, flags, input, crc32);
        verb(("start_process(path=%s args=%s flags=%s%s\n"
              "              sdir=%s\n"
              "              input=%s crc32=%x) => %d\n",
              path, args,
              flags & DBG_PROC_IS_DLL ? " is_dll" : "",
              flags & DBG_PROC_IS_GUI ? " under_gui" : "",
              sdir,
              input, crc32,
              result));
        append_long(cmd, result);
      }
      break;

    case RPC_GET_DEBUG_EVENT:
      {
        bool ida_is_idle = extract_long(&ptr, end);
        static debug_event_t ev;
        int result = has_pending_event ? 0 : remote_get_debug_event(&ev, ida_is_idle);
        append_long(cmd, result);
        if ( result == 1 )
        {
          append_debug_event(cmd, &ev);
          verb(("got event: %s\n", debug_event_str(&ev)));
        }
        else if ( !has_pending_event )
          poll_debug_events = true;
//        verb(("get_debug_event(ida_is_idle=%d) => %d (has_pending=%d, poll=%d)\n", ida_is_idle, result, has_pending_event, poll_debug_events));
        verbev(("get_debug_event(ida_is_idle=%d) => %d (has_pending=%d, poll=%d)\n", ida_is_idle, result, has_pending_event, poll_debug_events));
      }
      break;

    case RPC_ATTACH_PROCESS:
      {
        pid_t pid = extract_long(&ptr, end);
        int event_id = extract_long(&ptr, end);
        bool result = remote_attach_process(pid, event_id);
        verb(("attach_process(pid=%u, evid=%d) => %d\n", pid, event_id, result));
        append_long(cmd, result);
      }
      break;

    case RPC_PREPARE_TO_PAUSE_PROCESS:
      {
        bool result = remote_prepare_to_pause_process();
        verb(("prepare_to_pause_process() => %d\n", result));
        append_long(cmd, result);
      }
      break;

    case RPC_EXIT_PROCESS:
      {
        bool result = remote_exit_process();
        verb(("exit_process() => %d\n", result));
        append_long(cmd, result);
      }
      break;

    case RPC_CONTINUE_AFTER_EVENT:
      {
        debug_event_t ev;
        extract_debug_event(&ptr, end, &ev);
        bool result = remote_continue_after_event(&ev);
        verb(("continue_after_event(...) => %d\n", result));
        append_long(cmd, result);
      }
      break;

    case RPC_STOPPED_AT_DEBUG_EVENT:
      remote_stopped_at_debug_event();
      verb(("stopped_at_debug_event\n"));
      break;

    case RPC_TH_SUSPEND:
      {
        thid_t tid = extract_long(&ptr, end);
        bool result = remote_thread_suspend(tid);
        verb(("thread_suspend(tid=%d) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TH_CONTINUE:
      {
        thid_t tid = extract_long(&ptr, end);
        bool result = remote_thread_continue(tid);
        verb(("thread_continue(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TH_SET_STEP:
      {
        thid_t tid = extract_long(&ptr, end);
        bool result = remote_thread_set_step(tid);
        verb(("thread_set_step(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_READ_REGS:
      {
        thid_t tid = extract_long(&ptr, end);
        int nregs = extract_long(&ptr, end);
        regval_t *values = new regval_t[nregs];
        if ( values == NULL ) goto nomem;
        bool result = remote_thread_read_registers(tid, values, nregs);
        verb(("thread_read_regs(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
        append_regvals(cmd, values, nregs);
        delete values;
      }
      break;

    case RPC_WRITE_REG:
      {
        thid_t tid = extract_long(&ptr, end);
        int reg_idx = extract_long(&ptr, end);
        regval_t value;
        extract_regvals(&ptr, end, &value, 1);
        bool result = remote_thread_write_register(tid, reg_idx, &value);
        verb(("thread_write_reg(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_GET_SREG_BASE:
      {
        thid_t tid = extract_long(&ptr, end);
        int sreg_value = extract_long(&ptr, end);
        ea_t ea;
        bool result = remote_thread_get_sreg_base(tid, sreg_value, &ea);
        verb(("get_thread_sreg_base(tid=%u, %d) => %a\n", tid, sreg_value, result ? ea : BADADDR));
        append_long(cmd, result);
        if ( result )
          append_ea(cmd, ea);
      }
      break;

    case RPC_SET_EXCEPTION_INFO:
      {
        int qty = extract_long(&ptr, end);
        exception_info_t *extable = extract_exception_info(&ptr, end, qty);
        remote_set_exception_info(extable, qty);
        verb(("set_exception_info(qty=%u)\n", qty));
      }
      break;

    case RPC_GET_MEMORY_INFO:
      {
        memory_info_t *areas;
        int qty;
        int result = remote_get_memory_info(&areas, &qty);
        verb(("get_memory_info() => %d (qty=%d)\n", result, qty));
        append_long(cmd, result);
        if ( result > 0 )
        {
          append_long(cmd, qty);
          for ( int i=0; i < qty; i++ )
            append_memory_info(cmd, &areas[i]);
          qfree(areas);
        }
      }
      break;

    case RPC_READ_MEMORY:
      {
        ea_t ea = extract_ea(&ptr, end);
        size_t size = extract_long(&ptr, end);
        uchar *buf = new uchar[size];
        if ( buf == NULL ) goto nomem;
        ssize_t result = remote_read_memory(ea, buf, size);
        verb(("read_memory(ea=%a size=%d) => %d", ea, size, result));
        if ( result && size == 1 )
          verb((" (0x%02X)\n", *buf));
        else
          verb(("\n"));
        append_long(cmd, ulong(result));
        append_memory(cmd, buf, size);
        delete buf;
      }
      break;

    case RPC_WRITE_MEMORY:
      {
        ea_t ea = extract_ea(&ptr, end);
        size_t size = extract_long(&ptr, end);
        uchar *buf = new uchar[size];
        if ( buf == NULL ) goto nomem;
        extract_memory(&ptr, end, buf, size);
        ssize_t result = remote_write_memory(ea, buf, size);
        verb(("write_memory(ea=%a size=%d) => %d", ea, size, result));
        if ( result && size == 1 )
          verb((" (0x%02X)\n", *buf));
        else
          verb(("\n"));
        append_long(cmd, ulong(result));
        delete buf;
      }
      break;

    case RPC_ISOK_BPT:
      {
        bpttype_t type = extract_long(&ptr, end);
        ea_t ea        = extract_ea(&ptr, end);
        int len        = extract_long(&ptr, end);
        int result  = remote_is_ok_bpt(type, ea, len);
        verb(("isok_bpt(type=%d ea=%a len=%d) => %d\n", type, ea, len, result));
        append_long(cmd, result);
      }
      break;

    case RPC_ADD_BPT:
      {
        bpttype_t type = extract_long(&ptr, end);
        ea_t ea        = extract_ea(&ptr, end);
        int len        = extract_long(&ptr, end);
        bool result = remote_add_bpt(type, ea, len);
        verb(("add_bpt(type=%d ea=%a len=%d) => %d\n", type, ea, len, result));
        append_long(cmd, result);
      }
      break;

    case RPC_DEL_BPT:
      {
        ea_t ea  = extract_ea(&ptr, end);
        int size = extract_long(&ptr, end);
        uchar *buf = NULL;
        if ( size != 0 )
        {
          buf = new uchar[size];
          if ( buf == NULL ) goto nomem;
          extract_memory(&ptr, end, buf, size);
        }
        bool result = remote_del_bpt(ea, buf, size);
        verb(("del_bpt(ea=%a) => %d\n", ea, result));
        append_long(cmd, result);
        delete buf;
      }
      break;

    case RPC_OPEN_FILE:
      {
        char *file = extract_str(&ptr, end);
        bool readonly = extract_long(&ptr, end);
        ulong fsize = 0;
        int fn = find_free_channel();
        if ( fn != -1 )
        {
          channels[fn] = (readonly ? fopenRB : fopenWB)(file);
          if ( channels[fn] == NULL )
            fn = -1;
          else if ( readonly )
            fsize = efilelength(channels[fn]);
        }
        verb(("open_file('%s', %d) => %d %d\n", file, readonly, fn, fsize));
        append_long(cmd, fn);
        if ( fn != -1 )
          append_long(cmd, fsize);
        else
          append_long(cmd, qerrcode());
      }
      break;

    case RPC_CLOSE_FILE:
      {
        int fn = extract_long(&ptr, end);
        if ( fn >= 0 && fn < qnumber(channels) )
        {
          qfclose(channels[fn]);
          channels[fn] = NULL;
        }
        verb(("close_file(%d)\n", fn));
      }
      break;

    case RPC_READ_FILE:
      {
        char *buf = NULL;
        int fn    = extract_long(&ptr, end);
        long off  = extract_long(&ptr, end);
        long size = extract_long(&ptr, end);
        long s2 = size - 1;
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
          qfseek(channels[fn], off, SEEK_SET);
          s2 = qfread(channels[fn], buf, size);
        }
        append_long(cmd, size);
        if ( size != s2 )
          append_long(cmd, qerrcode());
        append_memory(cmd, buf, size);
        delete buf;
        verb(("read_file(%d, 0x%lX, %d) => %d\n", fn, off, size, s2));
      }
      break;

    case RPC_WRITE_FILE:
      {
        char *buf = NULL;
        int fn     = extract_long(&ptr, end);
        ulong off  = extract_long(&ptr, end);
        ulong size = extract_long(&ptr, end);
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
          extract_memory(&ptr, end, buf, size);
        }
        qfseek(channels[fn], off, SEEK_SET);
        ulong s2 = qfwrite(channels[fn], buf, size);
        append_long(cmd, size);
        if ( size != s2 )
          append_long(cmd, qerrcode());
        delete buf;
        verb(("write_file(%d, 0x%lX, %d) => %d\n", fn, off, size, s2));
      }
      break;

    case RPC_IOCTL:
      {
        char *buf = NULL;
        int fn = extract_long(&ptr, end);
        size_t size = extract_long(&ptr, end);
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
        }
        extract_memory(&ptr, end, buf, size);
        void *outbuf = NULL;
        ssize_t outsize = 0;
        int code = remote_ioctl(fn, buf, size, &outbuf, &outsize);
        append_long(cmd, code);
        append_long(cmd, outsize);
        if ( outsize > 0 )
          append_memory(cmd, outbuf, outsize);
        qfree(outbuf);
        verb(("ioctl(%d) => %d\n", fn, code));
      }
      break;

    case RPC_EVOK:
      has_pending_event = false;
      cmd = "";
      verbev(("got evok, clearing has_pending_event\n"));
      break;

#else // ifdef DEBUGGER_SERVER
    case RPC_SET_DEBUG_NAMES:
      {
        int qty = extract_long(&ptr, end);
        ea_t *addrs = new ea_t[qty];
        if ( addrs == NULL ) goto nomem;
        char **names = new char *[qty];
        if ( names == NULL ) { delete addrs; goto nomem; }
        char name[MAXSTR];
        ea_t old = 0;
        name[0] = '\0';
        for ( int i=0; i < qty; i++ )
        {
          adiff_t o2 = extract_ea(&ptr, end);
          if ( extract_long(&ptr, end) ) o2 = -o2;
          old += o2;
          addrs[i] = old;
          int oldlen = extract_long(&ptr, end);
          qstrncpy(&name[oldlen], extract_str(&ptr, end), sizeof(name)-oldlen);
          names[i] = qstrdup(name);
        }
        int result = set_debug_names(addrs, names, qty);
        verb(("set_debug_name(qty=%d) => %d\n", qty, result));
        append_long(cmd, result);
        for ( int i=0; i < qty; i++ )
          qfree(names[i]);
        delete addrs;
        delete names;
      }
      break;

    case RPC_SYNC_STUB:
      {
        char *fname = extract_str(&ptr, end);
        ulong crc = extract_long(&ptr, end);
        size_t size = 0;
        uchar *contents = sync_stub(fname, crc, &size);
        append_long(cmd, size);
        if ( contents != NULL )
        {
          append_memory(cmd, contents, size);
          qfree(contents);
        }
      }
      break;

    case RPC_ERROR:
    case RPC_MSG:
    case RPC_WARNING:
      {
        char *str = extract_str(&ptr, end);
             if ( rp->code == RPC_MSG   ) msg("%s", str);
        else if ( rp->code == RPC_ERROR ) error("%s", str);
        else                              warning("%s", str);
      }
      break;

    case RPC_EVENT:
      {
        extract_debug_event(&ptr, end, &pending_event);
        has_pending_event = true;
        cmd = prepare_rpc_packet(RPC_EVOK);
        verbev(("got event, storing it and sending RPC_EVOK\n"));
      }
      break;

#endif

    default:
      return prepare_rpc_packet(RPC_UNK);
    nomem:
      return prepare_rpc_packet(RPC_MEM);
  }
  return cmd;
}

//--------------------------------------------------------------------------
static int process_long(string &cmd)
{
  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  qfree(rp);
  return result;
}

#ifndef DEBUGGER_SERVER
//--------------------------------------------------------------------------
inline int rpc_getint(ushort code)
{
  string cmd = prepare_rpc_packet(code);
  return process_long(cmd);
}

//--------------------------------------------------------------------------
static int rpc_getint2(uchar code, int x)
{
  string cmd = prepare_rpc_packet(code);
  append_long(cmd, x);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_init(bool _debug_debugger)
{
  has_pending_event = false;
  poll_debug_events = false;
  return rpc_getint2(RPC_INIT, _debug_debugger);
}

//--------------------------------------------------------------------------
void rpc_term(void)
{
  string cmd = prepare_rpc_packet(RPC_TERM);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
// input is valid only if n==0
int rpc_process_get_info(int n, const char *input, process_info_t *info)
{
  string cmd = prepare_rpc_packet(RPC_GET_PROCESS_INFO);
  append_long(cmd, n);
  if ( n == 0 )
    append_str(cmd, input);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end);
  if ( result )
    extract_process_info(&answer, end, info);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int rpc_detach_process(void)
{
  return rpc_getint(RPC_DETACH_PROCESS);
}

//--------------------------------------------------------------------------
int rpc_start_process(const char *path,
                      const char *args,
                      const char *startdir,
                      int flags,
                      const char *input_path,
                      ulong input_file_crc32)
{
  string cmd = prepare_rpc_packet(RPC_START_PROCESS);
  append_str(cmd, path);
  append_str(cmd, args);
  append_str(cmd, startdir);
  append_long(cmd, flags);
  append_str(cmd, input_path);
  append_long(cmd, input_file_crc32);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_get_debug_event(debug_event_t *event, bool ida_is_idle)
{
  if(event && event->eid == PROCESS_START)
    msg("remote name = %s, base = %08x, size = %08x, rebase_to = %08x BADADDR = %08x\n", event->modinfo.name, event->modinfo.base, event->modinfo.size, event->modinfo.rebase_to, BADADDR);

  if ( has_pending_event )
  {
    verbev(("get_debug_event => has pending event, returning it\n"));
    *event = pending_event;
    has_pending_event = false;
    poll_debug_events = false;
    return 1;
  }

  int result = false;
  if ( poll_debug_events )
  {
    // do we have something waiting?
    // we must use TIMEOUT here to avoid competition between
    // IDA analyzer and the debugger program.
    // The analysis will be slow during the application run.
    // As soon as the program is suspended, the analysis will be fast
    // because get_debug_event() will not be called.
    if ( irs_ready(irs) != 0 )
    {
      verbev(("get_debug_event => remote has an event for us\n"));
      // get the packet - it should be RPC_EVENT (nothing else can be)
      string empty;
      rpc_packet_t *rp = process_request(empty, ida_is_idle);
      verbev(("get_debug_event => processed remote event, has=%d\n", has_pending_event));
      if ( rp != NULL || !has_pending_event )
        error("rpc: event protocol error");
    }
  }
  else
  {
    verbev(("get_debug_event => first time, send GET_DEBUG_EVENT\n"));
    string cmd = prepare_rpc_packet(RPC_GET_DEBUG_EVENT);
    append_long(cmd, ida_is_idle);

    rpc_packet_t *rp = process_request(cmd);
    if ( rp == NULL ) return -1;
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;

    result = extract_long(&answer, end);
    if ( result == 1 )
      extract_debug_event(&answer, end, event);
    else
      poll_debug_events = true;
    verbev(("get_debug_event => remote said %d, poll=%d now\n", result, poll_debug_events));
    qfree(rp);
  }
  return result;
}

//--------------------------------------------------------------------------
int rpc_attach_process(pid_t pid, int event_id)
{
  string cmd = prepare_rpc_packet(RPC_ATTACH_PROCESS);
  append_long(cmd, pid);
  append_long(cmd, event_id);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_prepare_to_pause_process(void)
{
  return rpc_getint(RPC_PREPARE_TO_PAUSE_PROCESS);
}

//--------------------------------------------------------------------------
int rpc_exit_process(void)
{
  return rpc_getint(RPC_EXIT_PROCESS);
}

//--------------------------------------------------------------------------
int rpc_continue_after_event(const debug_event_t *event)
{
  string cmd = prepare_rpc_packet(RPC_CONTINUE_AFTER_EVENT);
  append_debug_event(cmd, event);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
void rpc_stopped_at_debug_event(void)
{
  string cmd = prepare_rpc_packet(RPC_STOPPED_AT_DEBUG_EVENT);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
int rpc_thread_suspend(thid_t tid)
{
  return rpc_getint2(RPC_TH_SUSPEND, tid);
}

//--------------------------------------------------------------------------
int rpc_thread_continue(thid_t tid)
{
  return rpc_getint2(RPC_TH_CONTINUE, tid);
}

//--------------------------------------------------------------------------
int rpc_thread_set_step(thid_t tid)
{
  return rpc_getint2(RPC_TH_SET_STEP, tid);
}

//--------------------------------------------------------------------------
int rpc_thread_read_registers(thid_t tid, regval_t *values, int n)
{
  string cmd = prepare_rpc_packet(RPC_READ_REGS);
  append_long(cmd, tid);
  append_long(cmd, n);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  extract_regvals(&answer, end, values, n);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int rpc_thread_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  string cmd = prepare_rpc_packet(RPC_WRITE_REG);
  append_long(cmd, tid);
  append_long(cmd, reg_idx);
  append_regvals(cmd, value, 1);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_get_memory_info(memory_info_t **areas, int *qty)
{
  string cmd = prepare_rpc_packet(RPC_GET_MEMORY_INFO);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  if ( result > 0 )
  {
    *qty = extract_long(&answer, end);
    *areas = (memory_info_t *)qalloc(*qty * sizeof(memory_info_t));
    if ( *qty != 0 )
    {
      if ( areas == NULL )
        nomem("get_memory_info");
      for ( int i=0; i < *qty; i++ )
        extract_memory_info(&answer, end, &(*areas)[i]);
    }
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t rpc_read_memory(ea_t ea, void *buffer, size_t size)
{
  string cmd = prepare_rpc_packet(RPC_READ_MEMORY);
  append_ea(cmd, ea);
  append_long(cmd, size);

  msg("read remote mem %x size: %d\n", ea, size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  extract_memory(&answer, end, buffer, size);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t rpc_write_memory(ea_t ea, const void *buffer, size_t size)
{
  string cmd = prepare_rpc_packet(RPC_WRITE_MEMORY);
  append_ea(cmd, ea);
  append_long(cmd, size);
  append_memory(cmd, buffer, size);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
static int rpc_bpt(uchar code, bpttype_t type, ea_t ea, int len)
{
  string cmd = prepare_rpc_packet(code);
  append_long(cmd, type);
  append_ea(cmd, ea);
  append_long(cmd, len);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  return rpc_bpt(RPC_ISOK_BPT, type, ea, len);
}

//--------------------------------------------------------------------------
int rpc_add_bpt(bpttype_t type, ea_t ea, int len)
{
  return rpc_bpt(RPC_ADD_BPT, type, ea, len);
}

//--------------------------------------------------------------------------
int rpc_del_bpt(ea_t ea, const uchar *orig_bytes, int len)
{
  string cmd = prepare_rpc_packet(RPC_DEL_BPT);
  append_ea(cmd, ea);
  append_long(cmd, len);
  append_memory(cmd, orig_bytes, len);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_thread_get_sreg_base(thid_t tid, int sreg_value, ea_t *ea)
{
  string cmd = prepare_rpc_packet(RPC_GET_SREG_BASE);
  append_long(cmd, tid);
  append_long(cmd, sreg_value);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end);
  if ( result )
    *ea = extract_ea(&answer, end);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
void rpc_set_exception_info(const exception_info_t *table, int qty)
{
  string cmd = prepare_rpc_packet(RPC_SET_EXCEPTION_INFO);
  append_long(cmd, qty);
  append_exception_info(cmd, table, qty);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
int rpc_open_file(const char *file, ulong *fsize, bool readonly)
{
  string cmd = prepare_rpc_packet(RPC_OPEN_FILE);
  append_str(cmd, file);
  append_long(cmd, readonly);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int fn = extract_long(&answer, end);
  if ( fn != -1 )
  {
    if ( fsize != NULL && readonly )
      *fsize = extract_long(&answer, end);
  }
  else
  {
    qerrcode(extract_long(&answer, end));
  }
  qfree(rp);
  return fn;
}

//--------------------------------------------------------------------------
void rpc_close_file(int fn)
{
  string cmd = prepare_rpc_packet(RPC_CLOSE_FILE);
  append_long(cmd, fn);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_read_file(int fn, ulong off, void *buf, size_t size)
{
  string cmd = prepare_rpc_packet(RPC_READ_FILE);
  append_long(cmd, fn);
  append_long(cmd, off);
  append_long(cmd, size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  long rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));
  if ( rsize > 0 )
  {
    if ( rsize > size )
      error("rpc_read_file: protocol error");
    extract_memory(&answer, end, buf, rsize);
  }
  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_write_file(int fn, ulong off, const void *buf, size_t size)
{
  string cmd = prepare_rpc_packet(RPC_WRITE_FILE);
  append_long(cmd, fn);
  append_long(cmd, off);
  append_long(cmd, size);
  append_memory(cmd, buf, size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  long rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));
  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
int idaapi rpc_ioctl(int fn,
                     const void *buf,
                     size_t size,
                     void **poutbuf,
                     ssize_t *poutsize)
{
  string cmd = prepare_rpc_packet(RPC_IOCTL);
  append_long(cmd, fn);
  append_long(cmd, size);
  append_memory(cmd, buf, size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int code = extract_long(&answer, end);
  ssize_t outsize = extract_long(&answer, end);
  if ( outsize > 0 && poutbuf != NULL )
  {
    *poutbuf = qalloc(outsize);
    if ( *poutbuf != NULL )
      extract_memory(&answer, end, *poutbuf, outsize);
  }
  if ( poutsize != NULL ) *poutsize = outsize;
  qfree(rp);
  return code;
}

//--------------------------------------------------------------------------
static void connection_failed(rpc_packet_t *rp)
{
  qfree(rp);
  if ( irs != NULL )
  {
    term_client_irs(irs);
    irs = NULL;
  }
}

//--------------------------------------------------------------------------
bool open_remote(const char *hostname, int port_number, const char *password)
{
  rpc_packet_t *rp = NULL;
  irs = init_client_irs(hostname, port_number);
  if ( irs == NULL )
  {
failed:
    connection_failed(rp);
    return false;
  }

  rp = recv_request(false);
  if ( rp == NULL )
    goto failed;

  if ( rp->code != RPC_OPEN )  // is this an ida debugger server?
  {
    connection_failed(rp);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Bogus remote server");
    return false;
  }

  int len = rp->length; //ntohl(rp->length);
  show_hex(rp+1, len, "SEND %s %d bytes:\n", get_rpc_name(rp->code), len);
  
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  int version = extract_long(&answer, end);
  int remote_debugger_id = extract_long(&answer, end);
  int easize = extract_long(&answer, end);
  msg("IDD_INTERFACE_VERSION = %d\n", IDD_INTERFACE_VERSION);
  msg("Remote IDD_INTERFACE_VERSION = %d\n", version);
  msg("id = %d\n", debugger.id);
  msg("remote id = %d\n", remote_debugger_id);
  msg("remote easize = %d\n", easize);
  
  if ( version != IDD_INTERFACE_VERSION
    || remote_debugger_id != debugger.id
    || easize != sizeof(ea_t) )
  {
    connection_failed(rp);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Incompatible debugging server");
    string cmd = prepare_rpc_packet(RPC_OK);
    append_long(cmd, false);
    send_request(cmd);
    return false;
  }
  qfree(rp);

  string cmd = prepare_rpc_packet(RPC_OK);
  append_long(cmd, true);
  append_str(cmd, password);
  send_request(cmd);

  rp = recv_request(false);
  if ( rp == NULL || rp->code != RPC_OK )
    goto failed;

  answer = (uchar *)(rp+1);
  end = answer + rp->length;
  bool password_ok = extract_long(&answer, end);
  if ( !password_ok )  // is this an ida debugger server?
  {
    connection_failed(rp);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Bad password");
    return false;
  }

  qfree(rp);
  return true;
}

//--------------------------------------------------------------------------
bool close_remote(void)
{
  string cmd = prepare_rpc_packet(RPC_OK);
  send_request(cmd);
  term_client_irs(irs);
  irs = NULL;
  network_error_code = 0;
  return true;
}

//--------------------------------------------------------------------------
void neterr(const char *module)
{
  int code = irs_error(irs);
  error("%s: %s", module, winerr(code));
}

//--------------------------------------------------------------------------
// check and send to the remote server the specified stub
// do it only if its crc does not match the specified crc
// this function runs on the local machine with ida interface
static uchar *sync_stub(const char *fname, ulong crc, size_t *psize)
{
  char path[QMAXPATH];
  bool told = false;
  if ( getsysfile(path, sizeof(path), fname, NULL) != NULL )
  {
    linput_t *li = open_linput(path, false);
    if ( li != NULL )
    {
      long size = qlsize(li);
      if ( size > 0 )
      {
        uchar *buf = qnewarray(uchar, size);
        if ( buf != NULL )
        {
          if ( qlread(li, buf, size) == size )
          {
            if ( calc_crc32(0, buf, size) != crc )
            {
              close_linput(li);
              *psize = size;
              return buf;
            }
            else
            {
              msg("Kernel debugger stub is up to date...\n");
              told = true;
              *psize = 1;       // signal ok
            }
          }
          qfree(buf);
        }
      }
      close_linput(li);
    }
  }
  if ( !told )
    warning("AUTOHIDE NONE\nCould not find/read debugger stub %s", fname);
  return NULL;
}

#else

//--------------------------------------------------------------------------
// this function runs on the server size
bool rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name)
{
  bool ok = false;
  int32 crc32 = -1;
  linput_t *li = open_linput(server_stub_name, false);
  if ( li != NULL )
  {
    crc32 = calc_file_crc32(li);
    close_linput(li);
  }
  string stub = prepare_rpc_packet(RPC_SYNC_STUB);
  append_str(stub, ida_stub_name);
  append_long(stub, crc32);
  rpc_packet_t *rp = process_request(stub, true);
  if ( rp != NULL )
  {
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;
    size_t size = extract_long(&answer, end);
    if ( size == 1 )
    {
      ok = true;
    }
    else if ( size != 0 )
    {
      FILE *fp = fopenWB(server_stub_name);
      if ( fp != NULL )
      {
        ok = qfwrite(fp, answer, size) == size;
        msg("Updated kernel debugger stub: %s\n", ok ? "success" : "failed");
        qfclose(fp);
      }
      else
      {
        swarning("Could not update the kernel debugger stub.\n%s", qerrstr());
      }
    }
    qfree(rp);
  }
  return ok;
}

//--------------------------------------------------------------------------
int rpc_set_debug_names(const ea_t *ea, const char *const *names, int qty)
{
  string cmd = prepare_rpc_packet(RPC_SET_DEBUG_NAMES);
  append_long(cmd, qty);
  ea_t old = 0;
  const char *optr = "";
  for ( int i=0; i < qty; i++ )
  {
    adiff_t diff = ea[i] - old;
    bool neg = diff < 0;
    if ( neg ) diff = - diff;
    append_ea(cmd, diff);
    append_long(cmd, neg);
    old = ea[i];
    const char *nptr = names[i];
    int len = 0;
    while ( nptr[len] != '\0' && nptr[len] == optr[len] )
      len++;
    append_long(cmd, len);
    append_str(cmd, nptr+len);
    optr = nptr;
  }

  return process_long(cmd);
}

//--------------------------------------------------------------------------
ssize_t rpc_svmsg(int code, const char *format, va_list va)
{
       if ( code == 0 ) code = RPC_MSG;
  else if ( code >  0 ) code = RPC_WARNING;
  else                  code = RPC_ERROR;
  string cmd = prepare_rpc_packet(code);

  char buf[MAXSTR];
  qvsnprintf(buf, sizeof(buf), format, va);
  append_str(cmd, buf);

  qfree(process_request(cmd));
  return strlen(buf);
}

//--------------------------------------------------------------------------
static int poll_events(bool idling)
{
  int code = 0;
  if ( !has_pending_event )
  {
    has_pending_event = remote_get_debug_event(&pending_event, idling);
    if ( has_pending_event )
    {
      poll_debug_events = false;
      verbev(("got event, sending it, poll will be 0 now\n"));
      string cmd = prepare_rpc_packet(RPC_EVENT);
      append_debug_event(cmd, &pending_event);
      code = send_request(cmd);
    }
  }
  return code;
}

#endif

#else           // if there is no network at all

int rpc_set_debug_names(const ea_t *addrs, const char *const *names, int qty)
  { return set_debug_names(addrs, names, qty); }
ssize_t rpc_svmsg(int code, const char *format, va_list va)
{
  if ( code == 0 )
    return vmsg(format, va);
  if ( code > 0 )
    vwarning(format, va);
  else
    verror(format, va);
  return 0;
}
bool open_remote(const char *, int, const char *)
  { return true; }
bool close_remote(void)
  { return true; }

#endif

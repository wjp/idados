
#pragma pack(push, 1)

#ifdef REMOTE_DEBUGGER
#ifndef DEBUGGER_SERVER
#define DEBUGGER_CLIENT
#endif
#endif

#if defined(DEBUGGER_SERVER) || defined(DEBUGGER_CLIENT)
#define REMOTE_DEBUGGING
#endif

#define TIMEOUT         (1000/25)       // in milliseconds, timeout for polling
                                        // network and debugger

#ifdef __LINUX__
#define SYSTEM_SPECIFIC_ERRNO   errno
#define SYSTEM_SPECIFIC_ERRSTR  strerror
#else
#define SYSTEM_SPECIFIC_ERRNO  GetLastError()
#define SYSTEM_SPECIFIC_ERRSTR winerr
#endif

// functions exported by the local debugger client for the remote:

bool rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name);
int  rpc_set_debug_names(const ea_t *ea, const char *const *name, int qty);
ssize_t rpc_svmsg(int code, const char *str, va_list va);

// functions exported by the remote debugger client for the local:

// flags for start_process::flags
#define DBG_PROC_IS_DLL 0x01  // database contains a dll (not exe)
#define DBG_PROC_IS_GUI 0x02  // using gui version of ida

#define DECLARE_REMOTE_FUNCTIONS(prefix)                                       \
int idaapi prefix ## init(bool _debug_debugger);                               \
void idaapi prefix ## term(void);                                              \
int  idaapi prefix ## process_get_info(int n,                                  \
                                const char *input,                             \
                                process_info_t *info);                         \
int  idaapi prefix ## detach_process(void);                                    \
int  idaapi prefix ## start_process(const char *path,                          \
                                const char *args,                              \
                                const char *startdir,                          \
                                int flags,                                     \
                                const char *input_path,                        \
                                ulong input_file_crc32);                       \
int  idaapi prefix ## get_debug_event(debug_event_t *event, bool ida_is_idle); \
int  idaapi prefix ## attach_process(process_id_t process_id, int event_id);   \
int  idaapi prefix ## prepare_to_pause_process(void);                          \
int  idaapi prefix ## exit_process(void);                                      \
int  idaapi prefix ## continue_after_event(const debug_event_t *event);        \
void idaapi prefix ## set_exception_info(const exception_info_t *info, int qty); \
void idaapi prefix ## stopped_at_debug_event(void);                            \
int  idaapi prefix ## thread_suspend(thread_id_t thread_id);                   \
int  idaapi prefix ## thread_continue(thread_id_t thread_id);                  \
int  idaapi prefix ## thread_set_step(thread_id_t thread_id);                  \
int  idaapi prefix ## thread_read_registers(thread_id_t thread_id,             \
                                            regval_t *values,                  \
                                            int count);                        \
int  idaapi prefix ## thread_write_register(thread_id_t thread_id,             \
                                            int reg_idx,                       \
                                            const regval_t *value);            \
int  idaapi prefix ## thread_get_sreg_base(thread_id_t thread_id,              \
                                           int sreg_value,                     \
                                           ea_t *ea);                          \
int  idaapi prefix ## get_memory_info(memory_info_t **areas, int *qty);        \
ssize_t idaapi prefix ## read_memory(ea_t ea, void *buffer, size_t size);      \
ssize_t idaapi prefix ## write_memory(ea_t ea, const void *buffer, size_t size); \
int  idaapi prefix ## is_ok_bpt(bpttype_t type, ea_t ea, int len);             \
int  idaapi prefix ## add_bpt(bpttype_t type, ea_t ea, int len);               \
int  idaapi prefix ## del_bpt(ea_t ea, const uchar *orig_bytes, int len);      \
int  idaapi prefix ## open_file(const char *file, ulong *fsize, bool readonly);\
void idaapi prefix ## close_file(int fn);                                      \
ssize_t idaapi prefix ## read_file(int fn, ulong off, void *buf, size_t size); \
ssize_t idaapi prefix ## write_file(int fn, ulong off, const void *buf, size_t size); \
int  idaapi prefix ## ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize);

DECLARE_REMOTE_FUNCTIONS(remote_)
DECLARE_REMOTE_FUNCTIONS(rpc_)

#ifdef REMOTE_DEBUGGER
#define prefix rpc_
#else
#define prefix remote_
#endif

#define r_init                     paste(prefix, init)
#define r_term                     paste(prefix, term)
#define r_process_get_info         paste(prefix, process_get_info)
#define r_detach_process           paste(prefix, detach_process)
#define r_start_process            paste(prefix, start_process)
#define r_get_debug_event          paste(prefix, get_debug_event)
#define r_attach_process           paste(prefix, attach_process)
#define r_prepare_to_pause_process paste(prefix, prepare_to_pause_process)
#define r_exit_process             paste(prefix, exit_process)
#define r_continue_after_event     paste(prefix, continue_after_event)
#define r_set_exception_info       paste(prefix, set_exception_info)
#define r_stopped_at_debug_event   paste(prefix, stopped_at_debug_event)
#define r_thread_suspend           paste(prefix, thread_suspend)
#define r_thread_continue          paste(prefix, thread_continue)
#define r_thread_set_step          paste(prefix, thread_set_step)
#define r_thread_read_registers    paste(prefix, thread_read_registers)
#define r_thread_write_register    paste(prefix, thread_write_register)
#define r_get_memory_info          paste(prefix, get_memory_info)
#define r_read_memory              paste(prefix, read_memory)
#define r_write_memory             paste(prefix, write_memory)
#define r_is_ok_bpt                paste(prefix, is_ok_bpt)
#define r_add_bpt                  paste(prefix, add_bpt)
#define r_del_bpt                  paste(prefix, del_bpt)
#define r_thread_get_sreg_base     paste(prefix, thread_get_sreg_base)

#define paste(x, y) paste2(x, y)
#define paste2(x, y) x ## y

void neterr(const char *module);
bool close_remote(void);
bool open_remote(const char *hostname, int port_number);

extern bool has_pending_event;
extern bool poll_debug_events;
extern debugger_t debugger;

char *debug_event_str(const debug_event_t *ev, char *buf, size_t bufsize);
char *debug_event_str(const debug_event_t *ev);

#ifdef __NT__
#include <windows.h>
void DEBUG_CONTEXT(CONTEXT &Context);
void show_exception_record(const EXCEPTION_RECORD &er, int level=0);
#endif

bool get_exception_name(int code, char *buf, size_t bufsize);
int is_valid_bpt(bpttype_t type, ea_t ea, int len);

// low level connection transport
// currently we have 2 transports: tcp/ip and activesync

// the idarpc_stream_struct_t structure is not defined.
// it is used as an opaque type provided by the transport level.
// the transport level defines its own local type for it.
typedef struct idarpc_stream_struct_t idarpc_stream_t;

bool init_irs_layer(void);
void setup_irs(idarpc_stream_t *irs);   // setup stream options
                                        // (used only for tcp/ip socket options)
idarpc_stream_t *init_server_irs(void *stream); // init server side stream
idarpc_stream_t *init_client_irs(const char *hostname, int port_number);
void term_client_irs(idarpc_stream_t *irs);
void term_server_irs(idarpc_stream_t *irs);
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n); // -1-error
ssize_t irs_recv(idarpc_stream_t *irs,       void *buf, size_t n); // -1-error
int irs_ready(idarpc_stream_t *irs);  // 0-nothing, 1-data ready, -1-error
int irs_error(idarpc_stream_t *irs);  // get error code
ulong irs_htonl(ulong x);
ulong irs_ntohl(ulong x);

struct rpc_packet_t      // fields are always sent in the network order
{
  ulong length;          // length of the packet (do not count length & code)
  uchar code;            // function code
};

//----------------------------------------------------------------------
//
//      UTILITY FUNCTIONS
//
//----------------------------------------------------------------------
inline ssize_t smsg(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  ssize_t code = rpc_svmsg(0, format, va);
  va_end(va);
  return code;
}

inline void swarning(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  rpc_svmsg(1, format, va);
  va_end(va);
}

inline void serror(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  rpc_svmsg(-1, format, va);
  va_end(va);
  exit(1);
}

#ifdef USE_ASYNC
inline void lprintf(const char *,...) {} // No stdout on some WinCE devices?
#else
inline void lprintf(const char *format,...)
{
  va_list va;
  va_start(va, format);
  qvprintf(format, va);
  va_end(va);
}
#endif

#pragma pack(pop)


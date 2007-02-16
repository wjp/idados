#include <loader.hpp>

static const uchar bpt_code[] = BPT_CODE;

static bool ask_user_and_copy(const char *ipath);
//--------------------------------------------------------------------------
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  int ret = is_valid_bpt(type, ea, len);
  if ( ret != BPT_OK )
    return ret;

  return r_is_ok_bpt(type, ea, len);
}

//--------------------------------------------------------------------------
static int idaapi add_bpt(bpttype_t type, ea_t ea, int len)
{
  int ret = is_valid_bpt(type, ea, len);
  if ( ret != BPT_OK )
    return false;

  return r_add_bpt(type, ea, len);
}

//--------------------------------------------------------------------------
static int idaapi start_process(const char *path,
                                const char *args,
                                const char *startdir,
                                ulong input_file_crc32)
{
  // check that the host application has been specified
  char p2[QMAXPATH];
  get_input_file_path(p2, sizeof(p2));
  if ( is_dll && strcmp(path, p2) == 0 )
  {
    warning("AUTOHIDE NONE\n"
            "Please specify the host application first (Debugger, Process options)");
    return 0;
  }
  int flags = is_dll ? DBG_PROC_IS_DLL : 0;
  if ( callui(ui_get_hwnd).vptr != NULL )
    flags |= DBG_PROC_IS_GUI;
  const char *input;
  if ( is_temp_database() )
  {
    input = "";
  }
  else
  {
    // for mini databases the name of the input file won't have the full
    // path. make it full path so that we will use correct path for the input
    // file name.
    if ( is_miniidb() )
    {
      set_root_filename(path);
      input = path;
    }
    else
    {
      input = p2;
    }
  }
  int code;
  while ( true )
  {
    code = r_start_process(path, args, startdir, flags, input, input_file_crc32);
#ifdef REMOTE_DEBUGGER
    if ( code == -2 )
    {
      // if the file is missing on the remote location
      // then propose to copy it
      if ( ask_user_and_copy(p2) )
      {
        get_input_file_path(p2, sizeof(p2));
        path = p2;
        startdir = "";
        continue;
      }
    }
#endif
    break;
  }
  return code;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed, -1-error
static int idaapi get_debug_event(debug_event_t *event, bool ida_is_idle)
{
  int code = r_get_debug_event(event, ida_is_idle);
  if ( code == 1 )
  {
    // determine rebasing - we can't do that reliabily remotely, because:
    // - 'is_dll' is not passed to attach_process(), and we can't modify
    //   the protocol without breaking compatibility
    // - 'input_file_path' is undefined if attach_process() but process_get_info()
    //   was not called (if debugger started from the command line with PID)
    switch ( event->eid )
    {
      case PROCESS_ATTACH:
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
        info("AUTOHIDE REGISTRY\n"
             "Successfully attached to the process.\n"
             "Now you can browse the process memory and set breakpoints.\n");
#endif
        // no break
      case PROCESS_START:
        event->modinfo.rebase_to = is_dll ? BADADDR : event->modinfo.base;
        break;

      case LIBRARY_LOAD:
        {
          char input_file_path[MAXSTR];
          get_input_file_path(input_file_path, sizeof(input_file_path));
          // we now compare on basenames, not fullpaths, because
          // databases attached to a moved DLL were not rebased properly,
          // causing problems like breakpoints at bad addresses, ...
          // TODO We should really display a warning for the users here,
          // if the loaded DLL path is different from the DLL path specified
          // in the database.
          if ( stricmp(qbasename(event->modinfo.name), qbasename(input_file_path)) == 0 )
            event->modinfo.rebase_to = event->modinfo.base;
          break;
        }
    }
  }
  return code;
}

//--------------------------------------------------------------------------
static void idaapi stopped_at_debug_event(bool dlls_added)
{
  if ( dlls_added )
    r_stopped_at_debug_event();
}

//--------------------------------------------------------------------------
#ifdef REMOTE_DEBUGGER
static int copy_to_remote(const char *lname, const char *rname)
{
  int code = 0;
  int fn = rpc_open_file(rname, NULL, false);
  if ( fn != -1 )
  {
    linput_t *li = open_linput(lname, false);
    if ( li != NULL )
    {
      size_t size = qlsize(li);
      if ( size > 0 )
      {
        char *buf = (char *)qalloc(size);
        qlread(li, buf, size);
        if ( rpc_write_file(fn, 0, buf, size) != size )
          code = qerrcode();
      }
      close_linput(li);
    }
    else
    {
      code = qerrcode();
    }
    rpc_close_file(fn);
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_LINUX_USER
    // chmod +x
    rpc_ioctl(0, rname, strlen(rname)+1, NULL, 0);
#endif
  }
  else
  {
    code = qerrcode();
  }
  return code;
}

//--------------------------------------------------------------------------
// ipath==input file path
static bool ask_user_and_copy(const char *ipath)
{
  // check if the input file exists at the current dir of the remote host
  const char *input_file = qbasename(ipath);
  int fn = -1;
  // try to open remote file in the current dir if not tried before
  if ( input_file != ipath )
    fn = rpc_open_file(input_file, NULL, true);
  if ( fn != -1 )
  {
    rpc_close_file(fn);
    switch ( askbuttons_c("~U~se found",
                          "~C~opy new",
                          "Cancel",
                          1,
                          "IDA could not find the remote file %s.\n"
                          "But it could find remote file %s.\n"
                          "Do you want to use the found file?",
                          ipath, input_file) )
    {
      case 1:
        set_root_filename(input_file);
        return true;
      case -1:
        return false;
    }
    // the user wants to overwrite the old file
  }
  else
  {
    if ( askyn_c(1, "HIDECANCEL\n"
                    "The remote file %s could not be found.\n"
                    "Do you want IDA to copy the executable to the remote computer?",
                    ipath) <= 0 )
      return false;
  }

  // We are to copy the input file to the remote computer's current directory
  const char *lname = ipath;
  // check if the file path is valid on the local system
  if ( !qfileexist(lname) )
  {
    lname = askfile_c(false, lname, "Please select the file to copy");
    if ( lname == NULL )
      return false;
  }
  const char *rname = qbasename(lname);
  int code = copy_to_remote(lname, rname);
  if ( code != 0 )
  {
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
    // Windows CE does not have errno and uses GetLastError()
    const char *err = winerr(code);
#else
    const char *err = qerrstr(code);
#endif
    warning("Failed to copy %s -> %s\n%s", lname, rname, err);
  }
  set_root_filename(rname);
  return true;
}
#endif

//--------------------------------------------------------------------------
static int idaapi process_get_info(int n, process_info_t *info)
{
  char input[MAXSTR];
  input[0] = '\0';
  if ( n == 0 && !is_temp_database() )
    get_input_file_path(input, sizeof(input));
  return r_process_get_info(n, input, info);
}

//--------------------------------------------------------------------------
static bool idaapi init_debugger(const char *hostname, int port_num, const char *password)
{
  if ( !open_remote(hostname, port_num, password) )
    return false;

  int code = r_init((debug & IDA_DEBUG_DEBUGGER) != 0);
  if ( code < 0 )   // network error
  {
    close_remote();
    return false;
  }
  debugger.process_get_info = (code & 1) ? process_get_info : NULL;
  debugger.detach_process   = (code & 2) ? r_detach_process : NULL;
  inited = true;
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  slot = BADADDR;
#endif
  return true;
}

//--------------------------------------------------------------------------
static bool idaapi term_debugger(void)
{
  if ( inited )
  {
    inited = false;
    return close_remote();
  }
  return false;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
  if ( init_plugin() )
  {
    dbg = &debugger;
    return PLUGIN_KEEP;
  }
  return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
  if ( inited )
    r_term();
}

//--------------------------------------------------------------------------
// The plugin method - is not used for debugger plugins
static void idaapi run(int /*arg*/)
{
#if 0 // DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  show_wince_rom();
#endif
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

debugger_t debugger =
{
  IDD_INTERFACE_VERSION,
  DEBUGGER_NAME,
  DEBUGGER_ID,
  PROCESSOR_NAME,
  DEBUGGER_FLAGS,

  register_classes,
  RC_GENERAL,
  registers,
  qnumber(registers),

  MEMORY_PAGE_SIZE,

  bpt_code,
  qnumber(bpt_code),

  init_debugger,
  term_debugger,

  NULL, // process_get_info: patched at runtime if ToolHelp functions are available
  start_process,
  r_attach_process,
  NULL, // detach_process:   patched at runtime if Windows XP/2K3
  rebase_if_required_to,
  r_prepare_to_pause_process,
  r_exit_process,

  get_debug_event,
  r_continue_after_event,
  r_set_exception_info,
  stopped_at_debug_event,

  r_thread_suspend,
  r_thread_continue,
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  NULL,
#else
  r_thread_set_step,
#endif
  thread_read_registers,
  thread_write_register,
  r_thread_get_sreg_base,

  r_get_memory_info,
  r_read_memory,
  r_write_memory,

  is_ok_bpt,
  add_bpt,
  r_del_bpt,
#ifdef REMOTE_DEBUGGER
  rpc_open_file,
  rpc_close_file,
  rpc_read_file,
#endif
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  local_pstos0,
#endif
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  PLUGIN_DBG, // plugin flags
#else
  PLUGIN_HIDE|PLUGIN_DBG, // plugin flags
#endif
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
#if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
  "Ctrl-F1",
#else
  ""                    // the preferred hotkey to run the plugin
#endif
};

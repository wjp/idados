#define REMOTE_DEBUGGER
#define RPC_CLIENT

char wanted_name[] = "Remote Dosbox debugger";
#define DEBUGGER_NAME  "dosbox"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_DOSBOX_EMULATOR
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE | DBG_FLAG_USE_SREGS
//#define HAVE_APPCALL

//////
#include "tcpip.h"
#include <ua.hpp>
#include <area.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include "rpc_client.h"
#include "rpc_debmod_dosbox.h"

rpc_debmod_dosbox_t g_dbgmod;
#include "common_stub_impl.cpp"

#define S_MAP_ADDRESS s_map_address

#include "pc_local_impl.cpp"
#include "dosbox_local_impl.cpp"
#include "common_local_impl.cpp"

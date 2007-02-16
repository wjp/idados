


#define REMOTE_DEBUGGER
#define DEBUGGER_CLIENT

char wanted_name[] = "Remote Linux DOSBox debugger";
#define DEBUGGER_NAME  "dos16"
#define PROCESSOR_NAME "metapc"
#define DEBUGGER_ID    37 
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE

#include "idarpc.cpp"
#include "pc_local.cpp"
#include "linux_local.cpp"
#include "common_local.cpp"


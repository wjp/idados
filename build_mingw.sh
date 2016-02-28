#!/usr/bin/env bash
IDA_SDK=../idasdk69

g++ -D__NT__ -D__IDP__ -DNO_OBSOLETE_FUNCS -DNDEBUG -D_SECURE_SCL=0 -fexceptions dosbox_rstub.cpp rpc_debmod_dosbox.cpp "$IDA_SDK/plugins/debugger/"{debmod,rpc_client,rpc_debmod,rpc_engine,rpc_hlp,tcpip,util}.cpp -Os "-I$IDA_SDK/include" "-I$IDA_SDK/plugins/debugger" -I. -static-libgcc -static-libstdc++ "-L$IDA_SDK/bin" -Wl,--dll,--enable-stdcall-fixup,--dynamicbase,--large-address-aware -lida -lws2_32 -shared -mwindows -odosbox_rstub.plw
if [ $? -eq 0 ]; then
    echo "Done! Next steps:"
    echo "1. Copy dosbox_rstub.plw to your IDA plugins directory"
    echo "2. Copy libwinpthread-1.dll from /mingw32/bin/libwinpthread-1.dll"
    echo "   to your IDA directory (NOT the plugins directory), or"
    echo "   add the MinGW bin directory (which contains libwinpthread-1.dll)"
    echo "   to your PATH."
fi

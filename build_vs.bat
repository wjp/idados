SET IDASDK=..\idasdk69

cl dosbox_rstub.cpp rpc_debmod_dosbox.cpp "%IDASDK%\plugins\debugger\tcpip.cpp" "%IDASDK%\plugins\debugger\rpc_client.cpp" "%IDASDK%\plugins\debugger\rpc_debmod.cpp" "%IDASDK%\plugins\debugger\debmod.cpp" "%IDASDK%\plugins\debugger\rpc_hlp.cpp" "%IDASDK%\plugins\debugger\rpc_engine.cpp" "%IDASDK%\plugins\debugger\util.cpp" /I"%IDASDK%\include" /I"%INCLUDE%" -I"%IDASDK%\plugins\debugger" /D__NT__ /D__VC__ /D__IDP__ /LD /GF /EHs /Gy /FC /Ox /Oi /DNDEBUG /D_SECURE_SCL=0 /MD /ERRORREPORT:QUEUE /Fedosbox_rstub.plw /link /LIBPATH:"%IDASDK%\lib\x86_win_vc_32\;%LIBPATH%" /DLL /LARGEADDRESSAWARE /DYNAMICBASE "%IDASDK%\lib\x86_win_vc_32\ida.lib"
@IF %ERRORLEVEL% NEQ 0 GOTO END
@ECHO.
@ECHO Done! Copy dosbox_rstub.plw to your IDA plugins directory
:END

CC=g++
CFLAGS=-DWIN32 -D__NT__ -D__IDP__ -I../../include -mrtd -mno-cygwin
LFLAGS=../../libgcc.w32/ida.a -Wl,--dll -shared -lwsock32 

all: test_debug.plw

deb_pc.cpp:
pc_local.cpp:
common_local.cpp:
win32_local.cpp:
idarpc.cpp:
idarpc.hpp:

test_debug.plw: win32_rstub.o tcpip.o
	$(CC) $(CFLAGS) -o $@ win32_rstub.o tcpip.o $(LFLAGS)

win32_rstub.o: win32_rstub.cpp deb_pc.cpp pc_local.cpp common_local.cpp win32_local.cpp idarpc.cpp idarpc.hpp
	$(CC) -c $(CFLAGS) -o $@ win32_rstub.cpp

tcpip.o: tcpip.cpp
	$(CC) -c $(CFLAGS) -o $@ tcpip.cpp

install: test_debug.plw
	cp test_debug.plw /cygdrive/c/Program\ Files/IDA/plugins

clean:
	rm test_debug.plw *.o

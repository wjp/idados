To build the plugin for linux:


export IDA=/path/to/idasdk55
export __LINUX__=1

Edit $IDA/plugins/debugger/tcpip.h, to change the definition of SOCKET
from int to intptr_t.

$(IDA)/bin/idamake.pl



To build dosbox:

./configure --enable-debug=ida32 --with-ida-sdk=$IDA --with-ida-plugin=/path/to/idaplugin

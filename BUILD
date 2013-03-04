To build the plugin for Linux:

export IDA=/path/to/idasdk64/
export __LINUX__=1
perl $IDA/bin/idamake.pl


To build the plugin for Mac OS X:

export IDA=/path/to/idasdk64/
export __MAC__=1
perl $IDA/bin/idamake.pl


To build dosbox on a 32-bit system:

./autogen.sh
./configure --enable-debug=ida32 --with-ida-sdk=$IDA --with-ida-plugin=/path/to/idaplugin


To build a 32-bit dosbox on a 64-bit Linux system:

./autogen.sh
CC="cc -m32" CXX="c++ -m32" ./configure --enable-debug=ida32 --with-ida-sdk=$IDA --with-ida-plugin=/path/to/idaplugin --host=i686-pc-linux-gnu


To build a 32-bit dosbox and plugin on a 64-bit Mac OS X system:
(The specific darwin release chosen shouldn't matter.)

./autogen.sh
CC="cc -m32" CXX="c++ -m32" ./configure --enable-debug=ida32 --with-ida-sdk=$IDA --with-ida-plugin=/path/to/idaplugin --host=i686-apple-darwin12

# General build instructions

In order to use IDA DOSBox debugger you need to build two things:

1. Client plugin for IDA (this repository)
2. Custom version of DOSBox which builds in the IDA debugger server ([other repository](https://github.com/wjp/dosbox))

The custom DOSBox build also requires some of the files in this repository, so you will pass the path to this repository in the `--with-ida-plugin` configure flag when compiling DOSBox. (It doesn’t matter which order they are built in.)

# IDADOS plugin

## Windows

### MSVC

1. Install Microsoft Compiler:
   * [Visual Studio](https://www.visualstudio.com/downloads/download-visual-studio-vs)
   * [Visual C++ for Python 2.7](http://www.microsoft.com/en-us/download/details.aspx?id=44266)
1. Set path to IDA SDK in `build_vs.bat`
1. Open the Visual C++ command line (or open a command line and run `vcvarsall.bat x86`)
1. Run `build_vs.bat` and follow its instructions

### MinGW-w64 (i686)

1. Install [msys2](http://repo.msys2.org/distrib/i686/msys2-i686-20160205.exe) and follow the setup instructions
1. Run `pacman -S mingw-w64-i686-toolchain` to install GCC
1. (optional) Run `pacman -S mingw-w64-i686-SDL` to install SDL if you also plan to compile DOSBox with MinGW
1. Set the path to IDA SDK in `build_mingw.sh`
1. Run `build_mingw.sh` and follow its instructions

**64-bit IDA/DOSBox:** Replace “i686” with “x86_64” in the instructions above.

## Linux

```
export IDA=/path/to/idasdk64/
export __LINUX__=1
perl $IDA/bin/idamake.pl
```

## Mac OS

```
export IDA=/path/to/idasdk64/
export __MAC__=1
perl $IDA/bin/idamake.pl
```

---

# DOSBox with IDA debugger support

First, make sure to copy/symlink your IDA library (Linux: `libida.so`, Mac: `libida.dylib`, Windows: `ida.wll`) to your `idasdk/bin` directory. **Windows users:** Rename ida.wll to ida.dll when you copy it! Then, follow the instructions for your platform below.

## 32-bit system (Windows with MinGW-w64 i686, Linux)

```
./autogen.sh
./configure --enable-debug=ida32 --with-ida-sdk=/full/path/to/idasdk --with-ida-plugin=/full/path/to/idados
make
```

**MinGW-w64 users:** You will need to change the `#if __GNUC__` surrounding the `memicmp` declaration in `idasdk/include/pro.h` to `#if 0` to compile successfully.

## 32-bit DOSBox on 64-bit Linux

```
./autogen.sh
CC="cc -m32" CXX="c++ -m32" ./configure --enable-debug=ida32 --with-ida-sdk=/full/path/to/idasdk --with-ida-plugin=/full/path/to/idados --host=i686-pc-linux-gnu
make
```

## 32-bit DOSBox on 64-bit Mac OS

(The specific darwin release chosen shouldn’t matter.)

```
./autogen.sh
CC="cc -m32" CXX="c++ -m32" ./configure --enable-debug=ida32 --with-ida-sdk=/full/path/to/idasdk --with-ida-plugin=/full/path/to/idados --host=i686-apple-darwin12
make
```

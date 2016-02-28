# IDA DOSBox debugger plugin

## Authors

* Eric Fry <efry@users.sourceforge.net>
* Willem Jan Palenstijn <wjp@usecode.org>

## Getting started

1. Download the IDA SDK.
1. Download the plugin source from https://github.com/wjp/idados.
1. Download the patched DOSBox source from the 'idados' branch of https://github.com/wjp/dosbox.
1. Build the plugin and DOSBox as described in the [BUILD.md](./BUILD.md) file.

## Usage

1. Load the executable you are debugging into IDA in the usual manner.
1. Configure DOSBox with `core=normal`.
1. Run DOSBox and mount disks, etc. in the usual manner.
1. In DOSBox, run the binary you want to debug, prefixed with `debug`.
   e.g. `debug sierra.exe`. DOSBox will pause here while waiting for a
   connection from IDA.
1. In IDA, start the debugger, selecting the "Remote DOSBox" debugger.
   You should be able to leave the connection options at their defaults.
   The binary and arguments are ignored.

## Notes

This plugin has not been tested on many platforms, but it has been reported to
work with 32-bit IDA 6.9 Starter, on 32-bit Windows (using [MSYS2](http://msys2.github.io/)),
64-bit Linux, and 64-bit Mac OS X.

The debugger plugin will rebase the program to match the memory location
in DOSBox, but there have been many bugs with this in older versions of IDA.
If this is causing problems, try manually rebasing before starting the debugger,
or even recreating the database at the right offset.

There is a known bug with breakpoints on the program entry point. As a
workaround, you can use the "Suspend on debugging start" option in IDA if you
wish to break on starting the process. Breakpoints at other locations should
work fine.

With a 32-bit IDA, you will have to build a 32-bit dosbox, even on 64-bit
platforms.

And finally, patches to improve the plugin are most welcome!

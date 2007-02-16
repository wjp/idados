#include <loader.hpp>

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
  if ( !netnode::inited() || is_miniidb() )
  {
#ifdef __LINUX__
    // local debugger is available if we are running under Linux
    return true;
#else
    // for other systems only the remote debugger is available
    return debugger.is_remote();
#endif
  }

  msg("ok\n");
  uchar buf[sizeof(ulong)+1];

  memset(buf,0, sizeof(ulong)+1);

  uchar *ptr = buf;
  ptr = pack_dd(ptr, buf + sizeof(buf), 127);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 128);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 129);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 256);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);

  memset(buf,0, sizeof(ulong)+1);
  ptr = pack_dd(buf, buf + sizeof(buf), 512);
  msg("buf = {%d,%d,%d,%d,%d} size=%d\n", buf[0], buf[1], buf[2], buf[3], buf[4], ptr-buf);


#if 0
  if ( inf.filetype != f_ELF ) return false; // only ELF files
  if ( ph.id != PLFM_386 ) return false; // only IBM PC
#endif

  is_dll = false; // FIXME!

  msg("ok\n");

  return true;
}

//--------------------------------------------------------------------------
char comment[] = "Userland linux debugger plugin.";

char help[] =
        "A sample Userland linux debugger plugin\n"
        "\n"
        "This module shows you how to create debugger plugins.\n";


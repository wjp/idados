#ifdef __NT__
#include <windows.h>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <kernwin.hpp>
#include <err.h>
#include "idarpc.hpp"

#ifdef __NT__
#  define qsend(socket, buf, size) sendto(socket, (const char*)buf, size, 0, NULL, 0)
#  define qrecv(socket, buf, size) recvfrom(socket, (char *)buf, size, 0, NULL, 0)
#  define get_network_error()      WSAGetLastError()
#  ifdef _MSC_VER
#    pragma comment(lib, "wsock32")
#  endif
#else   // not NT, i.e. UNIX
#  include <errno.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  define qsend(socket, buf, size) send(socket, buf, size, 0)
#  define qrecv(socket, buf, size) recv(socket, (char *)buf, size, 0)
#  define get_network_error()      errno
#  define closesocket(s)           close(s)
#  define SOCKET int
#  define INVALID_SOCKET (-1)
#  define SOCKET_ERROR   (-1)
#endif

//-------------------------------------------------------------------------
#if defined(__NT__)
void NT_CDECL term_sockets(void)
{
  WSACleanup();
}

//-------------------------------------------------------------------------
#ifdef __BORLANDC__
#pragma warn -8084 // Suggest parentheses to clarify precedence
#endif

bool init_irs_layer(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD( 2, 0 );

  err = WSAStartup( wVersionRequested, &wsaData );
  if ( err != 0 ) return false;

  atexit(term_sockets);

  /* Confirm that the WinSock DLL supports 2.0.*/
  /* Note that if the DLL supports versions greater    */
  /* than 2.0 in addition to 2.0, it will still return */
  /* 2.0 in wVersion since that is the version we      */
  /* requested.                                        */

  if ( LOBYTE( wsaData.wVersion ) != 2 ||
       HIBYTE( wsaData.wVersion ) != 0 )
    /* Tell the user that we couldn't find a usable */
    /* WinSock DLL.                                  */
    return false;

  /* The WinSock DLL is acceptable. Proceed. */
  return true;
}
#else
inline void term_sockets(void) {}
inline bool init_irs_layer(void) { return true; }
#endif

//-------------------------------------------------------------------------
void irs_term(idarpc_stream_t *irs)
{
  SOCKET s = (SOCKET)irs;
  closesocket(s);
  term_sockets();
}

//-------------------------------------------------------------------------
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n)
{
  SOCKET s = (SOCKET)irs;
  return qsend(s, buf, n);
}

//-------------------------------------------------------------------------
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n)
{
  SOCKET s = (SOCKET)irs;
  return qrecv(s, buf, n);
}

//-------------------------------------------------------------------------
int irs_error(idarpc_stream_t *)
{
  return get_network_error();
}

//-------------------------------------------------------------------------
int irs_ready(idarpc_stream_t *irs)
{
  SOCKET s = (SOCKET)irs;
  int milliseconds = TIMEOUT;
  int seconds = milliseconds / 1000;
  milliseconds %= 1000;
  struct timeval tv = { seconds, milliseconds * 1000 };
  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(s, &rd);
  return select(int(s+1),
         &rd, NULL,
         NULL,
         seconds != -1 ? &tv : NULL);
}

//--------------------------------------------------------------------------
void setup_irs(idarpc_stream_t *irs)
{
  SOCKET socket = (SOCKET)irs;
  /* Set socket options.  We try to make the port reusable and have it
	 close as fast as possible without waiting in unnecessary wait states
	 on close.
   */
  int on = 1;
  char *const ptr = (char *)&on;
  if ( setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, ptr, sizeof(on)) != 0 )
    neterr("setsockopt1");

  /* Enable TCP keep alive process. */
  if ( setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, ptr, sizeof(on)) != 0 )
    neterr("setsockopt2");

  /* Speed up the interactive response. */
  if ( setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, ptr, sizeof(on)) != 0 )
    neterr("setsockopt3");
}

//-------------------------------------------------------------------------
void term_server_irs(idarpc_stream_t *irs)
{
  SOCKET s = (SOCKET)irs;
  closesocket(s);
}

#ifndef DEBUGGER_SERVER
//-------------------------------------------------------------------------
void term_client_irs(idarpc_stream_t *irs)
{
  term_server_irs(irs);
  term_sockets();
}

//-------------------------------------------------------------------------
static in_addr name_to_addr(const char *name)
{
  in_addr addr;
  addr.s_addr = inet_addr(name);
  if ( addr.s_addr == INADDR_NONE )
  {
    struct hostent *he = gethostbyname(name);
    if ( he != NULL )
    {
#define INADDRSZ   4
//      warning("addrtype = %d addr=%08lX", he->h_addrtype, *(unsigned long*)he->h_addr);
      memcpy(&addr, he->h_addr, INADDRSZ);
      return addr;
    }
  }
  return addr;
}

//-------------------------------------------------------------------------
static bool name_to_sockaddr(const char *name, ushort port, sockaddr_in *sa)
{
  memset(sa, 0, sizeof(sockaddr_in));
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  sa->sin_addr = name_to_addr(name);
  return sa->sin_addr.s_addr != INADDR_NONE;
}

//-------------------------------------------------------------------------
idarpc_stream_t *init_client_irs(const char *hostname, int port_number)
{
  if ( hostname[0] == '\0' )
  {
    warning("AUTOHIDE NONE\n"
            "Please specify the hostname in Debugger, Process options");
    return NULL;
  }

  if ( !init_irs_layer() )
  {
    warning("AUTOHIDE NONE\n"
            "Could not initialize sockets: %s", winerr(get_network_error()));
    return NULL;
  }

  SOCKET rpc_socket = socket(AF_INET, SOCK_STREAM, 0);
  if ( rpc_socket == INVALID_SOCKET )
    neterr("socket");

  setup_irs((idarpc_stream_t*)rpc_socket);

  struct sockaddr_in sa;
  if ( !name_to_sockaddr(hostname, (ushort)port_number, &sa) )
  {
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Could not resolve %s: %s", hostname, winerr(get_network_error()));
    return NULL;
  }

  if ( connect(rpc_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
  {
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Could not connect to %s: %s", hostname, winerr(get_network_error()));
    return NULL;
  }
  return (idarpc_stream_t*)rpc_socket;
}

#endif


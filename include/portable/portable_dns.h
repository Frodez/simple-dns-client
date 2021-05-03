#ifndef PORTABLE_SYS_DNS_SERVER_H
#define PORTABLE_SYS_DNS_SERVER_H

#include "portable_platform.h"

#ifdef __WINDOWS__

#ifdef __MINGW64__

#include <resolv.h>

#elif (defined(_MSC_VER))

#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#endif

#else

#include <resolv.h>

#endif

#endif
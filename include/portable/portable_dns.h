#ifndef PORTABLE_DNS_H
#define PORTABLE_DNS_H

#include "portable_platform.h"

#ifdef __WINDOWS__

#ifdef __MINGW64__

#include <resolv.h>

#elif (defined(_MSC_VER))

#include <iphlpapi.h>
#include <winsock2.h>
#pragma comment(lib, "IPHLPAPI.lib")

#endif

#else

#include <resolv.h>

#endif

#endif
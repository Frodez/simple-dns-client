#ifndef PORTABLE_PLATFORM_H
#define PORTABLE_PLATFORM_H

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#define __WINDOWS__

#endif

#endif
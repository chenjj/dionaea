/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* "your bind can bind mapped ipv4 localhost to an ipv6 socket" */
/* #undef BIND_IPV4_MAPPED_LOCALHOST */

/* The directory for installing idiosyncratic read-only
   architecture-independent data. */
#define DATADIR "/opt/dionaea/share"

/* The root of the directory tree for read-only architecture-independent data
   files. */
#define DATAROOTDIR "/opt/dionaea/share"

/* enable debug code generation */
#define DEBUG 1

/* Define to 1 if you have the `bind' function. */
#define HAVE_BIND 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 to compile with cspm support */
/* #undef HAVE_LIBCSPM */

/* Define to 1 to compile with emu support */
#define HAVE_LIBEMU 1

/* Define to 1 to compile with ev support */
#define HAVE_LIBEV 1

/* Define to 1 to compile with gc support */
/* #undef HAVE_LIBGC */

/* Define to 1 to compile with lcfg support */
#define HAVE_LIBLCFG 1

/* Define to 1 to compile with netfilter_queue support */
/* #undef HAVE_LIBNETFILTER_QUEUE */

/* Define to 1 to compile with nl support */
/* #undef HAVE_LIBNL */

/* Define to 1 to compile with pcap support */
#define HAVE_LIBPCAP 1

/* Define to 1 to compile with ssl support */
#define HAVE_LIBSSL 1

/* Define to 1 to compile with udns support */
#define HAVE_LIBUDNS 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <netpacket/packet.h> header file. */
#define HAVE_NETPACKET_PACKET_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 to compile with xmatch support */
/* #undef HAVE_XMATCH */

/* where to look for plugins */
#define LIBDIR "/opt/dionaea/lib"

/* Number of args for rtnl_link_alloc_cache (new version) */
/* #undef LIBNL_RTNL_LINK_ALLOC_CACHE_ARGC */

/* where to put logs etc */
#define LOCALESTATEDIR "/opt/dionaea/var"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* don't enable debug code generation */
/* #undef NDEBUG */

/* I'm ... capacity instead of spoiler */
#define NPERFORMANCE 1

/* Name of package */
#define PACKAGE "dionaea"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "nepenthesdev@gmail.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "dionaea"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "dionaea 0.1.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "dionaea"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.1.0"

/* I'm looking for performance */
/* #undef PERFORMANCE */

/* default working directory */
#define PREFIX "/opt/dionaea"

/* path to the python interpreter */
#define PYTHON_PATH "/opt/dionaea/bin/python3.2"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* System configuration dir */
#define SYSCONFDIR "/opt/dionaea/etc"

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Version number of package */
#define VERSION "0.1.0"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

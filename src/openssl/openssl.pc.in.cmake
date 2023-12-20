prefix=@prefix@
exec_prefix=${prefix}
libdir=${exec_prefix}/@libdir@
includedir=${prefix}/@includedir@

Name: OpenSSL
Description: Secure Sockets Layer and cryptography libraries and tools
Version: @VERSION_STRING@
Libs: -L${libdir} -l@libssl@ -l@libcrypto@


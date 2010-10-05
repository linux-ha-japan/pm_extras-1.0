#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
#AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_INIT(pm_extras, 1.0)
AM_INIT_AUTOMAKE(pm_extras, 1.0)

# Checks for programs.

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
dnl Fix default variables - "prefix" variable if not specified
if test "$prefix" = "NONE"; then
        prefix="/usr"

        dnl Fix "localstatedir" variable if not specified
        if test "$localstatedir" = "\${prefix}/var"; then
                localstatedir="/var"
        fi
        dnl Fix "sysconfdir" variable if not specified
        if test "$sysconfdir" = "\${prefix}/etc"; then
                sysconfdir="/etc"
        fi
        dnl Fix "libdir" variable if not specified
        if test "$libdir" = "\${exec_prefix}/lib"; then
                if test -e /usr/lib64; then
                        libdir="/usr/lib64"
                else
                        libdir="/usr/lib"
                fi
        fi
fi

# Checks for library functions.

AC_CONFIG_FILES(Makefile	\
		resources/Makefile
		)
AC_OUTPUT

dnl *****************
dnl Configure summary
dnl *****************

eval prefix="`eval echo ${prefix}`"
eval exec_prefix="`eval echo ${prefix}`"
eval bindir="`eval echo ${bindir}`"
eval sbindir="`eval echo ${sbindir}`"
eval libexecdir="`eval echo ${libexecdir}`"
eval datadir="`eval echo ${datadir}`"
eval sysconfdir="`eval echo ${sysconfdir}`"
eval sharedstatedir="`eval echo ${sharedstatedir}`"
eval localstatedir="`eval echo ${localstatedir}`"
eval libdir="`eval echo ${libdir}`"
eval includedir="`eval echo ${includedir}`"
eval oldincludedir="`eval echo ${oldincludedir}`"
eval infodir="`eval echo ${infodir}`"
eval mandir="`eval echo ${mandir}`"

AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE configuration:])
AC_MSG_RESULT([  Version                  = ${VERSION}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([  AIS Plugins              = ${LCRSODIR}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  CFLAGS                   = ${CFLAGS}])


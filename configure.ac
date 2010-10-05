#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
#AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_INIT(pm_extras, 1.0)
AM_INIT_AUTOMAKE(pm_extras, 1.0)
AC_PROG_CC
AC_PROG_LIBTOOL

extract_header_define() {
          AC_MSG_CHECKING(for $2 in $1)
          Cfile=/tmp/extract_define.$2.${$}
          printf "#include <stdio.h>\n" > ${Cfile}.c
          printf "#include <%s>\n" $1 >> ${Cfile}.c
          printf "int main(int argc, char **argv) { printf(\"%%s\", %s); return 0; }\n" $2 >> ${Cfile}.c
          $CC $CFLAGS ${Cfile}.c -o ${Cfile}
          value=`${Cfile}`
          AC_MSG_RESULT($value)
          printf $value
          rm -f ${Cfile}.c ${Cfile}
        }

AC_ARG_WITH(ais,
    [  --with-ais
       Support the OpenAIS messaging and membership layer ],
    [ SUPPORT_AIS=$withval ],
    [ SUPPORT_AIS=try ],
)

AC_ARG_WITH(heartbeat,
    [  --with-heartbeat
       Support the Heartbeat messaging and membership layer ],
    [ SUPPORT_HEARTBEAT=$withval ],
    [ SUPPORT_HEARTBEAT=try ],
)

# Checks for programs.
AC_PATH_PROGS(PKGCONFIG, pkg-config)

# Checks for libraries.

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

dnl ========================================================================
dnl    Cluster stack - OpenAIS
dnl ========================================================================

AISLIB=""

dnl Normalize the values
case $SUPPORT_AIS in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *) SUPPORT_AIS=no;;
esac

AC_MSG_CHECKING(for native AIS)
AISMSGLIB=""
AIS_VERSION="none"
COROSYNC_PKG="$PKGCONFIG libcoroipcc"

if test $SUPPORT_AIS = no; then
   AC_MSG_RESULT(no... not requested.)

else
   AC_MSG_RESULT($SUPPORT_AIS, with '$AISPREFIX')

   AC_CHECK_HEADERS(openais/saAis.h)
   AC_CHECK_HEADERS(corosync/coroipcc.h)

   $COROSYNC_PKG --exists
   if test $? = 0; then
       AIS_VERSION="corosync"

   elif test "$ac_cv_header_openais_saAis_h" = "yes"; then
       AIS_VERSION="whitetank"
   else
       aisreason="Whitetank headers not found"
   fi  
fi

if test $AIS_VERSION != "none"; then
   AC_MSG_CHECKING(for OpenAIS branch)
   AC_MSG_RESULT($AIS_VERSION)
fi

if test $AIS_VERSION = "corosync"; then
   if test "$ac_cv_header_corosync_coroipcc_h" != "yes"; then
       AIS_VERSION="none"
       aisreason="Corosync headers not found"
   fi

   saveLIBS="$LIBS"
   LIBS="$LIBS `$COROSYNC_PKG --libs-only-L`"
   AC_CHECK_LIB(coroipcc, coroipcc_msg_send_reply_receive, [])
   LIBS="$saveLIBS"

   if test $ac_cv_lib_coroipcc_coroipcc_msg_send_reply_receive != yes; then
        AC_MSG_RESULT(Cannot locate AIS messaging library)
        aisreason="requred Corosync libraries not found"
        AIS_VERSION="none"
   fi

fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
   dnl Find it in lib, lib64, or wherever it wants to live...
   AC_MSG_CHECKING(location of OpenAIS libraries)
   dnl CoroSync location
   alib=`ls ${AISPREFIX}/*/libcpg.so | head -n 1`
   if test -z "$alib"; then
      dnl Whitetank location
      alib=`ls ${AISPREFIX}/*/*/libcpg.so | head -n 1`
   fi
   AISLIB=`dirname $alib`
   AC_MSG_RESULT($AISLIB)
   if test "x$AISLIB" = "x"; then
     AC_MSG_WARN(Use --with-ais-prefix to specify the prefix OpenAIS was installed with)
     aisreason="library directory not found"
     AIS_VERSION="none"

   elif test ! -d "$AISLIB"; then
     AC_MSG_WARN(Use --with-ais-prefix to specify the prefix OpenAIS was installed with)
     aisreason="specified library directory does not exist"
     AIS_VERSION="none"
   fi
fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
   AC_MSG_CHECKING(location of OpenAIS plugins)
   if test -z "$LCRSODIR"; then
      LCRSODIR="$libexecdir/lcrso"
      alib=`ls ${AISPREFIX}/*/lcrso/objdb.lcrso | head -n 1`
      LCRSODIR=`dirname $alib`
   fi
   AC_MSG_RESULT($LCRSODIR)

   if test "x$LCRSODIR" = "x"; then
     AC_MSG_RESULT(Invalid.  Please specify the correct location with --with-lcrso-dir)
     aisreason="plugin directory not found"
     AIS_VERSION="none"

   elif test ! -d "$LCRSODIR"; then
     AC_MSG_RESULT(Invalid.  Please specify the correct location with --with-lcrso-dir)
     aisreason="specified plugin directory does not exist"
     AIS_VERSION="none"
   fi
fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
     dnl Don't add the messaging library to LIBS since most daemons don't need/use it
     saveLIBS="$LIBS"
     LIBS="$LIBS -L${AISLIB} -R${AISLIB}"

     AC_CHECK_LIB(SaMsg, saSendReceiveReply, [])
     AC_CHECK_LIB(SaMsg, openais_msg_send_reply_receive, [])

     if test $ac_cv_lib_SaMsg_openais_msg_send_reply_receive = yes; then
       :  OpenAIS
     elif test $ac_cv_lib_SaMsg_saSendReceiveReply = yes; then
       :  OpenAIS
        AC_DEFINE_UNQUOTED(TRADITIONAL_AIS_IPC, 1, "Use the 'old' AIS IPC interface")
     else
        AC_MSG_RESULT(Cannot locate AIS messaging library)
        aisreason="requred libraries not found"
        AIS_VERSION="none"
     fi
     LIBS="$saveLIBS"
fi

SUPPORT_AIS=1
case $AIS_VERSION in
    corosync)
        AC_DEFINE_UNQUOTED(AIS_COROSYNC, 1, "AIS target is the corosync series")
        LCRSODIR=`$PKGCONFIG corosync --variable=lcrsodir`
        CFLAGS="$CFLAGS `$COROSYNC_PKG --cflags`"
        AISMSGLIB=`$COROSYNC_PKG --libs`
        ;;
    whitetank) 
        AC_DEFINE_UNQUOTED(AIS_WHITETANK, 1, "AIS target is the whitetank series")
        CFLAGS="$CFLAGS -I$AISPREFIX/include/openais"
        AISMSGLIB="-L${AISLIB} -R${AISLIB} -lSaMsg"
        ;;
    none)
        SUPPORT_AIS=0
        if test "x$aisreason" != x; then
          if test $missingisfatal = 0; then
            AC_MSG_WARN(Unable to support OpenAIS: $aisreason) 
          else
            AC_MSG_FAILURE(Unable to support OpenAIS: $aisreason) 
          fi
        fi
        ;;
    *) AC_MSG_FAILURE(Unknown OpenAIS branch: $AIS_VERSION);;
esac

AC_DEFINE_UNQUOTED(SUPPORT_AIS, $SUPPORT_AIS, Support the OpenAIS messaging and membership layer)
AM_CONDITIONAL(BUILD_AIS_SUPPORT, test $SUPPORT_AIS = 1)

dnl
dnl    Cluster stack - Sanity
dnl

STACKS=""
CLUSTERLIBS=""
if test $SUPPORT_HEARTBEAT = 1; then
   STACKS="$STACKS heartbeat"
   CLUSTERLIBS="$CLUSTERLIBS -lhbclient -lccmclient"
fi

if test $SUPPORT_AIS = 1; then
   STACKS="$STACKS $AIS_VERSION"
   CLUSTERLIBS="$CLUSTERLIBS ${AISMSGLIB}"
else
   AISPREFIX=""
   LCRSODIR="$libdir"
fi

PKG_FEATURES="$PKG_FEATURES$STACKS"

AC_MSG_CHECKING(for supported stacks)
if test x"$STACKS" = x; then
   AC_MSG_FAILURE(You must choose at least one cluster stack to support)
fi
AC_MSG_RESULT($STACKS)

AC_SUBST(CLUSTERLIBS)
AC_SUBST(LCRSODIR)

# Checks for header files.
CFLAGS="$CFLAGS -I${prefix}/include/heartbeat"

AC_CHECK_HEADERS(hb_config.h)
AC_CHECK_HEADERS(glue_config.h)
AC_CHECK_HEADERS(agent_config.h)

GLUE_HEADER=none
if test "$ac_cv_header_glue_config_h" = "yes"; then
   GLUE_HEADER=glue_config.h
elif test "$ac_cv_header_hb_config_h" = "yes"; then
   GLUE_HEADER=hb_config.h
else
   AC_MSG_FAILURE(Core development headers were not found)
fi

CRM_DAEMON_GROUP=`extract_header_define $GLUE_HEADER HA_APIGROUP`
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_GROUP)
CRM_DAEMON_USER=`extract_header_define $GLUE_HEADER HA_CCMUSER`
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_USER)

# Checks for library functions.

AC_CONFIG_FILES(Makefile	\
		resources/Makefile \
		tools/Makefile
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


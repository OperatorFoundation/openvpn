#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2006, David Shaw <dshaw@jabberwocky.com>
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
# LIBU2FHOST_CHECK_CONFIG ([DEFAULT-ACTION], [MINIMUM-VERSION],
#                       [ACTION-IF-YES], [ACTION-IF-NO])
# ----------------------------------------------------------
#      David Shaw <dshaw@jabberwocky.com>   May-09-2006
#
# Checks for libu2f-host.  DEFAULT-ACTION is the string yes or no to
# specify whether to default to --with-libu2f-host or --without-libu2f-host.
# If not supplied, DEFAULT-ACTION is yes.  MINIMUM-VERSION is the
# minimum version of libu2f-host to accept.  Pass the version as a regular
# version number like 7.10.1. If not supplied, any version is
# accepted.  ACTION-IF-YES is a list of shell commands to run if
# libu2f-host was successfully found and passed the various tests.
# ACTION-IF-NO is a list of shell commands that are run otherwise.
# Note that using --without-libu2f-host does run ACTION-IF-NO.
#
# This macro #defines HAVE_LIBU2FHOST if a working libu2f-host setup is
# found, and sets @LIBU2FHOST@ and @LIBU2FHOST_CPPFLAGS@ to the necessary
# values.
#
# Users may override the detected values by doing something like:
# LIBU2FHOST="-lu2f-host" LIBU2FHOST_CPPFLAGS="-I/usr/myinclude" ./configure

AC_DEFUN([LIBU2FHOST_CHECK_CONFIG],
[
  AC_ARG_WITH(libu2f-host,
     AS_HELP_STRING([--with-libu2f-host=PREFIX],[look for the u2f-host library in PREFIX/lib and headers in PREFIX/include]),
     [_libu2fhost_with=$withval],[_libu2fhost_with=ifelse([$1],,[yes],[$1])])

  if test "$_libu2fhost_with" != "no" ; then

     AC_PROG_AWK

     _libu2fhost_version_parse="eval $AWK '{split(\$NF,A,\".\"); X=256*256*A[[1]]+256*A[[2]]+A[[3]]; print X;}'"

     _libu2fhost_try_link=yes

     if test -d "$_libu2fhost_with" ; then
        LIBU2FHOST_CPPFLAGS="-I$withval/include"
        _libu2fhost_ldflags="-L$withval/lib"
        AC_PATH_PROG([_libu2fhost_config],[u2f-host],[],
                     ["$withval/bin"])
     else
        AC_PATH_PROG([_libu2fhost_config],[u2f-host],[],[$PATH])
     fi

     if test x$_libu2fhost_config != "x" ; then
        AC_CACHE_CHECK([for the version of libu2f-host],
           [libu2fhost_cv_lib_u2fhost_version],
           [libu2fhost_cv_lib_u2fhost_version=`$_libu2fhost_config --version | $AWK '{print $[]2}'`])

        _libu2fhost_version=`echo $libu2fhost_cv_lib_u2fhost_version | $_libu2fhost_version_parse`
        _libu2fhost_wanted=`echo ifelse([$2],,[0],[$2]) | $_libu2fhost_version_parse`

        if test $_libu2fhost_wanted -gt 0 ; then
           AC_CACHE_CHECK([for libu2fhost >= version $2],
              [libu2fhost_cv_lib_version_ok],
              [
              if test $_libu2fhost_version -ge $_libu2fhost_wanted ; then
                 libu2fhost_cv_lib_version_ok=yes
              else
                 libu2fhost_cv_lib_version_ok=no
              fi
              ])
        fi

        _libu2fhost_try_link=no

        unset _libu2fhost_wanted
     fi

     if test $_libu2fhost_try_link = yes ; then

        # we didn't find u2f-host, so let's see if the user-supplied
        # link line (or failing that, "-lu2f-host") is enough.
        LIBU2FHOST=${LIBU2FHOST-"$_libu2fhost_ldflags -lu2f-host"}

        AC_CACHE_CHECK([whether libu2fhost is usable],
           [libu2fhost_cv_lib_u2fhost_usable],
           [
           _libu2fhost_save_cppflags=$CPPFLAGS
           CPPFLAGS="$LIBU2FHOST_CPPFLAGS $CPPFLAGS"
           _libu2fhost_save_libs=$LIBS
           LIBS="$LIBU2FHOST $LIBS"

           AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <u2f-host/u2f-host.h>]],[[
/* Try and use a few common options to force a failure if we are
   missing symbols or can't link. */
int x;
x=U2FH_VERSION_NUMBER;
if (x) {;}
]])],libu2fhost_cv_lib_u2fhost_usable=yes,libu2fhost_cv_lib_u2fhost_usable=no)

           CPPFLAGS=$_libu2fhost_save_cppflags
           LIBS=$_libu2fhost_save_libs
           unset _libu2fhost_save_cppflags
           unset _libu2fhost_save_libs
           ])

        if test $libu2fhost_cv_lib_u2fhost_usable = yes ; then

           _libu2fhost_save_cppflags=$CPPFLAGS
           CPPFLAGS="$CPPFLAGS $LIBU2FHOST_CPPFLAGS"
           _libu2fhost_save_libs=$LIBS
           LIBS="$LIBS $LIBU2FHOST"

           CPPFLAGS=$_libu2fhost_save_cppflags
           LIBS=$_libu2fhost_save_libs
           unset _libu2fhost_save_cppflags
           unset _libu2fhost_save_libs

           AC_DEFINE(HAVE_LIBU2FHOST,1,
             [Define to 1 if you have a functional u2f-host library.])
           AC_SUBST(LIBU2FHOST_CPPFLAGS)
           AC_SUBST(LIBU2FHOST)
        else
           unset LIBU2FHOST
           unset LIBU2FHOST_CPPFLAGS
        fi
     fi

     unset _libu2fhost_try_link
     unset _libu2fhost_version_parse
     unset _libu2fhost_config
     unset _libu2fhost_version
     unset _libu2fhost_ldflags
  fi

  if test x$_libu2fhost_with = xno || test x$libu2fhost_cv_lib_u2fhost_usable != xyes ; then
     # This is the IF-NO path
     ifelse([$4],,:,[$4])
  else
     # This is the IF-YES path
     ifelse([$3],,:,[$3])
  fi

  unset _libu2fhost_with
])dnl

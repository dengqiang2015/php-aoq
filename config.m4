dnl $Id$
dnl config.m4 for extension aoq

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(aoq, for aoq support,
dnl Make sure that the comment is aligned:
dnl [  --with-aoq             Include aoq support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(aoq, whether to enable aoq support,
dnl Make sure that the comment is aligned:
[  --enable-aoq           Enable aoq support])

if test "$PHP_AOQ" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-aoq -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/aoq.h"  # you most likely want to change this
  dnl if test -r $PHP_AOQ/$SEARCH_FOR; then # path given as parameter
  dnl   AOQ_DIR=$PHP_AOQ
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for aoq files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       AOQ_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$AOQ_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the aoq distribution])
  dnl fi

  dnl # --with-aoq -> add include path
  dnl PHP_ADD_INCLUDE($AOQ_DIR/include)

  dnl # --with-aoq -> check for lib and symbol presence
  dnl LIBNAME=aoq # you may want to change this
  dnl LIBSYMBOL=aoq # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $AOQ_DIR/lib, AOQ_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_AOQLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong aoq lib version or lib not found])
  dnl ],[
  dnl   -L$AOQ_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(AOQ_SHARED_LIBADD)

  PHP_NEW_EXTENSION(aoq, aoq.c, $ext_shared)
fi

if test -z "$PHP_DEBUG"; then
        AC_ARG_ENABLE(debug,
                [--enable-debg  compile with debugging system],
                [PHP_DEBUG=$enableval], [PHP_DEBUG=no]
        )
fi

/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Dengqiang<962404383@qq.com>                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_AOQ_H
#define PHP_AOQ_H
#endif


#define PHP_AOQ_VERSION "1.0.0" /* Replace with version number for your extension */
#define PHP_AOQ_AUTHOR "dengqiang"
#define PHP_AOQ_AUTHOR_EMAIL "962404383@qq.com"
#define PHP_AOQ_HOST "0.0.0.0"
#define PHP_AOQ_PORT 5211
#define PHP_AOQ_TIMEOUT 30
#define PHP_AOQ_READ_TIMEOUT 1 //sec
#define PHP_AOQ_TCP_NODELAY 1 //tcp no delay
#define AOQ_SOCK_STATUS_CONNECTED 1
#define AOQ_SOCK_STATUS_DISCONNECTED -1

#ifdef PHP_WIN32
#   define PHP_AOQ_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_AOQ_API __attribute__ ((visibility("default")))
#else
#   define PHP_AOQ_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif


#undef ZVAL_STRING
#define ZVAL_STRING(z, s, duplicate) do { \
    const char *_s=(s); \
    ZVAL_STRINGL(z, _s, strlen(_s), duplicate); \
} while (0)
#undef RETVAL_STRING
#define RETVAL_STRING(s, duplicate) ZVAL_STRING(return_value, s, duplicate)
#undef RETURN_STRING
#define RETURN_STRING(s, duplicate) { RETVAL_STRING(s, duplicate); return; }
#undef ZVAL_STRINGL
#define ZVAL_STRINGL(z, s, l, duplicate) do { \
     const char *__s=(s); int __l=l;            \
    zval *__z = (z);                        \
    Z_STRLEN_P(__z) = __l;                  \
    Z_STRVAL_P(__z) = (duplicate?estrndup(__s, __l):(char*)__s);\
    Z_TYPE_P(__z) = IS_STRING;\
} while(0)
#undef RETVAL_STRINGL
#define RETVAL_STRINGL(s, l, duplicate) ZVAL_STRINGL(return_value, s, l, duplicate)
#undef RETURN_STRINGL
#define RETURN_STRINGL(s, l, duplicate) { RETVAL_STRINGL(s, l, duplicate); return; }

#undef PHP_STREAM_BUFFER_NONE
#define PHP_STREAM_BUFFER_NONE	0	/* unbuffered */
#undef PHP_STREAM_BUFFER_FULL
#define PHP_STREAM_BUFFER_FULL	2	/* fully buffered */

/* {{{ struct int */
typedef struct {
    php_stream     *stream;
    char           *host;
    short          port;
    double         timeout;
    double         read_timeout;
    int            retry_times;
    int            failed;
    int            status;
    int            persistent;
    char           *persistent_id;
    char           *sock_err;
    int            sock_errno;
} AoqSock;
/* }}} */


#if (PHP_MAJOR_VERSION < 7)
typedef struct {
    zend_object std;
    AoqSock *sock;
} aoq_object;
#else
typedef struct {
    AoqSock *sock;
    zend_object std;
} aoq_object;
#endif

PHP_AOQ_API zend_class_entry * aoq_get_exception_base(TSRMLS_D);
void parse_head_len(char *buf, int *head_len);
void parse_argvlen(char *buf, int head_len, int *reslen);
char * parse_argv(char *buf, int head_len, int *reslen);
PHP_AOQ_API AoqSock * aoq_sock_create(char *host, int host_len, unsigned short port, double timeout, double read_timeout, int persistent, char *persistent_id, int retry_times TSRMLS_DC);
PHP_AOQ_API int aoq_sock_connect(AoqSock *aoq_sock TSRMLS_DC);
PHP_AOQ_API int aoq_sock_server_open(AoqSock *aoq_sock TSRMLS_DC);
PHP_AOQ_API int aoq_sock_write_cmd(AoqSock *aoq_sock, char *cmd, size_t sz TSRMLS_DC);
PHP_AOQ_API char * aoq_sock_read_reply(AoqSock *aoq_sock, int *buf_len TSRMLS_DC);
PHP_AOQ_API int aoq_sock_disconnect(AoqSock *aoq_sock TSRMLS_DC);
PHP_AOQ_API void aoq_free_socket(AoqSock *aoq_sock);
PHP_AOQ_API char * aoq_status(AoqSock *aoq_sock, int *reslen TSRMLS_DC);
PHP_AOQ_API int aoq_push(AoqSock *aoq_sock, char *qname, int qname_len, char *qval ,int qval_len TSRMLS_DC);
PHP_AOQ_API char * aoq_pop(AoqSock *aoq_sock, char *qname, int qname_len, int *reslen TSRMLS_DC);
PHP_AOQ_API char *aoq_queues(AoqSock *aoq_sock, int *reslen TSRMLS_DC);
PHP_AOQ_API char *aoq_queue(AoqSock *aoq_sock, char *qname, int qname_len, int *reslen TSRMLS_DC);
PHP_AOQ_API int aoq_delqueue(AoqSock *aoq_sock, char *qname, int qname_len TSRMLS_DC);
PHP_AOQ_API AoqSock * aoq_sock_get(zval *id TSRMLS_DC, int no_throw);
PHP_AOQ_API int aoq_connect(INTERNAL_FUNCTION_PARAMETERS, int persistent);
PHP_AOQ_API AoqSock *aoq_sock_get_connected(INTERNAL_FUNCTION_PARAMETERS);


PHP_MINIT_FUNCTION(aoq);
PHP_MSHUTDOWN_FUNCTION(aoq);
PHP_RINIT_FUNCTION(aoq);
PHP_RSHUTDOWN_FUNCTION(aoq);
PHP_MINFO_FUNCTION(aoq);

PHP_FUNCTION(confirm_aoq_compiled); /* For testing, remove later. */
PHP_METHOD(Aoq, __construct);
PHP_METHOD(Aoq, __destruct);
PHP_METHOD(Aoq, connect);
PHP_METHOD(Aoq, pconnect);
PHP_METHOD(Aoq, set_chunk_size);
PHP_METHOD(Aoq, set_read_buffer);
PHP_METHOD(Aoq, set_write_buffer);
PHP_METHOD(Aoq, status);    
PHP_METHOD(Aoq, push);
PHP_METHOD(Aoq, pop);   
PHP_METHOD(Aoq, queues);    
PHP_METHOD(Aoq, queue); 
PHP_METHOD(Aoq, delqueue);
PHP_METHOD(Aoq, disconnect);


#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(aoq);
PHP_MSHUTDOWN_FUNCTION(aoq);
PHP_MINFO_FUNCTION(aoq);

PHP_AOQ_API int aoq_connect(INTERNAL_FUNCTION_PARAMETERS, int persistent);

#ifndef _MSC_VER
ZEND_BEGIN_MODULE_GLOBALS(aoq)
ZEND_END_MODULE_GLOBALS(aoq)
#endif

extern zend_module_entry aoq_module_entry;

#define aoq_module_ptr &aoq_module_entry
#define phpext_aoq_ptr aoq_module_ptr

/* 
    Declare any global variables you may need between the BEGIN
    and END macros here:     

ZEND_BEGIN_MODULE_GLOBALS(aoq)
    long  global_value;
    char *global_string;
ZEND_END_MODULE_GLOBALS(aoq)
*/

/* In every utility function you add that needs to use variables 
   in php_aoq_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as AOQ_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define AOQ_G(v) TSRMG(aoq_globals_id, zend_aoq_globals *, v)
#else
#define AOQ_G(v) (aoq_globals.v)
#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

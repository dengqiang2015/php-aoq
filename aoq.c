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
  | Author:  Dengqiang<962404383@qq.com>                                 |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_aoq.h"
#include <zend_exceptions.h>
#ifdef PHP_SESSION
#include "ext/session/php_session.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_math.h>
#if (PHP_MAJOR_VERSION < 7)
#include <ext/standard/php_smart_str.h>
#endif
#include "php_network.h"
#include <sys/types.h>
#include <netinet/tcp.h>  /* TCP_NODELAY */
#include <sys/socket.h>
#include <ext/standard/php_rand.h>


#ifdef PHP_SESSION
extern ps_module ps_mod_aoq;
#endif


zend_class_entry *aoq_ce;
zend_class_entry *aoq_exception_ce;
zend_class_entry *runtime_exception_ce;


#if (PHP_MAJOR_VERSION < 7)
void free_aoq_object(void *object TSRMLS_DC)
{
    aoq_object *aoq = (aoq_object *)object;

    zend_object_std_dtor(&aoq->std TSRMLS_CC);

    if (aoq->sock){
		aoq_sock_disconnect(aoq->sock TSRMLS_CC);
        aoq_free_socket(aoq->sock);
    }
    efree(aoq);
}

zend_object_value create_aoq_object(zend_class_entry *ce TSRMLS_DC)
{
    zend_object_value retval;
    aoq_object *aoq = ecalloc(1, sizeof(aoq_object));

    memset(aoq, 0, sizeof(aoq_object));
    zend_object_std_init(&aoq->std, ce TSRMLS_CC);

#if PHP_VERSION_ID < 50399
    zval *tmp;
    zend_hash_copy(aoq->std.properties, &ce->default_properties,
        (copy_ctor_func_t)zval_add_ref, (void *)&tmp, sizeof(zval *));
#endif

    retval.handle = zend_objects_store_put(aoq,
        (zend_objects_store_dtor_t)zend_objects_destroy_object,
        (zend_objects_free_object_storage_t)free_aoq_object,
        NULL TSRMLS_CC);
    retval.handlers = zend_get_std_object_handlers();

    return retval;
}
#else
zend_object_handlers aoq_object_handlers;

void free_aoq_object(zend_object *object)
{
    aoq_object *aoq = (aoq_object *)((char *)(object) - XtOffsetOf(aoq_object, std));

    zend_object_std_dtor(&aoq->std TSRMLS_CC);
    if (aoq->sock) {
        aoq_sock_disconnect(aoq->sock TSRMLS_CC);
        aoq_free_socket(aoq->sock TSRMLS_CC);
    }
}

zend_object * create_aoq_object(zend_class_entry *ce TSRMLS_DC)
{
    aoq_object *aoq = ecalloc(1, sizeof(aoq_object) + zend_object_properties_size(ce));

    aoq->sock = NULL;

    zend_object_std_init(&aoq->std, ce TSRMLS_CC);
    object_properties_init(&aoq->std, ce);

    memcpy(&aoq_object_handlers, zend_get_std_object_handlers(), sizeof(aoq_object_handlers));
    aoq_object_handlers.offset = XtOffsetOf(aoq_object, std);
    aoq_object_handlers.free_obj = free_aoq_object;
    aoq->std.handlers = &aoq_object_handlers;

    return &aoq->std;
}
#endif



/* If you declare any globals in php_aoq.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(aoq)
*/

/* True global resources - no need for thread safety here */

/* Argument info for any function expecting 0 args */
ZEND_BEGIN_ARG_INFO_EX(arginfo_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_connect, 0, 0, 2)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, retry_times)
    ZEND_ARG_INFO(0, read_timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pconnect, 0, 0, 2)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_set_chunk_size, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_set_read_buffer, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_set_write_buffer, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_push, 2)
    ZEND_ARG_INFO(0, qname)
    ZEND_ARG_INFO(0, qval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_pop, 1)
    ZEND_ARG_INFO(0, qname)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_queue, 1)
    ZEND_ARG_INFO(0, qname)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_delqueue, 1)
    ZEND_ARG_INFO(0, qname)
ZEND_END_ARG_INFO()

#ifdef ZTS
ZEND_DECLARE_MODULE_GLOBALS(aoq)
#endif

static zend_function_entry aoq_functions[] = {
    PHP_ME(Aoq, __construct , arginfo_void, ZEND_ACC_CTOR | ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, __destruct , arginfo_void, ZEND_ACC_DTOR | ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, connect , arginfo_connect , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, pconnect , arginfo_pconnect , ZEND_ACC_PUBLIC)
	PHP_ME(Aoq, set_chunk_size  , arginfo_set_chunk_size , ZEND_ACC_PUBLIC)
	PHP_ME(Aoq, set_read_buffer  , arginfo_set_read_buffer , ZEND_ACC_PUBLIC)
	PHP_ME(Aoq, set_write_buffer  , arginfo_set_write_buffer , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, status  , arginfo_void , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, push  , arginfo_push , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, pop  , arginfo_pop , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, queues  , arginfo_void , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, queue  , arginfo_queue , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, delqueue  , arginfo_delqueue , ZEND_ACC_PUBLIC)
    PHP_ME(Aoq, disconnect , arginfo_void, ZEND_ACC_PUBLIC)
    PHP_MALIAS(Aoq, open, connect, arginfo_connect, ZEND_ACC_PUBLIC)
    PHP_MALIAS(Aoq, popen, pconnect, arginfo_pconnect, ZEND_ACC_PUBLIC)
    PHP_MALIAS(Aoq, close, disconnect, arginfo_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};



/* {{{ aoq_module_entry
 */
zend_module_entry aoq_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
     STANDARD_MODULE_HEADER,
#endif
    "aoq",
    NULL,
    PHP_MINIT(aoq),
    PHP_MSHUTDOWN(aoq),
    NULL,       /* Replace with NULL if there's nothing to do at request start */
    NULL,   /* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(aoq),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_AOQ_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
/* }}} */

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("aoq.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_aoq_globals, aoq_globals)
    STD_PHP_INI_ENTRY("aoq.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_aoq_globals, aoq_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_aoq_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_aoq_init_globals(zend_aoq_globals *aoq_globals)
{
    aoq_globals->global_value = 0;
    aoq_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
#ifdef COMPILE_DL_AOQ
ZEND_GET_MODULE(aoq)
#endif


PHP_MINIT_FUNCTION(aoq)
{
    /* If you have INI entries, uncomment these lines 
    REGISTER_INI_ENTRIES();
    */
    zend_class_entry aoq_class_entry;
    zend_class_entry aoq_exception_class_entry;
    /* Aoq class */
    INIT_CLASS_ENTRY(aoq_class_entry, "Aoq", aoq_functions);
    aoq_ce = zend_register_internal_class(&aoq_class_entry TSRMLS_CC);
    aoq_ce->create_object = create_aoq_object;
    
     /* AoqException class */
    INIT_CLASS_ENTRY(aoq_exception_class_entry, "AoqException", NULL);
    aoq_exception_ce = zend_register_internal_class_ex(
        &aoq_exception_class_entry,
#if (PHP_MAJOR_VERSION < 7)
        aoq_get_exception_base(TSRMLS_C),
        NULL TSRMLS_CC
#else
        aoq_get_exception_base(TSRMLS_C)
#endif
    );

#ifdef PHP_SESSION
    php_session_register_module(&ps_mod_aoq);
#endif
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(aoq)
{
    /* uncomment this line if you have INI entries
    UNREGISTER_INI_ENTRIES();
    */
    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(aoq)
{
    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(aoq)
{
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(aoq)
{
    char default_port[6] = {'\0'};
    char default_read_timeout[6] = {'\0'};
    char default_write_timeout[6] = {'\0'};
    char default_timeout[6] = {'\0'};
    char default_read_buffer_size[6] = {'\0'};
    char default_write_buffer_size[6] = {'\0'};
    char default_tcp_nodelay[2]={'\0'};
    sprintf(default_port, "%d", PHP_AOQ_PORT);
    sprintf(default_read_timeout, "%d", PHP_AOQ_READ_TIMEOUT);
    sprintf(default_timeout, "%d", PHP_AOQ_TIMEOUT);
    sprintf(default_tcp_nodelay, "%d", PHP_AOQ_TCP_NODELAY);
    
    php_info_print_table_start();
    php_info_print_table_header(2, "aoq support", "enabled");
    php_info_print_table_row(2, "version", PHP_AOQ_VERSION);
    php_info_print_table_row(2, "author", PHP_AOQ_AUTHOR);
    php_info_print_table_row(2, "email", PHP_AOQ_AUTHOR_EMAIL);
    php_info_print_table_row(2, "default host", PHP_AOQ_HOST);
    php_info_print_table_row(2, "default port", (const char *)default_port);
    php_info_print_table_row(2, "default timeout", (const char *)default_timeout);
    php_info_print_table_row(2, "default read timeout", (const char *)default_read_timeout);
    php_info_print_table_row(2, "default tcp no delay", (const char *)default_tcp_nodelay);
    php_info_print_table_end();

    /* Remove comments if you have entries in php.ini
    DISPLAY_INI_ENTRIES();
    */
}
/* }}} */



static zend_always_inline void *
zend_hash_str_find_ptr(const HashTable *ht, const char *str, size_t len)
{
    void **ptr;

    if (zend_hash_find(ht, str, len + 1, (void **)&ptr) == SUCCESS) {
        return *ptr;
    }
    return NULL;
}

PHP_AOQ_API zend_class_entry * aoq_get_exception_base(TSRMLS_D)
{
    if (runtime_exception_ce == NULL) {
#if HAVE_SPL
        runtime_exception_ce = zend_hash_str_find_ptr(CG(class_table), "RuntimeException", sizeof("RuntimeException") - 1);
#else
    #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 2)
        runtime_exception_ce = zend_exception_get_default();
    #else
        runtime_exception_ce = zend_exception_get_default(TSRMLS_C);
    #endif
#endif
    }
    return runtime_exception_ce;
}


PHP_AOQ_API void parse_head_len(char *buf, int *head_len)
{
    char *head_len_str = (char *)emalloc(2*sizeof(char));
    memcpy(head_len_str, buf, 2);
    *head_len = atoi(head_len_str);
    efree(head_len_str);
}

PHP_AOQ_API void parse_argvlen(char *buf, int head_len, int *reslen)
{
    char reslen_str[7] = {'\0'};
    memcpy(reslen_str, buf+4, 6);
    *reslen = atoi(reslen_str);
}

PHP_AOQ_API char * parse_argv(char *buf, int head_len, int *reslen)
{
    char *argv_str = (char *)emalloc((*reslen+1)*sizeof(char));
    memcpy(argv_str, buf+head_len, *reslen);
    *(argv_str+(*reslen)) = '\0';
    return argv_str;
}

/**
 * aoq_sock_create
 */
PHP_AOQ_API AoqSock * aoq_sock_create(char *host, int host_len, unsigned short port, double timeout, double read_timeout, int persistent, char *persistent_id, int retry_times)
{
    AoqSock *aoq_sock;

    aoq_sock         = ecalloc(1, sizeof(AoqSock));
    aoq_sock->host   = estrndup(host, host_len);
    aoq_sock->stream = NULL;
    aoq_sock->status = AOQ_SOCK_STATUS_DISCONNECTED;
    aoq_sock->retry_times = retry_times;
    aoq_sock->persistent = persistent;
    aoq_sock->persistent_id = NULL;

    if(persistent_id) {
        aoq_sock->persistent_id = estrdup(persistent_id);
    }

    aoq_sock->port    = port;
    aoq_sock->timeout = timeout > 0 ? timeout : PHP_AOQ_TIMEOUT;
    aoq_sock->read_timeout = read_timeout > 0 ? read_timeout : PHP_AOQ_READ_TIMEOUT;
    aoq_sock->sock_err = NULL;
    aoq_sock->sock_errno = 0;

    return aoq_sock;
}


/**
 * aoq_sock_connect
 */
PHP_AOQ_API int aoq_sock_connect(AoqSock *aoq_sock TSRMLS_DC)
{
    struct timeval tv, read_tv, *tv_ptr = NULL;
    char host[1024], *persistent_id = NULL;
    const char *fmtstr = "%s:%d";
    int host_len;
    php_netstream_data_t *sock;
    int tcp_flag = 1;
    int retry_times = 0;

    if (aoq_sock->stream != NULL) {
        aoq_sock_disconnect(aoq_sock TSRMLS_CC);
    }

    tv.tv_sec  = (time_t)aoq_sock->timeout;
    tv.tv_usec = (int)((aoq_sock->timeout - tv.tv_sec) * 1000000);
    if(tv.tv_sec != 0 || tv.tv_usec != 0) {
        tv_ptr = &tv;
    }

    read_tv.tv_sec  = (time_t)aoq_sock->read_timeout;
    read_tv.tv_usec = (int)((aoq_sock->read_timeout-read_tv.tv_sec)*1000000);

    if(aoq_sock->host[0] == '/' && aoq_sock->port < 1) {
        host_len = snprintf(host, sizeof(host), "unix://%s", aoq_sock->host);
    } else {
        if(aoq_sock->port == 0)
            aoq_sock->port = PHP_AOQ_PORT;

#ifdef HAVE_IPV6
        /* If we've got IPv6 and find a colon in our address, convert to proper
         * IPv6 [host]:port format */
        if (strchr(aoq_sock->host, ':') != NULL) {
            fmtstr = "[%s]:%d";
        }
#endif
        host_len = snprintf(host, sizeof(host), fmtstr, aoq_sock->host, aoq_sock->port);
    }

    if (aoq_sock->persistent) {
        if (aoq_sock->persistent_id) {
            spprintf(&persistent_id, 0, "phpaoq:%s:%s", host, aoq_sock->persistent_id);
        } else {
            spprintf(&persistent_id, 0, "phpaoq:%s:%f", host, aoq_sock->timeout);
        }
    }


    aoq_sock->stream = php_stream_xport_create(host, host_len, 0, STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT, persistent_id, tv_ptr, NULL, &(aoq_sock->sock_err), &(aoq_sock->sock_errno));

    while( !aoq_sock->stream && retry_times < aoq_sock->retry_times)
    {
        aoq_sock->stream = php_stream_xport_create(host, host_len,0, STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT, persistent_id, tv_ptr, NULL, &(aoq_sock->sock_err), &(aoq_sock->sock_errno));
        retry_times++;
        sleep(1);
    }
    
    if (persistent_id) {
        efree(persistent_id);
    }

    if (!aoq_sock->stream) {
        return -1;
    }

    /* set TCP_NODELAY */
    sock = (php_netstream_data_t*)aoq_sock->stream->abstract;
    if (PHP_AOQ_TCP_NODELAY && setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *) &tcp_flag, sizeof(int)) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Can't activate TCP_NODELAY option!");
    }

    php_stream_auto_cleanup(aoq_sock->stream);

    if (read_tv.tv_sec != 0 || read_tv.tv_usec != 0) {
        php_stream_set_option(aoq_sock->stream,PHP_STREAM_OPTION_READ_TIMEOUT, 0, &read_tv);
    }
    php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);

    aoq_sock->status = AOQ_SOCK_STATUS_CONNECTED;

    return 0;
}

/**
 * aoq_sock_server_open
 */
PHP_AOQ_API int aoq_sock_server_open(AoqSock *aoq_sock TSRMLS_DC)
{
    int res = -1;

    switch (aoq_sock->status) {
        case AOQ_SOCK_STATUS_DISCONNECTED:
            return aoq_sock_connect(aoq_sock TSRMLS_CC);
        case AOQ_SOCK_STATUS_CONNECTED:
            res = 0;
        break;
    }

    return res;
}

/**
 * aoq_sock_write_aoq_cmd
 */
PHP_AOQ_API int aoq_sock_write_aoq_cmd(AoqSock *aoq_sock, char *aoq_cmd, size_t sz TSRMLS_DC)
{
    if (!aoq_sock || aoq_sock->status == AOQ_SOCK_STATUS_DISCONNECTED) {
        zend_throw_exception(aoq_exception_ce, "Connection closed", 0 TSRMLS_CC);
    } else if (!php_stream_eof(aoq_sock->stream) && php_stream_write(aoq_sock->stream, aoq_cmd, sz) == sz
    ) {
        return sz;
    }
    return -1;
}


/**
 * aoq_sock_read_reply
 */
PHP_AOQ_API char * aoq_sock_read_reply(AoqSock *aoq_sock, int *buf_len TSRMLS_DC)
{
    size_t readlen = 0;
    size_t buflen = 8192;
    size_t malloc_size = buflen;
    char *buf = (char *)emalloc(buflen*sizeof(char));
    char *b = buf;
    if (!aoq_sock || aoq_sock->status == AOQ_SOCK_STATUS_DISCONNECTED) {
        efree(buf);
        b = NULL;
        zend_throw_exception(aoq_exception_ce, "Connection closed", 0 TSRMLS_CC);
    }

    
    while (1) {
        readlen = php_stream_read(aoq_sock->stream, b, buflen);
        *buf_len += readlen;
        if (*(b+readlen-1) != '\n' && !php_stream_eof(aoq_sock->stream)) {
            if ((malloc_size-(*buf_len)) < buflen) {
                buf = erealloc(buf, *buf_len+buflen);
                b = buf+(*buf_len);
                malloc_size += buflen;
            } 
            continue;
        }
        *(b+(*buf_len)-1) = '\0';
        break;
   }

   return buf;
}



PHP_AOQ_API char * aoq_status(AoqSock *aoq_sock, int *reslen TSRMLS_DC)
{
    char aoq_cmd[7] = {'\0'};
    
    int head_len= 0;
    int buf_len = 0;
    char *buf = NULL;
    char *result = (char *)"";
    
    memcpy(aoq_cmd, "0501 \n", 6);
    
    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, 6 TSRMLS_CC) > 0)
    {
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            efree(buf);
            return NULL;
        }
        parse_argvlen(buf, head_len, reslen);
        
        result = parse_argv(buf, head_len, reslen);
        efree(buf);
        return result;
    }
    return NULL;
}

PHP_AOQ_API int aoq_push(AoqSock *aoq_sock, char *qname, int qname_len, char *qval ,int qval_len TSRMLS_DC)
{
    int reslen = 0;
    int head_len = 0;
    int buf_len = 0;
    int result = 0;
    char *buf = NULL;
    char *aoq_cmd = NULL;
    char *argval = NULL;

    aoq_cmd = (char *)emalloc((qname_len+qval_len+19)*sizeof(char));
    *(aoq_cmd+qname_len+qval_len+18) = '\0';
    sprintf(aoq_cmd, "1702%06d%06d %s%s\n", qname_len, qval_len, qname, qval);

    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, qname_len+qval_len+18 TSRMLS_CC) > 0)
    {
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            efree(aoq_cmd);
            efree(buf);
            return -1;
        }
        parse_argvlen(buf, head_len, &reslen);
        
        if(reslen == 0)
        {

            efree(aoq_cmd);
            efree(buf);
            return -1;
        }
        argval = parse_argv(buf, head_len, &reslen);
        result = atoi(argval);
        efree(argval);
        efree(aoq_cmd);
        efree(buf);
        return result;
    }

    efree(aoq_cmd);
    return -1;
}

PHP_AOQ_API char * aoq_pop(AoqSock *aoq_sock, char *qname, int qname_len, int *reslen TSRMLS_DC)
{
    char aoq_cmd[1024] = {'\0'};
    
    int head_len = 0;
    int buf_len = 0;
    char *buf = NULL;
    char *result = NULL;
    
    sprintf(aoq_cmd, "1103%06d %s\n", qname_len, qname);
    
    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, qname_len+12 TSRMLS_CC) > 0)
    {
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            efree(buf);
            return NULL;
        }
        parse_argvlen(buf, head_len, reslen);
        
        result = parse_argv(buf, head_len, reslen);
        efree(buf);
        return result;
    }
    return NULL;
}

PHP_AOQ_API char * aoq_queues(AoqSock *aoq_sock, int *reslen TSRMLS_DC)
{
    char aoq_cmd[7] = {'\0'};
    int head_len =0;
    int buf_len = 0;
    char *buf = NULL;
    char *result = NULL;
    
    memcpy(aoq_cmd, "0504 \n", 6);
    
    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, 6 TSRMLS_CC) > 0)
    {
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            efree(buf);
            return NULL;
        }
        parse_argvlen(buf, head_len, reslen);
        
        result = parse_argv(buf, head_len, reslen);
        efree(buf);
        return result;
    }
    return NULL;
}

PHP_AOQ_API char * aoq_queue(AoqSock *aoq_sock, char *qname, int qname_len, int *reslen TSRMLS_DC)
{
    char aoq_cmd[1024] = {'\0'};
    int head_len = 0;
    int buf_len = 0;
    char *buf = NULL;
    char *result = (char *)"";
    
    sprintf(aoq_cmd, "1105%06d %s\n", qname_len, qname);
    
    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, qname_len+12 TSRMLS_CC) > 0)
    {
        
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            
            efree(buf);
            return NULL;
        }

        parse_argvlen(buf, head_len, reslen);
        

        result = parse_argv(buf, head_len, reslen);
        efree(buf);
        return result;
    }

    return NULL;
}

PHP_AOQ_API int aoq_delqueue(AoqSock *aoq_sock, char *qname, int qname_len TSRMLS_DC)
{
    char aoq_cmd[1024] = {'\0'};
    int reslen = 0;
    int head_len = 0;
    int buf_len = 0;
    int result = 0;
    char *buf = NULL;
    char *argval = NULL;
    
    sprintf(aoq_cmd, "1106%06d %s\n", qname_len, qname);
    
    if(aoq_sock_write_aoq_cmd(aoq_sock, aoq_cmd, qname_len+12 TSRMLS_CC) > 0)
    {
        buf = aoq_sock_read_reply(aoq_sock, &buf_len TSRMLS_CC);
        parse_head_len(buf, &head_len);
        if(head_len != 11)
        {
            efree(buf);
            return -1;
        }
        parse_argvlen(buf, head_len, &reslen);
        
        if(reslen == 0)
        {
            efree(buf);
            return -1;
        }
        argval = parse_argv(buf, head_len, &reslen);
        result = atoi(argval);
        efree(argval);
        efree(buf);
        return result;
    }
    return -1;
}


/**
 * aoq_sock_disconnect
 */
PHP_AOQ_API int aoq_sock_disconnect(AoqSock *aoq_sock TSRMLS_DC)
{
    if (aoq_sock == NULL) {
        return 1;
    }

    if (aoq_sock->stream != NULL) {
            aoq_sock->status = AOQ_SOCK_STATUS_DISCONNECTED;

            /* Stil valid? */
            if (!aoq_sock->persistent) {
                php_stream_close(aoq_sock->stream);
            }
            aoq_sock->stream = NULL;

            return 1;
    }
    
    return -1;
}


/**
 * aoq_free_socket
 */
PHP_AOQ_API void aoq_free_socket(AoqSock *aoq_sock)
{
    if(aoq_sock == NULL)
    {
        return;
    }
    
    if(aoq_sock->sock_err) {
        efree(aoq_sock->sock_err);
    }
    if(aoq_sock->persistent_id) {
        efree(aoq_sock->persistent_id);
    }
    efree(aoq_sock->host);
    efree(aoq_sock);
}


PHP_AOQ_API AoqSock * aoq_sock_get(zval *id TSRMLS_DC, int no_throw)
{
    aoq_object *aoq;

    if (Z_TYPE_P(id) == IS_OBJECT) {
#if (PHP_MAJOR_VERSION < 7)
        aoq = (aoq_object *)zend_objects_get_address(id TSRMLS_CC);
#else
        aoq = (aoq_object *)((char *)Z_OBJ_P(id) - XtOffsetOf(aoq_object, std));
#endif
        if (aoq->sock) {
            return aoq->sock;
        }
    }
    // Throw an exception unless we've been requested not to
    if (!no_throw) {
        zend_throw_exception(aoq_exception_ce, "aoq server is unavailable", 0 TSRMLS_CC);
    }
    return NULL;
}


PHP_AOQ_API int aoq_connect(INTERNAL_FUNCTION_PARAMETERS, int persistent)
{
    zval *object;
    char *host = NULL, *persistent_id = NULL;
    zend_long port = -1, retry_times = 0;
    int host_len, persistent_id_len;
    double timeout = 0.0, read_timeout = 0.0;
    aoq_object *aoq;

#ifdef ZTS
    /* not sure how in threaded mode this works so disabled persistence at
     * first */
    persistent = 0;
#endif

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
                                     "Os|ldsld", &object, aoq_ce, &host,
                                     &host_len, &port, &timeout, &persistent_id,
                                     &persistent_id_len, &retry_times,
                                     &read_timeout) == FAILURE)
    {
        return FAILURE;
    } else if (!persistent) {
        persistent_id = NULL;
    }

    if (timeout < 0L || timeout > INT_MAX) {
        zend_throw_exception(aoq_exception_ce,
            "Invalid connect timeout", 0 TSRMLS_CC);
        return FAILURE;
    }

    if (read_timeout < 0L || read_timeout > INT_MAX) {
        zend_throw_exception(aoq_exception_ce,
            "Invalid read timeout", 0 TSRMLS_CC);
        return FAILURE;
    }

    if (retry_times < 0L || retry_times > INT_MAX) {
        zend_throw_exception(aoq_exception_ce, "Invalid retry times",
            0 TSRMLS_CC);
        return FAILURE;
    }

    /* If it's not a unix socket, set to default */
    if(port == -1 && host_len && host[0] != '/') {
        port = PHP_AOQ_PORT;
    }

#if (PHP_MAJOR_VERSION < 7)
    aoq = (aoq_object *)zend_objects_get_address(object TSRMLS_CC);
#else
    aoq = (aoq_object *)((char *)Z_OBJ_P(object) - XtOffsetOf(aoq_object, std));
#endif
    /* if there is a aoq sock already we have to remove it */
    if (aoq->sock) {
        aoq_sock_disconnect(aoq->sock TSRMLS_CC);
        aoq_free_socket(aoq->sock);
    }

    aoq->sock = aoq_sock_create(host, host_len, port, timeout, read_timeout, persistent, persistent_id, retry_times);

    if (aoq_sock_server_open(aoq->sock TSRMLS_CC) < 0) {
        aoq_free_socket(aoq->sock);
        aoq->sock = NULL;
        return FAILURE;
    }

    return SUCCESS;
}


/**
 * aoq_sock_get_direct
 * Returns our attached int pointer if we're connected
 */
PHP_AOQ_API AoqSock *aoq_sock_get_connected(INTERNAL_FUNCTION_PARAMETERS) 
{
    zval *object;
    AoqSock *aoq_sock;

    // If we can't grab our object, or get a socket, or we're not connected,
    // return NULL
    if((zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
       &object, aoq_ce) == FAILURE) ||
       (aoq_sock = aoq_sock_get(object TSRMLS_CC, 1)) == NULL ||
       aoq_sock->status != AOQ_SOCK_STATUS_CONNECTED)
    {
        return NULL;
    }

    /* Return our socket */
    return aoq_sock;
}

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_aoq_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_aoq_compiled)
{
    char *arg = NULL;
    int arg_len, len;
    char *strg;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &arg, &arg_len) == FAILURE) {
        RETURN_FALSE;
    }

    len = spprintf(&strg, 0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "aoq", arg);
    RETURN_STRINGL(strg, len, 0);
}


/* {{{ proto aoq aoq::__construct()
    Public constructor */
PHP_METHOD(Aoq, __construct)
{
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto aoq aoq::__destruct()
    Public Destructor
 */
PHP_METHOD(Aoq,__destruct) {

   if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
        RETURN_FALSE;
    }
    
    RETURN_TRUE;
    
}

/* {{{ proto boolean aoq::connect(string host, int port [, double timeout [, int retry_times [, double read_timeout]])
 */
PHP_METHOD(Aoq, connect)
{
    if (aoq_connect(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0) == FAILURE) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}
/* }}} */

/* {{{ proto boolean aoq::pconnect(string host, int port [, double timeout])
 */
PHP_METHOD(Aoq, pconnect)
{
    if (aoq_connect(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1) == FAILURE) {
        RETURN_FALSE;
    } else {
        /* FIXME: should we remove whole `else` block? */
        /* reset multi/exec state if there is one. */
        AoqSock *aoq_sock;
        if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
            RETURN_FALSE;
        }

        RETURN_TRUE;
    }
}
/* }}} */


PHP_METHOD(Aoq, set_chunk_size)
{
	AoqSock *aoq_sock;
	int	ret;
	zend_long csize;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &csize) == FAILURE) {
		RETURN_FALSE;
	}

	if (csize <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The chunk size must be a positive integer, %d given ", csize);
		RETURN_FALSE;
	}
	
	if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
             
           RETURN_FALSE;
    }
	/* stream.chunk_size is actually a size_t, but php_stream_set_option
	 * can only use an int to accept the new value and return the old one.
	 * In any case, values larger than INT_MAX for a chunk size make no sense.
	 */
	if (csize > INT_MAX) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The chunk size cannot be larger than %d", INT_MAX);
		RETURN_FALSE;
	}

	ret = php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_SET_CHUNK_SIZE, (int)csize, NULL);

	RETURN_LONG(ret > 0 ? (int)ret : (int)EOF);
}


PHP_METHOD(Aoq, set_read_buffer)
{
	AoqSock *aoq_sock;
	int ret;
	size_t buff;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &buff) == FAILURE) {
		RETURN_FALSE;
	}
	
	if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
             
           RETURN_FALSE;
    }


	/* if buff is 0 then set to non-buffered */
	if (buff == 0) {
		ret = php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_READ_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);
	} else {
		ret = php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_READ_BUFFER, PHP_STREAM_BUFFER_FULL, &buff);
	}

	RETURN_LONG(ret == 0 ? 0 : EOF);
}


PHP_METHOD(Aoq, set_write_buffer)
{
	AoqSock *aoq_sock;
	int ret;
	size_t buff;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &buff) == FAILURE) {
		RETURN_FALSE;
	}
	
	if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
             
           RETURN_FALSE;
    }

	/* if buff is 0 then set to non-buffered */
	if (buff == 0) {
		ret = php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);
	} else {
		ret = php_stream_set_option(aoq_sock->stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_FULL, &buff);
	}

	RETURN_LONG(ret == 0 ? 0 : EOF);
}


PHP_METHOD(Aoq, status)
{
    AoqSock *aoq_sock;
    int reslen = 0;
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
        
            RETURN_FALSE;
    }
    
    
    char *result = aoq_status(aoq_sock, &reslen TSRMLS_CC);
    if(result == NULL)
    {
        RETURN_FALSE;
    }
    
    RETURN_STRINGL(result, reslen, 0);
}

PHP_METHOD(Aoq, push)
{
    AoqSock *aoq_sock;
    char *qname, *qval;
    int qname_len;
    int qval_len;
    int result;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &qname, &qname_len,
                             &qval, &qval_len)==FAILURE)
    {
        RETURN_FALSE;
    }
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
             
           RETURN_FALSE;
    }
    
    result = aoq_push(aoq_sock, qname, qname_len, qval, qval_len TSRMLS_CC);
    
    if(result == 1)
    {
        
        RETURN_TRUE;
    }
    
    
    RETURN_FALSE;
}

PHP_METHOD(Aoq, pop)
{
    AoqSock *aoq_sock;
    char *qname;
    int qname_len;
    char *result;
    int reslen = 0;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &qname, &qname_len)==FAILURE)
    {
        RETURN_FALSE;
    }
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
           
        RETURN_FALSE;
    }
    
    result = aoq_pop(aoq_sock, qname, qname_len, &reslen TSRMLS_CC);

    if(result == NULL)
    {
        RETURN_FALSE;
    }
    
    RETURN_STRINGL(result, reslen, 0);
}

PHP_METHOD(Aoq, queues)
{
    AoqSock *aoq_sock;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
        RETURN_FALSE;
    }
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
           RETURN_FALSE;
    }

    int reslen = 0;
    char *result = aoq_queues(aoq_sock, &reslen TSRMLS_CC);
    
    if(result == NULL)
    {
        
        RETURN_FALSE;
    }

    RETURN_STRINGL(result, reslen, 0);
}

PHP_METHOD(Aoq, queue)
{
    AoqSock *aoq_sock;
    char *qname;
    int qname_len;
    char *result;
    int reslen = 0;
    
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &qname, &qname_len)==FAILURE)
    {
        RETURN_FALSE;
    }
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
           
           RETURN_FALSE;
    }
    
    
    result = aoq_queue(aoq_sock, qname, qname_len, &reslen TSRMLS_CC);
    
    if(result == NULL)
    {
        
        RETURN_FALSE;
    }
    
    
    RETURN_STRINGL(result, reslen, 0);
}

PHP_METHOD(Aoq, delqueue)
{
    AoqSock *aoq_sock;
    char *qname;
    int qname_len;
    int result;
    
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &qname, &qname_len)==FAILURE)
    {
        RETURN_FALSE;
    }
    
    if ((aoq_sock = aoq_sock_get(getThis() TSRMLS_CC, 0)) == NULL) {
           
           RETURN_FALSE;
    }
    
    result = aoq_delqueue(aoq_sock, qname, qname_len TSRMLS_CC);

    if(result == 1)
    {
        
        RETURN_TRUE;
    }
    
    
    RETURN_FALSE;
}

PHP_METHOD(Aoq, disconnect)
{
    AoqSock *aoq_sock = aoq_sock_get_connected(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (aoq_sock && aoq_sock_disconnect(aoq_sock TSRMLS_CC)) {
        RETURN_TRUE;
    }
    RETURN_FALSE;
}

/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

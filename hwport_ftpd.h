/*
    Copyright (C) HWPORT.COM.
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_hwport_ftpd_header_hwport_ftpd_h__)
# define __def_hwport_ftpd_header_hwport_ftpd_h__ "hwport_ftpd.h"

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

#if defined(HAVE_CONFIG_H)
# include "config.h"
#endif

/* ---- */

#if defined(__linux__)
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <sys/wait.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdarg.h>
# include <memory.h>
# include <string.h>
# include <time.h>
# include <fcntl.h>
# include <errno.h>
# include <unistd.h>
# include <netdb.h>
# include <signal.h>
# include <dirent.h>

# include <netinet/in.h>
#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__)
# include <winsock2.h>
# include <ws2tcpip.h>
# include <windows.h>
# include <process.h>
# include <iptypes.h>
# include <iphlpapi.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/locking.h>
# include <io.h>
# include <direct.h>
# include <stdio.h>
# include <stddef.h>
# include <stdlib.h>
# include <stdarg.h>
# include <memory.h>
# include <string.h>
# include <time.h>
# include <fcntl.h>
# include <errno.h>
# include <signal.h>

# define def_hwport_ftpd_windows (1)
# if !defined(size_t)
#  define size_t unsigned long
# endif
# if !defined(ssize_t)
#  define ssize_t long
# endif
# if !defined(uid_t)
#  define uid_t int
# endif
# if !defined(gid_t)
#  define gid_t int
# endif
# if !defined(pid_t)
#  define pid_t int
# endif
# if !defined(PATH_MAX)
#  define PATH_MAX (256)
# endif
#endif

#if defined(__GNUC__)
# include <pwd.h>
# define def_hwport_ftpd_use_pwd (1L) /* pwd support */
#else
# define def_hwport_ftpd_use_pwd (0L)
#endif

#if defined(__GNUC__)
# include <shadow.h>
# define def_hwport_ftpd_use_shadow (1L) /* shadow support */
#else
# define def_hwport_ftpd_use_shadow (0L)
#endif

#if defined(__GNUC__)
# include <grp.h>
# define def_hwport_ftpd_use_grp (1L) /* grp support */
#else
# define def_hwport_ftpd_use_grp (0L)
#endif

#if defined(__GNUC__)
# include <glob.h>
# define def_hwport_ftpd_use_glob (1L) /* glob support */
#else
# define def_hwport_ftpd_use_glob (0L)
#endif

#if defined(__GNUC__)
# include <crypt.h>
# define def_hwport_ftpd_use_crypt (1L) /* crypt support */
#else
# define def_hwport_ftpd_use_crypt (0L)
#endif

#if defined(__GNUC__)
# include <pthread.h>
# define def_hwport_ftpd_use_pthread (1L) /* pthread support */
#else
# define def_hwport_ftpd_use_pthread (0L)
#endif

/* ---- */

#define def_hwport_ftpd_can_use_long_long (1L)

#if !defined(hwport_ftpd_builtin_expect)
# if __GNUC__ < 3L
#  define hwport_ftpd_builtin_expect(m_expression,m_value) m_expression
# else
#  define hwport_ftpd_builtin_expect(m_expression,m_value) __builtin_expect((long)(m_expression),(long)(m_value))
# endif
#endif

#if defined(__GNUC__)
# define hwport_ftpd_vsprintf_varg_check(m_format_index,m_varg_index) __attribute__((__format__(__printf__,m_format_index,m_varg_index)))
#else
# define hwport_ftpd_vsprintf_varg_check(m_format_index,m_varg_index)
#endif

#if !defined(def_hwport_ftpd_import)
# define def_hwport_ftpd_import extern
#endif

#if !defined(def_hwport_ftpd_import_c)
# if defined(__cplusplus)
#  define def_hwport_ftpd_import_c extern "C"
# else
#  define def_hwport_ftpd_import_c extern
# endif
#endif

#if !defined(def_hwport_ftpd_export)
# if defined(__cplusplus)
#  define def_hwport_ftpd_export
# else
#  define def_hwport_ftpd_export
# endif
#endif

#if !defined(def_hwport_ftpd_export_c)
# if defined(__cplusplus)
#  define def_hwport_ftpd_export_c extern "C"
# else
#  define def_hwport_ftpd_export_c
# endif
#endif

/* ---- */

#if !defined(hwport_ftpd_path_node_t)
typedef struct hwport_ftpd_path_node_ts {
    struct hwport_ftpd_path_node_ts *m_prev;
    struct hwport_ftpd_path_node_ts *m_next;
    unsigned int m_ignore;
    char *m_name;
}__hwport_ftpd_path_node_t;
# define hwport_ftpd_path_node_t __hwport_ftpd_path_node_t
#endif

/* ---- */

#if defined(PF_INET) && defined(AF_INET)
# define def_hwport_ftpd_can_use_ipv4 (1L)
#else
# define def_hwport_ftpd_can_use_ipv4 (0L)
#endif

#if defined(PF_INET6) && defined(AF_INET6)
# define def_hwport_ftpd_can_use_ipv6 (1L)
#else
# define def_hwport_ftpd_can_use_ipv6 (0L)
#endif

/* ---- */

#if !defined(hwport_ftpd_socket_t)
typedef int __hwport_ftpd_socket_t;
# define hwport_ftpd_socket_t __hwport_ftpd_socket_t
#endif

#if !defined(hwport_ftpd_socklen_t)
typedef socklen_t __hwport_ftpd_socklen_t;
# define hwport_ftpd_socklen_t __hwport_ftpd_socklen_t
#endif

#if !defined(hwport_ftpd_sockdomain_t)
typedef int __hwport_ftpd_sockdomain_t;
# define hwport_ftpd_sockdomain_t __hwport_ftpd_sockdomain_t
#endif

#if !defined(hwport_ftpd_sockfamily_t)
# if defined(def_hwport_ftpd_windows)
typedef int __hwport_ftpd_sockfamily_t;
# else
typedef sa_family_t __hwport_ftpd_sockfamily_t;
# endif
# define hwport_ftpd_sockfamily_t __hwport_ftpd_sockfamily_t
#endif

#if !defined(hwport_ftpd_sockprotocol_t)
typedef int __hwport_ftpd_sockprotocol_t;
# define hwport_ftpd_sockprotocol_t __hwport_ftpd_sockprotocol_t
#endif

#if !defined(hwport_ftpd_sockaddr_t)
typedef struct sockaddr __hwport_ftpd_sockaddr_t;
# define hwport_ftpd_sockaddr_t __hwport_ftpd_sockaddr_t
#endif

#if (def_hwport_ftpd_can_use_ipv4 != 0L) && (!defined(hwport_ftpd_in4_addr_t))
typedef struct in_addr __hwport_ftpd_in4_addr_t;
# define hwport_ftpd_in4_addr_t __hwport_ftpd_in4_addr_t
#endif

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && (!defined(hwport_ftpd_in6_addr_t))
typedef struct in6_addr __hwport_ftpd_in6_addr_t;
# define hwport_ftpd_in6_addr_t __hwport_ftpd_in6_addr_t
#endif

#if (def_hwport_ftpd_can_use_ipv4 != 0L) && (!defined(hwport_ftpd_sockaddr_in4_t))
typedef struct sockaddr_in __hwport_ftpd_sockaddr_in4_t;
# define hwport_ftpd_sockaddr_in4_t __hwport_ftpd_sockaddr_in4_t
#endif

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && (!defined(hwport_ftpd_sockaddr_in6_t))
typedef struct sockaddr_in6 __hwport_ftpd_sockaddr_in6_t;
# define hwport_ftpd_sockaddr_in6_t __hwport_ftpd_sockaddr_in6_t
#endif

#if !defined(hwport_ftpd_sockaddr_storage_t)
typedef struct sockaddr_storage __hwport_ftpd_sockaddr_storage_t;
# define hwport_ftpd_sockaddr_storage_t __hwport_ftpd_sockaddr_storage_t
#endif

#if !defined(hwport_ftpd_sockaddr_all_t)
typedef union hwport_ftpd_sockaddr_all_tu {
    unsigned char m_raw[ sizeof(hwport_ftpd_sockaddr_storage_t) ];

    hwport_ftpd_sockaddr_storage_t m_ss;
    hwport_ftpd_sockaddr_t m_s;
# if def_hwport_ftpd_can_use_ipv4 != 0L
    hwport_ftpd_sockaddr_in4_t m_in4;
# endif
# if def_hwport_ftpd_can_use_ipv6 != 0L
    hwport_ftpd_sockaddr_in6_t m_in6;
# endif
}__hwport_ftpd_sockaddr_all_t;
# define hwport_ftpd_sockaddr_all_t __hwport_ftpd_sockaddr_all_t
#endif


/* ---- */

#define def_hwport_ftpd_company_name "HWPORT.COM."
#define def_hwport_ftpd_server_name "HWPORT FTP Server"

#define def_hwport_ftpd_worker_recv_timeout (-1)
#define def_hwport_ftpd_worker_send_timeout (-1)

/* ---- */

#if !defined(hwport_ftpd_t)
typedef void * __hwport_ftpd_t;
# define hwport_ftpd_t __hwport_ftpd_t
#endif

#if !defined(hwport_ftpd_account_t)
typedef struct hwport_ftpd_account_ts {
    struct hwport_ftpd_account_ts *m_prev;
    struct hwport_ftpd_account_ts *m_next;

    unsigned int m_flags;

    char *m_username;
    char *m_plain_password;

    char *m_path_home;

    uid_t m_uid;
    gid_t m_gid;
}__hwport_ftpd_account_t;
# define hwport_ftpd_account_t __hwport_ftpd_account_t
# define def_hwport_ftpd_account_flag_none (0x00000000u)
# define def_hwport_ftpd_account_flag_admin_user (0x00000001u)
# define def_hwport_ftpd_account_flag_system_user (0x00000002u)
# define def_hwport_ftpd_account_flag_guest_user (0x00000004u)
# define def_hwport_ftpd_account_flag_allow_all_path (0x00000008u)
# define def_hwport_ftpd_account_flag_encrypted_by_crypt (0x00010000u)
#endif

#if !defined(hwport_ftpd_shadow_t)
typedef struct hwport_ftpd_shadow_ts {
    hwport_ftpd_socket_t m_listen_socket;
    hwport_ftpd_sockaddr_all_t m_listen_addr;

    hwport_ftpd_account_t *m_account_head;
    hwport_ftpd_account_t *m_account_tail;
}__hwport_ftpd_shadow_t;
# define hwport_ftpd_shadow_t __hwport_ftpd_shadow_t
#endif

#if !defined(hwport_ftpd_session_t)
typedef struct hwport_ftpd_session_ts {
    hwport_ftpd_t m_handle;
    
    hwport_ftpd_account_t *m_account_head;
    hwport_ftpd_account_t *m_current_account;

    unsigned int m_flags;

    int m_send_timeout;
    int m_recv_timeout;

    /* command */
    hwport_ftpd_socket_t m_command_socket;
    hwport_ftpd_sockaddr_all_t m_command_sockaddr_all;
    hwport_ftpd_socklen_t m_command_sockaddr_size;
    size_t m_command_buffer_size; 
    unsigned char *m_command_buffer;

    char *m_command;
    char *m_param;

    /* data */
    hwport_ftpd_socket_t m_data_socket;
    hwport_ftpd_sockaddr_all_t m_data_sockaddr_all;
    hwport_ftpd_socklen_t m_data_sockaddr_size;
    size_t m_data_buffer_size; 
    unsigned char *m_data_buffer;
    off_t m_restart_position;

    /* file */
    int m_fd;

    /* current user info */
    char *m_username;
    unsigned int m_type;
   
    /* - */
    char *m_path_home;
    char *m_path_work;
    char *m_path_rename_from;
}__hwport_ftpd_session_t;
# define hwport_ftpd_session_t __hwport_ftpd_session_t

# define def_hwport_ftpd_session_flag_none (0x00000000u)
# define def_hwport_ftpd_session_flag_user (0x00000001u)
# define def_hwport_ftpd_session_flag_restart_position (0x00000002u)
# define def_hwport_ftpd_session_flag_rename_from (0x00000004u)
# define def_hwport_ftpd_session_flag_fork (0x00000008u)

# define def_hwport_ftpd_session_type_none (0x00000000u)
# define def_hwport_ftpd_session_type_A (0x00000001u)
# define def_hwport_ftpd_session_type_I (0x00000002u)
# define def_hwport_ftpd_session_type_L8 (0x00000003u)

# define def_hwport_ftpd_list_option_none (0x00000000u)
# define def_hwport_ftpd_list_option_a (0x00000001u)
# define def_hwport_ftpd_list_option_l (0x00000002u)
# define def_hwport_ftpd_list_option_f (0x00000004u)
# define def_hwport_ftpd_list_option_r (0x00000008u)
# define def_hwport_ftpd_list_option_unknown (0x80000000u)
#endif

/* ---- */

#if !defined(__def_hwport_ftpd_source_hwport_ftpd_c__)
def_hwport_ftpd_import_c int hwport_ftpd_isdigit(int s_character);
def_hwport_ftpd_import_c int hwport_ftpd_isspace(int s_character);
def_hwport_ftpd_import_c int hwport_ftpd_toupper(int s_character);

def_hwport_ftpd_import_c size_t hwport_ftpd_strnlen(const char *s_string, size_t s_max_size);
def_hwport_ftpd_import_c size_t hwport_ftpd_strlen(const char *s_string);

def_hwport_ftpd_import_c char *hwport_ftpd_strncpy(char *s_to, const char *s_from, size_t s_max_size);
def_hwport_ftpd_import_c char *hwport_ftpd_strcpy(char *s_to, const char *s_from);
def_hwport_ftpd_import_c char *hwport_ftpd_strncat(char *s_to, const char *s_from, size_t s_max_size);
def_hwport_ftpd_import_c char *hwport_ftpd_strcat(char *s_to, const char *s_from);

def_hwport_ftpd_import_c int hwport_ftpd_strncmp(const char *s_left, const char *s_right, size_t s_max_size);
def_hwport_ftpd_import_c int hwport_ftpd_strcmp(const char *s_left, const char *s_right);
def_hwport_ftpd_import_c int hwport_ftpd_strncasecmp(const char *s_left, const char *s_right, size_t s_max_size);
def_hwport_ftpd_import_c int hwport_ftpd_strcasecmp(const char *s_left, const char *s_right);

def_hwport_ftpd_import_c char *hwport_ftpd_strpbrk(const char *s_string, const char *s_this);

def_hwport_ftpd_import_c char *hwport_ftpd_strstr(const char *s_string, const char *s_this);
def_hwport_ftpd_import_c char *hwport_ftpd_strcasestr(const char *s_string, const char *s_this);

def_hwport_ftpd_import_c char *hwport_ftpd_strndup(const char *s_string, size_t s_size);
def_hwport_ftpd_import_c char *hwport_ftpd_strdup(const char *s_string);

def_hwport_ftpd_import_c size_t hwport_ftpd_xtoa_limit(char *s_output, size_t s_max_output_size, unsigned int s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits);
#if def_hwport_ftpd_can_use_long_long != (0L)
def_hwport_ftpd_import_c size_t hwport_ftpd_llxtoa_limit(char *s_output, size_t s_max_output_size, unsigned long long s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits);
#endif
def_hwport_ftpd_import_c int hwport_ftpd_atox(const char *s_string, int s_base);
def_hwport_ftpd_import_c int hwport_ftpd_atoi(const char *s_string);
#if def_hwport_ftpd_can_use_long_long != (0L)
def_hwport_ftpd_import_c long long hwport_ftpd_atollx(const char *s_string, int s_base);
def_hwport_ftpd_import_c long long hwport_ftpd_atoll(const char *s_string);
#endif
def_hwport_ftpd_import_c int hwport_ftpd_vsnprintf(char *s_output, size_t s_max_output_size, const char *s_format, va_list s_var);
def_hwport_ftpd_import_c int hwport_ftpd_vsprintf(char *s_output, const char *s_format, va_list s_var);
def_hwport_ftpd_import_c int hwport_ftpd_snprintf(char *s_output, size_t s_max_output_size, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(3,4);
def_hwport_ftpd_import_c int hwport_ftpd_sprintf(char *s_output, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(2,3);

def_hwport_ftpd_import_c char *hwport_ftpd_alloc_vsprintf(const char *s_format, va_list s_var);
def_hwport_ftpd_import_c char *hwport_ftpd_alloc_sprintf(const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(1,2);

def_hwport_ftpd_import_c char *hwport_ftpd_get_word_sep(int s_skip_space, const char *s_sep, char **s_sep_string);
def_hwport_ftpd_import_c char *hwport_ftpd_get_word_sep_alloc(int s_skip_space, const char *s_sep, const char **s_sep_string);

def_hwport_ftpd_import_c int hwport_ftpd_check_pattern(const char *s_pattern, const char *s_string);

def_hwport_ftpd_import_c hwport_ftpd_path_node_t *hwport_ftpd_free_path_node(hwport_ftpd_path_node_t *s_node);
def_hwport_ftpd_import_c hwport_ftpd_path_node_t *hwport_ftpd_path_to_node(const char *s_path);
def_hwport_ftpd_import_c char *hwport_ftpd_node_to_path(hwport_ftpd_path_node_t *s_node, int s_strip);
def_hwport_ftpd_import_c hwport_ftpd_path_node_t *hwport_ftpd_copy_path_node(hwport_ftpd_path_node_t *s_node);
def_hwport_ftpd_import_c hwport_ftpd_path_node_t *hwport_ftpd_append_path_node(hwport_ftpd_path_node_t *s_head, hwport_ftpd_path_node_t *s_node, int s_override);

def_hwport_ftpd_import_c char *hwport_ftpd_basename(char *s_pathname);

def_hwport_ftpd_import_c hwport_ftpd_sockprotocol_t hwport_ftpd_get_protocol_by_name(const char *s_protocol_name);

def_hwport_ftpd_import_c hwport_ftpd_socket_t hwport_ftpd_socket_open(hwport_ftpd_sockdomain_t s_domain, hwport_ftpd_sockfamily_t s_type, hwport_ftpd_sockprotocol_t s_protocol);
def_hwport_ftpd_import_c hwport_ftpd_socket_t hwport_ftpd_socket_close(hwport_ftpd_socket_t s_socket);

def_hwport_ftpd_import_c int hwport_ftpd_bind(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size);
def_hwport_ftpd_import_c int hwport_ftpd_listen(hwport_ftpd_socket_t s_socket, int s_backlog);
def_hwport_ftpd_import_c hwport_ftpd_socket_t hwport_ftpd_accept(hwport_ftpd_socket_t s_listen_socket, void *s_sockaddr_ptr, hwport_ftpd_socklen_t *s_sockaddr_size_ptr, int s_msec);
def_hwport_ftpd_import_c int hwport_ftpd_connect(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size, int s_msec);
def_hwport_ftpd_import_c ssize_t hwport_ftpd_recv(hwport_ftpd_socket_t s_socket, void *s_data, size_t s_size, int s_msec);
def_hwport_ftpd_import_c ssize_t hwport_ftpd_send(hwport_ftpd_socket_t s_socket, const void *s_data, size_t s_size, int s_msec);
def_hwport_ftpd_import_c ssize_t hwport_ftpd_send_message(hwport_ftpd_socket_t s_socket, int s_msec, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(3,4);

def_hwport_ftpd_import_c const char *hwport_ftpd_inet_ntop(hwport_ftpd_sockfamily_t s_family, const void *s_inX_addr_ptr, char *s_address, hwport_ftpd_socklen_t s_address_size);
def_hwport_ftpd_import_c const char *hwport_ftpd_inet_stop(const hwport_ftpd_sockaddr_all_t *s_sockaddr_all, char *s_address, hwport_ftpd_socklen_t s_address_size);
def_hwport_ftpd_import_c int hwport_ftpd_inet_pton(hwport_ftpd_sockfamily_t s_family, const char *s_address, void *s_inX_addr_ptr);

def_hwport_ftpd_import_c hwport_ftpd_t hwport_ftpd_open(void);
def_hwport_ftpd_import_c hwport_ftpd_t hwport_ftpd_close(hwport_ftpd_t s_handle);
def_hwport_ftpd_import_c int hwport_ftpd_do(hwport_ftpd_t s_handle, int s_msec);

def_hwport_ftpd_import_c hwport_ftpd_account_t *hwport_ftpd_new_account(const char *s_username, unsigned int s_flags);
def_hwport_ftpd_import_c hwport_ftpd_account_t *hwport_ftpd_free_account(hwport_ftpd_account_t *s_account);
def_hwport_ftpd_import_c int hwport_ftpd_account_set_plain_password(hwport_ftpd_account_t *s_account, const char *s_plain_password);
def_hwport_ftpd_import_c int hwport_ftpd_add_account(hwport_ftpd_t s_handle, hwport_ftpd_account_t *s_account);
def_hwport_ftpd_import_c int hwport_ftpd_account_set_path_home(hwport_ftpd_account_t *s_account, const char *s_path_home);
def_hwport_ftpd_import_c int hwport_ftpd_add_user(hwport_ftpd_t s_handle, hwport_ftpd_account_t **s_account_ptr, unsigned int s_flags, const char *s_username, const char *s_plain_password, const char *s_path_home);
def_hwport_ftpd_import_c hwport_ftpd_account_t *hwport_ftpd_account_check_login(hwport_ftpd_account_t *s_account_head, const char *s_username, const char *s_plain_password);

def_hwport_ftpd_import_c int hwport_ftpd_data_open(hwport_ftpd_session_t *s_session);
def_hwport_ftpd_import_c int hwport_ftpd_data_close(hwport_ftpd_session_t *s_session);
#endif

#endif

/* vim: set expandtab: */
/* End of header */

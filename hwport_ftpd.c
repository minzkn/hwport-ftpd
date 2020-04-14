/*
    Copyright (C) HWPORT.COM.
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_hwport_ftpd_source_hwport_ftpd_c__)
# define __def_hwport_ftpd_source_hwport_ftpd_c__ "hwport_ftpd.c"

#include "hwport_ftpd.h"

#define def_hwport_ftpd_command_buffer_size (512)
#define def_hwport_ftpd_data_buffer_size (4 << 10)

def_hwport_ftpd_export_c int hwport_ftpd_isdigit(int s_character);
def_hwport_ftpd_export_c int hwport_ftpd_isspace(int s_character);
def_hwport_ftpd_export_c int hwport_ftpd_toupper(int s_character);

def_hwport_ftpd_export_c size_t hwport_ftpd_strnlen(const char *s_string, size_t s_max_size);
def_hwport_ftpd_export_c size_t hwport_ftpd_strlen(const char *s_string);

def_hwport_ftpd_export_c char *hwport_ftpd_strncpy(char *s_to, const char *s_from, size_t s_max_size);
def_hwport_ftpd_export_c char *hwport_ftpd_strcpy(char *s_to, const char *s_from);
def_hwport_ftpd_export_c char *hwport_ftpd_strncat(char *s_to, const char *s_from, size_t s_max_size);
def_hwport_ftpd_export_c char *hwport_ftpd_strcat(char *s_to, const char *s_from);

static int hwport_ftpd_strncmp_private(const char *s_left, const char *s_right, size_t s_max_size, int s_is_case);
def_hwport_ftpd_export_c int hwport_ftpd_strncmp(const char *s_left, const char *s_right, size_t s_max_size);
def_hwport_ftpd_export_c int hwport_ftpd_strcmp(const char *s_left, const char *s_right);
def_hwport_ftpd_export_c int hwport_ftpd_strncasecmp(const char *s_left, const char *s_right, size_t s_max_size);
def_hwport_ftpd_export_c int hwport_ftpd_strcasecmp(const char *s_left, const char *s_right);

def_hwport_ftpd_export_c char *hwport_ftpd_strpbrk(const char *s_string, const char *s_this);

static char *hwport_ftpd_strstr_private(const char *s_string, const char *s_this, int s_is_case);
def_hwport_ftpd_export_c char *hwport_ftpd_strstr(const char *s_string, const char *s_this);
def_hwport_ftpd_export_c char *hwport_ftpd_strcasestr(const char *s_string, const char *s_this);

def_hwport_ftpd_export_c char *hwport_ftpd_strndup(const char *s_string, size_t s_size);
def_hwport_ftpd_export_c char *hwport_ftpd_strdup(const char *s_string);

def_hwport_ftpd_export_c size_t hwport_ftpd_xtoa_limit(char *s_output, size_t s_max_output_size, unsigned int s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits);
#if def_hwport_ftpd_can_use_long_long != (0L)
def_hwport_ftpd_export_c size_t hwport_ftpd_llxtoa_limit(char *s_output, size_t s_max_output_size, unsigned long long s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits);
#endif
def_hwport_ftpd_export_c int hwport_ftpd_atox(const char *s_string, int s_base);
def_hwport_ftpd_export_c int hwport_ftpd_atoi(const char *s_string);
#if def_hwport_ftpd_can_use_long_long != (0L)
def_hwport_ftpd_export_c long long hwport_ftpd_atollx(const char *s_string, int s_base);
def_hwport_ftpd_export_c long long hwport_ftpd_atoll(const char *s_string);
#endif
def_hwport_ftpd_export_c int hwport_ftpd_vsnprintf(char *s_output, size_t s_max_output_size, const char *s_format, va_list s_var);
def_hwport_ftpd_export_c int hwport_ftpd_vsprintf(char *s_output, const char *s_format, va_list s_var);
def_hwport_ftpd_export_c int hwport_ftpd_snprintf(char *s_output, size_t s_max_output_size, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(3,4);
def_hwport_ftpd_export_c int hwport_ftpd_sprintf(char *s_output, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(2,3);

def_hwport_ftpd_export_c char *hwport_ftpd_alloc_vsprintf(const char *s_format, va_list s_var);
def_hwport_ftpd_export_c char *hwport_ftpd_alloc_sprintf(const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(1,2);

def_hwport_ftpd_export_c char *hwport_ftpd_get_word_sep(int s_skip_space, const char *s_sep, char **s_sep_string);
def_hwport_ftpd_export_c char *hwport_ftpd_get_word_sep_alloc(int s_skip_space, const char *s_sep, const char **s_sep_string);

def_hwport_ftpd_export_c int hwport_ftpd_check_pattern(const char *s_pattern, const char *s_string);

static int hwport_ftpd_check_ignore_path_node(hwport_ftpd_path_node_t *s_current);
def_hwport_ftpd_export_c hwport_ftpd_path_node_t *hwport_ftpd_free_path_node(hwport_ftpd_path_node_t *s_node);
def_hwport_ftpd_export_c hwport_ftpd_path_node_t *hwport_ftpd_path_to_node(const char *s_path);
def_hwport_ftpd_export_c char *hwport_ftpd_node_to_path(hwport_ftpd_path_node_t *s_node, int s_strip);
def_hwport_ftpd_export_c hwport_ftpd_path_node_t *hwport_ftpd_copy_path_node(hwport_ftpd_path_node_t *s_node);
def_hwport_ftpd_export_c hwport_ftpd_path_node_t *hwport_ftpd_append_path_node(hwport_ftpd_path_node_t *s_head, hwport_ftpd_path_node_t *s_node, int s_override);

def_hwport_ftpd_export_c char *hwport_ftpd_basename(char *s_pathname);

def_hwport_ftpd_export_c hwport_ftpd_sockprotocol_t hwport_ftpd_get_protocol_by_name(const char *s_protocol_name);

def_hwport_ftpd_export_c hwport_ftpd_socket_t hwport_ftpd_socket_open(hwport_ftpd_sockdomain_t s_domain, hwport_ftpd_sockfamily_t s_type, hwport_ftpd_sockprotocol_t s_protocol);
def_hwport_ftpd_export_c hwport_ftpd_socket_t hwport_ftpd_socket_close(hwport_ftpd_socket_t s_socket);

def_hwport_ftpd_export_c int hwport_ftpd_bind(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size);
def_hwport_ftpd_export_c int hwport_ftpd_listen(hwport_ftpd_socket_t s_socket, int s_backlog);
def_hwport_ftpd_export_c hwport_ftpd_socket_t hwport_ftpd_accept(hwport_ftpd_socket_t s_listen_socket, void *s_sockaddr_ptr, hwport_ftpd_socklen_t *s_sockaddr_size_ptr, int s_msec);
def_hwport_ftpd_export_c int hwport_ftpd_connect(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size, int s_msec);
def_hwport_ftpd_export_c ssize_t hwport_ftpd_recv(hwport_ftpd_socket_t s_socket, void *s_data, size_t s_size, int s_msec);
def_hwport_ftpd_export_c ssize_t hwport_ftpd_send(hwport_ftpd_socket_t s_socket, const void *s_data, size_t s_size, int s_msec);
def_hwport_ftpd_export_c ssize_t hwport_ftpd_send_message(hwport_ftpd_socket_t s_socket, int s_msec, const char *s_format, ...) hwport_ftpd_vsprintf_varg_check(3,4);

def_hwport_ftpd_export_c const char *hwport_ftpd_inet_ntop(hwport_ftpd_sockfamily_t s_family, const void *s_inX_addr_ptr, char *s_address, hwport_ftpd_socklen_t s_address_size);
def_hwport_ftpd_export_c const char *hwport_ftpd_inet_stop(const hwport_ftpd_sockaddr_all_t *s_sockaddr_all, char *s_address, hwport_ftpd_socklen_t s_address_size);
def_hwport_ftpd_export_c int hwport_ftpd_inet_pton(hwport_ftpd_sockfamily_t s_family, const char *s_address, void *s_inX_addr_ptr);

static hwport_ftpd_t hwport_ftpd_open_private(int s_listen_port);
def_hwport_ftpd_export_c hwport_ftpd_t hwport_ftpd_open(void);
def_hwport_ftpd_export_c hwport_ftpd_t hwport_ftpd_close(hwport_ftpd_t s_handle);
#if def_hwport_ftpd_use_pthread != (0L)       
static int hwport_ftpd_detached_thread(void * (*s_thread_handler)(void *), void *s_argument, size_t s_stack_size);
#endif
def_hwport_ftpd_export_c int hwport_ftpd_do(hwport_ftpd_t s_handle, int s_msec);

def_hwport_ftpd_export_c hwport_ftpd_account_t *hwport_ftpd_new_account(const char *s_username, unsigned int s_flags);
def_hwport_ftpd_export_c hwport_ftpd_account_t *hwport_ftpd_free_account(hwport_ftpd_account_t *s_account);
def_hwport_ftpd_export_c int hwport_ftpd_account_set_plain_password(hwport_ftpd_account_t *s_account, const char *s_plain_password);
def_hwport_ftpd_export_c int hwport_ftpd_add_account(hwport_ftpd_t s_handle, hwport_ftpd_account_t *s_account);
def_hwport_ftpd_export_c int hwport_ftpd_account_set_path_home(hwport_ftpd_account_t *s_account, const char *s_path_home);
def_hwport_ftpd_export_c int hwport_ftpd_add_user(hwport_ftpd_t s_handle, hwport_ftpd_account_t **s_account_ptr, unsigned int s_flags, const char *s_username, const char *s_plain_password, const char *s_path_home);
def_hwport_ftpd_export_c hwport_ftpd_account_t *hwport_ftpd_account_login(hwport_ftpd_session_t *s_session, const char *s_username, const char *s_plain_password);

def_hwport_ftpd_export_c int hwport_ftpd_data_open(hwport_ftpd_session_t *s_session);
def_hwport_ftpd_export_c int hwport_ftpd_data_close(hwport_ftpd_session_t *s_session);

static void hwport_ftpd_session_end(hwport_ftpd_session_t *s_session);
static void *hwport_ftpd_worker(void *s_argument);

static int hwport_ftpd_command_user(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_pass(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_syst(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_type(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_mode(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_abor(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_quit(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_noop(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_port(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_eprt(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_pwd(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_change_remote_directory(hwport_ftpd_session_t *s_session, char *s_remote_path);
static int hwport_ftpd_command_cwd(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_cdup(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_rmd(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_mkd(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_dele(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_pasv(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_epsv(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_list(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_nlst(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_acct(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_size(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_stru(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_rnfr(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_rnto(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_retr(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_stor(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_appe(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_rest(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_mdtm(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_opts(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_site(hwport_ftpd_session_t *s_session);
static int hwport_ftpd_command_help(hwport_ftpd_session_t *s_session);

static int hwport_ftpd_get_path(hwport_ftpd_session_t *s_session, const char *s_change_directory, char **s_path_abs, char **s_path_work);

static unsigned int hwport_ftpd_get_list_option(char **s_param_ptr);
static int hwport_ftpd_list_buffer(hwport_ftpd_session_t *s_session, char *s_path, struct stat *s_stat_ptr, char *s_buffer, size_t s_buffer_size, unsigned int s_list_option);
static int hwport_ftpd_list_scan(hwport_ftpd_session_t *s_session, char *s_path, unsigned int s_list_option);
static int hwport_ftpd_list(hwport_ftpd_session_t *s_session, unsigned int s_list_option);

static off_t hwport_ftpd_ascii_to_binary_offset(const char *s_filename, off_t s_offset);

static int hwport_ftpd_command_stream(hwport_ftpd_session_t *s_session, int s_command_type);

static int hwport_ftpd_command(hwport_ftpd_session_t *s_session);

/* ---- */

static const char *g_hwport_ftpd_vsprintf_digits[2] = {
    "0123456789ABCDEF",
    "0123456789abcdef"
};

/* ---- */

int hwport_ftpd_isdigit(int s_character)
{
    if((s_character >= '0') && (s_character <= '9')) {
        return(1);
    }

    return(0);
}

int hwport_ftpd_isspace(int s_character)
{
    if((s_character == ' ') || (s_character == '\t')) {
        return(1);
    }

    return(0);
}

int hwport_ftpd_toupper(int s_character)
{
    if((s_character >= 'a') && (s_character <= 'z')) {
        return((s_character - 'a') + 'A');
    }

    return(s_character);
}

/* ---- */

size_t hwport_ftpd_strnlen(const char *s_string, size_t s_max_size)
{
    size_t s_result = (size_t)0;

    while(s_result < s_max_size) {
        if(s_string[s_result] == '\0') {
            break;
        }
        ++s_result;
    }

    return(s_result);
}

size_t hwport_ftpd_strlen(const char *s_string)
{
    size_t s_result = (size_t)0;

    while(s_string[s_result] != '\0') {
        ++s_result;
    }

    return(s_result);
}

/* ---- */

char *hwport_ftpd_strncpy(char *s_to, const char *s_from, size_t s_max_size)
{
    size_t s_offset = (size_t)0;

    while(s_offset < s_max_size) {
        if(s_from[s_offset] == '\0') {
            break;
        }
        s_to[s_offset] = s_from[s_offset];
        ++s_offset;
    }

    while(s_offset < s_max_size) {
        s_to[s_offset++] = '\0';
    }

    return(s_to);
}

char *hwport_ftpd_strcpy(char *s_to, const char *s_from)
{
    size_t s_offset = (size_t)0;

    while(s_from[s_offset] != '\0') {
        s_to[s_offset] = s_from[s_offset];
        ++s_offset;
    }
    s_to[s_offset] = '\0';
    
    return(s_to);
}

char *hwport_ftpd_strncat(char *s_to, const char *s_from, size_t s_max_size)
{
    return(hwport_ftpd_strncpy((char *)(&s_to[hwport_ftpd_strlen(s_to)]), s_from, s_max_size));
}

char *hwport_ftpd_strcat(char *s_to, const char *s_from)
{
    return(hwport_ftpd_strcpy((char *)(&s_to[hwport_ftpd_strlen(s_to)]), s_from));
}

/* ---- */

static int hwport_ftpd_strncmp_private(const char *s_left, const char *s_right, size_t s_max_size, int s_is_case)
{
    int s_diff = 0;
    size_t s_offset = (size_t)0;

    while((s_max_size == ((size_t)0u)) || (s_offset < s_max_size)) {
        if(s_is_case == 0) {
            s_diff = ((int)s_left[s_offset]) - ((int)s_right[s_offset]);
        }
        else {
            s_diff = hwport_ftpd_toupper((int)s_left[s_offset]) - hwport_ftpd_toupper((int)s_right[s_offset]);
        }

        if((s_diff != 0) || (s_left[s_offset] == '\0') || (s_right[s_offset] == '\0')) {
            break;
        }

        ++s_offset;
    }

    return((int)s_diff);
}

int hwport_ftpd_strncmp(const char *s_left, const char *s_right, size_t s_max_size)
{
    if(s_max_size == ((size_t)0u)) {
        return(0);
    }

    return(hwport_ftpd_strncmp_private(s_left, s_right, s_max_size, 0));
}

int hwport_ftpd_strcmp(const char *s_left, const char *s_right)
{
    return(hwport_ftpd_strncmp_private(s_left, s_right, (size_t)0u, 0));
}

int hwport_ftpd_strncasecmp(const char *s_left, const char *s_right, size_t s_max_size)
{
    if(s_max_size == ((size_t)0u)) {
        return(0);
    }

    return(hwport_ftpd_strncmp_private(s_left, s_right, s_max_size, 1));
}

int hwport_ftpd_strcasecmp(const char *s_left, const char *s_right)
{
    return(hwport_ftpd_strncmp_private(s_left, s_right, (size_t)0u, 1));
}

/* ---- */

char *hwport_ftpd_strpbrk(const char *s_string, const char *s_this)
{
    union {
        char *m_ptr;
        const char *m_const_ptr;
    }s_temp_ptr;

    size_t s_offset;
    size_t s_offset_local;
  
    s_offset = (size_t)0u;
    while(s_string[s_offset] != '\0') {
        s_offset_local = (size_t)0u;
        while(s_this[s_offset_local] != '\0') {
            if(s_string[s_offset] == s_this[s_offset_local]) {
                s_temp_ptr.m_const_ptr = (const char *)(&s_string[s_offset]);
                return(s_temp_ptr.m_ptr);
            }
            ++s_offset_local;
        }
        ++s_offset;
    }

    return((char *)0);
}

/* ---- */

static char *hwport_ftpd_strstr_private(const char *s_string, const char *s_this, int s_is_case)
{
    union {
        char *m_ptr;
        const char *m_const_ptr;
    }s_temp_ptr;

    size_t s_string_offset;
    size_t s_this_offset;
    size_t s_offset;
    size_t s_this_size;
    char s_string_byte;
    char s_this_byte;

    s_string_offset = (size_t)0u;
    s_this_offset = (size_t)0u;
    s_offset = (size_t)0u;
    s_this_size = hwport_ftpd_strlen(s_this);

    for(;;) {
        s_string_byte = s_string[s_string_offset];
        s_this_byte = s_this[s_this_offset];
        if((s_string_byte == '\0') || (s_this_byte == '\0')) {
            break;
        }
        if(((s_is_case == 0) && (s_string_byte == s_this_byte)) ||
           ((s_is_case != 0) && (hwport_ftpd_toupper((int)s_string_byte) == hwport_ftpd_toupper((int)s_this_byte)))) {
            if(s_this_offset == ((size_t)0)) {
                s_offset = s_string_offset;
            }
            ++s_this_offset;
            if(s_this_offset == s_this_size) {
                s_temp_ptr.m_const_ptr = (const char *)(&s_string[s_offset]);
                return(s_temp_ptr.m_ptr);
            }
        }
        else {
            s_this_offset = (size_t)0u;
        }
        ++s_string_offset;
    }

    return((char *)0);
}

char *hwport_ftpd_strstr(const char *s_string, const char *s_this)
{
    return(hwport_ftpd_strstr_private(s_string, s_this, 0));
}

char *hwport_ftpd_strcasestr(const char *s_string, const char *s_this)
{
    return(hwport_ftpd_strstr_private(s_string, s_this, 1));
}

/* ---- */

char *hwport_ftpd_strndup(const char *s_string, size_t s_size)
{
    char *s_result;

    s_size = hwport_ftpd_strnlen(s_string, s_size);

    s_result = (char *)malloc(s_size + ((size_t)1u));
    if(hwport_ftpd_builtin_expect(s_result == ((char *)0), 0)) {
        return((char *)0);
    }

    if(s_size > ((size_t)0u)) {
        (void)memcpy((void *)s_result, (const void *)s_string, s_size);
    }
    s_result[s_size] = '\0';

    return(s_result);
}

char *hwport_ftpd_strdup(const char *s_string)
{
    char *s_result;
    size_t s_size;

    s_size = hwport_ftpd_strlen(s_string);

    s_result = (char *)malloc(s_size + ((size_t)1u));
    if(hwport_ftpd_builtin_expect(s_result == ((char *)0), 0)) {
        return((char *)0);
    }

    if(s_size > ((size_t)0u)) {
        (void)memcpy((void *)s_result, (const void *)s_string, s_size);
    }
    s_result[s_size] = '\0';

    return(s_result);
}

/* ---- */

size_t hwport_ftpd_xtoa_limit(char *s_output, size_t s_max_output_size, unsigned int s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits)
{
    unsigned int s_result = 0u;
    char s_local_buffer[ 32 ];
    char s_pad;

    if(s_digits == ((const char *)0)) {
        s_digits = g_hwport_ftpd_vsprintf_digits[0];
    }

    do {
        s_local_buffer[s_result++] = s_digits[ s_value % s_radix ];
        s_value /= s_radix;
    }while(s_value != 0u);

    /* '0' padding */
    if((s_width & 0x80000000u) == 0u) {
        s_pad = s_digits[0];
    }
    else {
        s_pad = ' ';
    }
    s_width &= 0x7FFFFFFFu;
    if(s_width > s_result) {
        s_width -= s_result;
        while((s_width--) > 0u) {
            s_local_buffer[s_result++] = s_pad;
        }
    }

    /* reverse copy */
    if(s_output != ((char *)0)) {
        unsigned int s_offset;

        s_offset = s_result;
        while((s_offset > 0u) && ((s_max_output_size--) > ((size_t)0u))) {
            s_output[0] = s_local_buffer[--s_offset];
            s_output = (char *)(&s_output[1]);
        }
    }

    return((size_t)s_result);
}

#if def_hwport_ftpd_can_use_long_long != (0L)
# define hwport_ftpd_vsprintf_udiv(m_value,m_by) (m_value / m_by)
# define hwport_ftpd_vsprintf_umod(m_value,m_by) (m_value % m_by)
size_t hwport_ftpd_llxtoa_limit(char *s_output, size_t s_max_output_size, unsigned long long s_value, unsigned int s_radix, unsigned int s_width, const char *s_digits)
{
    unsigned int s_result = 0u;
    char s_local_buffer[ 32 ];
    char s_pad;

    if(s_digits == ((const char *)0)) {
        s_digits = g_hwport_ftpd_vsprintf_digits[0];
    }
    
    do {
        s_local_buffer[s_result++] = s_digits[ hwport_ftpd_vsprintf_umod(s_value, s_radix) ];
        s_value = hwport_ftpd_vsprintf_udiv(s_value, s_radix);
    }while(s_value != 0ull);

    /* '0' padding */
    if((s_width & 0x80000000u) == 0u) {
        s_pad = s_digits[0];
    }
    else {
        s_pad = ' ';
    }
    s_width &= 0x7FFFFFFFu;
    if(s_width > s_result) {
        s_width -= s_result;
        while((s_width--) > 0u) {
            s_local_buffer[s_result++] = s_pad;
        }
    }

    /* reverse copy */
    if(s_output != ((char *)0)) {
        unsigned int s_offset;

        s_offset = s_result;
        while((s_offset > 0u) && ((s_max_output_size--) > ((size_t)0u))) {
            s_output[0] = s_local_buffer[--s_offset];
            s_output = (char *)(&s_output[1]);
        }
    }

    return((size_t)s_result);
}
#endif

int hwport_ftpd_atox(const char *s_string, int s_base)
{
    int s_result = 0;
    int s_is_minus = 0;
    size_t s_offset = (size_t)0u;
    int s_temp;

    if(hwport_ftpd_builtin_expect(s_string[s_offset] == '\0', 0)) {
        return(0);
    }

    if(s_string[s_offset] == '+') {
        ++s_offset;
    }
    
    if(s_string[s_offset] == '-') {
        ++s_offset;
        s_is_minus = 1;
    }

    for(;;) {
        if(s_string[s_offset] == '\0') {
            break;
        }

        if(hwport_ftpd_isdigit(s_string[s_offset]) == 0) {
            break;
        }

        s_temp = s_string[s_offset] - '0';

        s_result = (s_result * s_base) + s_temp;
        ++s_offset;
    }

    if(s_is_minus == 0) {
        return(s_result);
    }

    if(s_base != 10) {
        return(s_result);
    }

    return(-s_result);
}

int hwport_ftpd_atoi(const char *s_string)
{
    return(hwport_ftpd_atox(s_string, 10));
}

#if def_hwport_ftpd_can_use_long_long != (0L)
long long hwport_ftpd_atollx(const char *s_string, int s_base)
{
    long long s_result = 0ll;
    int s_is_minus = 0;
    size_t s_offset = (size_t)0u;
    int s_temp;

    if(hwport_ftpd_builtin_expect(s_string[s_offset] == '\0', 0)) {
        return(0);
    }

    if(s_string[s_offset] == '+') {
        ++s_offset;
    }
    
    if(s_string[s_offset] == '-') {
        ++s_offset;
        s_is_minus = 1;
    }

    for(;;) {
        if(s_string[s_offset] == '\0') {
            break;
        }

        if(hwport_ftpd_isdigit(s_string[s_offset]) == 0) {
            break;
        }

        s_temp = s_string[s_offset] - '0';

        s_result = (s_result * ((long long)s_base)) + ((long long)s_temp);
        ++s_offset;
    }

    if(s_is_minus == 0) {
        return(s_result);
    }
    
    if(s_base != 10) {
        return(s_result);
    }

    return(-s_result);
}

long long hwport_ftpd_atoll(const char *s_string)
{
    return(hwport_ftpd_atollx(s_string, 10));
}
#endif

int hwport_ftpd_vsnprintf(char *s_output, size_t s_max_output_size, const char *s_format, va_list s_var)
{
#if defined(__GNUC__)
    return(vsnprintf(s_output, s_max_output_size, s_format, s_var));
#else
    size_t s_output_offset = (size_t)0u;
    size_t s_format_offset = (size_t)0u;
    const unsigned char *s_byte_ptr;

    int s_is_sharp;
    int s_is_negative_sign;
    int s_is_zero;
    int s_is_long;

    unsigned int s_width1, s_width2 = 0u;

    int s_temp_value_i;
    unsigned int s_temp_value_u;
# if def_hwport_ftpd_can_use_long_long != (0L)
    long long s_temp_value_ill;
    unsigned long long s_temp_value_ull;
# endif

    if(hwport_ftpd_builtin_expect(s_max_output_size <= ((size_t)1u), 0)) {
        if(s_max_output_size == ((size_t)1u)) {
            s_output[0] = '\0';
        }
        return(0);
    }
    --s_max_output_size;

    while(s_format[s_format_offset] != '\0') {
        /* '%' check */
        if(s_format[s_format_offset] != '%') {
            /* copy */
            if(s_output_offset >= s_max_output_size) {
                break;
            }
            s_output[s_output_offset++] = s_format[s_format_offset++];
            continue;
        }
        ++s_format_offset;

        /* '#' check */
        if(s_format[s_format_offset] == '#') {
            s_is_sharp = 1;
            ++s_format_offset;
        }
        else {
            s_is_sharp = 0;
        }
         
        /* '-' check */
        if(s_format[s_format_offset] == '-') {
            s_is_negative_sign = 1;
            ++s_format_offset;
        }
        else {
            s_is_negative_sign = 0;
        }
        
        /* '0' check */
        if(s_format[s_format_offset] == g_hwport_ftpd_vsprintf_digits[0][0]) {
            s_is_zero = 1;
            ++s_format_offset;
        }
        else {
            s_is_zero = 0;
        }
      
        /* '*' check */
        s_width1 = 0u; 
        if(s_format[s_format_offset] == '*') { 
            s_width1 = va_arg(s_var, unsigned int);
            ++s_format_offset;
        }

        /* ['0'..'9']... check */
        while(/* (s_format[s_format_offset] != '\0') && */ (hwport_ftpd_isdigit(s_format[s_format_offset]) != 0)) { 
            s_width1 += (unsigned int)(s_format[s_format_offset++] - g_hwport_ftpd_vsprintf_digits[0][0]);
            if(hwport_ftpd_isdigit(s_format[s_format_offset]) != 0) { 
                s_width1 *= 10u;
            }
        }

        /* '.' check */
        if(s_format[s_format_offset] == '.') { 
            ++s_format_offset;
            s_width2 = 0u;
            /* ['0'..'9']... check */
            while(/* (s_format[s_format_offset] != '\0') && */ (hwport_ftpd_isdigit(s_format[s_format_offset]) != 0)) { 
                s_width2 += (unsigned int)(s_format[s_format_offset++] - g_hwport_ftpd_vsprintf_digits[0][0]);
                if(hwport_ftpd_isdigit(s_format[s_format_offset]) != 0) { 
                    s_width2 *= 10u;
                }
            }
        }

        /* ['l']... check */
        s_is_long = 0;
        if(s_format[s_format_offset] == 'l') { 
            ++s_is_long;
            ++s_format_offset;
        }
#if def_hwport_ftpd_can_use_long_long != (0L)
        if(s_format[s_format_offset] == 'l') { 
            ++s_is_long;
            ++s_format_offset;
        }
#endif

        switch(s_format[s_format_offset]) {
            case 'c': /* character */
                s_temp_value_u = (unsigned int)va_arg(s_var, unsigned int);
                if(s_output_offset >= s_max_output_size) {
                    break;
                }
                s_output[s_output_offset++] = (char)(s_temp_value_u & 0x000000FFu);
                break;
            case 'i': /* signed decimal */
            case 'd': /* signed decimal */
                switch(s_is_long) {
                    case 0:
                    case 1:
                        s_temp_value_i = (int)va_arg(s_var, int);
                        if(s_temp_value_i < 0) {
                            if(s_output_offset >= s_max_output_size) {
                                break;
                            }
                            s_output[s_output_offset++] = '-';
                            s_temp_value_i = -s_temp_value_i;
                        }
                        s_output_offset += hwport_ftpd_xtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, (unsigned int)s_temp_value_i, 10u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), g_hwport_ftpd_vsprintf_digits[0]);
                        break;
#if def_hwport_ftpd_can_use_long_long != (0L)
                    case 2:
                        s_temp_value_ill = (long long)va_arg(s_var, long long);
                        if(s_temp_value_ill < 0ll) {
                            if(s_output_offset >= s_max_output_size) {
                                break;
                            }
                            s_output[s_output_offset++] = '-';
                            s_temp_value_ill = -s_temp_value_ill;
                        }
                        s_output_offset += hwport_ftpd_llxtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, (unsigned long long)s_temp_value_ill, 10u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), g_hwport_ftpd_vsprintf_digits[0]);
                        break;
#endif
                }
                break;
            case 'p': /* pointer (lower case) */
            case 'P': /* pointer (upper case) */
#if defined(__long64) && (def_hwport_ftpd_can_use_long_long != (0L))
                s_temp_value_ull = (unsigned long long)va_arg(s_var, unsigned long long);
                s_output_offset += hwport_ftpd_llxtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_ull, 16u, 16u, (s_format[s_format_offset] == 'P') ? g_hwport_ftpd_vsprintf_digits[0] : g_hwport_ftpd_vsprintf_digits[1]);
#else
                s_temp_value_u = (unsigned int)va_arg(s_var, unsigned int);
                s_output_offset += hwport_ftpd_xtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_u, 16u, 8u, (s_format[s_format_offset] == 'P') ? g_hwport_ftpd_vsprintf_digits[0] : g_hwport_ftpd_vsprintf_digits[1]);
#endif
                break;
            case 's': /* string */
                s_byte_ptr = (const unsigned char *)va_arg(s_var, const unsigned char *);
                if(s_byte_ptr == ((const unsigned char *)0)) {
                    s_byte_ptr = (const unsigned char *)"(null)";
                }

                if((s_width1 == 0u) && (s_width2 == 0u)) {
                    while(s_byte_ptr[0] != '\0') {
                        if(s_output_offset >= s_max_output_size) {
                            break;
                        }
                        s_output[s_output_offset++] = (char)s_byte_ptr[0];
                        s_byte_ptr = (const unsigned char *)(&s_byte_ptr[1]);
                    }
                    break;
                }

                s_temp_value_u = 0u;
                while(s_byte_ptr[s_temp_value_u] != '\0') {
                    ++s_temp_value_u;
                }
 
                s_temp_value_u = (s_width1 > s_temp_value_u) ? (s_width1 - s_temp_value_u) : 0u;
                if(s_is_negative_sign == 0u) {
                    while((s_temp_value_u--) > 0u) {
                        if(s_output_offset >= s_max_output_size) {
                            break;
                        }
                        s_output[s_output_offset++] = ' ';
                    }
                }
                while(((s_width1--) > 0u) && (s_byte_ptr[0] != '\0')) {
                    if(s_output_offset >= s_max_output_size) {
                        break;
                    }
                    s_output[s_output_offset++] = (char)s_byte_ptr[0];
                    s_byte_ptr = (const unsigned char *)(&s_byte_ptr[1]);
                }
                if(s_is_negative_sign != 0u) {
                    while((s_temp_value_u--) > 0u) {
                        if(s_output_offset >= s_max_output_size) {
                            break;
                        }
                        s_output[s_output_offset++] = ' ';
                    }
                }
                break;
            case 'u': /* unsigned decimal */
                switch(s_is_long) {
                    case 0:
                    case 1:
                        s_temp_value_u = (unsigned int)va_arg(s_var, unsigned int);
                        s_output_offset += hwport_ftpd_xtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_u, 10u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), g_hwport_ftpd_vsprintf_digits[0]);
                        break;
#if def_hwport_ftpd_can_use_long_long != (0L)
                    case 2:
                        s_temp_value_ull = (unsigned long long)va_arg(s_var, unsigned long long);
                        s_output_offset += hwport_ftpd_llxtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_ull, 10u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), g_hwport_ftpd_vsprintf_digits[0]);
                        break;
#endif
                }
                break;
            case 'x': /* hexa decimal (lower case) */
            case 'X': /* hexa decimal (upper case) */
                switch(s_is_long) {
                    case 0:
                    case 1:
                        s_temp_value_u = (unsigned int)va_arg(s_var, unsigned int);
                        s_output_offset += hwport_ftpd_xtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_u, 16u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), (s_format[s_format_offset] == 'X') ? g_hwport_ftpd_vsprintf_digits[0] : g_hwport_ftpd_vsprintf_digits[1]);
                        break;
#if def_hwport_ftpd_can_use_long_long != (0L)
                    case 2:
                        s_temp_value_ull = (unsigned long long)va_arg(s_var, unsigned long long);
                        s_output_offset += hwport_ftpd_llxtoa_limit((char *)(&s_output[s_output_offset]), s_max_output_size - s_output_offset, s_temp_value_ull, 16u, s_width1 | ((s_is_zero == 0) ? 0x80000000u : 0u), (s_format[s_format_offset] == 'X') ? g_hwport_ftpd_vsprintf_digits[0] : g_hwport_ftpd_vsprintf_digits[1]);
                        break;
#endif
                }
                break;
            default:
                if(s_output_offset >= s_max_output_size) {
                    break;
                }
                s_output[s_output_offset++] = s_format[s_format_offset++];
                break;
        }

        ++s_format_offset;
    }

    s_output[s_output_offset] = '\0';

    return((int)s_output_offset);
#endif    
}

int hwport_ftpd_vsprintf(char *s_output, const char *s_format, va_list s_var)
{
    return(hwport_ftpd_vsnprintf(s_output, ~((size_t)0), s_format, s_var));
}

int hwport_ftpd_snprintf(char *s_output, size_t s_max_output_size, const char *s_format, ...)
{
    va_list s_var;

    int s_result;

    va_start(s_var, s_format);

    s_result = hwport_ftpd_vsnprintf(s_output, s_max_output_size, s_format, s_var);

    va_end(s_var);

    return(s_result);
}

int hwport_ftpd_sprintf(char *s_output, const char *s_format, ...)
{
    va_list s_var;

    int s_result;

    va_start(s_var, s_format);

    s_result = hwport_ftpd_vsprintf(s_output, s_format, s_var);

    va_end(s_var);

    return(s_result);
}

/* ---- */

char *hwport_ftpd_alloc_vsprintf(const char *s_format, va_list s_var)
{
    char *s_result;
    size_t s_size;

    s_size = (size_t)256u;
    do {
        s_result = (char *)malloc(s_size);

        if(hwport_ftpd_builtin_expect(s_result == ((char *)0), 0)) {
            /* errno = ENOMEM */
            return((char *)0);
        }

        if(hwport_ftpd_vsnprintf(s_result, s_size - ((size_t)1u), s_format, s_var) < ((int)s_size)) {
            return(s_result);
        }

        free((void *)s_result);
        s_result = (void *)0;

        s_size += (size_t)256u;
    }while(s_size < ((size_t)(32 << 10)));

    return(s_result);
}

char *hwport_ftpd_alloc_sprintf(const char *s_format, ...)
{
    char *s_result;
    
    va_list s_var;

    va_start(s_var, s_format);

    s_result = hwport_ftpd_alloc_vsprintf(s_format, s_var);

    va_end(s_var);

    return(s_result);
}

/* ---- */

char *hwport_ftpd_get_word_sep(int s_skip_space, const char *s_sep, char **s_sep_string)
{
    unsigned char *s_string, *s_result;
    const unsigned char *s_sep_ptr;

    s_result = s_string = (unsigned char *)(*(s_sep_string));

    if(s_skip_space != 0) {
        while(hwport_ftpd_isspace((int)s_string[0]) != 0) {
            s_string = (unsigned char *)(&s_string[1]);
        }
        s_result = s_string;
    }

    while(s_string[0] != '\0') {
        s_sep_ptr = (const unsigned char *)s_sep;
        while((s_string[0] != s_sep_ptr[0]) && (s_sep_ptr[0] != '\0')) {
            s_sep_ptr = (const unsigned char *)(&s_sep_ptr[1]);
        }
        if(s_string[0] == s_sep_ptr[0]) {
            break;
        }
        s_string = (unsigned char *)(&s_string[1]);
    }
    
    *(s_sep_string) = (char *)s_string;

    return((char *)s_result);
}

char *hwport_ftpd_get_word_sep_alloc(int s_skip_space, const char *s_sep, const char **s_sep_string)
{
    char *s_result;

    size_t s_token_size;
    const unsigned char *s_string;
    const unsigned char *s_left;
    const unsigned char *s_right;
    const unsigned char *s_sep_ptr;

    s_string = (const unsigned char *)(*(s_sep_string));

    if(s_skip_space != 0) {
        while(hwport_ftpd_isspace((int)s_string[0]) != 0) {
            s_string = (const unsigned char *)(&s_string[1]);
        }
        s_right = s_left = s_string;
        while(s_string[0] != '\0') {
            s_sep_ptr = (const unsigned char *)s_sep;
            while((s_string[0] != s_sep_ptr[0]) && (s_sep_ptr[0] != '\0')) {
                s_sep_ptr = (const unsigned char *)(&s_sep_ptr[1]);
            }
            if(s_string[0] == s_sep_ptr[0]) {
                break;
            }
            s_string = (const unsigned char *)(&s_string[1]);
            if(hwport_ftpd_isspace((int)s_string[0]) == 0) {
                s_right = s_string;
            }
        }
    }
    else {
        s_right = s_left = s_string;
        while(s_string[0] != '\0') {
            s_sep_ptr = (const unsigned char *)s_sep;
            while((s_string[0] != s_sep_ptr[0]) && (s_sep_ptr[0] != '\0')) {
                s_sep_ptr = (const unsigned char *)(&s_sep_ptr[1]);
            }
            if(s_string[0] == s_sep_ptr[0]) {
                break;
            }
            s_string = (const unsigned char *)(&s_string[1]);
            s_right = s_string;
        }
    }
    
    s_token_size = (size_t)(s_right - s_left);
    s_result = (char *)malloc(s_token_size + ((size_t)1u));
    if(s_result != ((char *)0)) {
        if(s_token_size > ((size_t)0)) {
            (void)memcpy((void *)s_result, (const void *)s_left, s_token_size);
        }
        s_result[s_token_size] = '\0';
    }

    *(s_sep_string) = (const char *)s_string;

    return(s_result);
}

/* ---- */

int hwport_ftpd_check_pattern(const char *s_pattern, const char *s_string)
{
    size_t s_pattern_offset;
    size_t s_string_offset;
    unsigned char s_pattern_byte;
    unsigned char s_string_byte;

    s_pattern_offset = (size_t)0u;
    s_string_offset = (size_t)0u;

    for(;;) {
        s_pattern_byte = (unsigned char)s_pattern[s_pattern_offset];
        s_string_byte = (unsigned char)s_string[s_string_offset];

        if(s_pattern_byte == ((unsigned char)0u)) {
            break;
        }

        if(s_pattern_byte == ((unsigned char)'*')) {
            ++s_pattern_offset;
            s_pattern_byte = (unsigned char)s_pattern[s_pattern_offset];
            if(s_pattern_byte == ((unsigned char)'\\')) {
                ++s_pattern_offset;
                s_pattern_byte = (unsigned char)s_pattern[s_pattern_offset];
            }
            while(s_string_byte != ((unsigned char)0u)) {
                if(s_pattern_byte == s_string_byte)break;
                ++s_string_offset;
                s_string_byte = (unsigned char)s_string[s_string_offset];
            }
            if(s_pattern_byte == ((unsigned char)0u)) {
                break;
            }
        }
        else if(s_pattern_byte == ((unsigned char)'?')) {
            if(s_string_byte == ((unsigned char)0u)) {
                return(-1);
            }
        }
        else {
            if(s_pattern_byte == ((unsigned char)'\\')) {
                ++s_pattern_offset;
                s_pattern_byte = (unsigned char)s_pattern[s_pattern_offset];
                if(s_pattern_byte == ((unsigned char)0u)) {
                    break;
                }
            }
            if(s_pattern_byte != s_string_byte) {
                return(-1);
            }
        }
        ++s_pattern_offset;
        if(s_string_byte != ((unsigned char)0u)) {
            ++s_string_offset;
        }
    }

    return((s_pattern_byte == s_string_byte) ? 0 : (-1));
}

/* ---- */

static int hwport_ftpd_check_ignore_path_node(hwport_ftpd_path_node_t *s_current)
{
    hwport_ftpd_path_node_t *s_trace;
    size_t s_name_size;

    s_name_size = (s_current->m_name == ((char *)0)) ? ((size_t)0u) : hwport_ftpd_strlen(s_current->m_name);

    if(s_name_size == ((size_t)0u)) {
        if(s_current->m_prev != ((hwport_ftpd_path_node_t *)0)) {
            s_current->m_ignore = 1u;
        }
        
        return(0);
    }

    if(hwport_ftpd_strcmp(s_current->m_name, "..") == 0) {
        s_current->m_ignore = 1u;
        
        s_trace = s_current->m_prev;
        while(s_trace != ((hwport_ftpd_path_node_t *)0)) {
            if(s_trace->m_ignore == 0u) {
                s_name_size = (s_trace->m_name == ((char *)0)) ? ((size_t)0u) : hwport_ftpd_strlen(s_trace->m_name);

                if(s_name_size > ((size_t)0u)) {
                    s_trace->m_ignore = 1u;
                }
                break;
            }
            s_trace = s_trace->m_prev;
        }

        return(0);
    }
    
    if(hwport_ftpd_strcmp(s_current->m_name, ".") == 0) {
        s_current->m_ignore = 1u;
        return(0);
    }

    return(0);
}

hwport_ftpd_path_node_t *hwport_ftpd_free_path_node(hwport_ftpd_path_node_t *s_node)
{
    hwport_ftpd_path_node_t *s_prev;
    
    while(s_node != ((hwport_ftpd_path_node_t *)0)) {
        s_prev = s_node;
        s_node = s_node->m_next;

        if(s_prev->m_name != ((char *)0)) {
            free((void *)s_prev->m_name);
        }
        free((void *)s_prev);
    }

    return((hwport_ftpd_path_node_t *)0);
}

hwport_ftpd_path_node_t *hwport_ftpd_path_to_node(const char *s_path)
{
    hwport_ftpd_path_node_t *s_head = (hwport_ftpd_path_node_t *)0;
    hwport_ftpd_path_node_t *s_tail = (hwport_ftpd_path_node_t *)0;
    hwport_ftpd_path_node_t *s_new;
    char *s_name;

    if(hwport_ftpd_builtin_expect(s_path == ((const char *)0), 0)) {
        return((hwport_ftpd_path_node_t *)0);
    }
     
    while(s_path[0] != '\0') {
        s_name = hwport_ftpd_get_word_sep_alloc(0, "/\\", (const char **)(&s_path));
        if(s_name == ((char *)0)) {
            break;
        }

        if(s_path[0] != '\0') {
            s_path = (const char *)(&s_path[1]);
        }

        s_new = (hwport_ftpd_path_node_t *)malloc(sizeof(hwport_ftpd_path_node_t));        
        if(s_new == ((hwport_ftpd_path_node_t *)0)) {
            free((void *)s_name);
            return(hwport_ftpd_free_path_node(s_head));
        }

        s_new->m_prev = s_tail;
        s_new->m_next = (hwport_ftpd_path_node_t *)0;
        s_new->m_ignore = 0u;
        s_new->m_name = s_name;

        if(s_tail == ((hwport_ftpd_path_node_t *)0)) {
            s_head = s_new;
        }
        else {
            s_tail->m_next = s_new;
        }
        
        s_tail = s_new;

        (void)hwport_ftpd_check_ignore_path_node(s_new);
    }
     
    return(s_head);
}

char *hwport_ftpd_node_to_path(hwport_ftpd_path_node_t *s_node, int s_strip)
{
    char *s_result;
    hwport_ftpd_path_node_t *s_trace;
    hwport_ftpd_path_node_t *s_trace2;
    size_t s_alloc_size;
    size_t s_name_size;
    
    if(hwport_ftpd_builtin_expect(s_node == ((hwport_ftpd_path_node_t *)0), 0)) {
        return((char *)0);
    }

    s_alloc_size = (size_t)0u;
    s_trace = s_node;
    while(s_trace != ((hwport_ftpd_path_node_t *)0)) {
        if(s_strip != 0) {
            if(s_trace->m_ignore != 0u) {
                s_trace = s_trace->m_next;
                continue;
            }
        }

        s_trace2 = s_trace->m_next;
        while((s_strip != 0) && (s_trace2 != ((hwport_ftpd_path_node_t *)0))) {
            if(s_trace2->m_ignore == 0u) {
                break;
            }
            s_trace2 = s_trace2->m_next;
        }
        
        s_name_size = (s_trace->m_name == ((char *)0)) ? ((size_t)0u) : hwport_ftpd_strlen(s_trace->m_name);
        if(s_trace2 == ((hwport_ftpd_path_node_t *)0)) {
            if(s_name_size <= ((size_t)0u)) {
                s_alloc_size += ((size_t)1u) + ((size_t)1u);
            }
            else {
                s_alloc_size += s_name_size + ((size_t)1u);
            }
        }
        else {
            s_alloc_size += s_name_size + ((size_t)1u);
        }

        s_trace = s_trace->m_next;
    }
   
    s_result = (char *)malloc(s_alloc_size);
    if(hwport_ftpd_builtin_expect(s_result == ((char *)0), 0)) {
        /* errno = ENOMEM */
        return((char *)0);
    }

    s_alloc_size = (size_t)0u;
    s_trace = s_node;
    while(s_trace != ((hwport_ftpd_path_node_t *)0)) {
        if(s_strip != 0) {
            if(s_trace->m_ignore != 0u) {
                s_trace = s_trace->m_next;
                continue;
            }
        }

        s_trace2 = s_trace->m_next;
        while((s_strip != 0) && (s_trace2 != ((hwport_ftpd_path_node_t *)0))) {
            if(s_trace2->m_ignore == 0u) {
                break;
            }
            s_trace2 = s_trace2->m_next;
        }
        
        s_name_size = (s_trace->m_name == ((char *)0)) ? ((size_t)0u) : hwport_ftpd_strlen(s_trace->m_name);

        if(s_trace2 == ((hwport_ftpd_path_node_t *)0)) {
            if(s_name_size <= ((size_t)0u)) {
                s_alloc_size += (size_t)hwport_ftpd_sprintf((char *)(&s_result[s_alloc_size]), "/");
            }
            else {
                s_alloc_size += (size_t)hwport_ftpd_sprintf((char *)(&s_result[s_alloc_size]), "%s", s_trace->m_name);
            }
        }
        else {
            s_alloc_size += (size_t)hwport_ftpd_sprintf((char *)(&s_result[s_alloc_size]), "%s%s", s_trace->m_name, "/");
        }

        s_trace = s_trace->m_next;
    }

    return(s_result);
}

hwport_ftpd_path_node_t *hwport_ftpd_copy_path_node(hwport_ftpd_path_node_t *s_node)
{
    hwport_ftpd_path_node_t *s_result;
    char *s_path;

    s_path = hwport_ftpd_node_to_path(s_node, 0);
    if(hwport_ftpd_builtin_expect(s_path == ((char *)0), 0)) {
        return((hwport_ftpd_path_node_t *)0);
    }

    s_result = hwport_ftpd_path_to_node(s_path);

    free((void *)s_path);

    return(s_result);
}

hwport_ftpd_path_node_t *hwport_ftpd_append_path_node(hwport_ftpd_path_node_t *s_head, hwport_ftpd_path_node_t *s_node, int s_override)
{
    hwport_ftpd_path_node_t *s_temp;

    if(s_override != 0) {
        if(s_node != ((hwport_ftpd_path_node_t *)0)) {
            if(s_node->m_name != ((char *)0)) {
                if(hwport_ftpd_strlen(s_node->m_name) <= ((size_t)0u)) {
                    s_head = hwport_ftpd_free_path_node(s_head); 
                }
            }
        }
    }

    if(s_head == ((hwport_ftpd_path_node_t *)0)) {
        if(s_node != ((hwport_ftpd_path_node_t *)0)) {
            s_node->m_prev = (hwport_ftpd_path_node_t *)0;
        }
        s_head = s_node;
        s_node = (hwport_ftpd_path_node_t *)0;
    }
        
    if(s_node != ((hwport_ftpd_path_node_t *)0)) {
        s_temp = s_head;
        while(s_temp->m_next != ((hwport_ftpd_path_node_t *)0)) {
            s_temp = s_temp->m_next;
        }
        s_node->m_prev = s_temp;
        s_temp->m_next = s_node;
    }
        
    /* clear ignore */
    s_temp = s_head;
    while(s_temp != ((hwport_ftpd_path_node_t *)0)) {
        s_temp->m_ignore = 0;
        s_temp = s_temp->m_next;
    }

    /* restrip */
    s_temp = s_head;
    while(s_temp != ((hwport_ftpd_path_node_t *)0)) {
        (void)hwport_ftpd_check_ignore_path_node(s_temp);
        s_temp = s_temp->m_next;
    }
        
    return(s_head);
}

/* ---- */

char *hwport_ftpd_basename(char *s_pathname)
{
    static char sg_dot_string[] = {"."};
    char *s_result;
    size_t s_count;
    size_t s_offset;

    if(hwport_ftpd_builtin_expect(s_pathname == ((char *)0), 0)) {
        return((char *)(&sg_dot_string[0]));
    }

    if(hwport_ftpd_builtin_expect(s_pathname[0] == ((char)0), 0)) {
        return(s_pathname);
    }

    s_count = (size_t)0u;
    s_offset = hwport_ftpd_strlen(s_pathname);
    while(s_offset > ((size_t)0u)) {
        if((s_pathname[s_offset - ((size_t)1u)] == ((unsigned char)'/')) ||
           (s_pathname[s_offset - ((size_t)1u)] == ((unsigned char)'\\'))) {
            if(s_count > ((size_t)0u)) {
                break;
            }
            if(s_offset > ((size_t)1u)) {
                s_pathname[s_offset - ((size_t)1u)] = '\0';
            }
        }
        else {
            ++s_count;
        }
        --s_offset;
    }
    
    s_result = (char *)(&s_pathname[s_offset]);
    if(hwport_ftpd_strlen(s_result) <= ((size_t)0u)) {
        return((char *)(&sg_dot_string[0]));
    }
        
    return(s_result);
}

/* ---- */

/* 
 ip         IP         internet protocol, pseudo protocol number
 icmp       ICMP       internet control message protocol
 igmp       IGMP       Internet Group Management
 ggp        GGP        gateway-gateway protocol
 ipencap    IP-ENCAP   IP encapsulated in IP (officially ``IP'')
 st         ST         ST datagram mode
 tcp        TCP        transmission control protocol
 egp        EGP        exterior gateway protocol
 pup        PUP        PARC universal packet protocol
 udp        UDP        user datagram protocol
 hmp        HMP        host monitoring protocol
 xns-idp    XNS-IDP    Xerox NS IDP
 rdp        RDP        "reliable datagram" protocol
 iso-tp4    ISO-TP4    ISO Transport Protocol class 4
 xtp        XTP        Xpress Tranfer Protocol
 ddp        DDP        Datagram Delivery Protocol
 idpr-cmtp  IDPR-CMTP  IDPR Control Message Transport
 ipv6       IPv6       IPv6
 ipv6-route IPv6-Route Routing Header for IPv6
 ipv6-frag  IPv6-Frag  Fragment Header for IPv6
 idrp       IDRP       Inter-Domain Routing Protocol
 rsvp       RSVP       Reservation Protocol
 gre        GRE        General Routing Encapsulation
 esp        ESP        Encap Security Payload for IPv6
 ah         AH         Authentication Header for IPv6
 skip       SKIP       SKIP
 ipv6-icmp  IPv6-ICMP  ICMP for IPv6
 ipv6-nonxt IPv6-NoNxt No Next Header for IPv6
 ipv6-opts  IPv6-Opts  Destination Options for IPv6
 rspf       RSPF       Radio Shortest Path First.
 vmtp       VMTP       Versatile Message Transport
 ospf       OSPFIGP    Open Shortest Path First IGP
 ipip       IPIP       IP-within-IP Encapsulation Protocol
 encap      ENCAP      Yet Another IP encapsulation
 pim        PIM        Protocol Independent Multicast
*/
hwport_ftpd_sockprotocol_t hwport_ftpd_get_protocol_by_name(const char *s_protocol_name)
{
#if def_hwport_ftpd_use_pthread != (0L)
    static pthread_mutex_t sg_mutex = PTHREAD_MUTEX_INITIALIZER; 
#endif    
    hwport_ftpd_sockprotocol_t s_result;
    struct protoent *s_protocol_entry;

    struct {
        const char *m_name;
        hwport_ftpd_sockprotocol_t m_value;
    } s_pre_compare_table[] = {
#if defined(IPPROTO_TCP)    
        {"tcp", IPPROTO_TCP},
#endif
#if defined(IPPROTO_UDP)    
        {"udp", IPPROTO_UDP},
#endif
#if defined(IPPROTO_ICMP)    
        {"icmp", IPPROTO_ICMP},
#endif
#if defined(IPPROTO_ICMPV6)    
        {"ipv6-icmp", IPPROTO_ICMPV6},
#endif
#if defined(IPPROTO_IP)    
        {"ip", IPPROTO_IP},
#endif
#if defined(IPPROTO_IPV6)    
        {"ipv6", IPPROTO_IPV6},
#endif
        {(const char *)0, (hwport_ftpd_sockprotocol_t)0}
    };
    int s_pre_compare_index = 0;

    if(hwport_ftpd_builtin_expect(s_protocol_name == ((const char *)0), 0)) {
        /* errno = EINVAL */
        return((hwport_ftpd_sockprotocol_t)0);
    }

    while(s_pre_compare_table[s_pre_compare_index].m_name != ((const char *)0)) {
        if(hwport_ftpd_strcmp(s_protocol_name, s_pre_compare_table[s_pre_compare_index].m_name) == 0) {
            return(s_pre_compare_table[s_pre_compare_index].m_value);
        }
        ++s_pre_compare_index;
    }
       
#if def_hwport_ftpd_use_pthread != (0L)       
    /* int pthread_mutex_lock(pthread_mutex_t *mutex) */
    if(hwport_ftpd_builtin_expect(pthread_mutex_lock((pthread_mutex_t *)(&sg_mutex)) != 0, 0)) {
        /* errno = EBUSY */
        return((hwport_ftpd_sockprotocol_t)0);
    }
#endif    

    /* struct protoent *getprotobyname(const char *name) */
    s_protocol_entry = getprotobyname(s_protocol_name);
    s_result = (s_protocol_entry != ((struct protoent *)0)) ? ((hwport_ftpd_sockprotocol_t)s_protocol_entry->p_proto) : ((hwport_ftpd_sockprotocol_t)0);
    
#if def_hwport_ftpd_use_pthread != (0L)       
    /* int pthread_mutex_unlock(pthread_mutex_t *mutex) */
    (void)pthread_mutex_unlock((pthread_mutex_t *)(&sg_mutex));
#endif    

    return(s_result);
}

/* ---- */

hwport_ftpd_socket_t hwport_ftpd_socket_open(hwport_ftpd_sockdomain_t s_domain, hwport_ftpd_sockfamily_t s_type, hwport_ftpd_sockprotocol_t s_protocol)
{
    int s_socket;

    s_socket = socket((int)s_domain, (int)s_type, (int)s_protocol);
    if(hwport_ftpd_builtin_expect(s_socket == (-1), 0)) {
        /* errno = ... */
        return((hwport_ftpd_socket_t)(-1));
    }

    return((hwport_ftpd_socket_t)s_socket);
}

hwport_ftpd_socket_t hwport_ftpd_socket_close(hwport_ftpd_socket_t s_socket)
{
    int s_check;

    if(hwport_ftpd_builtin_expect(s_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        /* errno = EINVAL */
        return((hwport_ftpd_socket_t)(-1));
    }

#if defined(def_hwport_ftpd_windows)
    (void)s_check;
    _close((int)s_socket);
#else
    do {
        s_check = close((int)s_socket);
    }while((s_check == (-1)) && (errno == EINTR));
#endif    

    return((hwport_ftpd_socket_t)(-1));
}

/* ---- */

int hwport_ftpd_bind(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size)
{
    if(hwport_ftpd_builtin_expect(bind((int)s_socket, (const struct sockaddr *)s_sockaddr_ptr, (socklen_t)s_sockaddr_size) != 0, 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

int hwport_ftpd_listen(hwport_ftpd_socket_t s_socket, int s_backlog)
{
    if(hwport_ftpd_builtin_expect(listen((int)s_socket, s_backlog) != 0, 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

hwport_ftpd_socket_t hwport_ftpd_accept(hwport_ftpd_socket_t s_listen_socket, void *s_sockaddr_ptr, hwport_ftpd_socklen_t *s_sockaddr_size_ptr, int s_msec)
{
    int s_accept_socket;

    if(s_msec >= 0) {
        struct timeval s_timeval;
        fd_set s_rx;
        int s_check;

        s_timeval.tv_sec = s_msec / 1000;
        s_timeval.tv_usec = (s_msec % 1000) * 1000;

        FD_ZERO(&s_rx);
        FD_SET(s_listen_socket, &s_rx);

        s_check = select(((int)s_listen_socket) + 1, (fd_set *)(&s_rx), (fd_set *)0, (fd_set *)0, (struct timeval *)(&s_timeval));
        if(hwport_ftpd_builtin_expect(s_check == (-1), 0)) {
            /* errno = ... */
            return((hwport_ftpd_socket_t)(-1));
        }
        if(s_check == 0) {
            /* errno = ETIMEOUT */
            return((hwport_ftpd_socket_t)(-1));
        }
        if(hwport_ftpd_builtin_expect(FD_ISSET(s_listen_socket, &s_rx) == 0, 0)) {
            /* errno = EAGAIN */
            return((hwport_ftpd_socket_t)(-1));
        }
    }

    /* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) */
    s_accept_socket = accept((int)s_listen_socket, (struct sockaddr *)s_sockaddr_ptr, (socklen_t *)s_sockaddr_size_ptr);
    if(hwport_ftpd_builtin_expect(s_accept_socket == (-1), 0)) {
        /* errno = ... */
        return((hwport_ftpd_socket_t)(-1));
    }

    return(s_accept_socket);
}

int hwport_ftpd_connect(hwport_ftpd_socket_t s_socket, const void *s_sockaddr_ptr, hwport_ftpd_socklen_t s_sockaddr_size, int s_msec)
{
    (void)s_msec; /* TODO: non-blocking CONN wait */

    /* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) */
    if(hwport_ftpd_builtin_expect(connect(s_socket, (const struct sockaddr *)s_sockaddr_ptr, (socklen_t)s_sockaddr_size) != 0, 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

ssize_t hwport_ftpd_recv(hwport_ftpd_socket_t s_socket, void *s_data, size_t s_size, int s_msec)
{
    ssize_t s_result;
    
    if(s_msec >= 0) {
        struct timeval s_timeval;
        fd_set s_rx;
        int s_check;

        s_timeval.tv_sec = s_msec / 1000;
        s_timeval.tv_usec = (s_msec % 1000) * 1000;

        FD_ZERO(&s_rx);
        FD_SET(s_socket, &s_rx);

        s_check = select(((int)s_socket) + 1, (fd_set *)(&s_rx), (fd_set *)0, (fd_set *)0, (struct timeval *)(&s_timeval));
        if(hwport_ftpd_builtin_expect(s_check == (-1), 0)) {
            /* errno = ... */
            return((ssize_t)(-1));
        }
        if(s_check == 0) {
            /* errno = ETIMEOUT */
            return((ssize_t)(-2));
        }
        if(hwport_ftpd_builtin_expect(FD_ISSET(s_socket, &s_rx) == 0, 0)) {
            /* errno = EAGAIN */
            return((ssize_t)(-1));
        }
    }

    /* ssize_t recv(int sockfd, void *buf, size_t len, int flags) */
#if defined(def_hwport_ftpd_windows)
    s_result = (ssize_t)recv((int)s_socket, s_data, (size_t)s_size, 0);
#else
    s_result = (ssize_t)recv((int)s_socket, s_data, (size_t)s_size, MSG_NOSIGNAL);
#endif
    if(s_result == ((ssize_t)(-1))) {
        /* errno = ... */
        return((ssize_t)(-1));
    }
    if(s_result == ((ssize_t)0)) {
        /* errno = EEOF */
        return((ssize_t)0);
    }

    return(s_result);
}

ssize_t hwport_ftpd_send(hwport_ftpd_socket_t s_socket, const void *s_data, size_t s_size, int s_msec)
{
    ssize_t s_result;
    
    if(s_msec >= 0) {
        struct timeval s_timeval;
        fd_set s_tx;
        int s_check;

        s_timeval.tv_sec = s_msec / 1000;
        s_timeval.tv_usec = (s_msec % 1000) * 1000;

        FD_ZERO(&s_tx);
        FD_SET(s_socket, &s_tx);

        s_check = select(((int)s_socket) + 1, (fd_set *)0, (fd_set *)(&s_tx), (fd_set *)0, (struct timeval *)(&s_timeval));
        if(hwport_ftpd_builtin_expect(s_check == (-1), 0)) {
            /* errno = ... */
            return((ssize_t)(-1));
        }
        if(s_check == 0) {
            /* errno = ETIMEOUT */
            return((ssize_t)0);
        }
        if(hwport_ftpd_builtin_expect(FD_ISSET(s_socket, &s_tx) == 0, 0)) {
            /* errno = EAGAIN */
            return((ssize_t)(-1));
        }
    }

    /* ssize_t send(int sockfd, const void *buf, size_t len, int flags) */
#if defined(def_hwport_ftpd_windows)
    s_result = (ssize_t)send((int)s_socket, s_data, (size_t)s_size, 0);
#else
    s_result = (ssize_t)send((int)s_socket, s_data, (size_t)s_size, MSG_NOSIGNAL);
#endif
    if(s_result == ((ssize_t)(-1))) {
        /* errno = ... */
        return((ssize_t)(-1));
    }

    return(s_result);
}

ssize_t hwport_ftpd_send_message(hwport_ftpd_socket_t s_socket, int s_msec, const char *s_format, ...)
{
    ssize_t s_send_bytes;
    void *s_buffer;
    va_list s_var;

    va_start(s_var, s_format);
    s_buffer = hwport_ftpd_alloc_vsprintf(s_format, s_var);
    va_end(s_var);

    if(hwport_ftpd_builtin_expect(s_buffer == ((void *)0), 0)) {
        /* errno = ENOMEM */
        return((ssize_t)(-1));
    }

    s_send_bytes = hwport_ftpd_send(s_socket, (const void *)s_buffer, hwport_ftpd_strlen((const char *)s_buffer), s_msec);
    free(s_buffer);

    return(s_send_bytes);
}

/* ---- */

const char *hwport_ftpd_inet_ntop(hwport_ftpd_sockfamily_t s_family, const void *s_inX_addr_ptr, char *s_address, hwport_ftpd_socklen_t s_address_size)
{
    if(hwport_ftpd_builtin_expect((s_address == ((char *)0)) || (s_address_size <= ((hwport_ftpd_socklen_t)0)), 0)) {
        return((const char *)0);
    }

#if (def_hwport_ftpd_can_use_ipv4 != 0L) && defined(AF_INET)
    if(s_family == AF_INET) {
        const unsigned char *s_byte_ptr = (const unsigned char *)s_inX_addr_ptr;

        (void)hwport_ftpd_snprintf(s_address, (size_t)s_address_size, "%u.%u.%u.%u", (unsigned int)s_byte_ptr[0], (unsigned int)s_byte_ptr[1], (unsigned int)s_byte_ptr[2], (unsigned int)s_byte_ptr[3]);

        return((const char *)s_address);
    }
#endif

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && defined(AF_INET6)
    if(s_family == AF_INET6) {
        const hwport_ftpd_in6_addr_t *s_in6_addr;
        unsigned short int s_word_array[8];
        int s_offset, s_entry, s_count, s_max_entry, s_max_count;

        s_in6_addr = (const hwport_ftpd_in6_addr_t *)s_inX_addr_ptr;

        s_entry = (-1);
        s_max_entry = (-1);
        s_max_count = 0;
        s_offset = 0;
        while(s_offset < 8) {
#if defined(def_hwport_ftpd_windows)
            s_word_array[s_offset] = (unsigned short int)ntohs(s_in6_addr->s6_words[s_offset]);
#else
            s_word_array[s_offset] = (unsigned short int)ntohs((uint16_t)s_in6_addr->s6_addr16[s_offset]);
#endif
            if(s_word_array[s_offset] == ((unsigned short int)0)) {
                s_entry = s_offset;
                s_count = 1;
                ++s_offset;
                while(s_offset < 8) {
#if defined(def_hwport_ftpd_windows)
                    s_word_array[s_offset] = (unsigned short int)ntohs(s_in6_addr->s6_words[s_offset]);
#else
                    s_word_array[s_offset] = (unsigned short int)ntohs((uint16_t)s_in6_addr->s6_addr16[s_offset]);
#endif
                    if(s_word_array[s_offset] != ((unsigned short int)0u)) {
                        break;
                    }
                    ++s_offset;
                    ++s_count;
                }

                if(s_count > s_max_count) {
                    s_max_entry = s_entry;
                    s_max_count = s_count;
                }
            }
            ++s_offset;
        }

        s_offset = 0;
        s_address[0] = '\0';
        while(s_offset < 8) {
            if(s_offset == s_max_entry) {
                s_address_size -= (hwport_ftpd_socklen_t)hwport_ftpd_snprintf((char *)(&s_address[hwport_ftpd_strlen(s_address)]), (size_t)s_address_size, ":");
                s_offset += s_max_count;
                if(s_offset >= 8) {
                    s_address_size -= (hwport_ftpd_socklen_t)hwport_ftpd_snprintf((char *)(&s_address[hwport_ftpd_strlen(s_address)]), (size_t)s_address_size, ":");
                }
            }
            else {
                if(s_offset > 0) {
                    s_address_size -= (hwport_ftpd_socklen_t)hwport_ftpd_snprintf((char *)(&s_address[hwport_ftpd_strlen(s_address)]), (size_t)s_address_size, ":");
                }
                s_address_size -= (hwport_ftpd_socklen_t)hwport_ftpd_snprintf((char *)(&s_address[hwport_ftpd_strlen(s_address)]), (size_t)s_address_size, "%x", (unsigned int)s_word_array[s_offset]);
                ++s_offset;
            }
        }

        return((const char *)s_address);
    }
#endif

    return((const char *)memset((void *)s_address, 0, (size_t)s_address_size));
}

const char *hwport_ftpd_inet_stop(const hwport_ftpd_sockaddr_all_t *s_sockaddr_all, char *s_address, hwport_ftpd_socklen_t s_address_size)
{
    if(hwport_ftpd_builtin_expect((s_sockaddr_all == ((hwport_ftpd_sockaddr_all_t *)0)) || (s_address == ((char *)0)), 0)) {
        return((const char *)0);
    }

    if(hwport_ftpd_builtin_expect(s_address_size <= ((hwport_ftpd_socklen_t)1), 0)) {
        if(s_address_size >= ((hwport_ftpd_socklen_t)1)) {
            s_address[0] = '\0';
        }

        return((const char *)s_address);
    }

    if(hwport_ftpd_builtin_expect(s_sockaddr_all->m_ss.ss_family == AF_UNSPEC, 0)) {
        return((const char *)hwport_ftpd_strncpy(s_address, "?UNSPEC", (size_t)s_address_size));
    }

#if (def_hwport_ftpd_can_use_ipv4 != 0L) && defined(AF_INET)
    if(s_sockaddr_all->m_ss.ss_family == AF_INET) {
        return(hwport_ftpd_inet_ntop(s_sockaddr_all->m_ss.ss_family, (const void *)(&s_sockaddr_all->m_in4.sin_addr), s_address, s_address_size));
    }
#endif

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && defined(AF_INET6)
    if(s_sockaddr_all->m_ss.ss_family == AF_INET6) {
        return(hwport_ftpd_inet_ntop(s_sockaddr_all->m_ss.ss_family, (const void *)(&s_sockaddr_all->m_in6.sin6_addr), s_address, s_address_size));
    }
#endif

    return((const char *)hwport_ftpd_strncpy(s_address, "?N/A", (size_t)s_address_size));
}

int hwport_ftpd_inet_pton(hwport_ftpd_sockfamily_t s_family, const char *s_address, void *s_inX_addr_ptr)
{
    if(hwport_ftpd_builtin_expect((s_address == ((const char *)0)) || (s_inX_addr_ptr == ((void *)0)), 0)) {
        return(-1);
    }

#if (def_hwport_ftpd_can_use_ipv4 != 0L) && defined(AF_INET)
    if(s_family == AF_INET) {
        size_t s_offset;
        size_t s_buffer_offset;
        int s_value;
        int s_sep_count;
        unsigned char s_byte;
        unsigned char s_buffer[3 + 1];
        unsigned char s_array[sizeof(hwport_ftpd_in4_addr_t)];

        (void)memset(s_inX_addr_ptr, 0, sizeof(hwport_ftpd_in4_addr_t));

        s_offset = (size_t)0u;
        s_buffer_offset = (size_t)0u;
        s_sep_count = 0;

        for(;;) {
            s_byte = (unsigned char)s_address[s_offset++];

            if((s_byte == ((unsigned char)'.')) || (s_byte == ((unsigned char)'\0'))) {
                if(hwport_ftpd_builtin_expect((s_byte == ((unsigned char)'.')) && (s_sep_count >= 4), 0)) { /* too many dot */
                    break;
                }
               
                if(hwport_ftpd_builtin_expect(s_buffer_offset <= ((size_t)0u), 0)) { /* empty numeric */
                    break;
                }

                s_buffer[s_buffer_offset] = (unsigned char)'\0';
                s_buffer_offset = (size_t)0u;

                s_value = hwport_ftpd_atoi((const char *)(&s_buffer[0]));
                if(hwport_ftpd_builtin_expect((s_value < 0) || (s_value > 255), 0)) { /* out of range value */
                    break;
                }

                s_array[s_sep_count] = (unsigned char)s_value;

                if(s_byte == ((unsigned char)'\0')) {
                    if(hwport_ftpd_builtin_expect(s_sep_count != 3, 0)) { /* need more */
                        break;
                    }
                    
                    (void)memcpy(s_inX_addr_ptr, (const void *)(&s_array[0]), sizeof(s_array));

                    /* OK */
                    return(0);
                }

                ++s_sep_count;
            }
            else if((s_byte >= ((unsigned char)'0')) && (s_byte <= ((unsigned char)'9'))) {
                s_buffer[s_buffer_offset++] = s_byte;
                if(s_buffer_offset >= sizeof(s_buffer)) { /* too long digit */
                    break;
                }
            }
            else { /* not allow character */
                break;
            }
        }

        return(-1);
    }
#endif

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && defined(AF_INET6)
    if(s_family == AF_INET6) {
        size_t s_offset;
        size_t s_buffer_offset;
        int s_value;
        int s_sep_count;
        int s_rsep_count;
        unsigned char s_byte;
        unsigned char s_buffer[4 + 1];
        unsigned char s_array[sizeof(hwport_ftpd_in4_addr_t)];
        unsigned char s_rarray[sizeof(hwport_ftpd_in4_addr_t)];
        int s_rtime;

        (void)memset(s_inX_addr_ptr, 0, sizeof(hwport_ftpd_in4_addr_t));
        s_offset = (size_t)0u;
        s_buffer_offset = (size_t)0u;
        s_sep_count = 0;
        s_rsep_count = 0;
        s_rtime = 0;

        for(;;) {
            s_byte = (unsigned char)s_address[s_offset++];

            if((s_byte == ((unsigned char)':')) || (s_byte == ((unsigned char)'\0')) /* || (s_byte == ((unsigned char *)'/')) */ ) {
                if(hwport_ftpd_builtin_expect((s_byte == ((unsigned char)':')) && ((s_sep_count + s_rsep_count) >= 8), 0)) { /* too many dot */
                    break;
                }

                if((s_byte != ((unsigned char)'\0')) && (s_buffer_offset <= ((size_t)0u))) { /* empty numeric */
                    if((s_rtime != 0) && (s_rsep_count > 1)) { /* dup simple */
                        break;
                    }

                    s_buffer_offset = (size_t)0u;
                    s_rtime = 1;

                    continue;
                }

                s_buffer[s_buffer_offset] = (unsigned char)'\0';
                s_buffer_offset = (size_t)0u;

                s_value = hwport_ftpd_atox((const char *)(&s_buffer[0]), 16);

                if(hwport_ftpd_builtin_expect((s_value < 0) || (s_value > 0xFFFF), 0)) { /* out of range value */
                    break;
                }

                if(s_rtime == 0) {
                    s_array[(s_sep_count << 1) + 0] = ((unsigned char)(s_value >> 8)) & ((unsigned char)0xFFu);
                    s_array[(s_sep_count << 1) + 1] = ((unsigned char)(s_value >> 0)) & ((unsigned char)0xFFu);
                    ++s_sep_count;
                }
                else {
                    s_rarray[(s_rsep_count << 1) + 0] = ((unsigned char)(s_value >> 8)) & ((unsigned char)0xFFu);
                    s_rarray[(s_rsep_count << 1) + 1] = ((unsigned char)(s_value >> 0)) & ((unsigned char)0xFFu);
                    ++s_rsep_count;
                }

                if((s_byte == ((unsigned char)'\0')) /* || (s_byte == ((unsigned char)'/')) */) {
                    if(hwport_ftpd_builtin_expect(((s_sep_count <= 1) && (s_rsep_count <= 0)) || ((s_sep_count + s_rsep_count) < 1) || ((s_sep_count + s_rsep_count) > 8), 0)) { /* sep count problem */
                        break;
                    }

                    if(s_sep_count > 0) {
                        (void)memcpy(s_inX_addr_ptr, (const void *)(&s_array[0]), (size_t)(s_sep_count << 1));
                    }
                    
                    if(s_rsep_count > 0) {
                        (void)memcpy(((unsigned char *)s_inX_addr_ptr) + (16 - (s_rsep_count << 1)), (const void *)(&s_rarray[0]), (size_t)(s_rsep_count << 1));
                    }

                    /* OK */
                    return(0);
                }
            }
            else if(((s_byte >= ((unsigned char)'0')) && (s_byte <= ((unsigned char)'9'))) || ((s_byte >= ((unsigned char)'a')) && (s_byte <= ((unsigned char)'z'))) || ((s_byte >= ((unsigned char)'A')) && (s_byte <= ((unsigned char)'Z')))) {
                s_buffer[s_buffer_offset++] = s_byte;
                if(s_buffer_offset >= sizeof(s_buffer)) { /* too long digit */
                    break;
                }
            }
            else { /* not allow character */
                break;
            }
        }

        return(-1);
    }
#endif

    return(-1);
}

/* ---- */

static hwport_ftpd_t hwport_ftpd_open_private(int s_listen_port)
{
    hwport_ftpd_shadow_t *s_shadow;
    hwport_ftpd_sockfamily_t s_address_family;
    hwport_ftpd_socklen_t s_address_size;
    const void *s_address;
#if defined(SOMAXCONN)    
    int s_backlog = SOMAXCONN;
#else
    int s_backlog = 5;
#endif
    int s_reuse_enable = 1;

    s_shadow = (hwport_ftpd_shadow_t *)malloc(sizeof(hwport_ftpd_shadow_t));
    if(hwport_ftpd_builtin_expect(s_shadow == ((hwport_ftpd_shadow_t *)0), 0)) {
        /* errno = ENOMEM */
        return((hwport_ftpd_t)0);
    }
    (void)memset((void *)s_shadow, 0, sizeof(hwport_ftpd_shadow_t));
    s_shadow->m_listen_socket = (hwport_ftpd_socket_t)(-1);

    s_shadow->m_account_head = (hwport_ftpd_account_t *)0;
    s_shadow->m_account_tail = (hwport_ftpd_account_t *)0;
    
#if (def_hwport_ftpd_can_use_ipv6 != (0)) && defined(PF_INET6)
    s_shadow->m_listen_socket = hwport_ftpd_socket_open(PF_INET6, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
    if(hwport_ftpd_builtin_expect(s_shadow->m_listen_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
#if defined(PF_INET)    
        s_shadow->m_listen_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
        if(hwport_ftpd_builtin_expect(s_shadow->m_listen_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
            return(hwport_ftpd_close((hwport_ftpd_t)s_shadow));
        }
        s_address_family = AF_INET;
        s_address_size = (hwport_ftpd_socklen_t)sizeof(s_shadow->m_listen_addr.m_in4); 
        s_address = (void *)(&s_shadow->m_listen_addr.m_in4);

        s_shadow->m_listen_addr.m_in4.sin_family = s_address_family;
        s_shadow->m_listen_addr.m_in4.sin_addr.s_addr = htonl(INADDR_ANY);
        s_shadow->m_listen_addr.m_in4.sin_port = htons(s_listen_port);
#else
        return(hwport_ftpd_close((hwport_ftpd_t)s_shadow));
#endif
    }
    else {
        s_address_family = AF_INET6;
        s_address_size = (hwport_ftpd_socklen_t)sizeof(s_shadow->m_listen_addr.m_in6); 
        s_address = (void *)(&s_shadow->m_listen_addr.m_in6);

        s_shadow->m_listen_addr.m_in6.sin6_family = s_address_family;
        s_shadow->m_listen_addr.m_in6.sin6_flowinfo = 0;
        s_shadow->m_listen_addr.m_in6.sin6_addr = in6addr_any;
        s_shadow->m_listen_addr.m_in6.sin6_port = htons(s_listen_port);
    }
#elif defined(PF_INET)    
    s_shadow->m_listen_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
    if(hwport_ftpd_builtin_expect(s_shadow->m_listen_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        return(hwport_ftpd_close((hwport_ftpd_t)s_shadow));
    }
    s_address_family = AF_INET;
    s_address_size = (hwport_ftpd_socklen_t)sizeof(s_shadow->m_listen_addr.m_in4); 
    s_address = (void *)(&s_shadow->m_listen_addr.m_in4);

    s_shadow->m_listen_addr.m_in4.sin_family = s_address_family;
    s_shadow->m_listen_addr.m_in4.sin_addr.s_addr = htonl(INADDR_ANY);
    s_shadow->m_listen_addr.m_in4.sin_port = htons(s_listen_port);
#else
# error can not support ip !
#endif    

#if defined(def_hwport_ftpd_windows)
    (void)setsockopt((int)s_shadow->m_listen_socket, SOL_SOCKET, SO_REUSEADDR, (char *)(&s_reuse_enable), (socklen_t)sizeof(s_reuse_enable));
#else
    (void)setsockopt((int)s_shadow->m_listen_socket, SOL_SOCKET, SO_REUSEADDR, &s_reuse_enable, (socklen_t)sizeof(s_reuse_enable));
#endif

    if(hwport_ftpd_builtin_expect(hwport_ftpd_bind(s_shadow->m_listen_socket, s_address, s_address_size) != 0, 0)) {
        return(hwport_ftpd_close((hwport_ftpd_t)s_shadow));
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_listen(s_shadow->m_listen_socket, s_backlog) != 0, 0)) {
        return(hwport_ftpd_close((hwport_ftpd_t)s_shadow));
    }

    return((hwport_ftpd_t)s_shadow);
}

hwport_ftpd_t hwport_ftpd_open(void)
{
    hwport_ftpd_t s_handle;

    s_handle = hwport_ftpd_open_private(21);
    if(s_handle == ((hwport_ftpd_t)0)) {
        s_handle = hwport_ftpd_open_private(2211);
    }

    return(s_handle);
}

hwport_ftpd_t hwport_ftpd_close(hwport_ftpd_t s_handle)
{
    hwport_ftpd_shadow_t *s_shadow;

    if(hwport_ftpd_builtin_expect(s_handle == ((hwport_ftpd_t)0), 0)) {
        /* errno = EINVAL */
        return((hwport_ftpd_t)0);
    }

    s_shadow = (hwport_ftpd_shadow_t *)s_handle;
    
    if(s_shadow->m_account_head != ((hwport_ftpd_account_t *)0)) {
        s_shadow->m_account_head = hwport_ftpd_free_account(s_shadow->m_account_head);
    }

    if(s_shadow->m_listen_socket != ((hwport_ftpd_socket_t)(-1))) {
        s_shadow->m_listen_socket = hwport_ftpd_socket_close(s_shadow->m_listen_socket);
    }

    free((void *)s_handle);

    return((hwport_ftpd_t)0);
}

#if def_hwport_ftpd_use_pthread != (0L)       
static int hwport_ftpd_detached_thread(void * (*s_thread_handler)(void *), void *s_argument, size_t s_stack_size)
{
    int s_result;

    pthread_t s_thread_handle;
    pthread_attr_t s_thread_attr;
    size_t s_current_stack_size;

    if(hwport_ftpd_builtin_expect(pthread_attr_init((pthread_attr_t *)(&s_thread_attr)) != 0, 0)) {
        /* errno = ... */
        return(-1);
    }

    s_current_stack_size = (size_t)0u;
    if(pthread_attr_getstacksize((pthread_attr_t *)(&s_thread_attr), (size_t *)(&s_current_stack_size)) == 0) {
        if(s_stack_size <= ((size_t)0u)) {
            if(s_current_stack_size < ((size_t)(4 << 10))) {
                s_stack_size = (size_t)(4 << 10);
            }
        }
        else {
            if(s_stack_size == ((size_t)s_current_stack_size)) {
                s_stack_size = (size_t)0u;
            }
        }

        if(s_stack_size > ((size_t)0u)) {
            (void)pthread_attr_setstacksize((pthread_attr_t *)(&s_thread_attr), (size_t)s_stack_size);
        }
    }

    if(hwport_ftpd_builtin_expect(pthread_attr_setdetachstate((pthread_attr_t *)(&s_thread_attr), PTHREAD_CREATE_DETACHED) != 0, 0)) {
        /* errno = ... */
        s_result = (-1);
    }
    else if(hwport_ftpd_builtin_expect(pthread_create((pthread_t *)(&s_thread_handle), (pthread_attr_t *)(&s_thread_attr), s_thread_handler, (void *)s_argument) != 0, 0)) {
        /* errno = ... */
        s_result = (-1);
    }
    else {
        /* ok! thread detached. */
        s_result = 0;
    }

    (void)pthread_attr_destroy((pthread_attr_t *)(&s_thread_attr));

    return(s_result);
}
#endif

int hwport_ftpd_do(hwport_ftpd_t s_handle, int s_msec)
{
    hwport_ftpd_shadow_t *s_shadow;
    hwport_ftpd_session_t *s_session;

    if(hwport_ftpd_builtin_expect(s_handle == ((hwport_ftpd_t)0), 0)) {
        /* errno = EINVAL */
        return(-1);
    }

    s_shadow = (hwport_ftpd_shadow_t *)s_handle;

    s_session = (hwport_ftpd_session_t *)malloc(sizeof(hwport_ftpd_session_t));
    if(s_session == ((hwport_ftpd_session_t *)0)) {
        /* errno = ENOMEM */
        return(-1);
    }
    (void)memset((void *)s_session, 0, sizeof(hwport_ftpd_session_t));

    /* - */
    s_session->m_handle = s_handle;
    
    s_session->m_account_head = s_shadow->m_account_head;
    s_session->m_current_account = (hwport_ftpd_account_t *)0;
    
    s_session->m_flags = def_hwport_ftpd_session_flag_none;

    s_session->m_send_timeout = def_hwport_ftpd_worker_send_timeout; 
    s_session->m_recv_timeout = def_hwport_ftpd_worker_recv_timeout; 

    s_session->m_command_socket = (hwport_ftpd_socket_t)(-1);
    s_session->m_command_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_command_sockaddr_all);
    s_session->m_command_buffer_size = (size_t)def_hwport_ftpd_command_buffer_size;
    s_session->m_command_buffer = (unsigned char *)0;

    s_session->m_command = (char *)0;
    s_session->m_param = (char *)0;
    
    s_session->m_data_socket = (hwport_ftpd_socket_t)(-1);
    s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);
    s_session->m_data_buffer_size = (size_t)def_hwport_ftpd_data_buffer_size;
    s_session->m_data_buffer = (unsigned char *)0;
    s_session->m_restart_position = (off_t)0;

    s_session->m_fd = (-1);

    s_session->m_username = (char *)0;
    s_session->m_type = def_hwport_ftpd_session_type_none;
    s_session->m_path_home = (char *)0;
    s_session->m_path_work = (char *)0;
    s_session->m_path_rename_from = (char *)0;
   
    /* - */
    s_session->m_command_buffer = (unsigned char *)malloc(s_session->m_command_buffer_size);
    if(hwport_ftpd_builtin_expect(s_session->m_command_buffer == ((unsigned char *)0), 0)) {
        /* errno = ENOMEM */
        hwport_ftpd_session_end(s_session);
        return(-1);
    }
    
    s_session->m_data_buffer = (unsigned char *)malloc(s_session->m_data_buffer_size);
    if(hwport_ftpd_builtin_expect(s_session->m_data_buffer == ((unsigned char *)0), 0)) {
        /* errno = ENOMEM */
        hwport_ftpd_session_end(s_session);
        return(-1);
    }

    s_session->m_command_socket = hwport_ftpd_accept(s_shadow->m_listen_socket, (void *)(&s_session->m_command_sockaddr_all), (hwport_ftpd_socklen_t *)(&s_session->m_command_sockaddr_size), s_msec);
    if(hwport_ftpd_builtin_expect(s_session->m_command_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        /* errno = ... */
        hwport_ftpd_session_end(s_session);
        return(-1);
    }

#if def_hwport_ftpd_use_pthread != (0L) /* use thread mode */
    if(hwport_ftpd_builtin_expect(hwport_ftpd_detached_thread(hwport_ftpd_worker, (void *)s_session, (size_t)(4 << 10)) != 0, 0)) {
        /* errno = ... */
        hwport_ftpd_session_end(s_session);
        return(-1);
    }
#elif defined(def_hwport_ftpd_windows)
    do {
        HANDLE s_thread_handle;
	DWORD s_thread_id;

        s_thread_handle = CreateThread((LPSECURITY_ATTRIBUTES)0, (SIZE_T)0, (LPTHREAD_START_ROUTINE)hwport_ftpd_worker, (LPVOID)s_session, (DWORD)0, (LPDWORD)(&s_thread_id));
        if(s_thread_handle != ((HANDLE)0)) {
	    /* detached thread */
            (void)CloseHandle(s_thread_handle);
	}
    }while(0);
#else /* use fork mode */
    do {
        pid_t s_pid;

        s_pid = fork();

        if(s_pid == ((pid_t)0)) {
            s_pid = fork();
            if(s_pid == ((pid_t)0)) {
                setsid();
                s_session->m_flags |= def_hwport_ftpd_session_flag_fork;
            
                (void)hwport_ftpd_worker((void *)s_session);
            }

            exit(0);
            return(0);
        }

        (void)waitpid(s_pid, (int *)0, 0);
        
        hwport_ftpd_session_end(s_session);
    }while(0);
#endif

    return(0);
}

/* ---- */

hwport_ftpd_account_t *hwport_ftpd_new_account(const char *s_username, unsigned int s_flags)
{
    hwport_ftpd_account_t *s_result;
    size_t s_username_size;
    size_t s_alloc_size;

    s_alloc_size = sizeof(hwport_ftpd_account_t);
    if(hwport_ftpd_builtin_expect(s_username == ((const char *)0), 0)) {
        s_username_size = (size_t)0u;
    }
    else {
        s_username_size = hwport_ftpd_strlen(s_username);
        s_alloc_size += s_username_size + ((size_t)1u);
    }

    s_result = (hwport_ftpd_account_t *)malloc(s_alloc_size);
    if(hwport_ftpd_builtin_expect(s_result == ((hwport_ftpd_account_t *)0), 0)) {
        return((hwport_ftpd_account_t *)0);
    }

    s_result->m_prev = (hwport_ftpd_account_t *)0; 
    s_result->m_next = (hwport_ftpd_account_t *)0; 

    s_result->m_flags = s_flags;

    if(hwport_ftpd_builtin_expect(s_username == ((const char *)0), 0)) {
        s_result->m_username = (char *)0;
    }
    else {
        s_result->m_username = hwport_ftpd_strcpy((char *)(&s_result[1]), s_username);
    }
    s_result->m_plain_password = (char *)0;

    s_result->m_path_home = (char *)0;

#if defined(def_hwport_ftpd_windows)
    s_result->m_uid = 0;
    s_result->m_gid = 0;
#else
    s_result->m_uid = getuid();
    s_result->m_gid = getgid();
#endif    

    return(s_result);
}

hwport_ftpd_account_t *hwport_ftpd_free_account(hwport_ftpd_account_t *s_account)
{
    hwport_ftpd_account_t *s_prev;

    if(hwport_ftpd_builtin_expect(s_account == ((hwport_ftpd_account_t *)0), 0)) {
        /* errno = EINVAL */
        return((hwport_ftpd_account_t *)0);
    }

    while(s_account->m_prev != ((hwport_ftpd_account_t *)0)) {
        s_account = s_account->m_prev;
    }

    while(s_account != ((hwport_ftpd_account_t *)0)) {
        s_prev = s_account;
        s_account = s_account->m_next;
        
        if(s_prev->m_path_home != ((char *)0)) {
            free((void *)s_prev->m_path_home);
        }
    
        if(s_prev->m_plain_password != ((char *)0)) {
            free(memset((void *)s_prev->m_plain_password, 0, hwport_ftpd_strlen(s_prev->m_plain_password)));
        }

        free((void *)s_prev);
    }

    return((hwport_ftpd_account_t *)0);
}

int hwport_ftpd_account_set_plain_password(hwport_ftpd_account_t *s_account, const char *s_plain_password)
{
    char *s_temp;

    if(hwport_ftpd_builtin_expect(s_account == ((hwport_ftpd_account_t *)0), 0)) {
        /* errno = EINVAL */
        return(-1);
    }

    s_temp = (char *)0;
    if(s_plain_password != ((const char *)0)) {
        s_temp = hwport_ftpd_strdup(s_plain_password);
        if(hwport_ftpd_builtin_expect(s_temp == ((char *)0), 0)) {
            /* errno = ENOMEM */
            return(-1);
        }
    }
   
    if(s_account->m_plain_password != ((char *)0)) {
        free(memset((void *)s_account->m_plain_password, 0, hwport_ftpd_strlen(s_account->m_plain_password)));
    }

    s_account->m_plain_password = s_temp;

    return(0);
}

int hwport_ftpd_account_set_path_home(hwport_ftpd_account_t *s_account, const char *s_path_home)
{
    char *s_temp;

    if(hwport_ftpd_builtin_expect(s_account == ((hwport_ftpd_account_t *)0), 0)) {
        /* errno = EINVAL */
        return(-1);
    }

    s_temp = (char *)0;
    if(s_path_home != ((const char *)0)) {
        s_temp = hwport_ftpd_strdup(s_path_home);
        if(hwport_ftpd_builtin_expect(s_temp == ((char *)0), 0)) {
            /* errno = ENOMEM */
            return(-1);
        }
    }
   
    if(s_account->m_path_home != ((char *)0)) {
        free((void *)s_account->m_path_home);
    }

    s_account->m_path_home = s_temp;

    return(0);
}

int hwport_ftpd_add_account(hwport_ftpd_t s_handle, hwport_ftpd_account_t *s_account)
{
    hwport_ftpd_shadow_t *s_shadow;

    hwport_ftpd_account_t *s_account_head;
    hwport_ftpd_account_t *s_account_tail;

    if(hwport_ftpd_builtin_expect((s_handle == ((hwport_ftpd_t)0)) || (s_account == ((hwport_ftpd_account_t *)0)), 0)) {
        /* errno = EINVAL */
        return(-1);
    }

    s_shadow = (hwport_ftpd_shadow_t *)s_handle;

    s_account_head = s_account;
    while(s_account_head->m_prev != ((hwport_ftpd_account_t *)0)) {
        s_account_head = s_account_head->m_prev;
    }
    
    s_account_tail = s_account;
    while(s_account_tail->m_next != ((hwport_ftpd_account_t *)0)) {
        s_account_tail = s_account_tail->m_next;
    }

    if(s_shadow->m_account_tail == ((hwport_ftpd_account_t *)0)) {
        s_shadow->m_account_head = s_account_head;
    }
    else {
        s_account_head->m_prev = s_shadow->m_account_tail;
        s_shadow->m_account_tail->m_next = s_account_head;
    }

    s_shadow->m_account_tail = s_account_tail;

    return(0);
}

int hwport_ftpd_add_user(hwport_ftpd_t s_handle, hwport_ftpd_account_t **s_account_ptr, unsigned int s_flags, const char *s_username, const char *s_plain_password, const char *s_path_home)
{
    hwport_ftpd_account_t *s_new;

    if(s_account_ptr != ((hwport_ftpd_account_t **)0)) {
        *s_account_ptr = (hwport_ftpd_account_t *)0;
    }

    s_new = hwport_ftpd_new_account(s_username, def_hwport_ftpd_account_flag_none | s_flags);
    if(hwport_ftpd_builtin_expect(s_new == ((hwport_ftpd_account_t *)0), 0)) {
        /* errno = ENOMEM */
        return(-1);
    }

    if(hwport_ftpd_account_set_plain_password(s_new, s_plain_password) != 0) {
        /* errno = ENOMEM */
        (void)hwport_ftpd_free_account(s_new);
        return(-1);
    }
    
    if(hwport_ftpd_account_set_path_home(s_new, s_path_home) != 0) {
        /* errno = ENOMEM */
        (void)hwport_ftpd_free_account(s_new);
        return(-1);
    }

    if(s_handle != ((hwport_ftpd_t)0)) {
        if(hwport_ftpd_add_account(s_handle, s_new) != 0) {
            /* errno = ENOMEM */
            (void)hwport_ftpd_free_account(s_new);
            return(-1);
        }
    }

    if(s_account_ptr != ((hwport_ftpd_account_t **)0)) {
        *s_account_ptr = s_new;
    }

    return(0);
}

static hwport_ftpd_account_t *hwport_ftpd_account_search_user(hwport_ftpd_session_t *s_session, const char *s_username, hwport_ftpd_account_t **s_account_dup)
{
    hwport_ftpd_account_t *s_account_new = (hwport_ftpd_account_t *)0;
    hwport_ftpd_account_t *s_account_head;
    unsigned int s_account_flags; 
                    
#if def_hwport_ftpd_use_pwd != (0L)		
    struct passwd *s_passwd;
#endif    

    if(s_account_dup != ((hwport_ftpd_account_t **)0)) {
        *s_account_dup = (hwport_ftpd_account_t *)0;
    }
    
    s_account_head = s_session->m_account_head;
    while(s_account_head != ((hwport_ftpd_account_t *)0)) {
        s_account_flags = s_account_head->m_flags;

        if((s_account_flags & def_hwport_ftpd_account_flag_system_user) != def_hwport_ftpd_account_flag_none) {
            if(s_username != ((const char *)0)) {
                if((s_account_head->m_username == ((char *)0)) || (hwport_ftpd_strcmp(s_account_head->m_username, s_username) == 0)) {
#if def_hwport_ftpd_use_pwd != (0L)		
# if def_hwport_ftpd_use_shadow != (0L)		
                    lckpwdf();
# endif		    
                    setpwent();
                    for(;;) {
                        s_passwd = getpwent();
                        if(s_passwd == ((struct passwd *)0)) {
                           break;
                        }
            
                        if(hwport_ftpd_builtin_expect(s_passwd->pw_passwd == ((char *)0), 0)) {
                            continue;
                        }

                        if(strcmp(s_passwd->pw_name, s_username) == 0) {
                            char *s_password_field;
            
                            if(hwport_ftpd_strcmp(s_passwd->pw_name, "root") == 0) {
                                s_account_flags |= def_hwport_ftpd_account_flag_admin_user;
#if 1L /* allow "/" directory access */
                                s_account_flags |= def_hwport_ftpd_account_flag_allow_all_path;
#endif                                

#if 0L /* disable root login */
                                continue;
#endif
                            }

                            s_password_field = s_passwd->pw_passwd;

                            if(s_password_field[0] == '\0') { /* no password user */
                                s_account_new = hwport_ftpd_new_account(s_passwd->pw_name, s_account_flags);
                                if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                                     s_account_new->m_uid = s_passwd->pw_uid;
                                     s_account_new->m_gid = s_passwd->pw_gid;
                                    if(hwport_ftpd_account_set_plain_password(s_account_new, (const char *)0) != 0) {
                                        s_account_new = hwport_ftpd_free_account(s_account_new);
                                    }
                                    else if(hwport_ftpd_account_set_path_home(s_account_new, s_passwd->pw_dir) != 0) {
                                        s_account_new = hwport_ftpd_free_account(s_account_new);
                                    }
                                }
                                break;
                            }

                            if((hwport_ftpd_strcmp(s_password_field, "x") == 0) ||
                               (hwport_ftpd_strcmp(s_password_field, "*") == 0)) { /* reference to shadow */
# if def_hwport_ftpd_use_shadow != (0L)		
                                struct spwd *s_spwd;
                                setspent();
                                for(;;) {
                                    s_spwd = getspent();
                                    if(s_spwd == ((struct spwd *)0)) {
                                        break;
                                    }

                                    if(hwport_ftpd_builtin_expect(s_spwd->sp_namp == ((char *)0), 0)) {
                                        continue;
                                    }

                                    if(strcmp(s_passwd->pw_name, s_spwd->sp_namp) == 0) {
                                        if(s_spwd->sp_pwdp == ((char *)0)) {
                                            break;
                                        }
                        
                                        s_password_field = s_spwd->sp_pwdp;
                                        if(s_password_field[0] == '\0') { /* no password user */
                                            s_account_new = hwport_ftpd_new_account(s_passwd->pw_name, s_account_flags);
                                            if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                                                 s_account_new->m_uid = s_passwd->pw_uid;
                                                 s_account_new->m_gid = s_passwd->pw_gid;
                                                if(hwport_ftpd_account_set_plain_password(s_account_new, (const char *)0) != 0) {
                                                    s_account_new = hwport_ftpd_free_account(s_account_new);
                                                }
                                                else if(hwport_ftpd_account_set_path_home(s_account_new, s_passwd->pw_dir) != 0) {
                                                    s_account_new = hwport_ftpd_free_account(s_account_new);
                                                }
                                            }
                                            break;
                                        }

                                        if((hwport_ftpd_strcmp(s_password_field, "!") == 0) ||
                                           (hwport_ftpd_strcmp(s_password_field, "*") == 0)) { /* disable user */
                                            break;
                                        }
                    
                                        /* encrypted by crypt password user */
                                        s_account_flags |= def_hwport_ftpd_account_flag_encrypted_by_crypt;
                                        s_account_new = hwport_ftpd_new_account(s_passwd->pw_name, s_account_flags);
                                        if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                                             s_account_new->m_uid = s_passwd->pw_uid;
                                             s_account_new->m_gid = s_passwd->pw_gid;
                                            if(hwport_ftpd_account_set_plain_password(s_account_new, s_password_field) != 0) {
                                                s_account_new = hwport_ftpd_free_account(s_account_new);
                                            }
                                            else if(hwport_ftpd_account_set_path_home(s_account_new, s_passwd->pw_dir) != 0) {
                                                s_account_new = hwport_ftpd_free_account(s_account_new);
                                            }
                                        }
                                    
                                        break;
                                    }
                                }
                                endspent();
# endif				
                                continue;
                            }

                            /* plain password user */
                            s_account_new = hwport_ftpd_new_account(s_passwd->pw_name, s_account_flags);
                            if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                                 s_account_new->m_uid = s_passwd->pw_uid;
                                 s_account_new->m_gid = s_passwd->pw_gid;
                                if(hwport_ftpd_account_set_plain_password(s_account_new, s_password_field) != 0) {
                                    s_account_new = hwport_ftpd_free_account(s_account_new);
                                }
                                else if(hwport_ftpd_account_set_path_home(s_account_new, s_passwd->pw_dir) != 0) {
                                    s_account_new = hwport_ftpd_free_account(s_account_new);
                                }
                            }
                            break;
                        }
                    }
                    endpwent();
# if def_hwport_ftpd_use_shadow != (0L)		
                    ulckpwdf();
# endif		    
#endif		    

                    if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                        break;
                    }
                }
            }
        }
        else if(s_account_head->m_username == ((char *)0)) {
            if(s_username == ((const char *)0)) {
                s_account_new = hwport_ftpd_new_account((const char *)0, s_account_flags);
                if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                    s_account_new->m_uid = s_account_head->m_uid;
                    s_account_new->m_gid = s_account_head->m_gid;
                    if(hwport_ftpd_account_set_plain_password(s_account_new, s_account_head->m_plain_password) != 0) {
                        s_account_new = hwport_ftpd_free_account(s_account_new);
                    }
                    else if(hwport_ftpd_account_set_path_home(s_account_new, s_account_head->m_path_home) != 0) {
                        s_account_new = hwport_ftpd_free_account(s_account_new);
                    }
                }
                break;
            }
        }
        else if(s_username != ((char *)0)) {
            if(hwport_ftpd_strcmp(s_username, (const char *)s_account_head->m_username) == 0) {
                s_account_new = hwport_ftpd_new_account(s_account_head->m_username, s_account_flags);
                if(s_account_new != ((hwport_ftpd_account_t *)0)) {
                    s_account_new->m_uid = s_account_head->m_uid;
                    s_account_new->m_gid = s_account_head->m_gid;
                    if(hwport_ftpd_account_set_plain_password(s_account_new, s_account_head->m_plain_password) != 0) {
                        s_account_new = hwport_ftpd_free_account(s_account_new);
                    }
                    else if(hwport_ftpd_account_set_path_home(s_account_new, s_account_head->m_path_home) != 0) {
                        s_account_new = hwport_ftpd_free_account(s_account_new);
                    }
                }
                break;
            }
        }
        s_account_head = s_account_head->m_next;
    }

    if(s_account_dup != ((hwport_ftpd_account_t **)0)) {
        *s_account_dup = s_account_new;
    }
    else {
        s_account_new = hwport_ftpd_free_account(s_account_new);
    }

    return(s_account_head);
}

hwport_ftpd_account_t *hwport_ftpd_account_login(hwport_ftpd_session_t *s_session, const char *s_username, const char *s_plain_password)
{
    hwport_ftpd_account_t *s_account, *s_account_dup;

    int s_valid_password;
    char *s_path_home;

    s_account = hwport_ftpd_account_search_user(s_session, s_username, (hwport_ftpd_account_t **)(&s_account_dup));
    if(s_account_dup == ((hwport_ftpd_account_t *)0)) {
        return((hwport_ftpd_account_t *)0);
    }

    if(s_account_dup->m_plain_password == ((char *)0)) {
        if(s_plain_password == ((const char *)0)) {
            s_valid_password = 1;
        }
        else if(s_plain_password[0] == '\0') {
            s_valid_password = 1;
        }
        else {
            s_valid_password = 0;
        }
    }
    else if(s_plain_password == ((char *)0)) {
        s_valid_password = 0;
    }
    else if((s_account_dup->m_flags & def_hwport_ftpd_account_flag_encrypted_by_crypt) != def_hwport_ftpd_account_flag_none) {
#if def_hwport_ftpd_use_crypt != (0L) /* crypt password support */
        char s_temp_salt[12 + 1];
        size_t s_encrypted_password_size;

        s_encrypted_password_size = hwport_ftpd_strlen(s_account_dup->m_plain_password);

        s_temp_salt[0] = '\0';
        if(s_account_dup->m_plain_password[0] == '$') {
            if(s_encrypted_password_size > ((size_t)12u)) {
                if((s_account_dup->m_plain_password[2] == '$') ||
                   (s_account_dup->m_plain_password[11] == '$')) {
                    (void)memcpy((void *)(&s_temp_salt[0]), (const void *)s_account_dup->m_plain_password, (size_t)12u);
                    s_temp_salt[12] = '\0';
                }
            }
        }
        else if(s_encrypted_password_size > ((size_t)2u)) {
            (void)memcpy((void *)(&s_temp_salt[0]), (const void *)s_account_dup->m_plain_password, (size_t)2u);
            s_temp_salt[2] = '\0';
        }

        if(hwport_ftpd_strcmp(s_account_dup->m_plain_password, crypt(s_plain_password, &s_temp_salt[0])) == 0) {
            s_valid_password = 1;
        }
        else {
            s_valid_password = 0;
        }

        (void)memset((void *)(&s_temp_salt[0]), 0, sizeof(s_temp_salt));
#else /* not supported crypt */
        s_valid_password = 0;
#endif
    }
    else if(hwport_ftpd_strcmp(s_plain_password, (const char *)s_account_dup->m_plain_password) == 0) {
        s_valid_password = 1;
    }
    else {
        s_valid_password = 0;
    }

    if(s_valid_password == 0) {
        return(hwport_ftpd_free_account(s_account_dup));
    }
    
    s_path_home = s_account->m_path_home;
    if(s_path_home == ((char *)0)) {
        s_path_home = s_account_dup->m_path_home;
    }
    if(s_path_home == ((char *)0)) {
        s_path_home = getenv("HOME");
    }

    if((s_account_dup->m_flags & def_hwport_ftpd_account_flag_allow_all_path) != def_hwport_ftpd_account_flag_none) { /* admin user */
        s_session->m_path_home = hwport_ftpd_strdup("/");
        s_session->m_path_work = hwport_ftpd_strdup((s_path_home == ((char *)0)) ? "/" : s_path_home);
    }
    else { /* normal user */
        s_session->m_path_home = hwport_ftpd_strdup((s_path_home == ((char *)0)) ? "/" : s_path_home);
        s_session->m_path_work = hwport_ftpd_strdup("/");
    }
    
#if defined(def_hwport_ftpd_windows)
#else
    if((s_session->m_flags & def_hwport_ftpd_session_flag_fork) != def_hwport_ftpd_session_flag_none) { /* fork process : can use sete[u|g]id */
        /* set effective owner */
        (void)setegid(s_account_dup->m_gid);
        (void)seteuid(s_account_dup->m_uid);
    }
#endif    
    
    s_account_dup = hwport_ftpd_free_account(s_account_dup);

    return(s_account);
}

/* ---- */

int hwport_ftpd_data_open(hwport_ftpd_session_t *s_session)
{
    hwport_ftpd_socket_t s_accept_socket;

    if(s_session->m_data_socket == ((hwport_ftpd_socket_t)(-1))) { /* PORT session */
        int s_check;

#if def_hwport_ftpd_can_use_ipv6 != (0)
        if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET6) {
            s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET6, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
        }
# if defined(PF_INET)        
        else {
            s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
        }
# endif        
#elif defined(PF_INET)
        s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
#endif
        if(s_session->m_data_socket == ((hwport_ftpd_socket_t)(-1))) {
            /* errno = ... */
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 451, ' ', "Socket error !") == (-1), 0)) {
                return(-1);
            }
            return(-1);
        }

        s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);
        s_check = hwport_ftpd_connect(s_session->m_data_socket, (const void *)(&s_session->m_data_sockaddr_all), s_session->m_data_sockaddr_size, (-1));
        if(hwport_ftpd_builtin_expect(s_check == (-1), 0)) {
            /* errno = ... */
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 451, ' ', "Connect error !") == (-1), 0)) {
                (void)hwport_ftpd_data_close(s_session);
                return(-1);
            }
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }

        do {
            struct linger s_linger;

            (void)memset((void *)(&s_linger), 0, sizeof(s_linger));
            s_linger.l_onoff = 1;
            s_linger.l_linger = 4;
#if defined(def_hwport_ftpd_windows)
            (void)setsockopt(s_session->m_data_socket, SOL_SOCKET, SO_LINGER, (const char *)(&s_linger), (socklen_t)sizeof(s_linger));
#else
            (void)setsockopt(s_session->m_data_socket, SOL_SOCKET, SO_LINGER, &s_linger, (socklen_t)sizeof(s_linger));
#endif	    
        }while(0);
    
        return(0);
    }
    
    /* PASV session */
    s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);
    s_accept_socket = hwport_ftpd_accept(s_session->m_data_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (hwport_ftpd_socklen_t *)(&s_session->m_data_sockaddr_size), (-1));
    if(hwport_ftpd_builtin_expect(s_accept_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        /* errno = ... */
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 451, ' ', "Accept error !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }

    s_session->m_data_socket = hwport_ftpd_socket_close(s_session->m_data_socket);
    s_session->m_data_socket = s_accept_socket;

    do {
        struct linger s_linger;

        (void)memset((void *)(&s_linger), 0, sizeof(s_linger));
        s_linger.l_onoff = 1;
        s_linger.l_linger = 4;
#if defined(def_hwport_ftpd_windows)
        (void)setsockopt(s_session->m_data_socket, SOL_SOCKET, SO_LINGER, (const char *)(&s_linger), (socklen_t)sizeof(s_linger));
#else
        (void)setsockopt(s_session->m_data_socket, SOL_SOCKET, SO_LINGER, &s_linger, (socklen_t)sizeof(s_linger));
#endif	
    }while(0);

    return(0);
}

int hwport_ftpd_data_close(hwport_ftpd_session_t *s_session)
{
    if(s_session->m_data_socket != ((hwport_ftpd_socket_t)(-1))) {
        s_session->m_data_socket = hwport_ftpd_socket_close(s_session->m_data_socket);
    }

    return(0);
}

/* ---- */

static void hwport_ftpd_session_end(hwport_ftpd_session_t *s_session)
{
    if(s_session->m_path_rename_from != ((char *)0)) {
        free((void *)s_session->m_path_rename_from);
    }

    if(s_session->m_path_work != ((char *)0)) {
        free((void *)s_session->m_path_work);
    }

    if(s_session->m_path_home != ((char *)0)) {
        free((void *)s_session->m_path_home);
    }

    if(s_session->m_username != ((char *)0)) {
        free((void *)s_session->m_username);
    }
   
    if(s_session->m_fd != (-1)) {
#if defined(def_hwport_ftpd_windows)
        _close(s_session->m_fd);
#else
        while((close(s_session->m_fd) == (-1)) && (errno == EINTR));
#endif
        s_session->m_fd = (-1);
    }

    if(s_session->m_data_buffer != ((unsigned char *)0)) {
        free((void *)s_session->m_data_buffer);
    }

    (void)hwport_ftpd_data_close(s_session);

    if(s_session->m_command_buffer != ((unsigned char *)0)) {
        free((void *)s_session->m_command_buffer);
    }

    if(s_session->m_command_socket != ((hwport_ftpd_socket_t)(-1))) {
        s_session->m_command_socket = hwport_ftpd_socket_close(s_session->m_command_socket);
    }

    free((void *)s_session);
}

static void *hwport_ftpd_worker(void *s_argument)
{
    hwport_ftpd_session_t *s_session = (hwport_ftpd_session_t *)s_argument;
    ssize_t s_recv_bytes;

    size_t s_offset;
    unsigned char s_byte;

    do {
        int s_temp_value;
        struct linger s_linger;

#if defined(IPTOS_LOWDELAY) && defined(IP_TOS)
        s_temp_value = IPTOS_LOWDELAY;
#if defined(def_hwport_ftpd_windows)
        (void)setsockopt(s_session->m_command_socket, IPPROTO_IP, IP_TOS, (const char *)(&s_temp_value), (socklen_t)sizeof(s_temp_value));
#else
        (void)setsockopt(s_session->m_command_socket, IPPROTO_IP, IP_TOS, &s_temp_value, (socklen_t)sizeof(s_temp_value));
#endif
#endif

        s_temp_value = 1;
#if defined(def_hwport_ftpd_windows)
        (void)setsockopt(s_session->m_command_socket, SOL_SOCKET, SO_OOBINLINE, (const char *)(&s_temp_value), (socklen_t)sizeof(s_temp_value));
#else
        (void)setsockopt(s_session->m_command_socket, SOL_SOCKET, SO_OOBINLINE, &s_temp_value, (socklen_t)sizeof(s_temp_value));
#endif

        (void)memset((void *)(&s_linger), 0, sizeof(s_linger));
        s_linger.l_onoff = 1;
        s_linger.l_linger = 4;
#if defined(def_hwport_ftpd_windows)
        (void)setsockopt(s_session->m_command_socket, SOL_SOCKET, SO_LINGER, (const char *)(&s_linger), (socklen_t)sizeof(s_linger));
#else
        (void)setsockopt(s_session->m_command_socket, SOL_SOCKET, SO_LINGER, &s_linger, (socklen_t)sizeof(s_linger));
#endif	
    }while(0);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 220, ' ', def_hwport_ftpd_server_name) == (-1), 0)) {
        /* errno = ... */
        hwport_ftpd_session_end(s_session);
        return((void *)0);
    }

    for(;;) {
        s_recv_bytes = hwport_ftpd_recv(s_session->m_command_socket, (void *)s_session->m_command_buffer, s_session->m_command_buffer_size - ((size_t)1u), s_session->m_recv_timeout);
        if(hwport_ftpd_builtin_expect((s_recv_bytes == ((ssize_t)(-1))) || (s_recv_bytes == ((ssize_t)(-2))), 0)) {
            break;
        }
        if(hwport_ftpd_builtin_expect(s_recv_bytes == ((ssize_t)0), 0)) { /* end of connection */
            break;
        }

        /* make zero terminate string */
        s_session->m_command_buffer[s_recv_bytes] = '\0';
       
        /* TELNET protocol (RFC854)
           IAC   255(FFH) interpret as command:
           IP    244(F4H) interrupt process--permanently
           DM          242(F2H) data mark--for connect. cleaning
        */
        s_offset = (size_t)0u;
        while(s_recv_bytes > ((ssize_t)0)) {
            s_byte = s_session->m_command_buffer[s_offset];
            if((s_byte != ((unsigned char)0xFFu) /* IAC */) &&
               (s_byte != ((unsigned char)0xF4u) /* IP */) &&
               (s_byte != ((unsigned char)0xF2u) /* DM */)) {
                break;
            }

            (void)hwport_ftpd_send(s_session->m_command_socket, (const void *)(&s_session->m_command_buffer[s_offset]), (size_t)1, s_session->m_send_timeout);

            ++s_offset;
            --s_recv_bytes;
        }
        if(s_recv_bytes == ((ssize_t)0)) { /* ignore command */
            continue;
        }

        /* make command message */
        s_session->m_command = (char *)(&s_session->m_command_buffer[s_offset]);
        while(s_session->m_command_buffer[s_offset] != '\0') {
            if((s_session->m_command_buffer[s_offset] == '\r') && (s_session->m_command_buffer[s_offset + ((ssize_t)1)] == '\n')) {
                s_session->m_command_buffer[s_offset] = '\0';
                break;
            }
            ++s_offset;    
        }

        /* parse command(toupper) and param token */
        s_session->m_param = s_session->m_command;
        s_session->m_command = hwport_ftpd_get_word_sep(1, " \t", (char **)(&s_session->m_param));
        if(s_session->m_param[0] != '\0') {
            s_session->m_param[0] = '\0';
            s_session->m_param = (char *)(&s_session->m_param[1]);
        }

        /* do command */
        if(hwport_ftpd_command(s_session) != 0) {
            /* disconnect by command handler */
            break;
        }
    }

    hwport_ftpd_session_end(s_session);

    return((void *)0);
}

/* ---- */

static int hwport_ftpd_command_user(hwport_ftpd_session_t *s_session)
{
    if(s_session->m_username != ((char *)0)) {
        free((void *)s_session->m_username);
        s_session->m_username = (char *)0;
    }

    /* no account info */
    if(s_session->m_account_head == ((hwport_ftpd_account_t *)0)) {
        char *s_path_home;

        s_path_home = getenv("HOME");
        s_session->m_current_account = (hwport_ftpd_account_t *)0;
        s_session->m_path_home = hwport_ftpd_strdup((s_path_home == ((char *)0)) ? "/" : s_path_home);
        s_session->m_path_work = hwport_ftpd_strdup("/");
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 230, ' ', "Login successful.") == (-1), 0)) {
            /* errno = ... */
            s_session->m_current_account = (hwport_ftpd_account_t *)0;
            return(-1);
        }
        return(0);
    }

    /* for no password user */
    s_session->m_current_account = hwport_ftpd_account_login(s_session, s_session->m_param, (const char *)0);
    if(s_session->m_current_account != ((hwport_ftpd_account_t *)0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 230, ' ', "Login successful.") == (-1), 0)) {
            /* errno = ... */
            s_session->m_current_account = (hwport_ftpd_account_t *)0;
            return(-1);
        }
        return(0);
    }

    s_session->m_username = (char *)hwport_ftpd_strdup(s_session->m_param);
    if(hwport_ftpd_builtin_expect(s_session->m_username == ((char *)0), 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 451, ' ', "Memory exhausted !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    s_session->m_flags |= def_hwport_ftpd_session_flag_user;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 331, ' ', "Password required for ", s_session->m_username) == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_pass(hwport_ftpd_session_t *s_session)
{
    if(s_session->m_username == ((char *)0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 530, ' ', "Please login with USER !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    s_session->m_current_account = hwport_ftpd_account_login(s_session, (const char *)s_session->m_username, (const char *)s_session->m_param);
    if(s_session->m_current_account != ((hwport_ftpd_account_t *)0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 230, ' ', "Login successful.") == (-1), 0)) {
            /* errno = ... */
            s_session->m_current_account = (hwport_ftpd_account_t *)0;
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 530, ' ', "Login incorrect !") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_syst(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 215, ' ', "UNIX Type: L8") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_type(hwport_ftpd_session_t *s_session)
{
    size_t s_param_size = hwport_ftpd_strlen(s_session->m_param);

    if(s_param_size == ((size_t)1u)) {
        switch(hwport_ftpd_toupper((int)s_session->m_param[0])) {
            case 'A':
                s_session->m_type = def_hwport_ftpd_session_type_A;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "Type set to A") == (-1), 0)) {
                    return(-1);
                }
                return(0);
            case 'I':
                s_session->m_type = def_hwport_ftpd_session_type_I;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "Type set to I") == (-1), 0)) {
                    return(-1);
                }
                return(0);
            case 'L':
                s_session->m_type = def_hwport_ftpd_session_type_L8;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "Type set to L (byte size 8)") == (-1), 0)) {
                    return(-1);
                }
                return(0);
            default:
                s_session->m_type = def_hwport_ftpd_session_type_none;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 501, ' ', "Type unknown !") == (-1), 0)) {
                    return(-1);
                }
                return(0);
        }
    }
    else if(s_param_size == ((size_t)3u)) {
        if((hwport_ftpd_toupper((int)s_session->m_param[0]) == 'L') && (s_session->m_param[1] == ' ')) {
            if(s_session->m_param[2] == '8') {
                s_session->m_type = def_hwport_ftpd_session_type_L8;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "Type set to L 8") == (-1), 0)) {
                    return(-1);
                }
                return(0);
            }
            else {
                s_session->m_type = def_hwport_ftpd_session_type_none;
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 504, ' ', "Byte size must be 8 !") == (-1), 0)) {
                    return(-1);
                }
                return(0);
            }
        }
    }
    
    s_session->m_type = def_hwport_ftpd_session_type_none;
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "TYPE not understood !") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_mode(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "MODE command not implemented !") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_abor(hwport_ftpd_session_t *s_session)
{
    (void)hwport_ftpd_data_close(s_session);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 426, ' ', "Transfer aborted. Data connection closed.") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_quit(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 221, ' ', "Good-bye") == (-1), 0)) {
        return(-1);
    }

    return(1 /* to disconnect */);
}

static int hwport_ftpd_command_noop(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "NOOP command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_port(hwport_ftpd_session_t *s_session)
{
    int s_temp_value;
    unsigned int s_value[ 6 ];
    unsigned int s_temp;
    
    char *s_string;
    int s_index;

    s_index = 0;
    while(s_index < ((int)(sizeof(s_value) / sizeof(unsigned int)))) {
        s_string = hwport_ftpd_get_word_sep(1, ",", (char **)(&s_session->m_param));
        if(s_string[0] == '\0') {
            break;
        }

        if(s_session->m_param[0] != '\0') {
            s_session->m_param[0] = '\0';
            s_session->m_param = (char *)(&s_session->m_param[1]);
        }

        s_temp_value = hwport_ftpd_atoi(s_string);
        if((s_temp_value < 0) || (s_temp_value > 255)) {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 501, ' ', "Illegal PORT command") == (-1), 0)) {
                return(-1);
            }
        }

        s_value[s_index++] = (unsigned int)s_temp_value;
    }
    if(s_index < ((int)(sizeof(s_value) / sizeof(unsigned int)))) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 501, ' ', "Illegal PORT command") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    (void)hwport_ftpd_data_close(s_session);

#if 1L /* follow param */
    (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));

    s_session->m_data_sockaddr_all.m_in4.sin_family = AF_INET;
    
    s_temp = (s_value[0] << 24) | (s_value[1] << 16) | (s_value[2] << 8) | (s_value[3]);
    s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr = htonl(s_temp);
    
    s_temp = (s_value[4] << 8) | (s_value[5]);
    s_session->m_data_sockaddr_all.m_in4.sin_port = htons((unsigned short)s_temp);
#else /* follw command socket address */
    /* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) */
    s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);
    if(getpeername(s_session->m_command_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (socklen_t *)(&s_session->m_data_sockaddr_size)) == 0) {
        if(s_session->m_data_sockaddr_all.m_ss.ss_family != AF_INET) {
            (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));

            s_session->m_data_sockaddr_all.m_in4.sin_family = AF_INET;
    
            s_temp = (s_value[0] << 24) | (s_value[1] << 16) | (s_value[2] << 8) | (s_value[3]);
            s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr = htonl(s_temp);
        }
            
        s_temp = (s_value[4] << 8) | (s_value[5]);
        s_session->m_data_sockaddr_all.m_in4.sin_port = htons(s_temp);
    }
    else {
        (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));

        s_session->m_data_sockaddr_all.m_in4.sin_family = AF_INET;
    
        s_temp = (s_value[0] << 24) | (s_value[1] << 16) | (s_value[2] << 8) | (s_value[3]);
        s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr = htonl(s_temp);
    }

    s_temp = (s_value[4] << 8) | (s_value[5]);
    s_session->m_data_sockaddr_all.m_in4.sin_port = htons(s_temp);
#endif

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "PORT command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_eprt(hwport_ftpd_session_t *s_session)
{
    size_t s_offset_left;
    size_t s_offset_right;

    const char *s_sep_string;
    int s_field_count;
    int s_field_index;
    char *s_field[3];

    hwport_ftpd_sockfamily_t s_family;

    s_offset_left = (ssize_t)0;
    s_offset_right = hwport_ftpd_strlen(s_session->m_param);

    if(s_offset_right <= ((ssize_t)0)) { /* no message ? */
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "EPRT command not implemented !") == (-1), 0)) {
            return(-1);
        }

        return(-1);
    }
    --s_offset_right;

    while(s_session->m_param[s_offset_left] != '\0') {
        if(s_session->m_param[s_offset_left] == '|') {
            ++s_offset_left;
            break;
        }
        ++s_offset_left;
    }

    if((s_offset_right <= ((ssize_t)0)) || (s_offset_left > s_offset_right)) { /* invalid format */
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "EPRT command not implemented !") == (-1), 0)) {
            return(-1);
        }

        return(-1);
    }
            
    s_field_count = 3;
    for(s_field_index = 0;s_field_index < s_field_count;s_field_index++) {
        s_field[s_field_index] = (char *)0;
    }
    
    s_sep_string = (const char *)(&s_session->m_param[s_offset_left]);
    for(s_field_index = 0;(s_field_index < s_field_count) && (s_sep_string[0] != '\0');s_field_index++) {
        s_field[s_field_index] = hwport_ftpd_get_word_sep_alloc(1, ",|)", (const char **)(&s_sep_string));
        if(s_field[s_field_index] == ((char *)0)) {
            break;
        }
        if(s_sep_string != '\0') {
            s_sep_string = (const char *)(&s_sep_string[1]);
        }
    }
    if(s_field_index < s_field_count) {
        for(s_field_index = 0;s_field_index < s_field_count;s_field_index++) {
            if(s_field[s_field_index] != ((char *)0)) {
                free((void *)s_field[s_field_index]);
            }
        }
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "EPRT command not implemented !") == (-1), 0)) {
            return(-1);
        }

        return(-1);
    }
    
    (void)hwport_ftpd_data_close(s_session);

    (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));
    s_family = hwport_ftpd_atoi(s_field[0]);
    if(s_family == 1) {
        s_family = AF_INET;
        
        s_session->m_data_sockaddr_all.m_in4.sin_family = s_family;
        (void)hwport_ftpd_inet_pton(s_family, (const char *)s_field[1], (void *)(&s_session->m_data_sockaddr_all.m_in4.sin_addr));
        s_session->m_data_sockaddr_all.m_in4.sin_port = htons((unsigned short)hwport_ftpd_atoi(s_field[2]));
    }
    else if(s_family == 2) {
#if def_hwport_ftpd_can_use_ipv6 != (0L)            
        s_family = AF_INET6;
        
        s_session->m_data_sockaddr_all.m_in6.sin6_family = s_family;
        (void)hwport_ftpd_inet_pton(s_family, (const char *)s_field[1], (void *)(&s_session->m_data_sockaddr_all.m_in6.sin6_addr));
        s_session->m_data_sockaddr_all.m_in6.sin6_port = htons((unsigned short)hwport_ftpd_atoi(s_field[2]));
#else                
        s_family = AF_UNSPEC;
#endif            
    }
    else {
        s_family = AF_UNSPEC;
    }
    
    for(s_field_index = 0;s_field_index < s_field_count;s_field_index++) {
        if(s_field[s_field_index] != ((char *)0)) {
            free((void *)s_field[s_field_index]);
        }
    }

    if(hwport_ftpd_builtin_expect(s_family == AF_UNSPEC, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "EPRT command not implemented !") == (-1), 0)) {
            return(-1);
        }

        return(-1);
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "EPRT command successful") == (-1), 0)) {
        return(-1);
    }
    
    return(0);
}
        
static int hwport_ftpd_command_pwd(hwport_ftpd_session_t *s_session)
{
    const char *s_path_work = (s_session->m_path_work == ((char *)0)) ? ((const char *)"") : ((const char *)s_session->m_path_work);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c\"%s\" is current directory.\r\n", 257, ' ', s_path_work) == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_change_remote_directory(hwport_ftpd_session_t *s_session, char *s_remote_path)
{
    char *s_path_abs;
    char *s_path_work;
    struct stat s_stat;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_remote_path, (char **)(&s_path_abs), (char **)(&s_path_work)) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not change directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(stat(s_path_abs, (struct stat *)(&s_stat)) != 0) {
        free((void *)s_path_work);
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_remote_path, ": No such file or directory") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    if(S_ISDIR(s_stat.st_mode) == 0) {
        free((void *)s_path_work);
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_remote_path, ": No such file or directory") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    free((void *)s_path_abs);

    if(s_session->m_path_work != ((char *)0)) {
        free((void *)s_session->m_path_work);
    }
    s_session->m_path_work = s_path_work;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 250, ' ', "CWD command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_cwd(hwport_ftpd_session_t *s_session)
{
    return(hwport_ftpd_command_change_remote_directory(s_session, s_session->m_param));
}

static int hwport_ftpd_command_cdup(hwport_ftpd_session_t *s_session)
{
    char s_param_local[] = {".."};

    return(hwport_ftpd_command_change_remote_directory(s_session, (char *)(&s_param_local[0])));
}

static int hwport_ftpd_command_rmd(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    char *s_path_work;
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)(&s_path_work)) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not remove directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_strcmp(s_session->m_path_home, s_path_abs) == 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not remove home directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_strcmp(s_session->m_path_work, s_path_work) == 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not remove current directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(rmdir(s_path_abs) != 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not remove directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    
    free((void *)s_path_abs);
    free((void *)s_path_work);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 250, ' ', "RMD command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_mkd(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not make directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(mkdir(s_path_abs, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        free((void *)s_path_abs);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not make directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    if(s_session->m_current_account != ((hwport_ftpd_account_t *)0)) { /* set effective user:group */
        int s_check;

        s_check = chown(s_path_abs, s_session->m_current_account->m_uid, s_session->m_current_account->m_gid);
    }
    
    free((void *)s_path_abs);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 250, ' ', "MKD command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_dele(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    char *s_path_work;
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)(&s_path_work)) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not delete file !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_strcmp(s_session->m_path_home, s_path_abs) == 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not delete home directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_strcmp(s_session->m_path_work, s_path_work) == 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not delete current directory !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(remove(s_path_abs) != 0) {
        free((void *)s_path_abs);
        free((void *)s_path_work);

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not delete file !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    
    free((void *)s_path_abs);
    free((void *)s_path_work);

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 250, ' ', "DELE command successful") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_pasv(hwport_ftpd_session_t *s_session)
{
    unsigned int s_value[6];
    unsigned int s_temp;

    (void)hwport_ftpd_data_close(s_session);

    s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);
     
    s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
    if(hwport_ftpd_builtin_expect(s_session->m_data_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "PASV socket create fail !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_builtin_expect(getsockname(s_session->m_command_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (socklen_t *)(&s_session->m_data_sockaddr_size)) != 0, 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "PASV getsockname fail !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

#if (def_hwport_ftpd_can_use_ipv6 != 0L) && defined(AF_INET6)
    if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET6) { /* convert ipv6 to ipv4 */
        if((IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)(&s_session->m_data_sockaddr_all.m_in6.sin6_addr)) != 0) ||
           (IN6_IS_ADDR_V4COMPAT((const struct in6_addr *)(&s_session->m_data_sockaddr_all.m_in6.sin6_addr)) != 0)) { /* convert ipv6 to ipv4 */
            hwport_ftpd_in4_addr_t s_in4_addr;

            s_in4_addr.s_addr = s_session->m_data_sockaddr_all.m_in6.sin6_addr.s6_addr32[3];

            (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));
            s_session->m_data_sockaddr_all.m_in4.sin_family = AF_INET;
            s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr = s_in4_addr.s_addr;
        }
    }
#endif

    if(s_session->m_data_sockaddr_all.m_ss.ss_family != AF_INET) { /* fixed to ipv4 */
        (void)memset((void *)(&s_session->m_data_sockaddr_all), 0, sizeof(s_session->m_data_sockaddr_all));
        s_session->m_data_sockaddr_all.m_in4.sin_family = AF_INET;
        s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    s_session->m_data_sockaddr_all.m_in4.sin_port = 0;
    if(hwport_ftpd_builtin_expect(hwport_ftpd_bind(s_session->m_data_socket, (const void *)(&s_session->m_data_sockaddr_all), s_session->m_data_sockaddr_size) != 0, 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "PASV bind fail !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_builtin_expect(getsockname(s_session->m_data_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (socklen_t *)(&s_session->m_data_sockaddr_size)) != 0, 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "PASV getsockname fail !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_listen(s_session->m_data_socket, 1) != 0, 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "PASV listen fail !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_builtin_expect(ntohl(s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr) == INADDR_ANY, 0)) {
        (void)hwport_ftpd_data_close(s_session);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 425, ' ', "Can not open passive connection") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        return(0);
    }

    s_temp = (unsigned int)ntohl(s_session->m_data_sockaddr_all.m_in4.sin_addr.s_addr);
    s_value[0] = (s_temp >> 24) & 0xFFu;
    s_value[1] = (s_temp >> 16) & 0xFFu;
    s_value[2] = (s_temp >> 8) & 0xFFu;
    s_value[3] = (s_temp) & 0xFFu;
    s_temp = (unsigned int)ntohs(s_session->m_data_sockaddr_all.m_in4.sin_port);
    s_value[4] = (s_temp >> 8) & 0xFFu;
    s_value[5] = (s_temp) & 0xFFu;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%cEntering passive mode (%u,%u,%u,%u,%u,%u).\r\n", 227, ' ', s_value[0], s_value[1], s_value[2], s_value[3], s_value[4], s_value[5]) == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_epsv(hwport_ftpd_session_t *s_session)
{
    (void)hwport_ftpd_data_close(s_session);

    s_session->m_data_sockaddr_size = (hwport_ftpd_socklen_t)sizeof(s_session->m_data_sockaddr_all);

#if (def_hwport_ftpd_can_use_ipv6 != (0)) && defined(PF_INET6)
    s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET6, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
    if(s_session->m_data_socket == ((hwport_ftpd_socket_t)(-1))) {
        s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
    }
    else {
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)    
        do {
            int s_ipv6_only = 0;
            (void)setsockopt(s_session->m_data_socket, IPPROTO_IPV6, IPV6_V6ONLY, &s_ipv6_only, sizeof(s_ipv6_only));
        }while(0);
#endif        
    }
#else
    s_session->m_data_socket = hwport_ftpd_socket_open(PF_INET, SOCK_STREAM, hwport_ftpd_get_protocol_by_name("tcp"));
#endif
    if(hwport_ftpd_builtin_expect(s_session->m_data_socket == ((hwport_ftpd_socket_t)(-1)), 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "EPSV socket create fail !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(0);
    }

    if(hwport_ftpd_builtin_expect(getsockname(s_session->m_command_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (socklen_t *)(&s_session->m_data_sockaddr_size)) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "EPSV getsockname fail !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(0);
    }

#if defined(AF_INET6)
    if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET6) {
        s_session->m_data_sockaddr_all.m_in6.sin6_port = htons(0);
    }
    else if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET) {
        s_session->m_data_sockaddr_all.m_in4.sin_port = htons(0);
    }
#else
    s_session->m_data_sockaddr_all.m_in4.sin_port = htons(0);
#endif    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_bind(s_session->m_data_socket, (const void *)(&s_session->m_data_sockaddr_all), s_session->m_data_sockaddr_size) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "EPSV bind fail !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(0);
    }

    if(hwport_ftpd_builtin_expect(getsockname(s_session->m_data_socket, (struct sockaddr *)(&s_session->m_data_sockaddr_all), (socklen_t *)(&s_session->m_data_sockaddr_size)) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "EPSV getsockname fail !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(0);
    }
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_listen(s_session->m_data_socket, 1) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 500, ' ', "EPSV listen fail !") == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
        (void)hwport_ftpd_data_close(s_session);
        return(0);
    }

#if defined(AF_INET6)
    if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET6) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%cEntering Extended Passive Mode (|||%u|).\r\n", 229, ' ', (unsigned int)ntohs(s_session->m_data_sockaddr_all.m_in6.sin6_port)) == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
    }
    else if(s_session->m_data_sockaddr_all.m_ss.ss_family == AF_INET) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%cEntering Extended Passive Mode (|%u||%u|).\r\n", 229, ' ', 1u, (unsigned int)ntohs(s_session->m_data_sockaddr_all.m_in4.sin_port)) == (-1), 0)) {
            (void)hwport_ftpd_data_close(s_session);
            return(-1);
        }
    }
    else {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "EPSV command not implemented !") == (-1), 0)) {
            return(-1);
        }
    }
#else
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%cEntering Extended Passive Mode (|%u||%u|).\r\n", 229, ' ', 1u, (unsigned int)ntohs(s_session->m_data_sockaddr_all.m_in4.sin_port)) == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }
#endif    

    return(0);
}

static int hwport_ftpd_command_list(hwport_ftpd_session_t *s_session)
{
    unsigned int s_list_option = def_hwport_ftpd_list_option_l;

    if(hwport_ftpd_data_open(s_session) != 0) {
        return(0);
    }
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 150, ' ', "Opening ASCII mode data connection for file list") == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }
   
    s_list_option |= hwport_ftpd_get_list_option((char **)(&s_session->m_param));
    (void)hwport_ftpd_list(s_session, s_list_option);
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 226, ' ', "Transfer complete") == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }
    
    (void)hwport_ftpd_data_close(s_session);

    return(0);
}

static int hwport_ftpd_command_nlst(hwport_ftpd_session_t *s_session)
{
    unsigned int s_list_option = def_hwport_ftpd_list_option_none;

    if(hwport_ftpd_data_open(s_session) != 0) {
        return(0);
    }
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 150, ' ', "Opening ASCII mode data connection for file list") == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }
   
    s_list_option |= hwport_ftpd_get_list_option((char **)(&s_session->m_param));
    (void)hwport_ftpd_list(s_session, s_list_option);
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 226, ' ', "Transfer complete") == (-1), 0)) {
        (void)hwport_ftpd_data_close(s_session);
        return(-1);
    }

    (void)hwport_ftpd_data_close(s_session);

    return(0);
}

static int hwport_ftpd_command_acct(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "ACCT command not implemented !") == (-1), 0)) {
        return(-1);
    }
    
    return(0);
}

static int hwport_ftpd_command_size(hwport_ftpd_session_t *s_session)
{
    int s_result;
    char *s_path_abs;
    char *s_path;
    struct stat s_stat;

    FILE *s_fp;
    off_t s_offset;
    int s_byte;
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Unknown size !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    s_path = s_path_abs;
    
    s_result = 0;
    switch(s_session->m_type) {
        case def_hwport_ftpd_session_type_none:
        case def_hwport_ftpd_session_type_L8:
        case def_hwport_ftpd_session_type_I:
            if(stat(s_path, (struct stat *)(&s_stat)) != 0) {
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a regular file.") == (-1), 0)) {
                    /* errno = ... */
                    s_result = (-1);
                }
                break;
            }
            if(S_ISREG(s_stat.st_mode) == 0) {
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a regular file.") == (-1), 0)) {
                    /* errno = ... */
                    s_result = (-1);
                }
                break;
            }
    
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%llu\r\n", 213, ' ', (unsigned long long)s_stat.st_size) == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
        case def_hwport_ftpd_session_type_A: 
            if(stat(s_path, (struct stat *)(&s_stat)) != 0) {
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a regular file.") == (-1), 0)) {
                    /* errno = ... */
                    s_result = (-1);
                }
                break;
            }
            if(S_ISREG(s_stat.st_mode) == 0) {
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a regular file.") == (-1), 0)) {
                    /* errno = ... */
                    s_result = (-1);
                }
                break;
            }

            s_fp = fopen(s_path, "r");
            if(hwport_ftpd_builtin_expect(s_fp == ((FILE *)0), 0)) {
                if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": Can not open file !") == (-1), 0)) {
                    /* errno = ... */
                    s_result = (-1);
                }
                break;
            }

            s_offset = (off_t)0;
            for(;;) {
                s_byte = getc(s_fp);
                if(s_byte == EOF) {
                    break;
                }
                if(s_byte == 'c') {
                    ++s_offset;
                }
                ++s_offset;
            }

            (void)fclose(s_fp);
            
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%llu\r\n", 213, ' ', (unsigned long long)s_offset) == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
        default:
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 504, ' ', "SIZE not implemented for type") == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
    }
                
    free((void *)s_path_abs);

    return(s_result);
}

static int hwport_ftpd_command_stru(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "STRU command not implemented !") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_rnfr(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    char *s_path;
    struct stat s_stat;
    
    if(s_session->m_path_rename_from != ((char *)0)) {
        free((void *)s_session->m_path_rename_from);
        s_session->m_path_rename_from = (char *)0;
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "RNFR error !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    s_path = s_path_abs;
    
    if(stat(s_path, (struct stat *)(&s_stat)) != 0) {
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": No such file or directory.") == (-1), 0)) {
            /* errno = ... */
            return(-1);
        }
        return(0);
    }
    
    s_session->m_path_rename_from = s_path_abs;
    s_session->m_flags |= def_hwport_ftpd_session_flag_rename_from;
  
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 350, ' ', "RNFR successful") == (-1), 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_rnto(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    
    if(s_session->m_path_rename_from == ((char *)0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "RNTO error !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "RNTO error !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
 
    /* int rename(const char *oldpath, const char *newpath) */
    if(rename(s_session->m_path_rename_from, s_path_abs) != 0) {
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": Rename error.") == (-1), 0)) {
            /* errno = ... */
            return(-1);
        }
        return(0);
    }

    free((void *)s_path_abs);
  
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 250, ' ', "Rename successful") == (-1), 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_retr(hwport_ftpd_session_t *s_session)
{
    return(hwport_ftpd_command_stream(s_session, 0));
}

static int hwport_ftpd_command_stor(hwport_ftpd_session_t *s_session)
{
    return(hwport_ftpd_command_stream(s_session, 1));
}

static int hwport_ftpd_command_appe(hwport_ftpd_session_t *s_session)
{
    return(hwport_ftpd_command_stream(s_session, 2));
}

static int hwport_ftpd_command_rest(hwport_ftpd_session_t *s_session)
{
#if def_hwport_ftpd_can_use_long_long != (0L)
    s_session->m_restart_position = (off_t)hwport_ftpd_atoll(s_session->m_param);
#else    
    s_session->m_restart_position = (off_t)hwport_ftpd_atoi(s_session->m_param);
#endif
    s_session->m_flags |= def_hwport_ftpd_session_flag_restart_position;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 320, ' ', "Restart position ready") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_mdtm(hwport_ftpd_session_t *s_session)
{
    char *s_path_abs;
    char *s_path;
    struct stat s_stat;
    struct tm s_tm;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Unknown size !") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }
    s_path = s_path_abs;
    
    if(stat(s_path, (struct stat *)(&s_stat)) != 0) {
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a plain file.") == (-1), 0)) {
            /* errno = ... */
            return(-1);
        }
        return(0);
    }
    if(S_ISREG(s_stat.st_mode) == 0) {
        free((void *)s_path_abs);
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 550, ' ', s_session->m_param, ": not a plain file.") == (-1), 0)) {
            /* errno = ... */
            return(-1);
        }
        return(0);
    }
    
    free((void *)s_path_abs);
  
    (void)memcpy((void *)(&s_tm), gmtime((const time_t *)(&s_stat.st_mtime)), sizeof(s_tm)); 

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%04u%02u%02u%02u%02u%02u\r\n", 213, ' ', (unsigned int)(s_tm.tm_year + 1900), (unsigned int)(s_tm.tm_mon + 1), (unsigned int)(s_tm.tm_mday), (unsigned int)(s_tm.tm_hour), (unsigned int)(s_tm.tm_min), (unsigned int)(s_tm.tm_sec)) == (-1), 0)) {
        /* errno = ... */
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_opts(hwport_ftpd_session_t *s_session)
{
    char *s_sep_string;
    char *s_option_name;
    char *s_option_value;

    int s_switch_remote = (-1);
    int s_switch_local = (-1);

    /* token: name and value */
    s_sep_string = s_session->m_param;
    s_option_name = hwport_ftpd_get_word_sep(1, " \t", (char **)(&s_sep_string));
    if(s_sep_string[0] != '\0') {
        s_sep_string[0] = '\0';
        s_sep_string = (char *)(&s_sep_string[1]);
    }
    s_option_value = s_sep_string;

    if((hwport_ftpd_strcasecmp(s_option_name, "UTF8") == 0) ||
       (hwport_ftpd_strcasecmp(s_option_name, "UTF-8") == 0)) {
        char *s_lang;

        if((s_option_value[0] == '\0') ||
           (hwport_ftpd_strcasecmp(s_option_value, "ON") == 0) ||
           (hwport_ftpd_strcasecmp(s_option_value, "ENABLE") == 0) ||
           (hwport_ftpd_strcasecmp(s_option_value, "TRUE") == 0)) {
            s_switch_remote = 1;
        }
        else {
            s_switch_remote = 0;
        }

        s_lang = getenv("LANG");
        if(s_lang != ((char *)0)) {
            if((hwport_ftpd_strcasestr(s_lang, "UTF8") != ((char *)0)) ||
               (hwport_ftpd_strcasestr(s_lang, "UTF-8") != ((char *)0))) {
                s_switch_local = 1;
            }
            else {
                s_switch_local = 0;
            }
        }
#if 1L && defined(__linux__) /* OPTION: UTF-8 is default for linux */
        else {
            s_switch_local = 1;
        }
#endif

        if(s_switch_remote != s_switch_local) {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 504, ' ', "UIF-8 disabled") == (-1), 0)) {
                return(-1);
            }

            return(0);
        }

        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 200, ' ', "OK, UTF-8 enabled") == (-1), 0)) {
            return(-1);
        }

        return(0);
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s%s\r\n", 501, ' ', "OPTS: ", s_option_name, " not understood") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_site(hwport_ftpd_session_t *s_session)
{
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 502, ' ', "SITE command not implemented !") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

static int hwport_ftpd_command_help(hwport_ftpd_session_t *s_session)
{
    static const char *cg_help[] = {
        "The following commands are recognized (* =>'s unimplemented):",
        "CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV",
        "EPRT*   EPSV*   ALLO*   RNFR    RNTO    DELE    MDTM    RMD",
        "XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP",
        "NOOP    FEAT*   OPTS    AUTH*   CCC*    CONF*   ENC*    MIC*",
        "PBSZ*   PROT*   TYPE    STRU*   MODE*   RETR    STOR    STOU*",
        "APPE    REST    ABOR    USER    PASS    ACCT*   REIN*   LIST",
        "NLST    STAT*   SITE*   MLSD*   MLST*",
        "Direct comments to " def_hwport_ftpd_company_name,
        (const char *)0
    };
    int s_help_index;

    s_help_index = 0;
    while(cg_help[s_help_index] != ((const char *)0)) {
        if(s_help_index == 0 || cg_help[s_help_index + 1] == ((const char *)0)) {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 214, (cg_help[s_help_index + 1] == ((const char *)0)) ? ' ' : '-', cg_help[s_help_index]) == (-1), 0)) {
                return(-1);
            }
        }
        else {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%c%s\r\n", ' ', cg_help[s_help_index]) == (-1), 0)) {
                return(-1);
            }
        }
        ++s_help_index;
    }

    return(0);
}

/* ---- */

static int hwport_ftpd_get_path(hwport_ftpd_session_t *s_session, const char *s_change_directory, char **s_path_abs, char **s_path_work)
{
    hwport_ftpd_path_node_t *s_path_abs_node;
    hwport_ftpd_path_node_t *s_path_work_node;
    hwport_ftpd_path_node_t *s_path_append_node;

    char *s_path_abs_local;
    char *s_path_work_local;

    if(s_path_abs != ((char **)0)) {
        *s_path_abs = (char *)0;
    }

    if(s_path_work != ((char **)0)) {
        *s_path_work = (char *)0;
    }
    
    s_path_work_node = hwport_ftpd_path_to_node((s_session->m_path_work == ((char *)0)) ? ((const char *)"") : ((const char *)s_session->m_path_work));
    if(hwport_ftpd_builtin_expect(s_path_work_node == ((hwport_ftpd_path_node_t *)0), 0)) {
        return(-1);
    }
    s_path_append_node = hwport_ftpd_path_to_node(s_change_directory);
    s_path_work_node = hwport_ftpd_append_path_node(s_path_work_node, s_path_append_node, 1);

    s_path_work_local = hwport_ftpd_node_to_path(s_path_work_node, 1);
    if(hwport_ftpd_builtin_expect(s_path_work_local == ((char *)0), 0)) {
        s_path_work_node = hwport_ftpd_free_path_node(s_path_work_node);
        return(-1);
    }

    s_path_abs_node = hwport_ftpd_path_to_node((s_session->m_path_home == ((char *)0)) ? ((const char *)"") : ((const char *)s_session->m_path_home));
    if(hwport_ftpd_builtin_expect(s_path_abs_node == ((hwport_ftpd_path_node_t *)0), 0)) {
        free((void *)s_path_work_local);
        s_path_work_node = hwport_ftpd_free_path_node(s_path_work_node);
        return(-1);
    }
    s_path_append_node = hwport_ftpd_path_to_node(s_path_work_local);
    s_path_abs_node = hwport_ftpd_append_path_node(s_path_abs_node, s_path_append_node, 0);
    s_path_abs_local = hwport_ftpd_node_to_path(s_path_abs_node, 1);
    if(hwport_ftpd_builtin_expect(s_path_abs_local == ((char *)0), 0)) {
        free((void *)s_path_work_local);
        s_path_abs_node = hwport_ftpd_free_path_node(s_path_abs_node);
        s_path_work_node = hwport_ftpd_free_path_node(s_path_work_node);
        return(-1);
    }

    if(s_path_work == ((char **)0)) {
        free((void *)s_path_work_local);
    }
    else {
        *s_path_work = s_path_work_local;
    }

    if(s_path_abs == ((char **)0)) {
        free((void *)s_path_abs_local);
    }
    else {
        *s_path_abs = s_path_abs_local;
    }
    
    s_path_abs_node = hwport_ftpd_free_path_node(s_path_abs_node);
    s_path_work_node = hwport_ftpd_free_path_node(s_path_work_node);

    return(0);
}

/* ---- */

static unsigned int hwport_ftpd_get_list_option(char **s_param_ptr)
{
    unsigned int s_result = def_hwport_ftpd_list_option_none;
    char *s_param = *s_param_ptr;

    while(s_param[0] == '-') {
        while((s_param[0] != '\0') && (hwport_ftpd_isspace(s_param[0]) == 0)) {
            switch(s_param[0]) {
                case 'a':
                case 'A':
                    s_result |= def_hwport_ftpd_list_option_a;
                    break;
                case 'l':
                case 'L':
                    s_result |= def_hwport_ftpd_list_option_l;
                    break;
                case 'f':
                case 'F':
                    s_result |= def_hwport_ftpd_list_option_f;
                    break;
                case 'r':
                case 'R':
                    s_result |= def_hwport_ftpd_list_option_r;
                    break;
                default:
                    s_result |= def_hwport_ftpd_list_option_unknown;
                    break;
            }

            s_param = (char *)(&s_param[1]);
        }

        if(s_param[0] != '\0') {
            while((s_param[0] != '\0') && (hwport_ftpd_isspace(s_param[0]) != 0)) {
                s_param = (char *)(&s_param[1]);
            }
        }
    }

    *s_param_ptr = s_param;

    return(s_result);
}

static int hwport_ftpd_list_buffer(hwport_ftpd_session_t *s_session, char *s_path, struct stat *s_stat_ptr, char *s_buffer, size_t s_buffer_size, unsigned int s_list_option)
{
    char *s_basename;
    size_t s_offset = (size_t)0u;

    (void)s_session;

    s_basename = hwport_ftpd_basename(s_path);

    if((s_list_option & def_hwport_ftpd_list_option_l) != def_hwport_ftpd_list_option_none) {
        static const char *cg_month_name_table[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dev"};
        const char *c_this;
#if def_hwport_ftpd_use_pwd != (0L)		
        struct passwd *s_passwd;
#endif	
#if def_hwport_ftpd_use_grp != (0L)
        struct group *s_group;
#endif	
        struct tm s_tm;
        time_t s_time_now;

        if(S_ISREG(s_stat_ptr->st_mode) != 0) {
            c_this = "-";
        }
        else if(S_ISDIR(s_stat_ptr->st_mode) != 0) {
            c_this = "d";
        }
        else if(S_ISCHR(s_stat_ptr->st_mode) != 0) {
            c_this = "c";
        }
        else if(S_ISBLK(s_stat_ptr->st_mode) != 0) {
            c_this = "b";
        }
        else if(S_ISFIFO(s_stat_ptr->st_mode) != 0) {
            c_this = "p";
        }
        else if(S_ISLNK(s_stat_ptr->st_mode) != 0) {
            c_this = "l";
        }
        else if(S_ISSOCK(s_stat_ptr->st_mode) != 0) {
            c_this = "s";
        }
        else {
            c_this = "-";
        }
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        /* user */
        c_this = ((s_stat_ptr->st_mode & S_IRUSR) != 0) ? "r" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        c_this = ((s_stat_ptr->st_mode & S_IWUSR) != 0) ? "w" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        if(((s_stat_ptr->st_mode & S_ISUID) != 0) && ((s_stat_ptr->st_mode & S_IXUSR) != 0)) {
            c_this = "s";
        }
        else if((s_stat_ptr->st_mode & S_ISUID) != 0) {
            c_this = "S";
        }
        else if((s_stat_ptr->st_mode & S_IXUSR) != 0) {
            c_this = "x";
        }
        else {
            c_this = "-";
        }
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        /* group */
        c_this = ((s_stat_ptr->st_mode & S_IRGRP) != 0) ? "r" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        c_this = ((s_stat_ptr->st_mode & S_IWGRP) != 0) ? "w" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);
        
        if(((s_stat_ptr->st_mode & S_ISGID) != 0) && ((s_stat_ptr->st_mode & S_IXGRP) != 0)) {
            c_this = "s";
        }
        else if((s_stat_ptr->st_mode & S_ISGID) != 0) {
            c_this = "S";
        }
        else if((s_stat_ptr->st_mode & S_IXGRP) != 0) {
            c_this = "x";
        }
        else {
            c_this = "-";
        }
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);
        
        /* other */
        c_this = ((s_stat_ptr->st_mode & S_IROTH) != 0) ? "r" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        c_this = ((s_stat_ptr->st_mode & S_IWOTH) != 0) ? "w" : "-";
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);
        
        if(((s_stat_ptr->st_mode & S_ISVTX) != 0) && ((s_stat_ptr->st_mode & S_IXOTH) != 0)) {
            c_this = "t";
        }
        else if((s_stat_ptr->st_mode & S_ISVTX) != 0) {
            c_this = "T";
        }
        else if((s_stat_ptr->st_mode & S_IXOTH) != 0) {
            c_this = "x";
        }
        else {
            c_this = "-";
        }
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s", c_this);

        /* nlink */
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%4u", (unsigned int)s_stat_ptr->st_nlink);

        /* username */
#if def_hwport_ftpd_use_pwd != (0L)		
        s_passwd = getpwuid(s_stat_ptr->st_uid);
        if(s_passwd != ((struct passwd *)0)) {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %-8s", s_passwd->pw_name);
        }
        else {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %8u", (unsigned int)s_stat_ptr->st_uid);
        }
#else	
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %8u", (unsigned int)s_stat_ptr->st_uid);
#endif	

        /* groupname */
#if def_hwport_ftpd_use_grp != (0L)	
        s_group = getgrgid(s_stat_ptr->st_gid);
        if(s_group != ((struct group *)0)) {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %-8s", s_group->gr_name);
        }
        else {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %8u", (unsigned int)s_stat_ptr->st_gid);
        }
#else
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %8u", (unsigned int)s_stat_ptr->st_gid);
#endif

        /* size */
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %8u", (unsigned int)s_stat_ptr->st_size);

        /* time */
        (void)memcpy((void *)(&s_tm), (const void *)localtime((const time_t *)(&s_stat_ptr->st_mtime)), sizeof(s_tm));
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %s %2u", cg_month_name_table[s_tm.tm_mon], (unsigned int)s_tm.tm_mday);
        s_time_now = time((time_t *)0);
        if((s_time_now - s_stat_ptr->st_mtime) > ((time_t)(60 * 60 * 24 * 180))) {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %5u", (unsigned int)(s_tm.tm_year + 1900));
        }
        else {
            s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %02u:%02u", (unsigned int)s_tm.tm_hour, (unsigned int)s_tm.tm_min);
        }
        
        /* basename */
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " %s", s_basename);

        /* linkname */
        if(S_ISLNK(s_stat_ptr->st_mode) != 0) {
            char *s_temp;
            int s_linkname_size;

            s_temp = (char *)malloc((size_t)(PATH_MAX + 1));
            if(s_temp != ((char *)0)) {
                s_linkname_size = readlink(s_path, s_temp, PATH_MAX);
                if(s_linkname_size != (-1)) {
                    s_temp[s_linkname_size] = '\0';
                }
                s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, " -> %s", s_temp);
                free((void *)s_temp);
            }
        }
        
        /* end */
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "\r\n");
    }
    else {
        /* basename */
        s_offset += (size_t)hwport_ftpd_snprintf((char *)(&s_buffer[s_offset]), s_buffer_size - s_offset, "%s\r\n", s_basename);
    }

    return(0);
}

static int hwport_ftpd_list_scan(hwport_ftpd_session_t *s_session, char *s_path, unsigned int s_list_option)
{
    int s_result = 0;
    char *s_temp_path;
    DIR *s_dir;
    struct dirent *s_dirent;
    struct stat s_stat;

    if(stat(s_path, (struct stat *)(&s_stat)) != 0) {
        return(-1);
    }

    if(S_ISDIR(s_stat.st_mode) == 0) {
        s_result = hwport_ftpd_list_buffer(s_session, s_path, (struct stat *)(&s_stat), (char *)s_session->m_data_buffer, s_session->m_data_buffer_size, s_list_option); 
        if(s_result == 0) {  
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_data_socket, s_session->m_send_timeout, "%s", (char *)s_session->m_data_buffer) == (-1), 0)) {
                s_result = (-1);
            }
        }
     
        return(s_result);
    }

    s_dir = opendir(s_path);
    if(s_dir == ((DIR *)0)) {
        return(-1);
    }

    for(;;) {
        s_dirent = readdir(s_dir);
        if(s_dirent == ((struct dirent *)0)) {
            break;
        }

        if(s_dirent->d_name[0] == '.') {
            if((s_list_option & def_hwport_ftpd_list_option_a) == def_hwport_ftpd_list_option_none) {
                continue;
            }
        }
 
        s_temp_path = hwport_ftpd_alloc_sprintf("%s/%s", s_path, s_dirent->d_name);
        if(hwport_ftpd_builtin_expect(s_temp_path == ((char *)0), 0)) {
            continue;
        }

#if 0L /* OPTION: Microsoft window explorer is unknown symbolic link */
        if(lstat(s_temp_path, (struct stat *)(&s_stat)) != 0) {
            free((void *)s_temp_path);
            continue;
        }
#else
        if(stat(s_temp_path, (struct stat *)(&s_stat)) != 0) {
            free((void *)s_temp_path);
            continue;
        }
#endif

        s_result = hwport_ftpd_list_buffer(s_session, s_temp_path, (struct stat *)(&s_stat), (char *)s_session->m_data_buffer, s_session->m_data_buffer_size, s_list_option); 
        if(s_result == 0) {  
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_data_socket, s_session->m_send_timeout, "%s", (char *)s_session->m_data_buffer) == (-1), 0)) {
                s_result = (-1);
            }
        }

        free((void *)s_temp_path);

        if(s_result != 0) {
            break;
        }
    }

    (void)closedir(s_dir);

    return(s_result);
}

static int hwport_ftpd_list(hwport_ftpd_session_t *s_session, unsigned int s_list_option)
{
#if def_hwport_ftpd_use_glob != (0L)
    int s_result = 0;
    char *s_path_abs;
    glob_t s_glob;
    size_t s_glob_index;
    struct stat s_stat;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        return(-1);
    }

    /* int glob(const char *pattern, int flags, int (*errfunc) (const char *epath, int eerrno), glob_t *pglob) */
    if(hwport_ftpd_strpbrk(s_session->m_param, "~{[*?") == ((char *)0)) { /* no glob mode */
        s_result = hwport_ftpd_list_scan(s_session, s_path_abs, s_list_option);
    }
    else {
        int s_glob_flags = GLOB_NOCHECK;
        if(glob(s_path_abs, s_glob_flags, NULL, (glob_t *)(&s_glob)) == 0) { /* glob mode */
            if(s_glob.gl_pathc > ((size_t)0u)) {
                s_glob_index = (size_t)0u;
                while(s_glob.gl_pathv[s_glob_index] != ((char *)0)) {
                    if(stat(s_glob.gl_pathv[s_glob_index], (struct stat *)(&s_stat)) == 0) {
                        s_result = hwport_ftpd_list_buffer(s_session, s_glob.gl_pathv[s_glob_index], (struct stat *)(&s_stat), (char *)s_session->m_data_buffer, s_session->m_data_buffer_size, s_list_option); 
                        if(hwport_ftpd_builtin_expect(s_result != 0, 0)) {
                            break;
                        }
                        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_data_socket, s_session->m_send_timeout, "%s", (char *)s_session->m_data_buffer) == (-1), 0)) {
                            s_result = (-1);
                            break;
                        }
                    } 
                    ++s_glob_index;
                }
            }

            /* void globfree(glob_t *pglob); */
            globfree((glob_t *)(&s_glob));
        }
        else { /* glob fail mode */
            s_result = hwport_ftpd_list_scan(s_session, s_path_abs, s_list_option);
        }
    }

    free((void *)s_path_abs);

    return(s_result);
#else
    int s_result;
    char *s_path_abs;

    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        return(-1);
    }

    s_result = hwport_ftpd_list_scan(s_session, s_path_abs, s_list_option);
    free((void *)s_path_abs);

    return(s_result);
#endif    
}

/* ---- */

static off_t hwport_ftpd_ascii_to_binary_offset(const char *s_filename, off_t s_offset)
{
    off_t s_result;
    off_t s_temp_offset;
    FILE *s_fp;
    int s_byte;

    s_fp = fopen(s_filename, "r");
    if(hwport_ftpd_builtin_expect(s_fp == ((FILE *)0), 0)) {
        return((off_t)(-1));
    }

    s_result = (off_t)0; 
    s_temp_offset = (off_t)0; 

    if(s_offset == ((off_t)(-1))) {
        for(;;) {
            s_byte = getc(s_fp);
            if(s_byte == EOF) {
                break;
            }
            ++s_result;
            if(s_byte == '\n') {
                ++s_result;
            }
        }
        /* s_result is ascii mode size */
    }
    else {
        while(s_offset < s_temp_offset) {
            s_byte = getc(s_fp);
            if(s_byte == EOF) {
                s_result = (off_t)(-1);
                break;
            }
            ++s_result;
            ++s_temp_offset;

            if(s_byte == '\n') {
                ++s_temp_offset;
            }
        }
        /* s_result is binary mode offset */
    }

    (void)fclose(s_fp);

    return(s_result);
}

/* ---- */

static int hwport_ftpd_command_stream(hwport_ftpd_session_t *s_session, int s_command_type)
{
    int s_result = 0;

    char *s_path_abs;
    char *s_path;
    
    int s_is_new;
    int s_open_flags;
    
    unsigned char *s_buffer;
    size_t s_buffer_size;
    
    size_t s_want_size;
    ssize_t s_read_bytes;
    ssize_t s_write_bytes;

    off_t s_position = (off_t)0;
    
    if(hwport_ftpd_builtin_expect(hwport_ftpd_get_path(s_session, s_session->m_param, (char **)(&s_path_abs), (char **)0) != 0, 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Stream error !") == (-1), 0)) {
            s_result = (-1);
        }
        goto l_end_stream_0;
    }
    s_path = s_path_abs;

    if(hwport_ftpd_data_open(s_session) != 0) {
        goto l_end_stream_1;
    }

    switch(s_command_type) {
        case 0: /* retr */
            s_open_flags = O_RDONLY;
            break;
        case 1: /* stor */
            s_open_flags = O_CREAT | O_WRONLY;
            break;
        case 2: /* appe */
            s_open_flags = O_CREAT | O_WRONLY | O_APPEND;
            break;
        default:
            s_open_flags = O_RDONLY;
            break;
    }

#if defined(O_LARGEFILE)
    s_open_flags |= O_LARGEFILE;
#endif
#if defined(O_BINARY)
    s_open_flags |= O_BINARY;
#endif
    if((s_open_flags & O_CREAT) != 0) {
        int s_open_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

#if defined(O_TRUNC)
        if(s_session->m_restart_position <= ((off_t)0)) {
            s_open_flags |= O_TRUNC;
        }
#endif

#if defined(O_EXCL)    
        s_is_new = 1;
        s_session->m_fd = open(s_path, s_open_flags | O_EXCL, s_open_mode);
        if(s_session->m_fd == (-1)) {
            s_is_new = 0;
            s_session->m_fd = open(s_path, s_open_flags, s_open_mode);
        }
#else
        s_is_new = (access(s_path, R_OK) == 0) ? 0 : 1;
        s_session->m_fd = open(s_path, s_open_flags, s_open_mode);
#endif
    }
    else {
        s_is_new = 0;
        s_session->m_fd = open(s_path, s_open_flags);
    }
    if(hwport_ftpd_builtin_expect(s_session->m_fd == (-1), 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not open file !") == (-1), 0)) {
            /* errno = ... */
            s_result = (-1);
        }
        goto l_end_stream_2;
    }
    
    /* restart position */
    if(s_session->m_restart_position > ((off_t)0)) {
        off_t s_seek_offset;
        off_t s_seek_position;

        if(s_session->m_type == def_hwport_ftpd_session_type_A) {
            s_seek_position = hwport_ftpd_ascii_to_binary_offset(s_path, s_session->m_restart_position);
        }
        else {
            s_seek_position = s_session->m_restart_position;
        }
        if(hwport_ftpd_builtin_expect(s_seek_position == ((off_t)(-1)), 0)) {
            s_seek_offset = (off_t)(-1);
        }
        else {
            s_seek_offset = lseek(s_session->m_fd, (off_t)s_seek_position, SEEK_SET);
        }
        if(s_seek_offset == ((off_t)(-1))) {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Can not seek file !") == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            goto l_end_stream_3;
        }

        s_position += (off_t)s_seek_offset;
    }
        
    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 150, ' ', "Opening data connection") == (-1), 0)) {
        /* errno = ... */
        s_result = (-1);
        goto l_end_stream_3;
    }

    for(;;) {
        if(s_session->m_type == def_hwport_ftpd_session_type_A) {
            s_buffer = (unsigned char *)(&(s_session->m_data_buffer[s_session->m_data_buffer_size >> 2]));
            s_want_size = s_session->m_data_buffer_size >> 2;
        }
        else {
            s_buffer = (unsigned char *)(&(s_session->m_data_buffer[0]));
            s_want_size = s_session->m_data_buffer_size;
        }

        if(s_command_type == 0) {
            s_read_bytes = (ssize_t)read(s_session->m_fd, (void *)s_session->m_data_buffer, (size_t)s_want_size);
        }
        else {
            s_read_bytes = hwport_ftpd_recv(s_session->m_data_socket, (void *)s_session->m_data_buffer, s_want_size, s_session->m_recv_timeout);
        }
        if((s_read_bytes == ((ssize_t)(-1))) || (s_read_bytes == ((ssize_t)(-2)))) {
            /* errno = ... */
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Data read error !") == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
        }
        if(s_read_bytes == ((ssize_t)0)) { /* EOF */
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 226, ' ', "Transfer complete") == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
        }

        if(s_session->m_type == def_hwport_ftpd_session_type_A) { /* change to ascii */
            size_t s_offset = (size_t)0u;
            s_buffer_size = (size_t)0u;
            while(s_offset < ((size_t)s_read_bytes)) {
                if(s_session->m_data_buffer[s_offset] == '\n') {
                    s_buffer[s_buffer_size++] = '\r';
                }
                s_buffer[s_buffer_size++] = s_session->m_data_buffer[s_offset++];
            }
        }
        else {
            s_buffer = s_session->m_data_buffer;
            s_buffer_size = (size_t)s_read_bytes;
        }

        if(s_command_type == 0) {
            s_write_bytes = hwport_ftpd_send(s_session->m_data_socket, (const void *)s_buffer, s_buffer_size, s_session->m_send_timeout);
        }
        else {
            s_write_bytes = (ssize_t)write(s_session->m_fd, (const void *)s_buffer, s_buffer_size);
        }
        if(s_write_bytes != ((ssize_t)s_buffer_size)) {
            /* errno = ... */
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 550, ' ', "Data send error !") == (-1), 0)) {
                /* errno = ... */
                s_result = (-1);
            }
            break;
        }

        s_position += (off_t)s_write_bytes;
    }
    
l_end_stream_3:;
    while((close(s_session->m_fd) == (-1)) && (errno == EINTR));
    s_session->m_fd = (-1);

    if(s_is_new != 0) {
        if(s_result != 0) {
            (void)remove(s_path);
        }
        else if(s_session->m_current_account != ((hwport_ftpd_account_t *)0)) { /* set effective user:group */
            int s_check;

            s_check = chown(s_path, s_session->m_current_account->m_uid, s_session->m_current_account->m_gid);
        }
    }

l_end_stream_2:;
    (void)hwport_ftpd_data_close(s_session);

l_end_stream_1:;
    free((void *)s_path_abs);

l_end_stream_0:;
    return(s_result);
}


/* ---- */

static int hwport_ftpd_command(hwport_ftpd_session_t *s_session)
{
    typedef int (* hwport_ftpd_command_handler_t)(hwport_ftpd_session_t *);
    static const struct {
        const char *m_command;
        hwport_ftpd_command_handler_t m_handler;
        unsigned int m_flags; /* bit0=NeedCheckLogin */
    } sg_command_table[] = {
        {"USER", hwport_ftpd_command_user, 0x0000000u}, /* USER <SP> <username> <CRLF> */
        {"PASS", hwport_ftpd_command_pass, 0x0000000u}, /* PASS <SP> <password> <CRLF> */
        {"SYST", hwport_ftpd_command_syst, 0x0000001u}, /* SYST <CRLF> */
        {"TYPE", hwport_ftpd_command_type, 0x0000001u}, /* TYPE <SP> <type-code> <CRLF> */
        {"MODE", hwport_ftpd_command_mode, 0x0000001u}, /* MODE <SP> <mode-code> <CRLF> */
        {"ABOR", hwport_ftpd_command_abor, 0x0000001u}, /* ABOR <CRLF> */
        {"QUIT", hwport_ftpd_command_quit, 0x0000000u}, /* QUIT <CRLF> */
        {"NOOP", hwport_ftpd_command_noop, 0x0000001u}, /* NOOP <CRLF> */
        {"PORT", hwport_ftpd_command_port, 0x0000001u}, /* PORT <SP> <host-port> <CRLF> */
        {"EPRT", hwport_ftpd_command_eprt, 0x0000001u}, /* EPRT <SP> <d> <net-prt> <d> <net-addr> <d> <tcp-port> <d> <CRLF> */
        {"PWD" , hwport_ftpd_command_pwd , 0x0000001u}, /* PWD  <CRLF> */
        {"XPWD", hwport_ftpd_command_pwd , 0x0000001u}, /* XPWD <CRLF> */
        {"CWD" , hwport_ftpd_command_cwd , 0x0000001u}, /* CWD  <SP> <pathname> <CRLF> */
        {"XCWD", hwport_ftpd_command_cwd , 0x0000001u}, /* XCWD <SP> <pathname> <CRLF> */
        {"CDUP", hwport_ftpd_command_cdup, 0x0000001u}, /* CDUP <CRLF> */
        {"XCUP", hwport_ftpd_command_cdup, 0x0000001u}, /* XCUP <CRLF> */
        {"RMD" , hwport_ftpd_command_rmd , 0x0000001u}, /* RMD  <SP> <pathname> <CRLF> */
        {"XRMD", hwport_ftpd_command_rmd , 0x0000001u}, /* XRMD <SP> <pathname> <CRLF> */
        {"MKD" , hwport_ftpd_command_mkd , 0x0000001u}, /* MKD  <SP> <pathname> <CRLF> */
        {"XMKD", hwport_ftpd_command_mkd , 0x0000001u}, /* XMKD <SP> <pathname> <CRLF> */
        {"DELE", hwport_ftpd_command_dele, 0x0000001u}, /* DELE <SP> <pathname> <CRLF> */
        {"PASV", hwport_ftpd_command_pasv, 0x0000001u}, /* PASV <CRLF> */
        {"EPSV", hwport_ftpd_command_epsv, 0x0000001u}, /* EPSV <SP> <net-prt> <CRLF> OR EPSV <SP> ALL <CRLF> */ 
        {"LPSV", hwport_ftpd_command_epsv, 0x0000001u}, /* LPSV ??? */
        {"LIST", hwport_ftpd_command_list, 0x0000001u}, /* LIST [<SP> <pathname>] <CRLF> */
        {"NLST", hwport_ftpd_command_nlst, 0x0000001u}, /* NLST [<SP> <pathname>] <CRLF> */
        {"ACCT", hwport_ftpd_command_acct, 0x0000001u}, /* ACCT <SP> <account-information> <CRLF> */
        {"SIZE", hwport_ftpd_command_size, 0x0000001u}, /* SIZE <SP> <pathname> <CRLF> */
        {"STRU", hwport_ftpd_command_stru, 0x0000001u}, /* STRU <SP> <structure-code> <CRLF> */
        {"RNFR", hwport_ftpd_command_rnfr, 0x0000001u}, /* RNFR <SP> <pathname> <CRLF> */
        {"RNTO", hwport_ftpd_command_rnto, 0x0000001u}, /* RNTO <SP> <pathname> <CRLF> */
        {"RETR", hwport_ftpd_command_retr, 0x0000001u}, /* RETR <SP> <pathname> <CRLF> */
        {"STOR", hwport_ftpd_command_stor, 0x0000001u}, /* STOR <SP> <pathname> <CRLF> */
        {"APPE", hwport_ftpd_command_appe, 0x0000001u}, /* APPE <SP> <pathname> <CRLF> */
        {"REST", hwport_ftpd_command_rest, 0x0000001u}, /* REST <SP> <marker> <CRLF> */
        {"MDTM", hwport_ftpd_command_mdtm, 0x0000001u}, /* MDTM <SP> <pathname> <CRLF> */
        {"OPTS", hwport_ftpd_command_opts, 0x0000001u}, /* OPTS <SP> <option> <value> <CRLF> */
        {"SITE", hwport_ftpd_command_site, 0x0000001u}, /* SITE <SP> <string> <CRLF> */
        {"HELP", hwport_ftpd_command_help, 0x0000001u}, /* HELP [<SP> <string>] <CRLF> */
#if 0L /* TODO */
        {"SMNT", hwport_ftpd_command_smnt, 0x0000001u}, /* SMNT <SP> <pathname> <CRLF> */
        {"REIN", hwport_ftpd_command_rein, 0x0000001u}, /* REIN <CRLF> */
        {"STOU", hwport_ftpd_command_stou, 0x0000001u}, /* STOU <CRLF> */
        {"STAT", hwport_ftpd_command_stat, 0x0000001u}, /* STAT [<SP> <pathname>] <CRLF> */
        {"ALLO", hwport_ftpd_command_stat, 0x0000001u}, /* ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>] <CRLF> */
#endif
        {(const char *)0, (hwport_ftpd_command_handler_t)0, 0x0000000u} 
    };
    int s_command_index = 0;
       
    /* clear immediately status (USER, REST, RNFR) */ 
    if((s_session->m_flags & def_hwport_ftpd_session_flag_user) != def_hwport_ftpd_session_flag_none) {
        s_session->m_flags &= ~(def_hwport_ftpd_session_flag_user);
    }
    else {
        if(s_session->m_username != ((char *)0)) {
            free((void *)s_session->m_username);
            s_session->m_username = (char *)0;
        }
    }

    if((s_session->m_flags & def_hwport_ftpd_session_flag_restart_position) != def_hwport_ftpd_session_flag_none) {
        s_session->m_flags &= ~(def_hwport_ftpd_session_flag_restart_position);
    }
    else {
        s_session->m_restart_position = (off_t)0;
    }
    
    if((s_session->m_flags & def_hwport_ftpd_session_flag_rename_from) != def_hwport_ftpd_session_flag_none) {
        s_session->m_flags &= ~(def_hwport_ftpd_session_flag_rename_from);
    }
    else {
        if(s_session->m_path_rename_from != ((char *)0)) {
            free((void *)s_session->m_path_rename_from);
            s_session->m_path_rename_from = (char *)0;
        }
    }

    while(sg_command_table[s_command_index].m_command != ((const char *)0)) {
        if(hwport_ftpd_strcmp(s_session->m_command, sg_command_table[s_command_index].m_command) == 0) {
            break;
        }
        ++s_command_index;
    }
    if(hwport_ftpd_builtin_expect(sg_command_table[s_command_index].m_command == ((const char *)0), 0)) {
        if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 500, ' ', s_session->m_command, " not understood") == (-1), 0)) {
            return(-1);
        }
        return(0);
    }

    if((sg_command_table[s_command_index].m_flags & 0x00000001u) != 0x00000000u) { /* need check login */
        if((s_session->m_current_account == ((hwport_ftpd_account_t *)0)) && (s_session->m_account_head != ((hwport_ftpd_account_t *)0))) {
            if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s\r\n", 530, ' ', "Please login with USER and PASS !") == (-1), 0)) {
                return(-1);
            }
            return(0);
        }
    }

    if(sg_command_table[s_command_index].m_handler != ((hwport_ftpd_command_handler_t)0)) {
        return(sg_command_table[s_command_index].m_handler(s_session));
    }

    if(hwport_ftpd_builtin_expect(hwport_ftpd_send_message(s_session->m_command_socket, s_session->m_send_timeout, "%03u%c%s%s\r\n", 500, ' ', s_session->m_command, " not understood") == (-1), 0)) {
        return(-1);
    }

    return(0);
}

/* ---- */

#endif

/* vim: set expandtab: */
/* End of source */

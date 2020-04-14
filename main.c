/*
    Copyright (C) HWPORT.COM.
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#include "hwport_ftpd.h"

static void hwport_ftpd_break_signal(int s_signal);
static void hwport_ftpd_dummy_signal(int s_signal);
static void hwport_ftpd_install_signal(void);

static int hwport_ftpd_load_system_account(hwport_ftpd_t s_handle);
static int hwport_ftpd_load_default_account(hwport_ftpd_t s_handle);

int main(int s_argc, char **s_argv);

static int g_ftpd_break = 0;

static void hwport_ftpd_break_signal(int s_signal)
{
    g_ftpd_break = 1;

    /* reinstall signal */
    (void)signal(s_signal, hwport_ftpd_break_signal);
}

static void hwport_ftpd_dummy_signal(int s_signal)
{
    /* reinstall signal */
    (void)signal(s_signal, hwport_ftpd_dummy_signal);
}

static void hwport_ftpd_install_signal(void)
{
#if defined(def_hwport_ftpd_windows)
    (void)signal(SIGINT, hwport_ftpd_break_signal);
    (void)signal(SIGTERM, hwport_ftpd_break_signal);
#else
    (void)signal(SIGPIPE, hwport_ftpd_dummy_signal);
    (void)signal(SIGINT, hwport_ftpd_break_signal);
    (void)signal(SIGQUIT, hwport_ftpd_break_signal);
    (void)signal(SIGTERM, hwport_ftpd_break_signal);
    (void)signal(SIGHUP, hwport_ftpd_break_signal);
#endif    
}

static int hwport_ftpd_load_system_account(hwport_ftpd_t s_handle)
{
#if 1L /* all system user */
    (void)hwport_ftpd_add_user(s_handle, (hwport_ftpd_account_t **)0, def_hwport_ftpd_account_flag_none | def_hwport_ftpd_account_flag_system_user, (const char *)0, (const char *)0, (const char *)0);
#elif 0L /* specific system user only */
    (void)hwport_ftpd_add_user(s_handle, (hwport_ftpd_account_t **)0, def_hwport_ftpd_account_flag_none | def_hwport_ftpd_account_flag_system_user, "root", (const char *)0, (const char *)0);
#else
    (void)s_handle;
#endif
        return(0);
}

static int hwport_ftpd_load_default_account(hwport_ftpd_t s_handle)
{
#if 1L /* OPTION: allow for guest user account */
    (void)hwport_ftpd_add_user(s_handle, (hwport_ftpd_account_t **)0, def_hwport_ftpd_account_flag_none | def_hwport_ftpd_account_flag_guest_user, "test", (const char *)0, (const char *)0 /* "/home/ftp" */);
    (void)hwport_ftpd_add_user(s_handle, (hwport_ftpd_account_t **)0, def_hwport_ftpd_account_flag_none | def_hwport_ftpd_account_flag_guest_user, "ftp", (const char *)0, (const char *)0 /* "/home/ftp" */);
    (void)hwport_ftpd_add_user(s_handle, (hwport_ftpd_account_t **)0, def_hwport_ftpd_account_flag_none | def_hwport_ftpd_account_flag_guest_user, "anonymous", (const char *)0, (const char *)0 /* "/home/ftp" */);
#else    
    (void)s_handle;
#endif

    return(0);
}

int main(int s_argc, char **s_argv)
{
    hwport_ftpd_t s_handle;

    (void)s_argc;
    (void)s_argv;

    hwport_ftpd_install_signal();

    s_handle = hwport_ftpd_open();
    if(hwport_ftpd_builtin_expect(s_handle == ((hwport_ftpd_t)0), 0)) {
        /* can not open ftpd */
        return(EXIT_FAILURE);
    }

    (void)hwport_ftpd_load_system_account(s_handle);
    (void)hwport_ftpd_load_default_account(s_handle);

    while(g_ftpd_break == 0) {
        (void)hwport_ftpd_do(s_handle, 1000 /* (-1)=suspend */);
    }

    s_handle = hwport_ftpd_close(s_handle);

    return(EXIT_SUCCESS);
}

/* vim: set expandtab: */
/* End of source */

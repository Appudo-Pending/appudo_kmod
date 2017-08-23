#include "debug_trace.h"

int debug_trace_user(pid_t pid)
{
    char tmp[64];
    char *argv[] = { "/usr/bin/kernel_trace_helper", "-p", tmp, "/tmp/kern/kernel_trace.txt", NULL };
    static char *envp[] = {
        "HOME=/tmp/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL
    };
    sprintf(tmp, "%i", pid);
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

int dump_stack_user(pid_t pid)
{
    return debug_trace_user(pid);
}

int dump_stack_user_current(void)
{
    return debug_trace_user(task_pid_nr(current));
}

ssize_t send_signal(int sig, struct task_struct *task, void* data)
{
    int ret;
    struct siginfo info;

    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    info.si_ptr = data;

    ret = send_sig_info(sig, &info, task);
    if (ret < 0) {
        printk("send_signal error\n");
        return ret;
    }
    return 0;
}

ssize_t send_signal_current(int sig, void* data)
{
    return send_signal(sig, current, data);
}


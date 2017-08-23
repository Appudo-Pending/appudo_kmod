
int dump_stack_user(pid_t pid);
int dump_stack_user_current(void);

ssize_t send_signal(int sig, struct task_struct *task, void* data);
ssize_t send_signal_current(int sig, void* data);

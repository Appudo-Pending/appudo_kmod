/*
 *  fs/eventfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 * Portions Copyright (C) 2015
 *      bf1368eaf5a22ea65fcfd4f7e0efccd233a810deaaebfb8b374a76c2e472d618 source@appudo.com
 */

/*
 * This is a special eventfd implementation that works as an event stack for multiple processes.
 * It depends on the fact that the wait queue for an eventfd is an ordered queue.
 * Ordered by the time when a waiter was added to the queue.
 *
 * The private field of a wait queue item has some additional data to wake up only the last added
 * item and move it to the end of the list.
 * As with a normal eventfd the count of the eventfd_ctx struct is used to signal an EPOLLIN or EPOLLERR.
 * As long as the count is > 0 and < max a poll can succeed.
 *
 * But instead of the original eventfd a poll will only succeed for the process that placed the waiter
 * and for the waiter that is at the end of the queue.
 *
 * Additional waiter data in the private field:
 * 1. The pid of the process that placed the waiter.
 * 2. The wait state (1 = inactive, 2 = wait for write, 3 = ready to poll).
 *
 * Special handling of the waiter data:
 * 1. When an eventfd is added to an epoll queue it is first polled from the proceess where this is done.
 *    At this time the private data field of the waiter is NULL.
 *    This is the time to set the pid and the state to "inactive" or "wait for write".
 * 2. A write to the eventfd will add data to the count, set the state of the top item to "ready to poll"
 *    and move it to the end of the queue. A wakeup is done for this single waiter.
 * 3. The next poll will check the last item of the wait queue for a count > 0 or count == max and
 *    the "read to poll" state. Only if all of this is true, the poll will return EPOLLIN or EPOLLER.
 * => A write ativates the top waiter and prepares the next waiter. If there is an active waiter, a poll
 *    will succeed.
 *
 * A read can invalidate a poll.
 * A write of zero will rewake the current waiter but not move it. (TODO)
 *
 * Special usage of the pid in the waiter:
 * The pid of the active item is used to safely send data to this process from
 * another process.
 * At the moment safe means that the process exists and it is in fact the process
 * that was meant.
 * Of course it would be nice to have restrictions where to place the data.
 * This could later be done with additional data in the waiter.
 *
 */
#ifndef NDEBUG
static void eventpoll_print(struct eventfd_ctx *ctx)
{
    wait_queue_t* wq = NULL;

    printk(KERN_ERR "###LIST_START###\n");
    list_for_each_entry(wq, &ctx->wqh.task_list, task_list) {
        printk(KERN_ERR "###ITEM: %p###\n", wq->private);
    }
    printk(KERN_ERR "###LIST_END###\n");
}
#endif

static struct file_operations* orig_eventfd_fops = 0;
static struct file_operations eventfd_fops = { };
static struct file_operations eventfd_fops_dbg = { };
static struct file_operations eventfd_fops_ioctl = { };

struct eventfd_ctx {
    struct kref kref;
    wait_queue_head_t wqh;
    /*
     * Every time that a write(2) is performed on an eventfd, the
     * value of the __u64 being written is added to "count" and a
     * wakeup is performed on "wqh". A read(2) will return the "count"
     * value to userspace, and will reset "count" to zero. The kernel
     * side eventfd_signal() also, adds to the "count" counter and
     * issue a wakeup.
    */
    __u64 count;
    unsigned int flags;
};

static void eventfd_ex_shutdown(struct eventfd_ctx *ctx)
{
    spin_lock_irq(&ctx->wqh.lock);
    ctx->count = ULLONG_MAX;
    if (waitqueue_active(&ctx->wqh))
        wake_up_locked_poll(&ctx->wqh, POLLERR);
    spin_unlock_irq(&ctx->wqh.lock);
}

static int eventfd_ex_flush(struct file * efile, fl_owner_t id)
{
    if(current->flags & PF_EXITING)
    {
        eventfd_ex_shutdown(efile->private_data);
    }
    return 0;
}

struct task_struct* eventfd_ex_task(wait_queue_t* wq)
{
    return (struct task_struct*)((unsigned long)wq->private & ~3L);
}

unsigned long eventfd_ex_flags(wait_queue_t* wq)
{
    return (unsigned long)wq->private & 3L;
}

void eventfd_ex_set_data(wait_queue_t* wq, unsigned long flags)
{
    wq->private = (void*)((unsigned long)current | flags);
}

void eventfd_ex_set_flags(wait_queue_t* wq, unsigned long flags)
{
    wq->private = (void*)((unsigned long)eventfd_ex_task(wq) | flags);
}

static wait_queue_t* eventfd_ex_active(struct eventfd_ctx *ctx)
{
    wait_queue_t* wq = NULL;

    list_for_each_entry(wq, &ctx->wqh.task_list, task_list) {
        if((eventfd_ex_flags(wq) & 3L) > 1L)
        {
            return wq;
        }
    }
    return NULL;
}

static wait_queue_t* eventfd_ex_active_task(struct eventfd_ctx *ctx, pid_t pid)
{
    wait_queue_t* wq = NULL;

    list_for_each_entry(wq, &ctx->wqh.task_list, task_list) {
        if((eventfd_ex_flags(wq) & 3L) > 1L)
        {
            struct task_struct* t = eventfd_ex_task(wq);
            if(t->pid == pid)
            {
                return wq;
            }
        }
    }
    return NULL;
}

static unsigned int eventfd_ex_poll(struct file *file, poll_table *wait)
{
    struct eventfd_ctx *ctx = file->private_data;
    unsigned int events = 0;
    wait_queue_t* wq = NULL;
    u64 count;
    int flags = 0;
    poll_wait(file, &ctx->wqh, wait);

    spin_lock_irq(&ctx->wqh.lock);
    if (waitqueue_active(&ctx->wqh))
    {
        wq = list_last_entry(&ctx->wqh.task_list, wait_queue_t, task_list);
        flags = eventfd_ex_task(wq) == current ? eventfd_ex_flags(wq) : 0;
        wq = list_first_entry(&ctx->wqh.task_list, wait_queue_t, task_list);
        if(wq->private == NULL)
        {
            eventfd_ex_set_data(wq, (wait->_key & POLLIN) ? 2L : 1L);
        }
    }
    spin_unlock_irq(&ctx->wqh.lock);
    smp_rmb();
    count = ctx->count;

    if (count == ULLONG_MAX)
    {
        events |= POLLERR;
    }
    else
    if((flags & 3L) == 3L)
    {
        if (count)
            events |= POLLIN;
    }

    return events;
}

static void eventfd_ex_invalidate(struct eventfd_ctx *ctx)
{
    wait_queue_t* last = list_last_entry(&ctx->wqh.task_list, wait_queue_t, task_list);
    if((eventfd_ex_flags(last) & 3L) == 3L)
        eventfd_ex_set_flags(last, 2L);
}

static ssize_t eventfd_ex_write(struct file *file, const char __user *buf, size_t count,
                 loff_t *ppos)
{
    struct eventfd_ctx *ctx = file->private_data;
    wait_queue_t* wq;

    spin_lock_irq(&ctx->wqh.lock);
    if(waitqueue_active(&ctx->wqh))
    {
        wq = eventfd_ex_active(ctx);
        if(wq != NULL)
        {
            if(count == 0)
            {
                // TODO just rewake active
            }
            else
            {
                eventfd_ex_invalidate(ctx);
                ctx->count = 1;
                //send_sig(SIGHUP, current, 0);
                eventfd_ex_set_flags(wq, 3L);
                wq->flags |= WQ_FLAG_EXCLUSIVE;
                wake_up_locked_poll(&ctx->wqh, POLLIN);
                wq->flags &= ~WQ_FLAG_EXCLUSIVE;
                list_move_tail(&wq->task_list, &ctx->wqh.task_list);
            }
        }
    }
    spin_unlock_irq(&ctx->wqh.lock);

    return count;
}

static long
eventfd_ex_ioctl (struct file *efile, unsigned int ioctl, unsigned long arg)
{
    int res = 0;
    int fd = -1;
    struct eventfd_ctx *ctx;
    void __user *argp = (void __user *) arg;
    wait_queue_t* wq = NULL;
    struct file *file;
    struct file *sfile;
    struct fdtable *fdt;
    struct files_struct *files;
    struct task_struct* task;

    switch(ioctl)
    {
    case EVENTPOLL_SHUTDOWN: {
        eventfd_ex_shutdown(efile->private_data);
        break;
    }
    case EVENTPOLL_POP_NUM: {
        int i = 0;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        for(;i < arg; i++)
        {
            if(!waitqueue_active(&ctx->wqh))
            {
                res = -EFAULT;
                goto END;
            }
            wq = eventfd_ex_active(ctx);
            if(wq != NULL && ctx->count != ULLONG_MAX)
            {
                eventfd_ex_invalidate(ctx);
                eventfd_ex_set_flags(wq, 3L);
                ctx->count |= 1;
                list_move(&wq->task_list, &ctx->wqh.task_list);
                wq->flags |= WQ_FLAG_EXCLUSIVE;
                wake_up_locked_poll(&ctx->wqh, POLLIN);
                wq->flags &= ~WQ_FLAG_EXCLUSIVE;
                list_move_tail(&wq->task_list, &ctx->wqh.task_list);
            }
            else
            {
                res = -EFAULT;
                goto END;
            }
        }

        END:
        spin_unlock_irq(&ctx->wqh.lock);
        break;
    }
    case EVENTPOLL_DBG_WAITER: {
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh))
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }
        wq = list_last_entry(&ctx->wqh.task_list, wait_queue_t, task_list);
        task = eventfd_ex_task(wq);
        if(task)
        {
            if(copy_to_user(argp, &task->pid, sizeof (pid_t)))
                res = -EFAULT;
        }
        else
        {
            res = -EFAULT;
        }
        spin_unlock_irq(&ctx->wqh.lock);
        break;
    }
    case EVENTPOLL_REARM: {
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh))
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }
        wq = list_last_entry(&ctx->wqh.task_list, wait_queue_t, task_list);
        task = eventfd_ex_task(wq);
        if(task && task->pid == arg && ctx->count != ULLONG_MAX)
        {
            eventfd_ex_invalidate(ctx);
            list_move(&wq->task_list, &ctx->wqh.task_list);
        }
        else
        {
            res = -EFAULT;
        }
        spin_unlock_irq(&ctx->wqh.lock);
        break;
    }
    case EVENTPOLL_POP_PID: {
        int i = 0;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh))
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }
        wq = eventfd_ex_active_task(ctx, arg);
        if(wq != NULL && ctx->count != ULLONG_MAX)
        {
            for(;i < arg; i++)
            {
                eventfd_ex_invalidate(ctx);
                eventfd_ex_set_flags(wq, 3L);
                ctx->count |= 1;
                list_move(&wq->task_list, &ctx->wqh.task_list);
                wq->flags |= WQ_FLAG_EXCLUSIVE;
                wake_up_locked_poll(&ctx->wqh, POLLIN);
                wq->flags &= ~WQ_FLAG_EXCLUSIVE;
                list_move_tail(&wq->task_list, &ctx->wqh.task_list);
            }
        }
        else
        {
            res = -EFAULT;
        }
        spin_unlock_irq(&ctx->wqh.lock);
        break;
    }
    case EVENTPOLL_COPYFD_FROM: {
        struct eventpoll_data data;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh) || (wq = eventfd_ex_active(ctx)) == NULL)
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }

        task = eventfd_ex_task(wq);
        if(task)
            get_task_struct(task);
        spin_unlock_irq(&ctx->wqh.lock);
        if(task == NULL)
            return -EFAULT;

        if(copy_from_user(&data, argp, sizeof (struct eventpoll_data)) ||
           task->pid != data.target_pid)
        {
            res = -EFAULT;
            goto put_task;
        }

        files = get_files_struct(task);
        if(files == NULL)
        {
            res = -EFAULT;
            goto put_task;
        }

        rcu_read_lock();
        file = fcheck_files(files, data.target_fd);
        if(file)
        {
            if((file->f_mode & FMODE_PATH)
                    || !atomic_long_inc_not_zero (&file->f_count))
                file = NULL;
        }
        rcu_read_unlock();

        if(file == NULL)
        {
            put_files_struct(files);
            res = -EFAULT;
            goto put_task;
        }

        fd = data.target_fd;

        res = get_unused_fd_flags(0);
        if(res >= 0)
            fd_install(res, file);
        else
            fput(file);

        put_files_struct(files);

        break;
    }
    /*
     * TODO possibly make this more secure by makeing the file to override in the
     * target an input for the source process.
     * So a process can only override a file it has a reference for.
     */
    case EVENTPOLL_COPYFD_TO: {
        struct eventpoll_data data;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh) || (wq = eventfd_ex_active(ctx)) == NULL)
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }

        task = eventfd_ex_task(wq);
        if(task)
            get_task_struct(task);
        spin_unlock_irq(&ctx->wqh.lock);
        if(task == NULL)
            return -EFAULT;

        if(copy_from_user(&data, argp, sizeof (struct eventpoll_data)) ||
           task->pid != data.target_pid)
        {
            res = -EFAULT;
            goto put_task;
        }

        rcu_read_lock();
        sfile = fcheck(data.source_fd);
        if(!sfile || (sfile->f_mode & FMODE_PATH) || !atomic_long_inc_not_zero(&sfile->f_count))
            sfile = NULL;
        rcu_read_unlock();

        if(sfile == NULL)
        {
            res = 0;
            goto put_task;
        }

        files = get_files_struct(task);
        if(files == NULL)
        {
            res = -EFAULT;
            goto put_task;
        }

        rcu_read_lock();
        file = fcheck_files(files, data.target_fd);
        if(file)
        {
            if((file->f_mode & FMODE_PATH)
                    || !atomic_long_inc_not_zero (&file->f_count))
                file = NULL;
        }
        rcu_read_unlock();

        if(file == NULL)
        {
            fput(sfile);
            put_files_struct(files);
            res = 0;
            goto put_task;
        }

        fd = data.target_fd;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        rcu_assign_pointer(fdt->fd[fd], sfile);
        spin_unlock(&files->file_lock);

        filp_close(file, files);
        fput(file);

        put_files_struct(files);

        res = fd;

        put_task:
            put_task_struct(task);
        break;
    }
    case EVENTPOLL_CLOSEFDS: {
        struct eventpoll_data data;
        struct files_struct *files;
        struct file *file;
        struct fdtable *fdt;
        int fd;
        int lowfd;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh) || (wq = eventfd_ex_active(ctx)) == NULL)
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }

        task = eventfd_ex_task(wq);
        if(task)
            get_task_struct(task);
        spin_unlock_irq(&ctx->wqh.lock);
        if(task == NULL)
            return -EFAULT;

        if(copy_from_user(&data, argp, sizeof (struct eventpoll_data)) ||
           task->pid != data.target_pid)
        {
            res = -EFAULT;
            goto put_task;
        }

        files = task->files;
        lowfd = data.target_fd;

        if(lowfd < 0)
            lowfd = 0;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        if(lowfd >= fdt->max_fds)
            goto out_unlock;
        for(fd = lowfd; fd < fdt->max_fds; fd++)
        {
            file = fdt->fd[fd];
            if(!file)
                continue;

            rcu_assign_pointer(fdt->fd[fd], NULL);
            __clear_bit(fd, fdt->close_on_exec);
            spin_unlock(&files->file_lock);
            put_unused_fd(fd);
            filp_close(file, files);
            cond_resched();
            spin_lock(&files->file_lock);
        }

        out_unlock:
            spin_unlock(&files->file_lock);

        break;
    }
    case EVENTPOLL_COPY_TO: {
        struct page *process_pages[2];
        struct eventpoll_copy_data copy_data;
        struct mm_struct *mm;
        struct iovec lvec;
        struct iovec rvec;
        struct iov_iter iter;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh) || (wq = eventfd_ex_active(ctx)) == NULL)
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }

        task = eventfd_ex_task(wq);
        if(task)
            get_task_struct(task);
        spin_unlock_irq(&ctx->wqh.lock);
        if(task == NULL)
            return -EFAULT;

        if (copy_from_user(&copy_data, argp, sizeof (struct eventpoll_copy_data)) ||
            task->pid != copy_data.target_pid)
        {
            res = -EFAULT;
            goto put_task;
        }

        switch(copy_data.size)
        {
        case 0:
        case -1:
            rvec.iov_base = &copy_data.source_buffer;
            copy_data.size = copy_data.size == 0 ? sizeof(int) : sizeof(void*);
            break;
        default:
            rvec.iov_base = copy_data.source_buffer;
            break;
        }

        lvec.iov_base = copy_data.target_buffer;
        lvec.iov_len = copy_data.size;
        rvec.iov_len = copy_data.size;
        iov_iter_init(&iter, WRITE, &rvec, 1, copy_data.size);

        mm = get_task_mm(task);
        if(mm == NULL)
        {
            res = -EACCES;
            goto put_task;
        }

        if(process_vm_rw_single_vec(
                (unsigned long)lvec.iov_base, lvec.iov_len,
                &iter, process_pages, mm, task, WRITE))
            res = -EACCES;
        else
            res = copy_data.size;

        mmput(mm);

        goto put_task;
    }
    case EVENTPOLL_COPY_FROM: {
        struct page *process_pages[2];
        struct eventpoll_copy_data copy_data;
        struct mm_struct *mm;
        struct iovec lvec;
        struct iovec rvec;
        struct iov_iter iter;
        ctx = efile->private_data;
        spin_lock_irq(&ctx->wqh.lock);
        if (!waitqueue_active(&ctx->wqh) || (wq = eventfd_ex_active(ctx)) == NULL)
        {
            spin_unlock_irq(&ctx->wqh.lock);
            return -EFAULT;
        }

        task = eventfd_ex_task(wq);
        if(task)
            get_task_struct(task);
        spin_unlock_irq(&ctx->wqh.lock);
        if(task == NULL)
            return -EFAULT;

        if (copy_from_user(&copy_data, argp, sizeof (struct eventpoll_copy_data)) ||
            copy_data.size == 0 ||
            task->pid != copy_data.target_pid)
        {
            res = -EFAULT;
            goto put_task;
        }

        rvec.iov_base = copy_data.source_buffer;
        lvec.iov_base = copy_data.target_buffer;
        lvec.iov_len = copy_data.size;
        rvec.iov_len = copy_data.size;
        iov_iter_init(&iter, READ, &rvec, 1, copy_data.size);

        mm = get_task_mm(task);
        if(mm == NULL)
        {
            res = -EACCES;
            goto put_task;
        }

        if(process_vm_rw_single_vec(
                (unsigned long)lvec.iov_base, lvec.iov_len,
                &iter, process_pages, mm, task, READ))
            res = -EACCES;
        else
            res = copy_data.size;

        mmput(mm);

        goto put_task;
    }
    default:
        res = -1;
        break;
    }

    return res;
}

static void eventfd_ex_init(int fd)
{
    struct file* efile;
    efile = fget(fd);
    *(&eventfd_fops) = *efile->f_op;
    *(&eventfd_fops_ioctl) = *efile->f_op;
    orig_eventfd_fops = (struct file_operations*)efile->f_op;
    eventfd_fops.poll = eventfd_ex_poll;
    eventfd_fops_ioctl.poll = eventfd_ex_poll;
    eventfd_fops.write = eventfd_ex_write;
    eventfd_fops.flush = eventfd_ex_flush;
    eventfd_fops.unlocked_ioctl = eventfd_ex_ioctl;
    eventfd_fops_ioctl.unlocked_ioctl = eventfd_ex_ioctl;
    *(&eventfd_fops_dbg) = *(&eventfd_fops);
    fput(efile);
}

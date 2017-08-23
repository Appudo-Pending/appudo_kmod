/*
    Copyright (C) 2016
        0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com

    Copyright (C) 2015
        a742baed6b4bbfbc5c50dfea489f8dc0976855df1a27fb4662ce2cc5123dcc1a source@appudo.com
        bf1368eaf5a22ea65fcfd4f7e0efccd233a810deaaebfb8b374a76c2e472d618 source@appudo.com

    eventpoll.c is part of Appudo

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, 51 Franklin Street - Fifth Floor, Boston,
    MA 02110-1301, USA.
*/

#include <linux/eventfd.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rcupdate.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/stat.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/socket.h>
#include <linux/security.h>
#include <linux/net.h>
#include <linux/audit.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/mmu_context.h>
#include <linux/fdtable.h>
#include <linux/kallsyms.h>
#include "./eventpoll.h"
#include "./locks.h"
#include "./group_cache.h"
#include <linux/syscalls.h>

#ifndef NDEBUG
#define SIG_TEST 44

static ssize_t write_signal(struct task_struct *task, void* data)
{
    return send_signal(SIG_TEST, task, data);
}
#endif

#include "debug_trace.c"
#include "mm/process_vm_access.c"
#include "fs/eventfd.c"
#include "fs/file.c"
#include "sock.c"
#include "group_cache.c"

struct group_data* group_get_data(struct file *file)
{
    return (struct group_data*)((unsigned long)file->private_data & ~3L);
}

int group_get_clone(struct file *file)
{
    return (unsigned long)file->private_data & 2L;
}

int group_get_master(struct file *file)
{
    return (unsigned long)file->private_data & 1L;
}

void group_set_flags(struct file *file, unsigned flags)
{
    file->private_data = (struct group_data*)(((unsigned long)file->private_data & ~1L) | (flags & 3L));
}

int eventpoll_ex_open(struct inode* inode, struct file* file)
{
    file->private_data = NULL;
    if(!try_module_get(THIS_MODULE))
    {
        printk(KERN_INFO "eventfd try_module_get failed\n");
        return -ENODEV;
    }

    return 0;
}

int eventpoll_ex_release(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);
    if(file->private_data && group_get_clone(file) == 0)
    {
        group_cache_destroy(group_get_data(file));
        file->private_data = NULL;
    }
    return 0;
}


static long
eventpoll_ex_ioctl_init (struct file *f, unsigned int ioctl, unsigned long arg);

static struct file_operations eventpoll_ex_fops = {
    .owner 			= THIS_MODULE,
    .open 			= eventpoll_ex_open,
    .release 		= eventpoll_ex_release,
    .unlocked_ioctl = eventpoll_ex_ioctl_init,
};


static struct proto_ops* orig_socket_pops = 0;
static struct proto_ops socket_pops = { };

static struct proto_ops socket_hook_pops = { };

#define KCMSG_FIRSTHDR(msg)      __CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
int sock_sendmsg_hook(struct socket *sock, struct msghdr *m, size_t total_len)
{
    /*
    char tmp[512];
    size_t len;
    //struct cmsghdr* cmsg = NULL;
    //char* data;
    //int i = 0;

    if(total_len)
    {
        struct iov_iter it = m->msg_iter;
        len = copy_from_iter(tmp, sizeof(tmp), &it);
        tmp[len] = 0;
        printk(KERN_ERR "%li %p\n", total_len, sock);
    }
    */
    /*
    cmsg = KCMSG_FIRSTHDR(m);
    printk(KERN_ERR "msg %p, %li, %li\n", cmsg, m->msg_controllen, total_len);
    if(cmsg)
    {
        data = CMSG_DATA(cmsg);
        len = cmsg->cmsg_len - CMSG_LEN(0);
        if(len > sizeof(tmp)-1)
            len = sizeof(tmp)-1;
        for(; i < len; i++)
            tmp[i] = data[i];
        tmp[len] = 0;
        printk(KERN_ERR "%s\n", tmp);
    }
    */
    return orig_unix_stream_sendmsg(sock, m, total_len);
}

int sock_release_hook(struct socket *sock)
{
    return -1;
}

static long
eventpoll_ex_ioctl (struct file *f, unsigned int ioctl, unsigned long arg)
{
    void __user *argp = (void __user *) arg;
    int res = 0;
    int found = 0;

    switch(ioctl)
    {
    case EVENTPOLL_DBG_CLOSE: {
        struct eventpoll_egroup_info info = {.data=arg};
        struct file * file;

        rcu_read_lock();
        file = fcheck(info.min);
        found = file && atomic_long_inc_not_zero(&file->f_count);
        rcu_read_unlock();

        if(found)
        {
            res = sys_close(info.min);
            if(file->f_op == &eventfd_fops_dbg)
            {
                dump_stack_user(info.max);
            }
            fput(file);
        }
        break;
    }
    case EVENTPOLL_DBG_CLOSE_NO_EV: {
        struct eventpoll_egroup_info info = {.data=arg};
        struct file * file;

        rcu_read_lock();
        file = fcheck(info.min);
        found = file && atomic_long_inc_not_zero(&file->f_count);
        rcu_read_unlock();

        if(found)
        {
            res = sys_close(info.min);
            if(file->f_op == &eventfd_fops_dbg)
            {
                send_signal_current(SIGSTOP, NULL);
            }
            fput(file);
        }
        break;
    }
    case EVENTPOLL_INIT : {
        struct file *source_file = NULL;
        struct eventpoll_init data;
        data.data = arg;
        if(f->private_data == NULL)
        {
            if(data.source_fd == -1)        // init
            {
                struct group_data* new_gdata;
                if((res = group_cache_init(&new_gdata, 255)))
                {
                    break;
                }
                f->private_data = new_gdata;
                group_set_flags(f, data.flags & 1L);
            }
            else                            // clone
            {
                rcu_read_lock();
                source_file = fcheck(data.source_fd);
                found = source_file && atomic_long_inc_not_zero(&source_file->f_count);
                rcu_read_unlock();

                if(!found)
                {
                    res = -EFAULT;
                    break;
                }

                f->private_data = source_file->private_data;

                fput(source_file);
                group_set_flags(f, (data.flags & 1L) | 2L);
            }
            break;
        }
        res = -EFAULT;
        break;
    }
    case EVENTPOLL_SET_PRIV_DATA : {
        int fd;
        long data;
        struct file *source_file = NULL;

        if(copy_from_user(&data, argp, sizeof (long)))
        {
            res = -EFAULT;
            break;
        }

        fd = data;

        rcu_read_lock();
        source_file = fcheck(fd);
        found = source_file && atomic_long_inc_not_zero(&source_file->f_count);
        rcu_read_unlock();

        if(!found)
        {
            res = -EFAULT;
            break;
        }

        if(copy_to_user(argp, &source_file->private_data, sizeof (long)))
        {
            res = -EFAULT;
        }

        fput(source_file);

        break;
    }
    case EVENTPOLL_SET_WRITE_HOOK : {
        int fd = arg;
        struct file *source_file = NULL;
        struct socket *source_sock = NULL;

        fd = arg;
        rcu_read_lock();
        source_file = fcheck(fd);
        found = source_file && atomic_long_inc_not_zero(&source_file->f_count);
        rcu_read_unlock();

        if(!found)
        {
            res = -EFAULT;
            break;
        }


        source_sock = (struct socket*)source_file->private_data;
        source_sock->ops = &socket_hook_pops;
        fput(source_file);

        break;
    }
    case EVENTPOLL_LOCK_FILE: {
        struct file *source_file = NULL;
        struct eventpoll_lock data;

        if(copy_from_user(&data, argp, sizeof (struct eventpoll_lock)))
        {
            res = -EFAULT;
            break;
        }
        rcu_read_lock();
        source_file = fcheck(data.fileFd);
        found = source_file && atomic_long_inc_not_zero(&source_file->f_count);
        rcu_read_unlock();

        if(!found)
        {
            res = -EFAULT;
            break;

        }

        res = try_lock_ofd64(source_file, &data.lock, data.user_ptr, data.msgFd);

        fput(source_file);

        break;
    }
        /*
    case EVENTPOLL_CLOSEWAIT: {
        struct files_struct *files = current->files;
        struct file *efile;
        struct fdtable *fdt;
        int fd = arg;
        rcu_read_lock();
        efile = fcheck(fd);
        found = efile && atomic_long_inc_not_zero(&efile->f_count);
        rcu_read_unlock();

        if(!found)
            return -EFAULT;

        while(atomic_long_read(&efile->f_count) > 2);

        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        rcu_assign_pointer(fdt->fd[fd], NULL);
        __clear_bit(fd, fdt->close_on_exec);
        spin_unlock(&files->file_lock);
        put_unused_fd(fd);
        filp_close(efile, files);
        cond_resched();
        fput(efile);
        break;
    }
    */
    case EVENTPOLL_CLOSEFDS: {
        struct files_struct *files = current->files;
        struct file *file;
        struct fdtable *fdt;
        int fd;
        int lowfd = arg;

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
#ifndef NDEBUG
    case EVENTPOLL_CHECK: {
        struct file *efile;
        int found;
        int fd = arg;
        rcu_read_lock();
        efile = fcheck(fd);
        found = efile && atomic_long_inc_not_zero(&efile->f_count);
        rcu_read_unlock();
        if(found)
            send_signal(SIG_TEST, current, NULL);
        else
            fput(efile);
        break;
    }
#endif
    case EVENTPOLL_DISABLE:
    case EVENTPOLL_DBG_ENABLE:
    case EVENTPOLL_ENABLE:
    case EVENTPOLL_ENABLE_NR: {
        struct file *efile;
        struct eventfd_ctx *ctx;
        int fd = arg;
        rcu_read_lock();
        efile = fcheck(fd);
        found = efile && atomic_long_inc_not_zero(&efile->f_count);
        rcu_read_unlock();

        if(!found)
            return -EFAULT;

        ctx = efile->private_data;
        ctx->count = 0;

        if(ioctl == EVENTPOLL_DBG_ENABLE)
            efile->f_op = &eventfd_fops_dbg;
        else
        if(ioctl == EVENTPOLL_ENABLE)
            efile->f_op = &eventfd_fops;
        else
        if(ioctl == EVENTPOLL_ENABLE_NR)
            efile->f_op = &eventfd_fops_ioctl;
        else
            efile->f_op = (const struct file_operations*)orig_eventfd_fops;

        fput(efile);
        break;
    }
    case EVENTPOLL_ADDR: {
        struct file *source_file = NULL;
        struct file *target_file = NULL;
        struct socket *target_sock = NULL;
        struct eventpoll_addr data;
        if(copy_from_user(&data, argp, sizeof (struct eventpoll_addr)))
        {
            res = -EFAULT;
            break;
        }

        rcu_read_lock();
        source_file = fcheck(data.source_fd);
        found = source_file && atomic_long_inc_not_zero(&source_file->f_count);
        rcu_read_unlock();

        if(!found)
        {
            source_file = NULL;
            res = -EFAULT;
            goto put_files;
        }

        rcu_read_lock();
        target_file = fcheck(data.target_fd);
        found = target_file && atomic_long_inc_not_zero(&target_file->f_count);
        rcu_read_unlock();

        if(!found)
        {
            fput(source_file);
            target_file = NULL;
            res = -EFAULT;
            goto put_files;
        }

        target_sock = (struct socket*)target_file->private_data;

        // set target
        sock_hold(target_sock->sk);
        unix_state_lock(target_sock->sk);
        target_sock->sk->sk_destruct = addr_unix_sock_destructor;
        rcu_assign_sk_user_data(target_sock->sk, source_file);
        target_sock->ops = &socket_pops;
        unix_state_unlock(target_sock->sk);
        sock_put(target_sock->sk);

        put_files:

        if(target_file)
            fput(target_file);

        break;
    }
    case EVENTPOLL_ADD_GROUPS: {
        struct eventpoll_group_info data;
        if(copy_from_user(&data, argp, sizeof (struct eventpoll_group_info)))
        {
            res = -EFAULT;
            break;
        }
        res = group_cache_add(group_get_data(f), data.userId, data.grouplist, data.size);
        break;
    }
    case EVENTPOLL_RST_GROUPS: {
        res = group_cache_reset(group_get_data(f));
        break;
    }
    case EVENTPOLL_SET_GROUPS: {
        struct eventpoll_group_info data;
        if(copy_from_user(&data, argp, sizeof (struct eventpoll_group_info)))
        {
            res = -EFAULT;
            break;
        }
        res = group_cache_gset(group_get_data(f), data.userId, data.egid, data.id);
        break;
    }
    case EVENTPOLL_CHK_GROUPS: {
        struct eventpoll_group_info data;
        if(copy_from_user(&data, argp, sizeof (struct eventpoll_group_info)))
        {
            res = -EFAULT;
            break;
        }
        res = group_cache_check(group_get_data(f), data.userId, data.id);
        break;
    }
    case EVENTPOLL_DEL_GROUPS: {
        struct eventpoll_group_info data;
        if(copy_from_user(&data, argp, sizeof (struct eventpoll_group_info)))
        {
            res = -EFAULT;
            break;
        }
        res = group_cache_remove(group_get_data(f), data.userId, data.id);
        break;
    }
    case EVENTPOLL_CLR_GROUPS: {
        res = group_cache_clear(group_get_data(f), 1);
        break;
    }
    case EVENTPOLL_INIT_EGRP: {
        struct eventpoll_egroup_info info = {.data=arg};
        res = group_cache_init_groups(group_get_data(f), info.min, info.max);
        break;
    }
    case EVENTPOLL_SET_EGRP: {
        struct eventpoll_egroup_info info = {.data=arg};
        res = group_cache_set_egroup(group_get_data(f), info.gid);
        break;
    }
    case EVENTPOLL_SET_GRP: {
        struct eventpoll_egroup_info info = {.data=arg};
        res = group_cache_set_group(group_get_data(f), info.gid, group_get_master(f));
        break;
    }
    default:
        res = -EFAULT;
        break;
    }
    return res;
}

static long
eventpoll_ex_ioctl_init (struct file *f, unsigned int ioctl, unsigned long arg)
{
    if(ioctl == EVENTPOLL_DBG_ENABLE ||
       ioctl == EVENTPOLL_ENABLE ||
       ioctl == EVENTPOLL_ENABLE_NR)
    {
        eventfd_ex_init(arg);
        eventpoll_ex_fops.unlocked_ioctl = eventpoll_ex_ioctl;
    }
    return eventpoll_ex_ioctl(f, ioctl, arg);
}

static struct miscdevice eventpoll_ex_misc = {
    .minor = EVENTPOLL_EX_MINOR,
    .name  = "eventpoll-ex",
    .fops  = &eventpoll_ex_fops,
    .mode  = S_IRWXO,
};

static int __init
eventpoll_ex_init (void)
{
    struct socket *sock;
    group_cache_static_init();
    if(sock_create(AF_UNIX, SOCK_STREAM, 0, &sock))
        return -1;
    orig_socket_pops = (struct proto_ops*)sock->ops;
    socket_pops = *sock->ops;
    socket_hook_pops = *sock->ops;
    orig_unix_stream_sendmsg = socket_hook_pops.sendmsg;
    socket_hook_pops.sendmsg = sock_sendmsg_hook;
    orig_unix_sock_destructor = sock->sk->sk_destruct;
    sock_release(sock);
    /*
    socket_pops.release = unix_release;
    orig_unix_release = orig_socket_pops->release;
    */
    socket_pops.getname = addr_unix_getname;

    return misc_register(&eventpoll_ex_misc);
}

static void __exit
eventpoll_ex_exit (void)
{
    misc_deregister(&eventpoll_ex_misc);
}


module_init (eventpoll_ex_init);
module_exit (eventpoll_ex_exit);


MODULE_LICENSE("GPL");

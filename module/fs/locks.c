/*
 *  linux/fs/locks.c
 *
 *  Provide support for fcntl()'s F_GETLK, F_SETLK, and F_SETLKW calls.
 *  Doug Evans (dje@spiff.uucp), August 07, 1992
 *
 *  Deadlock detection added.
 *  FIXME: one thing isn't handled yet:
 *	- mandatory locks (requires lots of changes elsewhere)
 *  Kelly Carmichael (kelly@[142.24.8.65]), September 17, 1994.
 *
 *  Miscellaneous edits, and a total rewrite of posix_lock_file() code.
 *  Kai Petzke (wpp@marie.physik.tu-berlin.de), 1994
 *
 *  Converted file_lock_table to a linked list from an array, which eliminates
 *  the limits on how many active file locks are open.
 *  Chad Page (pageone@netcom.com), November 27, 1994
 *
 *  Removed dependency on file descriptors. dup()'ed file descriptors now
 *  get the same locks as the original file descriptors, and a close() on
 *  any file descriptor removes ALL the locks on the file for the current
 *  process. Since locks still depend on the process id, locks are inherited
 *  after an exec() but not after a fork(). This agrees with POSIX, and both
 *  BSD and SVR4 practice.
 *  Andy Walker (andy@lysaker.kvaerner.no), February 14, 1995
 *
 *  Scrapped free list which is redundant now that we allocate locks
 *  dynamically with kmalloc()/kfree().
 *  Andy Walker (andy@lysaker.kvaerner.no), February 21, 1995
 *
 *  Implemented two lock personalities - FL_FLOCK and FL_POSIX.
 *
 *  FL_POSIX locks are created with calls to fcntl() and lockf() through the
 *  fcntl() system call. They have the semantics described above.
 *
 *  FL_FLOCK locks are created with calls to flock(), through the flock()
 *  system call, which is new. Old C libraries implement flock() via fcntl()
 *  and will continue to use the old, broken implementation.
 *
 *  FL_FLOCK locks follow the 4.4 BSD flock() semantics. They are associated
 *  with a file pointer (filp). As a result they can be shared by a parent
 *  process and its children after a fork(). They are removed when the last
 *  file descriptor referring to the file pointer is closed (unless explicitly
 *  unlocked).
 *
 *  FL_FLOCK locks never deadlock, an existing lock is always removed before
 *  upgrading from shared to exclusive (or vice versa). When this happens
 *  any processes blocked by the current lock are woken up and allowed to
 *  run before the new lock is applied.
 *  Andy Walker (andy@lysaker.kvaerner.no), June 09, 1995
 *
 *  Removed some race conditions in flock_lock_file(), marked other possible
 *  races. Just grep for FIXME to see them.
 *  Dmitry Gorodchanin (pgmdsg@ibi.com), February 09, 1996.
 *
 *  Addressed Dmitry's concerns. Deadlock checking no longer recursive.
 *  Lock allocation changed to GFP_ATOMIC as we can't afford to sleep
 *  once we've checked for blocking and deadlocking.
 *  Andy Walker (andy@lysaker.kvaerner.no), April 03, 1996.
 *
 *  Initial implementation of mandatory locks. SunOS turned out to be
 *  a rotten model, so I implemented the "obvious" semantics.
 *  See 'Documentation/filesystems/mandatory-locking.txt' for details.
 *  Andy Walker (andy@lysaker.kvaerner.no), April 06, 1996.
 *
 *  Don't allow mandatory locks on mmap()'ed files. Added simple functions to
 *  check if a file has mandatory locks, used by mmap(), open() and creat() to
 *  see if system call should be rejected. Ref. HP-UX/SunOS/Solaris Reference
 *  Manual, Section 2.
 *  Andy Walker (andy@lysaker.kvaerner.no), April 09, 1996.
 *
 *  Tidied up block list handling. Added '/proc/locks' interface.
 *  Andy Walker (andy@lysaker.kvaerner.no), April 24, 1996.
 *
 *  Fixed deadlock condition for pathological code that mixes calls to
 *  flock() and fcntl().
 *  Andy Walker (andy@lysaker.kvaerner.no), April 29, 1996.
 *
 *  Allow only one type of locking scheme (FL_POSIX or FL_FLOCK) to be in use
 *  for a given file at a time. Changed the CONFIG_LOCK_MANDATORY scheme to
 *  guarantee sensible behaviour in the case where file system modules might
 *  be compiled with different options than the kernel itself.
 *  Andy Walker (andy@lysaker.kvaerner.no), May 15, 1996.
 *
 *  Added a couple of missing wake_up() calls. Thanks to Thomas Meckel
 *  (Thomas.Meckel@mni.fh-giessen.de) for spotting this.
 *  Andy Walker (andy@lysaker.kvaerner.no), May 15, 1996.
 *
 *  Changed FL_POSIX locks to use the block list in the same way as FL_FLOCK
 *  locks. Changed process synchronisation to avoid dereferencing locks that
 *  have already been freed.
 *  Andy Walker (andy@lysaker.kvaerner.no), Sep 21, 1996.
 *
 *  Made the block list a circular list to minimise searching in the list.
 *  Andy Walker (andy@lysaker.kvaerner.no), Sep 25, 1996.
 *
 *  Made mandatory locking a mount option. Default is not to allow mandatory
 *  locking.
 *  Andy Walker (andy@lysaker.kvaerner.no), Oct 04, 1996.
 *
 *  Some adaptations for NFS support.
 *  Olaf Kirch (okir@monad.swb.de), Dec 1996,
 *
 *  Fixed /proc/locks interface so that we can't overrun the buffer we are handed.
 *  Andy Walker (andy@lysaker.kvaerner.no), May 12, 1997.
 *
 *  Use slab allocator instead of kmalloc/kfree.
 *  Use generic list implementation from <linux/list.h>.
 *  Sped up posix_locks_deadlock by only considering blocked locks.
 *  Matthew Wilcox <willy@debian.org>, March, 2000.
 *
 *  Leases and LOCK_MAND
 *  Matthew Wilcox <willy@debian.org>, June, 2000.
 *  Stephen Rothwell <sfr@canb.auug.org.au>, June, 2000.
 *
 *  Portions Copyright (C) 2016
 *      0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com
 */

#include "../locks.h"
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#define IS_POSIX(fl)	(fl->fl_flags & FL_POSIX)

static void lock_work_handler(struct work_struct *pwork);
static DECLARE_WORK(lock_work_queue, lock_work_handler);
static LLIST_HEAD(lock_list);

void print_lock(struct file_lock *lock)
{
#ifndef NDEBUG
    printk(KERN_ERR "lock0: [link:%p], [block:%p], [wait:%p], [owner:%p]\n", lock->fl_link, lock->fl_block, lock->fl_wait, lock->fl_owner);

    printk(KERN_ERR "lock1: [pid:%i], [flags:%i], [file:%p], [type:%i]\n", lock->fl_pid, lock->fl_flags, lock->fl_file, lock->fl_type);
#endif
}

/*
static void locks_init_lock_heads(struct file_lock *fl)
{
    INIT_HLIST_NODE(&fl->fl_link);
    INIT_LIST_HEAD(&fl->fl_block);
    init_waitqueue_head(&fl->fl_wait);
}
*/

static int do_lock_file_wait(struct file *filp, unsigned int cmd,
                 struct file_lock *fl)
{
    //int error;

    /*
    error = security_file_lock(filp, fl->fl_type);
    if (error)
        return error;
*/
    return vfs_lock_file(filp, cmd, fl, NULL);
}

int write_file(struct file* file, unsigned char* data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;
    loff_t offset = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);

    return ret;
}

void lock_copy(struct file_lock* to, struct file_lock* from)
{
    to->fl_break_time = from->fl_break_time;
    to->fl_downgrade_time = from->fl_downgrade_time;
}

/*
 *  inode->i_lock is held!
 */
void unlock_notify(struct file_lock* lock)
{
    //printk(KERN_ERR "notify0\n");
    INIT_LIST_HEAD(&lock->fl_block);
    llist_add((struct llist_node*)&lock->fl_block, &lock_list);
    schedule_work(&lock_work_queue);
    //printk(KERN_ERR "notify1\n");
}

static void lock_work_handler(struct work_struct *pwork)
{
    struct file_lock* lock;
    struct inode *inode;
    int error;

    //printk(KERN_ERR "notify work\n");

    while(!llist_empty(&lock_list))
    {
        lock = llist_entry((struct list_head*)llist_del_first(&lock_list), struct file_lock, fl_block);
        inode = file_inode((struct file*)lock->fl_owner);
        INIT_LIST_HEAD(&lock->fl_block);

        //print_lock(lock);

        lock->fl_flags = FL_POSIX | FL_OFDLCK | FL_SLEEP;

        if(!(error = do_lock_file_wait((struct file*)lock->fl_owner, F_SETLK64, lock)))
        {
            struct file* filep = (struct file*)lock->fl_break_time;
            //printk(KERN_ERR "send %p\n", filep);
            if(filep)
            {
                error = write_file(filep, (unsigned char*)&lock->fl_downgrade_time, sizeof(lock->fl_downgrade_time));
                //printk(KERN_ERR "write, %i\n", error);
                fput(filep);
            }
        }
        else
        {
            //printk(KERN_ERR "read, %i == %i\n", error, FILE_LOCK_DEFERRED);
            if(error == FILE_LOCK_DEFERRED)
                continue;
        }
        BUG_ON(lock->fl_nspid);
        locks_free_lock(lock);
        fput((struct file*)lock->fl_owner);
    }

}

static int lock_compare(struct file_lock *fl1, struct file_lock *fl2)
{
    (void)fl1;
    (void)fl2;
    return 0;
}

static const struct file_lock_operations lock_ops = {
  .fl_copy_lock = lock_copy,
  .fl_release_private = NULL,
};

static const struct lock_manager_operations lock_manager_ops = {
  .lm_compare_owner = lock_compare,
  .lm_owner_key = NULL,
  .lm_notify = unlock_notify,
  .lm_grant = NULL,
  .lm_break = NULL,
  .lm_change = NULL,
};

static int assign_type(struct file_lock *fl, long type)
{
    switch (type) {
    case F_RDLCK:
    case F_WRLCK:
    case F_UNLCK:
        fl->fl_type = type;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static int flock64_to_posix_lock(struct file *filp, struct file_lock *fl,
                 struct flock64 *l)
{
    switch (l->l_whence) {
    case SEEK_SET:
        fl->fl_start = 0;
        break;
    case SEEK_CUR:
        fl->fl_start = filp->f_pos;
        break;
    case SEEK_END:
        fl->fl_start = i_size_read(file_inode(filp));
        break;
    default:
        return -EINVAL;
    }
    if (l->l_start > OFFSET_MAX - fl->fl_start)
        return -EOVERFLOW;
    fl->fl_start += l->l_start;
    if (fl->fl_start < 0)
        return -EINVAL;

    /* POSIX-1996 leaves the case l->l_len < 0 undefined;
       POSIX-2001 defines it. */
    if (l->l_len > 0) {
        if (l->l_len - 1 > OFFSET_MAX - fl->fl_start)
            return -EOVERFLOW;
        fl->fl_end = fl->fl_start + l->l_len - 1;

    } else if (l->l_len < 0) {
        if (fl->fl_start + l->l_len < 0)
            return -EINVAL;
        fl->fl_end = fl->fl_start - 1;
        fl->fl_start += l->l_len;
    } else
        fl->fl_end = OFFSET_MAX;

    fl->fl_owner = current->files;
    fl->fl_pid = current->tgid;
    fl->fl_file = filp;
    fl->fl_flags = FL_POSIX;
    fl->fl_ops = NULL;
    fl->fl_lmops = NULL;

    return assign_type(fl, l->l_type);
}

/* Ensure that fl->fl_filp has compatible f_mode for F_SETLK calls */
static int
check_fmode_for_setlk(struct file_lock *fl)
{
    switch (fl->fl_type) {
    case F_RDLCK:
        if (!(fl->fl_file->f_mode & FMODE_READ))
            return -EBADF;
        break;
    case F_WRLCK:
        if (!(fl->fl_file->f_mode & FMODE_WRITE))
            return -EBADF;
    }
    return 0;
}

static struct file* get_lock_msg_file(int msgFd)
{
    struct task_struct* task = pid_task(find_vpid(current->tgid), PIDTYPE_PID);
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *filep = NULL;
    if(task)
    {
        files = task->files;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        filep = fdt->fd[msgFd];
        if(filep)
            get_file(filep);
        spin_unlock(&files->file_lock);
    }
    return filep;
}

/* Apply the lock described by l to an open file descriptor.
 * This implements both the F_SETLK and F_SETLKW commands of fcntl().
 */
#if BITS_PER_LONG != 32
int try_lock_ofd64(struct file *filp, struct flock64 *lk, void* usrPtr, int msgFd)
{
    struct file_lock *lock = locks_alloc_lock();
    struct inode *inode;
    int error;

    if (lock == NULL)
        return -ENOLCK;

    /*
     * This might block, so we do it before checking the inode.
     */
    error = -EFAULT;

    inode = file_inode(filp);

    /* Don't allow mandatory locks on files that may be memory mapped
     * and shared.
     */
    if (mandatory_lock(inode) && mapping_writably_mapped(filp->f_mapping)) {
        error = -EAGAIN;
        goto out;
    }

    error = flock64_to_posix_lock(filp, lock, lk);
    if (error)
        goto out;

    error = check_fmode_for_setlk(lock);
    if (error)
        goto out;

    error = -EINVAL;
    if (lk->l_pid != 0)
        goto out;

    lock->fl_flags |= FL_OFDLCK | FL_SLEEP;
    lock->fl_owner = (fl_owner_t)filp;
    lock->fl_downgrade_time = (unsigned long)usrPtr;
    lock->fl_break_time = 0;
    lock->fl_ops = &lock_ops;
    lock->fl_lmops = &lock_manager_ops;
    lock->fl_break_time = (unsigned long)get_lock_msg_file(msgFd);
    get_file(filp);

    error = do_lock_file_wait(filp, F_SETLK64, lock);
    if(error == FILE_LOCK_DEFERRED)
    {
        //printk(KERN_ERR "added\n");
        //print_lock(lock);

        return -EAGAIN;
    }
    else
    {
        fput(filp);
        //printk(KERN_ERR "normal %i\n", current->tgid);
    }

out:
    locks_free_lock(lock);
    return error;
}
#endif

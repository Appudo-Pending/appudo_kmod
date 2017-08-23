/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 *
 */

/*
 * get_files_struct is copied from fs/file.c
 */
struct files_struct *
get_files_struct (struct task_struct *task)
{
    struct files_struct *files;

    task_lock (task);
    files = task->files;
    if (files)
        atomic_inc (&files->count);
    task_unlock (task);

    return files;
}


/*
 * put_files_struct is extracted from fs/file.c
 */
void
put_files_struct (struct files_struct *files)
{
    if (atomic_dec_and_test (&files->count))
    {
        BUG ();
    }
}

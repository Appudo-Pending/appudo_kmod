/*
 * linux/mm/process_vm_access.c
 *
 * Copyright (C) 2010-2011 Christopher Yeoh <cyeoh@au1.ibm.com>, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,20,0))
static inline long
___get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
            unsigned long start, unsigned long nr_pages,
            int write, int force, struct page **pages)
{
    long err;

    down_read(&mm->mmap_sem);
    err = get_user_pages(tsk, mm, start, nr_pages, write, force, pages,
                 NULL);
    up_read(&mm->mmap_sem);

    return err;
}
#else
static inline long
___get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
                             unsigned long start, unsigned long nr_pages,
                             int write, int force, struct page **pages)
{
    return __get_user_pages_unlocked(tsk, tsk->mm, start, nr_pages,
                     write, force, pages, FOLL_TOUCH);
}
#endif

/**
 * process_vm_rw_pages - read/write pages from task specified
 * @pages: array of pointers to pages we want to copy
 * @start_offset: offset in page to start copying from/to
 * @len: number of bytes to copy
 * @iter: where to copy to/from locally
 * @vm_write: 0 means copy from, 1 means copy to
 * Returns 0 on success, error code otherwise
 */
static int process_vm_rw_pages(struct page **pages,
                   unsigned offset,
                   size_t len,
                   struct iov_iter *iter,
                   int vm_write)
{
    /* Do the copy for each page */
    while (len && iov_iter_count(iter)) {
        struct page *page = *pages++;
        size_t copy = PAGE_SIZE - offset;
        size_t copied;

        if (copy > len)
            copy = len;

        if (vm_write) {
            copied = copy_page_from_iter(page, offset, copy, iter);
            set_page_dirty_lock(page);
        } else {
            copied = copy_page_to_iter(page, offset, copy, iter);
        }
        len -= copied;
        if (copied < copy && iov_iter_count(iter))
            return -EFAULT;
        offset = 0;
    }
    return 0;
}

/* Maximum number of pages kmalloc'd to hold struct page's during copy */
#define PVM_MAX_KMALLOC_PAGES (PAGE_SIZE * 2)

/**
 * process_vm_rw_single_vec - read/write pages from task specified
 * @addr: start memory address of target process
 * @len: size of area to copy to/from
 * @iter: where to copy to/from locally
 * @process_pages: struct pages area that can store at least
 *  nr_pages_to_copy struct page pointers
 * @mm: mm for task
 * @task: task to read/write from
 * @vm_write: 0 means copy from, 1 means copy to
 * Returns 0 on success or on failure error code
 */
static int process_vm_rw_single_vec(unsigned long addr,
                    unsigned long len,
                    struct iov_iter *iter,
                    struct page **process_pages,
                    struct mm_struct *mm,
                    struct task_struct *task,
                    int vm_write)
{
    unsigned long pa = addr & PAGE_MASK;
    unsigned long start_offset = addr - pa;
    unsigned long nr_pages;
    ssize_t rc = 0;
    unsigned long max_pages_per_loop = PVM_MAX_KMALLOC_PAGES
        / sizeof(struct pages *);

    /* Work out address and page range required */
    if (len == 0)
        return 0;
    nr_pages = (addr + len - 1) / PAGE_SIZE - addr / PAGE_SIZE + 1;

    while (!rc && nr_pages && iov_iter_count(iter)) {
        int pages = min(nr_pages, max_pages_per_loop);
        size_t bytes;

        /* Get the pages we're interested in */
        pages = ___get_user_pages_unlocked(task, mm, pa, pages,
                                vm_write, 0, process_pages);


        if (pages <= 0)
            return -EFAULT;

        bytes = pages * PAGE_SIZE - start_offset;
        if (bytes > len)
            bytes = len;

        rc = process_vm_rw_pages(process_pages,
                     start_offset, bytes, iter,
                     vm_write);

        len -= bytes;
        start_offset = 0;
        nr_pages -= pages;
        pa += pages * PAGE_SIZE;
        while (pages)
            put_page(process_pages[--pages]);
    }

    return rc;
}

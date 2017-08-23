/*
    Copyright (C) 2016
        0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com

    groups_from_user, groups_sort, update_current_groups from linux kernel

    group_cache.c is part of Appudo

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

#include "./group_cache.h"
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/security.h>

struct group_item
{
    union
    {
        uid_t   userId;
        int     nextFree;
    };
    struct group_info* info;
};

struct group_data
{
    int                free_idx;
    unsigned int       num_items;
    gid_t              min;
    gid_t              max;
    gid_t              master;
    spinlock_t         lock;
    struct group_info* empty_info;
    struct group_item  items[1];
};

typedef int (*security_task_fix_setuid_t)(struct cred *new, const struct cred *old,
                                     int flags);
security_task_fix_setuid_t _security_task_fix_setuid = NULL;


struct group_info* group_get_info(struct group_item *item)
{
    return (struct group_info*)((unsigned long)item->info & ~1L);
}

int group_get_info_master(struct group_item *item)
{
    return (unsigned long)item->info & 1L;
}

void group_set_info_master(struct group_item *item, bool master)
{
    item->info = (struct group_info*)((unsigned long)item->info | (unsigned long)master);
}

/* fill a group_info from a user-space array - it must be allocated already */
static int groups_from_user(struct group_info *group_info,
    gid_t __user *grouplist, struct group_data* ginfo, int* master)
{
    struct user_namespace *user_ns = current_user_ns();
    int i;
    unsigned int count = group_info->ngroups;
    gid_t mgid = ginfo->master;
    gid_t min = ginfo->min;
    gid_t max = ginfo->max;
    *master = 0;

    for (i = 0; i < count; i++) {
        gid_t gid;
        kgid_t kgid;
        if (get_user(gid, grouplist+i))
            return -EFAULT;

        if(gid < min || gid > max)
        {
            if(mgid == gid)
            {
                *master = 1;
            }
            else
            {
                return -EINVAL;
            }
        }

        kgid = make_kgid(user_ns, gid);
        if (!gid_valid(kgid))
            return -EINVAL;

        GROUP_AT(group_info, i) = kgid;
    }
    return 0;
}

/* a simple Shell sort */
static void groups_sort(struct group_info *group_info)
{
    int base, max, stride;
    int gidsetsize = group_info->ngroups;

    for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
        ; /* nothing */
    stride /= 3;

    while (stride) {
        max = gidsetsize - stride;
        for (base = 0; base < max; base++) {
            int left = base;
            int right = left + stride;
            kgid_t tmp = GROUP_AT(group_info, right);

            while (left >= 0 && gid_gt(GROUP_AT(group_info, left), tmp)) {
                GROUP_AT(group_info, right) =
                    GROUP_AT(group_info, left);
                right = left;
                left -= stride;
            }
            GROUP_AT(group_info, right) = tmp;
        }
        stride /= 3;
    }
}

/**
 * update_current_groups - Change current's group subscription
 * @group_info: The group list to impose
 *
 * Validate a group subscription and, if valid, impose it upon current's task
 * security record.
 */
static int update_current_groups(struct group_data* ginfo, uid_t euid, struct group_item* item, gid_t egid)
{
    unsigned long flags;
    struct user_namespace *ns = current_user_ns();
    struct cred *new;
    const struct cred *old;
    struct group_info *group_info = group_get_info(item);
    int ok = euid != (uid_t) -1;
    kuid_t keuid;
    kgid_t kegid;

    keuid = make_kuid(ns, euid);

    if(egid != (gid_t)-1)
    {
        kegid = make_kgid(ns, egid);
        spin_lock_irqsave(&ginfo->lock, flags);
        ok &= (egid >= ginfo->min && egid <= ginfo->max);
        spin_unlock_irqrestore(&ginfo->lock, flags);
    }

    if(!ok ||
       !group_info ||
       !uid_valid(keuid) ||
       ((egid != (uid_t) -1) && !gid_valid(kegid)))
        return -EINVAL;

    /*
    if(!ns_capable(ns, CAP_SETUID))
        return -EPERM;
        */

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    new->euid = keuid;
    new->fsuid = keuid;
    if(egid != -1)
    {
        new->egid = kegid;
        new->fsgid = kegid;
    }
    else
    {
        new->egid = new->gid;
        new->fsgid = new->gid;
    }

    put_group_info(new->group_info);
    get_group_info(group_info);
    new->group_info = group_info;

    old = current_cred();

#ifdef CONFIG_SECURITY
    if(_security_task_fix_setuid(new, old, LSM_SETID_RES) < 0)
#else
    if(security_task_fix_setuid(new, old, LSM_SETID_RES) < 0)
#endif
    {
        abort_creds(new);
        return -EPERM;
    }
    return commit_creds(new);
}

int group_cache_add(struct group_data* ginfo, uid_t userId, gid_t* __user grouplist, unsigned int size)
{
    int result = -EINVAL;
    struct group_info* grs;
    struct group_item* item;
    unsigned long flags;
    int master;
    spin_lock_irqsave(&ginfo->lock, flags);
    RETRY:
    if(ginfo->free_idx != -1 && (grs = groups_alloc(size)))
    {
        if((result = groups_from_user(grs, grouplist, ginfo, &master)) != 0)
        {
            put_group_info(grs);
        }
        else
        {
            groups_sort(grs);
            result = ginfo->free_idx;
            item = ginfo->items + result;
            ginfo->free_idx = item->nextFree;

            item->info = grs;
            item->userId = userId;
            group_set_info_master(item, master != 0);
        }
    }
    else
    {
        if(ginfo->free_idx != -1)
        {
            // this is an error in user space that should not happen
            group_cache_clear(ginfo, 0);
            goto RETRY;
        }
    }
    spin_unlock_irqrestore(&ginfo->lock, flags);
    return result;
}

int group_cache_remove(struct group_data* ginfo, uid_t userId, unsigned int id)
{
    int result = 0;
    struct group_item* item;
    unsigned long flags;
    spin_lock_irqsave(&ginfo->lock, flags);

    if(id < ginfo->num_items && (item = ginfo->items + id)->userId == userId)
    {
        put_group_info(group_get_info(item));

        item->info = NULL;
        item->nextFree = ginfo->free_idx;

        ginfo->free_idx = id;
    }
    else
    {
        result = -EINVAL;
    }

    spin_unlock_irqrestore(&ginfo->lock, flags);

    return result;
}

int group_cache_set_group(struct group_data* ginfo, gid_t gid, int allow_master)
{
    unsigned long flags;
    struct user_namespace *ns = current_user_ns();
    kgid_t kgid;
    struct cred *new;
    int ok;

    if(!allow_master || gid == (gid_t)-1)
        return -EINVAL;

    kgid = make_kgid(ns, gid);

    spin_lock_irqsave(&ginfo->lock, flags);
    ok = (gid >= ginfo->min && gid <= ginfo->max) || (allow_master && gid == ginfo->master);
    spin_unlock_irqrestore(&ginfo->lock, flags);

    if (!gid_valid(kgid) || !ok)
        return -EINVAL;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    new->gid = kgid;
    new->egid = kgid;
    new->fsgid = kgid;

    return commit_creds(new);
}

int group_cache_set_egroup(struct group_data* ginfo, gid_t egid)
{
    unsigned long flags;
    struct user_namespace *ns = current_user_ns();
    kgid_t kegid;
    const struct cred *old;
    struct cred *new;
    int ok;

    if(egid != -1)
    {
        kegid = make_kgid(ns, egid);

        spin_lock_irqsave(&ginfo->lock, flags);
        ok = (egid >= ginfo->min && egid <= ginfo->max);
        spin_unlock_irqrestore(&ginfo->lock, flags);
    }
    else
    {
        old = current_cred();
        if(gid_eq(old->gid, old->egid))
            return 0;
        kegid = old->gid;
        ok = 1;
    }

    if (((egid != (gid_t) -1) && !gid_valid(kegid)) || !ok)
        return -EINVAL;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    new->egid = kegid;
    new->fsgid = kegid;

    return commit_creds(new);
}

int group_cache_check(struct group_data* ginfo, uid_t euid, unsigned int id)
{
    struct group_item* item;
    unsigned long flags;
    int ok;

    spin_lock_irqsave(&ginfo->lock, flags);
    ok = id < ginfo->num_items && (item = ginfo->items + id)->userId == euid;
    spin_unlock_irqrestore(&ginfo->lock, flags);

    return ok ? 0 : -EINVAL;
}

int group_cache_gset(struct group_data* ginfo, uid_t euid, gid_t egid, unsigned int id)
{
    int result = -EINVAL;
    struct group_item* item;
    unsigned long flags;
    int ok;

    spin_lock_irqsave(&ginfo->lock, flags);
    ok = id < ginfo->num_items && (item = ginfo->items + id)->userId == euid;
    spin_unlock_irqrestore(&ginfo->lock, flags);

    if(ok)
    {
        result = update_current_groups(ginfo, euid, item, egid);
    }

    return result;
}

int group_cache_reset(struct group_data* ginfo)
{
    struct cred *new;
    const struct cred *old;
    kuid_t keuid;
    kgid_t kgid;

    old = current_cred();
    keuid = old->uid;
    kgid = old->gid;

    /*
    if(!ns_capable(ns, CAP_SETUID))
        return -EPERM;
        */

    new = prepare_creds();
    if (!new)
    {
        return -ENOMEM;
    }

    new->euid = keuid;
    new->fsuid = keuid;
    new->fsgid = kgid;
    new->egid = kgid;

    put_group_info(new->group_info);
    get_group_info(ginfo->empty_info);
    new->group_info = ginfo->empty_info;

#ifdef CONFIG_SECURITY
    if(_security_task_fix_setuid(new, old, LSM_SETID_RES) < 0)
#else
    if(security_task_fix_setuid(new, old, LSM_SETID_RES) < 0)
#endif
    {
        abort_creds(new);
        return -EPERM;
    }
    return commit_creds(new);
}

void group_cache_static_init(void)
{
#ifdef CONFIG_SECURITY
    _security_task_fix_setuid = (security_task_fix_setuid_t)kallsyms_lookup_name("security_task_fix_setuid");
#endif
}

int group_cache_init_groups(struct group_data* ginfo, gid_t min, gid_t max)
{
    int result = -EINVAL;
    unsigned long flags;
    spin_lock_irqsave(&ginfo->lock, flags);
    if(min == -1) // init master
    {
        if(ginfo->master == -1)
        {
            ginfo->master = max;
            result = 0;
        }
    }
    else          // init min, max
    {
        if(ginfo->min == -1 && ginfo->max == -1)
        {
            ginfo->min = min;
            ginfo->max = max;
            result = 0;
        }
    }
    spin_unlock_irqrestore(&ginfo->lock, flags);
    return result;
}

int group_cache_init(struct group_data** _ginfo, unsigned int num_users)
{
    int i;
    struct group_item* item;
    struct group_data* ginfo;

    if(num_users == 0)
        return -EINVAL;

    ginfo = (struct group_data*)kmalloc(sizeof(struct group_data) + sizeof(struct group_item) * (num_users - 1), GFP_KERNEL);
    if(ginfo)
    {
       * _ginfo = ginfo;
       for(i = 0; i < num_users; i++)
       {
           item = ginfo->items + i;
           item->info = NULL;
           item->nextFree = i + 1;
       }

       item->nextFree = -1;
       ginfo->empty_info = groups_alloc(1);
       ginfo->free_idx = 0;
       ginfo->num_items = num_users;
       ginfo->min = -1;
       ginfo->max = -1;
       ginfo->master = -1;
       spin_lock_init(&ginfo->lock);
       if(ginfo->empty_info)
       {
           ginfo->empty_info->nblocks = 0;
       }
       else
       {
           kfree(ginfo);
           return -ENOMEM;
       }
       return 0;
    }
    return -ENOMEM;
}

int group_cache_destroy(struct group_data *ginfo)
{
    group_cache_clear(ginfo, 1);
    if(ginfo)
    {
        if(ginfo->empty_info)
            put_group_info(ginfo->empty_info);
        kfree(ginfo);
    }
    return 0;
}

int group_cache_clear(struct group_data *ginfo, int lock)
{
    int i;
    int num_users;
    struct group_item* item;
    if(ginfo)
    {
        unsigned long flags = 0;
        if(lock)
            spin_lock_irqsave(&ginfo->lock, flags);
        num_users = ginfo->num_items;
        for(i = 0; i < num_users; i++)
        {
            item = ginfo->items + i;
            if(item->info)
            {
                put_group_info(group_get_info(item));
                item->info = NULL;
                item->nextFree = ginfo->free_idx;

                ginfo->free_idx = i;
            }
        }
        if(lock)
            spin_unlock_irqrestore(&ginfo->lock, flags);
    }
    return 0;
}

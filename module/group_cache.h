/*
    Copyright (C) 2016
        0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com

    group_cache.h is part of Appudo

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
#ifndef GROUP_CACHE_H
#define GROUP_CACHE_H

struct group_data;

void group_cache_static_init(void);
int group_cache_init(struct group_data** _ginfo, unsigned int num_users);
int group_cache_init_groups(struct group_data* ginfo, gid_t min, gid_t max);
int group_cache_destroy(struct group_data* ginfo);
int group_cache_clear(struct group_data* ginfo, int lock);
int group_cache_reset(struct group_data* ginfo);
int group_cache_add(struct group_data *ginfo, uid_t userId, gid_t* grouplist, unsigned int size);
int group_cache_remove(struct group_data* ginfo, uid_t userId, unsigned int id);
int group_cache_gset(struct group_data* ginfo, uid_t euid, gid_t egid, unsigned int id);
int group_cache_check(struct group_data* ginfo, uid_t euid, unsigned int id);
int group_cache_set_egroup(struct group_data* ginfo, gid_t egid);
int group_cache_set_group(struct group_data* ginfo, gid_t gid, int allow_master);

#endif // GROUP_CACHE_H

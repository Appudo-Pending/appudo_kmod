/*
    Copyright (C) 2016
        0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com

    Copyright (C) 2015
        a742baed6b4bbfbc5c50dfea489f8dc0976855df1a27fb4662ce2cc5123dcc1a source@appudo.com
        bf1368eaf5a22ea65fcfd4f7e0efccd233a810deaaebfb8b374a76c2e472d618 source@appudo.com

    eventpoll.h is part of Appudo

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

/*
 * security:
 * - Only a master process is able to open the special eventpoll device.
 * - Other processes will request the device from the master and will only receive
 *   it after a security check.
 *   For example a message must be sent from a named socket that contains the
 *   pid and the service id of the requester. The pid can be matched with the
 *   kernel managed pid of the message and the service table in the master process.
 *   (The master process creates all service children)
 * - The group cache is connected to the original open eventpoll device file.
 * - An open eventpoll device without the master flag is unable to switch to the
 *   master group.
 * - The master group has no special permissions from the overall system perspective
 * - A range of non linux users and groups with no special permissions are used
 *   to prevent overall system damage if there is a security hole in this code.
 *
 * TODO: Replace the count to hold a pointer to a user space buffer in the target process.
 *       |64|3| => use bit 1+2 for the count, bit 3 for error and the rest to hold the
 *                 pointer
 *       The target process can hold a structure with multiple ranges and access permissions.
 *       As soon as the waiter is popped, the pointer is set to NULL.
 *
 */
#ifndef _EVENTOLL_EX_H
#define _EVENTOLL_EX_H

#include <linux/fs.h>

#define EVENTPOLL_EX_MINOR   139

struct eventpoll_init
{
    union
    {
        struct
        {
            unsigned  source_fd;
            unsigned  flags;
        };
        unsigned long data;
    };
};

struct eventpoll_addr
{
    unsigned source_fd;
    unsigned target_fd;
};

struct eventpoll_data
{
    unsigned source_fd;
    unsigned target_fd;
    pid_t    target_pid;
};

struct eventpoll_copy_data
{
    union
	{
    	void* 		  source_buffer;
		unsigned int  u32;
		int  		  i32;
		unsigned long u64;
		long  	  	  i64;
	};
	void* 	 	 target_buffer;
    pid_t 		 target_pid;
    unsigned int size;	// if size == 0, copy 64 bit
};

struct eventpoll_lock
{
    struct flock64 lock;
    void*          user_ptr;
    int            msgFd;
    int            fileFd;
};

struct eventpoll_group_info
{
    uid_t            userId;
    union
    {
        unsigned int id;
        unsigned int size;
    };
    union
    {
        gid_t        egid;
        gid_t*       grouplist;
    };
};

struct eventpoll_egroup_info
{
    union
    {
        gid_t gid;
        struct
        {
            gid_t min;
            gid_t max;
        };
        uint64_t  data;
    };
};

#define IOCTRL_APP 71

enum eventpoll_ex_ctrl
{
    EVENTPOLL_INIT       = _IO(IOCTRL_APP, 1),
	EVENTPOLL_ENABLE	  = _IO(IOCTRL_APP, 2),
	EVENTPOLL_ENABLE_NR	  = _IO(IOCTRL_APP, 3),
    EVENTPOLL_DISABLE	  = _IO(IOCTRL_APP, 4),
    EVENTPOLL_REARM 	  = _IO(IOCTRL_APP, 5),
    EVENTPOLL_DBG_WAITER  = _IOW(IOCTRL_APP, 6, pid_t),
    EVENTPOLL_CLOSEFDS	  = _IO(IOCTRL_APP, 7),
    EVENTPOLL_ADDR 		  = _IOR(IOCTRL_APP, 8, struct eventpoll_addr),
    EVENTPOLL_SHUTDOWN	  = _IO(IOCTRL_APP, 9),
    EVENTPOLL_POP_NUM     = _IO(IOCTRL_APP, 10),
    EVENTPOLL_POP_PID  	  = _IO(IOCTRL_APP, 11),
    EVENTPOLL_COPYFD_TO   = _IOR(IOCTRL_APP, 12, struct eventpoll_data),
    EVENTPOLL_COPY_TO     = _IOR(IOCTRL_APP, 13, struct eventpoll_copy_data),
    EVENTPOLL_COPYFD_FROM = _IOR(IOCTRL_APP, 14, struct eventpoll_data),
    EVENTPOLL_COPY_FROM   = _IOR(IOCTRL_APP, 15, struct eventpoll_copy_data),
    EVENTPOLL_LOCK_FILE   = _IOR(IOCTRL_APP, 16, struct eventpoll_lock),
    EVENTPOLL_CHECK  	  = _IO(IOCTRL_APP, 17),
    EVENTPOLL_ADD_GROUPS  = _IOR(IOCTRL_APP, 18, struct eventpoll_group_info),
    EVENTPOLL_SET_GROUPS  = _IOR(IOCTRL_APP, 19, struct eventpoll_group_info),
    EVENTPOLL_DEL_GROUPS  = _IOR(IOCTRL_APP, 20, struct eventpoll_group_info),
    EVENTPOLL_CLR_GROUPS  = _IO(IOCTRL_APP, 21),
    EVENTPOLL_RST_GROUPS  = _IO(IOCTRL_APP, 22),
    EVENTPOLL_CHK_GROUPS  = _IO(IOCTRL_APP, 23),
    EVENTPOLL_INIT_EGRP   = _IO(IOCTRL_APP, 24),
    EVENTPOLL_SET_EGRP    = _IO(IOCTRL_APP, 25),
    EVENTPOLL_SET_GRP     = _IO(IOCTRL_APP, 26),

    EVENTPOLL_SET_WRITE_HOOK   = _IO(IOCTRL_APP, 27),
    EVENTPOLL_SET_PRIV_DATA    = _IOWR(IOCTRL_APP, 28, long),
    EVENTPOLL_DBG_CLOSE        = _IO(IOCTRL_APP, 29),
    EVENTPOLL_DBG_CLOSE_NO_EV  = _IO(IOCTRL_APP, 30),
    EVENTPOLL_DBG_ENABLE       = _IO(IOCTRL_APP, 31),
};

#endif

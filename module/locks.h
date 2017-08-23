/*
    Copyright (C) 2016
        0bd5726fc1d70b36a90f29c71b210d39e31f619abee5ab9f63bf2b9cde947653 source@appudo.com

    locks.h is part of Appudo

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

#ifndef LOCKS_H
#define LOCKS_H

#include <linux/file.h>
#include <linux/fs.h>

#if BITS_PER_LONG != 32
int try_lock_ofd64(struct file *filp, struct flock64 *l, void* usrPtr, int msgFd);
#endif

#endif // LOCKS_H

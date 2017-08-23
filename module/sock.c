/*
    Copyright (C) 2015
        a742baed6b4bbfbc5c50dfea489f8dc0976855df1a27fb4662ce2cc5123dcc1a source@appudo.com

    sock.c is part of Appudo

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

#include "debug_trace.h"

static void (*orig_unix_sock_destructor)(struct sock *sock) = 0;

static void addr_unix_sock_destructor(struct sock *sock)
{
    struct file* peer;
    peer = (struct file*)rcu_dereference_sk_user_data(sock);
    if(peer)
    {
        fput(peer);
    }
    orig_unix_sock_destructor(sock);
}

static inline void unix_release_addr(struct unix_address *addr)
{
    if (atomic_dec_and_test(&addr->refcnt))
        kfree(addr);
}

static int (*orig_unix_stream_sendmsg)(struct socket *sock, struct msghdr *m, size_t total_len) = 0;
/*
static int (*orig_unix_release)(struct socket *) = 0;

static int (*orig_unix_stream_release)(struct socket *sock) = 0;

static int unix_release(struct socket *sock)
{
    struct socket* link = NULL;
    struct sock *sk = sock->sk;
    struct unix_sock *u;
    if(!sk)
        return 0;
    u = unix_sk(sk);
    link = (struct socket *)u->addr;
    fput(link->file);
    u->addr = NULL;
    return orig_unix_release(sock);
}

*/
static int addr_unix_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
    struct file* peer_file;
    struct socket* link;
    struct sock *sk = sock->sk;
    int res = -EFAULT;
    sock_hold(sk);
    peer_file = (struct file*)rcu_dereference_sk_user_data(sk);
    if(peer_file)
    {
        link = (struct socket*)peer_file->private_data;

        if(link)
        {
            res = link->ops->getname(link, uaddr, uaddr_len, peer);
        }
    }

    sock_put(sk);

    return res;
}

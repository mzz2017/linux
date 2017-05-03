/*
 * POSIX file descriptor based virtual network interface feature for
 * LKL Copyright (c) 2015,2016 Ryo Nakamura, Hajime Tazaki
 *
 * Author: Ryo Nakamura <upa@wide.ad.jp>
 *         Hajime Tazaki <thehajime@gmail.com>
 *         Octavian Purdila <octavian.purdila@intel.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "virtio.h"
#include "virtio_net_fd.h"

struct lkl_netdev_fd {
	struct lkl_netdev dev;
	/* file-descriptor based device */
	int fd;
	/*
	 * Controlls the poll mask for fd. Can be acccessed concurrently from
	 * poll, tx, or rx routines but there is no need for syncronization
	 * because:
	 *
	 * (a) TX and RX routines set different variables so even if they update
	 * at the same time there is no race condition
	 *
	 * (b) Even if poll and TX / RX update at the same time poll cannot
	 * stall: when poll resets the poll variable we know that TX / RX will
	 * run which means that eventually the poll variable will be set.
	 */
	int poll_tx, poll_rx;
	/* controle pipe */
	int pipe[2];
};

static int fd_net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
	int ret;
	struct lkl_netdev_fd *nd_fd =
		container_of(nd, struct lkl_netdev_fd, dev);
    struct msghdr msg;
	struct sockaddr_ll ll;
    memset(&msg, 0, sizeof(msg));
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = if_nametoindex("venet0"); //ifname
	//ll.sll_ifindex = if_nametoindex("enp0s9"); //ifname
	ll.sll_protocol = htons(ETH_P_IP);
    msg.msg_name = &ll;
    msg.msg_namelen = sizeof(ll);
    msg.msg_iov = iov;
    msg.msg_iovlen = cnt;

        //for(int i =0; i< iov[0].iov_len; i++){
        //    printf("%02x", *((char *)iov[0].iov_base + i) & 0xff);
        //}
        //printf("\n\n");

    //iov[0].iov_base += 14;
    //iov[0].iov_len -= 14;
    //for(int i=0; i< cnt; i++){
    //    printf("iov[%d].iov_len=%d\n", i, iov[i].iov_len);
    //}

    //test
    //if(iov[0].iov_len < 14){
    //    printf("iov[0].iov_len=%d\n", iov[0].iov_len);
    //    printf("iov[1].iov_len=%d\n", iov[1].iov_len);
    //}

    // strip the MAC header(14 bytes)
    for(int i=0; i< cnt; i++){
        if(iov[i].iov_len >= 14){
            iov[i].iov_base += 14;
            iov[i].iov_len -= 14;
            break;
        }
    }

	do {
		//ret = writev(nd_fd->fd, iov, cnt);
		ret = sendmsg(nd_fd->fd, &msg, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		if (errno != EAGAIN) {
			perror("write to fd netdev fails");
		} else {
			char tmp;

			nd_fd->poll_tx = 1;
			if (write(nd_fd->pipe[1], &tmp, 1) <= 0)
				perror("virtio net fd pipe write");
		}
	}
	return ret;
}

static int fd_net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
	int ret;
	struct lkl_netdev_fd *nd_fd =
		container_of(nd, struct lkl_netdev_fd, dev);
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
	struct sockaddr_ll ll;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = if_nametoindex("venet0"); //ifname
	//ll.sll_ifindex = if_nametoindex("enp0s9"); //ifname
	ll.sll_protocol = htons(ETH_P_IP);
    msg.msg_name = &ll;
    msg.msg_namelen = sizeof(ll);
    //msg.msg_iov = (struct iovec *)iov + 1;
    msg.msg_iov = iov;
    msg.msg_iovlen = cnt;
    char mac_layer[] = {0x08,0x00,0x27,0x1a,0xb1,0x01,0x08,0x08,0x27,0x1a,0xb1,0x02,0x08,0x00};

    // the iov buffer is preallocated, recvmsg wouldn't allocate memory for it. refer to "man readv"
    // left space for the MAC header(14 bytes)
    int i=0;
    for(; i< cnt; i++){
        if(iov[i].iov_len >= 14){
            iov[i].iov_base += 14;
            iov[i].iov_len -= 14;
            break;
        }
    }

	do {
		//ret = readv(nd_fd->fd, (struct iovec *)iov + 1, cnt);
		ret = recvmsg(nd_fd->fd, &msg, 0);

        //for(int i =0; i< iov[1].iov_len; i++){
        //    printf("%02x", *((char *)iov[1].iov_base + i) & 0xff);
        //}
        //printf("\n\n");
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		if (errno != EAGAIN) {
			perror("virtio net fd read");
		} else {
			char tmp;

			nd_fd->poll_rx = 1;
			if (write(nd_fd->pipe[1], &tmp, 1) < 0)
				perror("virtio net fd pipe write");
		}
	} else {

        //int i=0;
        //for(; i< cnt; i++){
        //    if(iov[i].iov_len > 0){
        //        break;
        //    }
        //}
        /*ICMP and TCP dst port 443*/
        unsigned char *p = (unsigned char *)iov[i].iov_base;
        if((*(p + 9) != 0x06 ||*(p + 22) != 0x01 || *(p + 23) != 0xbb )&& \
                *(p + 9) != 0x01){
            ret = -1;
		    char tmp;

		    nd_fd->poll_rx = 1;
		    if (write(nd_fd->pipe[1], &tmp, 1) < 0)
		    	perror("virtio net fd pipe write");
            //iov[i]_len is a constant number. As iov[i]_base is a preallocated buffer .
        } else {

            //char tmp[2000];
            //memcpy(tmp, iov[i].iov_base, ret);
            //memcpy((char *)(iov[i].iov_base) +14, tmp, ret);
            //memcpy(iov[i].iov_base, mac_layer, 14);

            // add MAC header length(14 bytes) to return value
            ret += 14;
            // fulfill the lefted space for MAC header(14 bytes)
            iov[i].iov_base -= 14;
            iov[i].iov_len += 14;
            memcpy(iov[i].iov_base, mac_layer, 14);

        }
    }
	return ret;
}

static int fd_net_poll(struct lkl_netdev *nd)
{
	struct lkl_netdev_fd *nd_fd =
		container_of(nd, struct lkl_netdev_fd, dev);
	struct pollfd pfds[2] = {
		{
			.fd = nd_fd->fd,
		},
		{
			.fd = nd_fd->pipe[0],
			.events = POLLIN,
		},
	};
	int ret;

	if (nd_fd->poll_rx)
		pfds[0].events |= POLLIN|POLLPRI;
	if (nd_fd->poll_tx)
		pfds[0].events |= POLLOUT;

	do {
		ret = poll(pfds, 2, -1);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		perror("virtio net fd poll");
		return 0;
	}

	if (pfds[1].revents & (POLLHUP|POLLNVAL))
		return LKL_DEV_NET_POLL_HUP;

	if (pfds[1].revents & POLLIN) {
		char tmp[PIPE_BUF];

		ret = read(nd_fd->pipe[0], tmp, PIPE_BUF);
		if (ret == 0)
			return LKL_DEV_NET_POLL_HUP;
		if (ret < 0)
			perror("virtio net fd pipe read");
	}

	ret = 0;

	if (pfds[0].revents & (POLLIN|POLLPRI)) {
		nd_fd->poll_rx = 0;
		ret |= LKL_DEV_NET_POLL_RX;
	}

	if (pfds[0].revents & POLLOUT) {
		nd_fd->poll_tx = 0;
		ret |= LKL_DEV_NET_POLL_TX;
	}

	return ret;
}

static void fd_net_poll_hup(struct lkl_netdev *nd)
{
	struct lkl_netdev_fd *nd_fd =
		container_of(nd, struct lkl_netdev_fd, dev);

	/* this will cause a POLLHUP / POLLNVAL in the poll function */
	close(nd_fd->pipe[0]);
	close(nd_fd->pipe[1]);
}

static void fd_net_free(struct lkl_netdev *nd)
{
	struct lkl_netdev_fd *nd_fd =
		container_of(nd, struct lkl_netdev_fd, dev);

	close(nd_fd->fd);
	free(nd_fd);
}

struct lkl_dev_net_ops fd_net_ops =  {
	.tx = fd_net_tx,
	.rx = fd_net_rx,
	.poll = fd_net_poll,
	.poll_hup = fd_net_poll_hup,
	.free = fd_net_free,
};

struct lkl_netdev *lkl_register_netdev_fd(int fd)
{
	struct lkl_netdev_fd *nd;

	nd = malloc(sizeof(*nd));
	if (!nd) {
		fprintf(stderr, "fdnet: failed to allocate memory\n");
		/* TODO: propagate the error state, maybe use errno for that? */
		return NULL;
	}

	memset(nd, 0, sizeof(*nd));

	nd->fd = fd;
	if (pipe(nd->pipe) < 0) {
		perror("pipe");
		free(nd);
		return NULL;
	}

	if (fcntl(nd->pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror("fnctl");
		close(nd->pipe[0]);
		close(nd->pipe[1]);
		free(nd);
		return NULL;
	}

	nd->dev.ops = &fd_net_ops;
	return &nd->dev;
}

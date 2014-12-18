#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/

enum msg_id_t {
	TEE_REGISTER_SERVER = 1,
	TEE_TEST_SERVER,
	TEE_RESERVED = 0xFFFF,
};

struct tee_msg {
	enum msg_id_t msg_id;
	uint16_t flags;
	int32_t msg_data_len;
	char msg_data[MAX_PAYLOAD - 8];
};

int sock_fd;
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;

static int process_msg() {
	struct tee_msg msg_payload;
	char *msg_buf;

	memcpy(&msg_payload, NLMSG_DATA(nlh), sizeof(msg_payload));

	switch (msg_payload.msg_id) {
	case TEE_TEST_SERVER:
		msg_buf = malloc(msg_payload.msg_data_len);
		memcpy(msg_buf, msg_payload.msg_data, msg_payload.msg_data_len);
		printf("Server received test msg: %s\n", msg_buf);
		free(msg_buf);

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg_payload.msg_id = TEE_TEST_SERVER;
	msg_payload.msg_data_len = 10;
	strcpy(msg_payload.msg_data, "server: OK\n");
	memcpy(NLMSG_DATA(nlh), &msg_payload, sizeof(msg_payload));
	sendmsg(sock_fd, &msg, 0);

		break;
	default:
		printf("Wrong message type\n");
		return -1;
	}

	return 0;
}

int main()
{
	struct tee_msg msg_payload;

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (sock_fd < 0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg_payload.msg_id = TEE_REGISTER_SERVER;
	msg_payload.msg_data_len = 0;
	memcpy(NLMSG_DATA(nlh), &msg_payload, sizeof(msg_payload));
	printf("Registering server to the kernel\n");
	sendmsg(sock_fd, &msg, 0);

	while (1) {
		printf("Waiting for message from kernel\n");
		/* Read message from kernel */
		recvmsg(sock_fd, &msg, 0);
		process_msg();
	}
	free(nlh);
	close(sock_fd);
}

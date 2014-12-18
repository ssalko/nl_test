#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

#define DEVICE_FILE "/dev/nl_test"

#define MAX_PAYLOAD 1024

enum msg_id_t {
  TEE_REGISTER_SERVER = 1,
  TEE_TEST_SERVER,
  TEE_RESERVED = 0xFFFF,
};

struct tee_msg {
  enum msg_id_t msg_id;
	uint16_t flags;
  uint32_t msg_data_len;
  char msg_data[MAX_PAYLOAD - 8];
};

enum ioctls_cmds {
  NLTEST_TEST_SERVER = 0,
};

int main() {
	int fd; 
	struct tee_msg msg;
	char msg_buf[] = "testapp: this is a test\n";	
	int ret;

	fd = open(DEVICE_FILE, O_RDWR | O_SYNC);
	if (fd < 0) {
		printf("error opening file\n");
		return -1;
	}

	msg.msg_id = TEE_TEST_SERVER;
	msg.msg_data_len = sizeof(msg_buf);
	memcpy(msg.msg_data, msg_buf, sizeof(msg_buf));

	printf("msgdata: %p %s\n", msg.msg_data, msg.msg_data);
	printf("msg_id: %d\n", msg.msg_id);
	ret = ioctl(fd, NLTEST_TEST_SERVER, (unsigned long)&msg);

	printf("Received from tee server: %s\n", (char*)msg.msg_data);

	close(fd);

	return ret;
}

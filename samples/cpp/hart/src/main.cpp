/*
 * Copyright (c) 2023, Meta
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <iostream>

#include "pthread.h"
#include "mqueue.h"

// #include "appconnector.h"

// template <AppPdu>
// uint16_t AppConnector<AppPdu>::getStats(uint16_t &stxs, uint16_t &acks, uint16_t &baks)
// {
// 	return 0;
// }

// int signal(int signum, sighandler_t handler)
// {
// 	return 0;
// }

// int raise(int sig)
// {
// 	return 0;
// }

uint8_t stack1[50];
uint8_t stack2[50];

static char *msg = "hello from thread1";

void* thread1_routine(void *data)
{
	struct mq_attr attrs;

	attrs.mq_msgsize = 19;
	attrs.mq_maxmsg = 10;

	mqd_t queue = mq_open("mqueue1", O_CREAT | O_WRONLY, 777, &attrs);
	std::cout << "Hello from Thread 1\n";

	mq_send(queue, msg, 19, 0);

	return NULL;
}

void* thread2_routine(void *data)
{
	int ret;
	char msg_buffer[19];
	struct mq_attr attrs;

	attrs.mq_msgsize = 19;
	attrs.mq_maxmsg = 10;

	mqd_t queue = mq_open("mqueue1", O_CREAT | O_RDONLY, 777, &attrs);
	printf("mq_open ret %d %d\n", queue);
	std::cout << "Hello from Thread 2\n";
	ret = mq_receive(queue, msg_buffer, 19, 0);
	printf("MQUEUE recv (%d -> %d): %s\n", ret, errno, msg_buffer);

	return NULL;
}

int main(void)
{
	pthread_t thread1;
	pthread_t thread2;
	int ret;

	ret = pthread_create(&thread1, NULL, &thread1_routine, NULL);
	ret = pthread_create(&thread2, NULL, &thread2_routine, NULL);

	printf("Thread 1 0x%X, thread 2 0x%X\n", thread1, thread2);
	std::cout << "Hello, C++ world! " << CONFIG_BOARD << std::endl;

	while (1){
		k_sleep(K_MSEC(10));
	}

	return 0;
}

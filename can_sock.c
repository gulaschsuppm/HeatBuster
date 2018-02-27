#include "can_sock.h"
#include <stdbool.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/error.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int fd;

bool can_setup (int32_t CANbaseAddress, uint8_t nodeId, uint16_t bitRate)
{
	bool ret = true;

	struct sockaddr_can sockAddr;
	struct can_filter* filter;

    /* Create and bind socket */
    fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);

    if(fd < 0)
    {
    	printf("Couldn_t open socket.\n");
        ret = false;
    }
    else
    {
        sockAddr.can_family = AF_CAN;
        sockAddr.can_ifindex = CANbaseAddress;
        if(bind(fd, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) != 0)
        {
        	printf("Couldn't bind CAN.\n");
        	ret = false;
        }
    }

    /* allocate memory for filter array */
    if(ret == true)
    {
        filter = (struct can_filter *) calloc(1, sizeof(struct can_filter));
        if(filter == NULL)
        {
            ret = false;
        }
    }

	/* Additional check. */
	if(ret == true && filter == NULL)
	{
		ret = false;
	}

	printf("Can should be set up.\n");

//	/* close CAN module filters for now. */
//	if(ret == true)
//	{
//	setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);
//	}

	return ret;
}

int can_read_blocking(uint8_t* buffer, size_t buffer_len)
{
	struct can_frame msg;
	int n, size;

    /* Read socket and pre-process message */
    size = sizeof(struct can_frame);
    n = read(fd, &msg, size);

    if (msg.can_dlc <= buffer_len)
    {
    	memcpy(buffer, msg.data, msg.can_dlc);
    }
    else
    {
    	printf("Buffer too small for msg length %d\n", msg.can_dlc);
    }

    return msg.can_dlc;
}

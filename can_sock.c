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
#include <errno.h>

#include <azure_c_shared_utility/xlogging.h>

#define MAX_CAN_NODES	6

static int fd;

static uint8_t can_id_table[MAX_CAN_NODES];
static uint8_t num_of_nodes = 0;
static uint8_t node_id;
struct can_filter* filter;

bool can_setup (int32_t CANbaseAddress, uint8_t nodeId, uint16_t bitRate, uint8_t* node_table, size_t node_table_length)
{
	bool ret = true;

	struct sockaddr_can sockAddr;

	if (node_table_length <= MAX_CAN_NODES)
	{
		memcpy(can_id_table, node_table, node_table_length);
		node_id = nodeId;
		num_of_nodes = node_table_length;
	}
	else
	{
		LogError("Node table too long.");
		ret = false;
	}

	if (ret == true)
	{
		/* Create and bind socket */
		fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
	}

    if(ret == false || fd < 0)
    {
    	LogError("Couldn_t open socket.");
        ret = false;
    }
    else
    {
        sockAddr.can_family = AF_CAN;
        sockAddr.can_ifindex = CANbaseAddress;
        if(bind(fd, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) != 0)
        {
        	LogError("Couldn't bind CAN.");
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
	else if (filter != NULL)
	{
		filter->can_id = nodeId;
		filter->can_mask = nodeId;
	}

    if(setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, filter, sizeof(struct can_filter)) != 0)
    //if(setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0) != 0)
    {
    	ret = false;
    }

    if (ret != false)
    {
    	LogInfo("Can should be set up.");
    }

	return ret;
}

void can_shutdown(void)
{
    close(fd);
    free(filter);
    filter = NULL;
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
    	LogError("Buffer too small for msg length %d.", msg.can_dlc);
    }

    return msg.can_dlc;
}

int can_write(uint8_t* buffer, size_t buffer_len)
{
	static int can_id_idx = 0;

	struct can_frame msg;
	struct canfd_frame msg1;

	/* Early exit if buffer is too big. */
	if (buffer_len > sizeof(msg.data))
	{
		LogError("Buffer too long for CAN frame.");
		return 0;
	}

	msg.can_id = can_id_table[can_id_idx];
	can_id_idx = (can_id_idx + 1) % MAX_CAN_NODES;
	msg.can_dlc = buffer_len;
	memcpy(msg.data, buffer, buffer_len);

    size_t count = sizeof(msg);

    char print_temp[9] = {0};
    memcpy(print_temp, msg.data, buffer_len);
	LogInfo("Trying to write CAN data %s to node %d.", print_temp, msg.can_id);

    int n = write(fd, &msg, count);

    if (n < 0)
    {
    	int error = errno;
    	LogError("CAN write failed with %d.", error);
    }

    if (n != count)
    {
    	LogError("Could not send all bytes %d %d.", count, n);
    }
    else
    {
    	LogInfo("CAN message sent.");
    }

    return n;
}

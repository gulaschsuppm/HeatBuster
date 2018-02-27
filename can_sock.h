#ifndef CAN_H_
#define CAN_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

bool can_setup(int32_t CANbaseAddress, uint8_t nodeId, uint16_t bitRate);

int can_read_blocking(uint8_t* buffer, size_t buffer_len);

#endif /* CAN_H_ */

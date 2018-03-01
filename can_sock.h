#ifndef CAN_H_
#define CAN_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

bool can_setup (int32_t CANbaseAddress, uint8_t nodeId, uint16_t bitRate, uint8_t* node_table, size_t node_table_length);
void can_shutdown(void);

int can_write(uint8_t* buffer, size_t buffer_len);
int can_read(uint8_t* buffer, size_t buffer_len);
int can_read_blocking(uint8_t* buffer, size_t buffer_len);

#endif /* CAN_H_ */

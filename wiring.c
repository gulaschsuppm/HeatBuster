/*
* IoT Hub Raspberry Pi C - Microsoft Sample Code - Copyright (c) 2017 - Licensed MIT
*/
#include "./wiring.h"
#include <stdint.h>
#include <string.h>

#include <azure_c_shared_utility/xlogging.h>

static unsigned int BMEInitMark = 0;

#if SIMULATED_DATA
float random(int min, int max)
{
    int range = (int)(rand()) % (100 * (max - min));
    return min + (float)range / 100;
}

int readMessage(int messageId, char *payload)
{
	char temperature_buf[5];
	char humidity_buf[5];
    int ret =1;
	uint8_t buffer[8];

	int bytes = can_read(buffer, sizeof(buffer));
    
    if(bytes != (int)NULL)
    {
        if (bytes == sizeof(buffer))
        {
            memcpy(temperature_buf, buffer, 4);
            temperature_buf[4] = '\0';
            memcpy(humidity_buf, buffer + 4, 4);
            humidity_buf[4] = '\0';
        }

        LogInfo("CAN message received.");

        snprintf(payload,
                BUFFER_SIZE,
                "{ \"deviceId\": \"Raspberry Pi - C\", \"messageId\": %d, \"temperature\": %s, \"humidity\": %s }",
                messageId,
                temperature_buf,
                humidity_buf);
        float temperature;

        sscanf(temperature_buf, "%f", &temperature);
        ret = (temperature > TEMPERATURE_ALERT) ? 1 : 0;
    }else
    {
        ret = -1;
    }

    return ret;
}

#else
int mask_check(int check, int mask)
{
    return (check & mask) == mask;
}

// check whether the BMEInitMark's corresponding mark bit is set, if not, try to invoke corresponding init()
int check_bme_init()
{
    // wiringPiSetup == 0 is successful
    if (mask_check(BMEInitMark, WIRINGPI_SETUP) != 1 && wiringPiSetup() != 0)
    {
        return -1;
    }
    BMEInitMark |= WIRINGPI_SETUP;

    // wiringPiSetup < 0 means error
    if (mask_check(BMEInitMark, SPI_SETUP) != 1 && wiringPiSPISetup(SPI_CHANNEL, SPI_CLOCK) < 0)
    {
        return -1;
    }
    BMEInitMark |= SPI_SETUP;

    // bme280_init == 1 is successful
    if (mask_check(BMEInitMark, BME_INIT) != 1 && bme280_init(SPI_CHANNEL) != 1)
    {
        return -1;
    }
    BMEInitMark |= BME_INIT;
    return 1;
}

// check the BMEInitMark value is equal to the (WIRINGPI_SETUP | SPI_SETUP | BME_INIT)

int readMessage(int messageId, char *payload)
{
    if (check_bme_init() != 1)
    {
        // setup failed
        return -1;
    }

    float temperature, humidity, pressure;
    if (bme280_read_sensors(&temperature, &pressure, &humidity) != 1)
    {
        return -1;
    }

    snprintf(payload,
             BUFFER_SIZE,
             "{ \"deviceId\": \"Raspberry Pi - C\", \"messageId\": %d, \"temperature\": %f, \"humidity\": %f }",
             messageId,
             temperature,
             humidity);
    return temperature > TEMPERATURE_ALERT ? 1 : 0;
}
#endif

void setLED(int state)
{
	if (state == 0)
	{
		digitalWrite(LED_PIN, LOW);
	}
	else
	{
		digitalWrite(LED_PIN, HIGH);
	}
}

void setupWiring()
{
    if (wiringPiSetup() == 0)
    {
        BMEInitMark |= WIRINGPI_SETUP;
    }
    pinMode(LED_PIN, OUTPUT);
}

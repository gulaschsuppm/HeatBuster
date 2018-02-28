/*
* IoT Hub Raspberry Pi C - Microsoft Sample Code - Copyright (c) 2017 - Licensed MIT
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <azure_c_shared_utility/xlogging.h>
#include <azure_c_shared_utility/platform.h>
#include <azure_c_shared_utility/threadapi.h>
#include <azure_c_shared_utility/crt_abstractions.h>
#include <iothub_client.h>
#include <iothub_service_client_auth.h>
#include <iothub_registrymanager.h>
#include <iothub_client_options.h>
#include <iothub_message.h>
#include <iothubtransportmqtt.h>
#include <jsondecoder.h>
#include <pthread.h>
#include "./config.h"
#include "./wiring.h"
#include "./telemetry.h"
#include "can_sock.h"
#include <signal.h>
#include <net/if.h>

const char *onSuccess = "\"Successfully invoke device method\"";
const char *notFound = "\"No method found\"";

static bool messagePending = false;

static int interval = INTERVAL;

static const char *EVENT_SUCCESS = "success";
static const char *EVENT_FAILED = "failed";

pthread_t thread;
pthread_t can_send_thread;

static void sendCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void *userContextCallback)
{
    if (IOTHUB_CLIENT_CONFIRMATION_OK != result)
    {
        LogError("Failed to send message to Azure IoT Hub");
    }

    messagePending = false;
}

static void sendMessages(IOTHUB_CLIENT_LL_HANDLE iotHubClientHandle, char *buffer, int temperatureAlert)
{
    IOTHUB_MESSAGE_HANDLE messageHandle = IoTHubMessage_CreateFromByteArray(buffer, strlen(buffer));
    if (messageHandle == NULL)
    {
        LogError("Unable to create a new IoTHubMessage");
    }
    else
    {
        MAP_HANDLE properties = IoTHubMessage_Properties(messageHandle);
        Map_Add(properties, "temperatureAlert", (temperatureAlert > 0) ? "true" : "false");
        LogInfo("Sending message: %s", buffer);
        if (IoTHubClient_LL_SendEventAsync(iotHubClientHandle, messageHandle, sendCallback, NULL) != IOTHUB_CLIENT_OK)
        {
            LogError("Failed to send message to Azure IoT Hub");
        }
        else
        {
            messagePending = true;
            LogInfo("Message sent to Azure IoT Hub");
        }

        IoTHubMessage_Destroy(messageHandle);
    }
}

static char *get_device_id(char *str)
{
    char *substr = strstr(str, "DeviceId=");

    if (substr == NULL)
        return NULL;

    // skip "DeviceId="
    substr += 9;

    char *semicolon = strstr(substr, ";");
    int length = semicolon == NULL ? strlen(substr) : semicolon - substr;
    char *device_id = calloc(1, length + 1);
    memcpy(device_id, substr, length);
    device_id[length] = '\0';

    return device_id;
}

void toggleLED(void)
{
	static uint8_t count = 0;

	setLED(count++ % 2);
}

int deviceMethodCallback(
    const char *methodName,
    const unsigned char *payload,
    size_t size,
    unsigned char **response,
    size_t *response_size,
    void *userContextCallback)
{
    LogInfo("Try to invoke method %s\r\n", methodName);
    const char *responseMessage = onSuccess;
    int result = 200;

    if (strcmp(methodName, "toggleLED") == 0)
    {
    	toggleLED();
    }
    else
    {
        LogError("No method %s found\r\n", methodName);
        responseMessage = notFound;
        result = 404;
    }

    *response_size = strlen(responseMessage);
    *response = (unsigned char *)malloc(*response_size);
    strncpy((char *)(*response), responseMessage, *response_size);

    return result;
}

void twinCallback(
    DEVICE_TWIN_UPDATE_STATE updateState,
    const unsigned char *payLoad,
    size_t size,
    void *userContextCallback)
{
    char *temp = (char *)malloc(size + 1);
    for (int i = 0; i < size; i++)
    {
        temp[i] = (char)(payLoad[i]);
    }
    temp[size] = '\0';
    MULTITREE_HANDLE tree = NULL;

    if (JSON_DECODER_OK == JSONDecoder_JSON_To_MultiTree(temp, &tree))
    {
        MULTITREE_HANDLE child = NULL;

        if (MULTITREE_OK != MultiTree_GetChildByName(tree, "desired", &child))
        {
            LogInfo("This device twin message contains desired message only");
            child = tree;
        }
        const void *value = NULL;
        if (MULTITREE_OK == MultiTree_GetLeafValue(child, "interval", &value))
        {
            interval = atoi((const char *)value);
            LogInfo("Changing interval to %d.", interval);
        }
    }
    MultiTree_Destroy(tree);
    free(temp);
}

IOTHUBMESSAGE_DISPOSITION_RESULT receiveMessageCallback(IOTHUB_MESSAGE_HANDLE message, void *userContextCallback)
{
    const unsigned char *buffer = NULL;
    size_t size = 0;

    if (IOTHUB_MESSAGE_OK != IoTHubMessage_GetByteArray(message, &buffer, &size))
    {
        return IOTHUBMESSAGE_ABANDONED;
    }

    // message needs to be converted to zero terminated string
    char *temp = (char *)malloc(size + 1);

    if (temp == NULL)
    {
        return IOTHUBMESSAGE_ABANDONED;
    }

    strncpy(temp, buffer, size);
    temp[size] = '\0';

    (void)printf("Receiving message: %s\r\n", temp);
    free(temp);

    return IOTHUBMESSAGE_ACCEPTED;
}

static char *readFile(char *fileName)
{
    FILE *fp;
    int size;
    char *buffer;

    fp = fopen(fileName, "rb");

    if (fp == NULL)
    {
        LogError("ERROR: File %s doesn't exist!", fileName);
        return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    // Allocate memory for entire content
    buffer = calloc(1, size + 1);

    if (buffer == NULL)
    {
        fclose(fp);
        LogError("ERROR: Failed to allocate memory.");
        return NULL;
    }

    // Read the file into the buffer
    if (1 != fread(buffer, size, 1, fp))
    {
        fclose(fp);
        free(buffer);
        LogError("ERROR: Failed to read the file %s into memory.", fileName);
        return NULL;
    }

    fclose(fp);

    return buffer;
}

static bool setX509Certificate(IOTHUB_CLIENT_LL_HANDLE iotHubClientHandle, char *deviceId)
{
    char certName[256];
    char keyName[256];
    char cwd[1024];

    snprintf(certName, sizeof(certName), "%s/%s-cert.pem", CREDENTIAL_PATH, deviceId);
    snprintf(keyName, sizeof(keyName), "%s/%s-key.pem", CREDENTIAL_PATH, deviceId);

    char *x509certificate = readFile(certName);
    char *x509privatekey = readFile(keyName);

    if (x509certificate == NULL ||
        x509privatekey == NULL ||
        IoTHubClient_LL_SetOption(iotHubClientHandle, OPTION_X509_CERT, x509certificate) != IOTHUB_CLIENT_OK ||
        IoTHubClient_LL_SetOption(iotHubClientHandle, OPTION_X509_PRIVATE_KEY, x509privatekey) != IOTHUB_CLIENT_OK)
    {
        LogError("Failed to set options for x509.");
        return false;
    }

    free(x509certificate);
    free(x509privatekey);

    return true;
}

char *parse_iothub_name(char *connectionString)
{
    if (connectionString == NULL)
    {
        return NULL;
    }

    char *hostName = strtok(connectionString, ".");
    int prefixLen = strlen("HostName=");
    int len = strlen(hostName) - prefixLen + 1;
    char *iotHubName = (char *)malloc(len);
    if (iotHubName == NULL)
    {
        return NULL;
    }
    memcpy(iotHubName, hostName + prefixLen, len - 1);
    iotHubName[len - 1] = '\0';
    return iotHubName;
}

typedef struct AIParams
{
    char *iotHubName;
    const char *event;
    const char *message;
} AIParams;

void *send_ai(void *argv)
{
    AIParams *params = argv;
    send_telemetry_data(params->iotHubName, params->event, params->message);
    free(params->iotHubName);
    free(params);
}

void *send_telemetry_data_multi_thread(char *iotHubName, const char *eventName, const char *message)
{
    AIParams *params = malloc(sizeof(AIParams));
    if (params != NULL)
    {
        params->iotHubName = iotHubName;
        params->event = eventName;
        params->message = message;
        pthread_create(&thread, NULL, send_ai, (void *)params);
    }
    else
    {
        free(iotHubName);
    }
}

static bool run_thread = true;

void *can_thread(void *argv)
{
	uint8_t data[9];
	float temp;

	while (run_thread)
	{
		sleep(30);
		temp = random(0, 99);
		snprintf(data, sizeof(data), "%2.4f", temp);
		temp = random(0, 99);
		snprintf(data + 4, sizeof(data) - 4, "%2.4f", temp);
		int count = can_write(data, 8);
	}
}

void close_thread(int sig)
{
	LogInfo("CTRL-C received, closed thread.");
	run_thread = false;
	pthread_join(can_send_thread, NULL);
}

void printDeviceInfo(IOTHUB_DEVICE* device, int orderNum)
{
    if ((device != NULL) && (device->deviceId != NULL))
    {
        if (orderNum >= 0)
        {
            (void)printf("Device(%d)\r\n", orderNum);
        }
        else
        {
            (void)printf("Device\r\n");
        }
        (void)printf("    deviceId                    : %s\r\n", device->deviceId);
        (void)printf("    primaryKey                  : %s\r\n", device->primaryKey);
        (void)printf("    secondaryKey                : %s\r\n", device->secondaryKey);
        (void)printf("    generationId                : %s\r\n", device->generationId);
        (void)printf("    eTag                        : %s\r\n", device->eTag);
        (void)printf("    authMethod                  : %d\r\n", device->authMethod);
        if (device->connectionState == IOTHUB_DEVICE_CONNECTION_STATE_CONNECTED)
        {
            (void)printf("    connectionState             : Connected\r\n");
        }
        else
        {
            (void)printf("    connectionState             : Disconnected\r\n");
        }
        (void)printf("    connectionStateUpdatedTime  : %s\r\n", device->eTag);
        if (device->status == IOTHUB_DEVICE_STATUS_ENABLED)
        {
            (void)printf("    status                      : Enabled\r\n");
        }
        else
        {
            (void)printf("    status                      : Disabled\r\n");
        }
        (void)printf("    statusReason                : %s\r\n", device->statusReason);
        (void)printf("    statusUpdatedTime           : %s\r\n", device->statusUpdatedTime);
        (void)printf("    lastActivityTime            : %s\r\n", device->lastActivityTime);
        (void)printf("    cloudToDeviceMessageCount   : %zu\r\n", device->cloudToDeviceMessageCount);
    }
}

int register_device(char* iot_hub_connection_string, char* deviceId, char* connection_string, size_t connection_string_len)
{
	int ret = 0;

    IOTHUB_REGISTRYMANAGER_RESULT result;

    IOTHUB_REGISTRY_DEVICE_CREATE deviceCreateInfo;
    IOTHUB_REGISTRY_DEVICE_UPDATE deviceUpdateInfo;

    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iotHubServiceClientHandle = IoTHubServiceClientAuth_CreateFromConnectionString(iot_hub_connection_string);
    if (iotHubServiceClientHandle == NULL)
    {
        (void)printf("IoTHubServiceClientAuth_CreateFromConnectionString failed\r\n");
        ret = 1;
    }
    else
    {
		IOTHUB_REGISTRYMANAGER_HANDLE iotHubRegistryManagerHandle = NULL;
		IOTHUB_DEVICE deviceInfo;
		IOTHUB_REGISTRY_STATISTICS registryStatistics;

		(void)printf("iotHubServiceClientHandle has been created successfully\r\n");
		(void)printf("Creating RegistryManager...\r\n");

		iotHubRegistryManagerHandle = IoTHubRegistryManager_Create(iotHubServiceClientHandle);

		(void)printf("RegistryManager has been created successfully\r\n");

		deviceCreateInfo.deviceId = deviceId;
		deviceCreateInfo.primaryKey = "";
		deviceCreateInfo.secondaryKey = "";
		deviceCreateInfo.authMethod = IOTHUB_REGISTRYMANAGER_AUTH_SPK;

		// Create device
		result = IoTHubRegistryManager_CreateDevice(iotHubRegistryManagerHandle, &deviceCreateInfo, &deviceInfo);
		switch (result)
		{
		case IOTHUB_REGISTRYMANAGER_OK:
			(void)printf("IoTHubRegistryManager_CreateDevice: Device has been created successfully: deviceId=%s\r\n", deviceInfo.deviceId);
			break;
		case IOTHUB_REGISTRYMANAGER_DEVICE_EXIST:
			(void)printf("IoTHubRegistryManager_CreateDevice: Device already exists\r\n");
			break;
		case IOTHUB_REGISTRYMANAGER_ERROR:
			(void)printf("IoTHubRegistryManager_CreateDevice failed\r\n");
			ret = 1;
			break;
		default:
			(void)printf("IoTHubRegistryManager_CreateDevice failed with unknown error\r\n");
			ret = 1;
			break;
		}

		if (ret == 0)
		{
			result = IoTHubRegistryManager_GetDevice(iotHubRegistryManagerHandle, deviceCreateInfo.deviceId, &deviceInfo);
			switch (result)
			{
			case IOTHUB_REGISTRYMANAGER_OK:
				(void)printf("IoTHubRegistryManager_GetDevice: Successfully got device info: deviceId=%s\r\n", deviceInfo.deviceId);
				printDeviceInfo(&deviceInfo, -1);
				break;
			case IOTHUB_REGISTRYMANAGER_ERROR:
				(void)printf("IoTHubRegistryManager_GetDevice failed\r\n");
				ret = 1;
				break;
			default:
				(void)printf("IoTHubRegistryManager_GetDevice failed with unknown error\r\n");
				ret = 1;
				break;
			}
		}

		if (ret == 0)
		{
			sprintf(connection_string, "HostName=%s;DeviceId=%s;SharedAccessKey=%s", iotHubServiceClientHandle->hostname, deviceInfo.deviceId, deviceInfo.primaryKey);
		}
    }

    return ret;
}

int main(int argc, char *argv[])
{
    initial_telemetry();
    if (argc < 6)
    {
        LogError("Usage: %s <IoT hub connection string> <device_id> <can_if> <can_id> <node_ids>", argv[0]);
        send_telemetry_data(NULL, EVENT_FAILED, "Device connection string is not provided");
        return 1;
    }

	signal(SIGINT, close_thread);

	uint8_t can_table[] = {0x00, 0x01};

	int index = if_nametoindex(argv[3]);
	uint8_t can_id = atoi(argv[4]);
	sscanf(argv[5], "%d %d", &can_table[0], &can_table[1]);

	LogInfo("%s index %d, Node ID %d, Nodes %d %d.", argv[3], index, can_id, can_table[0], can_table[1]);
	/* Setup CAN. */
	if (!can_setup(index, can_id, 125, can_table, sizeof(can_table)))
	{
		LogError("Could not setup CAN.");
		return 1;
	}

	if (0 != pthread_create(&can_send_thread, NULL, can_thread, NULL))
	{
		LogError("CAN send thread could not be created.");
		return 1;
	}

    setupWiring();

    if (platform_init() != 0)
    {
        LogError("Failed to initialize the platform.");
        send_telemetry_data(NULL, EVENT_FAILED, "Failed to initialize the platform.");
    }
    else
    {
		char connection_string[256] = {0};
		LogInfo("Trying to register %s with connection string %s.", argv[2], argv[1]);
		if (0 != register_device(argv[1], argv[2], connection_string, sizeof(connection_string)))
		{
			LogError("Cannot parse device id from IoT device connection string");
			send_telemetry_data(NULL, EVENT_FAILED, "Cannot parse device id from connection string");
			pthread_join(thread, NULL);
			return 1;
		}
		else
		{
			LogInfo("Device connection string: %s.\n", connection_string);
		    IOTHUB_CLIENT_LL_HANDLE iotHubClientHandle;

		    if ((iotHubClientHandle = IoTHubClient_LL_CreateFromConnectionString(connection_string, MQTT_Protocol)) == NULL)
			{
				LogError("iotHubClientHandle is NULL!");
				send_telemetry_data(NULL, EVENT_FAILED, "Cannot create iotHubClientHandle");
			}
			else
			{
				if (strstr(argv[1], "x509=true") != NULL)
				{
					// Use X.509 certificate authentication.
					if (!setX509Certificate(iotHubClientHandle, argv[2]))
					{
						send_telemetry_data(NULL, EVENT_FAILED, "Certificate is not right");
						return 1;
					}
				}

				// set C2D and device method callback
				IoTHubClient_LL_SetMessageCallback(iotHubClientHandle, receiveMessageCallback, NULL);
				IoTHubClient_LL_SetDeviceMethodCallback(iotHubClientHandle, deviceMethodCallback, NULL);
				IoTHubClient_LL_SetDeviceTwinCallback(iotHubClientHandle, twinCallback, NULL);

				IoTHubClient_LL_SetOption(iotHubClientHandle, "product_info", "HappyPath_RaspberryPi-C");

				char *iotHubName = parse_iothub_name(argv[1]);
				send_telemetry_data_multi_thread(iotHubName, EVENT_SUCCESS, "IoT hub connection is established");
				int count = 0;
				while (run_thread)
				{
					if (!messagePending)
					{
						++count;
						char buffer[BUFFER_SIZE];
						if (buffer != NULL)
						{
							int result = readMessage(count, buffer);
							if (result != -1)
							{
								sendMessages(iotHubClientHandle, buffer, result);
							}
							else
							{
								LogError("Failed to read message");
							}
						}
						delay(interval);
					}
					IoTHubClient_LL_DoWork(iotHubClientHandle);
				}

				can_shutdown();
				IoTHubClient_LL_Destroy(iotHubClientHandle);
			}
			platform_deinit();
		}
    }

    return 0;
}

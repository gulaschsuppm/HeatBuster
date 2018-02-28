#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  set (CMAKE_C_FLAGS "--std=c99 -g ${CMAKE_C_FLAGS}")
endif()

include_directories("/usr/local/include/azureiot"
                    "/usr/local/include/azureiot/inc/"
                    "/usr/local/include/iothub_service_client")

set(SOURCE main.c bme280.c wiring.c telemetry.c can_sock.c config.h bme280.h wiring.h telemetry.h can_sock.h)
add_executable(app ${SOURCE})
target_link_libraries(app wiringPi
                          serializer
                          iothub_client
                          iothub_service_client
                          iothub_client_mqtt_transport
                          umqtt
                          aziotsharedutil
                          ssl
                          crypto
                          curl
                          pthread
                          m
                          ssl
                          crypto)


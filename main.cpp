/* mbed Microcontroller Library
 * Copyright (c) 2017 u-blox
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#define MBED_AUTH_AND_UPD_TCP_EXAMPLE 1
#define MBED_CELLULAR_UBLOX_TCP_UDP_ECHO_APPLICATION 0
#define MBED_CELLULAR_UBLOX_UDP_NTP_APPLICATION 0
#define MBED_CELLULAR_EXAMPLE 0

#if MBED_AUTH_AND_UPD_TCP_EXAMPLE

#include "mbed.h"
#include "CellularContext.h"
#include "mbed-trace/mbed_trace.h"

#define UDP_SERVER "2.pool.ntp.org"
#define TCP_SERVER "52.215.34.155"
#define UDP_PORT 123

static	CellularContext *ctx;

static void printNtpTime(char * buf, int len)
{
    time_t timestamp = 0;
    struct tm *localTime;
    char timeString[25];
    time_t TIME1970 = 2208988800U;

    if (len >= 43) {
        timestamp |= ((int) *(buf + 40)) << 24;
        timestamp |= ((int) *(buf + 41)) << 16;
        timestamp |= ((int) *(buf + 42)) << 8;
        timestamp |= ((int) *(buf + 43));
        timestamp -= TIME1970;
        localTime = localtime(&timestamp);
        if (localTime) {
            if (strftime(timeString, sizeof(timeString), "%a %b %d %H:%M:%S %Y", localTime) > 0) {
                printf("NTP timestamp is %s.\n", timeString);
            }
        }
    }
}

/**
 * Opens a UDP or a TCP socket with the given echo server and performs an echo
 * transaction retrieving current.
 */
nsapi_error_t udp_tcp_echo()
{
    nsapi_size_or_error_t retcode;
    const char *host_name = MBED_CONF_APP_ECHO_SERVER_HOSTNAME;
    const int port = MBED_CONF_APP_ECHO_SERVER_PORT;

#if MBED_CONF_APP_SOCK_TYPE == TCP
    TCPSocket sock;
#else
    UDPSocket sock;
#endif

    retcode = sock.open(ctx);
    if (retcode != NSAPI_ERROR_OK) {
#if MBED_CONF_APP_SOCK_TYPE == TCP
        printf("TCPSocket.open() fails, code: %d\n", retcode);
#else
        printf("UDPSocket.open() fails, code: %d\n", retcode);
#endif
        return -1;
    }

    SocketAddress sock_addr;
    retcode = ctx->gethostbyname("52.215.34.155", &sock_addr);
    if (retcode != NSAPI_ERROR_OK) {
        printf("Couldn't resolve remote host: %s, code: %d\n", host_name, retcode);
        return -1;
    }

    sock_addr.set_port(port);
    sock.set_timeout(15000);
    int n = 0;
    const char *echo_string = "TEST";
    char recv_buf[4];
#if MBED_CONF_APP_SOCK_TYPE == TCP
    retcode = sock.connect(sock_addr);
    if (retcode < 0) {
        printf("TCPSocket.connect() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("TCP: connected with %s server\n", host_name);
    }
    retcode = sock.send((void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        printf("TCPSocket.send() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("TCP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recv((void*) recv_buf, sizeof(recv_buf));
#else

    retcode = sock.sendto(sock_addr, (void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        printf("UDPSocket.sendto() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("UDP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recvfrom(&sock_addr, (void*) recv_buf, sizeof(recv_buf));
#endif

    sock.close();

    if (n > 0) {
        printf("Received from echo server %d Bytes\n", n);
        return 0;
    }

    return -1;
}

int get_ntp_time()
{
    int x;
    char buf[1024];
    UDPSocket sockUdp;
    SocketAddress udpServer;
    SocketAddress udpSenderAddress;
    nsapi_size_or_error_t retcode;

    retcode = ctx->gethostbyname(UDP_SERVER, &udpServer);
    if (retcode != NSAPI_ERROR_OK) {
        printf("Couldn't resolve remote host: %s, code: %d\n", UDP_SERVER, retcode);
        return -1;
    }

    udpServer.set_port(UDP_PORT);
	printf("Opening a UDP socket...\n");
	if (sockUdp.open(ctx) == 0) {
		printf("UDP socket open.\n");
		sockUdp.set_timeout(10000);
		printf("Sending time request to \"2.pool.ntp.org\" over UDP socket...\n");
		memset (buf, 0, sizeof(buf));
		*buf = '\x1b';
		if (sockUdp.sendto(udpServer, (void *) buf, 48) == 48) {
			printf("Socket send completed, waiting for UDP response...\n");
			x = sockUdp.recvfrom(&udpSenderAddress, buf, sizeof (buf));
			if (x > 0) {
				printf("Received %d byte response from server %s on UDP socket:\n"
					   "-------------------------------------------------------\n",
					   x, udpSenderAddress.get_ip_address());
				printNtpTime(buf, x);
				printf("-------------------------------------------------------\n");
			}
		}

		printf("Closing socket...\n");
		sockUdp.close();
		printf("Socket closed.\n");
	}
}


int main()
{
#if MBED_CONF_MBED_TRACE_ENABLE
     mbed_trace_init();
#endif

    ctx = CellularContext::get_default_instance();

    ctx->set_sim_pin(MBED_CONF_APP_CELLULAR_SIM_PIN);
#ifdef MBED_CONF_APP_APN
    ctx->set_credentials(MBED_CONF_APP_APN);
#endif

    // Set Auth type
    ctx->set_authentication_type(CellularContext::CHAP);

    if (ctx->connect() != NSAPI_ERROR_OK) {
        printf("Connection failed\n");
    	return -1;
    }

    printf("Connection established\n");
    while (1) {
    	get_ntp_time();

		udp_tcp_echo();

        wait_ms(1000);
    }
}


#endif



#if MBED_CELLULAR_UBLOX_TCP_UDP_ECHO_APPLICATION
/* mbed Microcontroller Library
 * Copyright (c) 2017 u-blox
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
//#include "CellularTargets.h"
#include "mbed-trace/mbed_trace.h"


/*
 * UDP/TCP Appliaction main
 */

int main()
{
#if MBED_CONF_MBED_TRACE_ENABLE
     mbed_trace_init();
#endif

	NetworkInterface *interface = NetworkInterface::get_default_instance();

    UDPSocket sockUdp;
    SocketAddress udpServer;

    TCPSocket sockTcp;
    SocketAddress tcpServer;

    int x;

    static const char send_buffer[]= "_____0000:0123456789012345678901234567890123456789"
    								"01234567890123456789012345678901234567890123456789"
                                     "_____0100:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0200:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0300:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0400:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
    								 /*"_____0500:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0600:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0700:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0800:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____0900:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1000:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1100:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1200:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1300:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1400:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1500:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1600:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1700:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1800:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____1900:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"
                                     "_____2000:0123456789012345678901234567890123456789"
                                     "01234567890123456789012345678901234567890123456789"*/;


    printf("Starting up, please wait up to 180 seconds for network registration to complete...\n");
    //interface->set_credentials(APN, USERNAME, PASSWORD);
    for (x = 0; interface->connect() != 0; x++) {
        if (x > 0) {
            printf("Retrying (have you checked that an antenna is plugged in and your APN is correct?)...\n");
        }
    }

    if ((interface->gethostbyname("52.215.34.155", &udpServer) == 0) &&
    	(interface->gethostbyname("52.215.34.155", &tcpServer) == 0)) {
        udpServer.set_port(7);
        tcpServer.set_port(7);
        printf("UDP: IP address: %s on port %d.\n", udpServer.get_ip_address(), udpServer.get_port());
        printf("TCP: IP address: %s on port %d.\n", tcpServer.get_ip_address(), tcpServer.get_port());

        printf("Performing socket operations in a loop ...\n");
		while (1) {
            if (interface->get_connection_status()) {
                printf("Connection established\n");

				// UDP Socket Operation
				printf("=== UDP ===\n");
				printf("Opening a UDP socket...\n");
				if (sockUdp.open(interface) == 0) {
					printf("UDP socket opened.\n");
					sockUdp.set_timeout(10000);
					sockUdp.bind(4023);

					printf("Sending data on UDP Echo server, Data: %s, length: %d\n",(char *)send_buffer, strlen(send_buffer));
					//int len = sockUdp.sendto(udpServer,(void *) send_buffer, sizeof(send_buffer));
					if (sockUdp.sendto(udpServer,(void *) send_buffer, strlen(send_buffer)) == strlen(send_buffer)) {
						char rec_buf[(strlen(send_buffer))*2+1];
						wait_ms(1000);
						printf("Socket send completed, waiting for UDP response...\n");
						x = sockUdp.recvfrom(&udpServer,(char *) rec_buf, strlen(send_buffer)*2+1);

						printf("UDP Data Received: %s, size: %d\r\n", rec_buf, x);

						memset(rec_buf, 0, strlen(rec_buf));
					}

					wait_ms(1000);
					printf("Closing UDP socket...\n");
					sockUdp.close();
					printf("UDP Socket closed.\n");
				}
				wait_ms(1000);

				// TCP Socket Operation
				printf("=== TCP ===\n");
				printf("Opening a TCP socket...\n");

				if (sockTcp.open(interface) == 0) {
					printf("TCP socket opened.\n");
					sockTcp.set_timeout(10000);

					printf("Connecting socket to %s on port %d...\n", tcpServer.get_ip_address(), tcpServer.get_port());
					if (sockTcp.connect(tcpServer) == 0) {
						printf("Sending data on TCP Echo server\n");
						if (sockTcp.send((void *) send_buffer, sizeof(send_buffer)) == sizeof(send_buffer)) {
							char rec_buf[sizeof(send_buffer)];
							//wait_ms(1000);
							printf("Socket send completed, waiting for TCP response...\n");
							x = sockTcp.recv((void *) rec_buf, sizeof(rec_buf));

							printf("TCP Data Received: %s, size: %d\r\n",(char *)rec_buf, x);
						}
					}

					wait_ms(5000);
					printf("Closing TCP socket...\n");
					sockTcp.close();
					printf("TCP Socket closed.\n");

				}
			} else {
				printf("Connection Lost\n");
				break;
			}
		}

		interface->disconnect();
		printf("Stopped.\n");
    } else {
        printf("Unable to get IP address\n");
    }

    while (1);
}

// End Of File
#endif



#if MBED_CELLULAR_UBLOX_UDP_NTP_APPLICATION

/* mbed Microcontroller Library
 * Copyright (c) 2017 u-blox
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "mbed-trace/mbed_trace.h"

//#define INTERFACE_CLASS  EasyCellularConnection

// The credentials of the SIM in the board.  If PIN checking is enabled
// for your SIM card you must set this to the required PIN.
#define PIN 		"0000"
#define APN         NULL
#define USERNAME    NULL
#define PASSWORD    NULL

// LEDs
DigitalOut ledRed(LED1, 1);
DigitalOut ledGreen(LED2, 1);
DigitalOut ledBlue(LED3, 1);

// The user button
volatile bool buttonPressed = false;

static void good() {
    ledGreen = 0;
    ledBlue = 1;
    ledRed = 1;
}

static void bad() {
    ledRed = 0;
    ledGreen = 1;
    ledBlue = 1;
}

static void event() {
    ledBlue = 0;
    ledRed = 1;
    ledGreen = 1;
}

static void pulseEvent() {
    event();
    wait_ms(500);
    good();
}

static void ledOff() {
    ledBlue = 1;
    ledRed = 1;
    ledGreen = 1;
}

static void printNtpTime(char * buf, int len)
{
    time_t timestamp = 0;
    struct tm *localTime;
    char timeString[25];
    time_t TIME1970 = 2208988800U;

    if (len >= 43) {
        timestamp |= ((int) *(buf + 40)) << 24;
        timestamp |= ((int) *(buf + 41)) << 16;
        timestamp |= ((int) *(buf + 42)) << 8;
        timestamp |= ((int) *(buf + 43));
        timestamp -= TIME1970;
        localTime = localtime(&timestamp);
        if (localTime) {
            if (strftime(timeString, sizeof(timeString), "%a %b %d %H:%M:%S %Y", localTime) > 0) {
                printf("NTP timestamp is %s.\n", timeString);
            }
        }
    }
}

static void cbButton()
{
    buttonPressed = true;
    pulseEvent();
}

/* This example program for the u-blox C030 and C027 boards and uses it
 * to make a simple sockets connection to a server, using 2.pool.ntp.org
 * for UDP and developer.mbed.org for TCP.
 * Progress may be monitored with a serial terminal running at 9600 baud.
 * The LED on the C030 board will turn green when this program is
 * operating correctly, pulse blue when a sockets operation is completed
 * and turn red if there is a failure.
 */

int main()
{
#if MBED_CONF_MBED_TRACE_ENABLE
     mbed_trace_init();
#endif

    //INTERFACE_CLASS *interface = new INTERFACE_CLASS(true);
    NetworkInterface *interface = NetworkInterface::get_default_instance();

#ifndef TARGET_UBLOX_C030_N211
    TCPSocket sockTcp;
#endif
    UDPSocket sockUdp;
    SocketAddress udpServer;
    SocketAddress udpSenderAddress;
    SocketAddress tcpServer;
    char buf[1024];

    int x;
#ifdef TARGET_UBLOX_C027
    // No user button on C027
    InterruptIn userButton(NC);
#else
    InterruptIn userButton(SW0);
#endif

    // Attach a function to the user button
    userButton.rise(&cbButton);

    good();
    printf("Starting up, please wait up to 180 seconds for network registration to complete...\n");
    //interface->set_credentials(APN, USERNAME, PASSWORD);
    for (x = 0; interface->connect() != 0; x++) {
        if (x > 0) {
            bad();
            printf("Retrying (have you checked that an antenna is plugged in and your APN is correct?)...\n");
        }
    }
    pulseEvent();

    printf("Getting the IP address of \"developer.mbed.org\" and \"2.pool.ntp.org\"...\n");
    if ((interface->gethostbyname("2.pool.ntp.org", &udpServer) == 0) && //2.pool.ntp.org // 158.69.125.231
        (interface->gethostbyname("developer.mbed.org", &tcpServer) == 0)) {
        pulseEvent();

        udpServer.set_port(123);
        printf("\"2.pool.ntp.org\" address: %s on port %d.\n", udpServer.get_ip_address(), udpServer.get_port());
        //printf("\"developer.mbed.org\" address: %s on port %d.\n", tcpServer.get_ip_address(), tcpServer.get_port());
        tcpServer.set_port(80);

        printf("Performing socket operations in a loop (until the user button is pressed on C030 or forever on C027)...\n");
        while (!buttonPressed) {
            if (interface->get_connection_status()) {
                printf("Connection established\n");
				// UDP Sockets
				printf("=== UDP ===\n");
				printf("Opening a UDP socket...\n");
				if (sockUdp.open(interface) == 0) {
					pulseEvent();
					//sockUdp.bind(4023);
					printf("UDP socket open.\n");
					sockUdp.set_timeout(10000);
					printf("Sending time request to \"2.pool.ntp.org\" over UDP socket...\n");
					memset (buf, 0, sizeof(buf));
					*buf = '\x1b';
					if (sockUdp.sendto(udpServer, (void *) buf, 48) == 48) {
						pulseEvent();
						printf("Socket send completed, waiting for UDP response...\n");
						do {
							x = 0;
							x = sockUdp.recvfrom(&udpSenderAddress, buf, sizeof (buf));
							if (x > 0) {
								pulseEvent();
								printf("Received %d byte response from server %s on UDP socket:\n"
									   "-------------------------------------------------------\n",
									   x, udpSenderAddress.get_ip_address());
								printNtpTime(buf, x);
								printf("-------------------------------------------------------\n");
							}
						} while(x == 0);
					}
					printf("Closing socket...\n");
					sockUdp.close();
					pulseEvent();
					printf("Socket closed.\n");
				}

#ifndef TARGET_UBLOX_C030_N211
				// TCP Sockets
				printf("=== TCP ===\n");
				printf("Opening a TCP socket...\n");
				if (sockTcp.open(interface) == 0) {
					pulseEvent();
					printf("TCP socket open.\n");
					sockTcp.set_timeout(10000);
					printf("Connecting socket to %s on port %d...\n", tcpServer.get_ip_address(), tcpServer.get_port());
					if (sockTcp.connect(tcpServer) == 0) {
						pulseEvent();

						memset (buf, 0, sizeof(buf));
						memset (buf, 0, sizeof(buf));
						printf("Connected, sending HTTP GET request to \"developer.mbed.org\" over socket...\n");
						strcpy (buf, "GET /media/uploads/mbed_official/hello.txt HTTP/1.0\r\n\r\n");
						// Note: since this is a short string we can send it in one go as it will
						// fit within the default buffer sizes.  Normally you should call sock.send()
						// in a loop until your entire buffer has been sent.
						if (sockTcp.send((void *) buf, strlen(buf)) == (int) strlen(buf)) {
							pulseEvent();
							printf("Socket send completed, waiting for response...\n");
							do {
								x = 0;
								x = sockTcp.recv((void *)buf, sizeof (buf));
								if (x > 0) {
									pulseEvent();
									printf("Received %d byte response from server on TCP socket:\n"
										   "----------------------------------------------------\n%.*s"
										   "----------------------------------------------------\n",
											x, x, buf);
								}
							} while (x == 0);
						}
					}
					printf("Closing socket...\n");
					sockTcp.close();
					pulseEvent();
					printf("Socket closed.\n");
				}
#endif
            	wait_ms(5000);
#ifndef TARGET_UBLOX_C027
            	printf("[Checking if user button has been pressed]\n");
#endif
        	} else {
                printf("Connection Lost\n");
        		break;
        	}
    	}

        pulseEvent();
        printf("User button was pressed, stopping...\n");
        interface->disconnect();
        ledOff();
        printf("Stopped.\n");
    } else {
        bad();
        printf("Unable to get IP address of \"developer.mbed.org\" or \"2.pool.ntp.org\".\n");
    }

    while (1);
}

#endif


#if MBED_CELLULAR_EXAMPLE
/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "common_functions.h"
#include "UDPSocket.h"
#include "CellularLog.h"


#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"

#include "mbed.h"

#include "CellularLog.h"
#include "CellularDevice.h"
#include "Semaphore.h"
#include "CellularContext.h"


#define UDP 0
#define TCP 1

// Number of retries /
#define RETRY_COUNT 3

NetworkInterface *iface;

// Echo server hostname
const char *host_name = MBED_CONF_APP_ECHO_SERVER_HOSTNAME;

// Echo server port (same for TCP and UDP)
const int port = MBED_CONF_APP_ECHO_SERVER_PORT;

static rtos::Mutex trace_mutex;

#if MBED_CONF_MBED_TRACE_ENABLE
static void trace_wait()
{
    trace_mutex.lock();
}

static void trace_release()
{
    trace_mutex.unlock();
}

static char time_st[50];

static char* trace_time(size_t ss)
{
    snprintf(time_st, 49, "[%08llums]", Kernel::get_ms_count());
    return time_st;
}

static void trace_open()
{
    mbed_trace_init();
    mbed_trace_prefix_function_set( &trace_time );

    mbed_trace_mutex_wait_function_set(trace_wait);
    mbed_trace_mutex_release_function_set(trace_release);

    mbed_cellular_trace::mutex_wait_function_set(trace_wait);
    mbed_cellular_trace::mutex_release_function_set(trace_release);
}

static void trace_close()
{
    mbed_cellular_trace::mutex_wait_function_set(NULL);
    mbed_cellular_trace::mutex_release_function_set(NULL);

    mbed_trace_free();
}
#endif // #if MBED_CONF_MBED_TRACE_ENABLE

Thread dot_thread(osPriorityNormal, 512);

void print_function(const char *format, ...)
{
    trace_mutex.lock();
    va_list arglist;
    va_start( arglist, format );
    vprintf(format, arglist);
    va_end( arglist );
    trace_mutex.unlock();
}

void dot_event()
{
    while (true) {
        ThisThread::sleep_for(4000);
        if (iface && iface->get_connection_status() == NSAPI_STATUS_GLOBAL_UP) {
            break;
        } else {
            trace_mutex.lock();
            printf(".");
            fflush(stdout);
            trace_mutex.unlock();
        }
    }
}

/**
 * Connects to the Cellular Network
 */
nsapi_error_t do_connect()
{
    nsapi_error_t retcode = NSAPI_ERROR_OK;
    uint8_t retry_counter = 0;

    while (iface->get_connection_status() != NSAPI_STATUS_GLOBAL_UP) {
        retcode = iface->connect();
        if (retcode == NSAPI_ERROR_AUTH_FAILURE) {
            print_function("\n\nAuthentication Failure. Exiting application\n");
        } else if (retcode == NSAPI_ERROR_OK) {
            print_function("\n\nConnection Established.\n");
        } else if (retry_counter > RETRY_COUNT) {
            print_function("\n\nFatal connection failure: %d\n", retcode);
        } else {
            print_function("\n\nCouldn't connect: %d, will retry\n", retcode);
            retry_counter++;
            continue;
        }
        break;
    }
    return retcode;
}

/**
 * Opens a UDP or a TCP socket with the given echo server and performs an echo
 * transaction retrieving current.
 */
nsapi_error_t test_send_recv()
{
    nsapi_size_or_error_t retcode;
#if MBED_CONF_APP_SOCK_TYPE == TCP
    TCPSocket sock;
#else
    UDPSocket sock;
#endif

    retcode = sock.open(iface);
    if (retcode != NSAPI_ERROR_OK) {
#if MBED_CONF_APP_SOCK_TYPE == TCP
        print_function("TCPSocket.open() fails, code: %d\n", retcode);
#else
        print_function("UDPSocket.open() fails, code: %d\n", retcode);
#endif
        return -1;
    }

    SocketAddress sock_addr;
    retcode = iface->gethostbyname("52.215.34.155", &sock_addr);
    if (retcode != NSAPI_ERROR_OK) {
        print_function("Couldn't resolve remote host: %s, code: %d\n", host_name, retcode);
        return -1;
    }

    sock_addr.set_port(port);

    sock.set_timeout(15000);
    int n = 0;
    const char *echo_string = "TEST";
    char recv_buf[4];
#if MBED_CONF_APP_SOCK_TYPE == TCP
    retcode = sock.connect(sock_addr);
    if (retcode < 0) {
        print_function("TCPSocket.connect() fails, code: %d\n", retcode);
        return -1;
    } else {
        print_function("TCP: connected with %s server\n", host_name);
    }
    retcode = sock.send((void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        print_function("TCPSocket.send() fails, code: %d\n", retcode);
        return -1;
    } else {
        print_function("TCP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recv((void*) recv_buf, sizeof(recv_buf));
#else

    retcode = sock.sendto(sock_addr, (void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        print_function("UDPSocket.sendto() fails, code: %d\n", retcode);
        return -1;
    } else {
        print_function("UDP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recvfrom(&sock_addr, (void*) recv_buf, sizeof(recv_buf));
#endif

    sock.close();

    if (n > 0) {
        print_function("Received from echo server %d Bytes\n", n);
        return 0;
    }

    return -1;
}

int main()
{
    print_function("\n\nmbed-os-example-cellular\n");
    print_function("Establishing connection\n");
#if MBED_CONF_MBED_TRACE_ENABLE
    trace_open();
#else
    dot_thread.start(dot_event);
#endif // #if MBED_CONF_MBED_TRACE_ENABLE

    CellularContext::AuthenticationType type = CellularContext::AuthenticationType::NOAUTH;

    //CellularNetwork *nw;
    //nsapi_error_t err = nw->set_access_technology(CellularNetwork::RAT_CATM1);

    // sim pin, apn, credentials and possible plmn are taken atuomtically from json when using get_default_instance()
    iface = NetworkInterface::get_default_instance();
    MBED_ASSERT(iface);

    nsapi_error_t retcode = NSAPI_ERROR_NO_CONNECTION;

    /* Attempt to connect to a cellular network */
    if (do_connect() == NSAPI_ERROR_OK) {
        retcode = test_send_recv();
    }

    if (iface->disconnect() != NSAPI_ERROR_OK) {
        print_function("\n\n disconnect failed.\n\n");
    }

    if (retcode == NSAPI_ERROR_OK) {
        print_function("\n\nSuccess. Exiting \n\n");
    } else {
        print_function("\n\nFailure. Exiting \n\n");
    }

#if MBED_CONF_MBED_TRACE_ENABLE
    trace_close();
#else
    dot_thread.terminate();
#endif // #if MBED_CONF_MBED_TRACE_ENABLE

    return 0;
}
// EOF


#endif

// End Of File

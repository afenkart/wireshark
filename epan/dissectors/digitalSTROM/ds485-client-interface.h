/*
 This file is part of the digitalSTROM ds485-client library.

 Copyright (C) 2010 digitalSTROM.org, Schlieren, Switzerland

 digitalSTROM ds485-client library is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 digitalSTROM ds485-client library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with digitalSTROM ds485-client library. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DS485CLIENTINTERFACE_H_
#define DS485CLIENTINTERFACE_H_

#include <digitalSTROM/ds.h>
#include <digitalSTROM/ds485.h>
#include <digitalSTROM/ds485-socket-server.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ds485ClientHandle_t;

typedef enum {
    ERROR_RESPONSE_TIMEOUT = -1,
    NOTICE_CALL_TO_BROADCAST = -2,
    ERROR_INVALID_HANDLE = -3,
    ERROR_INVALID_CONNSPEC = -4,
    ERROR_THREAD_START_FAILED = -5,
    ERROR_NO_PORT_FOUND = -6,
    ERROR_INVALID_ADDRESS = -7,
    ERROR_CREATE_SOCKET = -8,
    ERROR_SOCKET_OPTIONS = -9,
    ERROR_SOCKET_CONNECT = -10,
    ERROR_SOCKET_FULL = -11,
    ERROR_SOCKET_FAILED = -12,
    ERROR_WAITQ_USAGE = -13,
    ERROR_INVALID_FD = -16,
    ERROR_INVALID_PARAMETER = -17,
    ERROR_REC_WRONG_FUNCTION_ID = -18,
    ERROR_REC_WRONG_MODIFIER = -19,
    ERROR_SYNC_RESPONSE_TIMEOUT = -20,
    ERROR_DSUID_CONVERSION = -21,
} ds485c_error_t;

/* without braces it's interpreted as function pointer */
extern const char* (ds485c_strerror)(int __errnum);

/**
 * Callback Methoden
 */
typedef int (*client_callback_state_t)(void *data, const bus_state_t state);
typedef int (*client_callback_bus_change_t)(void *data, dsuid_t *id, int flags);
typedef int (*client_callback_container_t)(void *data, const ds485_container_t *container);
typedef int (*client_callback_netlib_packet_t)(void *data, const ds485n_packet_t *packet);

struct ds485c_callbacks {
    client_callback_state_t state_change_cb;
    void *state_change_data;
    client_callback_bus_change_t bus_change_cb;
    void *bus_change_data;
    client_callback_container_t container_pkt_cb;
    void *container_pkt_data;
    client_callback_netlib_packet_t netlib_pkt_cb;
    void *netlib_pkt_data;
};

enum client_open_flags {
    PROMISCUOUS_MODE = 0x1, /**< Return all RESPONSE-type messages instead of only the ones in answer to own REQUESTs */
};

/**
 * Opens a connection using the specified connection type
 *
 * @CONNSPEC: tcp://localhost:8442
 * @flags: PROMISCUOUS_MODE - server shall forward all messages
 *
 * @RETURN: handle or NULL on failure
 *
 * @DEPRECATED:
 * - will create handle and open connection in one step
 *   hence you can miss (state-)callbacks
 *   use ds485_client_open2 instead
 */
extern ds485ClientHandle_t ds485_client_open(const char *connspec, int flags)
    __attribute__ ((deprecated));

/**
 * Creates a handle, installs callbacks and connects to server
 *
 * @CONNSPEC: tcp://localhost:8442
 * @flags: PROMISCUOUS_MODE - server shall forward all messages
 * @callbacks: state / bus_change / long and short messages
 *
 * @RETURN: handle or NULL on failure
 */
extern ds485ClientHandle_t ds485_client_open2(const char *connspec, int flags,
                                              struct ds485c_callbacks *cb);

/**
 * Closes the session, frees all connection related ressources
 */
extern int ds485_client_close(ds485ClientHandle_t handle);

/**
 * Query the list of devices on the dS485 bus
 *
 * @param client_index
 * @param device_list
 * @param device_list_size
 * @return negative if error; number of found devices otherwise
 */
extern int ds485_client_query_devices(ds485ClientHandle_t handle, dsuid_t *device_list, int device_list_size);

/**
 * Query the current bus state
 */
extern int ds485_client_query_state(ds485ClientHandle_t handle, bus_state_t *state);

/**
 * Restart the dS485 bus.
 */
extern int ds485_client_restart_bus(ds485ClientHandle_t handle);

/**
 * Send dM-API command
 */
extern int ds485_client_send_command(ds485ClientHandle_t handle, ds485_container_t *request);
extern int ds485_client_send_long_command(ds485ClientHandle_t handle, ds485n_packet_t *request);

/**
 * Send dM-API command, receive a single response packet
 *
 * @return 0: success; >0: error from device; -1: failure; -2: request to broadcast will return responses by callback
 */
extern int ds485_client_send_sync_command(ds485ClientHandle_t handle, ds485_container_t *request, ds485_container_t *response, int timeout);
extern int ds485_client_send_sync_long_command(ds485ClientHandle_t handle, ds485n_packet_t *request, ds485n_packet_t *response, int timeout);

/**
 * Set and remove a reception handler for dS485 Packet's, optional a filter for a message id can be given
 * @deprecated: use ds485_client_open2 instead
 */
extern client_callback_container_t ds485_client_set_receive_callback(ds485ClientHandle_t handle, client_callback_container_t cb, void *data) __attribute__ ((deprecated));
extern client_callback_netlib_packet_t ds485_client_set_receive_netlib_packet_callback(ds485ClientHandle_t handle, client_callback_netlib_packet_t cb, void *data) __attribute__ ((deprecated));

/**
 * Set and remove a callback handler to register for bus state changes
 * @deprecated: use ds485_client_open2 instead
 */
extern client_callback_state_t ds485_client_set_state_callback(ds485ClientHandle_t handle, client_callback_state_t cb, void *data) __attribute__ ((deprecated));

/**
 * Set and remove a callback handler to register for bus device registration/deregistration changes
 * @deprecated: use ds485_client_open2 instead
 */
extern client_callback_bus_change_t ds485_client_set_bus_change_callback(ds485ClientHandle_t handle, client_callback_bus_change_t cb, void *data) __attribute__ ((deprecated));

/**
 * Get dSUID of library.
 *
 * @param handle [in] Library handle
 * @param dsuid [out] own dsuid
 * @return 0 on success; negative on failure
 */
extern int ds485_client_get_dsuid(ds485ClientHandle_t handle, dsuid_t *dsuid);
#ifdef __cplusplus
}
#endif

#endif /* DS485CLIENTINTERFACE_H_ */

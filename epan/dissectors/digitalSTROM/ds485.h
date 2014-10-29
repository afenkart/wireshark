/*
 This file is part of the digitalSTROM ds485-core library.

 Copyright (C) 2010 digitalSTROM.org, Schlieren, Switzerland

 digitalSTROM ds485-core library is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation version 2
 of the License.

 digitalSTROM ds485-core library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with digitalSTROM ds485-core library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _ds485_h
#define _ds485_h

#include <digitalSTROM/ds.h>
#include <digitalSTROM/ds485-const.h>
#define DS485_MAX_PAYLOAD_SIZE 127
#define DS485_MAX_PAYLOAD_SIZE_RAW DS485_MAX_PAYLOAD_SIZE + 1
#define DS485_CONTAINER_DATA_LENGTH DS485_MAX_PAYLOAD_SIZE
#define DS485_CONTAINER_SIZE (sizeof(ds485_container_t) - (DS485_CONTAINER_DATA_LENGTH))

/**
 * Internal errors
 */
enum {
    DS485_INTERNAL_ERROR_OK = 0,
    DS485_INTERNAL_ERROR_GENERAL = -1,
    DS485_INTERNAL_ERROR_EMPTY_TX_QUEUE = -2,
    DS485_INTERNAL_ERROR_INVALID_BUS_ADDR = -3,
};

/**
 * Status des dS485 Bus
 */
typedef enum {
    DS485_STATE_ISOLATED = 1,
    DS485_STATE_JOIN,
    DS485_STATE_CONNECTED,
    DS485_STATE_ACTIVE,
    DS485_STATE_DISCONNECTED,
} bus_state_t;

/**
 * Typ des dS485Packets
 */
typedef enum {
    DS485_CONTAINER_REQUEST = 1,
    DS485_CONTAINER_RESPONSE,
    DS485_CONTAINER_EVENT
} container_type_t;

typedef enum {
    DS485_FLAG_NONE = 1,
    DS485_FLAG_BROADCAST = 2,
} container_flags_t;

/**
 * dS485 API Daten Container
 */
typedef struct ds485_container {
    dsuid_t destinationId;
    dsuid_t sourceId;
    uint32_t containerType;
    uint32_t containerFlags;
    uint8_t length;
    union {
        struct {
            unsigned char transactionId;
            unsigned char data[DS485_MAX_PAYLOAD_SIZE];
        };
        unsigned char raw_data[DS485_MAX_PAYLOAD_SIZE_RAW];
    };
#ifdef SWIG
} ds485_container_t;
#else
} __attribute__ ((packed)) ds485_container_t;
#endif

/**
 * dS485 Protocol Statistic
 */
typedef struct {
    /* TX */
    uint32_t txToken;
    uint16_t txStartupRequest;
    uint16_t txStartupResponse;
    uint16_t txJoinRequest;
    uint16_t txJoinResponse;
    uint16_t txGetAddressRequest;
    uint16_t txGetAddressResponse;
    uint16_t txSetAddressRequest;
    uint16_t txSetAddressResponse;
    uint16_t txSetSuccessorAddressRequest;
    uint16_t txSetSuccessorAddressResponse;
    uint16_t txResponse;
    uint16_t txDataRequest;
    uint16_t txDataResponse;
    uint16_t txDataEvent;
    /* RX */
    uint16_t rxResponse;
    uint16_t rxDataRequest;
    uint16_t rxDataResponse;
    uint16_t rxDataEvent;
    /* Actions */
    uint16_t startRegisterStation;
    uint16_t doneRegisterStation;
    uint16_t enterOperational;
    uint16_t successorLost;
} DS485Statistics;

/***
 * External references - have to be supplied by platform module
 */

/**
 * Receive frame error bits
 */
#define RX_FLAG_CRC_ERROR            0x01
#define RX_FLAG_FRAME_ERROR            0x02
#define RX_FLAG_PROTOCOL_ERROR        0x04
#define RX_FLAG_NOTFORME            0x10
#define RX_FLAG_INVALID_ADDRESS        0x80

#define RX_FLAG_ERRORS (RX_FLAG_CRC_ERROR | RX_FLAG_FRAME_ERROR | RX_FLAG_PROTOCOL_ERROR)

/**
 * Packet filter bits
 */
#define DS485_FILTER_ALL_RESPONSES   0x01

#endif

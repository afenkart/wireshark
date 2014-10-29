/*
 This file is part of the digitalSTROM ds485-daemon (ds485d).

 Copyright (C) 2010 digitalSTROM.org, Schlieren, Switzerland

 digitalSTROM ds485-daemon is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation version 2
 of the License.

 digitalSTROM ds485-daemon is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with digitalSTROM ds485-daemon; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _ds485_socket_interface_h
#define _ds485_socket_interface_h

#include <stdint.h>
#include <digitalSTROM/ds485.h>

/**
 * ds485 daemon interface
 */
#define DS485D_API_REVISION            1

/**
 * command/data structure
 */
typedef struct _ds485Command {
    uint8_t command;
    uint16_t length;
    uint8_t data[2];
} __attribute__ ((packed)) dS485dCommand;

typedef struct _ds485dCmdRegister {
    dsuid_t dsuid;
} __attribute__ ((packed)) dS485dCmdRegister;

typedef struct _dS485CmdApidata {
    uint8_t command;
    uint16_t length;
    ds485_container_t apiData;
} __attribute__ ((packed)) dS485CmdApidata;

typedef struct _dS485CmdLongApidata {
    uint8_t command;
    uint16_t length;
    ds485n_packet_t apiData;
} __attribute__ ((packed)) dS485CmdLongApidata;

/**
 * command defintions
 */

/* reserved, data: deprecated */
#define DS485D_CMD_SYNC                0x00

/* data: 1 byte api revision */
#define DS485D_CMD_API_REVISION        0x01

/* data: - */
#define DS485D_CMD_PING                0x02

/* data: n byte dS485Container */
#define DS485D_CMD_TX_PACKET        0x03

/* data: n byte dS485Container */
#define DS485D_CMD_RX_PACKET        0x04

/* data: n byte dS485Packet, deprecated */
#define DS485D_CMD_DEVICE_PACKET    0x05

/* data: n byte dS485 netlib packet */
#define DS485N_CMD_LONG_TX_PACKET      0x06

/* data: n byte dS485 netlib packet */
#define DS485N_CMD_LONG_RX_PACKET      0x07

/* data: n byte dS485 netlib packet, deprecated  */
#define DS485N_CMD_LONG_DEVICE_PACKET  0x08

/* data: n byte dS485dCmdRegister */
#define DS485D_CMD_REGISTER            0x10

/* data: n byte dS485dCmdRegister */
#define DS485D_CMD_UNREGISTER        0x11

/* data: 1 byte filter flags */
#define DS485D_CMD_PACKETFILTER        0x12

/* data: 1 byte rawmode on/off, deprecated */
#define DS485D_CMD_RAWMODE            0x13

#define DS485D_CMD_QUERY_DEVICES    0x20

#define DS485D_CMD_QUERY_DSUID      0x21

#define DS485D_CMD_QUERY_ADDRESS    0x22

#define DS485D_CMD_QUERY_BUSSTATE   0x23

#define DS485D_CMD_BUS_CHANGE       0x24

#define DS485D_CMD_BUS_STATE        0x25

#define DS485D_CMD_RESTART_BUS      0x26

#endif /* _ds485_socket_interface_h */


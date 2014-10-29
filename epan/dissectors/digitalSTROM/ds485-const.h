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

#ifndef DS485CONST_H_
#define DS485CONST_H_

/*
 * Message Declarations
 */
enum DS485MessageSizes {
    DS485_MIN_DATA_PAYLOAD_SIZE = 3,        /* transaction ID + message ID + modifier/error code */
    DS485_HEADER_CRC_SIZE       = 6,        /* start + destination + source + command/length + crc16 */
    DS485_SHORT_PAYLOAD_SIZE    = 15,
    DS485_LONG_PAYLOAD_SIZE     = 128,
    DS485_SHORT_MESSAGE_SIZE    = (DS485_SHORT_PAYLOAD_SIZE+DS485_HEADER_CRC_SIZE),
    DS485_LONG_MESSAGE_SIZE     = (DS485_LONG_PAYLOAD_SIZE+DS485_HEADER_CRC_SIZE)
};

/*
 * dS485 Frame
 */
typedef struct _dS485Frame {
    uint8_t      size;
    uint8_t      data[DS485_LONG_MESSAGE_SIZE];
} dS485Frame;

enum DS485SpecialCharacters {
    DS485_START_BYTE    = 0xFD,
    DS485_ESCAPE_BYTE   = 0xFC,
    DS485_RESERVED_BYTE = 0xFE
};

enum DS485SpecialDestination {
    DS485_BROADCAST = 0xFF
};

enum DS485MessageOffset {
    DS485_START_OFFSET  = 0,
    DS485_DEST_OFFSET   = 1,
    DS485_SRC_OFFSET    = 2,
    DS485_CL_OFFSET     = 3,
    DS485_DATA_OFFSET   = 4
};

enum DS485Addresses {
    DS485_MASTER_ADDRESS        = 0,
    DS485_MIN_ADDRESS           = 0,
    DS485_MIN_SLAVE_ADDRESS     = 1,
    DS485_MAX_SLAVE_ADDRESS     = 62,
    DS485_INTERMEDIATE_ADDRESS  = 63,
    DS485_INVALID_ADDRESS       = 255
};

enum DS485CommandLengthMask {
    DS485_COMMAND_MASK      = 0xF0,
    DS485_LENGTH_MASK       = 0x0F
};

enum DS485DestinationMask {
    DS485_DESTINATION_MASK  = 0xC0,
    DS485_DATACONTROL_MASK  = 0x80,
    DS485_BROADCAST_MASK    = 0x40
};

enum DS485SourceMask {
    DS485_SOURCE_MASK       = 0xC0,
    DS485_REQ_MASK          = 0x00,
    DS485_ACK_RESPONSE_MASK = 0x80,
    DS485_BUSY_MASK         = 0x40,
    DS485_EVENT_MASK        = 0xC0,
};

typedef enum {
    DS485_CMD_TOKEN                     = 0,
    DS485_CMD_STARTUP                   = 1,
    DS485_CMD_JOIN                      = 2,
    DS485_CMD_GET_ADDRESS               = 3,
    DS485_CMD_SET_ADDRESS               = 4,
    DS485_CMD_SET_SUCCESSOR_ADDRESS     = 5,
    DS485_CMD_RESPONSE                  = 6,
    DS485_CMD_RESERVED                  = 7,
    DS485_CMD_RESTART_BUS               = 8,
    DS485_LAST_CMD                      = DS485_CMD_RESTART_BUS,
} DS485CommandId;

typedef enum {
    DS485_TYPE_REQ                      = DS485_REQ_MASK,
    DS485_TYPE_ACK_RES                  = DS485_ACK_RESPONSE_MASK,
    DS485_TYPE_BUSY                     = DS485_BUSY_MASK,
    DS485_TYPE_EVENT                    = DS485_EVENT_MASK,
} DS485CommandType;


typedef enum {
    DS485_TYPE_CONTROL                  = 0x00,
    DS485_TYPE_DATA                     = DS485_DATACONTROL_MASK
} DS485MessageType;



#endif /* DS485CONST_H_ */

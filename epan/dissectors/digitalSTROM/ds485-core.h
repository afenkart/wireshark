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

#ifndef _ds485_interface_h
#define _ds485_interface_h

#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include <digitalSTROM/ds.h>
#include <digitalSTROM/ds485.h>

typedef void *ds485Handle_t;

extern ds485Handle_t ds485_api_open( const char *device, const dsid_t *dsid );

extern int ds485_api_close( ds485Handle_t handle );

/**
 * Sends a packet over the dS485 bus.
 *
 * If the library is in the blocking mode, the call returns when the message is
 *  sent.
 */
extern int ds485_api_send_data( ds485Handle_t handle, ds485_container_t const * packet );

/**
 * Returns the oldest packet from the message queue.
 *
 * If the library is in the blocking mode, the call returns when a message is
 * received, otherwise it returns immediately an returns -1 if no packet is in
 * the queue.
 * If this function is not called enough fast and the message queue is getting
 * full, the oldest messages are removed.
 */
extern int ds485_api_recv_data( ds485Handle_t handle, ds485_container_t* packet );

/**
 * @param handle
 * @param members Array where the members of the dS485 bus are written to. The
 * Array has to have a length that all members can be written to.
 * @param maxNumberOfMembers the #members array has space for this many entries
 * @return the number of bus members written to members
 */
extern int ds485_api_get_bus_members( ds485Handle_t handle, dsuid_t *members, int maxNumberOfMembers );

extern bus_state_t ds485_api_get_bus_state( ds485Handle_t handle );

/**
 * Instructs the dS485 bus master to restart the fast bus registration process.
 *
 * @param handle
 */
extern int ds485_api_restart_bus( ds485Handle_t handle );


/*
 * Configure protocol stack and platform dependent settings
 */

/**
 * Enables/disables the loopback mode of the library. This is for rs485 adapter
 * who don't replicate the sent stream back to the library.
 */
#define IOC_LOOPBACK_MODE        0x4240

/**
 * Enables/disables the blocking mode of the library.
 */
#define IOC_BLOCKING_MODE        0x4241

/**
 * Sets the callback function who is called for messages from the library.
 */
#define IOC_SET_MSG_CB            0x4280

/**
 * Sets the callback function who is called when a new bus member is found or
 * a bus member is not longer on the bus.
 */
#define IOC_SET_BUS_CHANGE_CB   0x4282

/**
 * Sets the callback function who is called when a packet is received.
 */
#define IOC_SET_RECEIVED_CB     0x4283

/**
 * Sets the callback function who signals the result of a ds485_api_send_data
 * call.
 */
#define IOC_SET_SENDER_CB       0x4284

/**
 * Sets the callback function who is called if the bus-state has changed.
 */
#define IOC_SET_BUS_STATE_CB    0x4285

/**
 * Sets a filehandle (int) where the stream from RS485 is replicated to. Please
 * ensure that writing to this device will not block, it can disturb the
 * dS485 stack.
 */
#define IOC_SET_LOGGER_FD       0x4281

/*
 * Callback typedefs
 */

typedef void (*ds485_api_callback_msg_t)(ds485Handle_t dev, unsigned char level, const char *msg, va_list args);
typedef void (*ds485_api_callback_bus_change_t)(ds485Handle_t dev, dsuid_t *dsuid, int flags );
typedef void (*ds485_api_callback_received_t)(ds485Handle_t dev, ds485_container_t const * frame);
typedef void (*ds485_api_callback_sender_t)(ds485Handle_t dev, int error);
typedef void (*ds485_api_callback_state_t)(ds485Handle_t dev, bus_state_t state);


extern int ds485_api_ioctl( ds485Handle_t handle, unsigned int cmd, void* data, unsigned int length);
extern dsuid_t ds485_dsid_to_dsuid(const dsid_t *dsid);



#endif /*_ds485_interface_h*/


#ifndef __SERVER_INTF_H_
#define __SERVER_INTF_H_

#include <digitalSTROM/ds485-core.h>

#include <stdbool.h>
#include <stddef.h>

struct dS485_server;
struct _dS485dClient;

enum DS485NetlibPacketSizes {
    DS485N_PACKET_PAYLOAD_SIZE     = 8600,
    DS485N_PACKET_MESSAGE_SIZE     = (DS485N_PACKET_PAYLOAD_SIZE+DS485_HEADER_CRC_SIZE)
};

enum DS485NetlibPacketOffset {
    DS485N_PACKET_START_OFFSET     = 0,
    DS485N_PACKET_DEST_OFFSET      = 1,
    DS485N_PACKET_SRC_OFFSET       = 2,
    DS485N_PACKET_CL_OFFSET_LOW    = 3,
    DS485N_PACKET_CL_OFFSET_HIGH   = 4,
    DS485N_PACKET_DATA_OFFSET      = 5,
};

#define DS485N_PACKET_MAX_PAYLOAD_SIZE      DS485N_PACKET_PAYLOAD_SIZE - 1
#define DS485N_PACKET_MAX_PAYLOAD_SIZE_RAW  DS485N_PACKET_MAX_PAYLOAD_SIZE + 1
#define DS485N_HDR_LEN                      (offsetof(ds485n_packet_t, data))

/**
 * set loglevel via environment
 * see man syslog.h, valid args are 0(emerg)-7(debug)
 * default is 5(notice)
 */
#define DS485_NETLIB_DEBUG "DS485_NETLIB_DEBUG"

/**
 * if environment variable is set, log output is redirected to syslog
 */
#define DS485_SYSLOG "DS485_SYSLOG"

typedef struct ds485n_packet {
    dsuid_t destinationId;
    dsuid_t sourceId;
    uint16_t dummy; // explictly needed now as we pack the struct; without packing compilers did 32-bit align here
    uint32_t containerType; /* legacy */ // using uint32_t, enum type is dangerous because it could be 1,2 or 4 bytes depending on compiler
    uint16_t length; // TODO: this is only works on a little-endian architecture (x86, most ARM). Should be made endian-independent
    union {
        struct {
            unsigned char transactionId;
            unsigned char data[DS485N_PACKET_MAX_PAYLOAD_SIZE];
        } __attribute__((packed));
        unsigned char raw_data[DS485N_PACKET_MAX_PAYLOAD_SIZE_RAW];
    } __attribute__((packed));
} __attribute__((packed)) ds485n_packet_t;


struct dS485_server_callbacks
{
    /**
     * client sent a packet for forwarding
     */
    int (*receive_data)(struct dS485_server *server, ds485_container_t* packet);

    /**
     * client sent a long packet for forwarding
     */
    int (*receive_long_data)(struct dS485_server *server, ds485n_packet_t* packet);

    /**
     * Fill devices array with dsuid of all devices
     */
    int (*get_bus_members)(struct dS485_server *server, dsuid_t *devices, int length);

    /**
     * get server address
     */
    dsuid_t (*get_dsuid)(struct dS485_server *server);

    /**
     * current state of the server
     */
    bus_state_t (*get_bus_state)(struct dS485_server *server);

    int (*restart_bus)(struct dS485_server *server);

    /**
     * promiscious mode, forwared all packets
     */
    int (*set_packetfilter)(struct dS485_server *server, uint8_t rxfilter);
};

/*
 * Generic parts
 */
void ds485_server_emit_bus_change(struct dS485_server *server, dsuid_t dsuid, int
                                  flags);
void ds485_server_emit_bus_state(struct dS485_server *server, bus_state_t state);

void ds485_server_reply(struct dS485_server *server,
                        const ds485_container_t *container);
void ds485_server_reply_long(struct dS485_server *server,
                             const ds485n_packet_t *packet);

struct dS485_server *ds485_server_init(struct dS485_server_callbacks *cb, bool upperPath);
void ds485_server_cleanup(struct dS485_server *server);

int ds485_server_listen(struct dS485_server* server, int port, bool listenGlobal);
void ds485_server_abort(struct dS485_server *server);


#endif

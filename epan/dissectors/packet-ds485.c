/* packet-ds485.c
 *
 * Routines for digitalStrom netlib packet disassembly
 *
 * Copyright (C) 2014 digitalStrom AG
 * Written by Andreas Fenkart <afenkart@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <string.h>
#include <epan/aftypes.h>
#include <epan/etypes.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#include "packet-ds485.h"
#include "digitalSTROM/ds485-socket-server.h"
#include "digitalSTROM/ds485-socket-interface.h"
#include "digitalSTROM/ds485-client-interface.h"
#include "digitalSTROM/ds485.h"

#define FRAME_HEADER_LEN    3

#if 0
static dissector_table_t dS485_dissector_table;
#endif


/* protocols and header fields */
static int proto_dS485 = -1;
static int hf_ds485_msg_type = -1;
static int hf_ds485_msg_size = -1;
static int hf_ds485_query_busstate = -1;
static int hf_ds485_dsid = -1;
static int hf_ds485_api_revision = -1;
static int hf_ds485_packet_filter = -1;
static int hf_ds485_restart_bus_status = -1;

/* bus change event */
static int hf_ds485_cont_src_dsid = -1;
static int hf_ds485_cont_dst_dsid = -1;
static int hf_ds485_cont_type = -1;
static int hf_ds485_cont_flags = -1;
static int hf_ds485_cont_length = -1;
static int hf_ds485_cont_data = -1;
static int hf_ds485_cont_transaction_id = -1;
static int hf_ds485_bus_change_event = -1;
static int hf_ds485_long_cont_length = -1;
static int hf_ds485_long_cont_data = -1;


static gint ett_ds485 = -1;

static const value_string packettypenames[] = {
	{ DS485D_CMD_SYNC,			"sync" },
	{ DS485D_CMD_API_REVISION,	"revision" },
	{ DS485D_CMD_PING,	        "ping" },
	{ DS485D_CMD_TX_PACKET,		"TX packet" },
	{ DS485D_CMD_RX_PACKET,		"RX packet" },
	{ DS485N_CMD_LONG_TX_PACKET,	"TX long packet" },
	{ DS485N_CMD_LONG_RX_PACKET,	"RX long packet" },
	{ DS485D_CMD_DEVICE_PACKET,     "Device packet" },
	{ DS485D_CMD_REGISTER,		"register" },
	{ DS485D_CMD_UNREGISTER,	"unregister" },
	{ DS485D_CMD_PACKETFILTER,	"packet filter" },
	{ DS485D_CMD_RAWMODE,		"RAW mode" },
	{ DS485D_CMD_QUERY_DEVICES,     "query devices" },
	{ DS485D_CMD_QUERY_DSUID,	"query DSID" },
	{ DS485D_CMD_QUERY_ADDRESS,	"query address" },
	{ DS485D_CMD_QUERY_BUSSTATE,    "query bus state" },
	{ DS485D_CMD_BUS_CHANGE,	"bus change event" },
	{ DS485D_CMD_BUS_STATE,		"bus state event" },
	{ DS485D_CMD_RESTART_BUS,	"restart bus" },
};

static const value_string state_names[] = {
	{ DS485_STATE_ISOLATED,		"isolated" },
	{ DS485_STATE_JOIN,			"join" },
	{ DS485_STATE_CONNECTED,	"connected" },
	{ DS485_STATE_ACTIVE,		"active" },
	{ DS485_STATE_DISCONNECTED,	"disconnected" }
};

static const value_string cont_type_names[] = {
	{ DS485_CONTAINER_REQUEST,	"request" },
	{ DS485_CONTAINER_RESPONSE,	"response" },
	{ DS485_CONTAINER_EVENT,	"event" }
};

/* TODO split flags */
static const value_string cont_flag_names[] = {
	{ DS485_FLAG_NONE,			"none" },
	{ DS485_FLAG_BROADCAST,		"broadcast" }
};

// inverted logic 0 -> join, 1 -> leave
#define DSM_CHANGE_LEAVE	0x1
const true_false_string tfs_dsm_leave = { "leave", "join" };

static hf_register_info hf_msg[] = {
	{ &hf_ds485_msg_type,
		{ "type", "ds485.type", FT_UINT8, BASE_HEX, VALS(packettypenames),
			0x0, NULL, HFILL }},
	{ &hf_ds485_msg_size,
		{ "size", "ds485.size", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_ds485_api_revision,
		{ "api revision", "ds485.api_revision", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
	{ &hf_ds485_packet_filter,
		{ "promiscious", "ds485", FT_BOOLEAN, 8, NULL,
			PROMISCUOUS_MODE, NULL, HFILL }},
	{ &hf_ds485_query_busstate,
		{ "state", "ds485.state", FT_UINT8, BASE_HEX, VALS(state_names),
			0x0, NULL, HFILL }},
	{ &hf_ds485_dsid,
		{ "dsid", "ds485.dsid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ds485_bus_change_event,
		{ "dsm_join", "ds485.cont.dsm_join", FT_BOOLEAN, 8,
			TFS(&tfs_dsm_leave), DSM_CHANGE_LEAVE, NULL, HFILL }},
	{ &hf_ds485_restart_bus_status,
		{ "status", "ds485", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	{ &hf_ds485_cont_src_dsid,
		{ "src", "ds485.cont.src_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ds485_cont_dst_dsid,
		{ "dst", "ds485.cont.dst_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ds485_cont_type,
		{ "type", "ds485.cont.type", FT_UINT32, BASE_HEX, VALS(cont_type_names),
			0x0, NULL, HFILL }},
	{ &hf_ds485_cont_flags,
		{ "flags", "ds485.cont.flags", FT_UINT32, BASE_HEX, VALS(cont_flag_names),
			0x0, NULL, HFILL }},
	{ &hf_ds485_cont_length,
		{ "length", "ds485.cont.length", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
	{ &hf_ds485_cont_transaction_id,
		{ "transaction_id", "ds485.cont.transaction_id", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},
	{ &hf_ds485_cont_data,
		{ "data", "ds485.cont.data", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	{ &hf_ds485_long_cont_length,
		{ "length", "ds485.long_cont.length", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
	{ &hf_ds485_long_cont_data,
		{ "data", "ds485.long_cont.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
};

static gint *ett[] = {
	&ett_ds485,
};

static int decode_dsm_api(tvbuff_t *tvb, proto_tree *ds485_tree, int len)
{
	(void)tvb;
	(void)ds485_tree;

	proto_tree_add_item(ds485_tree, hf_ds485_cont_data, tvb, 0, len,
						ENC_LITTLE_ENDIAN);
	return 0;
}

static int decode_container(tvbuff_t *tvb, proto_tree *ds485_tree,
							bool dsm_api_data)
{
	ds485_container_t container;
	tvbuff_t *tvb_dsm_api = NULL;
	int length;

	proto_tree_add_item(ds485_tree, hf_ds485_cont_dst_dsid, tvb,
						offsetof(ds485_container_t, destinationId),
						sizeof(container.destinationId),
						ENC_NA);
	proto_tree_add_item(ds485_tree, hf_ds485_cont_src_dsid, tvb,
						offsetof(ds485_container_t, sourceId),
						sizeof(container.sourceId),
						ENC_NA);
	proto_tree_add_item(ds485_tree,
						hf_ds485_cont_type, tvb,
						offsetof(ds485_container_t, containerType),
						sizeof(container.containerType),
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree,
						hf_ds485_cont_flags, tvb,
						offsetof(ds485_container_t, containerFlags),
						sizeof(container.containerFlags),
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree, hf_ds485_cont_length, tvb,
						offsetof(ds485_container_t, length),
						sizeof(container.length),
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree, hf_ds485_cont_transaction_id, tvb,
						offsetof(ds485_container_t, transactionId),
						sizeof(container.transactionId),
						ENC_LITTLE_ENDIAN);

	if (dsm_api_data) {
		length = tvb_get_guint8(tvb, offsetof(ds485_container_t, length));
		tvb_dsm_api = tvb_new_subset_length(tvb,
											offsetof(ds485_container_t, data),
											length);
		decode_dsm_api(tvb_dsm_api, ds485_tree, length);
	}
	return 0;
}

static int decode_long_container(tvbuff_t *tvb, proto_tree *ds485_tree,
								 bool dsm_api_data)
{
	ds485n_packet_t packet;
	tvbuff_t *tvb_dsm_api = NULL;
	int length;

	proto_tree_add_item(ds485_tree, hf_ds485_cont_dst_dsid, tvb,
						offsetof(ds485n_packet_t, destinationId),
						sizeof(packet.destinationId),
						ENC_NA);
	proto_tree_add_item(ds485_tree, hf_ds485_cont_src_dsid, tvb,
						offsetof(ds485n_packet_t, sourceId),
						sizeof(packet.sourceId),
						ENC_NA);
	proto_tree_add_item(ds485_tree,
						hf_ds485_cont_type, tvb,
						offsetof(ds485n_packet_t, containerType),
						sizeof(packet.containerType),
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree, hf_ds485_long_cont_length, tvb,
						offsetof(ds485n_packet_t, length),
						sizeof(packet.length),
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree, hf_ds485_cont_transaction_id, tvb,
						offsetof(ds485n_packet_t, transactionId),
						sizeof(packet.transactionId),
						ENC_LITTLE_ENDIAN);

	if (dsm_api_data) {
		length = tvb_get_letohs(tvb, offsetof(ds485n_packet_t, length));
		tvb_dsm_api = tvb_new_subset_length(tvb,
											offsetof(ds485n_packet_t, data),
											length);
		decode_dsm_api(tvb_dsm_api, ds485_tree, length);
	}
	return 0;
}

static int dissect_dS485_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree
								 *tree, void *data)
{
	guint8 packet_type = tvb_get_guint8(tvb, 0);
	guint16 packet_len = tvb_get_letohs(tvb, 1);
	proto_item *ti = NULL;
	proto_tree *ds485_tree = NULL;
	tvbuff_t *tvb_container = NULL;
	int offset;
	(void)data;

	//tvb_memcpy(tvb, &container, 3, sizeof(ds485_container_t));
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "dS485d");
	col_add_fstr(pinfo->cinfo, COL_INFO, "dS485d %s",
				 val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

	if (!tree) {
		/* no details required */
		return 0;
	}

	ti = proto_tree_add_item(tree, proto_dS485, tvb, 0, -1, ENC_NA);
	ds485_tree = proto_item_add_subtree(ti, ett_ds485);

	proto_tree_add_item(ds485_tree, hf_ds485_msg_type, tvb, 0, 1,
						ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ds485_tree, hf_ds485_msg_size, tvb, 1, 2,
						ENC_LITTLE_ENDIAN);

	/* strip tag / length field */
	tvb_container = tvb_new_subset_length(tvb, 3, packet_len - 3);

	switch (packet_type) {
	case DS485D_CMD_API_REVISION:
		proto_tree_add_item(ds485_tree, hf_ds485_api_revision, tvb, 3, 1,
							ENC_LITTLE_ENDIAN);
		break;

	case DS485D_CMD_PING:
		break;

	case DS485D_CMD_TX_PACKET:
	case DS485D_CMD_RX_PACKET:
		decode_container(tvb_container, ds485_tree, true);
		break;

	case DS485N_CMD_LONG_RX_PACKET:
	case DS485N_CMD_LONG_TX_PACKET:
		decode_long_container(tvb_container, ds485_tree, true);
		break;

	case DS485D_CMD_PACKETFILTER:
		proto_tree_add_item(ds485_tree, hf_ds485_packet_filter, tvb, 3, 1,
							ENC_LITTLE_ENDIAN);
		break;

	case DS485D_CMD_QUERY_DEVICES:
		if (packet_len == 3) {
			/* it's the request */
			break;
		}

		for (offset = 3; offset + sizeof(dsid_t) <= packet_len;
			 offset += sizeof(dsid_t)) {
			proto_tree_add_item(ds485_tree, hf_ds485_dsid, tvb, offset,
								sizeof(dsid_t), ENC_NA);
		}
		break;

	case DS485D_CMD_QUERY_DSUID:
		if (packet_len == 3) {
			/* it's the request */
			break;
		}

		proto_tree_add_item(ds485_tree, hf_ds485_dsid, tvb, 3,
							sizeof(dsid_t), ENC_NA);
		break;

	case DS485D_CMD_QUERY_BUSSTATE:
		if (packet_len == 3) {
			/* it's the request */
			break;
		}

		proto_tree_add_item(ds485_tree, hf_ds485_query_busstate, tvb, 3, 1,
							ENC_LITTLE_ENDIAN);
		break;

	case DS485D_CMD_BUS_CHANGE:
		decode_container(tvb_container, ds485_tree, false);
		proto_tree_add_item(ds485_tree, hf_ds485_bus_change_event, tvb,
							offsetof(ds485_container_t, data) + 3,
							1, ENC_NA);

		break;

	case DS485D_CMD_BUS_STATE:
		if (packet_len == 3) {
			/* it's the request */
			break;
		}

		decode_container(tvb_container, ds485_tree, false);
		proto_tree_add_item(ds485_tree, hf_ds485_query_busstate,
							tvb,
							offsetof(ds485_container_t, data) + 3,
							1, ENC_LITTLE_ENDIAN);
		break;

	case DS485D_CMD_RESTART_BUS:
		proto_tree_add_item(ds485_tree,
							hf_ds485_restart_bus_status,
							tvb, 3, 1,
							ENC_LITTLE_ENDIAN);
		break;

	case DS485D_CMD_QUERY_ADDRESS:
	case DS485D_CMD_DEVICE_PACKET:
	case DS485D_CMD_REGISTER:
	case DS485D_CMD_UNREGISTER:
	case DS485D_CMD_RAWMODE:
	case DS485D_CMD_SYNC:
		// deprecated stuff
		break;
	}

	return 0;
}

static guint get_dS485_message_len(packet_info *pinfo __attribute__((unused)),
								   tvbuff_t *tvb, int offset __attribute__((unused)))
{
	return tvb_get_letohs(tvb, offset + 1);
}


/* The main dissecting routine */
static void dissect_dS485(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
					 get_dS485_message_len, dissect_dS485_message, NULL);
}

void proto_register_dS485(void)
{
	proto_dS485 = proto_register_protocol("digitalSTROM 485", "dS485", "ds485");
	proto_register_field_array(proto_dS485, hf_msg, array_length(hf_msg));
	proto_register_subtree_array(ett, array_length(ett));

#if 0
	/* subdissector code */
	dS485_dissector_table = register_dissector_table("dS485.item",
													 "dS485 item type", FT_UINT32, BASE_DEC);
#endif
}

/* http://ask.wireshark.org/questions/17504/how-can-i-make-my-dissector-handle-multiple-ports */
void proto_reg_handoff_dS485(void)
{
	dissector_handle_t dS485_handle;

	dS485_handle = create_dissector_handle(dissect_dS485, proto_dS485);
	//dissector_add_uint("wtap_encap", WTAP_ENCAP_DS485, dS485_handle);
	dissector_add_uint("tcp.port", 8440, dS485_handle);
	dissector_add_uint("tcp.port", 8441, dS485_handle);
	dissector_add_uint("tcp.port", 8442, dS485_handle);
	dissector_add_uint("tcp.port", 8945, dS485_handle);
	dissector_add_uint("tcp.port", 8445, dS485_handle);
}

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/uuid.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "../src/adapter.h"
#include "../src/device.h"

#include "log.h"
#include "error.h"
#include "device.h"
#include "manager.h"
#include "avctp.h"
#include "avrcp.h"
#include "sdpd.h"
#include "dbus-common.h"
#include "control.h"
#include "player.h"

/* Company IDs for vendor dependent commands */
#define IEEEID_BTSIG		0x001958

/* Error codes for metadata transfer */
#define E_INVALID_COMMAND	0x00
#define E_INVALID_PARAM		0x01
#define E_PARAM_NOT_FOUND	0x02
#define E_INTERNAL		0x03
#define AVRCP_STATUS_SUCCESS 					0x04
#define AVRCP_STATUS_OUT_OF_BOUNDS 				0x0B
#define AVRCP_STATUS_INVALID_PLAYER_ID 			0x11
#define AVRCP_STATUS_PLAYER_NOT_BROWSABLE 		0x12
#define AVRCP_STATUS_NO_AVAILABLE_PLAYERS 		0x15
#define AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED 	0x16

/* Packet types */
#define AVRCP_PACKET_TYPE_SINGLE	0x00
#define AVRCP_PACKET_TYPE_START		0x01
#define AVRCP_PACKET_TYPE_CONTINUING	0x02
#define AVRCP_PACKET_TYPE_END		0x03

/* PDU types for metadata transfer */
#define AVRCP_GET_CAPABILITIES		0x10
#define AVRCP_LIST_PLAYER_ATTRIBUTES	0X11
#define AVRCP_LIST_PLAYER_VALUES	0x12
#define AVRCP_GET_CURRENT_PLAYER_VALUE	0x13
#define AVRCP_SET_PLAYER_VALUE		0x14
#define AVRCP_GET_PLAYER_ATTRIBUTE_TEXT	0x15
#define AVRCP_GET_PLAYER_VALUE_TEXT	0x16
#define AVRCP_DISPLAYABLE_CHARSET	0x17
#define AVRCP_CT_BATTERY_STATUS		0x18
#define AVRCP_GET_ELEMENT_ATTRIBUTES	0x20
#define AVRCP_GET_PLAY_STATUS		0x30
#define AVRCP_REGISTER_NOTIFICATION	0x31
#define AVRCP_REQUEST_CONTINUING	0x40
#define AVRCP_ABORT_CONTINUING		0x41
#define AVRCP_SET_ABSOLUTE_VOLUME	0x50
#define AVRCP_SET_BROWSED_PLAYER	0x70
#define AVRCP_GET_FOLDER_ITEMS		0x71
#define AVRCP_CHANGE_PATH			0x72
#define AVRCP_GET_ITEM_ATTRIBUTES	0x73
#define AVRCP_PLAY_ITEM				0x74
#define AVRCP_SEARCH				0x80
#define AVRCP_ADD_TO_NOW_PLAYING	0x90
#define AVRCP_GENERAL_REJECT		0xA0


/* Capabilities for AVRCP_GET_CAPABILITIES pdu */
#define CAP_COMPANY_ID		0x02
#define CAP_EVENTS_SUPPORTED	0x03

#define AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH 5
#define AVRCP_GET_CAPABILITIES_PARAM_LENGTH 1

#define AVRCP_FEATURE_CATEGORY_1	0x0001
#define AVRCP_FEATURE_CATEGORY_2	0x0002
#define AVRCP_FEATURE_CATEGORY_3	0x0004
#define AVRCP_FEATURE_CATEGORY_4	0x0008
#define AVRCP_FEATURE_PLAYER_SETTINGS	0x0010
#define AVRCP_FEATURE_BROWSING			0x0040

enum battery_status {
	BATTERY_STATUS_NORMAL =		0,
	BATTERY_STATUS_WARNING =	1,
	BATTERY_STATUS_CRITICAL =	2,
	BATTERY_STATUS_EXTERNAL =	3,
	BATTERY_STATUS_FULL_CHARGE =	4,
};

#define AVRCP_BROWSING_TIMEOUT		1

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t packet_type:2;
	uint8_t rsvd:6;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 7

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t rsvd:6;
	uint8_t packet_type:2;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 7

#else
#error "Unknown byte order"
#endif

#define AVRCP_MTU	(AVC_MTU - AVC_HEADER_LENGTH)
#define AVRCP_PDU_MTU	(AVRCP_MTU - AVRCP_HEADER_LENGTH)

struct avrcp_browsing_header {
	uint8_t pdu_id;
	uint16_t param_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_BROWSING_HEADER_LENGTH 3

struct avrcp_server {
	bdaddr_t src;
	uint32_t tg_record_id;
	uint32_t ct_record_id;
	GSList *players;
	GSList *media_players;
	struct avrcp_player *active_player;
	struct avrcp_player *ct_player; /* this will be active player now*/
	struct avctp *session;
	unsigned int browsing_timer;
};

struct pending_pdu {
	uint8_t pdu_id;
	GList *attr_ids;
	uint16_t offset;
};

struct pending_list_items {
	GSList *items;
	uint32_t start;
	uint32_t end;
};

struct avrcp_player {
	struct avrcp_server *server;
	struct avctp *session;
	struct audio_device *dev;

	unsigned int handler;
	uint16_t registered_events;
	uint8_t transaction_events[AVRCP_EVENT_LAST + 1];
	struct pending_pdu *pending_pdu;

	struct avrcp_player_cb *cb;
	void *user_data;
	GDestroyNotify destroy;
	uint16_t id;
	uint64_t uid;
	uint16_t uid_counter;
	bool browsed;
	bool browsable;
	uint8_t *features;
	char *path;
	uint8_t scope;
	struct pending_list_items *p;
	char *change_path;
};

struct avrcp_state_callback {
	avrcp_state_cb cb;
	void *user_data;
	unsigned int id;
};

static GSList *callbacks = NULL;
static GSList *servers = NULL;
static unsigned int avctp_id = 0;

/* Company IDs supported by this device */
static uint32_t company_ids[] = {
	IEEEID_BTSIG,
};

static void register_volume_notification(struct avrcp_player *player);
static void avrcp_register_notification(struct control *con, uint8_t event);
static void avrcp_get_element_attributes(struct avctp *session);
static void avrcp_connect_browsing(struct avrcp_server *server);
static struct avrcp_player *create_ct_player(struct avrcp_server *server,
								uint16_t id);
static void avrcp_get_media_player_list(struct avrcp_server *server);

static sdp_record_t *avrcp_ct_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *apseq1, *root;
	uuid_t root_uuid, l2cap, avctp, avrct, avrctr;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *aproto1, *proto[2], *proto1[2];
	sdp_record_t *record;
	sdp_data_t *psm[2], *version, *features;
	uint16_t lp = AVCTP_PSM, ap = AVCTP_BROWSING_PSM;
	uint16_t avrcp_ver = 0x0105, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
						AVRCP_FEATURE_CATEGORY_2 |
						AVRCP_FEATURE_CATEGORY_3 |
						AVRCP_FEATURE_CATEGORY_4 |
						AVRCP_FEATURE_BROWSING);

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrct, AV_REMOTE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &avrct);
	sdp_uuid16_create(&avrctr, AV_REMOTE_CONTROLLER_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &avrctr);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	psm[0] = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm[0]);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(NULL, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	/* Additional Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto1[0] = sdp_list_append(NULL, &l2cap);
	psm[1] = sdp_data_alloc(SDP_UINT16, &ap);
	proto1[0] = sdp_list_append(proto1[0], psm[1]);
	apseq1 = sdp_list_append(NULL, proto1[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto1[1] = sdp_list_append(NULL, &avctp);
	proto1[1] = sdp_list_append(proto1[1], version);
	apseq1 = sdp_list_append(apseq1, proto1[1]);

	aproto1 = sdp_list_append(NULL, apseq1);
	sdp_set_add_access_protos(record, aproto1);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP CT", NULL, NULL);

	free(psm[0]);
	free(psm[1]);
	free(version);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(proto1[0], NULL);
	sdp_list_free(proto1[1], NULL);
	sdp_list_free(aproto1, NULL);
	sdp_list_free(apseq1, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static sdp_record_t *avrcp_tg_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM;
	uint16_t avrcp_ver = 0x0104, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
					AVRCP_FEATURE_CATEGORY_2 |
					AVRCP_FEATURE_CATEGORY_3 |
					AVRCP_FEATURE_CATEGORY_4 |
					AVRCP_FEATURE_PLAYER_SETTINGS );

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static unsigned int attr_get_max_val(uint8_t attr)
{
	switch (attr) {
	case AVRCP_ATTRIBUTE_EQUALIZER:
		return AVRCP_EQUALIZER_ON;
	case AVRCP_ATTRIBUTE_REPEAT_MODE:
		return AVRCP_REPEAT_MODE_GROUP;
	case AVRCP_ATTRIBUTE_SHUFFLE:
		return AVRCP_SHUFFLE_GROUP;
	case AVRCP_ATTRIBUTE_SCAN:
		return AVRCP_SCAN_GROUP;
	}

	return 0;
}

static const char *battery_status_to_str(enum battery_status status)
{
	switch (status) {
	case BATTERY_STATUS_NORMAL:
		return "normal";
	case BATTERY_STATUS_WARNING:
		return "warning";
	case BATTERY_STATUS_CRITICAL:
		return "critical";
	case BATTERY_STATUS_EXTERNAL:
		return "external";
	case BATTERY_STATUS_FULL_CHARGE:
		return "fullcharge";
	}

	return NULL;
}

/*
 * get_company_id:
 *
 * Get three-byte Company_ID from incoming AVRCP message
 */
static uint32_t get_company_id(const uint8_t cid[3])
{
	return cid[0] << 16 | cid[1] << 8 | cid[2];
}

/*
 * set_company_id:
 *
 * Set three-byte Company_ID into outgoing AVRCP message
 */
static void set_company_id(uint8_t cid[3], const uint32_t cid_in)
{
	cid[0] = cid_in >> 16;
	cid[1] = cid_in >> 8;
	cid[2] = cid_in;
}

int avrcp_player_event(struct avrcp_player *player, uint8_t id, void *data)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t size;
	int err;

	if (player->session == NULL)
		return -ENOTCONN;

	if (!(player->registered_events & (1 << id)))
		return 0;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);

	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->params[0] = id;

	DBG("id=%u", id);

	switch (id) {
	case AVRCP_EVENT_STATUS_CHANGED:
		size = 2;
		pdu->params[1] = *((uint8_t *)data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		size = 9;
		memcpy(&pdu->params[1], data, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		size = 1;
		break;
	default:
		error("Unknown event %u", id);
		return -EINVAL;
	}

	pdu->params_len = htons(size);

	err = avctp_send_vendordep(player->session, player->transaction_events[id],
					AVC_CTYPE_CHANGED, AVC_SUBUNIT_PANEL,
					buf, size + AVRCP_HEADER_LENGTH);
	if (err < 0)
		return err;

	/* Unregister event as per AVRCP 1.3 spec, section 5.4.2 */
	player->registered_events ^= 1 << id;

	return 0;
}

static uint16_t player_write_media_attribute(struct avrcp_player *player,
						uint32_t id, uint8_t *buf,
						uint16_t *pos,
						uint16_t *offset)
{
	uint16_t len;
	uint16_t attr_len;
	char valstr[20];
	void *value;

	DBG("%u", id);

	value = player->cb->get_metadata(id, player->user_data);
	if (value == NULL) {
		*offset = 0;
		return 0;
	}

	switch (id) {
	case AVRCP_MEDIA_ATTRIBUTE_TRACK:
	case AVRCP_MEDIA_ATTRIBUTE_N_TRACKS:
	case AVRCP_MEDIA_ATTRIBUTE_DURATION:
		snprintf(valstr, 20, "%u", GPOINTER_TO_UINT(value));
		value = valstr;
		break;
	}

	attr_len = strlen(value);
	value = ((char *) value) + *offset;
	len = attr_len - *offset;

	if (len > AVRCP_PDU_MTU - *pos) {
		len = AVRCP_PDU_MTU - *pos;
		*offset += len;
	} else {
		*offset = 0;
	}

	memcpy(&buf[*pos], value, len);
	*pos += len;

	return attr_len;
}

static GList *player_fill_media_attribute(struct avrcp_player *player,
					GList *attr_ids, uint8_t *buf,
					uint16_t *pos, uint16_t *offset)
{
	struct media_attribute_header {
		uint32_t id;
		uint16_t charset;
		uint16_t len;
	} *hdr = NULL;
	GList *l;

	for (l = attr_ids; l != NULL; l = g_list_delete_link(l, l)) {
		uint32_t attr = GPOINTER_TO_UINT(l->data);
		uint16_t attr_len;

		if (*offset == 0) {
			if (*pos + sizeof(*hdr) >= AVRCP_PDU_MTU)
				break;

			hdr = (void *) &buf[*pos];
			hdr->id = htonl(attr);
			hdr->charset = htons(0x6A); /* Always use UTF-8 */
			*pos += sizeof(*hdr);
		}

		attr_len = player_write_media_attribute(player, attr, buf,
								pos, offset);

		if (hdr != NULL)
			hdr->len = htons(attr_len);

		if (*offset > 0)
			break;
	}

	return l;
}

static struct pending_pdu *pending_pdu_new(uint8_t pdu_id, GList *attr_ids,
							unsigned int offset)
{
	struct pending_pdu *pending = g_new(struct pending_pdu, 1);

	pending->pdu_id = pdu_id;
	pending->attr_ids = attr_ids;
	pending->offset = offset;

	return pending;
}

static gboolean player_abort_pending_pdu(struct avrcp_player *player)
{
	if (player->pending_pdu == NULL)
		return FALSE;

	g_list_free(player->pending_pdu->attr_ids);
	g_free(player->pending_pdu);
	player->pending_pdu = NULL;

	return TRUE;
}

static int player_set_attribute(struct avrcp_player *player,
						uint8_t attr, uint8_t val)
{
	DBG("Change attribute: %u %u", attr, val);

	return player->cb->set_setting(attr, val, player->user_data);
}

static int player_get_attribute(struct avrcp_player *player, uint8_t attr)
{
	int value;

	DBG("attr %u", attr);

	value = player->cb->get_setting(attr, player->user_data);
	if (value < 0)
		DBG("attr %u not supported by player", attr);

	return value;
}

static uint8_t avrcp_handle_get_capabilities(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 1)
		goto err;

	DBG("id=%u", pdu->params[0]);

	switch (pdu->params[0]) {
	case CAP_COMPANY_ID:
		for (i = 0; i < G_N_ELEMENTS(company_ids); i++) {
			set_company_id(&pdu->params[2 + i * 3],
							company_ids[i]);
		}

		pdu->params_len = htons(2 + (3 * G_N_ELEMENTS(company_ids)));
		pdu->params[1] = G_N_ELEMENTS(company_ids);

		return AVC_CTYPE_STABLE;
	case CAP_EVENTS_SUPPORTED:
		pdu->params[1] = 4;
		pdu->params[2] = AVRCP_EVENT_STATUS_CHANGED;
		pdu->params[3] = AVRCP_EVENT_TRACK_CHANGED;
		pdu->params[4] = AVRCP_EVENT_TRACK_REACHED_START;
		pdu->params[5] = AVRCP_EVENT_TRACK_REACHED_END;

		pdu->params_len = htons(2 + pdu->params[1]);
		return AVC_CTYPE_STABLE;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_list_player_attributes(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	if (!player)
		goto done;

	for (i = 1; i <= AVRCP_ATTRIBUTE_SCAN; i++) {
		if (player_get_attribute(player, i) < 0)
			continue;

		len++;
		pdu->params[len] = i;
	}

done:
	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_list_player_values(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 1 || !player)
		goto err;

	if (player_get_attribute(player, pdu->params[0]) < 0)
		goto err;

	len = attr_get_max_val(pdu->params[0]);

	for (i = 1; i <= len; i++)
		pdu->params[i] = i;

	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_element_attributes(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint64_t *identifier = (uint64_t *) &pdu->params[0];
	uint16_t pos;
	uint8_t nattr;
	GList *attr_ids;
	uint16_t offset;

	if (len < 9 || *identifier != 0)
		goto err;

	nattr = pdu->params[8];

	if (len < nattr * sizeof(uint32_t) + 1)
		goto err;

	if (!nattr) {
		/*
		 * Return all available information, at least
		 * title must be returned if there's a track selected.
		 */
		attr_ids = player->cb->list_metadata(player->user_data);
		len = g_list_length(attr_ids);
	} else {
		unsigned int i;
		uint32_t *attr = (uint32_t *) &pdu->params[9];

		for (i = 0, len = 0, attr_ids = NULL; i < nattr; i++, attr++) {
			uint32_t id = ntohl(bt_get_unaligned(attr));

			/* Don't add invalid attributes */
			if (id == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL ||
					id > AVRCP_MEDIA_ATTRIBUTE_LAST)
				continue;

			len++;
			attr_ids = g_list_prepend(attr_ids,
							GUINT_TO_POINTER(id));
		}

		attr_ids = g_list_reverse(attr_ids);
	}

	if (!len)
		goto err;

	player_abort_pending_pdu(player);
	pos = 1;
	offset = 0;
	attr_ids = player_fill_media_attribute(player, attr_ids, pdu->params,
								&pos, &offset);

	if (attr_ids != NULL) {
		player->pending_pdu = pending_pdu_new(pdu->pdu_id, attr_ids,
								offset);
		pdu->packet_type = AVRCP_PACKET_TYPE_START;
	}

	pdu->params[0] = len;
	pdu->params_len = htons(pos);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_current_player_value(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint8_t *settings;
	unsigned int i;

	if (player == NULL || len <= 1 || pdu->params[0] != len - 1)
		goto err;

	/*
	 * Save a copy of requested settings because we can override them
	 * while responding
	 */
	settings = g_memdup(&pdu->params[1], pdu->params[0]);
	len = 0;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and send a response with the existent ones. Only if all IDs are
	 * non-existent we should send an error.
	 */
	for (i = 0; i < pdu->params[0]; i++) {
		int val;

		if (settings[i] < AVRCP_ATTRIBUTE_EQUALIZER ||
					settings[i] > AVRCP_ATTRIBUTE_SCAN) {
			DBG("Ignoring %u", settings[i]);
			continue;
		}

		val = player_get_attribute(player, settings[i]);
		if (val < 0)
			continue;

		pdu->params[++len] = settings[i];
		pdu->params[++len] = val;
	}

	g_free(settings);

	if (len) {
		pdu->params[0] = len / 2;
		pdu->params_len = htons(len + 1);

		return AVC_CTYPE_STABLE;
	}

	error("No valid attributes in request");

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_set_player_value(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;
	uint8_t *param;

	if (len < 3 || len > 2 * pdu->params[0] + 1U)
		goto err;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and set the existent ones. Sec. 5.2.4 is not clear however how to
	 * indicate that a certain ID was not accepted. If at least one
	 * attribute is valid, we respond with no parameters. Otherwise an
	 * E_INVALID_PARAM is sent.
	 */
	for (len = 0, i = 0, param = &pdu->params[1]; i < pdu->params[0];
							i++, param += 2) {
		if (player_set_attribute(player, param[0], param[1]) < 0)
			continue;

		len++;
	}

	if (len) {
		pdu->params_len = 0;

		return AVC_CTYPE_ACCEPTED;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_displayable_charset(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);

	if (len < 3) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	/*
	 * We acknowledge the commands, but we always use UTF-8 for
	 * encoding since CT is obliged to support it.
	 */
	pdu->params_len = 0;
	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_ct_battery_status(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	const char *valstr;

	if (len != 1)
		goto err;

	valstr = battery_status_to_str(pdu->params[0]);
	if (valstr == NULL)
		goto err;

	pdu->params_len = 0;

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_play_status(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint32_t position;
	uint32_t duration;
	void *pduration;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	position = player->cb->get_position(player->user_data);
	pduration = player->cb->get_metadata(AVRCP_MEDIA_ATTRIBUTE_DURATION,
							player->user_data);
	if (pduration != NULL)
		duration = htonl(GPOINTER_TO_UINT(pduration));
	else
		duration = htonl(UINT32_MAX);

	position = htonl(position);

	memcpy(&pdu->params[0], &duration, 4);
	memcpy(&pdu->params[4], &position, 4);
	pdu->params[8] = player->cb->get_status(player->user_data);;

	pdu->params_len = htons(9);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_register_notification(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint64_t uid;

	/*
	 * 1 byte for EventID, 4 bytes for Playback interval but the latest
	 * one is applicable only for EVENT_PLAYBACK_POS_CHANGED. See AVRCP
	 * 1.3 spec, section 5.4.2.
	 */
	if (len != 5)
		goto err;

	switch (pdu->params[0]) {
	case AVRCP_EVENT_STATUS_CHANGED:
		len = 2;
		pdu->params[1] = player->cb->get_status(player->user_data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		len = 9;
		uid = player->cb->get_uid(player->user_data);
		memcpy(&pdu->params[1], &uid, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		len = 1;
		break;
	default:
		/* All other events are not supported yet */
		goto err;
	}

	/* Register event and save the transaction used */
	player->registered_events |= (1 << pdu->params[0]);
	player->transaction_events[pdu->params[0]] = transaction;

	pdu->params_len = htons(len);

	return AVC_CTYPE_INTERIM;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_request_continuing(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || player->pending_pdu == NULL)
		goto err;

	pending = player->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;


	len = 0;
	pending->attr_ids = player_fill_media_attribute(player,
							pending->attr_ids,
							pdu->params, &len,
							&pending->offset);
	pdu->pdu_id = pending->pdu_id;

	if (pending->attr_ids == NULL) {
		g_free(player->pending_pdu);
		player->pending_pdu = NULL;
		pdu->packet_type = AVRCP_PACKET_TYPE_END;
	} else {
		pdu->packet_type = AVRCP_PACKET_TYPE_CONTINUING;
	}

	pdu->params_len = htons(len);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_abort_continuing(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || player->pending_pdu == NULL)
		goto err;

	pending = player->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;

	player_abort_pending_pdu(player);
	pdu->params_len = 0;

	return AVC_CTYPE_ACCEPTED;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static struct pdu_handler {
	uint8_t pdu_id;
	uint8_t code;
	uint8_t (*func) (struct avrcp_player *player,
					struct avrcp_header *pdu,
					uint8_t transaction);
} handlers[] = {
		{ AVRCP_GET_CAPABILITIES, AVC_CTYPE_STATUS,
					avrcp_handle_get_capabilities },
		{ AVRCP_LIST_PLAYER_ATTRIBUTES, AVC_CTYPE_STATUS,
					avrcp_handle_list_player_attributes },
		{ AVRCP_LIST_PLAYER_VALUES, AVC_CTYPE_STATUS,
					avrcp_handle_list_player_values },
		{ AVRCP_GET_ELEMENT_ATTRIBUTES, AVC_CTYPE_STATUS,
					avrcp_handle_get_element_attributes },
		{ AVRCP_GET_CURRENT_PLAYER_VALUE, AVC_CTYPE_STATUS,
					avrcp_handle_get_current_player_value },
		{ AVRCP_SET_PLAYER_VALUE, AVC_CTYPE_CONTROL,
					avrcp_handle_set_player_value },
		{ AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, AVC_CTYPE_STATUS,
					NULL },
		{ AVRCP_GET_PLAYER_VALUE_TEXT, AVC_CTYPE_STATUS,
					NULL },
		{ AVRCP_DISPLAYABLE_CHARSET, AVC_CTYPE_STATUS,
					avrcp_handle_displayable_charset },
		{ AVRCP_CT_BATTERY_STATUS, AVC_CTYPE_STATUS,
					avrcp_handle_ct_battery_status },
		{ AVRCP_GET_PLAY_STATUS, AVC_CTYPE_STATUS,
					avrcp_handle_get_play_status },
		{ AVRCP_REGISTER_NOTIFICATION, AVC_CTYPE_NOTIFY,
					avrcp_handle_register_notification },
		{ AVRCP_REQUEST_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_request_continuing },
		{ AVRCP_ABORT_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_abort_continuing },
		{ },
};

/* handle vendordep pdu inside an avctp packet */
static size_t handle_vendordep_pdu(struct avctp *session, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	struct pdu_handler *handler;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = get_company_id(pdu->company_id);

	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, company 0x%06X len 0x%04X",
			pdu->pdu_id, company_id, pdu->params_len);

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (operand_count < AVRCP_HEADER_LENGTH) {
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

	for (handler = handlers; handler; handler++) {
		if (handler->pdu_id == pdu->pdu_id)
			break;
	}

	if (!handler || handler->code != *code) {
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

	if (!handler->func) {
		pdu->params[0] = E_INVALID_PARAM;
		goto err_metadata;
	}

	*code = handler->func(player, pdu, transaction);

	if (*code != AVC_CTYPE_REJECTED &&
				pdu->pdu_id != AVRCP_GET_ELEMENT_ATTRIBUTES &&
				pdu->pdu_id != AVRCP_REQUEST_CONTINUING &&
				pdu->pdu_id != AVRCP_ABORT_CONTINUING)
		player_abort_pending_pdu(player);

	return AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

err_metadata:
	pdu->params_len = htons(1);
	*code = AVC_CTYPE_REJECTED;

	return AVRCP_HEADER_LENGTH + 1;
}

size_t avrcp_handle_vendor_reject(uint8_t *code, uint8_t *operands)
{
    struct avrcp_header *pdu = (void *) operands;
    uint32_t company_id = get_company_id(pdu->company_id);

    *code = AVC_CTYPE_REJECTED;
    pdu->params_len = htons(1);
    pdu->params[0] = E_INTERNAL;

    DBG("rejecting AVRCP PDU 0x%02X, company 0x%06X len 0x%04X",
            pdu->pdu_id, company_id, pdu->params_len);

    return AVRCP_HEADER_LENGTH + 1;
}

static struct avrcp_server *find_server(GSList *list, const bdaddr_t *src)
{
	for (; list; list = list->next) {
		struct avrcp_server *server = list->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

static gboolean avrcp_handle_volume_changed(struct avctp *session,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t volume;

	if (code != AVC_CTYPE_INTERIM && code != AVC_CTYPE_CHANGED)
		return FALSE;

	volume = pdu->params[1] & 0x7F;

	player->cb->set_volume(volume, player->dev, player->user_data);

	if (code == AVC_CTYPE_CHANGED) {
		register_volume_notification(player);
		return FALSE;
	}

	return TRUE;
}

static void register_volume_notification(struct avrcp_player *player)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = AVRCP_EVENT_VOLUME_CHANGED;
	pdu->params_len = htons(AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(player->session, AVC_CTYPE_NOTIFY,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_handle_volume_changed, player);
}

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct avctp *session;
	const sdp_record_t *rec;
	sdp_list_t *list;
	sdp_profile_desc_t *desc;
	sdp_data_t *data;
	
	uint16_t features;

	
	server = find_server(servers, &dev->src);
	if (!server)
		return;

/*	player = server->active_player;
	if (!player)
		return;
*/
	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
	//media_player_destroy(server->ct_player->user_data);
	
	if(!server->ct_player)
		return;
	
	server->ct_player->dev = dev;
	while(server->ct_player)
		avrcp_unregister_player(server->ct_player);
	server->session = NULL;
	
		/*player->session = NULL;
		player->dev = NULL;
		player->registered_events = 0;

		if (player->handler) {
			avctp_unregister_pdu_handler(player->handler);
			player->handler = 0;
		}*/

		break;
	case AVCTP_STATE_CONNECTING:
		DBG("AVRCP Connecting");
		//avrcp_get_capabilities(dev);
/*
		player->session = avctp_connect(&dev->src, &dev->dst);
		player->dev = dev;

		if (!player->handler)
			player->handler = avctp_register_pdu_handler(
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							player);
*/
		break;
	case AVCTP_STATE_CONNECTED:
		DBG("AVRCP Connected");
			
		/* 
		 * This callback gets called when the avctp layer gets 
		 * connected regardless if the host or device initiated the 
		 * connection. This check is to make sure the avrcp server 
		 * object's session member is initialized 
		 */	
		if(!server->session){
			session = avctp_connect(&dev->src, &dev->dst);			
			if(session) {
				server->session = session;
			}	
		}
		
		rec = btd_device_get_record(dev->btd_dev, AVRCP_TARGET_UUID);
		if (rec == NULL)
			return;

		if (sdp_get_profile_descs(rec, &list) < 0)
			return;

		desc = list->data;

		if (desc && desc->version >= 0x0104){
			;
			//register_volume_notification(player);
		}
				
		data = sdp_data_get(rec, SDP_ATTR_SUPPORTED_FEATURES);
		features = data->val.uint16;
		
		/* Only create player if category 1 is supported */
		if (desc && (features & AVRCP_FEATURE_CATEGORY_1)){
			player = create_ct_player(server, 0);
			if (player == NULL){
				sdp_list_free(list, free);
				return;
			}
		}
		
		if(desc && (features & AVRCP_FEATURE_BROWSING)){
			/* TODO call avrcp_connect_browser here */
			/* this expects avrcp struct as parameter */
			avrcp_connect_browsing(server);
		}
		sdp_list_free(list, free);
		return;
		
	case AVCTP_STATE_BROWSING_CONNECTED:
		if (server->browsing_timer > 0) {
			g_source_remove(server->browsing_timer);
			server->browsing_timer = 0;			
			//avctp_connect_browsing(session->conn);
		}
		DBG("AVCTP_STATE_BROWSING_CONNECTED");
		return;
	default:
		return;
	}
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct avrcp_server *server;
	struct avctp *session;

	DBG("Connecting to avrcp...");
	server = find_server(servers, &dev->src);
	if (server == NULL){
		DBG("Server not found");
		return FALSE;
	}
			
	session = avctp_connect(&dev->src, &dev->dst);
	if (!session){
		DBG("Connecting to avrcp failed");
		return FALSE;
	}
	
	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct avctp *session;

	session = avctp_get(&dev->src, &dev->dst);
	if (!session)
		return;

	avctp_disconnect(session);
}
/*
static struct avrcp_player_cb ct_player_cb = {
	.get_setting = ct_get_setting,
	.set_setting = ct_set_setting,
	.list_metadata = ct_list_metadata,
	.get_uid = ct_get_uid,
	.get_metadata = ct_get_metadata,
	.get_position = ct_get_position,
	.get_status = ct_get_status,
	.set_volume = ct_set_volume
};
*/

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;
	struct avrcp_server *server;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
	}

	server = g_new0(struct avrcp_server, 1);
	if (!server)
		return -ENOMEM;

	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP target service record");
		g_free(server);
		sdp_record_free(record);
		return -1;
	}
	server->tg_record_id = record->handle;

	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP service record");
		sdp_record_free(record);
		g_free(server);
		return -1;
	}
	server->ct_record_id = record->handle;

	if (avctp_register(src, master) < 0) {
		remove_record_from_server(server->ct_record_id);
		remove_record_from_server(server->tg_record_id);
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);
	
	if(server->ct_record_id){
		DBG("TODO Create controller player");
		//server->ct_player = avrcp_register_player(&server->src, NULL, server, NULL);
		
	}
	
	/* Add a listener for avctp state changes */
	if (!avctp_id) {
		avctp_id = avctp_add_state_cb(state_changed, NULL);
	}

	servers = g_slist_append(servers, server);

	return 0;
}

static void player_destroy(gpointer data)
{
	struct avrcp_player *player = data;
	DBG("Destroy player");
	if (player->destroy)
		player->destroy(player->user_data);

	player_abort_pending_pdu(player);

	if (player->handler)
		avctp_unregister_pdu_handler(player->handler);

	g_free(player);
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avrcp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	g_slist_free_full(server->players, player_destroy);

	servers = g_slist_remove(servers, server);

	remove_record_from_server(server->ct_record_id);
	remove_record_from_server(server->tg_record_id);

	avctp_unregister(&server->src);
	g_free(server);

	if (servers)
		return;

	if (avctp_id) {
		avctp_remove_state_cb(avctp_id);
		avctp_id = 0;
	}
}

struct avrcp_player *avrcp_register_player(const bdaddr_t *src,
						struct avrcp_player_cb *cb,
						void *user_data,
						GDestroyNotify destroy)
{
	struct avrcp_server *server;
	struct avrcp_player *player;

	server = find_server(servers, src);
	if (!server)
		return NULL;

	player = g_new0(struct avrcp_player, 1);
	player->server = server;
	player->cb = cb;
	player->user_data = user_data;
	player->destroy = destroy;

	if (!server->players){
		server->ct_player = player;
		server->active_player = player;
	}

	if (!avctp_id)
		avctp_id = avctp_add_state_cb(state_changed, NULL);
	DBG("Adding player to players");
	server->players = g_slist_append(server->players, player);

	return player;
}

void avrcp_unregister_player(struct avrcp_player *player)
{
	struct avrcp_server *server = player->server;

	server->players = g_slist_remove(server->players, player);

	if (server->ct_player == player)
		server->ct_player = g_slist_nth_data(server->players, 0);

	player_destroy(player);
}

static gboolean avrcp_handle_set_volume(struct avctp *session,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t volume;

	if (code == AVC_CTYPE_REJECTED || code == AVC_CTYPE_NOT_IMPLEMENTED)
		return FALSE;

	volume = pdu->params[0] & 0x7F;

	player->cb->set_volume(volume, player->dev, player->user_data);

	return FALSE;
}

int avrcp_set_volume(struct audio_device *dev, uint8_t volume)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	uint8_t buf[AVRCP_HEADER_LENGTH + 1];
	struct avrcp_header *pdu = (void *) buf;

	server = find_server(servers, &dev->src);
	if (server == NULL)
		return -EINVAL;

	player = server->active_player;
	if (player == NULL)
		return -ENOTSUP;

	if (player->session == NULL)
		return -ENOTCONN;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);

	pdu->pdu_id = AVRCP_SET_ABSOLUTE_VOLUME;
	pdu->params[0] = volume;
	pdu->params_len = htons(1);

	DBG("volume=%u", volume);

	return avctp_send_vendordep_req(player->session, AVC_CTYPE_CONTROL,
					AVC_SUBUNIT_PANEL, buf, sizeof(buf),
					avrcp_handle_set_volume, player);
}

static const char *status_to_string(uint8_t status)
{
	switch (status) {
	case AVRCP_PLAY_STATUS_STOPPED:
		return "stopped";
	case AVRCP_PLAY_STATUS_PLAYING:
		return "playing";
	case AVRCP_PLAY_STATUS_PAUSED:
		return "paused";
	case AVRCP_PLAY_STATUS_FWD_SEEK:
		return "forward-seek";
	case AVRCP_PLAY_STATUS_REV_SEEK:
		return "reverse-seek";
	case AVRCP_PLAY_STATUS_ERROR:
		return "error";
	default:
		return NULL;
	}
}

static gboolean avrcp_get_play_status_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avctp *session = user_data;
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct media_player *mp;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t duration;
	uint32_t position;
	uint8_t status;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;
	mp = player->user_data;

	if (pdu == NULL || code == AVC_CTYPE_REJECTED ||
						ntohs(pdu->params_len) != 9)
		return FALSE;

	memcpy(&duration, pdu->params, sizeof(uint32_t));
	duration = ntohl(duration);
	media_player_set_duration(mp, duration);

	memcpy(&position, pdu->params + 4, sizeof(uint32_t));
	position = ntohl(position);
	media_player_set_position(mp, position);

	memcpy(&status, pdu->params + 8, sizeof(uint8_t));
	media_player_set_status(mp, status_to_string(status));

	return FALSE;
}

static void avrcp_get_play_status(struct avctp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH];
	struct avrcp_header *pdu = (void *) buf;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_PLAY_STATUS;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	avctp_send_vendordep_req(session, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, sizeof(buf),
					avrcp_get_play_status_rsp,
					session);
}

static gboolean avrcp_get_capabilities_resp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct control *control_ptr = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint16_t events = 0;
	uint8_t count;

	if (pdu == NULL || pdu->params[0] != CAP_EVENTS_SUPPORTED)
		return FALSE;
	DBG("get capabilities response");

	count = pdu->params[1];

	for (; count > 0; count--) {
		uint8_t event = pdu->params[1 + count];

		events |= (1 << event);

		switch (event) {
		case AVRCP_EVENT_STATUS_CHANGED:
		case AVRCP_EVENT_TRACK_CHANGED:
		case AVRCP_EVENT_SETTINGS_CHANGED:
		case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
		case AVRCP_EVENT_UIDS_CHANGED:
		case AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED:
		//case AVRCP_EVENT_VOLUME_CHANGED:
			DBG("Event Supported: %d", event);
			avrcp_register_notification(control_ptr, event);
			break;
		}
	}
	
	//if (!(events & (1 << AVRCP_EVENT_SETTINGS_CHANGED)))
	//	avrcp_list_player_attributes(conn);

	if (!(events & (1 << AVRCP_EVENT_STATUS_CHANGED)))
		avrcp_get_play_status(conn);
    
	if (!(events & (1 << AVRCP_EVENT_STATUS_CHANGED)))
		avrcp_get_element_attributes(conn);

	return TRUE;
}
 
void avrcp_get_capabilities(struct control *con)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + AVRCP_GET_CAPABILITIES_PARAM_LENGTH];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;
	

	if (con->session == NULL)
		return;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_CAPABILITIES;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = CAP_EVENTS_SUPPORTED;
	pdu->params_len = htons(AVRCP_GET_CAPABILITIES_PARAM_LENGTH);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);
	DBG("Getting caps for session: %p", con->session);
	avctp_send_vendordep_req(con->session, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_get_capabilities_resp,
					con);
}

static gboolean connect_browsing(gpointer user_data)
{
	struct avrcp_server *server = user_data;

	server->browsing_timer = 0;

	avctp_connect_browsing(server->session);

	return FALSE;
}


static void avrcp_connect_browsing(struct avrcp_server *server)
{
	/* Immediately connect browsing channel if initiator otherwise delay
	 * it to avoid possible collisions
	 */
	if (avctp_is_initiator(server->session)) {
		avctp_connect_browsing(server->session);
		return;
	}

	/* this gets done when this is not the initiator */
	/* comment out for now */
	if (server->browsing_timer > 0)
		return;

	DBG("Delaying connect_browsing call for %d sec",AVRCP_BROWSING_TIMEOUT);
	server->browsing_timer = g_timeout_add_seconds(AVRCP_BROWSING_TIMEOUT,
							connect_browsing,
							server);

}

static const char *metadata_to_str(uint32_t id)
{
	switch (id) {
	case AVRCP_MEDIA_ATTRIBUTE_TITLE:
		return "Title";
	case AVRCP_MEDIA_ATTRIBUTE_ARTIST:
		return "Artist";
	case AVRCP_MEDIA_ATTRIBUTE_ALBUM:
		return "Album";
	case AVRCP_MEDIA_ATTRIBUTE_GENRE:
		return "Genre";
	case AVRCP_MEDIA_ATTRIBUTE_TRACK:
		return "TrackNumber";
	case AVRCP_MEDIA_ATTRIBUTE_N_TRACKS:
		return "NumberOfTracks";
	case AVRCP_MEDIA_ATTRIBUTE_DURATION:
		return "Duration";
	}

	return NULL;
}

void set_metadata(struct control *con,
				const char *key,
				void *data, size_t len)
{
	char *value, *curval;

	value = g_strndup(data, len);

	DBG("%s: %s", key, value);
	if(con->metadata == NULL){
		return;
	}
	curval = g_hash_table_lookup(con->metadata, key);
	if (g_strcmp0(curval, value) == 0) {
		g_free(value);
		return;
	}

	g_hash_table_replace(con->metadata, g_strdup(key), value);
}

static void avrcp_parse_attribute_list(struct avrcp_player *player,
					uint8_t *operands, uint8_t count)
{
	struct media_player *mp = player->user_data;
	struct media_item *item;
	int i;

	item = media_player_set_playlist_item(mp, player->uid);

	for (i = 0; count > 0; count--) {
		uint32_t id;
		uint16_t charset, len;

		id = bt_get_be32(&operands[i]);
		i += sizeof(uint32_t);

		charset = bt_get_be16(&operands[i]);
		i += sizeof(uint16_t);

		len = bt_get_be16(&operands[i]);
		i += sizeof(uint16_t);

		if (charset == 106) {
			const char *key = metadata_to_str(id);

			if (key != NULL)
				media_player_set_metadata(mp, item,
							metadata_to_str(id),
							&operands[i], len);
		}

		i += len;
	}
}

static gboolean avrcp_get_element_attributes_rsp(struct avctp *session,
						uint8_t code, uint8_t subunit,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct avctp *con = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t count;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	if (code == AVC_CTYPE_REJECTED)
		return FALSE;

	count = pdu->params[0];

	if (ntohs(pdu->params_len) - 1 < count * 8) {
		error("Invalid parameters");
		return FALSE;
	}

	avrcp_parse_attribute_list(player, &pdu->params[1], count);

	avrcp_get_play_status(session);

	return FALSE;
}

static void avrcp_get_element_attributes(struct avctp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_ELEMENT_ATTRIBUTES;
	pdu->params_len = htons(9);
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_get_element_attributes_rsp,
					session);
}

static const char *type_to_string(uint8_t type)
{
	switch(type & 0x0F) {
		case 0x01:
			return "Audio";
		case 0x02:
			return "Video";
		case 0x03:
			return "Audio, Video";
		case 0x04:
			return "Audio Broadcasting";
		case 0x05:
			return "Audio, Audio Broadcasting";
		case 0x06:
			return "Video, Audio Broadcasting";
		case 0x07:
			return "Audio, Video, Audio Broadcasting";
		case 0x08:
			return "Video Broadcasting";
		case 0x09:
			return "Audio, Video Broadcasting";
		case 0x0A:
			return "Video, Video Broadcasting";
		case 0x0B:
			return "Audio, Video, Video Broadcasting";
		case 0x0C:
			return "Audio Broadcasting, Video Broadcasting";
		case 0x0D:
			return "Audio, Audio Broadcasting, Video Broadcasting";
		case 0x0E:
			return "Video, Audio Broadcasting, Video Broadcasting";
		case 0x0F:
			return "Audio, Video, Audio Broadcasting, Video Broadcasting";
			
	}
	return "None";
}

static const char *subtype_to_string(uint32_t subtype)
{
	switch (subtype & 0x03) {
		case 0x01:
			return "Audio Book";
		case 0x02:
			return "Podcast";
		case 0x03:
			return "Audio Book, Podcast";
	}
	return "None";
}

static void avrcp_player_parse_features(struct avrcp_player *player, uint8_t * features)
{
	struct media_player *mp = player->user_data;
	
	player->features = g_memdup(features, 16);
	
	if (features[7] & 0x08) {
		DBG("Media player browsable is supported");
		media_player_set_browsable(mp, true);
		media_player_create_folder(mp, "/Filesystem",
						PLAYER_FOLDER_TYPE_MIXED, 0);
		player->browsable = true;
	}

	if (features[7] & 0x10) {
		DBG("Media player searchable is supported");
		media_player_set_searchable(mp, true);
	}

	if (features[8] & 0x02) {
		DBG("Media player now playing folder is supported");
		media_player_create_folder(mp, "/NowPlaying",
						PLAYER_FOLDER_TYPE_MIXED, 0);
		media_player_set_playlist(mp, "/NowPlaying");
	}
}

static struct media_item *parse_media_element(struct avrcp_server *server,
					uint8_t *operands, uint16_t len)
{
	struct avrcp_player *player;
	struct media_player *mp;
	struct media_item *item;
	uint16_t namelen;
	char name[255];
	uint64_t uid;

	if (len < 13)
		return NULL;

	uid = bt_get_be64(&operands[0]);

	namelen = MIN(bt_get_be16(&operands[11]), sizeof(name) - 1);
	if (namelen > 0) {
		memcpy(name, &operands[13], namelen);
		name[namelen] = '\0';
	}

	player = server->ct_player;
	mp = player->user_data;

	item = media_player_create_item(mp, name, PLAYER_ITEM_TYPE_AUDIO, uid);
	if (item == NULL)
		return NULL;

	media_item_set_playable(item, true);

	return item;
}

static void *parse_media_folder(struct avrcp_server *server,
					uint8_t *operands, uint16_t len)
{
	struct avrcp_player *player = server->ct_player;
	struct media_player *mp = player->user_data;
	struct media_item *item;
	uint16_t namelen;
	char name[255];
	uint64_t uid;
	uint8_t type;
	uint8_t playable;

	if (len < 12)
		return NULL;

	uid = bt_get_be64(&operands[0]);
	type = operands[8];
	playable = operands[9];

	namelen = MIN(bt_get_be16(&operands[12]), sizeof(name) - 1);
	if (namelen > 0) {
		memcpy(name, &operands[14], namelen);
		name[namelen] = '\0';
		DBG("Folder item (%08llu): %s",uid, name);
	}
	item = NULL;
	DBG("mp: %p", mp);
	DBG("uid: %llu", uid);
	item = media_player_create_folder(mp, name, type, uid);
	if (!item)
		return NULL;

	media_item_set_playable(item, playable & 0x01);

	return item;
}

static void avrcp_list_items(struct avctp *session, uint32_t start,
								uint32_t end);

static gboolean avrcp_list_items_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	struct avctp *session = user_data;
	struct avrcp_server *server;
	struct pending_list_items *p;
	struct avrcp_player *player;
	uint16_t count;
	uint32_t items, total;
	size_t i;
	int err = 0;
	
	/* get server here */	
	server = find_server(servers, avctp_get_src(session));
	if(!server){
		goto done;
	}
	player = server->ct_player;
	p = player->p;

	if (pdu == NULL) {
		err = -ETIMEDOUT;
		goto done;
	}

	/* AVRCP 1.5 - Page 76:
	 * If the TG receives a GetFolderItems command for an empty folder then
	 * the TG shall return the error (= Range Out of Bounds) in the status
	 * field of the GetFolderItems response.
	 */
	if (pdu->params[0] == AVRCP_STATUS_OUT_OF_BOUNDS)
		goto done;

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 5) {
		err = -EINVAL;
		goto done;
	}

	count = bt_get_be16(&operands[6]);
	if (count == 0)
		goto done;

	for (i = 8; count && i + 3 < operand_count; count--) {
		struct media_item *item;
		uint8_t type;
		uint16_t len;

		type = operands[i++];
		len = bt_get_be16(&operands[i]);
		i += 2;

		if (type != 0x03 && type != 0x02) {
			i += len;
			continue;
		}

		if (i + len > operand_count) {
			error("Invalid item length");
			break;
		}

		if (type == 0x03)
			//item = parse_media_element(session, &operands[i], len);
			item = parse_media_element(server, &operands[i], len);
		else
			item = parse_media_folder(server, &operands[i], len);

		if (item) {
			if (g_slist_find(p->items, item))
				goto done;
			p->items = g_slist_append(p->items, item);
		}

		i += len;
	}

	items = g_slist_length(p->items);
	total = p->end - p->start;
	if (items < total) {
		avrcp_list_items(conn, p->start + items + 1, p->end);
		return FALSE;
	}

done:
	media_player_list_complete(player->user_data, p->items, err);

	g_slist_free(p->items);
	g_free(p);
	player->p = NULL;

	return FALSE;
}

static void avrcp_list_items(struct avctp *session, uint32_t start,
								uint32_t end)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 10 +
			AVRCP_MEDIA_ATTRIBUTE_LAST * sizeof(uint32_t)];
	struct avrcp_player *player;
	struct avrcp_server *server;
	struct avrcp_browsing_header *pdu = (void *) buf;
	uint16_t length = AVRCP_BROWSING_HEADER_LENGTH + 10;
	uint32_t attribute;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_GET_FOLDER_ITEMS;
	pdu->param_len = htons(10 + sizeof(uint32_t));

	pdu->params[0] = player->scope;

	bt_put_be32(start, &pdu->params[1]);
	bt_put_be32(end, &pdu->params[5]);

	pdu->params[9] = 1;

	/* Only the title (0x01) is mandatory. This can be extended to
	 * support AVRCP_MEDIA_ATTRIBUTE_* attributes */
	attribute = htonl(AVRCP_MEDIA_ATTRIBUTE_TITLE);
	memcpy(&pdu->params[10], &attribute, sizeof(uint32_t));

	length += sizeof(uint32_t);

	avctp_send_browsing_req(session, buf, length,
					avrcp_list_items_rsp, session);
}

static const char * avrcp_status_to_str(uint8_t status)
{
	switch(status){
		case AVRCP_STATUS_SUCCESS: return "AVRCP_STATUS_SUCCESS";
		case AVRCP_STATUS_OUT_OF_BOUNDS: return "AVRCP_STATUS_OUT_OF_BOUNDS";
		case AVRCP_STATUS_INVALID_PLAYER_ID: return "AVRCP_STATUS_INVALID_PLAYER_ID";	
		case AVRCP_STATUS_PLAYER_NOT_BROWSABLE: return "AVRCP_STATUS_PLAYER_NOT_BROWSABLE";
		case AVRCP_STATUS_NO_AVAILABLE_PLAYERS: return "AVRCP_STATUS_NO_AVAILABLE_PLAYERS";
		case AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED: return "AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED";
		default: return "Unknown Error";
	}
}

static gboolean avrcp_set_browsed_player_rsp(struct avctp *conn,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	//struct avctp *session = user_data;
	struct avrcp_player *player = user_data;
	struct media_player *mp = player->user_data;
	struct avrcp_browsing_header *pdu = (void *) operands;
	uint32_t items;
	char **folders;
	uint8_t depth, count;
	size_t i;
	char name[255];

	if (pdu == NULL || pdu->params[0] != AVRCP_STATUS_SUCCESS ||
							operand_count < 13){
		DBG("Set Browsed error: %s", avrcp_status_to_str(pdu->params[0]));						
		return FALSE;
	}
	
	player->uid_counter = bt_get_be16(&pdu->params[1]);
	player->browsed = true;

	DBG("Set Browsed reply received");
	items = bt_get_be32(&pdu->params[3]);
	DBG("Media Player Number of items: %lu", (unsigned long)items);
	depth = pdu->params[9];
	DBG("Media Player depth: %d", depth);
	
	folders = g_new0(char *, depth + 2);
	folders[0] = g_strdup("/Filesystem");
	
	memset(name,0,255);
	for (i = 10, count = 1; count - 1 < depth && i < operand_count;
								count++) {
		uint8_t len;

		len = pdu->params[i++];

		if (i + len > operand_count || len == 0) {
			error("Invalid folder length");
			break;
		}

		memcpy(name,&pdu->params[i],len);
		DBG("Media Player Folder name: %s", name);
		folders[count] = g_memdup(&pdu->params[i], len);
		i += len;
	}
	
	player->path = g_build_pathv("/", folders);
	g_strfreev(folders);
	
	media_player_set_folder(mp, player->path, items);
	
	return FALSE;
}

static void avrcp_set_browsed_player(struct avctp *session,
						struct avrcp_player *player)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 2];
	struct avrcp_browsing_header *pdu = (void *) buf;
	uint16_t id;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_SET_BROWSED_PLAYER;
	id = htons(player->id);
	memcpy(pdu->params, &id, 2);
	pdu->param_len = htons(2);

	avctp_send_browsing_req(session, buf, sizeof(buf),
				avrcp_set_browsed_player_rsp, player);
}

static int ct_list_items(struct media_player *mp, const char *name,
				uint32_t start, uint32_t end, void *user_data)
{
	struct avrcp_player *player = user_data;
	struct pending_list_items *p;
	
	if (player->p != NULL)
		return -EBUSY;
	
	if (g_str_has_prefix(name, "/NowPlaying"))
		player->scope = 0x03;
	else if (g_str_has_suffix(name, "/search"))
		player->scope = 0x02;
	else
		player->scope = 0x01;

	avrcp_list_items(player->session, start, end);
	
	p = g_new0(struct pending_list_items, 1);
	p->start = start;
	p->end = end;
	player->p = p;
	
	return 0;
}

static gboolean avrcp_change_path_rsp(struct avctp *conn,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	struct avctp *session = user_data;
	struct avrcp_player *player;
	struct avrcp_server *server;
	struct media_player *mp;
	int ret;
	
	/* get server here */	
	server = find_server(servers, avctp_get_src(session));
	if(!server){
		goto done;
	}
	player = server->ct_player;
	mp = player->user_data;

	if (pdu == NULL) {
		ret = -ETIMEDOUT;
		goto done;
	}

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS) {
		ret = -EINVAL;
		goto done;
	}

	ret = bt_get_be32(&pdu->params[1]);

done:
	if (ret < 0) {
		g_free(player->change_path);
		player->change_path = NULL;
	} else {
		g_free(player->path);
		player->path = player->change_path;
		player->change_path = NULL;
	}

	media_player_change_folder_complete(mp, player->path, ret);

	return FALSE;
}

static void avrcp_change_path(struct avctp *session, uint8_t direction,
								uint64_t uid)
{
	struct avrcp_player *player;
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 11];
	struct avrcp_browsing_header *pdu = (void *) buf; 
	struct avrcp_server *server;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	memset(buf, 0, sizeof(buf));
	bt_put_be16(player->uid_counter, &pdu->params[0]);
	pdu->params[2] = direction;
	bt_put_be64(uid, &pdu->params[3]);
	pdu->pdu_id = AVRCP_CHANGE_PATH;
	pdu->param_len = htons(11);

	avctp_send_browsing_req(session, buf, sizeof(buf),
					avrcp_change_path_rsp, session);
}

static int ct_change_folder(struct media_player *mp, const char *path,
					uint64_t uid, void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t direction;

	player->change_path = g_strdup(path);

	direction = g_str_has_prefix(path, player->path) ? 0x01 : 0x00;

	avrcp_change_path(player->session, direction, uid);

	return 0;
}

static void avrcp_play_item(struct avctp *session, uint64_t uid)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 11];
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct avrcp_header *pdu = (void *) buf;
	uint16_t length;

	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_PLAY_ITEM;
	pdu->params_len = htons(11);
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	pdu->params[0] = player->scope;
	bt_put_be64(uid, &pdu->params[1]);
	bt_put_be16(player->uid_counter, &pdu->params[9]);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					NULL, session);
}

static int ct_play_item(struct media_player *mp, const char *name,
						uint64_t uid, void *user_data)
{
	struct avrcp_player *player = user_data;
	struct avctp *session;

	if (player->p != NULL)
		return -EBUSY;

	session = player->session;

	if (g_strrstr(name, "/NowPlaying"))
		player->scope = 0x03;
	else
		player->scope = 0x01;

	avrcp_play_item(session, uid);

	return 0;
}

static void avrcp_add_to_nowplaying(struct avctp *session, uint64_t uid)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 11];
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct avrcp_header *pdu = (void *) buf;
	uint16_t length;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_ADD_TO_NOW_PLAYING;
	pdu->params_len = htons(11);
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	pdu->params[0] = player->scope;
	bt_put_be64(uid, &pdu->params[1]);
	bt_put_be16(player->uid_counter, &pdu->params[9]);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					NULL, session);
}

static int ct_add_to_nowplaying(struct media_player *mp, const char *name,
						uint64_t uid, void *user_data)
{
	struct avrcp_player *player = user_data;
	struct avctp *session;

	if (player->p != NULL)
		return -EBUSY;

	session = player->session;

	if (g_strrstr(name, "/NowPlaying"))
		player->scope = 0x03;
	else
		player->scope = 0x01;

	avrcp_add_to_nowplaying(session, uid);

	return 0;
}

#if 0

static gboolean avrcp_search_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	struct avrcp *session = (void *) user_data;
	struct avrcp_player *player = session->controller->player;
	struct media_player *mp = player->user_data;
	int ret;

	if (pdu == NULL) {
		ret = -ETIMEDOUT;
		goto done;
	}

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 7) {
		ret = -EINVAL;
		goto done;
	}

	player->uid_counter = get_be16(&pdu->params[1]);
	ret = get_be32(&pdu->params[3]);

done:
	media_player_search_complete(mp, ret);

	return FALSE;
}

static void avrcp_search(struct avrcp *session, const char *string)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 255];
	struct avrcp_browsing_header *pdu = (void *) buf;
	uint16_t len, stringlen;

	memset(buf, 0, sizeof(buf));
	len = AVRCP_BROWSING_HEADER_LENGTH + 4;
	stringlen = strnlen(string, sizeof(buf) - len);
	len += stringlen;

	put_be16(AVRCP_CHARSET_UTF8, &pdu->params[0]);
	put_be16(stringlen, &pdu->params[2]);
	memcpy(&pdu->params[4], string, stringlen);
	pdu->pdu_id = AVRCP_SEARCH;
	pdu->param_len = htons(len - AVRCP_BROWSING_HEADER_LENGTH);

	avctp_send_browsing_req(session->conn, buf, len, avrcp_search_rsp,
								session);
}

static int ct_search(struct media_player *mp, const char *string,
							void *user_data)
{
	struct avrcp_player *player = user_data;
	struct avrcp *session;

	session = player->sessions->data;

	avrcp_search(session, string);

	return 0;
}
#endif

static const struct media_player_callback ct_cbs = {
/*	.set_setting	= ct_set_setting,
	.play		= ct_play,
	.pause		= ct_pause,
	.stop		= ct_stop,
	.next		= ct_next,
	.previous	= ct_previous,
	.fast_forward	= ct_fast_forward,
	.rewind		= ct_rewind,
	.list_items	= ct_list_items,
	.change_folder	= ct_change_folder,
	.search		= ct_search,
	.play_item	= ct_play_item,
	.add_to_nowplaying = ct_add_to_nowplaying,*/
	.set_setting	= NULL,
	.play		= NULL,
	.pause		= NULL,
	.stop		= NULL,
	.next		= NULL,
	.previous	= NULL,
	.fast_forward	= NULL,
	.rewind		= NULL,
	.list_items	= ct_list_items,
	.change_folder	= ct_change_folder,
	.search		= NULL,
	.play_item	= ct_play_item,
	.add_to_nowplaying = ct_add_to_nowplaying,
};

static struct avrcp_player *create_ct_player(struct avrcp_server *server,
								uint16_t id)
{
	struct avrcp_player *player;
	struct media_player *mp;
	struct audio_device *dev;
	const char *path;

	player = g_new0(struct avrcp_player, 1);
	player->session = server->session;
	player->server = server;

	dev = manager_get_device(&server->src, avctp_get_dest(server->session), FALSE);
	player->dev = dev;

	path = dev->path;
	
	DBG("path: %s", path);

	mp = media_player_controller_create(path, id);
	if (mp == NULL)
		return NULL;

	media_player_set_callbacks(mp, &ct_cbs, player);
	player->user_data = mp;
	player->destroy = (GDestroyNotify) media_player_destroy;

	if (server->ct_player == NULL){
		DBG("Set ct_player: %p", player);
		server->ct_player = player;
	}
	DBG("Adding player to players");
	server->players = g_slist_prepend(
						server->players,
						player);

	return player;
}

static struct avrcp_player *find_ct_player(struct avrcp_server *server, uint16_t id)
{
	GSList *l;
	DBG("Finding player with id %d", id);
	for (l = server->players; l; l = l->next) {
		struct avrcp_player *player = l->data;

		if (player->id == 0) {
			player->id = id;
			return player;
		}

		if (player->id == id)
			return player;
	}
	DBG("Player with id %d not found", id);
	return NULL;
}

static gboolean avrcp_get_item_attributes_rsp(struct avctp *conn,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avctp *session = user_data;
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct avrcp_browsing_header *pdu = (void *) operands;
	uint8_t count;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	if (pdu == NULL) {
		avrcp_get_element_attributes(session);
		return FALSE;
	}

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 4) {
		avrcp_get_element_attributes(session);
		return FALSE;
	}

	count = pdu->params[1];

	if (ntohs(pdu->param_len) - 1 < count * 8) {
		error("Invalid parameters");
		return FALSE;
	}

	avrcp_parse_attribute_list(player, &pdu->params[2], count);

	avrcp_get_play_status(session);

	return FALSE;
}

static void avrcp_get_item_attributes(struct avctp *session, uint64_t uid)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 12];
	struct avrcp_browsing_header *pdu = (void *) buf;
	
	server = find_server(servers, avctp_get_src(session));
	player = server->ct_player;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_GET_ITEM_ATTRIBUTES;
	pdu->params[0] = 0x03;
	bt_put_be64(uid, &pdu->params[1]);
	bt_put_be16(player->uid_counter, &pdu->params[9]);
	pdu->param_len = htons(12);

	avctp_send_browsing_req(session, buf, sizeof(buf),
				avrcp_get_item_attributes_rsp, session);
}

static struct avrcp_player * avrcp_parse_media_player_item(struct avrcp_server *server, 
						uint8_t *operands, uint16_t len)
{
	struct avrcp_player *player;
	struct media_player *mp;
	uint16_t id, namelen;
	uint32_t subtype;
	const char *curval, *strval;
	char name[255];
	/* 
	 * 28 is the number of bytes for the Media Player Item attribute. 
	 * See 6.10.2.1 of the AVRCP 1.4 specification document.
	 */
	if(len < 28)
		return;
	
	id = bt_get_be16(&operands[0]);
	DBG("Media player ID: %d",id);
	
	/* Find media player */
	player = find_ct_player(server, id);
	if (player == NULL) {
		DBG("Creating player");
		player = create_ct_player(server, id);
		if (player == NULL)
			return NULL;
	} else if (player->features != NULL)
		return player;
		
	player->id = id;
	
	mp = player->user_data;

	media_player_set_type(mp, type_to_string(operands[2]));

	subtype = bt_get_be32(&operands[3]);

	media_player_set_subtype(mp, subtype_to_string(subtype));

	curval = media_player_get_status(mp);
	strval = status_to_string(operands[7]);

	if (g_strcmp0(curval, strval) != 0) {
		media_player_set_status(mp, strval);
		avrcp_get_play_status(server->session);
	}

	avrcp_player_parse_features(player, &operands[8]);

	namelen = bt_get_be16(&operands[26]);
	if (namelen > 0 && namelen + 28 == len) {
		namelen = MIN(namelen, sizeof(name) - 1);
		memcpy(name, &operands[28], namelen);
		name[namelen] = '\0';
		media_player_set_name(mp, name);
	}

	if (server->ct_player == player && !player->browsed)
		avrcp_set_browsed_player(server->session, player);

	return player;	

}

static gboolean avrcp_get_media_player_list_rsp(struct avctp * conn, 
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	struct avrcp_server * server = user_data;
	struct avrcp_player * player;
	uint16_t count;
	size_t i;
	GSList *removed;
	
	if(pdu == NULL || pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 5) {
		return FALSE;
	}
	
	removed = g_slist_copy(server->players);
	count = bt_get_be16(&operands[6]);
	
	for(i = 8; count && i < operand_count; count--) {
		uint8_t type;
		uint16_t len;
		
		type = operands[i++];
		len = bt_get_be16(&operands[i]);;
		i += 2;
		
		if(type != 0x01) {
			i+= len;
			continue;
		}
		
		if(i + len > operand_count) {
			error("Invalid player item length");
			return FALSE;
		}
		
		DBG("Perform parsing here!");
		player = avrcp_parse_media_player_item(server, &operands[i], len);
		
		if (player)
			removed = g_slist_remove(removed, player);
		
		i+= len;
		
	}
	
	return TRUE;
}

static void avrcp_get_media_player_list(struct avrcp_server *server)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 10];
	struct avrcp_browsing_header *pdu = (void *) buf;
	
	memset(buf, 0, sizeof(buf));
	
	pdu->pdu_id = AVRCP_GET_FOLDER_ITEMS;
	pdu->param_len = htons(10);
	avctp_send_browsing_req(server->session,buf, sizeof(buf),avrcp_get_media_player_list_rsp,server);
}

static void avrcp_status_changed(struct avctp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	struct media_player *mp;
	uint8_t value;
	const char *curval, *strval;
	
	server = find_server(servers, avctp_get_src(session));
	if(!server)
		return;
	player = server->ct_player;
	if(!player)
		return;
	mp = player->user_data;

	value = pdu->params[1];

	curval = media_player_get_status(mp);
	strval = status_to_string(value);

	if (g_strcmp0(curval, strval) == 0)
		return;

	media_player_set_status(mp, strval);
	avrcp_get_play_status(session);
}

static void avrcp_track_changed(struct avctp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_server *server;
	server = find_server(servers, avctp_get_src(session));
	
	if(!server)
		return;
	
	struct avrcp_player *player = server->ct_player;
	if(!player)
		return;
	
	if (avctp_get_browsing_id(session)) {
		
		player->uid = bt_get_be64(&pdu->params[1]);
		avrcp_get_item_attributes(session, player->uid);
	} else
		avrcp_get_element_attributes(session);
}

static void avrcp_available_players_changed(struct avctp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_server *server;
	server = find_server(servers, avctp_get_src(session));
	if(!server)
		return;
	avrcp_get_media_player_list(server);
}

static void avrcp_addressed_player_changed(struct avctp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	uint16_t id = bt_get_be16(&pdu->params[1]);
	
	server = find_server(servers, avctp_get_src(session));
	
	if(!server)
		return;
		
	
	
	player = server->ct_player;

	if (player != NULL && player->id == id)
		return;

	player = find_ct_player(server, id);
	if (player == NULL) {
		player = create_ct_player(server, id);
		if (player == NULL)
			return;
	}

	player->uid_counter = bt_get_be16(&pdu->params[3]);
	server->ct_player = player;
	DBG("Addressed player changed %p", server->ct_player);

	if (player->features != NULL)
		return;

	avrcp_get_media_player_list(server);
}
					

static gboolean avrcp_handle_event(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct control *session = user_data;
	struct avrcp_header *pdu = (void *) operands;
	const char *curval, *strval;
	uint8_t event;

	if ((code != AVC_CTYPE_INTERIM && code != AVC_CTYPE_CHANGED) ||
								pdu == NULL)
		return FALSE;

	event = pdu->params[0];

	if (code == AVC_CTYPE_CHANGED) {
		switch (event){
			case AVRCP_EVENT_TRACK_CHANGED:
			case AVRCP_EVENT_STATUS_CHANGED:
			case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
			case AVRCP_EVENT_SETTINGS_CHANGED:
			case AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED:
			case AVRCP_EVENT_UIDS_CHANGED:
				avrcp_register_notification(session, event);
				break;
		}
		//session->registered_events ^= (1 << event);
		//avrcp_register_notification(session, event);
		return FALSE;
	}

	switch (event) {
	case AVRCP_EVENT_VOLUME_CHANGED:
	
		//avrcp_volume_changed(session, pdu);
		break;
	case AVRCP_EVENT_STATUS_CHANGED:
		avrcp_status_changed(conn, pdu);
		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		avrcp_track_changed(conn, pdu);
		break;
	case AVRCP_EVENT_SETTINGS_CHANGED:
		//avrcp_setting_changed(session, pdu);
		break;
	case AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED:
		avrcp_available_players_changed(conn, pdu);
		break;
	case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
		avrcp_addressed_player_changed(conn, pdu);
		break;
	case AVRCP_EVENT_UIDS_CHANGED:
		//avrcp_uids_changed(session, pdu);
		break;
	}

	//session->registered_events |= (1 << event);

	return TRUE;
}

static void avrcp_register_notification(struct control *con, uint8_t event)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = event;
	pdu->params_len = htons(AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(con->session, AVC_CTYPE_NOTIFY,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_handle_event, con);
}

unsigned int avrcp_add_state_cb(avrcp_state_cb cb, void *user_data)
{
	struct avrcp_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct avrcp_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	callbacks = g_slist_append(callbacks, state_cb);

	return state_cb->id;
}

gboolean avrcp_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = callbacks; l != NULL; l = l->next) {
		struct avrcp_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			callbacks = g_slist_remove(callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

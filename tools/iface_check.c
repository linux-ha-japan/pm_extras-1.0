/*
 * Copyright (c) 2010 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <crm/attrd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <corosync/list.h>
#include <corosync/corotypes.h>
#include <corosync/engine/coroapi.h>
#include <corosync/coroipc_types.h>
#include <corosync/lcr/lcr_comp.h>
#include <corosync/engine/logsys.h>

LOGSYS_DECLARE_SUBSYS ("IFCHK");

enum iface_status {
	IFACE_STATUS_UNKNOWN = 0,
	IFACE_STATUS_UP = 1,
	IFACE_STATUS_DOWN = 2,
	IFACE_STATUS_FAULTY = 3
};

typedef struct iface_check_s {
	char *ring_name;
	char *ip;
	int state;
	int tracked;
	hdb_handle_t handle;
	corosync_timer_handle_t state_get_timer_handle;
	struct list_head list;
} iface_check_t;

DECLARE_LIST_INIT(iface_check_list_head);

static int iface_check_config_init (struct corosync_api_v1 *corosync_api);
static int iface_check_startup (struct corosync_api_v1 *corosync_api);
static int iface_check_shutdown (void);

static inline int objdb_get_handle (
	hdb_handle_t handle,
	const char* handle_name,
	size_t handle_name_len,
	hdb_handle_t *object_handle);
static hdb_handle_t objdb_seq_get_handle(hdb_handle_t top_handle, char *seq_str);

static void init_state_get_func(void *data);
static void key_change_notify (
	object_change_type_t change_type,
	hdb_handle_t parent_object_handle,
	hdb_handle_t object_handle,
	const void *object_name_pt,
	size_t object_name_len,
	const void *key_name_pt,
	size_t key_len,
	const void *key_value_pt,
	size_t key_value_len,
	void *priv_data_pt);

static char *state_to_str(int state);
static int attrd_send_update(iface_check_t *iface_check, char mode);

static void req_exec_iface_check_start_endian_convert (void *msg);
static void req_exec_iface_check_mcast_endian_convert (void *msg);
static void message_handler_req_exec_iface_check_mcast (const void *msg, unsigned int nodeid);
static void message_handler_req_exec_iface_check_start (const void *msg, unsigned int nodeid);
static void message_handler_req_iface_check_start (void *conn, const void *msg);

static struct corosync_api_v1 *api;

struct req_exec_iface_check_start {
	coroipc_request_header_t header;
	unsigned int msg_code;
	unsigned int msg_count;
	unsigned int msg_size;
	unsigned int time_interval;
};

struct req_exec_iface_check_mcast {
	coroipc_request_header_t header;
	unsigned int msg_code;
};

static struct corosync_lib_handler iface_check_lib_engine[] =
{
	{ /* 0 */
		.lib_handler_fn	 = message_handler_req_iface_check_start,
		.flow_control	   = CS_LIB_FLOW_CONTROL_NOT_REQUIRED
	}
};

static struct corosync_exec_handler iface_check_exec_engine[] =
{
	{
		.exec_handler_fn	= message_handler_req_exec_iface_check_start,
		.exec_endian_convert_fn = req_exec_iface_check_start_endian_convert
	},
	{
		.exec_handler_fn	= message_handler_req_exec_iface_check_mcast,
		.exec_endian_convert_fn = req_exec_iface_check_mcast_endian_convert
	}
};

struct corosync_service_engine iface_check_service_engine = {
	.name			= "iface_check service.",
	.id			= 63,
	.priority		= 51,
	.private_data_size	= 0,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
	.config_init_fn		= iface_check_config_init,
	.exec_init_fn		= iface_check_startup,
	.exec_exit_fn		= iface_check_shutdown,
};

static struct corosync_service_engine *iface_check_get_service_engine_ver0 (void);

struct corosync_service_engine_iface_ver0 iface_check_service_engine_iface = {
	.corosync_get_service_engine_ver0 = iface_check_get_service_engine_ver0
};

static struct lcr_iface corosync_iface_check_ver0[1] = {
	/* version 0 */
	{
		.name			= "iface_check",
		.version		= 0,
		.versions_replace	= 0,
		.versions_replace_count	= 0,
		.dependencies		= 0,
		.dependency_count	= 0,
		.constructor		= NULL, /* constructor */
		.destructor		= NULL, /* destructor */
		.interfaces		= NULL
	}
};

static struct lcr_comp iface_check_comp_ver0 = {
	.iface_count	= 1,
	.ifaces		= corosync_iface_check_ver0
};

static struct corosync_service_engine *iface_check_get_service_engine_ver0 (void)
{
	return (&iface_check_service_engine);
}

#ifdef COROSYNC_SOLARIS
void corosync_lcr_component_register (void);

void corosync_lcr_component_register (void) {
#else
__attribute__ ((constructor)) static void corosync_lcr_component_register (void) {
#endif
	lcr_interfaces_set (&corosync_iface_check_ver0[0], &iface_check_service_engine_iface);
	lcr_component_register (&iface_check_comp_ver0);
}

static char *padding_ip_string(char *ip)
{
	char *pad_ip_str = NULL;
	crm_malloc0(pad_ip_str, 16);
	snprintf(pad_ip_str, 16, "%-15s", ip);

	return pad_ip_str;
}

static iface_check_t *iface_check_t_new(void)
{
		iface_check_t *new_t = malloc(sizeof(iface_check_t));

		new_t->ring_name = NULL;
		new_t->ip = NULL;
		new_t->state = IFACE_STATUS_UNKNOWN;
		new_t->tracked = 0;
		new_t->handle = 0;
		new_t->state_get_timer_handle = NULL;
		list_init(&new_t->list);

		return new_t;
}

static int attrd_send_update(iface_check_t *iface_check, char mode)
{
	gboolean updated = FALSE;
	static IPC_Channel *cluster = NULL;
	char *state_str;
	char *update_value;
	const char *conn_str = " is ";

	state_str = state_to_str(iface_check->state);
	crm_malloc0(update_value, strlen(state_str) + strlen(iface_check->ip) + strlen(conn_str) + 1);
	snprintf(update_value, strlen(state_str) + strlen(iface_check->ip) + strlen(conn_str) + 1,
		"%s%s%s", iface_check->ip, conn_str, state_str);

	if(cluster == NULL) {
		log_printf(LOGSYS_LEVEL_DEBUG, "Connecting to attrd...\n");
		cluster = init_client_ipc_comms_nodispatch(T_ATTRD);
	}

	if(cluster != NULL) {
		switch(mode) {
			case 'U':
				updated = attrd_update(cluster, 'U', NULL,
					iface_check->ring_name, update_value, NULL, NULL, 0);
				break;
			case 'D':
				updated = attrd_update(cluster, 'D', NULL,
					iface_check->ring_name, NULL, NULL, NULL, 0);
				break;
			default:
				updated = attrd_update(cluster, 'U', NULL,
					iface_check->ring_name, update_value, NULL, NULL, 0);
				break;
		}
	}
  
	crm_free(state_str);
	crm_free(update_value);

	if(updated == 0) {
		log_printf(LOGSYS_LEVEL_WARNING, "Failed to update.\n");
		return -1;
	}

	return 0;
}

static inline int objdb_get_handle (
	hdb_handle_t handle,
	const char* handle_name,
	size_t handle_name_len,
	hdb_handle_t *object_handle)
{
		hdb_handle_t find_handle;

		api->object_find_create (handle, handle_name, handle_name_len, &find_handle);

		if((api->object_find_next (find_handle, object_handle)) == -1) {
				return (-1);
		}

		return (0);
}

static hdb_handle_t objdb_seq_get_handle(
	hdb_handle_t top_handle,
	char *seq_str)
{
	hdb_handle_t find_handle;
	const char *seperator = ".";
	char *save_pt;
	char *handle_name;
	char *tmp_name = NULL;
	
	tmp_name = crm_strdup(seq_str);
	handle_name = strtok_r(tmp_name, ".", &save_pt);

	while(handle_name != NULL) {
		if (objdb_get_handle (
			top_handle, handle_name, strlen (handle_name), &find_handle) == -1) {
			log_printf(LOGSYS_LEVEL_WARNING, "token[%s] is not found.\n", handle_name);
			return -1;
		}
		top_handle = find_handle;
		handle_name = strtok_r(NULL, ".", &save_pt);
	}
	crm_free(tmp_name);

	return top_handle;

}

static char *state_to_str(int state)
{
	switch(state) {
		case IFACE_STATUS_UP:
			return crm_strdup("UP");
		case IFACE_STATUS_DOWN:
			return crm_strdup("DOWN");
		case IFACE_STATUS_FAULTY:
			return crm_strdup("FAULTY");
		default:
			return crm_strdup("UNKNOWN");
	}
}

static void init_state_get_func(void *data)
{
	iface_check_t *iface_check = (iface_check_t *)data;
	void *value;
	size_t len;

	if(iface_check->ip != NULL) {
		crm_free(iface_check->ip);
	}

	api->object_key_get(iface_check->handle, "iface", strlen("iface"), &value, &len);
	iface_check->ip = padding_ip_string(value);

	api->object_key_get(iface_check->handle, "state", strlen("state"), &value, &len);
	iface_check->state = *(int *)value;

	if(0 != attrd_send_update(iface_check, 'U')) {
		log_printf(LOGSYS_LEVEL_WARNING, "attrd is not yet ready.\n");
		api->timer_add_duration(
			(unsigned long long)1000 * MILLI_2_NANO_SECONDS,
			iface_check,
			init_state_get_func,
			&iface_check->state_get_timer_handle);
	} else {
		log_printf(LOGSYS_LEVEL_INFO, "%s is track start.\n", iface_check->ring_name);
		api->object_track_start(
			iface_check->handle,
			OBJECT_TRACK_DEPTH_RECURSIVE,
			key_change_notify, // object_change_notify
			NULL, // object_create_notify
			NULL, // object_destroy_notify
			NULL, // object_reload_notify
			iface_check); // priv_data
	}

	return;
}

static void key_change_notify (object_change_type_t change_type,
	hdb_handle_t parent_object_handle,
	hdb_handle_t object_handle,
	const void *object_name_pt,
	size_t object_name_len,
	const void *key_name_pt,
	size_t key_len,
	const void *key_value_pt,
	size_t key_value_len,
	void *priv_data_pt)
{
	iface_check_t *iface_check = (iface_check_t *)priv_data_pt;
	char *obj_name;
	char *ip_str;
	void *value;
	size_t len;

	if(safe_str_eq(key_name_pt, "state")) {
		log_printf(LOGSYS_LEVEL_INFO, "Status of %s changed. [%d] -> [%d]\n",
			iface_check->ring_name, iface_check->state, *(int *)key_value_pt);

		iface_check->state = *(int *)key_value_pt;

		if(iface_check->ip != NULL) {
			crm_free(iface_check->ip);
		}

		api->object_key_get(object_handle, "iface", strlen("iface"), &value, &len);
		iface_check->ip = padding_ip_string(value);

		attrd_send_update(iface_check, 'U');
	}

	return;

}

static int iface_check_config_init (struct corosync_api_v1 *corosync_api)
{
	api = corosync_api;
	int i;
	char *obj_name = "runtime.totem.pg.mrp.srp.rrp";
	void *interface_count;
	char *link_name;
	char *num;
	void *value;
	size_t len;
	objdb_value_types_t type;
	hdb_handle_t object_handle;
	hdb_handle_t find_handle;

	log_printf(LOGSYS_LEVEL_INFO, "interface check service config init.\n");

	object_handle = objdb_seq_get_handle(OBJECT_PARENT_HANDLE, obj_name);

	if(api->object_key_get_typed(object_handle,
		"interface_count", &interface_count, &len, &type) == -1) {
		log_printf(LOGSYS_LEVEL_ERROR, "interface_count is not found.\n");
		return -1;
	}

	for(i = 0; i < *(int *)interface_count; i++) {
		iface_check_t *iface_check = iface_check_t_new();

		num = crm_itoa(i);
		crm_malloc0(link_name, strlen("link") + strlen(num) + 1);
		snprintf(link_name, strlen("link") + strlen(num) + 1,
			"link%s", num);


		crm_malloc0(iface_check->ring_name, strlen("ringnumber()") + strlen(num) + 1);
		snprintf(iface_check->ring_name, strlen("ringnumber()") + strlen(num) + 1,
			"ringnumber(%s)", num);

		if(objdb_get_handle (
			object_handle, link_name, strlen (link_name), &iface_check->handle) == -1) {
			log_printf(LOGSYS_LEVEL_ERROR, "%s.%s is not found.\n", obj_name, link_name);
			crm_free(num);
			crm_free(link_name);
			return -1;
		}

		list_add_tail(&iface_check->list, &iface_check_list_head);

		crm_free(num);
		crm_free(link_name);
	}

	return 0;
}

static int iface_check_startup (struct corosync_api_v1 *corosync_api)
{
	struct list_head *iter;

	log_printf(LOGSYS_LEVEL_INFO, "interface check service startup.\n");

	for(iter = iface_check_list_head.next;
		iter != &iface_check_list_head;
		iter = iter->next) {
		iface_check_t *iface_check = list_entry (iter, iface_check_t, list);

		if(iface_check->ring_name == NULL) {
			continue;
		}

		api->timer_add_duration(
			(unsigned long long)0,
			iface_check,
			init_state_get_func, &iface_check->state_get_timer_handle);
	}

	return 0;
}

static int iface_check_shutdown (void)
{
	struct list_head *iter = iface_check_list_head.next;

	while(iter != &iface_check_list_head) {
		iface_check_t *iface_check = list_entry (iter, iface_check_t, list);

		attrd_send_update(iface_check, 'D');
		api->object_track_stop(
			key_change_notify,
			NULL,
			NULL,
			NULL,
			iface_check);

		if(iface_check->ring_name != NULL) {
			crm_free(iface_check->ring_name);
		}

		if(iface_check->ip != NULL) {
			crm_free(iface_check->ip);
		}
		iter = iter->next;

		crm_free(iface_check);

	}

	log_printf(LOGSYS_LEVEL_INFO, "interface check service shutdown complete.\n");

	return 0;
}

static void message_handler_req_iface_check_start (void *conn, const void *msg)
{
}

static void req_exec_iface_check_start_endian_convert (void *msg)
{
}

static void req_exec_iface_check_mcast_endian_convert (void *msg)
{
}

static void message_handler_req_exec_iface_check_start (const void *msg, unsigned int nodeid)
{
}

static void message_handler_req_exec_iface_check_mcast (const void *msg, unsigned int nodeid)
{
}



/* -------------------------------------------------------------------------
 * ifcheckd --- monitors interface of Heartbeat cluster.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright (c) 2010 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * -------------------------------------------------------------------------
 */

#include <libgen.h>
#include <crm/common/cluster.h>

static ll_cluster_t *hb_cluster = NULL;
const char *node_uname = NULL;
GMainLoop* mainloop = NULL;
gboolean need_shutdown = FALSE;
int attr_dampen = 0; /* 0s */
int ident;	/* our pid */

static void ifcheckd_lstatus_callback(
	const char *node, const char *link, const char *status, void *private_data);
static void do_node_walk(ll_cluster_t *hb_cluster);
static void do_if_walk(ll_cluster_t *hb_cluster, const char *ha_node);
static void send_update(gpointer attr_name, gpointer attr_value, gpointer user_data);

static void
ifcheckd_shutdown(int nsig)
{
	need_shutdown = TRUE;
	do_node_walk(hb_cluster);

	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(0);
	}
}

static gboolean
ifcheckd_ha_dispatch(IPC_Channel *channel, gpointer user_data)
{
	gboolean stay_connected = TRUE;

	crm_debug_2("Invoked");
	while(hb_cluster != NULL && IPC_ISRCONN(channel)) {
		if(hb_cluster->llc_ops->msgready(hb_cluster) == 0) {
			crm_debug_2("no message ready yet");
			break;
		}
		/* invoke the callbacks but dont block */
		hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);
	}
	
	if (hb_cluster == NULL || channel->ch_status != IPC_CONNECT) {
		stay_connected = FALSE;
	}

	return stay_connected;
}


static void
ifcheckd_ha_connection_destroy(gpointer user_data)
{
	crm_debug_2("Invoked");
	crm_crit("Lost connection to heartbeat service!");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
		return;
	}

	exit(LSB_EXIT_OK);
}

static gboolean
register_with_ha(void) 
{
	crm_debug_2("Invoked");
	hb_cluster = ll_cluster_new("heartbeat");
	if(hb_cluster == NULL) {
		return FALSE;
	}

	/* cluster connect */
	if(hb_cluster->llc_ops->signon(hb_cluster, NULL)!= HA_OK) {
		crm_err("Cannot signon with heartbeat");
		crm_err("REASON: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	node_uname = hb_cluster->llc_ops->get_mynodeid(hb_cluster);
	if(node_uname == NULL) {
		crm_err("failed to get node uname.");
		return FALSE;
	}

	G_main_add_IPC_Channel(G_PRIORITY_HIGH, hb_cluster->llc_ops->ipcchan(hb_cluster),
		FALSE, ifcheckd_ha_dispatch, hb_cluster, ifcheckd_ha_connection_destroy);

	crm_debug_2("set notify Link status callback handler");
	if (hb_cluster->llc_ops->set_ifstatus_callback(
			hb_cluster, ifcheckd_lstatus_callback, NULL) != HA_OK) {
		crm_err("Cannot set Link status callback: %s",
			 hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	/* initial update */
	do_node_walk(hb_cluster);

	return TRUE;
}

static void
do_if_walk(ll_cluster_t *hb_cluster, const char *ha_node)
{
	const char *iface_name = NULL;
	const char *iface_status = NULL;
	const char *ha_node_status = NULL;
	const char *ha_node_type = NULL;
	char *attr_name = NULL;
	GHashTable *iface_hash = NULL;

	crm_debug_2("Invoked");
	ha_node_type = hb_cluster->llc_ops->node_type(hb_cluster, ha_node);
	if(safe_str_eq("ping", ha_node_type)) {
		/* ignore ping node */
		crm_debug("Node %s: ignore the ping node", ha_node);
		return;
	}

	iface_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	if(hb_cluster->llc_ops->init_ifwalk(hb_cluster, ha_node) != HA_OK) {
		crm_err("Cannot start heartbeat link interface walk.");
		crm_err("REASON: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
		return;
	}

	while((iface_name = hb_cluster->llc_ops->nextif(hb_cluster)) != NULL) {
		attr_name = g_strdup_printf("%s-%s", ha_node, iface_name);
		ha_node_status = hb_cluster->llc_ops->node_status(hb_cluster, ha_node);
		crm_debug("Node %s: Status is %s", ha_node, ha_node_status);

		if(safe_str_eq("dead", ha_node_status) || need_shutdown) {
			/* delete the attribute information of a dead node. */
			g_hash_table_insert(iface_hash, attr_name, NULL);
			continue;
		}

		iface_status = hb_cluster->llc_ops->if_status(hb_cluster, ha_node, iface_name);
		g_hash_table_insert(iface_hash, attr_name, crm_strdup(iface_status));
		crm_debug("Link %s: Status is %s", iface_name, iface_status);
	}

	if(hb_cluster->llc_ops->end_ifwalk(hb_cluster) != HA_OK) {
		crm_err("Cannot end heartbeat link interface walk");
		crm_err("REASON: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
		return;
	}

	g_hash_table_foreach(iface_hash, send_update, NULL);
	g_hash_table_destroy(iface_hash);
	crm_debug_2("Complete");
}

static void
do_node_walk(ll_cluster_t *hb_cluster)
{
	const char *ha_node = NULL;

	crm_info("Requesting the list of configured nodes");
	if(hb_cluster->llc_ops->init_nodewalk(hb_cluster) != HA_OK) {
		crm_err("Cannot start node walk.");
		crm_err("REASON: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
		return;
	}

	while((ha_node = hb_cluster->llc_ops->nextnode(hb_cluster)) != NULL) {
		if(safe_str_eq(node_uname, ha_node)) {
			/* skip own node */
			crm_debug("Node %s: The own node skips", ha_node);
			continue;
		}
		do_if_walk(hb_cluster, ha_node);
	}

	if(hb_cluster->llc_ops->end_nodewalk(hb_cluster) != HA_OK) {
		crm_err("Cannot end node walk.");
		crm_err("REASON: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
		return;
	}

	crm_debug_2("Complete");
}

static struct crm_option long_options[] = {
	/* Top-level Options */
	{"help",	0, 0, '?', "\t\tThis text"},
	{"version",	0, 0, '$', "\t\tVersion information"},
	{"verbose",	0, 0, 'V', "\t\tIncrease debug output\n"},
	{"daemonize",	0, 0, 'D', "\tRun in daemon mode"},
	{"pid-file",	1, 0, 'p', "\tFile in which to store the process' PID\n"},
	{"attr-dampen",	1, 0, 'd', "How long to wait for no further changes to occur before "
		"updating the CIB with a changed attribute"},
	{0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;
	const char *pid_file = NULL;
	gboolean daemonize = FALSE;
	
	int option_index = 0;
	pid_file = "/var/run/ifcheckd.pid";

	mainloop_add_signal(SIGTERM, ifcheckd_shutdown);
	mainloop_add_signal(SIGINT, ifcheckd_shutdown);
	
	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);
	crm_set_options("V?$Dp:d:", NULL, long_options, "Daemon to check the Link information "
		"of the node to constitute a Heartbeat cluster");
	
	while (1) {
		flag = crm_get_option(argc, argv, &option_index);
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'p':
				pid_file = optarg;
				break;
			case 'd':
				attr_dampen = crm_get_msec(optarg);
				break;
			case 'D':
				daemonize = TRUE;
				break;
			case '$':
			case '?':
				crm_help(flag, LSB_EXIT_OK);
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n",
					flag, flag);
				crm_err("Argument code 0%o (%c) is not (?yet?) supported\n",
					flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		crm_err("non-option ARGV-elements: ");
		while (optind < argc) {
			crm_err("%s ", argv[optind]);
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
	if (argerr) {
		crm_help(flag, LSB_EXIT_GENERIC);
	}

	crm_make_daemon(crm_system_name, daemonize, pid_file);
	ident = getpid();

	if(register_with_ha() == FALSE) {
		crm_err("HA registration failed");
		cl_flush_logs();
		exit(LSB_EXIT_GENERIC);
	}

	crm_info("Starting %s", crm_system_name);
	mainloop = g_main_new(FALSE);
	g_main_run(mainloop);
	crm_info("Exiting %s", crm_system_name);	

	if(is_heartbeat_cluster()) {
		hb_cluster->llc_ops->signoff(hb_cluster, TRUE);
		hb_cluster->llc_ops->delete(hb_cluster);
	}

	return 0;
}

static void
send_update(gpointer attr_name, gpointer attr_value, gpointer user_data)
{
	char *damp = crm_itoa(attr_dampen/1000);

	attrd_lazy_update('U', node_uname, attr_name, attr_value, NULL, NULL, damp);
	crm_free(damp);

	return;
}

static void
ifcheckd_lstatus_callback(const char *node, const char *lnk, const char *status, void *private)
{
	crm_debug("Link status change: node %s link %s now has status [%s]", node, lnk, status);

	do_if_walk(hb_cluster, node);

	return;
}


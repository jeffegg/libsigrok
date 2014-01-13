/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2014 Jeff Eglinger <jeffegg@jeffegg.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _WIN32_WINNT 0x0501
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <stdio.h>

#include "protocol.h"
#include "libsigrok.h"
#include "libsigrok-internal.h"

SR_PRIV struct sr_dev_driver agilent_16700_rpi_driver_info;
static struct sr_dev_driver *di = &agilent_16700_rpi_driver_info;

struct tcp_info {
	char *address;
	char *port;
	int socket;
};

static int init(struct sr_context *sr_ctx)
{
	return std_init(sr_ctx, di, LOG_PREFIX);
}

int GetTCPString(char *output, int maxReadLen, int tcpSocket)
{
	int readLength = 0;

	if (tcpSocket < 0)
	{
		sr_err("getLine: no open socket connection!\n");
		return -1;
	}

	readLength = read(tcpSocket, output, maxReadLen);
	if (readLength < 0)
	{
		sr_err("Error reading from TCP stream");
		return -1;
	}
	return readLength;
}

// Reads from the TCP port
// returns the length of readData;
int GetText(char *output, int outputLength, int tcpSocket)
{
	char *currentPos = output;
	int currentLength = 0;
	int readLength = 0;
	int i;
	while (1)
	{
		readLength = GetTCPString(currentPos, outputLength - currentLength, tcpSocket);
		if (readLength < 0)
		{
			sr_err("Error reading from TCP stream");
			return -1;
		}

		currentLength += readLength;

		// Check for error returns
		if (strstr(output, "!ERROR") != NULL)
		{
			sr_err("Error detected from LA, %s", output);
			return -1;
		}

		// Check for the prompt to see if we're done */
		if (strstr(output, "->") != NULL)
		{
			return currentLength;
		}

		if ((outputLength - currentLength) <= 0)
		{
			return currentLength;
		}

		currentPos += readLength;
	}
}

static void SendCommand()
{

}

static void DecodeModule(struct Agilent16700Modules *module, char * moduleInfo)
{
	printf("%s\n", moduleInfo);

	if(strstr(moduleInfo, "MHz") != NULL)
	{
		//temp = moduleInfo;
		moduleInfo = strtok (NULL, " /\"");
		if(strstr(moduleInfo, "State"))
		{
			//module.maxStateFrequency
		}
		else if(strstr(moduleInfo, "Timing"))
		{
			//module->
		}
	}
	else if(strstr(moduleInfo, "GHz") != NULL)
	{
		printf(" -detechte G\n");
	}
}

static void ModuleInfoParser(char * moduleInfo)
{
	char *stringLoc = moduleInfo;
	struct Agilent16700Modules module;
	//typ loc act name           module     info
	//LA  F   1  "Analyzer<F>"  "16717A"  "333MHz State/2GHz Timing Zoom 2M Sample"

	//Type
	stringLoc = strtok(moduleInfo, " /\"");
	if(strncmp(stringLoc, "LA", 2))
	{
		module.type = ANALYZER;
	}
	else if(strncmp(stringLoc, "PG", 2))
	{
		module.type = PATTERN_GEN;
	}
	else if(strncmp(stringLoc, "SC", 2))
	{
		module.type = SCOPE;
	}
	else
	{
		return;
	}

	// Location
	stringLoc = strtok (NULL, " /\"");
	module.location1 = stringLoc[0];
	module.location2 = stringLoc[1];

	// active
	stringLoc = strtok (NULL, " /\"");

	// name
	stringLoc = strtok (NULL, " /\"");

	//model name
	stringLoc = strtok (NULL, " /\"");
	//moduleModel

	//Decode reset, could ne freq, samples, etc
	stringLoc = strtok (NULL, " /\"");
	while (stringLoc != NULL)
	{
		DecodeModule(&module, stringLoc);
		stringLoc = strtok (NULL, " /\"");
	}
}

static int probe(const char *ipAddr, GSList **devices) {
	const char *tcp_prefix = "tcp/";
	gchar **tokens, *address, *port;
	struct addrinfo hints;
	struct addrinfo *results, *res;
	char localcommand[1024] = "modules -a\n"; // Get the active modules
	//char localcommand[1300] = "modules\n"; // Get all modules
	char readcommand[1300] = ""; // Get all modules
	int len = 0;
	int i = 0;
	int err;
	struct tcp_info tcp;
	int nbytes;

	if (strncmp(ipAddr, tcp_prefix, strlen(tcp_prefix)) == 0) {
		sr_dbg("Opening TCP connection to: %s.", ipAddr);
		tokens = g_strsplit(ipAddr + strlen(tcp_prefix), "/", 0);
		address = tokens[0];
		port = tokens[1];
		if (!address || !port || tokens[2]) {
			sr_err("Invalid parameters.");
			g_strfreev(tokens);
			return SR_ERR_ARG;
		}
		tcp.address = g_strdup(address);
		tcp.port = g_strdup(port);
		tcp.socket = -1;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		err = getaddrinfo(tcp.address, tcp.port, &hints, &results);

		if (err) {
			sr_err("Address lookup failed: %s:%d: %s", tcp.address, tcp.port,
					gai_strerror(err));
			g_strfreev(tokens);
			return SR_ERR_MALLOC;
		}

		for (res = results; res; res = res->ai_next) {
			if ((tcp.socket = socket(res->ai_family, res->ai_socktype,
					res->ai_protocol)) < 0) {
				continue;
			}
			if (connect(tcp.socket, res->ai_addr, res->ai_addrlen) != 0) {
				close(tcp.socket);
				tcp.socket = -1;
				continue;
			}
			break;
		}

		freeaddrinfo(results);

		if (tcp.socket < 0) {
			sr_err("Failed to connect to %s:%s: %s", tcp.address, tcp.port,
					strerror(errno));
			g_strfreev(tokens);
			return SR_ERR_MALLOC;
		}

		len = strlen(localcommand);
		//"analyzer_info"
		nbytes = write(tcp.socket, localcommand, len);
		if (nbytes < 0) {
			sr_err("Write failed: %s", strerror(errno));
		}
		GetText(readcommand, sizeof(readcommand), tcp.socket);

		printf(readcommand);
		printf("\n");
		ModuleInfoParser(readcommand);
		//getText(max_lines, num_lines, output)

		g_strfreev(tokens);
	} else {
		sr_err("%s is not a valid IP address in format of tcp/", ipAddr);
	}

	return SR_OK;
}

static GSList *scan(GSList *options)
{
	struct drv_context *drvc;
	struct sr_config *src;
	GSList *l, *devices;

	(void)options;
	gchar *ipAddr = NULL;

	devices = NULL;
	drvc = di->priv;
	drvc->instances = NULL;

	for (l = options; l; l = l->next) {
		src = l->data;
		switch (src->key) {
		case SR_CONF_CONN:
			ipAddr = (char *)g_variant_get_string(src->data, NULL);
			break;
		case SR_CONF_SERIALCOMM:
			break;
		}
	}
	if (ipAddr) 
	{
		if (probe(ipAddr, &devices) == SR_ERR_MALLOC) 
		{
			g_free(ipAddr);
			return NULL;
		}
	}else
	{
		g_free(ipAddr);
		return NULL;
	}

	//Any devices found must have a struct sr_dev_inst created, which is added to the driver's known instances -- a GSList stored in the driver context's instances field.
	//A copy of the struct sr_dev_inst for every device found in the current invocation of scan() must also be returned in a GSList from the function itself; the frontend is responsible for freeing the list (but will not touch the instances it contains).
	//The instances thus returned to the frontend are central to the communication between the driver and the libsigrok frontend: every other callback function has an instance struct as a parameter.

	return devices;
}

static GSList *dev_list(void)
{
	return ((struct drv_context *)(di->priv))->instances;
}

static int dev_clear(void)
{
	return std_dev_clear(di, NULL);
}

static int dev_open(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and open it. */

	sdi->status = SR_ST_ACTIVE;

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and close it. */

	sdi->status = SR_ST_INACTIVE;

	return SR_OK;
}

static int cleanup(void)
{
	dev_clear();

	/* TODO: free other driver resources, if any. */

	return SR_OK;
}

static int config_get(int key, GVariant **data, const struct sr_dev_inst *sdi,
		const struct sr_probe_group *probe_group)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)probe_group;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(int key, GVariant *data, const struct sr_dev_inst *sdi,
		const struct sr_probe_group *probe_group)
{
	int ret;

	(void)data;
	(void)probe_group;

	if (sdi->status != SR_ST_ACTIVE)
		return SR_ERR_DEV_CLOSED;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(int key, GVariant **data, const struct sr_dev_inst *sdi,
		const struct sr_probe_group *probe_group)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)probe_group;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi,
				    void *cb_data)
{
	(void)sdi;
	(void)cb_data;

	if (sdi->status != SR_ST_ACTIVE)
		return SR_ERR_DEV_CLOSED;

	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi, void *cb_data)
{
	(void)cb_data;

	if (sdi->status != SR_ST_ACTIVE)
		return SR_ERR_DEV_CLOSED;

	/* TODO: stop acquisition. */

	return SR_OK;
}

SR_PRIV struct sr_dev_driver agilent_16700_rpi_driver_info = {
	.name = "agilent-16700-rpi",
	.longname = "Agilent 16700 RPI",
	.api_version = 1,
	.init = init,
	.cleanup = cleanup,
	.scan = scan,
	.dev_list = dev_list,
	.dev_clear = dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.priv = NULL,
};

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

#define LINE_WIDTH   100

//static int getMoreDataIfNeeded()
//{
//  if (textbuflen <= 0)
//  {
//    if ((textbuflen=read(InstrumentSocket,textbuffer,sizeof(textbuffer))) <= 0)
//    {
//      return(-1);
//    }
//    textptr = textbuffer;
//  }
//  return 0;
//}
//
//int getString(char *line, int len)
//{
//
//	int i=0;
//
//	if (InstrumentSocket < 0)
//	{
//		fprintf(stderr,"getLine: no open socket connection!\n");
//		return -1;
//	}
//
//
//	if (getMoreDataIfNeeded() < 0)
//		return -1;
//
//
//	while (textbuflen > 0 &&
//			i < len-1 &&
//			*textptr != '\r' &&
//			*textptr != '\n')
//	{
//		line[i] = *textptr++;
//		textbuflen--;
//		i++;
//	}
//
//	line[i] = 0;
//	if (i < len-1)
//	{
//		textptr++;
//		textbuflen--;
//		if (textbuflen >= 1 && (*textptr == '\r' || *textptr == '\n'))
//		{
//			textptr++;
//			textbuflen--;
//		}
//		return(i);
//	}
//	else
//	{
//		return(-1);
//	}
//}
//
//int getText(int max_lines, int *num_lines, char *output) {
//	int i;
//	int retVal = 0;
//
//	*num_lines = 0;
//
//	i = 0;
//	while (1) {
//
//		if (getString(&output[i * LINE_WIDTH], LINE_WIDTH) < 0) {
//			return (-1);
//		}
//
//		/*
//		 * Check for error returns
//		 */
//		if (!strncmp(&output[LINE_WIDTH * i], "!ERROR", 6)) {
//			retVal = -1;
//		}
//
//		/*
//		 * Check for the prompt to see if we're done
//		 */
//		if (!strncmp(&output[LINE_WIDTH * i], "->", 2)) {
//			return (retVal);
//		} else {
//			(*num_lines)++;
//		}
//
//		i++;
//
//		if (i >= max_lines) {
//			return (1);
//		}
//	}
//}

static int probe(const char *ipAddr, GSList **devices) {
	const char *tcp_prefix = "tcp/";
	gchar **tokens, *address, *port;
	struct addrinfo hints;
	struct addrinfo *results, *res;
	char localcommand[1024] = "analyzer_info\n";
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

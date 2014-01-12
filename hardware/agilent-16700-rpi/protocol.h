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

#ifndef LIBSIGROK_HARDWARE_AGILENT_16700_RPI_PROTOCOL_H
#define LIBSIGROK_HARDWARE_AGILENT_16700_RPI_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"

/* Message logging helpers with subsystem-specific prefix string. */
#define LOG_PREFIX "agilent-16700-rpi"

/** Private, per-device-instance driver context. */
struct dev_context {
	unsigned int numModules;
	struct Agilent16700Modules *modules;
	/* Model-specific information */

	/* Acquisition settings */

	/* Operational state */

	/* Temporary state across callbacks */

};

enum MODULE_TYPE {
	ANALYZER,
	PATTERN_GEN,
	SCOPE
};

struct Agilent16700Modules {
	char location1;
	char location2;
	char *moduleType;
	MODULE_TYPE type;
	uint64_t maxTimingFrequency;
	uint64_t maxTimingZoomFrequency;
	uint64_t maxStateFrequency;
	uint64_t sampleSize;
};

SR_PRIV int agilent_16700_rpi_receive_data(int fd, int revents, void *cb_data);

#endif

/*
 * dasd - Library for DASD related functions
 *
 * DASD related helper functions for accessing device information via sysfs
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "lib/dasd_sys.h"

/**
 * Get raw-track access mode status
 *
 * The "devnode" parameter can be any valid relative or absolute path to
 * a DASD device node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	devnode		Device node of interest
 *
 * @retval	1		Raw-track access mode is enabled
 * @retval	0		Raw-track access mode is disabled or
 *				cannot be determined
 */
int dasd_sys_raw_track_access(char *devnode)
{
	char busid[9];
	char path[47];
	FILE *fp;
	int rc;

	if (u2s_getbusid(devnode, busid))
		return 0;

	sprintf(path, "/sys/bus/ccw/devices/%s/raw_track_access", busid);

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	rc = fgetc(fp) - '0';
	fclose(fp);

	return (rc == 1) ? 1 : 0;
}


int dasd_get_pm_from_chpid(char *busid, unsigned int chpid, int *mask)
{
	unsigned int val;
	char path[40];
	int count, i;
	FILE *fp;

	sprintf(path, "/sys/bus/ccw/devices/%s/../chpids", busid);
	*mask = 0;
	fp = fopen(path, "r");
	if (!fp)
		return ENODEV;

	for (i = 0; i < 8; i++) {
		count = fscanf(fp, " %x", &val);
		if (count != 1) {
			fclose(fp);
			return EIO;
		}
		if (val == chpid)
			*mask = 0x80 >> i;
	}
	fclose(fp);

	return 0;
}

/**
 * reset chpid
 *
 * The "devnode" parameter can be any valid relative or absolute path to
 * a DASD device node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	devnode		Device node of interest
 * @param[in]	chpid		The chpid to reset
 *                              If NULL all chpids will be reset
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  No valid chpid specified.
 *   - ENODEV  Could not open device.
 *   - ENOENT  Specified chpid not found.
 *   - EIO     Other I/O error
 *
 */
int dasd_reset_chpid(char *devnode, char *chpid_char)
{
	unsigned int chpid;
	char path[41];
	char busid[9];
	int  mask, rc;
	char *endptr;
	FILE *fp;

	if (u2s_getbusid(devnode, busid))
		return ENODEV;

	if (!chpid_char) {
		sprintf(path, "/sys/bus/ccw/devices/%s/path_reset", busid);
		fp = fopen(path, "w");
		if (!fp)
			return ENODEV;
		fprintf(fp, "%s", "all\n");
		fclose(fp);
		return 0;
	}

	errno = 0;
	chpid = strtoul(chpid_char, &endptr, 16);
	if (errno || (endptr && (*endptr != '\0')))
		return EINVAL;

	rc = dasd_get_pm_from_chpid(busid, chpid, &mask);
	if (rc)
		return rc;
	if (!mask)
		return ENOENT;

	sprintf(path, "/sys/bus/ccw/devices/%s/path_reset", busid);
	fp = fopen(path, "w");
	if (!fp)
		return ENODEV;
	fprintf(fp, "%02x", mask);
	fclose(fp);

	return 0;
}

/*
 * Get dasd info for device
 *
 * @param[in]	info	struct where info will be saved
 * `info->device' must be initialized with the name of the device for which to
 * get the dasd info
 *
 * @retval	-1	could not get dasd info
 * @retval	0	dasd info obtained
 */
int dasd_get_info(dasd_info_t *info)
{
	int fd;
	struct dasd_eckd_characteristics *characteristics;

	fd = open(info->device, O_RDONLY);
	if (fd == -1)
	{
		warnx("open error\n" \
			"Could not open device '%s'.\n"
			"Maybe you have specified an unknown device or \n"
			"you are not authorized to do that.",
			info->device);
		return -1;
	}

	/* get disk geometry */
	if (ioctl(fd, HDIO_GETGEO, &info->geo) != 0)
	{
		close(fd);
		warnx("ioctl error\n" \
			"Could not retrieve disk geometry " \
			"information.");
		return -1;
	}

	if (ioctl(fd, BLKSSZGET, &info->blksize) != 0)
	{
		close(fd);
		warnx("ioctl error\n" \
			"Could not retrieve blocksize information!");
		return -1;
	}

	/* get disk information */
	if (ioctl(fd, BIODASDINFO2, &info->dasd_info) == 0) {
		info->dasd_info_version = 2;
	} else {
		/* INFO2 failed - try INFO using the same (larger) buffer */
		if (ioctl(fd, BIODASDINFO, &info->dasd_info) != 0) {
			close(fd);
			warnx("ioctl error\n"	\
					"Could not retrieve disk information.");
			return -1;
		}
	}

	characteristics = (struct dasd_eckd_characteristics *)
		&info->dasd_info.characteristics;
	if (characteristics->no_cyl == LV_COMPAT_CYL &&
			characteristics->long_no_cyl)
		info->hw_cylinders = characteristics->long_no_cyl;
	else
		info->hw_cylinders = characteristics->no_cyl;
	close(fd);

	if(u2s_getbusid(info->device, info->busid) == -1)
		info->busid_valid = 0;
	else
		info->busid_valid = 1;

	info->raw_track_access = dasd_sys_raw_track_access(info->device);

	return 0;
}

void
dasd_read_vlabel(dasd_info_t *info, volume_label_t *vlabel)
{
	volume_label_t tmp;
	unsigned long  pos;

	pos = info->dasd_info.label_block * info->blksize;

	bzero(vlabel, sizeof(volume_label_t));
	if ((strncmp(info->dasd_info.type, "ECKD", 4) == 0) &&
	    (!info->dasd_info.FBA_layout)) {
		/* OS/390 and zOS compatible disk layout */
		vtoc_read_volume_label(info->device, pos, vlabel);
	}
	else {
		/* standard LINUX disk layout */
		vtoc_read_volume_label(info->device, pos, &tmp);
		memcpy(vlabel->vollbl, &tmp, sizeof(tmp)-4);
	}
}

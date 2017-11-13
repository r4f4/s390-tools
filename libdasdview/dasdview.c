#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "lib/dasdview.h"

#define ERROR_STRING_SIZE 1024
static char error_str[ERROR_STRING_SIZE];

/*
 * Generate and print an error message based on the formatted
 * text string FMT and a variable amount of extra arguments.
 */
void
zt_error_print(const char *fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	vsnprintf(error_str, ERROR_STRING_SIZE, fmt, args);
	va_end (args);

	fprintf(stderr, "Error: %s\n", error_str);
}


/*
 * Attempts to find the sysfs entry for the given busid and reads
 * the contents of a specified attribute to the buffer
 */
static int dasdview_read_attribute(char *busid, char *attribute, char *buffer,
				   size_t count)
{
	char path[100];
	int rc, fd;
	ssize_t rcount;

	rc = 0;
	snprintf(path, sizeof(path), "/sys/bus/ccw/devices/%s/%s",
		 busid, attribute);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return errno;
	rcount = read(fd, buffer, count);
	if (rcount < 0)
		rc = errno;
	close(fd);
	return rc;
}

int
dasdview_get_info(dasdview_info_t *info)
{
	int fd;
	struct dasd_eckd_characteristics *characteristics;
	char buffer[10];
	int rc;

	fd = open(info->device, O_RDONLY);
	if (fd == -1)
	{
		zt_error_print("dasdview: open error\n" \
			"Could not open device '%s'.\n"
			"Maybe you have specified an unknown device or \n"
			"you are not authorized to do that.\n",
			info->device);
		return -1;
	}

	/* get disk geometry */
	if (ioctl(fd, HDIO_GETGEO, &info->geo) != 0)
	{
	        close(fd);
		zt_error_print("dasdview: ioctl error\n" \
			"Could not retrieve disk geometry " \
			"information.");
		return -1;
	}

	if (ioctl(fd, BLKSSZGET, &info->blksize) != 0)
	{
	        close(fd);
		zt_error_print("dasdview: ioctl error\n" \
			"Could not retrieve blocksize information!\n");
		return -1;
	}

	/* get disk information */
	if (ioctl(fd, BIODASDINFO2, &info->dasd_info) == 0) {
		info->dasd_info_version = 2;
	} else {
		/* INFO2 failed - try INFO using the same (larger) buffer */
		if (ioctl(fd, BIODASDINFO, &info->dasd_info) != 0) {
			close(fd);
			zt_error_print("dasdview: ioctl error\n"	\
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

	rc = dasdview_read_attribute(info->busid, "raw_track_access", buffer,
				sizeof(buffer));
	if (rc) {
		zt_error_print("dasdview: Could not retrieve raw_track_access"
			       " mode information.");
		return 0;
	}
	if ('1' == buffer[0])
		info->raw_track_access = 1;

	return 0;
}

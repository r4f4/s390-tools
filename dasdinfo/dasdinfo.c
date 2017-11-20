/*
 * dasdinfo - Display unique DASD ID, either UID or volser
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lib/dasd_sys.h"
#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

#define RD_BUFFER_SIZE 80
#define TEMP_DEV_MAX_RETRIES    1000

static const struct util_prg prg = {
	.desc = "Display DASD volume serial number and ID information",
	.args = "-i BUSID | -b BLOCKDEV | -d DEVNODE",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2007,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("DEVICE"),
	{
		.option = { "block", required_argument, NULL, 'b' },
		.argument = "BLOCKDEV",
		.desc = "Block device name, e.g. dasdb",
	},
	{
		.option = { "devnode", required_argument, NULL, 'd' },
		.argument = "DEVNODE",
		.desc = "Device node, e.g. /dev/dasda",
	},
	{
		.option = { "busid", required_argument, NULL, 'i' },
		.argument = "BUSID",
		.desc = "Bus ID, e.g. 0.0.e910",
	},
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "label", no_argument, NULL, 'l' },
		.desc = "Print DASD volume label (volser)",
	},
	{
		.option = { "uid", no_argument, NULL, 'u' },
		.desc = "Print DASD uid (without z/VM minidisk token)",
	},
	{
		.option = { "extended-uid", no_argument, NULL, 'x' },
		.desc = "Print DASD uid (including z/VM minidisk token)",
	},
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Same as -u -x -l",
	},
	{
		.option = { "export", no_argument, NULL, 'e' },
		.desc = "Export ID_BUS, ID_TYPE, ID_SERIAL for use in udev",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/* needed because ftw can not pass arbitrary arguments */
static char *searchbusid;
static char *busiddir;


static int dinfo_read_dasd_uid(char *uidfile, char *readbuf)
{
	return util_file_read_line(readbuf, RD_BUFFER_SIZE, uidfile);
}

static int dinfo_read_dasd_vlabel (char *device, volume_label_t *vlabel,
				   char *readbuf)
{
	char vollbl[5];
	char *space;

	bzero(vlabel, sizeof(volume_label_t));

	strcpy(info.device, device);
	if (dasd_get_info(&info) != 0)
		return -1;

	dasd_read_vlabel(&info, &vlabel);

	bzero(readbuf, 7);
	bzero(vollbl, 5);
	strncpy(vollbl, vlabel->vollbl, 4);
	vtoc_ebcdic_dec(vollbl, vollbl, 4);

	if ((strncmp(vollbl, "VOL1", 4) == 0) ||
	    (strncmp(vollbl, "LNX1", 4) == 0) ||
	    (strncmp(vollbl, "CMS1", 4) == 0)) {
		strncpy(readbuf, vlabel->volid, 6);
		vtoc_ebcdic_dec(readbuf, readbuf, 6);
		space = strchr(readbuf,' ');
		if (space)
			*space = 0;
	} else
		strcpy(readbuf, "");

	return 0;
}

static void *dinfo_malloc(size_t size)
{
	void *result;

	result = malloc(size);
	if (result == NULL) {
		printf("Could not allocate %lld bytes of memory",
			(unsigned long long) size);
	}
	return result;
}

static char *dinfo_make_path(char *dirname, char *filename)
{
	char *result;
	size_t len;

	len = strlen(dirname) + strlen(filename) + 2;
	result = (char *) dinfo_malloc(len);
	if (result == NULL)
		return NULL;
	sprintf(result, "%s/%s", dirname, filename);
	return result;
}

static int dinfo_create_devnode(dev_t dev, char **devno)
{
	char *result;
	char * pathname[] = { "/dev", getenv("TMPDIR"), "/tmp",
				getenv("HOME"), "." , "/"};
	char filename[] = "dasdinfo0000";
	mode_t mode;
	unsigned int path;
	int retry;
	int rc;
	int fd;

	mode = S_IFBLK | S_IRWXU;

	/* Try several locations for the temporary device node. */
	for (path=0; path < sizeof(pathname) / sizeof(pathname[0]); path++) {
		if (pathname[path] == NULL)
			continue;
		for (retry=0; retry < TEMP_DEV_MAX_RETRIES; retry++) {
			sprintf(filename, "dasdinfo%04d", retry);
			result = dinfo_make_path(pathname[path], filename);
			if (result == NULL)
				return -1;
			rc = mknod(result, mode, dev);
			if (rc == 0) {
				/* Need this test to cover
				 * 'nodev'-mounted
				 * filesystems. */
				fd = open(result, O_RDONLY);
				if (fd != -1) {
					close(fd);
					*devno = result;
					return 0;
				}
				remove(result);
				retry = TEMP_DEV_MAX_RETRIES;
			} else if (errno != EEXIST)
				retry = TEMP_DEV_MAX_RETRIES;
			free(result);
		}
	}
	printf("Error: Unable to create temporary device node");
	return -1;
}

static void dinfo_free_devnode(char *device)
{
	if (remove(device)) {
		printf("Warning: Could not remove "
			"temporary file %s", device);
	}
}

static int dinfo_extract_dev(dev_t *dev, char *str)
{
	char tmp[RD_BUFFER_SIZE];
	char *p = NULL;
	int ma, mi;

	bzero(tmp, RD_BUFFER_SIZE);
	strncpy(tmp, str, RD_BUFFER_SIZE);
	if ((p = strchr(tmp, ':')) == NULL) {
		printf("Error: unable to extract major/minor\n");
		return -1;
	}

	*p = '\0';
	ma = atoi(tmp);
	mi = atoi(p + sizeof(char));

	*dev = makedev(ma, mi);

	return 0;
}

static int dinfo_get_dev_from_blockdev(char *blockdev, dev_t *dev)
{
	char *readbuf = NULL;

	readbuf = dinfo_malloc(RD_BUFFER_SIZE);
	if (!readbuf) {
		printf("Error: Not enough memory to allocate readbuffer\n");
		return -1;
	}
	if (util_file_read_line(readbuf, RD_BUFFER_SIZE,
				"/sys/block/%s/dev", blockdev) < 0)
		return -1;
	if (dinfo_extract_dev(dev, readbuf) != 0)
		return -1;

	return 0;
}

static int
dinfo_is_busiddir(const char *fpath, const struct stat *UNUSED(sb),
		  int tflag, struct FTW *ftwbuf)
{
	char *tempdir;
	char linkdir[128];
	ssize_t i;
	if (tflag != FTW_D || (strncmp((fpath + ftwbuf->base), searchbusid,
				       strlen(searchbusid)) != 0))
		return FTW_CONTINUE;
	/*
	 * ensure that the found entry is a busid and not a
	 * subchannel ID
	 * for large systems subchannel IDs may look like busids
	 */
	if (asprintf(&tempdir, "%s/driver", fpath) < 0)
		return -1;
	i = readlink(tempdir, linkdir, 128);
	free(tempdir);
	if ((i < 0) || (i >= 128))
		return -1;
	/* append '\0' because readlink returns non zero terminated string */
	tempdir[i+1] = '\0';
	if (strstr(linkdir, "dasd") == NULL)
		return FTW_CONTINUE;
	free(busiddir);
	busiddir = strdup(fpath);
	if (busiddir == NULL)
		return -1;
	return FTW_STOP;
}

static int
dinfo_find_entry(const char *dir, const char *searchstring,
		 char type, char **result)
{
	DIR *directory = NULL;
	struct dirent *dir_entry = NULL;
	directory = opendir(dir);
	if (directory == NULL)
		return -1;
	while ((dir_entry = readdir(directory)) != NULL) {
		/* compare if the found entry has exactly the same name
		   and type as searched */
		if ((strncmp(dir_entry->d_name, searchstring,
			     strlen(searchstring)) == 0)
		    && (dir_entry->d_type & type)) {
			*result = strdup(dir_entry->d_name);
			if (*result == NULL)
				goto out;
			closedir(directory);
			return 0; /* found */
		}
	}
out:
	closedir(directory);
	return -1; /* nothing found or error */
}

static int
dinfo_get_blockdev_from_busid(char *busid, char **blkdev)
{
	int flags = FTW_PHYS; /* do not follow links */
	int rc = -1;

	char *tempdir = NULL;
	char *result = NULL;
	char *sysfsdir = "/sys/devices/";

	/* dinfo_is_devnode needs to know the busid */
	searchbusid = busid;
	if (nftw(sysfsdir, dinfo_is_busiddir, 200, flags) != FTW_STOP)
		goto out;

	/*
	 * new sysfs: busid directory  contains a directory 'block'
	 * which contains a directory 'dasdXXX'
	 */
	rc = dinfo_find_entry(busiddir, "block", DT_DIR, &result);
	if (rc == 0) {
		if (asprintf(&tempdir, "%s/%s/", busiddir, result) < 0) {
			rc = -1;
			goto out2;
		}
		rc = dinfo_find_entry(tempdir, "dasd", DT_DIR, blkdev);
	} else {
		/*
		 * old sysfs: entry for busiddir contain a link
		 * 'block:dasdXXX'
		 */
		rc = dinfo_find_entry(busiddir, "block:", DT_LNK, &result);
		if (rc != 0)
			goto out2;
		*blkdev = strdup(strchr(result, ':') + 1);
		if (*blkdev == NULL)
			rc = -1;
	}

out:
	free(tempdir);
out2:
	free(busiddir);
	free(result);
	return rc;
}

static int dinfo_get_uid_from_devnode(char **uidfile, char *devnode)
{
	struct stat stat_buffer;
	char stat_dev[RD_BUFFER_SIZE];
	char *readbuf;
	DIR *directory = NULL;
	struct dirent *dir_entry = NULL;
	int rc = 0;

	if (stat(devnode, &stat_buffer) != 0) {
		printf("Error: could not stat %s\n", devnode);
		return -1;
	}

	sprintf(stat_dev, "%d:%d", major(stat_buffer.st_rdev),
		minor(stat_buffer.st_rdev));

	if ((directory = opendir("/sys/block/")) == NULL) {
		printf("Error: could not open directory /sys/block\n");
		return -1;
	}

	readbuf = dinfo_malloc(RD_BUFFER_SIZE);
	if (!readbuf) {
		printf("Error: Not enough memory to allocate readbuffer\n");
		return -1;
	}

	while ((dir_entry = readdir(directory)) != NULL) {
		if (util_file_read_line(readbuf, RD_BUFFER_SIZE,
					"/sys/block/%s/dev",
					dir_entry->d_name) < 0)
			continue;

		if (strncmp(stat_dev, readbuf,
			    MAX(strlen(stat_dev), strlen(readbuf)-1)) == 0) {
			rc = snprintf(*uidfile, RD_BUFFER_SIZE,
				      "/sys/block/%s/device/uid",
				      dir_entry->d_name);
			if (rc >= RD_BUFFER_SIZE) {
				fprintf(stderr,
					"Error: Device name was truncated\n");
				return -1;
			}

			break;
		}
	}

	closedir(directory);
	return 0;
}

int main(int argc, char * argv[])
{
	struct utsname uname_buf;
	int version, release;
	char *uidfile = NULL;
	char *device = NULL;
	char *readbuf = NULL;
	dev_t dev;
	int export = 0;
	int c;
	int print_uid = 0;
	int print_extended_uid = 0;
	int print_vlabel = 0;
	char *blockdev = NULL;
	char *busid = NULL;
	char *devnode = NULL;
	volume_label_t vlabel;
	char *srchuid;
	int i, rc = 0;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			print_uid = 1;
			print_vlabel = 1;
			print_extended_uid = 1;
			break;
		case 'u':
			print_uid = 1;
			break;
		case 'x':
			print_extended_uid = 1;
			break;
		case 'l':
			print_vlabel = 1;
			break;
		case 'i':
			busid=strdup(optarg);
			break;
		case 'b':
			blockdev=strdup(optarg);
			break;
		case 'd':
			devnode=strdup(optarg);
			break;
		case 'e':
			export = 1;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		default:
			fprintf(stderr, "Try 'dasdinfo --help' for more "
				"information.\n");
			exit(1);
		}
	}

	uname(&uname_buf);
	sscanf(uname_buf.release, "%d.%d", &version,&release);
	if (strcmp(uname_buf.sysname,"Linux") ||
	    version < 2 || (version == 2 && release < 6)) {
		printf("%s %d.%d is not supported\n", uname_buf.sysname,
			version,release);
		exit(1);
	}

	if (!busid && !blockdev && !devnode) {
		printf("Error: please specify a device using either -b, -i "
		       "or -d\n");
		exit(1);
	}

	if ((busid && blockdev) || (busid && devnode) || (blockdev && devnode)) {
		printf("Error: please specify device only once,  either -b, -i "
		       "or -d\n");
		exit(1);
	}

	if (!print_uid && !print_extended_uid && !print_vlabel) {
		printf("Error: no action specified (e.g. -u)\n");
		exit(1);
	}

	readbuf = dinfo_malloc(RD_BUFFER_SIZE);
	uidfile = dinfo_malloc(RD_BUFFER_SIZE);
	if (!(readbuf && uidfile))
		exit(1);

	/* try to read the uid attribute */
	if (busid) {
		sprintf(uidfile,"/sys/bus/ccw/devices/%s/uid", busid);
	} else if (blockdev) {
		sprintf(uidfile,"/sys/block/%s/device/uid", blockdev);
	} else if (devnode) {
		if (dinfo_get_uid_from_devnode(&uidfile, devnode) != 0)
			goto error;
	}

	if (export) {
		printf("ID_BUS=ccw\n");
		printf("ID_TYPE=disk\n");
	}

	if (print_uid) {
		if (dinfo_read_dasd_uid(uidfile, readbuf) == 0) {
			/* look for the 4th '.' and cut there */
			srchuid = readbuf - 1;
			for (i = 0; i < 4; ++i) {
				srchuid = index(srchuid + 1, '.');
				if (!srchuid)
					break;
			}
			if (srchuid) {
				srchuid[0] = '\n';
				srchuid[1] = 0;
			}
			if (export) {
				printf("ID_UID=%s\n", readbuf);
			} else
				printf("%s\n", readbuf);
			if (!print_vlabel && !print_extended_uid)
				goto out;
		}
	}

	if (print_extended_uid) {
		if (dinfo_read_dasd_uid(uidfile, readbuf) == 0) {
			if (export) {
				printf("ID_XUID=%s\n", readbuf);
			} else
				printf("%s\n", readbuf);
			if (!print_vlabel)
				goto out;
		}
	}

	/* there is no uid, try to read the volume serial */
	if (busid) {
		char *blockdev_name = NULL;

		if (dinfo_get_blockdev_from_busid(busid, &blockdev_name) != 0)
			goto error;

		if (dinfo_get_dev_from_blockdev(blockdev_name, &dev) != 0)
			goto error;

		if (dinfo_create_devnode(dev, &device) != 0)
			goto error;

		free(blockdev_name);

	} else if (blockdev) {
		if (dinfo_get_dev_from_blockdev(blockdev, &dev) != 0)
			goto error;

		if (dinfo_create_devnode(dev, &device) != 0)
			goto error;

	} else if (devnode) {
		device = dinfo_malloc(RD_BUFFER_SIZE);
		if (!device)
			exit(1);
		strcpy(device, devnode);
	}

	if (dinfo_read_dasd_vlabel(device, &vlabel, readbuf) == 0) {
		if (export) {
			printf("ID_SERIAL=%s\n",readbuf);
		} else
			printf("%s\n", readbuf);
		goto out;
	}

error:
	printf("Error: could not read unique DASD ID\n");
	rc = 1;

out:
	if (device && (busid || blockdev))
		dinfo_free_devnode(device);

	free(uidfile);
	free(device);
	free(readbuf);

	exit(rc);
}

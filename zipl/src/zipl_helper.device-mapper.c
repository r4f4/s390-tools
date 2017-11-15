/*
 *
 * zipl_helper.device-mapper: print zipl parameters for a device-mapper device
 *
 * Copyright IBM Corp. 2009, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Depending on the name by which the script is called, it serves one of two
 * purposes:
 *
 * 1. Usage: zipl_helper.device-mapper <target directory> or
 *                                     <major:minor of target device>
 *
 * This tool attempts to obtain zipl parameters for a target directory or
 * partition located on a device-mapper device. It assumes that the
 * device-mapper table for this device conforms to the following rules:
 * - directory is located on a device consisting of a single device-mapper
 *   target
 * - only linear, mirror and multipath targets are supported
 * - supported physical device types are DASD and SCSI devices
 * - all of the device which contains the directory must be located on a single
 *   physical device (which may be mirrored or accessed through a multipath
 *   target)
 * - any mirror in the device-mapper setup must include block 0 of the
 *   physical device
 *
 * 2. Usage: chreipl_helper.device-mapper <major:minor of target device>
 *
 * This tool identifies the physical device which contains the specified
 * device-mapper target devices. If the physical device was found, its
 * major:minor parameters are printed. Otherwise, the script exits with an
 * error message and a non-zero return code.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <linux/limits.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>

#include "lib/util_list.h"
#include "lib/util_libc.h"
#include "lib/util_file.h"
#include "lib/dasdview.h"

struct target_status {
	char *path;
	char status;
	struct util_list_node list;
};

struct target_data {
	dev_t device;
	unsigned long start;
	struct util_list_node list;
};

struct target {
	unsigned long start;
	unsigned long length;
	unsigned short type;
	struct util_list *data;
	struct util_list_node list;
};

struct target_entry {
	dev_t device;
	struct target *target;
	struct util_list_node list;
};

struct physical_device {
	dev_t device;
	unsigned long offset;
	struct util_list *target_list;
};

struct device_characteristics {
	unsigned short type;
	unsigned long blocksize;
	struct {
		unsigned long cylinders;
		unsigned long heads;
		unsigned long sectors;
	} geometry;
	unsigned long bootsectors;
	unsigned long partstart;
};

/* From include/linux/fs.h */
#define BDEVNAME_SIZE 32

#define PARTITIONS_FILE "/proc/partitions"

/* Constants */
const unsigned int SECTOR_SIZE = 512;
const unsigned int DASD_PARTN_MASK = 0x03;
const unsigned int SCSI_PARTN_MASK = 0x0f;

const char CHREIPL_HELPER[] = "chreipl_helper.device-mapper";

/* Internal constants */
enum dev_type {
	DEV_TYPE_CDL = 0,
	DEV_TYPE_LDL,
	DEV_TYPE_FBA,
	DEV_TYPE_SCSI
};

enum target_type {
	TARGET_TYPE_LINEAR = 0,
	TARGET_TYPE_MIRROR,
	TARGET_TYPE_MULTIPATH
};


static void
get_type_name(char *name, unsigned short type)
{
	switch (type) {
		case DEV_TYPE_SCSI:
			strcpy(name, "SCSI");
			break;
		case DEV_TYPE_CDL:
			strcpy(name, "CDL");
			break;
		case DEV_TYPE_FBA:
			strcpy(name, "FBA");
			break;
		case DEV_TYPE_LDL:
			strcpy(name, "LDL");
			break;
		default:
			fprintf(stderr, "Error: unrecognized dev type %d\n", type);
	}
}


static FILE *
execute_command_and_get_output_stream(const char *fmt, ...)
{
	char *cmd;
	va_list ap;
	FILE *stream;

	va_start(ap, fmt);
	util_vasprintf(&cmd, fmt, ap);
	va_end(ap);

	stream = popen(cmd, "r");
	if (!stream) {
		fprintf(stderr, "Error: '%s' failed", cmd);
		free(cmd);
		return NULL;
	}

	free(cmd);
	return stream;
}


static inline struct target_data *
target_data_new(unsigned int maj, unsigned int min, unsigned int start)
{
	struct target_data *td = util_malloc(sizeof(struct target_data));
	td->device = makedev(maj, min);
	td->start = start;

	return td;
}

static inline void
target_data_free(struct target_data *td)
{
	free(td);
}

static void
target_data_list_free(struct util_list *data)
{
	struct target_data *td, *n;

	util_list_iterate_safe(data, td, n) {
		util_list_remove(data, td);
		target_data_free(td);
	}
	util_list_free(data);
}

static inline struct target *
target_new(unsigned long start, unsigned long length, unsigned short type, struct util_list *data)
{
	struct target *entry = util_malloc(sizeof(struct target));

	entry->start = start;
	entry->length = length;
	entry->type = type;
	entry->data = data;

	return entry;
}

static void
target_free(struct target *target)
{
	struct target_data *e, *n;

	util_list_iterate_safe(target->data, e, n) {
		util_list_remove(target->data, e);
		target_data_free(e);
	}
	util_list_free(target->data);
	free(target);
}

static inline unsigned long
target_get_start(struct target *t)
{
	struct target_data *td = util_list_start(t->data);
	return td->start;
}

static inline void
target_get_major_minor(struct target *t, unsigned int *maj, unsigned int *min)
{
	struct target_data *td = util_list_start(t->data);
	*maj = major(td->device);
	*min = minor(td->device);
}

static struct target_entry *
target_entry_new(dev_t dev, struct target *t)
{
	struct target_entry *te = util_malloc(sizeof(struct target_entry));
	te->device = dev;
	te->target = t;

	return te;
}

static inline void
target_entry_free(struct target_entry *entry)
{
	target_free(entry->target);
	free(entry);
}

static struct target_entry *
target_list_get_first_by_type(struct util_list *target_list, unsigned short type)
{
	struct target_entry *entry;

	util_list_iterate(target_list, entry) {
		if (entry->target->type == type)
			return entry;
	}
	return NULL;
}

static void
target_list_free(struct util_list *target_list)
{
	struct target_entry *entry, *n;

	util_list_iterate_safe(target_list, entry, n) {
		util_list_remove(target_list, entry);
		target_entry_free(entry);
	}
	util_list_free(target_list);
}


static void
get_device_name(char *devname, dev_t dev)
{
	FILE *fd = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	sprintf(devname, "%u:%u", major(dev), minor(dev));

	fd = fopen(PARTITIONS_FILE, "r");
	if (!fd)
		return;

	if (getline(&line, &len, fd) == -1) /* Ignore header */
		goto out;
	if (getline(&line, &len, fd) == -1) /* Ignore empty line */
		goto out;

	while ((read = getline(&line, &len, fd)) != -1) {
		char buf[BDEVNAME_SIZE];
		unsigned int mj, mn;

		sscanf(line, "%d %d %*u %s", &mj, &mn, buf);
		if (major(dev) == mj && minor(dev) == mn) {
			strcpy(devname, buf);
			break;
		}
	}

out:
	free(line);
	fclose(fd);
}


static long
get_blocksize(const char *device)
{
	int fd;
	long size;

	fd = open(device, O_RDONLY);
	if (fd == -1)
		return -1;
	if (ioctl(fd, BLKSSZGET, &size) != 0) {
		close(fd);
		return -1;
	}
	close(fd);

	return size;
}


static int
create_temp_device_node(char *name, unsigned int major, unsigned int minor)
{
	int num;
	const char path_base[] = "/dev";
	char buf[PATH_MAX];

	for (num = 0; num < 100; num++) {
		snprintf(buf, sizeof(buf), "%s/zipl-dm-temp-%02d", path_base, num);
		if (!access(buf, F_OK))
			continue;
		if (mknod(buf, S_IFBLK, makedev(major, minor)))
			continue;
		strcpy(name, buf);
		return 0;
	}
	fprintf(stderr, "Error: Could not create temporary device node in "
			"'%s'\n", path_base);
	return -1;
}


static int
get_partition_start(unsigned int maj, unsigned int min)
{
	unsigned long val;
	if (util_file_read_ul(&val, 10, "/sys/dev/block/%u:%u/start",
			maj, min) != 0) {
		return 0;
	}
	return val;
}


static int
get_device_characteristics(struct device_characteristics *dc, dev_t dev)
{
	int res;
	dasdview_info_t info;

	if (create_temp_device_node(info.device, major(dev), minor(dev)))
		return -1;

	res = dasdview_get_info(&info);
	if (res != 0) { // assume SCSI if dasdinfo failed
		long blocksize = get_blocksize(info.device);
		if (blocksize < 0) {
			unlink(info.device);
			fprintf(stderr, "Error: Could not get block size for '%s'\n",
					info.device);
			return -1;
		}
		dc->blocksize = blocksize;
		dc->type = DEV_TYPE_SCSI;
		// first block contains IPL records
		dc->bootsectors = dc->blocksize / SECTOR_SIZE;
	} else {
		unsigned int sectors = info.geo.sectors;
		dc->blocksize = info.blksize;
		if (!strcmp(info.dasd_info.type, "FBA")) {
			dc->type = DEV_TYPE_FBA;
			dc->bootsectors = dc->blocksize / SECTOR_SIZE;
		}
		else if (!strcmp(info.dasd_info.type, "ECKD")) {
			if (info.dasd_info.format == 1) {
				dc->type = DEV_TYPE_LDL;
				dc->bootsectors = dc->blocksize * 2 / SECTOR_SIZE;
			}
			else if (info.dasd_info.format == 2) {
				dc->type = DEV_TYPE_CDL;
				dc->bootsectors = dc->blocksize * sectors / SECTOR_SIZE;
			}
		}
		dc->geometry.cylinders = info.hw_cylinders;
		dc->geometry.heads = info.geo.heads;
		dc->geometry.sectors = info.geo.sectors;
	}
	dc->partstart = get_partition_start(major(dev), minor(dev));
	dc->partstart /= (dc->blocksize / SECTOR_SIZE);

	unlink(info.device);
	return 0;
}


static struct util_list *
get_linear_data(const char *devname, char *args)
{
	struct util_list *data;
	unsigned int maj, min, start;

	if (sscanf(args, "%u:%u %u", &maj, &min, &start) < 3) {
		fprintf(stderr, "Error: unrecognized device-mapper table format for"
				" device '%s'\n", devname);
		return NULL;
	}

	data = util_list_new(struct target_data, list);
	util_list_add_head(data, target_data_new(maj, min, start));

	return data;
}


#define STR_TOKEN_OR_GOTO(string, tok, label)		\
	do {											\
		char *tp = strtok(string, " ");				\
		if (!tp) {									\
			goto label;								\
		}											\
		tok = tp;									\
	} while (0)

#define NEXT_STR_TOKEN_OR_GOTO(tok, label)			\
	STR_TOKEN_OR_GOTO(NULL, tok, label)

#define INT_TOKEN_OR_GOTO(string, tok, label)		\
	do {											\
		char *tp = strtok(string, " ");				\
		if (!tp) {									\
			goto label;								\
		}											\
		errno = 0;									\
		tok = strtol(tp, NULL, 10);					\
		if (((errno == ERANGE) &&					\
			(tok == LONG_MIN || tok == LONG_MAX)) ||\
			(errno != 0 && tok == 0)) {				\
			goto label;								\
		}											\
	} while (0)

#define NEXT_INT_TOKEN_OR_GOTO(tok, label)			\
	INT_TOKEN_OR_GOTO(NULL, tok, label)

#define SKIP_NEXT_TOKENS_OR_GOTO(count, label)		\
	do {											\
		for (; count > 0; count--) {				\
			if (!strtok(NULL, " ")) {				\
				goto label;							\
			}										\
		}											\
	} while (0)

/*
 * There is no kernel documentation for the mirror target. Parameters obtained
 * from Linux sources: drivers/md/dm-log.c and drivers/md/dm-raid1.c
 *
 * <starting_sector> <length> mirror \
 * <log_type> <#log_args> <log_arg1>...<log_argN> \
 * <#devs> <device_name_1> <offset_1>...<device name N> <offset N> \
 * <#features> <feature_1>...<feature_N>
 */
static struct util_list *
get_mirror_data(const char *devname __attribute__((unused)), char *args)
{
	char *token;
	long nlogs, ndevs, nfeats;
	struct util_list *data = util_list_new(struct target_data, list);

	STR_TOKEN_OR_GOTO(args, token, out); // log_type

	NEXT_INT_TOKEN_OR_GOTO(nlogs, out); // #log_args
	SKIP_NEXT_TOKENS_OR_GOTO(nlogs, out); // log_args*

	NEXT_INT_TOKEN_OR_GOTO(ndevs, out);
	for (; ndevs > 0; ndevs--) {
		char *name;
		long offset;
		unsigned int maj, min;

		NEXT_STR_TOKEN_OR_GOTO(name, out);
		if (sscanf(name, "%u:%u", &maj, &min) < 2)
			goto out;
		NEXT_INT_TOKEN_OR_GOTO(offset, out);
		util_list_add_head(data, target_data_new(maj, min, offset));
	}
	NEXT_INT_TOKEN_OR_GOTO(nfeats, out);
	SKIP_NEXT_TOKENS_OR_GOTO(nfeats, out);

	return data;

out:
	target_data_list_free(data);
	return NULL;
}


static struct target_status *
target_status_new(const char *path, char status)
{
	struct target_status *ts = util_malloc(sizeof(struct target_status));
	ts->path = util_strdup(path);
	ts->status = status;

	return ts;
}

static void
target_status_free(struct target_status *ts)
{
	free(ts->path);
	free(ts);
}

static void
status_list_free(struct util_list *status)
{
	struct target_status *ts, *n;

	util_list_iterate_safe(status, ts, n) {
		util_list_remove(status, ts);
		target_status_free(ts);
	}
	util_list_free(status);
}

static char
status_list_get_status(struct util_list *status, const char *node)
{
	struct target_status *ts;

	util_list_iterate(status, ts) {
		if (!strcmp(ts->path, node))
			return ts->status;
	}
	return 'F';
}

static struct util_list *
get_multipath_status(const char *devname)
{
	FILE *fp;
	size_t n = 0;
	int len, failed = 0;
	char *line = NULL;
	struct util_list *status;

	fp = execute_command_and_get_output_stream(
			"dmsetup status /dev/%s 2>/dev/null", devname);
	if (!fp) {
		fprintf(stderr, "No paths found for %s\n", devname);
		return NULL;
	}

	status = util_list_new(struct target_status, list);
	while (getline(&line, &n, fp) != -1) {
		long cnt, ngr, ign, length;
		char *token = NULL;
		/* sample output (single line):
		 * 0 67108864 multipath \
		 * 2 0 0 \
		 * 0 \
		 * 2 2 \
		 *     E 0 \
		 *     2 2 \
		 *         8:16 F 1 \
		 *				0 1 \
		 *		   8:0 F 1 \
		 *		       0 1 \
		 *	   A 0 \
		 *	   2 2 \
		 *		   8:32 A 0 \
		 *		        0 1 \
		 *		   8:48 A 0 \
		 *		        0 1
		 */
		STR_TOKEN_OR_GOTO(line, token, out);
		NEXT_INT_TOKEN_OR_GOTO(length, out);
		NEXT_STR_TOKEN_OR_GOTO(token, out); // dtype
		if (!strcmp(token, "multipath"))
			continue;
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #mp_feature_args
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); // mp_feature_args*
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #handler_status_args
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); // handler_status_args*

		NEXT_INT_TOKEN_OR_GOTO(ngr, out);
		NEXT_INT_TOKEN_OR_GOTO(ign, out);
		for (; ngr > 0; ngr--) {
			long npaths, nsa;
			NEXT_STR_TOKEN_OR_GOTO(token, out);
			NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #ps_status_args
			SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); // ps_status_args*
			NEXT_INT_TOKEN_OR_GOTO(npaths, out);
			NEXT_INT_TOKEN_OR_GOTO(nsa, out);
			for (; npaths > 0; npaths--) {
				char *path, *active;
				NEXT_STR_TOKEN_OR_GOTO(path, out);
				NEXT_STR_TOKEN_OR_GOTO(active, out);
				util_list_add_tail(status,
						target_status_new(path, active[0]));
				NEXT_INT_TOKEN_OR_GOTO(cnt, out);
				failed += (*active != 'A');
				SKIP_NEXT_TOKENS_OR_GOTO(nsa, out);
			}
		}
	}

	free(line);
	pclose(fp);

	len = util_list_len(status);
	if (len == 0) {
		fprintf(stderr, "No paths found for '%s'\n", devname);
		goto out;
	} if (failed == len) {
		fprintf(stderr, "All paths for '%s' failed\n", devname);
		goto out;
	} else if (failed > 0) {
		fprintf(stderr, "There are one or more failed paths for device "
				"'%s'\n", devname);
	}

	return status;

out:
	free(line);
	pclose(fp);
	status_list_free(status);
	return NULL;
}

static struct util_list *
get_multipath_data(const char *devname, char *args)
{
	char *token;
	long cnt, pgroups;
	struct util_list *data = util_list_new(struct target_data, list);
	struct util_list *status = get_multipath_status(devname);

	if (!status)
		goto out;

	INT_TOKEN_OR_GOTO(args, cnt, out); // #feat
	SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); // feats*
	NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #handlers
	SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); // handlers*
	NEXT_INT_TOKEN_OR_GOTO(pgroups, out);
	NEXT_STR_TOKEN_OR_GOTO(token, out); // pathgroup
	for (; pgroups > 0; pgroups--) {
		long npaths;

		NEXT_STR_TOKEN_OR_GOTO(token, out); //path_selector
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #selectorargs
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out);
		NEXT_INT_TOKEN_OR_GOTO(npaths, out);
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); // #np_args
		for (; npaths > 0; npaths--) {
			char *path;
			unsigned int maj, min;
			NEXT_STR_TOKEN_OR_GOTO(path, out);
			if (sscanf(path, "%d:%d", &maj, &min) < 2)
				goto out;
			if (status_list_get_status(status, path) == 'A')
				util_list_add_head(data, target_data_new(maj, min, 0));
			SKIP_NEXT_TOKENS_OR_GOTO(cnt, out);
		}
	}

	status_list_free(status);
	return data;

out:
	status_list_free(status);
	target_data_list_free(data);
	return data;
}


static void
table_free(struct util_list *table)
{
	struct target *t, *n;

	util_list_iterate_safe(table, t, n) {
		util_list_remove(table, t);
		target_free(t);
	}
	util_list_free(table);
}

static void
filter_table(struct util_list *table, unsigned int start, unsigned int length)
{
	struct target *target, *n;

	util_list_iterate_safe(table, target, n) {
		if (!(((target->start + target->length - 1) >= start) &&
				(target->start <= (start + length - 1)))) {
			util_list_remove(table, target);
			target_free(target);
		}
	}
}

/*
 * Returns list of target devices
 */
static struct util_list *
get_table(dev_t dev)
{
	FILE *fp;
	size_t n = 0;
	char *line = NULL;
	char devname[BDEVNAME_SIZE];
	struct util_list *table;

	table = util_list_new(struct target, list);
	if (!table)
		return NULL;

	fp = execute_command_and_get_output_stream("dmsetup table -j %u -m %u 2>/dev/null", major(dev), minor(dev));
	if (!fp)
		return table;

	while (getline(&line, &n, fp) != -1) {
		unsigned long start, length;
		unsigned short ttype;
		char *type = NULL, *args = NULL;
		struct util_list *data = NULL;

		if (sscanf(line, "%lu %lu %ms %m[a-zA-Z0-9: -]",
					&start, &length, &type, &args) < 4) {
			get_device_name(devname, dev);
			fprintf(stderr, "Error: Unrecognized device-mapper table "
					"format for device '%s'\n", devname);
			goto out;
		}

		if (!strcmp(type, "linear")) {
			data = get_linear_data(devname, args);
			ttype = TARGET_TYPE_LINEAR;
		} else if (!strcmp(type, "mirror")) {
			data = get_mirror_data(devname, args);
			ttype = TARGET_TYPE_MIRROR;
		} else if (!strcmp(type,"multipath")) {
			data = get_multipath_data(devname, args);
			ttype = TARGET_TYPE_MULTIPATH;
		} else {
			get_device_name(devname, dev);
			fprintf(stderr, "Error: Unsupported setup: Unsupported "
					"device-mapper target type '%s' for device '%s'\n",
					type, devname);
		}
		free(type);
		free(args);
		if (!data)
			goto out;
		util_list_add_head(table, target_new(start, length, ttype, data));
	}

	free(line);
	pclose(fp);

	return table;

out:
	free(line);
	pclose(fp);
	table_free(table);
	return table;
}


static inline bool
is_dasd(unsigned short type)
{
	return (type == DEV_TYPE_CDL) || (type == DEV_TYPE_LDL) ||
		(type == DEV_TYPE_FBA);
}


static int
get_physical_device(struct physical_device *pd, dev_t dev, const char *directory)
{
	unsigned int start, length;
	struct target *target;
	struct util_list *table = NULL;
	struct util_list *target_list = NULL;

	table = get_table(dev);
	if (!table || !util_list_start(table)) {
		char devname[BDEVNAME_SIZE];
		get_device_name(devname, dev);
		fprintf(stderr, "Could not retrieve device-mapper information "
				"for device '%s'\n", devname);
		if (table)
			table_free(table);
		return -1;
	}

	target = util_list_start(table);

	/* Filesystem must be on a single dm target */
	if (util_list_next(table, target)) {
		fprintf(stderr, "Error: Unsupported setup: Directory '%s' is "
				"located on a multi-target device-mapper device\n",
				directory);
		table_free(table);
		return -1;
	}
	util_list_remove(table, target);
	table_free(table);

	target_list = util_list_new(struct target_entry, list);
	util_list_add_head(target_list, target_entry_new(dev, target));
	start = target->start;
	length = target->length;
	while (true) {
		unsigned int mmaj, mmin;

		/* convert fs_start to offset on parent dm device */
		start += target_get_start(target);
		target_get_major_minor(target, &mmaj, &mmin);
		table = get_table(makedev(mmaj, mmin));
		/* Found non-dm device */
		if (!table || !util_list_start(table)) {
			pd->device = makedev(mmaj, mmin);
			pd->offset = start;
			pd->target_list = target_list;
			if (table)
				table_free(table);
			return 0;
		}
		/*
		 * Get target in parent table which contains filesystem
		 * We are interested only in targets between [start,start+length-1]
		 */
		filter_table(table, start, length);
		target = util_list_start(table);
		if (!target || util_list_next(table, target)) {
			fprintf(stderr, "Error: Unsupported setup: Could not map  "
					"directory '%s' to a single physical device",
					directory);
			table_free(table);
			target_list_free(target_list);
			return -1;
		}
		util_list_remove(table, target);
		util_list_add_head(target_list,
				target_entry_new(makedev(mmaj, mmin), target));
		table_free(table);
		/* Convert fs_start to offset on parent target */
		start -= target->start;
	}
}


static inline int
get_major_minor(dev_t *dev, const char *filename)
{
	struct stat buf;

	if (stat(filename, &buf)) {
		fprintf(stderr, "Could not stat '%s'\n", filename);
		return -1;
	}
	*dev = buf.st_dev;
	return 0;
}

static int
get_physical_device_dir(struct physical_device *pd, const char *directory)
{
	dev_t dev;

	if (get_major_minor(&dev, directory) != 0)
		return -1;
	return get_physical_device(pd, dev, directory);
}


static int
get_target_base(dev_t *base, dev_t bottom, unsigned int start __attribute__((unused)), unsigned int length, struct util_list *target)
{
	dev_t top = bottom;
	struct target_entry *te, *mirror;

	util_list_iterate(target, te) {
		if ((te->target->start != 0) || (target_get_start(te->target) != 0) ||
			(te->target->start < length)) {
			break;
		}
		top = te->device;
	}

	/* Check for mirroring between base device and fs device */
	while ((mirror = util_list_next(target, te)) != NULL) {
		if (mirror->target->type == TARGET_TYPE_MIRROR) {
			char name[BDEVNAME_SIZE];
			get_device_name(name, mirror->device);
			fprintf(stderr, "Error: Unsupported setup: Block 0 is not "
					"mirrored in device '%s'\n", name);
			return -1;
		}
	}

	*base = top;
	return 0;
}


static inline dev_t
get_partition_base(unsigned short type, dev_t dev)
{
	return makedev(major(dev), minor(dev) &
			(is_dasd(type) ? ~DASD_PARTN_MASK : ~SCSI_PARTN_MASK));
}


static int
extract_major_minor_from_cmdline(int argc, char *argv[], unsigned int *maj, unsigned int *min)
{
	int i;
	char *cmdline = NULL;

	for (i = 1; i < argc; i++)
		cmdline = util_strcat_realloc(cmdline, argv[i]);

	if (sscanf(cmdline, "%u:%u", maj, min) != 2) {
		free(cmdline);
		return -1;
	}

	free(cmdline);
	return 0;
}


static inline bool
toolname_is_chreipl_helper(const char *toolname)
{
	int tlen = strlen(toolname);
	int clen = strlen(CHREIPL_HELPER);

	if (tlen < clen)
		return false;

	return strcmp(toolname + tlen - clen, CHREIPL_HELPER) == 0;
}


void
print_usage(const char *toolname)
{
	fprintf(stderr, "%s <major:minor of target device>", toolname);
	if (!toolname_is_chreipl_helper(toolname))
		fprintf(stderr, " or <target directory>");
	fprintf(stderr, "\n");
}


int
main(int argc, char *argv[])
{
	int res;
	dev_t base;
	unsigned int maj, min;
	char type_name[8];
	char *directory = NULL;
	const char *toolname = argv[0];
	struct physical_device pd;
	struct device_characteristics dc;

	if (argc == 1)
		goto usage;

	if (!setlocale(LC_ALL, "C")) {
		fprintf(stderr, "Could not use standard locale");
		exit(EXIT_FAILURE);
	}

	if (toolname_is_chreipl_helper(toolname)) {
		if (extract_major_minor_from_cmdline(argc, argv, &maj, &min))
			goto usage;
		if (get_physical_device(&pd, makedev(maj, min), argv[1]))
			exit(EXIT_FAILURE);
		printf("%u:%u\n", major(pd.device), minor(pd.device));
		target_list_free(pd.target_list);
		exit(EXIT_SUCCESS);
	}

	directory = argv[1];
	if (!extract_major_minor_from_cmdline(argc, argv, &maj, &min))
		res = get_physical_device(&pd, makedev(maj, min), directory);
	else if (argc == 2)
		res = get_physical_device_dir(&pd, directory);
	else
		goto usage;

	if (res != 0)
		exit(EXIT_FAILURE);

	if (get_device_characteristics(&dc, pd.device))
		goto error;

	/* Handle partitions */
	if (dc.partstart > 0) {
		struct target_entry *mirror;
		struct device_characteristics ndc;
		/* Only the partition of the physical device is mapped so only the
		 * physical device can provide access to the boot record */
		base = get_partition_base(dc.type, pd.device);
		/* Check for mirror */
		mirror = target_list_get_first_by_type(pd.target_list, TARGET_TYPE_MIRROR);
		if (mirror) {
			char name[BDEVNAME_SIZE];
			get_device_name(name, mirror->device);
			// IPL records are not mirrored
			fprintf(stderr, "Error: Unsupported setup: Block 0 is not "
					"mirrored in device '%s'\n", name);
			goto error;
		}
		/* Adjust filesystem offset */
		pd.offset += (dc.partstart * (dc.blocksize / SECTOR_SIZE));
		dc.partstart = 0;
		/* Update device geometry */
		get_device_characteristics(&ndc, base);
		dc.geometry = ndc.geometry;
	} else {
		/* All of the device is mapped, so the base device is the top most dm
		 * device which provides access to boot sectors */
		if (get_target_base(&base, pd.device, 0, dc.bootsectors, pd.target_list))
			goto error;
	}

	target_list_free(pd.target_list);

	/* Check for valid offset of filesystem */
	if ((pd.offset % (dc.blocksize / SECTOR_SIZE)) != 0) {
		fprintf(stderr, "Error: File system not aligned on physical "
				"block size\n");
		goto error;
	}

	/* Print resulting information */
	printf("targetbase=%u:%u\n", major(base), minor(base));
	get_type_name(type_name, dc.type);
	printf("targettype=%s\n", type_name);
	if (dc.geometry.cylinders && dc.geometry.heads && dc.geometry.sectors) {
		printf("targetgeometry=%lu,%lu,%lu\n",
				dc.geometry.cylinders,
				dc.geometry.heads,
				dc.geometry.sectors);
	}
	printf("targetblocksize=%lu\n", dc.blocksize);
	printf("targetoffset=%lu\n", (pd.offset / (dc.blocksize / SECTOR_SIZE)));

	exit(EXIT_SUCCESS);

error:
	if (pd.target_list)
		target_list_free(pd.target_list);
	exit(EXIT_FAILURE);

usage:
	print_usage(toolname);
	exit(EXIT_FAILURE);
}

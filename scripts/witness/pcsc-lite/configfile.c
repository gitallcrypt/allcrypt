/* Stand-in for configfile.l, which needs flex: reads reader.conf files of
   FRIENDLYNAME/DEVICENAME/LIBPATH/CHANNELID lines, quoted or not. */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "configfile.h"

static SerialReader *list;
static int count;

static char *value_of(char *line) {
	char *p = line;
	while (*p && *p != ' ' && *p != '\t') p++;
	while (*p == ' ' || *p == '\t') p++;
	char *end = p + strlen(p);
	while (end > p && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ')) *--end = 0;
	if (*p == '"' && end > p + 1 && end[-1] == '"') { p++; end[-1] = 0; }
	return strdup(p);
}

static int read_file(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	SerialReader current = {0};
	current.channelId = -1;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, "FRIENDLYNAME", 12)) current.pcFriendlyname = value_of(line);
		else if (!strncmp(line, "DEVICENAME", 10)) current.pcDevicename = value_of(line);
		else if (!strncmp(line, "LIBPATH", 7)) current.pcLibpath = value_of(line);
		else if (!strncmp(line, "CHANNELID", 9)) {
			char *v = value_of(line); current.channelId = (int)strtol(v, NULL, 0); free(v);
		}
		if (current.pcFriendlyname && current.pcLibpath && current.channelId >= 0) {
			if (!current.pcDevicename) current.pcDevicename = strdup("/dev/null");
			list = realloc(list, sizeof(SerialReader) * (count + 2));
			list[count++] = current;
			memset(&list[count], 0, sizeof(SerialReader));
			memset(&current, 0, sizeof current);
			current.channelId = -1;
		}
	}
	fclose(f);
	return 0;
}

int DBGetReaderList(const char *readerconf, SerialReader **caller_reader_list) {
	list = NULL; count = 0;
	if (read_file(readerconf) < 0) return -1;
	*caller_reader_list = list;
	return 0;
}

int DBGetReaderListDir(const char *dir, SerialReader **caller_reader_list) {
	list = NULL; count = 0;
	DIR *d = opendir(dir);
	if (!d) return read_file(dir) < 0 ? -1 : (*caller_reader_list = list, 0);
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.') continue;
		char path[4096];
		snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
		read_file(path);
	}
	closedir(d);
	*caller_reader_list = list;
	return 0;
}

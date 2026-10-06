/* Stand-in for tokenparser.l: used only by the USB hotplug code, which this build leaves out. */
#include "config.h"
#include "simclist.h"
#include "parser.h"
int LTPBundleFindValueWithKey(list_t *l, const char *key, list_t **values) { (void)l; (void)key; (void)values; return -1; }
int bundleParse(const char *fileName, list_t *l) { (void)fileName; (void)l; return -1; }
void bundleRelease(list_t *l) { (void)l; }

#include "thirdparty/linenoise.c"

static string input(string prompt) {
	char* res = linenoise(STR_PTR(prompt));
	linenoiseHistoryAdd(res);
	return STR(res, strlen(res));
}

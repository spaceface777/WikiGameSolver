#ifdef ENABLE_PRETTY_INPUT
#include "thirdparty/linenoise.c"

static string input(string prompt) {
	char* res = linenoise(STR_PTR(prompt));
	if (res == 0) {
		exit(0);
	}
	linenoiseHistoryAdd(res);
	return STR(res, strlen(res));
}
#else
#ifdef _WIN32
int __cdecl write(int _Filehandle,const void *_Buf,unsigned int _MaxCharCount);
#endif
static string input(string prompt) {
	char buf[1024];
	while(1) {
		write(1, STR_PTR(prompt), STR_LEN(prompt));

		if (fgets (&buf[0], sizeof(buf), stdin) == null) {
			puts("invalid input, please try again");
			continue;
		}

		int len = strlen(buf) - 1;
		if (buf[len] != '\n') {
			puts("invalid input, please try again");
			continue;
		}

		// Otherwise remove newline and give string back to caller.
		buf[len] = '\0';
		return string_clone(STR(buf, len));
	}
}

#endif

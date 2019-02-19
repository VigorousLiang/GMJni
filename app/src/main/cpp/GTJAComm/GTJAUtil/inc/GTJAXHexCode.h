#ifndef __GTJAHEXCODE_H__
#define __GTJAHEXCODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL 0
#endif

int GTJAXHexDecode(const unsigned char *szIn, int len, char **szOut);

int GTJAXHexEncode(const char* szIn, const int len, unsigned char **szOut);

#ifdef __cplusplus
}
#endif

#endif

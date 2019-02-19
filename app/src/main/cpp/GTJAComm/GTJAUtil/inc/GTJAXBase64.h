#ifndef __GTJABASE64_H__
#define __GTJABASE64_H__

#include "bio.h"
#include "pem.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL 0
#endif

int Base64Encode(unsigned char* input, int inLen, char** output, int* outLen, bool with_new_line);
int Base64Decode(const char* input, int inLen, unsigned char** out, int* outLen, bool with_new_line);

#ifdef __cplusplus
}
#endif

#endif

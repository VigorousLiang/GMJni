#include "GTJAXHexCode.h"
#include <stdio.h>
#include <string.h>

/**
 * HEX解码 将形如0x12 0x2A 0x01 转换为122A01
 */
int GTJAXHexDecode(const unsigned char *szIn, int len, char **szOut) {
    (*szOut) = new char[len * 2 + 1];
    int i = 0;
    if (*szOut) {
        memset(*szOut, 0x00, len * 2 + 1);
        char* pTemp = *szOut;
        for (i = 0; i < len; i++) {
            sprintf(pTemp, "%02X", szIn[i]);
            pTemp += 2;
        }
    }
    return 2 * i;
}

/**
 * HEX编码 将形如122A01 转换为0x12 0x2A 0x01
 */
int GTJAXHexEncode(const char* szIn, const int len, unsigned char** szOut) {
    (*szOut) = new unsigned char[len/2];
    if ((*szOut) == NULL) {
        return 0;
    }

    memset(*szOut, 0x00, len/2);
	unsigned char* p = (*szOut);
	int j = 0;
	unsigned char hi;
	unsigned char low;

	for(int i = 0;i < len;){
		hi = szIn[i++];
		if( hi>='0' && hi<='9'){
			hi -= '0';
		}else if(hi>='A' && hi<='F'){
			hi -= 'A';
			hi += 10;
		}else if(hi>='a' && hi<='f'){
			hi -= 'a';
			hi += 10;
		}else{
			hi = 0;
		}
		low = 0;
		if(i < len){
			low = szIn[i++];
			if( low>='0' && low<='9'){
				low -= '0';
			}else if(low>='A' && low<='F'){
				low -= 'A';
				low += 10;
			}else if(low>='a' && low<='f'){
				low -= 'a';
				low += 10;
			}
		}
		p[j++] = ((hi&0x0F)<<4) | (low&0x0F);

	}
	return j;
}


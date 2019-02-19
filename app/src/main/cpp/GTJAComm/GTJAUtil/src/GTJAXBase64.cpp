#include "GTJAXBase64.h"

int Base64Encode(unsigned char* input, int inLen, char** output, int* outLen, bool with_new_line) {
    int ret = 0;
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;
    char * buff = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (b64) {
        if (!with_new_line) {
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        }
        bmem = BIO_new(BIO_s_mem());
        if (bmem) {
            bmem = BIO_push(b64, bmem);
            if (bmem) {
                if (BIO_write(bmem, input, inLen) == inLen) {
                    BIO_flush(bmem);
                    BIO_get_mem_ptr(bmem, &bptr);
                    if (bptr) {
                        *output = (char *) malloc(bptr->length + 1);
                        if (*output) {
                            memset(*output, 0x00, bptr->length + 1);
                            memcpy(*output, bptr->data, bptr->length);
                            *outLen = bptr->length;
                            ret = bptr->length;
                        }
                    }
                }
            }
        }
    }
    BIO_free_all(b64);
    return ret;
}

int Base64Decode(const char* input, int inLen, unsigned char** out, int* outLen, bool with_new_line) {
    int ret = 0;
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *) malloc(inLen + 1);
    if (buffer) {
        memset(buffer, 0x00, inLen + 1);
        memcpy(buffer, input, inLen);

        *out = (unsigned char *) malloc(inLen);
        if (*out) {
            memset(*out, 0x00, inLen);

            b64 = BIO_new(BIO_f_base64());
            if (b64) {
                if (!with_new_line) {
                    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                }
                bmem = BIO_new_mem_buf(buffer, inLen);
                if (bmem) {
                    bmem = BIO_push(b64, bmem);
                    if (bmem) {
                        ret = BIO_read(bmem, *out, inLen);
                        *outLen = ret;
                    }
                }
            }
        }
        free(buffer);
        buffer = NULL;
    }
    BIO_free_all(b64);
    return ret;
}

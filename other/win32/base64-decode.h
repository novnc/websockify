#ifndef __BASE64_DECODE_H
#define __BASE64_DECODE_H

int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size);

int
lws_b64_decode_string(const char *in, char *out, int out_size);

#endif // __BASE64_DECODE_H

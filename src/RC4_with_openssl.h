/* This file was automatically generated.  Do not edit! */
int example(void);
int example(void);
int Decrypt(unsigned char **plain,const char *cipher,int clen,const unsigned char *rc4Key);
int Decrypt(unsigned char **plain,const char *cipher,int clen,const unsigned char *rc4Key);
int Encrypt(char **cipher,const char *plain,int plen,const unsigned char *rc4Key);
int Encrypt(char **cipher,const char *plain,int plen,const unsigned char *rc4Key);
bool GenerateKeys(const unsigned char *password,int plen,unsigned char *rc4Salt,unsigned char *rc4Key);
bool GenerateKeys(const unsigned char *password,int plen,unsigned char *rc4Salt,unsigned char *rc4Key);
unsigned int countDecodedLength(const char *encoded);
unsigned int countDecodedLength(const char *encoded);
int Base64Decode(char **dest,const char *src);
int Base64Decode(char **dest,const char *src);
int Base64Encode(char **dest,const char *src,unsigned int slen);
int Base64Encode(char **dest,const char *src,unsigned int slen);

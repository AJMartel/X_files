#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#define RC4_ROUNDS		5
#define RC4_KEY_LEN		16

// This is a example how you can use OpenSSL lib with RC4 to encrypt and decrypt data
// https://en.wikipedia.org/wiki/RC4
// reference https://www.openssl.org/
int Base64Encode(char **dest, const char *src, unsigned int slen);
int Base64Decode(char **dest, const char *src);
unsigned int countDecodedLength(const char *encoded);
bool GenerateKeys(const unsigned char *password, int plen, unsigned char *rc4Salt, unsigned char *rc4Key);
int Encrypt(char **cipher, const char *plain, int plen, const unsigned char *rc4Key);
int Decrypt(unsigned char **plain, const char *cipher, int clen, const unsigned char *rc4Key);

int example(void)
{
	const unsigned char *password = "this is your KEY morpheus \0";
	unsigned char rc4Salt[PKCS5_SALT_LEN + 1] = { 0 };
	unsigned char rc4Key[RC4_KEY_LEN + 1] = { 0 };

	const char plain[] = "jus another text of coolerudos\0";
	int cipherTextLength = 0;
	char *ciphertext = { 0 };
	char *decryptedtext = { 0 };

	if (GenerateKeys(password, strlen(password) + 1, rc4Salt, rc4Key))
	{
		cipherTextLength = Encrypt(&ciphertext, plain, strlen(plain) + 1, rc4Key);

		if (cipherTextLength > 0)
		{
			printf("Encrypted text: %s\n\n", ciphertext);

			if (Decrypt(&decryptedtext, ciphertext, cipherTextLength, rc4Key) > 0)
			{
				printf("Decrypted text: %s\n\n", decryptedtext);

				if (decryptedtext)
				{
					HeapFree(GetProcessHeap(), 0, decryptedtext);
					decryptedtext = NULL;
				}
			}

			if (ciphertext)
			{
				HeapFree(GetProcessHeap(), 0, ciphertext);
				ciphertext = NULL;
			}
		}
	}

	exit(0);
}


int Base64Encode(char **dest, const char *src, unsigned int slen)
{

	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	int numBytesEncoded = 0;

	b64 = BIO_new(BIO_f_base64());

	if (!b64) 
		return 0;

	bio = BIO_new(BIO_s_mem());

	if (!bio) return 0;

	bio = BIO_push(b64, bio);

	if (!bio) 
		return 0;

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	if (BIO_write(bio, src, slen - 1) <= 0)
	{
		if (bio) BIO_free_all(bio);
		return 0;
	}

	if (1 != BIO_flush(bio)) 
	{
		if (bio) BIO_free_all(bio);
		return 0;
	}

	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);

	if (bio) BIO_free_all(bio);

	*dest = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (*bufferPtr).length + 1);
	if (*dest == NULL) 
		return false;

	(*bufferPtr).data[(*bufferPtr).length] = '\0';
	strncpy_s(*dest, (*bufferPtr).length + 1, (*bufferPtr).data, (*bufferPtr).length);

	numBytesEncoded = (*bufferPtr).length + 1;

	if (bufferPtr) 
	{
		free(bufferPtr);
		bufferPtr = NULL;
	}

	return numBytesEncoded;
}

int Base64Decode(char **dest, const char *src){

	unsigned int dlen = 0;
	BIO *bio, *b64;

	unsigned int decode_length = countDecodedLength(src);

	*dest = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decode_length + 1);
	if (*dest == NULL) 
		return false;

	bio = BIO_new_mem_buf((char*)src, -1);
	if (!bio) 
		return 0;

	b64 = BIO_new(BIO_f_base64());
	if (!b64) 
		return 0;

	bio = BIO_push(b64, bio);
	if (!bio) 
		return 0;

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	dlen = BIO_read(bio, *dest, strlen(src));

	if (dlen != decode_length)
	{
		if (dest)
		{
			HeapFree(GetProcessHeap(), 0, dest);
			dest = NULL;
		}

		if (bio) 
			BIO_free_all(bio);
		return false;
	}

	if (bio) 
		BIO_free_all(bio);

	*(*dest + decode_length) = '\0';

	return decode_length + 1;
}

unsigned int countDecodedLength(const char *encoded) 
{

	unsigned int len = strlen(encoded), padding = 0;

	if (encoded[len - 1] == '=' && encoded[len - 2] == '=')
		padding = 2;
	else if (encoded[len - 1] == '=')
		padding = 1;

	return (len * 3) / 4 - padding;
}

bool GenerateKeys(const unsigned char *password, int plen, unsigned char *rc4Salt, unsigned char *rc4Key)
{
	if (password == NULL || plen <= 0) 
		return false;

	if (RAND_bytes(rc4Salt, PKCS5_SALT_LEN) == 0) 
		return false;

	rc4Salt[PKCS5_SALT_LEN] = '\0';

	if (PKCS5_PBKDF2_HMAC_SHA1(password, RC4_KEY_LEN, rc4Salt, PKCS5_SALT_LEN, RC4_ROUNDS, RC4_KEY_LEN, rc4Key) == 0) 
		return false;

	rc4Key[RC4_KEY_LEN] = '\0';

	return true;
}

int Encrypt(char **cipher, const char *plain, int plen, const unsigned char *rc4Key)
{
	if (plain == NULL || plen <= 0 || rc4Key == NULL) 
		return 0;

	EVP_CIPHER_CTX *ctx;

	unsigned char rc4IV[EVP_MAX_IV_LENGTH + 1] = { 0 }; //remains empty
	unsigned char *cipher_tmp = { 0 };
	int len = 0, cipherTextLen = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) 
		return 0;

	if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, rc4Key, rc4IV)) 
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	cipher_tmp = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plen);

	if (cipher_tmp == NULL) 
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	if (1 != EVP_EncryptUpdate(ctx, cipher_tmp, &len, (unsigned char *)plain, plen - 1)) 
	{
		if (ctx) 
			EVP_CIPHER_CTX_free(ctx);

		if (cipher_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen = len;

	if (1 != EVP_EncryptFinal_ex(ctx, cipher_tmp + len, &len)) 
	{
		if (ctx) 
			EVP_CIPHER_CTX_free(ctx);

		if (cipher_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen += len;

	if (ctx) 
		EVP_CIPHER_CTX_free(ctx);

	if (cipherTextLen <= 0) 
	{
		if (cipher_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipher_tmp[cipherTextLen] = '\0';

	if ((cipherTextLen = Base64Encode(cipher, cipher_tmp, cipherTextLen + 1)) <= 0)
	{
		if (cipher_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	if (cipher_tmp) 
	{
		HeapFree(GetProcessHeap(), 0, cipher_tmp);
		cipher_tmp = NULL;
	}

	return cipherTextLen;
}

int Decrypt(unsigned char **plain, const char *cipher, int clen, const unsigned char *rc4Key)
{
	if (cipher == NULL || clen <= 0 || rc4Key == NULL) return 0;

	EVP_CIPHER_CTX *ctx;
	int len = 0, plainTextLen = 0, decodedLen = 0, converted_bytes = 0, retValue = 0;
	unsigned char *plain_tmp = { 0 };
	unsigned char rc4IV[EVP_MAX_IV_LENGTH + 1] = { 0 }; //remains empty

	if ((decodedLen = Base64Decode(&plain_tmp, cipher)) == 0) 
		return 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) 
	{
		if (plain_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	if (1 != EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4Key, rc4IV))
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);

		if (plain_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	*plain = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decodedLen);

	if (*plain == NULL) 
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);

		if (plain_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	if (1 != EVP_DecryptUpdate(ctx, *plain, &len, plain_tmp, decodedLen - 1))
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);

		if (plain_tmp) 
		{
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}

		if (plain) 
		{
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	if (plain_tmp) 
	{
		HeapFree(GetProcessHeap(), 0, plain_tmp);
		plain_tmp = NULL;
	}

	plainTextLen = len;

	if (1 != EVP_DecryptFinal_ex(ctx, *plain + len, &len))
	{
		if (ctx) EVP_CIPHER_CTX_free(ctx);

		if (plain) 
		{
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	plainTextLen += len;
	retValue = plainTextLen;

	*(*plain + plainTextLen) = '\0';

	if (ctx) 
		EVP_CIPHER_CTX_free(ctx);

	return retValue;
}

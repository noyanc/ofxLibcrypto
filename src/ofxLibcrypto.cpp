/*
 * ofxLibcrypto.cpp
 *
 *  Created on: Dec 9, 2014
 *      Author: noyan
 */

#include "ofxLibcrypto.h"
#include <string>


ofxLibcrypto::ofxLibcrypto() {
	unsigned char empty[] = { 0 };
	k = empty;
	v = empty;
}


ofxLibcrypto::~ofxLibcrypto() {

}


void ofxLibcrypto::initialize(unsigned char *ik, unsigned char *iv) {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	k = ik;
	v = iv;
}


void ofxLibcrypto::clean() {
	/* Clean up */
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
}

std::string ofxLibcrypto::encrypt(std::string plaintext) {
	unsigned char empty[] = { 0 };
	unsigned char *ciphertex = empty;
	int lenciphertext = encrypt((unsigned char*)plaintext.c_str(), (int)plaintext.length(), k, v, ciphertex);
	std::string str(reinterpret_cast<char*>(ciphertex));
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "encrypted";
	return str.substr(0, lenciphertext);
}


std::string ofxLibcrypto::encrypt(std::string plaintext, std::string key, std::string iv) {
	unsigned char empty[] = { 0 };
	unsigned char *ciphertex = empty;
	int lenciphertext = encrypt((unsigned char*)plaintext.c_str(), (int)plaintext.length(), (unsigned char*)key.c_str(), (unsigned char*)iv.c_str(), ciphertex);
	std::string str(reinterpret_cast<char*>(ciphertex));
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "encrypted";
	return str.substr(0, lenciphertext);
}


unsigned char* ofxLibcrypto::encrypt(unsigned char* plaintext, int lenplaintext) {
	unsigned char empty[] = { 0 };
	unsigned char* ciphertext = empty;
	int lenciphertext = encrypt(plaintext, lenplaintext, k, v, ciphertext);
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "encrypted";
	return ciphertext;
}


unsigned char* ofxLibcrypto::encrypt(unsigned char* plaintext, int lenplaintext, unsigned char* key, unsigned char* iv) {
	unsigned char empty[] = { 0 };
	unsigned char* ciphertext = empty;
	int lenciphertext = encrypt(plaintext, lenplaintext, key, iv, ciphertext);
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "encrypted";
	return ciphertext;
}


std::string ofxLibcrypto::decrypt(std::string ciphertext) {
	unsigned char empty[] = { 0 };
	unsigned char* plaintext = empty;
	int lenplaintext = decrypt((unsigned char*)ciphertext.c_str(), (int)ciphertext.length(), k, v, plaintext);
	std::string str(reinterpret_cast<char*>(plaintext));
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "decrypted";
	return str.substr(0, lenplaintext);
}


std::string ofxLibcrypto::decrypt(std::string ciphertext, std::string key, std::string iv) {
	unsigned char empty[] = { 0 };
	unsigned char* plaintext = empty;
	int lenplaintext = decrypt((unsigned char*)ciphertext.c_str(), (int)ciphertext.length(), (unsigned char*)key.c_str(), (unsigned char*)iv.c_str(), plaintext);
	std::string str(reinterpret_cast<char*>(plaintext));
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "decrypted";
	return str.substr(0, lenplaintext);
}


unsigned char* ofxLibcrypto::decrypt(unsigned char* ciphertext,  int lenciphertext) {
	unsigned char empty[] = { 0 };
	unsigned char* plaintext = empty;
	int lenplaintext = decrypt(ciphertext, lenciphertext, k, v, plaintext);
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "decrypted";
	return plaintext;
}


unsigned char* ofxLibcrypto::decrypt(unsigned char* ciphertext,  int lenciphertext, unsigned char* key, unsigned char* iv) {
	unsigned char empty[] = { 0 };
	unsigned char* plaintext = empty;
	int lenplaintext = decrypt(ciphertext, lenciphertext, key, iv, plaintext);
	clean();
	ofLogVerbose("ofxLibcrypto.cpp") << "decrypted";
	return plaintext;
}


int ofxLibcrypto::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int ofxLibcrypto::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


void ofxLibcrypto::handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

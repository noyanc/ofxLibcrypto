/*
 * ofxLibcrypto.h
 *
 *  Created on: Dec 9, 2014
 *      Author: R.Noyan Culum
 *      Company: Nitra Oyun Yazilim Ltd. Sti., Istanbul / Turkey
 *      Email: info@nitragames.com
 *      Web: http://www.nitragames.com
 *
 *      This software is a MIT Licenced cross-platform openFrameworks addon.
 *      You can visit http://openframeworks.cc for more information
 *      about how to use openFrameworks and its addons.
 *
 *      This software encrypts and decrypts given text using AES-256
 *      algorithm. AES-256 support comes with OpenSSL's libcrypto
 *      library integrated into OF core.
 *
 *      Usage:
 *      ofxLibcrypto aes;
 *      aes.initialize(string key, string iv); //these are your secret key and vector
 *      string encrypted_text = aes.encrypt(string plain_text);
 *      string plain_text = aes.decrypt(string encrypted_text);
 *
 */


#ifndef OFXLIBCRYPTO_H_
#define OFXLIBCRYPTO_H_

#include "ofMain.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


class ofxLibcrypto {
public:
	ofxLibcrypto();
	~ofxLibcrypto();

	void initialize(unsigned char* ik, unsigned char* iv);

	std::string encrypt(std::string plaintext);
	std::string encrypt(std::string plaintext, std::string key, std::string iv);
	unsigned char* encrypt(unsigned char* plaintext, int lenplaintext);
	unsigned char* encrypt(unsigned char* plaintext,  int lenplaintext, unsigned char* key, unsigned char* iv);
	int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

	std::string decrypt(std::string ciphertext);
	std::string decrypt(std::string ciphertext, std::string key, std::string iv);
	unsigned char* decrypt(unsigned char* ciphertext,  int lenciphertext);
	unsigned char* decrypt(unsigned char* ciphertext,  int lenplaintext, unsigned char* key, unsigned char* iv);
	int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

private:
	unsigned char *k, *v;
	void clean();
	void handleErrors(void);
};



#endif /* OFXLIBCRYPTO_H_ */

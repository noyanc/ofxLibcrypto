# ofxLibcrypto
Small openFrameworks addon to encrypt and decrypt strings using the AES-256 algorithm which comes with OpenSSL's libcrypto library integrated into OF core.

Tested on Android with openFrameworks 0.8.0


USAGE:

    ofxLibcrypto aes;
    std::string strkey = "01234567890123456789012345678901"; //put here your scret key
    std::string striv = "01234567890123456"; // put here your vector
    unsigned char *key = (unsigned char*)strkey.c_str();
    unsigned char *iv = (unsigned char*)striv.c_str();
    aes.initialize(key, iv);
    std::string encrypted_text = aes.encrypt("This is a plain text!");
    std::string plain_text = aes.decrypt(encrypted_text);

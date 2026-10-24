#include <openssl/evp.h>
#include "../../aethon/aethon.h"

int aes_decrypt(unsigned char* key,unsigned char* iv,unsigned char* cipher,unsigned char* tag, char* buffer)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        AETHON_SAFE_CHECK(Trait::always_false<bool>,"Failed to create EVP context\n");
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        AETHON_SAFE_CHECK(Trait::always_false<bool>,"Failed to initialize AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,(const unsigned char*)key,(const unsigned char*)iv) != 1) {
        AETHON_SAFE_CHECK(Trait::always_false<bool>,"Failed to set key/IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx,(unsigned char*)buffer,&plaintext_len,(unsigned char*)cipher,16) != 1) {
        AETHON_SAFE_CHECK(Trait::always_false<bool>,"DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,(unsigned char*)tag) != 1) {
        AETHON_SAFE_CHECK(Trait::always_false<bool>,"Failed to set authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int final_len = 0;
    int result = EVP_DecryptFinal_ex(ctx,(unsigned char*)buffer + plaintext_len,&final_len);
    if (result == 1) {
        plaintext_len += final_len;
        return 1;
    } else {
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);
}

int main()
{
    unsigned char key[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    unsigned char iv[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    unsigned char cipher[16] = {
        0x03, 0x88, 0xda, 0xce,
        0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9,
        0x71, 0xb2, 0xfe, 0x78
    };

    unsigned char tag[16] = {
        0xab, 0x6e, 0x47, 0xd4,
        0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2,
        0x12, 0x57, 0xbd, 0xdf
    };
    char buffer[100];    
    int resp=aes_decrypt(key, iv, cipher, tag, buffer);
    if (resp==0){
        std::cout<<"Auth failed\n";
    }
    return 0;
}
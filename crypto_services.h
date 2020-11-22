#pragma once
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include "network_services.h"









/// <summary>
/// Intialize crypto engine.
/// </summary>
extern void CryptoInit();

/// <summary>
/// Encrypts the specified plaintext.
/// </summary>
/// <param name="plaintext">The plaintext.</param>
/// <param name="plaintext_len">Length of the plaintext.</param>
/// <param name="key">The key.</param>
/// <param name="iv">The iv.</param>
/// <param name="ciphertext">The ciphertext.</param>
/// <returns>nubmer of encrypted byte</returns>
extern int Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);

/// <summary>
/// Decrypts the specified ciphertext.
/// </summary>
/// <param name="ciphertext">The ciphertext.</param>
/// <param name="ciphertext_len">Length of the ciphertext.</param>
/// <param name="key">The key.</param>
/// <param name="iv">The iv.</param>
/// <param name="plaintext">The plaintext.</param>
/// <returns>nubmer of decrypted byte</returns>
extern int Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);


/// <summary>
/// Creates the HMAC of specified message and key.
/// </summary>
/// <param name="key">The key.</param>
/// <param name="keylen">Length of key.</param>
/// <param name="data">The data.</param>
/// <param name="datalen">Length of data.</param>
/// <param name="result">Pointer to output buffer.</param>
extern void CreateHMAC_SHA256(const void* key, int keylen, const unsigned char* data, int datalen, unsigned char* result);

/// <summary>
/// Verify message authenticity and integrity with specified HMAC.
/// </summary>
/// <param name="message">The message.</param>
/// <param name="message_length">Length of the message.</param>
/// <param name="key">The key.</param>
/// <param name="key_size">Size of the key.</param>
/// <param name="target_HMAC">The target HMAC.</param>
/// <returns>return 1 if valid, 0 otherwise</returns>
extern int CompareHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, uint8_t* target_HMAC);

/// <summary>
/// Prepares the sending buffer according to specification: 2 bytes of payload length + 1 byte of payload type + payload
/// </summary>
/// <param name="key">The key.</param>
/// <param name="keylen">The keylen.</param>
/// <param name="iv">The iv.</param>
/// <param name="data">The data.</param>
/// <param name="datalen">The datalen.</param>
/// <param name="output_size">Size of the output message.</param>
/// <param name="is_hmac">set if want to append hmac [in].</param>
/// <param name="is_encrypt">set if want to encrypt message.</param>
/// <param name="command_id">command id of this payload.</param>
/// <param name="result">The result.</param>
extern void PrepareSendingBuffer(const void* key, int keylen, const void* iv, uint8_t* data, uint16_t datalen, uint16_t output_size, bool is_hmac, bool is_encrypt, uint16_t command_id, uint8_t* result);

/// <summary>
/// Updates the encrypt key.
/// </summary>
/// <param name="secret_key">The secret key.</param>
/// <param name="hint_number">The hint number.</param>
/// <param name="encrypt_key">The encrypt key.</param>
extern void UpdateEncryptKey(uint8_t* secret_key, uint8_t* hint_number, uint8_t* encrypt_key);


/// <summary>
/// Resets the key update.
/// </summary>
/// <param name="secret_key">The secret key.</param>
/// <param name="reset_key_hint">The reset key hint.</param>
/// <param name="backup_key">The backup key.</param>
/// <param name="encrypt_key">The encrypt key.</param>
extern void ResetKeyUpdate(uint8_t* secret_key, uint8_t* reset_key_hint, uint8_t* backup_key, uint8_t* encrypt_key);


/// <summary>
/// Deinitialize crypto engine
/// </summary>
extern void CryptoDeInit();

/// <summary>
/// Calculate digest SHA256 of incoming data. Wrapper of OpenSSL's SHA256 API
/// </summary>
/// <param name="data">The data. [in]</param>
/// <param name="data_length">Length of the data. [in]</param>
/// <param name="digest">The output digest. [out]</param>
extern void SHA256Calculate(uint8_t* data, uint16_t data_length, uint8_t* digest);

/// <summary>
/// Calculate digest SHA512 of incoming data. Wrapper of OpenSSL's SHA512 API
/// </summary>
/// <param name="data">The data. [in]</param>
/// <param name="data_length">Length of the data. [in]</param>
/// <param name="digest">The output digest. [out]</param>
extern void SHA512Calculate(uint8_t* data, uint16_t data_length, uint8_t* digest);
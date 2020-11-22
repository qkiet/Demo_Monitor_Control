#include "crypto_services.h"


/*********************
 * Declare private API * 
 **********************/
static void PaddingNull(uint8_t* buffer_in_out, uint16_t input_length, uint16_t output_length);
static void handleErrors();

/*********************
 * Define public API *
 *********************/
/// <summary>
/// Intialize crypto engine.
/// </summary>
void CryptoInit()
{
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);
}





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
void PrepareSendingBuffer(const void* key, int keylen, const void* iv, uint8_t* data, uint16_t datalen, uint16_t output_size, bool is_hmac, bool is_encrypt, uint16_t command_id, uint8_t* result)
{
    uint8_t temp_buff[1060];
    memcpy((void*)result, data, datalen);
    //First, append payload length
    memcpy((void*)temp_buff, result, datalen);
    memcpy(result, &datalen, sizeof(datalen));
    memcpy(result + MESSAGE_LENGTH_HEADER_SIZE, &command_id, sizeof(command_id));
    memcpy(result + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, temp_buff, datalen);

    //Second, padding with ISO 7816 padding scheme
    PaddingNull(result, datalen + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, output_size);

    //Then it encrypt
    if (is_encrypt)
    {
        Encrypt(result, output_size, (uint8_t*)key, (uint8_t*)iv, result);
    }

    //Add HMAC if specified
    if (is_hmac)
    {
        uint8_t hmac_buff[32];
        memcpy((void*)temp_buff, result, output_size);
        CreateHMAC_SHA256(key, keylen, result, output_size, hmac_buff);
        memcpy(result, hmac_buff, 32);
        memcpy(result + 32, temp_buff, output_size);
    }

}


/// <summary>
/// Creates the HMAC of specified message and key.
/// </summary>
/// <param name="key">The key.</param>
/// <param name="keylen">Length of key.</param>
/// <param name="data">The data.</param>
/// <param name="datalen">Length of data.</param>
/// <param name="result">Pointer to output buffer.</param>
void CreateHMAC_SHA256(const void* key, int keylen, const unsigned char* data, int datalen, unsigned char* result)
{
    unsigned int dummy_result_length;
    HMAC(EVP_sha256(), key, keylen, data, datalen, result, &dummy_result_length);
}


/// <summary>
/// Verify message authenticity and integrity with specified HMAC.
/// </summary>
/// <param name="message">The message.</param>
/// <param name="message_length">Length of the message.</param>
/// <param name="key">The key.</param>
/// <param name="key_size">Size of the key.</param>
/// <param name="target_HMAC">The target HMAC.</param>
/// <returns>return 1 if valid, 0 otherwise</returns>
int CompareHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, uint8_t* target_HMAC)
{
    uint8_t calculated_HMAC[32];
    CreateHMAC_SHA256(key, key_size, message, message_length, calculated_HMAC);
    for (int i = 0; i < 32; i++)
    {
        if (calculated_HMAC[i] != target_HMAC[i])
        {
            return 0;
        }
    }
    return 1;
}



/// <summary>
/// Updates the encrypt key.
/// </summary>
/// <param name="secret_key">The secret key.</param>
/// <param name="hint_number">The hint number.</param>
/// <param name="encrypt_key">The encrypt key.</param>
void UpdateEncryptKey(uint8_t* secret_key, uint8_t* hint_number, uint8_t* encrypt_key)
{
    uint8_t temp_buff[SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE + SESSION_NONCE_SIZE];
    uint8_t sha256_digest[32];
    memcpy(temp_buff, secret_key, SECRET_KEY_SIZE);
    memcpy(temp_buff + SECRET_KEY_SIZE, encrypt_key, SESSION_ENCRYPT_KEY_SIZE);
    memcpy(temp_buff + SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE, hint_number, SESSION_NONCE_SIZE);
    SHA256Calculate(temp_buff, SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE + SESSION_NONCE_SIZE, sha256_digest);
    memcpy(encrypt_key, sha256_digest, SECRET_KEY_SIZE);
}


/// <summary>
/// Resets the key update.
/// </summary>
/// <param name="secret_key">The secret key.</param>
/// <param name="reset_key_hint">The reset key hint.</param>
/// <param name="backup_key">The backup key.</param>
/// <param name="encrypt_key">The encrypt key.</param>
void ResetKeyUpdate(uint8_t* secret_key, uint8_t* reset_key_hint, uint8_t* backup_key, uint8_t* encrypt_key)
{
    uint8_t temp_buff[SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE + SESSION_NONCE_SIZE];
    uint8_t sha512_digest[64];
    memcpy(temp_buff, secret_key, SECRET_KEY_SIZE);
    memcpy(temp_buff + SECRET_KEY_SIZE, backup_key, SESSION_ENCRYPT_KEY_SIZE);
    memcpy(temp_buff + SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE, reset_key_hint, SESSION_NONCE_SIZE);
    SHA512Calculate(temp_buff, SECRET_KEY_SIZE + SESSION_ENCRYPT_KEY_SIZE + SESSION_NONCE_SIZE, sha512_digest);
    memcpy(encrypt_key, sha512_digest, SESSION_ENCRYPT_KEY_SIZE);
    memcpy(backup_key, sha512_digest + SESSION_ENCRYPT_KEY_SIZE, SESSION_ENCRYPT_KEY_SIZE);
}

/// <summary>
/// Encrypts the specified plaintext.
/// </summary>
/// <param name="plaintext">The plaintext.</param>
/// <param name="plaintext_len">Length of the plaintext.</param>
/// <param name="key">The key.</param>
/// <param name="iv">The iv.</param>
/// <param name="ciphertext">The ciphertext.</param>
/// <returns>nubmer of encrypted byte</returns>
int Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/// <summary>
/// Decrypts the specified ciphertext.
/// </summary>
/// <param name="ciphertext">The ciphertext.</param>
/// <param name="ciphertext_len">Length of the ciphertext.</param>
/// <param name="key">The key.</param>
/// <param name="iv">The iv.</param>
/// <param name="plaintext">The plaintext.</param>
/// <returns>nubmer of decrypted byte</returns>
int Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();



    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/// <summary>
/// Deinitialize crypto engine
/// </summary>
void CryptoDeInit()
{

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}

/// <summary>
/// Paddings input message with ISO 7816 padding scheeme to specified length.
/// </summary>
/// <param name="buffer_in_out">Pointer to buffer of input message and output message [in,out].</param>
/// <param name="input_length">Length of input message.</param>
static void PaddingNull(uint8_t* buffer_in_out, uint16_t input_length, uint16_t output_length)
{
    for (int i = input_length; i < output_length; i++)
    {
        buffer_in_out[i] = 0x00;
    } 

}

/// <summary>
/// Calculate digest SHA256 of incoming data. Wrapper of OpenSSL's SHA256 API
/// </summary>
/// <param name="data">The data. [in]</param>
/// <param name="data_length">Length of the data. [in]</param>
/// <param name="digest">The output digest. [out]</param>
void SHA256Calculate(uint8_t* data, uint16_t data_length, uint8_t* digest)
{
    SHA256_CTX digest_ctx;
    SHA256_Init(&digest_ctx);
    SHA256_Update(&digest_ctx, data, data_length);
    SHA256_Final(digest, &digest_ctx);

}

/// <summary>
/// Calculate digest SHA512 of incoming data. Wrapper of OpenSSL's SHA512 API
/// </summary>
/// <param name="data">The data. [in]</param>
/// <param name="data_length">Length of the data. [in]</param>
/// <param name="digest">The output digest. [out]</param>
void SHA512Calculate(uint8_t* data, uint16_t data_length, uint8_t* digest)
{
    SHA512_CTX digest_ctx;
    SHA512_Init(&digest_ctx);
    SHA512_Update(&digest_ctx, data, data_length);
    SHA512_Final(digest, &digest_ctx);
}

static void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
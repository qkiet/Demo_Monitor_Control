#include "network_services.h"




extern uint16_t real_message_size;
extern LARGE_INTEGER dummy_tick, start_session_tick, end_session_tick;
char sending_to_pdu_buffer[1024];

uint8_t PDU_password[20];

uint8_t secret_key[SECRET_KEY_SIZE];

typedef struct {
    char command_text[20];
    char help_text[65];
} pdu_command;
uint8_t total_number_of_commands = 9;
pdu_command commands_list[9] =
{
    {
        "TURN ON 1",
        "This command will turn on LED 1"
    },
    {
        "TURN ON 2",
        "This command will turn on LED 2"

    },
    {
        "TURN OFF 1",
        "This command will turn off LED 1"
    },
    {
        "TURN OFF 2",
        "This command will turn off LED 2"
    },
    {
        "TOGGLE 1",
        "This command will toggle LED 1"
    },
    {
        "TOGGLE 2",
        "This command will toggle LED 2"
    },
    {
        "STATUS",
        "This command will request status of both LED"
    },
    {
        "Repeat Last Command",
        "This command will repeat last command. Simulate Replay Attack"
    },
    {
        "STOP",
        "This command will stop session"
    },
};



void InitNetworkService(uint8_t* input_password)
{
    memcpy(PDU_password, input_password, strlen((char*)input_password));
    uint8_t salted_string[100];
    uint8_t first_random_salt[32] =
    {
            0xcc, 0x5b, 0xdf, 0x8b, 0x8a, 0x14, 0x9b, 0x9d,
            0xc7, 0x52, 0x23, 0x2f, 0x2b, 0x09, 0x03, 0x39,
            0x66, 0x7e, 0xfa, 0x6f, 0x12, 0x8e, 0x13, 0xa5,
            0x51, 0x78, 0x00, 0x61, 0x46, 0x60, 0x59, 0xe6
    };
    uint8_t second_random_salt[32] =
    {
            0xaa, 0xc4, 0x59, 0xa4, 0x63, 0x57, 0xa1, 0x70,
            0x79, 0xad, 0x1c, 0x46, 0xf7, 0xc1, 0x63, 0x86,
            0x68, 0x83, 0xcf, 0xe1, 0x36, 0xaa, 0x7d, 0x27,
            0x7f, 0xef, 0x6a, 0x0f, 0xe3, 0xcd, 0x03, 0x25
    };
    memcpy(salted_string, first_random_salt, 32);
    memcpy(salted_string + 32, PDU_password, strlen((char*)PDU_password));
    memcpy(salted_string + 32 + strlen((char*)PDU_password), second_random_salt, 32);
    SHA256Calculate(salted_string, 64 + strlen((char*)PDU_password), secret_key);
}

/// <summary>
/// Gets the real payload from secured payload by read first 2 bytes to get real size.
/// </summary>
/// <param name="input_payload">The input payload.</param>
/// <param name="actual_payload">The output actual payload.</param>
void GetRealPayload(uint8_t* input_payload, uint8_t* actual_payload)
{
    uint16_t actual_payload_size = (uint16_t) * (input_payload);
    memcpy(actual_payload, input_payload + 2, actual_payload_size);
}

bool CompareArray(uint8_t* array1, uint8_t* array2, uint16_t size)
{
    for (int i = 0; i < size; i++)
    {
        if (array1[i] != array2[i])
        {
            return false;
        }
    }
    return true;
}

/// <summary>
/// Sends the command and wait for response.
/// </summary>
/// <param name="PDU_socket">The pdu socket.</param>
/// <param name="command">The command.</param>
/// <param name="command_length">Length of the command.</param>
/// <param name="encrypt_key">The encrypt key.</param>
/// <param name="key_size">Size of the key.</param>
/// <param name="encrypt_iv">The encrypt iv.</param>
/// <param name="backup_key">The backup key.</param>
/// <param name="is_replay_attack">if set to <c>true</c> [is replay attack].</param>
/// <param name="is_corrupted">will message will get corrupted?.</param>
/// <param name="message_size">Size of the message.</param>
/// <param name="current_command_id">The current command identifier.</param>
/// <param name="sent_payload">The sent payload.</param>
/// <param name="sent_payload_length">Length of the sent payload.</param>
/// <returns>true if command is executed and response successfuly, false otherwise</returns>
bool SendCommand(SOCKET* PDU_socket,
    uint8_t* command,
    uint16_t command_length,
    uint8_t* encrypt_key,
    uint8_t key_size,
    uint8_t* encrypt_iv,
    uint8_t* backup_key,
    bool is_replay_attack,
    bool is_corrupted,
    uint16_t message_size,
    uint16_t current_command_id,
    uint8_t* sent_payload,
    uint16_t sent_payload_length)
{
    uint8_t temp_payload[1060],
        payload_to_PDU[1060],
        receive_buff[1060],
        temp_buff[1060],
        printed_string[1060],
        next_encrypt_hint[SESSION_NONCE_SIZE],
        reset_key_hint[SESSION_NONCE_SIZE];


    bool is_session_end = false, is_wait_for_reset_key_response = false;

    if (!is_replay_attack)
    {
        PrepareSendingBuffer(encrypt_key, key_size, encrypt_iv, command, command_length, message_size, true, true, current_command_id, payload_to_PDU);
    }
    else
    {
        memcpy(payload_to_PDU, sent_payload, sent_payload_length);
    }

    is_session_end = false;

    // Corrupt message if specified
    if (is_corrupted)
    {
        payload_to_PDU[0] = !payload_to_PDU[0];
    }


    if (send(*PDU_socket, (char*)payload_to_PDU, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
    {

        //Now it wait for response and deal with many cases
        while (1)
        {
            if (recv(*PDU_socket, (char*)receive_buff, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
            {
                //Valid with encrypt key
                if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE, message_size, encrypt_key, SESSION_ENCRYPT_KEY_SIZE, receive_buff))
                {
                    printf("Valid with Encrypt Key!!\n");
                    //Print response

                    Encrypt(receive_buff + HMAC_SIZE, message_size, encrypt_key, encrypt_iv, temp_buff);

                    //A NAK response. Resend command!
                    if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + SESSION_NONCE_SIZE), "NAK", 3) == 0)
                    {
                        printf("A NAK response\n\n\n");
                        //Update encrypt key
                        memcpy(next_encrypt_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
                        UpdateEncryptKey(secret_key, next_encrypt_hint, encrypt_key);

                        //Resend command
                        if (!is_replay_attack)
                        {
                            PrepareSendingBuffer(
                                encrypt_key,
                                SESSION_ENCRYPT_KEY_SIZE,
                                encrypt_iv,
                                command,
                                command_length,
                                message_size,
                                true,
                                true,
                                current_command_id,
                                payload_to_PDU);
                        }
                        else
                        {
                            memcpy(payload_to_PDU, sent_payload, sent_payload_length);
                        }


                    }
                    //Normal command response
                    else
                    {
                        memcpy(printed_string, temp_buff, message_size);
                        printed_string[(uint16_t)(*printed_string) + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE] = '\0';

                        printf("Receive Response: %s\n\n\n", printed_string + SESSION_NONCE_SIZE + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE);
                        //Update encrypt key
                        memcpy(next_encrypt_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
                        UpdateEncryptKey(secret_key, next_encrypt_hint, encrypt_key);

                        //Jump back to wait for user input
                        memcpy(sent_payload, payload_to_PDU, sent_payload_length);
                        return true;

                    }

                }

                //Valid with backup key. This happen only when PDU response to Reset Key Routine command
                else if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE, message_size, backup_key, SESSION_ENCRYPT_KEY_SIZE, receive_buff))
                {
                    printf("Valid with Backup Key!!\n");
                    is_wait_for_reset_key_response = false;
                    Encrypt(receive_buff + HMAC_SIZE, message_size, backup_key, encrypt_iv, temp_buff);

                    //Check for response
                    if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + SESSION_NONCE_SIZE), "OK", 2) == 0)
                    {
                        printf("Reset Key Response!!\n\n\n");
                        //Update encrypt key
                        memcpy(reset_key_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
                        ResetKeyUpdate(secret_key, reset_key_hint, backup_key, encrypt_key);
                        //Resend command
                        PrepareSendingBuffer(
                            encrypt_key,
                            SESSION_ENCRYPT_KEY_SIZE,
                            encrypt_iv,
                            command,
                            command_length,
                            message_size,
                            true,
                            true,
                            current_command_id,
                            payload_to_PDU);
                    }

                    //Bad response for reset key command. Close connection
                    else
                    {
                        return false;
                    }
                }

                //Invalid response
                else
                {
                    printf("Invalid Response!!\n\n\n");

                    //If it already wait for reset key response but still invalid, then close connection
                    if (is_wait_for_reset_key_response)
                    {
                        return false;
                    }
                    snprintf((char*)temp_payload, 9, "ResetKey");
                    is_wait_for_reset_key_response = true;
                    PrepareSendingBuffer(backup_key,
                        SESSION_ENCRYPT_KEY_SIZE,
                        encrypt_iv,
                        temp_payload,
                        strlen((char*)temp_payload),
                        message_size,
                        true,
                        true,
                        current_command_id,
                        payload_to_PDU);
                }
            }

            //Timeout sending or connection problem. Close connection
            else
            {
                return false;

            }

            //If it made here, GUI need to resend to PDU or send reset key command. If there is sending problem, close connection
            if (send(*PDU_socket, (char*)payload_to_PDU, message_size + HMAC_SIZE, 0) != message_size + HMAC_SIZE)
            {
                return false;
            }
        }
    }
    else
    {
        return false;
    }

}

/// <summary>
/// Run Secured Session if User specified.
/// </summary>
/// <param name="running_socket">SOCKET structure that connect to PDU.</param>
/// <param name="transaction_length">Length of the transaction. Only useful if this is Measure Session</param>
/// <param name="message_size">Size of the message.</param>
void RunSecuredSession(SOCKET* running_socket, int session_length, uint16_t message_size)
{
    uint8_t payload[MAXIMUM_PACKET_LENGTH],
        payload_to_PDU[MAXIMUM_PACKET_LENGTH],
        old_send_buff[MAXIMUM_PACKET_LENGTH],
        temp_buff[MAXIMUM_PACKET_LENGTH],
        receive_buff[MAXIMUM_PACKET_LENGTH],
        encrypt_key[SESSION_ENCRYPT_KEY_SIZE],
        old_encrypt_key[SESSION_ENCRYPT_KEY_SIZE],
        encrypt_iv[16],
        next_encrypt_hint[SESSION_NONCE_SIZE],
        reset_key_hint[SESSION_NONCE_SIZE],
        printed_string[MAXIMUM_PACKET_LENGTH],
        backup_key[SESSION_COMMAND_KEY_MAX_SIZE],
        Sha256_digest[32],
        Sha512_digest[64];
    uint16_t current_command_id = 0;
    int answer, answer_message_corrupted;
    int total_measured_sent_cmd = 0;
    bool replay_attack = false,
        is_session_end = false,
        is_wait_for_reset_key_response = false;
    uint8_t session_kind;
    int send_timeout = SEND_TIMEOUT;
    int receive_timeout = RECEIVE_TIMEOUT;
    bool is_message_corrupted = false;
    setsockopt(*running_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&receive_timeout, sizeof(receive_timeout));
    setsockopt(*running_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));

    //Begin Authentication Phase
    snprintf((char*)payload, 8, "REQUEST");
    memcpy(payload + strlen((char*)payload), &message_size, sizeof(message_size));

    PrepareSendingBuffer(
        secret_key, 
        32, 
        NULL, 
        payload,
        9, 
        64, 
        true,
        false, 
        current_command_id,
        payload_to_PDU);
    if (send(*running_socket, (char*)payload_to_PDU, 64 + HMAC_SIZE, 0) == 64 + HMAC_SIZE)
    {
        if (recv(*running_socket, (char*)receive_buff, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
        {
            //Incoming Ok+128-bit number is valid
            if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE, message_size, secret_key, 32, receive_buff))
            {
                //Calculate encrypt key, encrypt IV and backup key from authentication number by SHA512(secret key || authentication nubmer)
                memcpy(temp_buff, secret_key, SECRET_KEY_SIZE);
                memcpy(temp_buff + SECRET_KEY_SIZE, receive_buff + HMAC_SIZE + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + strlen("OK"), SESSION_NONCE_SIZE);
                SHA512Calculate(temp_buff, SECRET_KEY_SIZE + SESSION_NONCE_SIZE, Sha512_digest);
                memcpy(encrypt_key, Sha512_digest, SESSION_ENCRYPT_KEY_SIZE);
                memcpy(backup_key, Sha512_digest + SESSION_ENCRYPT_KEY_SIZE, SESSION_ENCRYPT_KEY_SIZE);
                memcpy(encrypt_iv, secret_key, SESSION_IV_SIZE / 2);
                memcpy(encrypt_iv + SESSION_IV_SIZE / 2, encrypt_key, SESSION_IV_SIZE / 2);


                //Send back ACK
                snprintf((char*)payload, 4, "ACK");
                PrepareSendingBuffer(
                    encrypt_key, 
                    SESSION_ENCRYPT_KEY_SIZE, 
                    encrypt_iv, 
                    payload, 
                    3, 
                    message_size, 
                    true, 
                    true, 
                    current_command_id,
                    payload_to_PDU);
                if (send(*running_socket, (char*)payload_to_PDU, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
                {
                    //
                    printf("Authenticate Successfully\n");
                    if (session_length > 0)
                    {
                        session_kind = SESSION_KIND_MEASURE;
                    }
                    else
                    {
                        session_kind = SESSION_KIND_DEMO;
                    }

                }
                else
                {
                    printf("Authentication Fail!\n");
                    return;
                }
            }
            else
            {
                printf("Authentication Fail!\n");
                return;
            }
        }
        else
        {
            printf("Authentication Fail!\n");
            return;
        }
    }
    else
    {
        printf("Authentication Fail!\n");
        return;
    }

    if (session_kind == SESSION_KIND_MEASURE)
    {
        for (int i = 0; i < session_length; i++)
        {
            memcpy(payload, commands_list[6].command_text, strlen(commands_list[6].command_text));
            PrepareSendingBuffer(encrypt_key, SESSION_ENCRYPT_KEY_SIZE, encrypt_iv, payload, strlen(commands_list[6].command_text), message_size, true, true, current_command_id, payload_to_PDU);
            if (!SendCommand(
                running_socket,
                payload,
                strlen(commands_list[6].command_text),
                encrypt_key,
                SESSION_ENCRYPT_KEY_SIZE,
                encrypt_iv,
                backup_key,
                replay_attack,
                is_message_corrupted,
                message_size,
                current_command_id,
                old_send_buff,
                message_size + HMAC_SIZE
            ))
            {
                break;
            }
            else
            {
                current_command_id++;
            }
        }
        printf("Done session\n");
        return;
    }
    else if (session_kind == SESSION_KIND_DEMO)
    {
        //Wait for command from upper layer: user
        while (1)
        {
            //Print all options and display user prompt
            while (1)
            {
                printf("Please enter one of following commands\n\n");
                for (int i = 0; i < total_number_of_commands; i++)
                {
                    printf("%d. %s: %s\n", i + 1, commands_list[i].command_text, commands_list[i].help_text);
                }
                printf("\n\n");
                printf("Enter answer (1-%d): ", total_number_of_commands);
                std::cin >> answer;

                //Stop, session done
                if (answer == total_number_of_commands)
                {
                    is_session_end = true;
                    break;
                }

                printf("Is message corrupted? Answer (0,1): ");
                std::cin >> answer_message_corrupted;

                if (answer_message_corrupted > 0)
                {
                    is_message_corrupted = true;
                }
                else
                {
                    is_message_corrupted = false;
                }

                //If this is REPEAT command
                if (answer == total_number_of_commands - 1)
                {
                    replay_attack = true;
                }
                else
                {
                    replay_attack = false;
                }

                if ((0 < answer) && (answer < total_number_of_commands))
                {
                    break;
                }

            }

            if (is_session_end)
            {
                break;
            }
            memcpy(payload, commands_list[answer - 1].command_text, strlen(commands_list[answer - 1].command_text));
            if (!SendCommand(
                running_socket,
                payload,
                strlen(commands_list[answer - 1].command_text),
                encrypt_key,
                SESSION_ENCRYPT_KEY_SIZE,
                encrypt_iv,
                backup_key,
                replay_attack,
                is_message_corrupted,
                message_size,
                current_command_id,
                old_send_buff,
                message_size + HMAC_SIZE
            ))
            {
                break;
            }
            else
            {
                current_command_id++;
            }
        }
        printf("Done session\n");
    }
}



void RunUnsecuredSession(SOCKET* running_socket, int transaction_length, int message_size, bool is_encrypted)
{
    uint8_t payload[MAXIMUM_PACKET_LENGTH],
        payload_to_PDU[MAXIMUM_PACKET_LENGTH],
        temp_buff[MAXIMUM_PACKET_LENGTH],
        receive_buff[MAXIMUM_PACKET_LENGTH],
        default_encrypt_key[SESSION_ENCRYPT_KEY_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        default_encrypt_iv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        printed_string[MAXIMUM_PACKET_LENGTH];
    int answer, last_answer = -1;
    int send_timeout = SEND_TIMEOUT;
    int receive_timeout = RECEIVE_TIMEOUT;
 
    uint16_t current_command_id = 0, receive_command_id;
    bool replay_attack, is_session_end = false;
    setsockopt(*running_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&receive_timeout, sizeof(receive_timeout));
    setsockopt(*running_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));

    //Begin Authentication Phase
    snprintf((char*)payload, 8, "REQUEST");
    memcpy(payload + strlen((char*)payload), &message_size, sizeof(message_size));
    if (is_encrypted)
    {
        PrepareSendingBuffer(
            default_encrypt_key, 
            SESSION_ENCRYPT_KEY_SIZE, 
            default_encrypt_iv, payload, 
            9, 
            64, 
            false, 
            true, 
            current_command_id,
            payload_to_PDU
            );
    }
    else
    {
        PrepareSendingBuffer(
            NULL, 
            0, 
            NULL, 
            payload, 
            9, 
            64, 
            false, 
            false, 
            current_command_id,
            payload_to_PDU);
    }
    //If master (PDU) receive sucessfully, begin session
    if (send(*running_socket, (char*)payload_to_PDU, 64, 0) == 64)
    {
        if (recv(*running_socket, (char*)receive_buff, message_size, 0) == message_size)
        {
            if (is_encrypted)
            {

                Decrypt(receive_buff, message_size, default_encrypt_key, default_encrypt_iv, temp_buff);
            }
            else
            {
                memcpy(temp_buff, receive_buff, message_size);
            }
            if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE), "ACK", 3) == 0)
            {
                //Begin Session here
                while (1)
                {
                    //Print all options and display user prompt. Wait for upper layer command here
                    while (1)
                    {
                        printf("Please enter one of following commands\n\n");
                        for (int i = 0; i < total_number_of_commands; i++)
                        {
                            printf("%d. %s: %s\n", i + 1, commands_list[i].command_text, commands_list[i].help_text);
                        }
                        printf("\n\n");
                        printf("Enter answer (1-%d): ", total_number_of_commands);
                        std::cin >> answer;

                        //If this is REPEAT command
                        if (answer == total_number_of_commands - 1)
                        {
                            answer = last_answer;
                            replay_attack = true;
                        }
                        else
                        {
                            replay_attack = false;
                        }

                        if ((0 < answer) && (answer < total_number_of_commands))
                        {
                            last_answer = answer;
                            break;
                        }
                        if (answer == total_number_of_commands)
                        {
                            goto UNSECURED_SESSION_END;
                        }
                    }
                    //Prepare first sending buffer
                    memcpy(payload, commands_list[answer - 1].command_text, strlen(commands_list[answer - 1].command_text));
                    if (is_encrypted)
                    {
                            
                        PrepareSendingBuffer(
                            default_encrypt_key, 
                            SESSION_ENCRYPT_KEY_SIZE, 
                            default_encrypt_iv, 
                            payload, 
                            strlen(commands_list[answer - 1].command_text), 
                            message_size, 
                            false, 
                            true, 
                            current_command_id, 
                            payload_to_PDU);
                    }
                    else
                    {
                        PrepareSendingBuffer(
                            NULL, 
                            0, 
                            NULL, 
                            payload, 
                            strlen(commands_list[answer - 1].command_text), 
                            message_size, 
                            false, 
                            false, 
                            current_command_id,
                            payload_to_PDU);
                    }

                    //Begin send and wait for response
                    if (send(*running_socket, (char*)payload_to_PDU, message_size, 0) == message_size)
                    {
                        while (1)
                        {
                            if (recv(*running_socket, (char*)receive_buff, message_size, 0) == message_size)
                            {
                                //Get response for further process
                                if (is_encrypted)
                                {
                                    Encrypt(receive_buff, message_size, default_encrypt_key, default_encrypt_iv, temp_buff);
                                }
                                else
                                {
                                    memcpy(temp_buff, receive_buff, message_size);
                                }
                                receive_command_id = (uint16_t)*(temp_buff + MESSAGE_LENGTH_HEADER_SIZE);
                                
                                //Process command
                                //This is not NAK, update command id
                                if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE), "NAK", 3) != 0)
                                {
                                    printf("Response: %s\n\n", temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE);
                                    current_command_id++;
                                    break;
                                }
                                else
                                {
                                    printf("Response: NAK\n\n");
                                }
                            }
                            else
                            {
                                is_session_end = true;
                                break;
                            }

                            //If it made here, GUI need to resend to PDU or send reset key command. If there is sending problem, close connection
                            if (send(*running_socket, (char*)payload_to_PDU, message_size, 0) != message_size)
                            {
                                is_session_end = true;
                                break;
                            }
                        }
                   
                    }
                    //Sending problem, terminate connection
                    else
                    {
                        break;
                    }

                    //Problem with reading response. Close connection
                    if (is_session_end)
                    {
                        break;
                    }

                }
            }
        }
      
    }

UNSECURED_SESSION_END:
    printf("Done Session\n");
}
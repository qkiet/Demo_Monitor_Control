// Measure_Delay.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include "crypto_services.h"
#include "network_services.h"
#include <chrono>
#include <intrin.h>
#include <bitset>
#include <cstdio>
#include <inttypes.h>

#pragma comment(lib, "Ws2_32.lib")

#define PDU_IP "192.168.2.100"
#define CLIENT_PORT 50
#define WIN32_LEAN_AND_MEAN

uint16_t real_message_size;
LARGE_INTEGER dummy_tick, start_session_tick, end_session_tick, freq;


void UserInput()
{

}


int main()
{

    CryptoInit();


    uint8_t encrypted_key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 ,15 };
    uint8_t encrypted_iv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 ,15 };

    uint8_t test_data[36] =
    { 0, 1, 2, 3, 4, 0, 0, 7, 8, 9, 10, 11, 12, 13, 0, 15, 16, 17,
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 14, 15, 16, 17 };
    uint8_t test_data_2[36] =
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
    uint8_t temp[36], decrypted[36];

    Encrypt(test_data, 36, encrypted_key, encrypted_iv, temp);
    Encrypt(temp, 36, encrypted_key, encrypted_iv, decrypted);

    Encrypt(test_data_2, 36, encrypted_key, encrypted_iv, temp);
    Encrypt(temp, 36, encrypted_key, encrypted_iv, decrypted);


    //Winsock data
    WSADATA wsaData;

    //Client socket
    SOCKET client_sock = INVALID_SOCKET;

    //socket addr t bind
    sockaddr_in localaddr;

    int session_type_answer;
    int number_of_transaction = 0;
    int message_size_answer;
    uint8_t PDU_entered_pass[20];
    bool PDU_password_required = false;
    //send buff

    int iResult = 0;


    while (1)
    {
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != NO_ERROR) {
            wprintf(L"Error at WSAStartup()\n");
            return 1;
        }

        //Create socket
        client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (client_sock == INVALID_SOCKET)
        {
            std::cout << "Socket creation error";
        }

        sockaddr_in remoteaddr = { 0 };
        remoteaddr.sin_family = AF_INET;
        inet_pton(AF_INET, PDU_IP, &remoteaddr.sin_addr);
        remoteaddr.sin_port = htons(7); // whatever the server is listening on

        int session_category_answer;

        std::cout << "Select session category you want to perform:\n\n1. Normal\n2. Measure\n\nMy answer: ";
        std::cin >> session_category_answer;

        std::cout << "Select session type you want to perform:\n\n1. Normal Unsecured\n2. Normal Encrypted\n3. Secured\n\nMy answer: ";
        std::cin >> session_type_answer;

        if (session_type_answer >= 3)
        {
            std::cout << "Please enter PDU password: ";
            std::cin >> PDU_entered_pass;
            PDU_password_required = true;
        }
        if (session_category_answer > 1)
        {
            std::cout << "How many transaction: ";
            std::cin >> number_of_transaction;
        }
        std::cout << "What is message size (1 = 64 bytes, 2 = 256 bytes, 3 = 1024 bytes): ";
        std::cin >> message_size_answer;

        switch (message_size_answer)
        {
        case 1:
            real_message_size = 64;
            break;
        case 2:
            real_message_size = 256;
            break;
        case 3:
            real_message_size = 1024;
            break;

        }
        if (PDU_password_required)
        {
            InitNetworkService(PDU_entered_pass);
        }
        //Connect successfully
        while (1)
        {
            iResult = connect(client_sock, (struct sockaddr*) & remoteaddr, sizeof(remoteaddr));
            if (iResult == 0)
            {
                std::cout << "Connect successfully\n";
                break;
            }
            else
            {
                std::cout << "Connect UNsuccessfuly. Error: " << WSAGetLastError() << "\n";
            }
        }

        //Begin measure service
        switch (session_type_answer)
        {
        case 1:
            RunUnsecuredSession(&client_sock, number_of_transaction, real_message_size, false);
            break;
        case 2:
            RunEncryptedSession(&client_sock, number_of_transaction, message_size_answer);
            break;
        default:
            RunSecuredSession(&client_sock, number_of_transaction, real_message_size);
        }


        // close the socket
        iResult = closesocket(client_sock);
        if (iResult == SOCKET_ERROR) {
            wprintf(L"close failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        WSACleanup();

        int is_continue;
        std::cout << "Do you want to continue? (0, 1): ";
        std::cin >> is_continue;
        if (is_continue == 0)
        {
            break;
        }


    }




    CryptoDeInit();
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
/// <param name="message_size">Size of the message.</param>
/// <param name="current_command_id">The current command identifier.</param>
/// <param name="sent_payload">The sent payload.</param>
/// <param name="sent_payload_length">Length of the sent payload.</param>
/// <returns>true if command is executed and response successfuly, false otherwise</returns>
//bool SendCommand(SOCKET *PDU_socket,
//    uint8_t* command, 
//    uint16_t command_length, 
//    uint8_t* encrypt_key, 
//    uint8_t key_size, 
//    uint8_t* encrypt_iv, 
//    uint8_t* backup_key, 
//    bool is_replay_attack,
//    uint16_t message_size,
//    uint16_t current_command_id,
//    uint8_t* sent_payload,
//    uint16_t sent_payload_length)
//{
//    uint8_t temp_payload[1060],
//            payload_to_PDU[1060],
//            receive_buff[1060],
//            temp_buff[1060],
//            printed_string[1060],
//            next_encrypt_hint[SESSION_NONCE_SIZE],
//            reset_key_hint[SESSION_NONCE_SIZE];
//
//
//    bool is_session_end = false, is_wait_for_reset_key_response = false;
//
//    if (!is_replay_attack)
//    {
//        PrepareSendingBuffer(encrypt_key, key_size, encrypt_iv, command, command_length, message_size, true, true, current_command_id, payload_to_PDU);
//    }
//    else
//    {
//        memcpy(payload_to_PDU, sent_payload, sent_payload_length);
//    }
//
//    is_session_end = false;
//    if (send(*PDU_socket, (char*)payload_to_PDU, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
//    {
//
//        //Now it wait for response and deal with many cases
//        while (1)
//        {
//            if (recv(*PDU_socket, (char*)receive_buff, message_size + HMAC_SIZE, 0) == message_size + HMAC_SIZE)
//            {
//                //Valid with encrypt key
//                if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE, message_size, encrypt_key, SESSION_ENCRYPT_KEY_SIZE, receive_buff))
//                {
//                    printf("Valid with Encrypt Key!!\n");
//                    //Print response
//
//                    Encrypt(receive_buff + HMAC_SIZE, message_size, encrypt_key, encrypt_iv, temp_buff);
//
//                    //A NAK response. Resend command!
//                    if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + SESSION_NONCE_SIZE), "NAK", 3) == 0)
//                    {
//                        printf("A NAK response\n\n\n");
//                        //Update encrypt key
//                        memcpy(next_encrypt_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
//                        UpdateEncryptKey(secret_key, next_encrypt_hint, encrypt_key);
//
//                        //Resend command
//                        PrepareSendingBuffer(
//                            encrypt_key,
//                            SESSION_ENCRYPT_KEY_SIZE,
//                            encrypt_iv,
//                            command,
//                            command_length,
//                            message_size,
//                            true,
//                            true,
//                            current_command_id,
//                            payload_to_PDU);
//
//                    }
//                    //Normal command response
//                    else
//                    {
//                        memcpy(printed_string, temp_buff, message_size);
//                        printed_string[(uint16_t)(*printed_string) + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE] = '\0';
//
//                        printf("Receive Response: %s\n\n\n", printed_string + SESSION_NONCE_SIZE + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE);
//                        //Update encrypt key
//                        memcpy(next_encrypt_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
//                        UpdateEncryptKey(secret_key, next_encrypt_hint, encrypt_key);
//                        current_command_id++;
//
//                        //Jump back to wait for user input
//                        return true;
//
//                    }
//
//                }
//
//                //Valid with backup key. This happen only when PDU response to Reset Key Routine command
//                else if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE, message_size, backup_key, SESSION_ENCRYPT_KEY_SIZE, receive_buff))
//                {
//                    printf("Valid with Backup Key!!\n");
//                    is_wait_for_reset_key_response = false;
//                    Encrypt(receive_buff + HMAC_SIZE, message_size, backup_key, encrypt_iv, temp_buff);
//
//                    //Check for response
//                    if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + SESSION_NONCE_SIZE), "OK", 2) == 0)
//                    {
//                        printf("Reset Key Response!!\n\n\n");
//                        //Update encrypt key
//                        memcpy(reset_key_hint, temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, SESSION_NONCE_SIZE);
//                        ResetKeyUpdate(secret_key, reset_key_hint, backup_key, encrypt_key);
//                        //Resend command
//                        PrepareSendingBuffer(
//                            encrypt_key,
//                            SESSION_ENCRYPT_KEY_SIZE,
//                            encrypt_iv,
//                            command,
//                            command_length,
//                            message_size,
//                            true,
//                            true,
//                            current_command_id,
//                            payload_to_PDU);
//                    }
//
//                    //Bad response for reset key command. Close connection
//                    else
//                    {
//                        return false;
//                    }
//                }
//
//                //Invalid response
//                else
//                {
//                    printf("Invalid Response!!\n\n\n");
//
//                    //If it already wait for reset key response but still invalid, then close connection
//                    if (is_wait_for_reset_key_response)
//                    {
//                        return false;
//                    }
//                    snprintf((char*)temp_payload, 9, "ResetKey");
//                    is_wait_for_reset_key_response = true;
//                    PrepareSendingBuffer(backup_key,
//                        SESSION_ENCRYPT_KEY_SIZE,
//                        encrypt_iv,
//                        temp_payload,
//                        strlen((char*)temp_payload),
//                        message_size,
//                        true,
//                        true,
//                        current_command_id,
//                        payload_to_PDU);
//                }
//            }
//
//            //Timeout sending or connection problem. Close connection
//            else
//            {
//                return false;
//
//            }
//
//            //If it made here, GUI need to resend to PDU or send reset key command. If there is sending problem, close connection
//            if (send(*PDU_socket, (char*)payload_to_PDU, message_size + HMAC_SIZE, 0) != message_size + HMAC_SIZE)
//            {
//                return false;
//            }
//        }
//    }
//    else
//    {
//        return false;
//    }
//
//}
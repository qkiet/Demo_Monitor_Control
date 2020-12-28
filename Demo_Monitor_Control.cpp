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

#define PDU_IP "192.168.2.102"
#define CLIENT_PORT 50
#define WIN32_LEAN_AND_MEAN

uint16_t real_message_size;
LARGE_INTEGER dummy_tick, start_session_tick, end_session_tick, freq;

#define ASSERT(x, error_message) if (x == 0) {printf("Something Wrong! %s\n Press Ctrl + C to terminate program\n\n", error_message); for(;;);}
 


void PrintHelp()
{   
    printf("Monitor and Control System Client version 1.0.\n\n");
    printf("Usage for execute: -i <smart_pdu_ip_address> -p <smart_pdu_port> -t <session_category> -s <session_secure_option> [-P <PDU_password>] [-n <number_of_commands] -S <message_size>\n");
    printf("Usage for help: -h or --help\n\n");
    printf("<session_category>: \"normal\" | \"measure\"\n");
    printf("<session_secure_option>: \"secured\" | \"unsec\"\n");
    printf("<message_size>: \"64\" | \"256\" | \"1024\"\n\n");

}




int main(int argc, char *argv[])
{
    typedef struct
    {
        char remote_ip_address[15];
        uint16_t remote_port_number;
        bool is_measure;
        bool is_secured;
        uint8_t PDU_password[20];
        int number_of_command;
        int message_size;
    } SIMULATION_PARAMETERS;

    SIMULATION_PARAMETERS sim_params
    {
        "\0",
        0,
        false,
        false,
        "\0",
        0,
        0
    };

    //
    // Process user argument section
    //

    // Scan for no argument 
    if (argc <= 1)
    {
        PrintHelp();
        return 0;
    }
    uint16_t temp_number;
    // Scan for help arugment
    for (int i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            PrintHelp();
            return 0;
        }
        //
        // Remote IP Address argument
        //
        if (strcmp(argv[i], "-i") == 0)
        {
            memcpy(sim_params.remote_ip_address, argv[i+1], strlen(argv[i+1]));
        }
        //
        // Remote port number argument
        //
        if (strcmp(argv[i], "-p") == 0)
        {
            temp_number = atoi(argv[i + 1]);
            sim_params.remote_port_number = temp_number;
        }
        //
        // Session category argument
        //

        if (strcmp(argv[i], "-t") == 0)
        {
            if (strcmp(argv[i + 1], "normal") == 0)
            {
                sim_params.is_measure = false;
            }
            else if (strcmp(argv[i + 1], "measure") == 0)
            {
                sim_params.is_measure = true;
            }
            //raise error
            else
            {
                printf("Session category (-t) not valid\n\n");
                return 0;
            }
        }
        //
        // Secure options argument
        //
        if (strcmp(argv[i], "-s") == 0)
        {
            if (strcmp(argv[i + 1], "secured") == 0)
            {
                sim_params.is_secured = true;
            }
            else if (strcmp(argv[i + 1], "unsec") == 0)
            {
                sim_params.is_secured = false;
            }
            //raise error
            else
            {
                printf("Session secure option (-s) not valid\n\n");
                return 0;
            }
        }
        //
        // PDU password argument
        //
        if (strcmp(argv[i], "-P") == 0)
        {
            memcpy(sim_params.PDU_password, argv[i + 1], strlen(argv[i + 1]));
        }
        //
        // Number of commands argument
        //
        if (strcmp(argv[i], "-n") == 0)
        {
            temp_number = atoi(argv[i + 1]);
            sim_params.number_of_command = temp_number;

        }
        //
        // Message size argument
        //
        if (strcmp(argv[i], "-S") == 0)
        {
            temp_number = atoi(argv[i + 1]);
            sim_params.message_size = temp_number;

        }
    }

    ASSERT(sim_params.remote_ip_address[0] != 0, "Invalid remote IP address");
    ASSERT(sim_params.remote_port_number != 0, "Invalid remote port number");
    ASSERT(sim_params.message_size != 0, "Invalid message size");
    ASSERT(sim_params.is_secured && sim_params.PDU_password[0] != 0, "Secured session but no password");
    if (sim_params.remote_ip_address[0] == '\0')
    {

    }

    //
    // done process argument
    //
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
        inet_pton(AF_INET, sim_params.remote_ip_address, &remoteaddr.sin_addr);
        remoteaddr.sin_port = htons(sim_params.remote_port_number ); // whatever the server is listening on
        if (sim_params.is_secured)
        {
            InitNetworkService(sim_params.PDU_password);
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

        if (!sim_params.is_secured)
        {
            RunUnsecuredSession(&client_sock, sim_params.number_of_command, sim_params.message_size, false);
        }
        else
        {
            RunSecuredSession(&client_sock, sim_params.number_of_command, sim_params.message_size);
        }

        //switch (session_type_answer)
        //{
        //case 1:
        //    RunUnsecuredSession(&client_sock, sim_params.number_of_command, sim_params.message_size, false);
        //    break;
        //case 2:
        //    RunUnsecuredSession(&client_sock, sim_params.number_of_command, sim_params.message_size, true);
        //    break;
        //default:
        //    RunSecuredSession(&client_sock, sim_params.number_of_command, sim_params.message_size);
        //}


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
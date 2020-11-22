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
            RunUnsecuredSession(&client_sock, number_of_transaction, message_size_answer, false);
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




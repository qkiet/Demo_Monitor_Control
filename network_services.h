#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "crypto_services.h"
#include <stdio.h>
#include <string.h>


#define HMAC_SIZE 32
#define SEND_TIMEOUT 8000
#define RECEIVE_TIMEOUT 8000
#define MAXIMUM_PACKET_LENGTH 1060
#define SECRET_KEY_SIZE   ( 256 / 8 )
#define SESSION_NONCE_SIZE  ( 128 / 8 )
#define SESSION_IV_SIZE  ( 128 / 8 )
#define SESSION_BLOCK_SIZE  ( 128 / 8 )
#define SESSION_ENCRYPT_KEY_SIZE  ( 128 / 8 )
#define SESSION_COMMAND_KEY_MAX_SIZE  ( 128 / 8 )
#define MESSAGE_LENGTH_HEADER_SIZE 2
#define MESSAGE_COMMAND_ID_SIZE 2
#define TYPE_PAYLOAD_NORMAL 0x00
#define TYPE_PAYLOAD_RESEND 0x01
#define SESSION_KIND_DEMO 0x00
#define SESSION_KIND_MEASURE 0x01


extern void InitNetworkService(uint8_t* input_password);
/// <summary>
/// Run Secured Session if User specified.
/// </summary>
/// <param name="running_socket">SOCKET structure that connect to PDU.</param>
/// <param name="transaction_length">Length of the transaction. Only useful if this is Measure Session</param>
/// <param name="message_size">Size of the message.</param>
extern void RunSecuredSession(SOCKET* running_socket, int transaction_length, uint16_t message_size);
extern void RunUnsecuredSession(SOCKET* running_socket, int transaction_length, int message_answer, bool is_encrypted);
extern void RunEncryptedSession(SOCKET* running_socket, int transaction_length, int message_answer);
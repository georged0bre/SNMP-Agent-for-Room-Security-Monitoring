#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <string>
#include <map> // used to define the object tree
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "SnmpProtocol.h"

using namespace std;

// SNMP
#define SNMP_MSG_MAX_LEN	2048
// Listening Port
#define PORT 161

// Funcție pentru afișarea unui array de octeți în format hexazecimal (pentru debugging)
void printAsHexa(char* byteArray, int lengthArray) {
	unsigned int value;
	for (int i = 0; i < lengthArray; i++)
	{
		value = byte2int(byteArray[i]);
		cout << hex << uppercase << "0x" << std::setw(2) << std::setfill('0') << value << " " << dec;
	}
	cout << endl;
}

int main(int argc, char* argv[])
{
	// Pornesc rețeaua WSAStartup, socket() și bind() pe portul 161
	SOCKET sd;
	int myerror;
	myerror = startSocket(sd, PORT);
	if (myerror < 0) {
		std::cerr << "Failed to start socket" << std::endl;
		return -1;
	}

	//Pregătesc memoria pentru a primi mesajele SNMP și pentru a salva informațiile despre expeditor
	int received_msg_length; // // Câți octeți are mesajul primit
	char recv_msg_buffer[SNMP_MSG_MAX_LEN]; //Memoria unde stocăm datele brute
	struct sockaddr_in client_ip_info; // Aici salvăm IP-ul celui care ne scrie (Managerul)

	// Initializare baza de date cu obiecte gestionate de agent
	TypeMyTree management_db;
	initializeManagementDB(management_db);
	std::cout << "SNMP Agent started. Listening on port " << PORT << "..." << std::endl;

	while (1)
	{
		//Programul "îngheață" aici până când cineva trimite un mesaj pe portul 161.
		// Rezultatul (0 sau eroare) ajunge în 'myerror'.
		myerror = receiveFromSocket(sd, recv_msg_buffer, received_msg_length, client_ip_info);

		// inet_ntoa: Transformă adresa IP din format binar (rețea) în text (ex: 127.0.0.1)
		// ntohs: Transformă portul din format rețea (Big-Endian) în format PC (Little-Endian)
		std::cout << "Received packet from " << inet_ntoa(client_ip_info.sin_addr) << ":" << ntohs(client_ip_info.sin_port) << std::endl;

		// Afișăm conținutul mesajului primit în format hexazecimal pentru debugging
		std::cout << "Number of bytes = " << received_msg_length << std::endl;
		std::cout << "Data in hexa:" << std::endl;
		printAsHexa(recv_msg_buffer, received_msg_length);

		//Pregătesc spațiu gol pentru răspuns
		char snmp_response_buffer[SNMP_MSG_MAX_LEN];

		// Aici vom construi răspunsul SNMP pe care îl vom trimite înapoi Managerului cu lungumea = lungime cerere 
		int response_msg_length = received_msg_length;

		// TODO SNMP_message cosntrusctor method needs to be fully implemented
		SNMP_message* request_msg = new SNMP_message(recv_msg_buffer); // Constructorul SNMP_message ia datele brute (recv_msg_buffer) și le "desface"
		SNMP_message* response_msg = new SNMP_message(); // Constructorul gol pentru a putea fi folosit la generarea răspunsului

		response_msg->version = request_msg->version;
		response_msg->comunity = request_msg->comunity;
		response_msg->request_id = request_msg->request_id; // Copiem ID-ul cererii pentru ca Managerul sa accepte raspunsul

		// Verificăm ce tip de cerere am primit de la Manager
		switch (request_msg->pdu_type)
		{
		case SNMP_message::PduType::GET_REQUEST:
			// TODO add here code to handle get requests
			std::cout << "Received GET request" << std::endl;
			processGetRequest(request_msg, response_msg, management_db);
			break;

		case SNMP_message::GET_NEXT_REQUEST:
			std::cout << "Processing GET-NEXT request " << std::endl;
			processGetNextRequest(request_msg, response_msg, management_db);
			break;

		case SNMP_message::PduType::SET_REQUEST:
			// TODO add here code to handle set requests
			std::cout << "Received SET request" << std::endl;
			processSetRequest(request_msg, response_msg, management_db);
			break;

		default:
			std::cout << "Pachet primit cu PDU Type: 0x" << hex << (int)request_msg->pdu_type << dec << std::endl;
			break;
		}

		// 1. Generăm pachetul binar final (TLV) din obiectul response_msg
		char send_buffer[SNMP_MSG_MAX_LEN];
		int len = response_msg->to_tlv(send_buffer, SNMP_MSG_MAX_LEN);

		if (len <= 0) {
			std::cerr << "Failed to encode SNMP message to TLV!" << std::endl;
		}
		else {
			// --- INCEPUT LOGARE CONSOLA (Cerinta Anexa B) ---
			std::cout << endl;
			std::cout << "Generated response:" << std::endl;
			std::cout << "------------------------------------------------------------------------------------------------------------------------" << std::endl;
			std::cout << " 1) Number of bytes = " << len << std::endl;
			std::cout << " 2) Data in hexa: " << std::endl;

			// Afișăm hexazecimalul pachetului trimis (Analiza de pachet)
			printAsHexa(send_buffer, len);

			// Obținem IP-ul clientului pentru logare
			char ip[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &(client_ip_info.sin_addr), ip, INET_ADDRSTRLEN);

			std::cout << " 3) Sending response to " << ip << " : " << ntohs(client_ip_info.sin_port) << std::endl;

			// Logare conținut VarBinds (ce date am pus în tabel)
			std::cout << " 4) Response VarBinds Details:" << std::endl;
			for (auto& vb : response_msg->variable_binding_list) {
				std::cout << "    OID: " << vb.oid << " => ";
				if (vb.type == INTEGER) {
					std::cout << "VALUE (INTEGER): " << vb.value.integer_value << std::endl;
				}
				else if (vb.type == IpAddress || vb.type == 0x40) {
					unsigned int ipVal = vb.value.integer_value;
					std::cout << "VALUE (IP): " << ((ipVal >> 24) & 0xFF) << "." << ((ipVal >> 16) & 0xFF) << "."
						<< ((ipVal >> 8) & 0xFF) << "." << (ipVal & 0xFF) << std::endl;
				}
				else {
					std::cout << "VALUE: NULL" << std::endl;
				}
			}
			std::cout << "------------------------------------------------------------------------------------------------------------------------";
			// --- SFARSIT LOGARE CONSOLA ---

			// 4. Trimiterea efectivă a pachetului către Manager (MIB Browser)
			sendToSocket(sd, send_buffer, len, client_ip_info);
		}
	}

	/*close the sockets */
	if (sd != NULL) {
		closesocket(sd);
		WSACleanup();
		cout << "Socket cleared. \n";
	}

	return 0;
}
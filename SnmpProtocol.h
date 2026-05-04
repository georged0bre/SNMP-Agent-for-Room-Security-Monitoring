#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <string>
#include <map>
#include <vector>

//Codurile standard ASN.1 pentru tipurile de date (ex: 2 = INTEGER)
enum Asn1DataType {
    INTEGER = 2,
    OCTET_STRING = 4,
    OBJECT_IDENTIFIER = 0x06,
    IpAddress = 0x40,
    NULL_asn1 = 0x05,
    SEQUENCE = 0x30,
    Gauge32 = 0x42,
};

// Codurile de eroare oficiale pentru pachetele SNMP (0 = succes, 2 = OID inexistent)
enum ErrorStatus {
    noError = 0, tooBig = 1, noSuchName = 2, badValue = 3, readOnly = 4, genErr = 5,
};

// Drepturile de acces pentru obiectele din baza de date
enum MaxAccess {
    not_accessible = 0, read_only = 1, read_write = 2,
};

// Tipul obiectului (scalar = valoare simplă, table = colecție de date, intr un tabel)
enum ObjectType {
    scalar = 0, table = 1, row = 2, column = 3,
};

// Uniune: ocupă același spațiu în memorie pentru un INT sau un STRING
typedef union A {
    int integer_value;
    char* char_array_value; 
} tvalue;

// Structura care definește un obiect în baza de date (nod) = Să stocheze tot ce știe Agentul despre un anumit senzor sau parametru în baza asta de date
typedef struct B {
    ObjectType object_type = ObjectType::scalar; 
    Asn1DataType data_type; 
    MaxAccess max_access = MaxAccess::not_accessible; 
    unsigned int length; 
    tvalue value; 
} TypeMyNode;

// Definim Baza de date: o hartă unde cauți după OID (string) și primești un Nod
typedef std::map<std::string, TypeMyNode> TypeMyTree;

// Structură pentru o variabilă SNMP (pereche OID - Valoare) dintr-un pachet,
// adica mesajul de il primesc si strebuie sa l caut dupa OID in baza de date
typedef struct {
    std::string oid;
    int length;
    Asn1DataType type; 
    tvalue value;
} VariableBind;

class SNMP_message {
public:
    int valid_paket; 
    int version;
    std::string comunity;

    enum PduType {
        GET_REQUEST = 0xA0,
        GET_NEXT_REQUEST = 0xA1,
        GET_RESPONSE = 0xA2,
        SET_REQUEST = 0xA3
    };
    PduType pdu_type;
    int request_id;
    ErrorStatus error_status;
    int error_index;
    std::vector<VariableBind> variable_binding_list;

    SNMP_message();
    SNMP_message(const char* data); // Constructor care DECODIFICĂ datele primite din rețea
    int to_tlv(char* buffer, int maxLength); // Funcție care DECODIFICĂ obiectul în biți (TLV)
};

// Acestea trebuie să fie singurele declarații pentru aceste funcții în tot proiectul
int startSocket(SOCKET& sd, int puerto);
int receiveFromSocket(SOCKET sd, char* recibido, int& recv_len, struct sockaddr_in& infoIpCliente);
int sendToSocket(SOCKET sd, const char* mensaje, int longMensaje, struct sockaddr_in& infoIpDestino);

void initializeManagementDB(TypeMyTree& db);
void processGetRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db);
void processGetNextRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db);
void processSetRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db);

unsigned int byte2int(unsigned char bb);
char int2byte(unsigned int number);
unsigned int int_to_tlv(char* ber_coding, unsigned int value);

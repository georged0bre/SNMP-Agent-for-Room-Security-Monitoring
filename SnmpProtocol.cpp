#include "snmpProtocol.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream> // Necesar pentru procesarea OID-urilor
#pragma warning(disable : 4996) // Dezactivare avertismente Visual Studio pentru functii nesigure (sscanf, etc.)
using namespace std;
#define SNMP_MSG_MAX_LEN 2048

// Convertire int în byte (folosită în to_tlv)
char int2byte(unsigned int number) { 
    return (char)(number & 0xFF);
}
// Convertire byte în int (folosită în read_tlv_int)
unsigned int byte2int(unsigned char bb) {
    return (unsigned int)bb;
}

// Transformă un int într-un format TLV (Tag-Length-Value) pentru a fi inclus în pachetul SNMP
unsigned int int_to_tlv(char* ber_coding, unsigned int value) {
    ber_coding[0] = 0x02;    
    unsigned int length = 1; 
   
    if (value <= 0x7F) length = 1;  
    else if (value <= 0xFFFF) length = 2;
    else if (value <= 0xFFFFFF) length = 3;
    else length = 4;

    ber_coding[1] = (char)length; 
    for (int i = 0; i < (int)length; i++) 
    {
        ber_coding[2 + i] = (char)((value >> ((length - 1 - i) * 8)) & 0xFF);
    }
    return 2 + length; 
}

// Transformă un format TLV (Tag-Length-Value) care reprezintă un INTEGER într-un int obișnuit pentru a fi folosit în program
int read_tlv_int(const char* buffer, unsigned int& value) {

    if ((unsigned char)buffer[0] != 0x02) return -1; 
    int length = (unsigned char)buffer[1];
    value = 0;
    for (int i = 0; i < length; i++) {
        value = (value << 8) | (unsigned char)buffer[2 + i];
    }
    return 2 + length; 
}

// SNMP_message 
SNMP_message::SNMP_message() {
    valid_paket = 0;
    version = 0;
    pdu_type = GET_REQUEST;
    request_id = 0;
    error_status = noError;
    error_index = 0;
}

// Constructor care DECODIFICA datele primite (Constructorul SNMP_message(const char* data))
SNMP_message::SNMP_message(const char* buffer) {
    int pos = 0;
    valid_paket = 0;

    // 1. Verificare Sequence Start
    if ((unsigned char)buffer[pos] != 0x30) return;
    pos += 2; // Sari peste 0x30 si lungime

    // 2. Versiune
    if ((unsigned char)buffer[pos] == 0x02) {
        int len_ver = (unsigned char)buffer[pos + 1];
        pos += 2;
        version = (unsigned char)buffer[pos];
        pos += len_ver;
    }

    // 3. Comunitate
    if ((unsigned char)buffer[pos] == 0x04) {
        int len_com = (unsigned char)buffer[pos + 1];
        pos += 2;
        comunity = std::string(buffer + pos, len_com);
        pos += len_com;
    }

    // 4. PDU Type (A0=GET, A1=GET_NEXT, A3=SET)
    unsigned char pdu_tag = (unsigned char)buffer[pos++];
    if (pdu_tag == 0xa0) pdu_type = GET_REQUEST;
    else if (pdu_tag == 0xa1) pdu_type = GET_NEXT_REQUEST;
    else if (pdu_tag == 0xa2) pdu_type = GET_RESPONSE;
    else if (pdu_tag == 0xa3) pdu_type = SET_REQUEST;
    else return; // Tip necunoscut

    pos++; // Sari peste lungimea totala a PDU-ului

    // 5. RequestID
    if ((unsigned char)buffer[pos] == 0x02) {
        int len = (unsigned char)buffer[pos + 1]; pos += 2;
        request_id = 0;
        for (int i = 0; i < len; i++) request_id = (request_id << 8) | (unsigned char)buffer[pos + i];
        pos += len;
    }

    // 6. Error Status
    if ((unsigned char)buffer[pos] == 0x02) {
        int len = (unsigned char)buffer[pos + 1]; pos += 2;
        int temp_err = 0;
        for (int i = 0; i < len; i++) temp_err = (temp_err << 8) | (unsigned char)buffer[pos + i];
        error_status = (ErrorStatus)temp_err;
        pos += len;
    }

    // 7. Error Index
    if ((unsigned char)buffer[pos] == 0x02) {
        int len = (unsigned char)buffer[pos + 1]; pos += 2;
        error_index = 0;
        for (int i = 0; i < len; i++) error_index = (error_index << 8) | (unsigned char)buffer[pos + i];
        pos += len;
    }

    // 8. VarBind List (Aici se intampla magia)
    if ((unsigned char)buffer[pos] == 0x30) {
        int vbl_len = (unsigned char)buffer[pos + 1];
        pos += 2;
        int end_vbl = pos + vbl_len;

        while (pos < end_vbl) {
            if ((unsigned char)buffer[pos] == 0x30) {
                int vb_total_len = (unsigned char)buffer[pos + 1];
                pos += 2; // Intram in VarBind (Sequence OID + Value)

                if ((unsigned char)buffer[pos] == 0x06) { // Tag OID
                    int oid_len = (unsigned char)buffer[pos + 1];
                    pos += 2;

                    // Decodare OID
                    std::string oid_str = std::to_string((unsigned char)buffer[pos] / 40) + "." + std::to_string((unsigned char)buffer[pos] % 40);
                    for (int i = 1; i < oid_len; i++) {
                        oid_str += "." + std::to_string((unsigned char)buffer[pos + i]);
                    }
                    pos += oid_len;

                    VariableBind vb;
                    vb.oid = oid_str;

                    // --- DECODIFICARE VALOARE (Sectiunea reparata) ---
                    unsigned char tag = (unsigned char)buffer[pos];
                    unsigned int len_val = (unsigned char)buffer[pos + 1];

                    if (tag == 0x02) { // INTEGER
                        unsigned int val = 0;
                        int consumed = read_tlv_int(buffer + pos, val);
                        vb.type = INTEGER;
                        vb.value.integer_value = val;
                        pos += consumed;
                    }
                    else if (tag == 0x40) { // IP ADDRESS (Tag-ul specific SNMP)
                        // IP-ul vine mereu ca 4 octeti: [0x40][0x04][A][B][C][D]
                        unsigned int ip_val = 0;
                        if (len_val == 4) {
                            ip_val |= (unsigned char)buffer[pos + 2] << 24;
                            ip_val |= (unsigned char)buffer[pos + 3] << 16;
                            ip_val |= (unsigned char)buffer[pos + 4] << 8;
                            ip_val |= (unsigned char)buffer[pos + 5];
                        }
                        vb.type = (decltype(vb.type))0x40; // IpAddress tag
                        vb.value.integer_value = ip_val;
                        pos += 2 + len_val;
                    }
                    else if (tag == 0x05) { // NULL (pentru GET Requests)
                        vb.type = NULL_asn1;
                        pos += 2;
                    }
                    else {
                        // Fallback pentru alte tipuri (Octet String etc.)
                        vb.type = NULL_asn1;
                        pos += 2 + len_val;
                    }

                    variable_binding_list.push_back(vb);
                }
            }
            else {
                pos++; // Siguranta pentru a nu ramane blocat
            }
        }
    }
    valid_paket = 1;
}
// Functie care CODIFICA obiectul in biti (TLV) pentru a fi trimis pe retea
int SNMP_message::to_tlv(char* buffer, int maxLength) {
    int pos = 0;

    // 1. Outer Sequence (Pachetul intreg)
    buffer[pos++] = 0x30;
    int seq_len_pos = pos++; // Salvam pozitia unde vom scrie lungimea totala
    int seq_start = pos;

    // 2. Version (Integer)
    buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = (char)version;

    // 3. Community String (Octet String)
    buffer[pos++] = 0x04; buffer[pos++] = (char)comunity.size();
    for (size_t i = 0; i < comunity.size(); i++) buffer[pos++] = comunity[i];

    // 4. PDU Type (0xA2 pentru GET_RESPONSE)
    buffer[pos++] = (unsigned char)pdu_type;
    int pdu_len_pos = pos++;
    int pdu_start = pos;

    // 5. Request ID, Error Status, Error Index
    pos += int_to_tlv(buffer + pos, (unsigned int)request_id);
    pos += int_to_tlv(buffer + pos, (unsigned int)error_status);
    pos += int_to_tlv(buffer + pos, (unsigned int)error_index);

    // 6. VarBindList (Sequence)
    buffer[pos++] = 0x30;
    int vbl_len_pos = pos++;
    int vbl_start = pos;

    for (auto& vb : variable_binding_list) {
        // Inceput VarBind (Sequence)
        buffer[pos++] = 0x30;
        int vb_len_pos = pos++;
        int vb_content_start = pos;

        // --- OID Encoding ---
        buffer[pos++] = 0x06; // Tag OID
        int oid_len_pos = pos++;
        int oid_start = pos;

        std::vector<unsigned int> comps;
        std::stringstream ss(vb.oid); std::string s;
        while (std::getline(ss, s, '.')) if (!s.empty()) comps.push_back(std::stoul(s));

        if (comps.size() >= 2) {
            buffer[pos++] = (char)(comps[0] * 40 + comps[1]);
            for (size_t i = 2; i < comps.size(); i++) {
                // Simplificare: scriem doar daca e sub 128 (pentru laborator e suficient)
                buffer[pos++] = (char)comps[i];
            }
        }
        buffer[oid_len_pos] = (char)(pos - oid_start);

        // --- VALUE Encoding (Aici am reparat problema cu NULL) ---
        if (vb.type == INTEGER) {
            pos += int_to_tlv(buffer + pos, (unsigned int)vb.value.integer_value);
        }
        else if (vb.type == 0x40) { // IpAddress Tag
            buffer[pos++] = 0x40;  // Tag IpAddress
            buffer[pos++] = 0x04;  // Lungime fixa 4 octeti
            // Extragem octetii din valoarea intreaga (ex: 0x7F000001 -> 127.0.0.1)
            buffer[pos++] = (char)((vb.value.integer_value >> 24) & 0xFF);
            buffer[pos++] = (char)((vb.value.integer_value >> 16) & 0xFF);
            buffer[pos++] = (char)((vb.value.integer_value >> 8) & 0xFF);
            buffer[pos++] = (char)(vb.value.integer_value & 0xFF);
        }
        else {
            // Daca nu e Integer sau IP, trimitem NULL (0x05 0x00)
            buffer[pos++] = 0x05;
            buffer[pos++] = 0x00;
        }

        // Inchidem lungimea pentru VarBind-ul curent
        buffer[vb_len_pos] = (char)(pos - vb_content_start);
    }

    // Inchidem toate lungimile (Back-patching)
    buffer[vbl_len_pos] = (char)(pos - vbl_start);
    buffer[pdu_len_pos] = (char)(pos - pdu_start);
    buffer[seq_len_pos] = (char)(pos - seq_start);

    return pos;
}

// --- Management DB & Logic Implementation ---

void initializeManagementDB(TypeMyTree& db) {
    TypeMyNode n1;
    n1.data_type = INTEGER; 
    n1.max_access = read_write;
    n1.value.integer_value = 10;
    db["1.3.6.1.2.1.48.1.1.0"] = n1; // numberEntered

    TypeMyNode n2;
    n2.data_type = INTEGER; 
    n2.max_access = read_write;
    n2.value.integer_value = 5;
    db["1.3.6.1.2.1.48.1.2.0"] = n2; // numberLeft

    TypeMyNode n3;
    n3.data_type = IpAddress; // Asigură-te că valoarea lui IpAddress este 0x40 în enum
    n3.max_access = read_write;
    n3.value.integer_value = 0x7F000001;   // SNMP așteaptă 4 octeți pentru IP. Exemplu pentru 127.0.0.1:
    db["1.3.6.1.2.1.48.1.3.0"] = n3;

    // --- Populare Tabel Istoric (365 zile) ---
 // Modificăm limita de la 3 la 365
    for (int i = 1; i <= 3; i++)
    {
        string index = to_string(i);

        // 1. Coloana dayYear (Indexul) - OID: .1.3.6.1.2.1.48.1.4.1.1.X
        TypeMyNode nodeDay;
        nodeDay.data_type = INTEGER; // Tipul cerut în MIB [cite: 164, 168]
        nodeDay.max_access = read_only; // Indexul este doar pentru citire [cite: 72, 188]
        nodeDay.value.integer_value = (unsigned int)i; // Valoarea va fi 1, 2, 3... 365
        db["1.3.6.1.2.1.48.1.4.1.1." + index] = nodeDay;

        // 2. Coloana peopleEntered - OID: .1.3.6.1.2.1.48.1.4.1.2.X
        TypeMyNode nodeIn;
        nodeIn.data_type = INTEGER;
        nodeIn.max_access = read_write; // Permite modificarea valorii [cite: 73, 175]
        nodeIn.value.integer_value = 0;
        db["1.3.6.1.2.1.48.1.4.1.2." + index] = nodeIn;

        // 3. Coloana peopleLeft - OID: .1.3.6.1.2.1.48.1.4.1.3.X
        TypeMyNode nodeOut;
        nodeOut.data_type = INTEGER;
        nodeOut.max_access = read_write;
        nodeOut.value.integer_value = 0;
        db["1.3.6.1.2.1.48.1.4.1.3." + index] = nodeOut;
    }
}

void processGetRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db) {
    res->pdu_type = SNMP_message::GET_RESPONSE;
    res->request_id = req->request_id;
    res->comunity = req->comunity;

    for (auto& var : req->variable_binding_list) {
        VariableBind vb;
        
        // 1. Încercăm să găsim OID-ul exact cum a venit (bun pentru TABEL)
        if (db.count(var.oid)) {
            vb.oid = var.oid;
            vb.type = db[var.oid].data_type;
            vb.value = db[var.oid].value;
        } 
        // 2. Dacă nu l-am găsit, încercăm să-i punem .0 (bun pentru SCALARI)
        else if (db.count(var.oid + ".0")) {
            std::string oid_fix = var.oid + ".0";
            vb.oid = oid_fix;
            vb.type = db[oid_fix].data_type;
            vb.value = db[oid_fix].value;
        } 
        // 3. Dacă tot nu există, dăm eroare
        else {
            vb.oid = var.oid;
            vb.type = NULL_asn1;
            res->error_status = noSuchName;
        }
        res->variable_binding_list.push_back(vb);
    }
}

void processSetRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db) {
    res->pdu_type = SNMP_message::GET_RESPONSE;
    res->request_id = req->request_id;
    res->comunity = req->comunity;

    for (auto& var : req->variable_binding_list) {
        std::string oid_to_check = var.oid;

        // --- PASUL 1: Verificăm dacă OID-ul există EXACT așa cum a venit ---
        // (Asta va merge pentru TABEL: ex .4.1.2.2)
        if (db.count(oid_to_check)) {
            if (db[oid_to_check].max_access == read_write) {
                db[oid_to_check].value.integer_value = var.value.integer_value;
                std::cout << "[SUCCESS] Tabel/IP actualizat: " << oid_to_check << std::endl;
                res->variable_binding_list.push_back(var);
            }
            else {
                res->error_status = readOnly; // Sau noSuchName
                res->variable_binding_list.push_back(var);
            }
        }
        // --- PASUL 2: Dacă nu l-am găsit, încercăm să-i punem un .0 ---
        // (Asta va merge pentru SCALARI: ex numberEntered)
        else if (db.count(oid_to_check + ".0")) {
            std::string scalar_oid = oid_to_check + ".0";
            db[scalar_oid].value.integer_value = var.value.integer_value;

            std::cout << "[SUCCESS] Scalar actualizat: " << scalar_oid << std::endl;

            VariableBind vb = var;
            vb.oid = scalar_oid;
            res->variable_binding_list.push_back(vb);
        }
        // --- PASUL 3: Nu există deloc ---
        else {
            std::cout << "[ERROR] OID negasit deloc: " << oid_to_check << std::endl;
            res->error_status = noSuchName;
            res->variable_binding_list.push_back(var);
        }
    }
}
void processGetNextRequest(SNMP_message* req, SNMP_message* res, TypeMyTree& db) {
    res->pdu_type = SNMP_message::GET_RESPONSE;
    res->request_id = req->request_id;
    res->comunity = req->comunity;

    for (auto& var : req->variable_binding_list) {
        auto it = db.upper_bound(var.oid); // Caută primul OID mai mare

        VariableBind vb;
        if (it != db.end()) {
            vb.oid = it->first;
            vb.type = it->second.data_type;
            vb.value = it->second.value;
            res->error_status = noError;
        }
        else {
            // Nu mai sunt date. Browser-ul va afișa eroarea ta din poză.
            vb.oid = var.oid;
            vb.type = NULL_asn1;
            res->error_status = noSuchName;
            res->error_index = 1;
        }
        res->variable_binding_list.push_back(vb);
    }
}


// --- Socket Implementation ---

int startSocket(SOCKET& sd, int puerto) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(puerto);
    if (bind(sd, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) return -1;
    return 0;
}

int receiveFromSocket(SOCKET sd, char* recibido, int& recv_len, struct sockaddr_in& infoIpCliente) {
    int clientLength = sizeof(infoIpCliente);
    memset(recibido, '\0', SNMP_MSG_MAX_LEN);
    recv_len = recvfrom(sd, recibido, SNMP_MSG_MAX_LEN, 0, (struct sockaddr*)&infoIpCliente, &clientLength);
    return (recv_len == SOCKET_ERROR) ? -1 : 0;
}

int sendToSocket(SOCKET sd, const char* mensaje, int longMensaje, struct sockaddr_in& infoIpDestino) {
    return (sendto(sd, mensaje, longMensaje, 0, (struct sockaddr*)&infoIpDestino, sizeof(infoIpDestino)) == SOCKET_ERROR) ? -1 : 0;
}
# SNMP-Agent-for-Room-Security-Monitoring
The goal of this project was to define a Management Information Base (MIB) and develop a functional SNMP Agent from scratch to handle network management operations (GET, SET, GETNEXT).
# SNMP Agent: Room Security & History Monitor

This project implements a fully functional **SNMP Agent** from scratch using C++. It is designed to manage a security system that monitors occupancy levels in a room and maintains a historical log of entries and exits[cite: 3, 4].

## 📋 Project Overview
The agent operates as a console application, communicating with SNMP Managers (like MibBrowser) via the UDP protocol on **Port 161**[cite: 3, 7]. It handles the encoding and decoding of **Basic Encoding Rules (BER)** to process management requests.

### Key Features
*   **Custom MIB Implementation**: Based on the `Lab1-MIB` definition, managing data under the OID `1.3.6.1.2.1.48.
*   **Scalar & Table Support**: Manages real-time counters and a 365-day historical data table.
*   **Protocol Operations**: Fully supports `GET`, `SET`, and `GET-NEXT` PDU types.
*   **BER Engine**: Custom logic for TLV (Tag-Length-Value) processing, including multi-byte integer support.
*   **Real-time Debugging**: Detailed console logging of raw hexadecimal packets and VarBind analysis.

## 🏗 System Architecture

### 1. Management Information Base (MIB)
The **Lab1-MIB.mib** file defines the following structure:
*   **`numberEntered`** (Integer32): Total number of people who entered (Read-Write).
*   **`numberLeft`** (Integer32): Total number of people who left (Read-Write).
*   **`deviceIp`** (IpAddress): Monitoring device IP (Read-Write).
*   **`dateTime`** (Table): A historical table indexed by `dayYear` (1-365) containing entry/exit records per day.

### 2. Technical Implementation (C++)
*   **Networking**: Uses `winsock2` for UDP socket management.
*   **Database**: Managed objects are stored in a `std::map<std::string, TypeMyNode>`, simulating a tree structure for OID lookups.
*   **Data Types**: Supports `INTEGER`, `OCTET STRING`, `OBJECT IDENTIFIER`, `IpAddress`, and `SEQUENCE`.

## 🚀 Getting Started

### Prerequisites
*   Windows OS (for `ws2_32.lib` dependencies).
*   A C++ Compiler (Visual Studio 2022 recommended).
*   An SNMP Manager (e.g., Manage-Engine MibBrowser or iReasoning).

### Build Instructions
1.  Include `SnmpProtocol.h`, `SnmpProtocol.cpp`, and `SNMP_agent.cpp` in your project.
2.  Add **`ws2_32.lib`** to your Linker Additional Dependencies.
3.  Compile and run the agent.
4.  Load `FinalMIB.mib` into your SNMP Manager and target `localhost` on port `161`.

## 📂 File Structure
*   **`SNMP_agent.cpp`**: Main entry point handling the socket loop and PDU switching.
*   **`SnmpProtocol.cpp`**: Core BER encoding/decoding and request processing logic.
*   **`SnmpProtocol.h`**: Protocol constants, ASN.1 type definitions, and class headers.
*   **`Lab1-MIB.mib`**: The ASN.1 MIB definition file.

## 👥 Authors
*   Brezeanu Valentina
*   Dobre George Cătălin
*   Costache Luis Andrei

---

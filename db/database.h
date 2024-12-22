#pragma once

#define SQLITE_HAS_CODEC
#define DB_PATH "../db/root.db"
#define DB_SCHEMA "../db/schema.sql"
#define ROOT_CERTS_TABLE "root_certs"
#define ISSUER_CERTS_TABLE "issuing_certs"
#define ISSUER_CSR_TABLE "issuing_csr"

#include <sqlite3.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <vector>

class Database {
private:
    sqlite3* db;                 
    std::string dbFileName;      
    std::string password;        

    void checkError(int resultCode, const std::string& errorMessage);
    void executeQuery(const std::string& query); // нужно переписать методы класса с использованием приватного метода
    void initializeSchema();

public:

    Database(const std::string& dbFileName, const std::string& password);
    ~Database();
    void open();                       
    void close();  
    void clear();


    void addRootCert(
        const std::string& certName,
        const std::string& serial,
        const std::string& info,
        int validity
    );

    void addIsuuerCSR(
        const std::string& csrName,
        const std::string& info
    );

    void addIssuerCert(
        const std::string& certName,
        const std::string& serial,
        const std::string& certDataFrom,
        const std::string& certDataTo,
        const std::string& info
    );

    void revokeRootCert(); // нужно дописать
    void revokeIssuerCert(const std::string& serial);

    void displayTable(const std::string& tableName);
};


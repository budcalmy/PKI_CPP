#pragma once

#include <iostream>
#include <memory>
#include <filesystem>
#include <stdexcept>
#include <utility>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../db/database.h"

#define ROOT_PRIVATE_KEY_PATH "../CA/root-ca/private"
#define ROOT_CNF "../CA/config/root_openssl.cnf"
#define ROOT_CERTS_PATH "../CA/root-ca/certs"

#define ISSUER_PRIVATE_KEY_PATH "../CA/issuing-ca/private"
#define ISSUER_CNF "../CA/config/issuing_openssl.cnf"
#define ISSUER_CSR_PATH "../CA/issuing-ca/csr"
#define ISSUER_CERTS_PATH "../CA/issuing-ca/certs"

using namespace std;

class Certificates {
private:
    void __printPublicKey(EVP_PKEY* pkey);
    void __deleteCertificate(const string& cert);
public:
    pair<X509_REQ*, string> readExistingX509_ReqFromPath(const string& reqPath);
    X509* readExistingX509FromPath(const string& certPath);

    X509* generateCertificate(Database& db, EVP_PKEY* pkey);
    pair<X509_REQ*, string> generetaIssuerCSR(Database& db, EVP_PKEY* pkey);

    X509* signIssuerReqCSR(X509_REQ* req, const string& reqFilename, X509* rootCert, EVP_PKEY* pkey, Database& db);

    static void displayCertificate(const string& certPath);
    static void displayCertificateReq(const string& reqPath);
};


void Certificates::__printPublicKey(EVP_PKEY* pkey) {
    if (!pkey) {
        std::cerr << "Ошибка: пустой указатель на ключ.\n";
        return;
    }

    unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (PEM_write_bio_PUBKEY(bio.get(), pkey) != 1) {
        std::cerr << "Ошибка: не удалось записать публичный ключ в BIO.\n";
        return;
    }

    char* bioData;
    long bioLength = BIO_get_mem_data(bio.get(), &bioData);
    std::cout << "Публичный ключ:\n" << std::string(bioData, bioLength) << "\n";
}


pair<X509_REQ*, string> Certificates::readExistingX509_ReqFromPath(const string& reqPath) {
    // Чтение существующего CSR из файла
    unique_ptr<BIO, decltype(&BIO_free)> csrBio(BIO_new_file(reqPath.c_str(), "r"), BIO_free);
    if (!csrBio) {
        cerr << "readExistingX509_ReqFromPath: Ошибка: не удалось открыть файл CSR: " << reqPath << "\n";
        return {nullptr, ""};
    }

    X509_REQ* existingReq = PEM_read_bio_X509_REQ(csrBio.get(), nullptr, nullptr, nullptr);
    if (!existingReq) {
        cerr << "readExistingX509_ReqFromPath: Ошибка: не удалось прочитать CSR из файла.\n";
        return {nullptr, ""};
    }

    std::filesystem::path pathObj(reqPath);

    return {existingReq, pathObj.stem().stem().string()};
}


X509* Certificates::readExistingX509FromPath(const string& certPath) {
    // Открытие файла сертификата для чтения
    unique_ptr<BIO, decltype(&BIO_free)> certBio(BIO_new_file(certPath.c_str(), "r"), BIO_free);
    if (!certBio) {
        cerr << "readExistingX509FromPath: Ошибка: не удалось открыть файл: " << certPath << endl;
        return nullptr;
    }

    // Чтение сертификата из файла
    X509* cert = PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        cerr << "readExistingX509FromPath: Ошибка: не удалось прочитать сертификат из файла: " << certPath << endl;
        return nullptr;
    }

    return cert;
}


X509* Certificates::generateCertificate(Database& db, EVP_PKEY* pkey) {

    if (!pkey) {
        throw runtime_error("generateRootCertificate: передан некорректный указатель на ключ.\n");
    }

    string uniqueName;
    int days;
    string countryName, organizationName, commonName;

    cout << "Введите уникальное имя для сертификата (например, MyRootCA): ";
    getline(cin, uniqueName);
    string certPath = string(ROOT_CERTS_PATH) + "/" + uniqueName + ".cert.pem";

    // Проверка существования root_cert
    if (std::filesystem::exists(certPath)) {
        cout << "generateRootCertificate: Запрос с таким именем уже существует. Загружаем из файла.\n";
        X509* cert = readExistingX509FromPath(certPath);
        return cert;
    }

    cout << "Введите количество дней действия сертификата: ";
    if (!(cin >> days) || days <= 0) {
        throw runtime_error("generateRootCertificate: введите корректное положительное число.\n");
    }
    cin.ignore();

    cout << "Введите countryName (например, RU): ";
    getline(cin, countryName);

    cout << "Введите organizationName (например, My Organization): ";
    getline(cin, organizationName);

    cout << "Введите commonName: ";
    getline(cin, commonName);

    // Создание нового X509 сертификата
    unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    if (!cert) {
        throw runtime_error("generateRootCertificate: не удалось создать структуру X509.\n");
    }

    // Установка серийного номера
    unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> serialNumber(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(serialNumber.get(), rand());
    X509_set_serialNumber(cert.get(), serialNumber.get());

    // Установка сроков действия
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 60 * 60 * 24 * days);

    // Установка субъекта и эмитента
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(countryName.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(organizationName.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);

    // Установка ключа
    X509_set_pubkey(cert.get(), pkey);

    // Подпись сертификата
    if (X509_sign(cert.get(), pkey, EVP_sha256()) <= 0) {
        throw runtime_error("generateRootCertificate: не удалось подписать сертификат.\n");
    }

    // Сохранение сертификата в файл
    unique_ptr<BIO, decltype(&BIO_free)> certBio(BIO_new_file(certPath.c_str(), "w"), BIO_free);
    if (!certBio || PEM_write_bio_X509(certBio.get(), cert.get()) == 0) {
        cerr << "generateRootCertificate: не удалось сохранить сертификат в файл: " << certPath << "\n";
    }

    cout << "Сертификат успешно создан и сохранён по пути: " << certPath << "\n";

    const ASN1_INTEGER* serial = X509_get_serialNumber(cert.get());
    BIGNUM* serialBN = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serialStr = BN_bn2dec(serialBN);

    const char* info = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0);

    try {
        db.addRootCert(uniqueName, serialStr, info, days);
    } catch (const std::exception& ex) {
        cerr << "generateRootCertificate: ошибка при добавлении сертификата в базу данных: " << ex.what() << "\n";
    }

    return cert.release();
}


pair<X509_REQ*, string> Certificates::generetaIssuerCSR(Database& db, EVP_PKEY* pkey) {

    if (!pkey) {
        throw runtime_error("generetaIssuerCSR: передан некорректный указатель на ключ.\n");
    }

    string uniqueName;
    string countryName, organizationName, commonName;

    cout << "generetaIssuerCSR: Введите имя для запроса (например, myCsr): ";
    getline(cin, uniqueName);
    string reqPath = string(ISSUER_CSR_PATH) + "/" + uniqueName + ".csr.pem";

    // Проверка существования CSR
    if (std::filesystem::exists(reqPath)) {
        cout << "generetaIssuerCSR: Запрос с таким именем уже существует. Загружаем из файла.\n";
        auto [req, uniqueName] = readExistingX509_ReqFromPath(reqPath);
        return {req, uniqueName};
    }

    cout << "Введите countryName (например, RU): ";
    getline(cin, countryName);

    cout << "Введите organizationName (например, My Organization): ";
    getline(cin, organizationName);

    cout << "Введите commonName: ";
    getline(cin, commonName);

    // Создание структуры для CSR
    unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(X509_REQ_new(), X509_REQ_free);
    if (!req) {
        throw runtime_error("generetaIssuerCSR: не удалось создать структуру для CSR.\n");
    }

    // Установка информации о субъекте
    X509_NAME* name = X509_REQ_get_subject_name(req.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(countryName.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(organizationName.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0);

    // Установка ключа
    if (X509_REQ_set_pubkey(req.get(), pkey) != 1) {
        throw runtime_error("generetaIssuerCSR: не удалось установить ключ в CSR.\n");
    }

    // Подпись запроса
    if (X509_REQ_sign(req.get(), pkey, EVP_sha256()) <= 0) {
        throw runtime_error("generetaIssuerCSR: не удалось подписать CSR.\n");
    }

    // Сохранение CSR в файл
    unique_ptr<BIO, decltype(&BIO_free)> csrBio(BIO_new_file(reqPath.c_str(), "w"), BIO_free);
    if (!csrBio || PEM_write_bio_X509_REQ(csrBio.get(), req.get()) == 0) {
        cerr << "generetaIssuerCSR: не удалось сохранить CSR в файл: " << reqPath << "\n";
    }

    cout << "generetaIssuerCSR: Запрос на сертификат успешно создан и сохранён по пути: " << reqPath << "\n";


    const char* info = X509_NAME_oneline(X509_REQ_get_subject_name(req.get()), nullptr, 0);

    try {
        db.addIsuuerCSR(uniqueName, info);
    } catch (const std::exception& ex) {
        cerr << "generetaIssuerCSR: ошибка при добавлении запроса в базу данных: " << ex.what() << "\n";
    }

    return {req.release(), uniqueName};
}


X509* Certificates::signIssuerReqCSR(X509_REQ* req, const string& reqFilename, X509* rootCert, EVP_PKEY* pkey, Database& db) {

    string issuerCertPath = string(ISSUER_CERTS_PATH) + "/" + reqFilename + ".cert.pem";

    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> reqPubKey(X509_REQ_get_pubkey(req), EVP_PKEY_free);
    if (!reqPubKey) {
        throw runtime_error("Ошибка: не удалось извлечь публичный ключ из CSR.");
    }

    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> rootPubKey(X509_get_pubkey(rootCert), EVP_PKEY_free);
    if (!rootPubKey) {
        throw runtime_error("Ошибка: не удалось извлечь публичный ключ из корневого сертификата.");
    }

    // std::cout << "Публичный ключ из CSR:\n";
    // __printPublicKey(reqPubKey.get());

    // std::cout << "Публичный ключ из корневого сертификата:\n";
    // __printPublicKey(rootPubKey.get());

    // if (EVP_PKEY_cmp(reqPubKey.get(), rootPubKey.get()) != 1) {
    //     throw runtime_error("Ошибка: публичный ключ CSR не соответствует публичному ключу корневого сертификата.");
    // }

    unique_ptr<X509, decltype(&X509_free)> newIssuerCert(X509_new(), X509_free);
    if (!newIssuerCert) {
        throw std::runtime_error("Ошибка: не удалось создать структуру для нового сертификата.");
    }

    // Установка серийного номера
    unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> serialNumber(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(serialNumber.get(), rand());
    X509_set_serialNumber(newIssuerCert.get(), serialNumber.get());

    // Установка сроков действия сертификата
    ASN1_TIME* rootNotBefore = X509_get_notBefore(rootCert);
    ASN1_TIME* rootNotAfter = X509_get_notAfter(rootCert);
    if (!rootNotBefore || !rootNotAfter) {
        throw std::runtime_error("Ошибка: не удалось получить даты начала или окончания действия из корневого сертификата.");
    }
    try {
        X509_set_notBefore(newIssuerCert.get(), rootNotBefore);
        X509_set_notAfter(newIssuerCert.get(), rootNotAfter);
    } catch (const exception& ex) {
        throw std::runtime_error(ex.what());
    }

    // Копирование данных субъекта из CSR
    X509_set_subject_name(newIssuerCert.get(), X509_REQ_get_subject_name(req));

    // Установка эмитента как корневого сертификата
    X509_set_issuer_name(newIssuerCert.get(), X509_get_subject_name(rootCert));

    // Установка публичного ключа из CSR
    if (X509_set_pubkey(newIssuerCert.get(), reqPubKey.get()) != 1) {
        throw runtime_error("Ошибка: не удалось установить публичный ключ из CSR.");
    }

    // Подпись нового сертификата
    if (X509_sign(newIssuerCert.get(), pkey, EVP_sha256()) <= 0) {
        throw runtime_error("Ошибка: не удалось подписать новый сертификат.");
    }

    // Сохранение подписанного сертификата в файл
    unique_ptr<BIO, decltype(&BIO_free)> newIssuerCertBio(BIO_new_file(issuerCertPath.c_str(), "w"), BIO_free);
    if (!newIssuerCertBio || PEM_write_bio_X509(newIssuerCertBio.get(), newIssuerCert.get()) == 0) {
        cerr << "signIssuerReqCSR: не удалось сохранить подписанный сертификат в файл: " << issuerCertPath << "\n";
    }

    cout << "Сертификат успешно подписан и сохранён по пути: " << issuerCertPath << "\n";


    const ASN1_INTEGER* serial = X509_get_serialNumber(newIssuerCert.get());
    BIGNUM* serialBN = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serialStr = BN_bn2dec(serialBN);

    const char* info = X509_NAME_oneline(X509_get_subject_name(newIssuerCert.get()), nullptr, 0);

    // Извлекаем даты начала и окончания действия сертификата
    ASN1_TIME* certNotBefore = X509_get_notBefore(newIssuerCert.get());
    ASN1_TIME* certNotAfter = X509_get_notAfter(newIssuerCert.get());

    struct tm tmNotBefore = {0}, tmNotAfter = {0};
    if (!ASN1_TIME_to_tm(certNotBefore, &tmNotBefore) || !ASN1_TIME_to_tm(certNotAfter, &tmNotAfter)) {
        throw std::runtime_error("Ошибка при преобразовании времени.");
    }

    char notBeforeStr[64], notAfterStr[64];
    strftime(notBeforeStr, sizeof(notBeforeStr), "%Y-%m-%d %H:%M:%S", &tmNotBefore);
    strftime(notAfterStr, sizeof(notAfterStr), "%Y-%m-%d %H:%M:%S", &tmNotAfter);

    db.addIssuerCert(reqFilename, serialStr, notBeforeStr, notAfterStr, info);


    return newIssuerCert.release();
}


void Certificates::displayCertificate(const string &certPath)
{
    string command = "openssl x509 -in " + certPath + " -text -noout";
    int result = system(command.c_str());
}

void Certificates::displayCertificateReq(const string& reqPath) {
    string command = "openssl req -in " + reqPath + " -text -noout";
    int result = system(command.c_str());
}
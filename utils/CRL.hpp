#pragma once

#include <iostream>
#include <fstream>
#include <ctime>
#include <limits> 

#include <openssl/x509.h> 
#include <openssl/x509v3.h>      
#include <openssl/pem.h>        
#include <openssl/bio.h>        
#include <openssl/err.h>

#include "../db/database.h"

#define ROOT_CRL "../CA/root-ca/crl"
#define ISSUER_CRL "../CA/issuing-ca/crl"
#define ISSUER_CRL_FILE "../CA/issuing-ca/crl/issuer_crl.pem"
#define ROOT_CRL_FILE "../CA/root-ca/crl/root_crl.pem"

#define CRL_UPDATE_TIME 30 // период обновления crl (дней)

using namespace std;

enum RevocationReason {
    KeyCompromise = 0,
    CACompromise = 1,
    AffiliationChanged = 2,
    Superseded = 3,
    CessationOfOperation = 4,
    CertificateHold = 5,
    RemoveFromCRL = 6,
    PrivilegeWithdrawn = 7,
    AccessDenied = 8
};

class CRL {
private:
    int __getRevocationReason();
public:
    CRL(const string& crlPath, EVP_PKEY *privateKey, X509 *emitetCert) {
        createCRL(crlPath, privateKey, emitetCert);
    }

    void createCRL(const string& crlPath, EVP_PKEY *privateKey, X509 *emitetCert);
    void regenerateCRL(const string &crlPath, EVP_PKEY *privateKey);
    void addRevokedCertificate(const string &crlPath, X509* revokedCert, EVP_PKEY *privateKey, Database& db);
    static void displayCRList(const string& crlPath);
};


int CRL::__getRevocationReason() {
    int reasonCode;
    while (true) {
        cout << "Выберите причину отзыва сертификата:" << endl;
        cout << "0 - KeyCompromise (Компрометация ключа)" << endl;
        cout << "1 - CACompromise (Компрометация CA)" << endl;
        cout << "2 - AffiliationChanged (Изменение аффилиации)" << endl;
        cout << "3 - Superseded (Заменён новым сертификатом)" << endl;
        cout << "4 - CessationOfOperation (Прекращение деятельности)" << endl;
        cout << "5 - CertificateHold (Приостановка)" << endl;
        cout << "6 - RemoveFromCRL (Удалить из CRL)" << endl;
        cout << "7 - PrivilegeWithdrawn (Отзыв привилегий)" << endl;
        cout << "8 - AccessDenied (Доступ запрещен)" << endl;
        cout << "Введите код причины: ";
        
        cin >> reasonCode;

        if (cin.fail() || reasonCode < 0 || reasonCode > 8) {
            cin.clear(); 
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
            cerr << "Неверный ввод. Пожалуйста, введите число от 0 до 8." << endl;
        } else {
            return reasonCode; 
        }
    }
}


void CRL::createCRL(const string& crlPath, EVP_PKEY *privateKey, X509 *emitetCert) {
    X509_CRL *crl = X509_CRL_new();
    if (!crl) {
        cerr << "Failed to create CRL object." << endl;
    }

    X509_CRL_set_version(crl, 2);

    // Устанавливаем эмитента
    X509_NAME *issuerName = X509_get_subject_name(emitetCert);
    X509_CRL_set_issuer_name(crl, issuerName);

    // Устанавливаем время создания и обновления
    ASN1_TIME *now = ASN1_TIME_new();
    ASN1_TIME_set(now, time(nullptr));
    X509_CRL_set_lastUpdate(crl, now);

    ASN1_TIME *nextUpdate = ASN1_TIME_new();
    ASN1_TIME_adj(nextUpdate, time(nullptr), CRL_UPDATE_TIME, 0); 
    X509_CRL_set_nextUpdate(crl, nextUpdate);

    // Подписываем CRL
    if (!X509_CRL_sign(crl, privateKey, EVP_sha256())) {
        cerr << "Failed to sign CRL." << endl;
        X509_CRL_free(crl);
    }

    // Сохраняем CRL в файл
    FILE *file = fopen(crlPath.c_str(), "wb");
    if (!file || !PEM_write_X509_CRL(file, crl)) {
        cerr << "Failed to write CRL to file." << endl;
        fclose(file);
        X509_CRL_free(crl);
    }

    cout << "CRL успешно создан.\n";

    fclose(file);
    X509_CRL_free(crl);
}


void CRL::regenerateCRL(const string &crlPath, EVP_PKEY *privateKey) {
    FILE *file = fopen(crlPath.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open CRL file." << endl;
    }

    X509_CRL *crl = PEM_read_X509_CRL(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!crl) {
        cerr << "Failed to read CRL." << endl;
    }

    // Обновляем время
    ASN1_TIME *now = ASN1_TIME_new();
    ASN1_TIME_set(now, time(nullptr));
    X509_CRL_set_lastUpdate(crl, now);

    ASN1_TIME *nextUpdate = ASN1_TIME_new();
    ASN1_TIME_adj(nextUpdate, time(nullptr), CRL_UPDATE_TIME, 0);
    X509_CRL_set_nextUpdate(crl, nextUpdate);

    // Подписываем CRL заново
    if (!X509_CRL_sign(crl, privateKey, EVP_sha256())) {
        cerr << "Failed to re-sign CRL." << endl;
        X509_CRL_free(crl);
    }

    // Сохраняем обновлённый CRL
    file = fopen(crlPath.c_str(), "wb");
    if (!file || !PEM_write_X509_CRL(file, crl)) {
        cerr << "Failed to write CRL to file." << endl;
        fclose(file);
        X509_CRL_free(crl);
    }

    fclose(file);
    X509_CRL_free(crl);
}


void CRL::addRevokedCertificate(const string &crlPath, X509* revokedCert, EVP_PKEY *privateKey, Database& db) {
    FILE *file = fopen(crlPath.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open CRL file." << endl;
    }

    X509_CRL *crl = PEM_read_X509_CRL(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!crl) {
        cerr << "Failed to read CRL." << endl;
    }

    // Создаём новую запись
    X509_REVOKED *revoked = X509_REVOKED_new();
    if (!revoked) {
        cerr << "Failed to create revoked entry." << endl;
        X509_CRL_free(crl);
    }


    // Устанавливаем серийный номер
    const ASN1_INTEGER* serial = X509_get_serialNumber(revokedCert);
    BIGNUM* serialBN = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serialStr = BN_bn2dec(serialBN);

    ASN1_INTEGER *asn1Serial = s2i_ASN1_INTEGER(nullptr, serialStr);
    X509_REVOKED_set_serialNumber(revoked, asn1Serial);

    // Устанавливаем дату отзыва на сегодняшнюю дату
    ASN1_TIME *revocationDate = ASN1_TIME_new();
    time_t currentTime = time(nullptr); 
    ASN1_TIME_set(revocationDate, currentTime); 
    X509_REVOKED_set_revocationDate(revoked, revocationDate); 

    // Устанавливаем причину отзыва
    int reasonCode = __getRevocationReason();

    if (reasonCode >= 0) {
        ASN1_ENUMERATED *reason = ASN1_ENUMERATED_new();
        ASN1_ENUMERATED_set(reason, reasonCode);
        X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, reason, 0, 0);
        ASN1_ENUMERATED_free(reason);
    }

    // Добавляем запись в CRL
    X509_CRL_add0_revoked(crl, revoked);

    regenerateCRL(crlPath, privateKey);

    fclose(file);
    X509_CRL_free(crl);
    cout << "Сертификат " + string(serialStr) + " был отозван.\n";

    try {
        db.revokeIssuerCert(serialStr);
    } catch (const std::runtime_error& e) {
        cerr << "Error executing query to update certificate status: " << e.what() << endl;
    }
}

void CRL::displayCRList(const string& crlPath) {
    std::string command = "openssl crl -in " + crlPath + " -text -noout";
    int result = system(command.c_str());
}

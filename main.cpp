#include <iostream>

#include "./db/database.h"
#include "./utils/Menu.hpp"
#include "./utils/Keys.hpp"
#include "./utils/Certificates.hpp"
#include "./utils/CRL.hpp"


int main() {
    try {
        Menu menu;
        Database db(DB_PATH, "1234");
        Keys keys;
        Certificates certificates;

        // CRL root_crl(ROOT_CRL_FILE, root_key, root_cert);
        // CRL issuer_crl(ISSUER_CRL_FILE, issuer_key, issuer_cert);

        
        // EVP_PKEY* root_key = generateKey(std::string(ROOT_PRIVATE_KEY_PATH));
        // EVP_PKEY* issuer_key = generateKey(std::string(ISSUER_PRIVATE_KEY_PATH));
        // X509* root_cert = generateRootCertificate(db, root_key);
        // EVP_PKEY* root_key = readExistingKeyFromPath("/Users/sukhon/Documents/work/PKI/CA/root-ca/private/root.key.pem");
        // X509* cert = generateRootCertificate(db, root_key);
        // EVP_PKEY* issuer_key = readExistingKeyFromPath("/Users/sukhon/Documents/work/PKI/CA/issuing-ca/private/issuer.key.pem");
        // auto [req, reqFilename] = generetaIssuerCSR(db, issuer_key);
        // X509* root_cert = readExistingX509FromPath("/Users/sukhon/Documents/work/PKI/CA/root-ca/certs/root30RUorgname.cert.pem");
        // auto [req, reqFilename] = readExistingX509_ReqFromPath("/Users/sukhon/Documents/work/PKI/CA/issuing-ca/csr/req2.csr.pem");
        // X509* issuer_cert = signIssuerReqCSR(req, reqFilename, root_cert, root_key, db);
        // X509* issuer_cert = readExistingX509FromPath("/Users/sukhon/Documents/work/PKI/CA/issuing-ca/certs/req2.cert.pem");

        // createCRL(ISSUER_CRL_FILE, issuer_key, issuer_cert);
        // addRevokedCertificate(ISSUER_CRL_FILE, issuer_cert, issuer_key, db);
        

        // db.clear();
        
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }
}

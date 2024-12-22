#include "database.h"

Database::Database(const std::string& dbFileName, const std::string& password)
    : db(nullptr), dbFileName(dbFileName), password(password)
{
    this->open();
    this->initializeSchema();
}

Database::~Database() {
    this->close();
}

void Database::checkError(int resultCode, const std::string& errorMessage) {
    if (resultCode != SQLITE_OK) {
        throw std::runtime_error(errorMessage + ": " + sqlite3_errmsg(db));
    }
}

void Database::open() {
    int resultCode = sqlite3_open(dbFileName.c_str(), &db);
    checkError(resultCode, "Не удалось открыть базу данных");

// #ifdef SQLITE_HAS_CODEC
//     resultCode = sqlite3_key(db, password.c_str(), password.size());
//     checkError(resultCode, "Не удалось установить ключ шифрования");
// #endif

    std::cout << "База данных успешно открыта.\n";
}

void Database::close() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
        std::cout << "База данных закрыта.\n";
    }
}

void Database::clear()
{
    std::vector<std::string> tables = {
        "root_certs",
        "issuing_csr",
        "issuing_certs"
    };

    for (const auto& table : tables) {
        std::string query = "DELETE FROM " + table;
        executeQuery(query);
    }

    executeQuery("DELETE FROM sqlite_sequence WHERE name IN ('root_certs', 'issuing_csr', 'issuing_certs');");

    std::cout << "База данных успешно очищена.\n";
}


void Database::executeQuery(const std::string& query) {
    char* errorMessage = nullptr;
    int resultCode = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errorMessage);

    if (resultCode != SQLITE_OK) {
        std::string errorStr = errorMessage;
        sqlite3_free(errorMessage);
        throw std::runtime_error("Ошибка выполнения SQL-запроса: " + errorStr);
    }
}


void Database::initializeSchema()
{
    std::ifstream file(DB_SCHEMA);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл: " << DB_SCHEMA << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    
    executeQuery(buffer.str());
}


void Database::addRootCert(const std::string &certName, const std::string& serial, const std::string &info, int validity)
{
    if (certName.empty() || serial.empty() || info.empty() || validity <= 0) {
        throw std::runtime_error("addRootCert: ошибка: все поля должны быть заполнены.");
    }

    const std::string sql = "INSERT INTO root_certs (certName, serial, info, validity) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_bind_text(stmt, 1, certName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, serial.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, info.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, std::to_string(validity).c_str(), -1, SQLITE_STATIC);  


    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
    std::cout << "Сертификат " + certName + " успешно добавлен в таблицу root_certs.\n";
}


void Database::addIsuuerCSR(const std::string &csrName, const std::string& info)
{
    if (csrName.empty() || info.empty()) {
        throw std::runtime_error("addIsuuerCSR: ошибка: все поля должны быть заполнены.");
    }

    const std::string sql = "INSERT INTO issuing_csr (csrName, info) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_bind_text(stmt, 1, csrName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, info.c_str(), -1, SQLITE_STATIC);  

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
    std::cout << "Запрос " + csrName + " успешно добавлен в таблицу issuing_csr.\n";
}


void Database::addIssuerCert(const std::string &certName, const std::string &serial, const std::string &certDataFrom, const std::string &certDataTo, const std::string &info)
{
    if (certName.empty() || serial.empty() || certDataFrom.empty() || certDataTo.empty() || info.empty()) {
        throw std::runtime_error("addIssuerCert: ошибка: все поля должны быть заполнены.");
    }

    const std::string sql = "INSERT INTO issuing_certs (certName, serial, certDataFrom, certDataTo, info) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_bind_text(stmt, 1, certName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, serial.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, certDataFrom.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, certDataTo.c_str(), -1, SQLITE_STATIC);  
    sqlite3_bind_text(stmt, 5, info.c_str(), -1, SQLITE_STATIC);  

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
    std::cout << "Сертификат " + certName + " успешно добавлен в таблицу issuing_certs.\n";
}


void Database::revokeIssuerCert(const std::string &serial)
{
    std::string sql = "UPDATE issuing_certs SET status = 'revoked' WHERE serial = ?";
    sqlite3_stmt *stmt;
    
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare SQL query: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_bind_text(stmt, 1, serial.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind serial number: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute SQL query: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
    std::cout << "Статуст сертификата с серийным номером " + serial + " был изменен на revoked.\n";
}

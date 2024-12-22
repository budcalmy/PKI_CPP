-- Таблица для корневых сертификатов
CREATE TABLE IF NOT EXISTS root_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certName TEXT NOT NULL,
    serial TEXT NOT NULL,
    info TEXT NOT NULL,
    validity INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')) -- нужно добавить триггер для автоматического обновления статуса если срок истек
);

-- Таблица для запросов на сертификаты
CREATE TABLE IF NOT EXISTS issuing_csr (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    csrName TEXT NOT NULL,
    info TEXT NOT NULL
);

-- Таблица для сертификатов, выданных эмитентом
CREATE TABLE IF NOT EXISTS issuing_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certName TEXT NOT NULL,
    serial TEXT NOT NULL,
    certDataFrom DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    certDataTo DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    info TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked'))
);

-- Триггер для обновления статуса после вставки
CREATE TRIGGER IF NOT EXISTS update_cert_status_after_insert
AFTER INSERT ON issuing_certs
FOR EACH ROW
BEGIN
    UPDATE issuing_certs
    SET status = CASE
        WHEN certDataTo < CURRENT_TIMESTAMP THEN 'revoked'
        ELSE 'active'
    END
    WHERE id = NEW.id;
END;

-- Триггер для обновления статуса после обновления
CREATE TRIGGER IF NOT EXISTS update_cert_status_after_update
AFTER UPDATE ON issuing_certs
FOR EACH ROW
BEGIN
    UPDATE issuing_certs
    SET status = CASE
        WHEN certDataTo < CURRENT_TIMESTAMP THEN 'revoked'
        ELSE 'active'
    END
    WHERE id = NEW.id;
END;
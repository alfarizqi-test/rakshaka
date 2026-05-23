CREATE TABLE IF NOT EXISTS users (
    id          VARCHAR(36) PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role        ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id          VARCHAR(36) PRIMARY KEY,
    user_id     VARCHAR(36) NOT NULL,
    title       VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category    ENUM('scam', 'phishing', 'judol') NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_images (
    id          VARCHAR(36) PRIMARY KEY,
    report_id   VARCHAR(36) NOT NULL,
    image_url   TEXT NOT NULL,
    CONSTRAINT fk_images_report FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

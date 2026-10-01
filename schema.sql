PRAGMA foreign_keys = ON;

-- ==========================================
-- USERS
-- ==========================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    verified INTEGER NOT NULL DEFAULT 0,
    balance INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- ==========================================
-- SESSIONS
-- ==========================================

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- ==========================================
-- PRODUCTS
-- ==========================================

CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    seller_id TEXT NOT NULL,
    title TEXT NOT NULL,
    game TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,

    FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CHECK (price > 0),
    CHECK (active IN (0, 1))
);

-- ==========================================
-- TRANSACTIONS
-- ==========================================

CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,

    buyer_id TEXT NOT NULL,
    seller_id TEXT NOT NULL,
    product_id TEXT NOT NULL,

    title TEXT NOT NULL,

    price INTEGER NOT NULL,
    fee INTEGER NOT NULL,
    total INTEGER NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'waiting_payment',

    created_at INTEGER NOT NULL,

    FOREIGN KEY (buyer_id)
        REFERENCES users(id),

    FOREIGN KEY (seller_id)
        REFERENCES users(id),

    FOREIGN KEY (product_id)
        REFERENCES products(id),

    CHECK (price > 0),
    CHECK (fee >= 0),
    CHECK (total >= price)
);

-- ==========================================
-- MESSAGES
-- ==========================================

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,

    room_id TEXT NOT NULL,
    uid TEXT NOT NULL,

    name TEXT NOT NULL,
    role TEXT NOT NULL,

    text TEXT NOT NULL,

    created_at INTEGER NOT NULL,

    FOREIGN KEY (uid)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- ==========================================
-- DELIVERIES
-- ==========================================

CREATE TABLE IF NOT EXISTS deliveries (
    transaction_id TEXT PRIMARY KEY,

    email TEXT NOT NULL,
    password_cipher TEXT NOT NULL,

    created_at INTEGER NOT NULL,

    FOREIGN KEY (transaction_id)
        REFERENCES transactions(id)
        ON DELETE CASCADE
);

-- ==========================================
-- WITHDRAWALS
-- ==========================================

CREATE TABLE IF NOT EXISTS withdrawals (
    id TEXT PRIMARY KEY,

    seller_id TEXT NOT NULL,

    amount INTEGER NOT NULL,

    method TEXT NOT NULL,
    destination TEXT NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'requested',

    created_at INTEGER NOT NULL,

    FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CHECK (amount > 0)
);

-- ==========================================
-- INDEXES
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);

CREATE INDEX IF NOT EXISTS idx_sessions_user
ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expiry
ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_products_seller
ON products(seller_id);

CREATE INDEX IF NOT EXISTS idx_products_game
ON products(game);

CREATE INDEX IF NOT EXISTS idx_products_active
ON products(active);

CREATE INDEX IF NOT EXISTS idx_transactions_buyer
ON transactions(buyer_id);

CREATE INDEX IF NOT EXISTS idx_transactions_seller
ON transactions(seller_id);

CREATE INDEX IF NOT EXISTS idx_transactions_product
ON transactions(product_id);

CREATE INDEX IF NOT EXISTS idx_transactions_status
ON transactions(status);

CREATE INDEX IF NOT EXISTS idx_messages_room
ON messages(room_id);

CREATE INDEX IF NOT EXISTS idx_messages_user
ON messages(uid);

CREATE INDEX IF NOT EXISTS idx_withdrawals_seller
ON withdrawals(seller_id);

CREATE INDEX IF NOT EXISTS idx_withdrawals_status
ON withdrawals(status);

-- Email breach monitoring (G11). Users opt in per email address after
-- confirming it with a code sent to that address; the server checks the
-- confirmed addresses against Have I Been Pwned with the operator's API key
-- and mails new breaches. Only the address and the breach list are stored,
-- never passwords. Portable SQL (SQLite and PostgreSQL): Unix milliseconds
-- for times (0 = not set), BIGINT for numbers and flags.
-- See docs/architecture/security-analysis.md.

CREATE TABLE breach_monitor_emails (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- Lower case.
    email TEXT NOT NULL,
    -- 0 until the address is confirmed.
    verified_at BIGINT NOT NULL,
    -- SHA-256 (hex) of the pending confirmation code, '' when none.
    code_hash TEXT NOT NULL,
    code_expires_at BIGINT NOT NULL,
    code_attempts BIGINT NOT NULL,
    -- When the last confirmation mail was sent (resend limit).
    code_sent_at BIGINT NOT NULL,
    -- Last successful check (0 = never) and the last error, if any.
    checked_at BIGINT NOT NULL,
    check_error TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (account_id, email)
);

CREATE INDEX breach_monitor_emails_due ON breach_monitor_emails (verified_at, checked_at);

-- Breaches a confirmed address was found in (Have I Been Pwned "breach
-- model"). `data_classes` is a JSON array of strings. `first_seen_at` is when
-- this server first saw the address in the breach; new rows after the first
-- check are mailed to the user.
CREATE TABLE breach_monitor_results (
    email_id TEXT NOT NULL REFERENCES breach_monitor_emails (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    domain TEXT NOT NULL,
    breach_date TEXT NOT NULL,
    added_date TEXT NOT NULL,
    pwn_count BIGINT NOT NULL,
    data_classes TEXT NOT NULL,
    first_seen_at BIGINT NOT NULL,
    PRIMARY KEY (email_id, name)
);

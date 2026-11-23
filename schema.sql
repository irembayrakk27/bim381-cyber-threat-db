BEGIN;

CREATE TABLE CVE (
    cve_id VARCHAR(30) PRIMARY KEY,
    description TEXT NOT NULL,
    published_date DATE NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL
        CHECK (cvss_score BETWEEN 0 AND 10)
);

CREATE TABLE CWE (
    cwe_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE VENDOR (
    vendor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    website TEXT
);

CREATE TABLE USER_ACCOUNT (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL
        CHECK (role IN ('Admin', 'Analyst', 'IT'))
);

CREATE TABLE OWNER (
    owner_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_type VARCHAR(20) NOT NULL
        CHECK (owner_type IN ('DEPARTMENT', 'SUPPLIER'))
);

CREATE TABLE PRODUCT (
    product_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    vendor_id BIGINT NOT NULL REFERENCES VENDOR(vendor_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE PRODUCT_VERSION (
    product_id BIGINT NOT NULL REFERENCES PRODUCT(product_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    version_number VARCHAR(100) NOT NULL,
    release_date DATE NOT NULL,
    PRIMARY KEY (product_id, version_number)
);

CREATE TABLE PATCH (
    patch_id VARCHAR(100) PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL REFERENCES CVE(cve_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    release_date DATE NOT NULL
);

CREATE TABLE ASSET (
    asset_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    building VARCHAR(100) NOT NULL,
    floor VARCHAR(20) NOT NULL,
    room VARCHAR(50) NOT NULL,
    owner_id BIGINT NOT NULL REFERENCES OWNER(owner_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE SERVER (
    asset_id BIGINT PRIMARY KEY REFERENCES ASSET(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    operating_system VARCHAR(100) NOT NULL,
    server_role VARCHAR(100) NOT NULL
);

CREATE TABLE ENDPOINT (
    asset_id BIGINT PRIMARY KEY REFERENCES ASSET(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    username VARCHAR(150) NOT NULL
);

CREATE TABLE CLOUD (
    asset_id BIGINT PRIMARY KEY REFERENCES ASSET(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    provider VARCHAR(100) NOT NULL,
    region VARCHAR(100) NOT NULL
);

CREATE TABLE DEPARTMENT (
    owner_id BIGINT PRIMARY KEY REFERENCES OWNER(owner_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE SUPPLIER (
    owner_id BIGINT PRIMARY KEY REFERENCES OWNER(owner_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE CVE_REFERENCE (
    cve_id VARCHAR(30) NOT NULL REFERENCES CVE(cve_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    reference_url TEXT NOT NULL,
    PRIMARY KEY (cve_id, reference_url)
);

CREATE TABLE CVE_CWE (
    cve_id VARCHAR(30) NOT NULL REFERENCES CVE(cve_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    cwe_id VARCHAR(20) NOT NULL REFERENCES CWE(cwe_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    PRIMARY KEY (cve_id, cwe_id)
);

CREATE TABLE CVE_PRODUCT_VERSION (
    cve_id VARCHAR(30) NOT NULL REFERENCES CVE(cve_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    product_id BIGINT NOT NULL,
    version_number VARCHAR(100) NOT NULL,
    PRIMARY KEY (cve_id, product_id, version_number),
    FOREIGN KEY (product_id, version_number)
        REFERENCES PRODUCT_VERSION(product_id, version_number)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE ASSET_PRODUCT_VERSION (
    asset_id BIGINT NOT NULL REFERENCES ASSET(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    product_id BIGINT NOT NULL,
    version_number VARCHAR(100) NOT NULL,
    install_date DATE NOT NULL,
    PRIMARY KEY (asset_id, product_id, version_number),
    FOREIGN KEY (product_id, version_number)
        REFERENCES PRODUCT_VERSION(product_id, version_number)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE PATCH_APPLICATION (
    application_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES ASSET(asset_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    patch_id VARCHAR(100) NOT NULL REFERENCES PATCH(patch_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    applied_date DATE NOT NULL,
    UNIQUE (asset_id, patch_id)
);

CREATE TABLE AUDIT_LOG (
    audit_log_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_id BIGINT NOT NULL UNIQUE
        REFERENCES PATCH_APPLICATION(application_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL
);

CREATE TABLE ANALYST_REVIEW (
    user_id BIGINT NOT NULL REFERENCES USER_ACCOUNT(user_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    asset_id BIGINT NOT NULL REFERENCES ASSET(asset_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    cve_id VARCHAR(30) NOT NULL REFERENCES CVE(cve_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    review_status VARCHAR(50) NOT NULL
        CHECK (review_status IN ('Open', 'In_Review', 'Closed')),
    review_date DATE NOT NULL,
    PRIMARY KEY (user_id, asset_id, cve_id)
);

-- BR-02: Validate patch application date.
CREATE FUNCTION check_patch_application_date()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.applied_date < (
        SELECT release_date FROM PATCH
        WHERE patch_id = NEW.patch_id
    ) THEN
        RAISE EXCEPTION 'Application date cannot precede patch release date';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_patch_application_date
BEFORE INSERT OR UPDATE ON PATCH_APPLICATION
FOR EACH ROW EXECUTE FUNCTION check_patch_application_date();

-- BR-09: Validate affected product version.
CREATE FUNCTION check_patch_asset_version()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM PATCH p
        JOIN CVE_PRODUCT_VERSION cpv ON cpv.cve_id = p.cve_id
        JOIN ASSET_PRODUCT_VERSION apv
          ON apv.product_id = cpv.product_id
         AND apv.version_number = cpv.version_number
        WHERE p.patch_id = NEW.patch_id
          AND apv.asset_id = NEW.asset_id
    ) THEN
        RAISE EXCEPTION 'Asset does not use a product version affected by this CVE';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_patch_asset_version
BEFORE INSERT OR UPDATE ON PATCH_APPLICATION
FOR EACH ROW EXECUTE FUNCTION check_patch_asset_version();

-- BR-06: Automatically create an audit record.
CREATE FUNCTION create_patch_audit_log()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO AUDIT_LOG (application_id, created_at, event_type)
    VALUES (NEW.application_id, CURRENT_TIMESTAMP, 'PATCH_APPLIED');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_create_patch_audit_log
AFTER INSERT ON PATCH_APPLICATION
FOR EACH ROW EXECUTE FUNCTION create_patch_audit_log();

-- BR-10: Only analysts can create reviews.
CREATE FUNCTION check_analyst_role()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM USER_ACCOUNT
        WHERE user_id = NEW.user_id AND role = 'Analyst'
    ) THEN
        RAISE EXCEPTION 'Only users with Analyst role can create reviews';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_analyst_role
BEFORE INSERT OR UPDATE ON ANALYST_REVIEW
FOR EACH ROW EXECUTE FUNCTION check_analyst_role();

COMMIT;

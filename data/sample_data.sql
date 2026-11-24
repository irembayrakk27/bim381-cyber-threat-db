-- Synthetic sample data for the Cyber Threat Intelligence and
-- Vulnerability Management System.
-- These records are for academic testing and do not represent
-- real CVEs, products, organizations, or security advisories.

BEGIN;

DO $$
DECLARE
    v_vendor1 BIGINT;
    v_vendor2 BIGINT;
    v_vendor3 BIGINT;

    v_product1 BIGINT;
    v_product2 BIGINT;
    v_product3 BIGINT;

    v_owner1 BIGINT;
    v_owner2 BIGINT;
    v_owner3 BIGINT;

    v_asset1 BIGINT;
    v_asset2 BIGINT;
    v_asset3 BIGINT;

    v_user1 BIGINT;
    v_user2 BIGINT;
    v_user3 BIGINT;
BEGIN

    -- 1. CVE records
    INSERT INTO CVE VALUES
    ('CVE-TEST-2026-0001', 'Synthetic web server vulnerability.',
     '2026-01-10', 9.1),
    ('CVE-TEST-2026-0002', 'Synthetic endpoint application vulnerability.',
     '2026-02-15', 7.5),
    ('CVE-TEST-2026-0003', 'Synthetic cloud database vulnerability.',
     '2026-03-20', 6.4);

    -- 2. CWE records
    INSERT INTO CWE VALUES
    ('CWE-TEST-001', 'Improper Input Validation',
     'Synthetic weakness related to input validation.'),
    ('CWE-TEST-002', 'Improper Access Control',
     'Synthetic weakness related to access control.'),
    ('CWE-TEST-003', 'Information Exposure',
     'Synthetic weakness related to information exposure.');

    -- 3. Vendors
    INSERT INTO VENDOR (name, website)
    VALUES ('Example Systems', 'https://example.invalid/systems')
    RETURNING vendor_id INTO v_vendor1;

    INSERT INTO VENDOR (name, website)
    VALUES ('Example Security', 'https://example.invalid/security')
    RETURNING vendor_id INTO v_vendor2;

    INSERT INTO VENDOR (name, website)
    VALUES ('Example Cloud', NULL)
    RETURNING vendor_id INTO v_vendor3;

    -- 4. Products
    INSERT INTO PRODUCT (name, vendor_id)
    VALUES ('Example Web Server', v_vendor1)
    RETURNING product_id INTO v_product1;

    INSERT INTO PRODUCT (name, vendor_id)
    VALUES ('Example Endpoint Agent', v_vendor2)
    RETURNING product_id INTO v_product2;

    INSERT INTO PRODUCT (name, vendor_id)
    VALUES ('Example Cloud Database', v_vendor3)
    RETURNING product_id INTO v_product3;

    -- 5. Product versions
    INSERT INTO PRODUCT_VERSION VALUES
    (v_product1, '1.0', '2025-06-01'),
    (v_product1, '1.1', '2025-12-01'),
    (v_product2, '3.0', '2025-07-01'),
    (v_product2, '3.1', '2025-12-15'),
    (v_product3, '5.0', '2025-08-01'),
    (v_product3, '5.1', '2026-01-01');

    -- 6. CVE-CWE relationships
    INSERT INTO CVE_CWE VALUES
    ('CVE-TEST-2026-0001', 'CWE-TEST-001'),
    ('CVE-TEST-2026-0002', 'CWE-TEST-002'),
    ('CVE-TEST-2026-0003', 'CWE-TEST-003');

    -- 7. CVE references
    INSERT INTO CVE_REFERENCE VALUES
    ('CVE-TEST-2026-0001', 'https://example.invalid/advisories/test-001'),
    ('CVE-TEST-2026-0002', 'https://example.invalid/advisories/test-002'),
    ('CVE-TEST-2026-0003', 'https://example.invalid/advisories/test-003');

    -- 8. Affected product versions
    INSERT INTO CVE_PRODUCT_VERSION VALUES
    ('CVE-TEST-2026-0001', v_product1, '1.0'),
    ('CVE-TEST-2026-0001', v_product1, '1.1'),
    ('CVE-TEST-2026-0002', v_product2, '3.0'),
    ('CVE-TEST-2026-0002', v_product2, '3.1'),
    ('CVE-TEST-2026-0003', v_product3, '5.0');

    -- 9. Owners
    INSERT INTO OWNER (owner_type)
    VALUES ('DEPARTMENT')
    RETURNING owner_id INTO v_owner1;

    INSERT INTO OWNER (owner_type)
    VALUES ('DEPARTMENT')
    RETURNING owner_id INTO v_owner2;

    INSERT INTO OWNER (owner_type)
    VALUES ('SUPPLIER')
    RETURNING owner_id INTO v_owner3;

    INSERT INTO DEPARTMENT VALUES
    (v_owner1, 'Information Technology'),
    (v_owner2, 'Security Operations');

    INSERT INTO SUPPLIER VALUES
    (v_owner3, 'Example Cloud Services');

    -- 10. Assets
    INSERT INTO ASSET
        (asset_name, building, floor, room, owner_id)
    VALUES
        ('WEB-SRV-01', 'Main Building', '2', '201', v_owner1)
    RETURNING asset_id INTO v_asset1;

    INSERT INTO ASSET
        (asset_name, building, floor, room, owner_id)
    VALUES
        ('ENDPOINT-01', 'Main Building', '1', '105', v_owner2)
    RETURNING asset_id INTO v_asset2;

    INSERT INTO ASSET
        (asset_name, building, floor, room, owner_id)
    VALUES
        ('CLOUD-DB-01', 'Cloud Environment', 'N/A', 'N/A', v_owner3)
    RETURNING asset_id INTO v_asset3;

    INSERT INTO SERVER VALUES
    (v_asset1, 'Ubuntu Server 24.04', 'Web Server');

    INSERT INTO ENDPOINT VALUES
    (v_asset2, 'sample.user');

    INSERT INTO CLOUD VALUES
    (v_asset3, 'Example Cloud', 'eu-central-1');

    -- 11. Installed product versions
    INSERT INTO ASSET_PRODUCT_VERSION VALUES
    (v_asset1, v_product1, '1.0', '2025-09-01'),
    (v_asset2, v_product2, '3.0', '2025-10-01'),
    (v_asset3, v_product3, '5.0', '2026-02-01');

    -- 12. Patches
    INSERT INTO PATCH VALUES
    ('PATCH-TEST-001', 'CVE-TEST-2026-0001', '2026-01-15'),
    ('PATCH-TEST-002', 'CVE-TEST-2026-0002', '2026-02-20');

    -- 13. Patch applications
    -- Both applications satisfy BR-02 and BR-09.
    INSERT INTO PATCH_APPLICATION
        (asset_id, patch_id, applied_date)
    VALUES
        (v_asset1, 'PATCH-TEST-001', '2026-01-20'),
        (v_asset2, 'PATCH-TEST-002', '2026-02-25');

    -- AUDIT_LOG records are generated automatically by BR-06.

    -- 14. Users
    INSERT INTO USER_ACCOUNT (name, email, role)
    VALUES ('Analyst One', 'analyst1@example.invalid', 'Analyst')
    RETURNING user_id INTO v_user1;

    INSERT INTO USER_ACCOUNT (name, email, role)
    VALUES ('Analyst Two', 'analyst2@example.invalid', 'Analyst')
    RETURNING user_id INTO v_user2;

    INSERT INTO USER_ACCOUNT (name, email, role)
    VALUES ('IT User', 'ituser@example.invalid', 'IT')
    RETURNING user_id INTO v_user3;

    -- 15. Analyst reviews
    INSERT INTO ANALYST_REVIEW
        (user_id, asset_id, cve_id, review_status, review_date)
    VALUES
        (v_user1, v_asset1, 'CVE-TEST-2026-0001', 'Closed', '2026-01-25'),
        (v_user1, v_asset2, 'CVE-TEST-2026-0002', 'In_Review', '2026-02-26'),
        (v_user2, v_asset3, 'CVE-TEST-2026-0003', 'Open', '2026-03-25');

END $$;

COMMIT;

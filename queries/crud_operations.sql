-- =========================================================
-- FR-14: ANALYST REVIEW OPERATIONS
-- =========================================================

-- List analyst reviews.
SELECT
    u.name AS analyst_name,
    a.asset_name,
    ar.cve_id,
    ar.review_status,
    ar.review_date
FROM ANALYST_REVIEW ar
JOIN USER_ACCOUNT u ON ar.user_id = u.user_id
JOIN ASSET a ON ar.asset_id = a.asset_id
ORDER BY ar.review_date DESC;


-- =========================================================
-- FR-15: USER CRUD OPERATIONS
-- =========================================================

BEGIN;

-- CREATE
INSERT INTO USER_ACCOUNT (name, email, role)
VALUES ('CRUD Test User', 'crud.test@example.invalid', 'Admin');

-- READ
SELECT user_id, name, email, role
FROM USER_ACCOUNT
WHERE email = 'crud.test@example.invalid';

-- UPDATE
UPDATE USER_ACCOUNT
SET name = 'Updated CRUD Test User'
WHERE email = 'crud.test@example.invalid';

-- READ updated record
SELECT user_id, name, email, role
FROM USER_ACCOUNT
WHERE email = 'crud.test@example.invalid';

-- DELETE
DELETE FROM USER_ACCOUNT
WHERE email = 'crud.test@example.invalid';

-- Verify deletion
SELECT *
FROM USER_ACCOUNT
WHERE email = 'crud.test@example.invalid';

ROLLBACK;

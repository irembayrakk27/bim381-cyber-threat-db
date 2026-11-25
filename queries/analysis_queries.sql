-- Cyber Threat Intelligence and Vulnerability Management System
-- Academic sample queries for PostgreSQL 16.
-- All sample vulnerability records are synthetic.

-- =========================================================
-- 1. JOIN QUERIES
-- =========================================================

-- Q1: List vulnerabilities, affected products, versions,
-- vendors and assets.
SELECT
    c.cve_id,
    c.cvss_score,
    p.name AS product_name,
    pv.version_number,
    v.name AS vendor_name,
    a.asset_name
FROM CVE c
JOIN CVE_PRODUCT_VERSION cpv
    ON c.cve_id = cpv.cve_id
JOIN PRODUCT_VERSION pv
    ON cpv.product_id = pv.product_id
   AND cpv.version_number = pv.version_number
JOIN PRODUCT p
    ON pv.product_id = p.product_id
JOIN VENDOR v
    ON p.vendor_id = v.vendor_id
LEFT JOIN ASSET_PRODUCT_VERSION apv
    ON apv.product_id = pv.product_id
   AND apv.version_number = pv.version_number
LEFT JOIN ASSET a
    ON apv.asset_id = a.asset_id
ORDER BY c.cvss_score DESC, c.cve_id;


-- Q2: List assets with their owners and asset types.
SELECT
    a.asset_id,
    a.asset_name,
    o.owner_type,
    COALESCE(d.name, s.name) AS owner_name,
    CASE
        WHEN srv.asset_id IS NOT NULL THEN 'Server'
        WHEN ep.asset_id IS NOT NULL THEN 'Endpoint'
        WHEN cl.asset_id IS NOT NULL THEN 'Cloud'
        ELSE 'Unclassified'
    END AS asset_type
FROM ASSET a
JOIN OWNER o
    ON a.owner_id = o.owner_id
LEFT JOIN DEPARTMENT d
    ON o.owner_id = d.owner_id
LEFT JOIN SUPPLIER s
    ON o.owner_id = s.owner_id
LEFT JOIN SERVER srv
    ON a.asset_id = srv.asset_id
LEFT JOIN ENDPOINT ep
    ON a.asset_id = ep.asset_id
LEFT JOIN CLOUD cl
    ON a.asset_id = cl.asset_id
ORDER BY a.asset_id;


-- =========================================================
-- 2. GROUP BY / HAVING QUERIES
-- =========================================================

-- Q3: Count affected vulnerabilities for each product.
SELECT
    p.product_id,
    p.name AS product_name,
    COUNT(DISTINCT cpv.cve_id) AS vulnerability_count
FROM PRODUCT p
LEFT JOIN CVE_PRODUCT_VERSION cpv
    ON p.product_id = cpv.product_id
GROUP BY p.product_id, p.name
HAVING COUNT(DISTINCT cpv.cve_id) > 0
ORDER BY vulnerability_count DESC, p.name;


-- Q4: Count patch applications for each asset.
SELECT
    a.asset_id,
    a.asset_name,
    COUNT(pa.application_id) AS applied_patch_count
FROM ASSET a
LEFT JOIN PATCH_APPLICATION pa
    ON a.asset_id = pa.asset_id
GROUP BY a.asset_id, a.asset_name
ORDER BY applied_patch_count DESC, a.asset_name;


-- Q5: Find products affected by more than one CVE.
SELECT
    p.name AS product_name,
    COUNT(DISTINCT cpv.cve_id) AS vulnerability_count
FROM PRODUCT p
JOIN CVE_PRODUCT_VERSION cpv
    ON p.product_id = cpv.product_id
GROUP BY p.product_id, p.name
HAVING COUNT(DISTINCT cpv.cve_id) > 1;


-- =========================================================
-- 3. SUBQUERIES
-- =========================================================

-- Q6: Find vulnerabilities whose CVSS score is above
-- the average CVSS score.
SELECT
    cve_id,
    description,
    cvss_score
FROM CVE
WHERE cvss_score > (
    SELECT AVG(cvss_score)
    FROM CVE
)
ORDER BY cvss_score DESC;


-- Q7: Find affected assets for which no patch has been applied
-- for the corresponding vulnerability.
SELECT DISTINCT
    a.asset_id,
    a.asset_name,
    c.cve_id,
    c.cvss_score
FROM ASSET a
JOIN ASSET_PRODUCT_VERSION apv
    ON a.asset_id = apv.asset_id
JOIN CVE_PRODUCT_VERSION cpv
    ON apv.product_id = cpv.product_id
   AND apv.version_number = cpv.version_number
JOIN CVE c
    ON cpv.cve_id = c.cve_id
WHERE NOT EXISTS (
    SELECT 1
    FROM PATCH p
    JOIN PATCH_APPLICATION pa
        ON p.patch_id = pa.patch_id
    WHERE p.cve_id = c.cve_id
      AND pa.asset_id = a.asset_id
)
ORDER BY c.cvss_score DESC;


-- =========================================================
-- 4. MULTI-TABLE REPORT
-- =========================================================

-- Q8: Comprehensive vulnerability review report.
-- Includes vulnerability, asset, analyst, patch and audit data.
SELECT
    c.cve_id,
    c.cvss_score,
    a.asset_name,
    u.name AS analyst_name,
    ar.review_status,
    ar.review_date,
    p.patch_id,
    pa.applied_date,
    al.event_type,
    al.created_at AS audit_created_at
FROM ANALYST_REVIEW ar
JOIN USER_ACCOUNT u
    ON ar.user_id = u.user_id
JOIN ASSET a
    ON ar.asset_id = a.asset_id
JOIN CVE c
    ON ar.cve_id = c.cve_id
LEFT JOIN PATCH p
    ON p.cve_id = c.cve_id
LEFT JOIN PATCH_APPLICATION pa
    ON pa.patch_id = p.patch_id
   AND pa.asset_id = a.asset_id
LEFT JOIN AUDIT_LOG al
    ON al.application_id = pa.application_id
ORDER BY c.cvss_score DESC, ar.review_date DESC;


-- =========================================================
-- 5. ADDITIONAL AGGREGATION REPORT
-- =========================================================

-- Q9: Summarize vulnerabilities by severity category.
SELECT
    CASE
        WHEN cvss_score >= 9.0 THEN 'Critical'
        WHEN cvss_score >= 7.0 THEN 'High'
        WHEN cvss_score >= 4.0 THEN 'Medium'
        ELSE 'Low'
    END AS severity,
    COUNT(*) AS vulnerability_count,
    ROUND(AVG(cvss_score), 2) AS average_cvss
FROM CVE
GROUP BY
    CASE
        WHEN cvss_score >= 9.0 THEN 'Critical'
        WHEN cvss_score >= 7.0 THEN 'High'
        WHEN cvss_score >= 4.0 THEN 'Medium'
        ELSE 'Low'
    END
ORDER BY average_cvss DESC;

-- =========================================================
-- 6. FUNCTIONAL REQUIREMENT QUERIES
-- =========================================================

-- FR-10: Count affected CVEs and calculate average CVSS per product.
SELECT
    p.product_id,
    p.name AS product_name,
    COUNT(DISTINCT c.cve_id) AS vulnerability_count,
    ROUND(AVG(c.cvss_score), 2) AS average_cvss
FROM PRODUCT p
JOIN CVE_PRODUCT_VERSION cpv
    ON p.product_id = cpv.product_id
JOIN CVE c
    ON cpv.cve_id = c.cve_id
GROUP BY p.product_id, p.name
ORDER BY vulnerability_count DESC, p.name;

-- FR-11: List assets not affected by any known vulnerability.
SELECT
    a.asset_id,
    a.asset_name
FROM ASSET a
WHERE NOT EXISTS (
    SELECT 1
    FROM ASSET_PRODUCT_VERSION apv
    JOIN CVE_PRODUCT_VERSION cpv
        ON apv.product_id = cpv.product_id
       AND apv.version_number = cpv.version_number
    WHERE apv.asset_id = a.asset_id
)
ORDER BY a.asset_id;

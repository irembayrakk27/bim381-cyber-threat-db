-- Generated from the three NVD-selected CSV files.
-- Review before execution. This script is intended for one-time migration.
BEGIN;

-- Remove old synthetic relationships before replacing the CVE records.
DELETE FROM CVE_REFERENCE;
DELETE FROM CVE_CWE;
DELETE FROM CVE_PRODUCT_VERSION;
DELETE FROM CWE;

-- Replace synthetic vendor and product labels.
UPDATE VENDOR SET name = 'Apache Software Foundation', website = 'https://httpd.apache.org/' WHERE vendor_id = 1;
UPDATE VENDOR SET name = 'OpenSSL Project', website = 'https://www.openssl.org/' WHERE vendor_id = 2;
UPDATE VENDOR SET name = 'F5, Inc.', website = 'https://www.f5.com/' WHERE vendor_id = 3;
UPDATE PRODUCT SET name = 'Apache HTTP Server' WHERE product_id = 1;
UPDATE PRODUCT SET name = 'OpenSSL' WHERE product_id = 2;
UPDATE PRODUCT SET name = 'NGINX Open Source' WHERE product_id = 3;

-- Update installed product versions; dependent asset mappings cascade.
UPDATE PRODUCT_VERSION SET version_number = '2.4.59', release_date = '2024-04-04' WHERE product_id = 1 AND version_number = '1.0';
UPDATE PRODUCT_VERSION SET version_number = '3.0.15', release_date = '2024-09-03' WHERE product_id = 2 AND version_number = '3.0';
UPDATE PRODUCT_VERSION SET version_number = '1.26.1', release_date = '2024-05-29' WHERE product_id = 3 AND version_number = '5.0';

-- Remove unused synthetic product versions.
DELETE FROM PRODUCT_VERSION WHERE
    (product_id = 1 AND version_number = '1.1') OR
    (product_id = 2 AND version_number = '3.1') OR
    (product_id = 3 AND version_number = '5.1');

-- Replace the three synthetic CVEs with real CVEs.
UPDATE CVE SET cve_id = 'CVE-2024-38473', description = 'Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request URLs with incorrect encoding to be sent to backend services, potentially bypassing authentication via crafted requests.
Users are recommended to upgrade to version 2.4.60, which fixes this issue.', published_date = '2024-07-01', cvss_score = 8.1 WHERE cve_id = 'CVE-TEST-2026-0001';
UPDATE CVE SET cve_id = 'CVE-2024-9143', description = 'Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the field polynomial can lead to out-of-bounds memory reads or writes.  Impact summary: Out of bound memory writes can lead to an application crash or even a possibility of a remote code execution, however, in all the protocols involving Elliptic Curve Cryptography that we''re aware of, either only "named curves" are supported, or, if explicit curve parameters are supported, they specify an X9.62 encoding of binary (GF(2^m)) curves that can''t represent problematic input values. Thus the likelihood of existence of a vulnerable application is low.  In particular, the X9.62 encoding is used for ECC keys in X.509 certificates, so problematic inputs cannot occur in the context of processing X.509 certificates.  Any problematic use-cases would have to be using an "exotic" curve encoding.  The affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(), and various supporting BN_GF2m_*() functions.  Applications working with "exotic" explicit binary (GF(2^m)) curve parameters, that make it possible to represent invalid field polynomials with a zero constant term, via the above or similar APIs, may terminate abruptly as a result of reading or writing outside of array bounds.  Remote code execution cannot easily be ruled out.  The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.', published_date = '2024-10-16', cvss_score = 8.8 WHERE cve_id = 'CVE-TEST-2026-0002';
UPDATE CVE SET cve_id = 'CVE-2026-113425', description = 'When NGINX Plus or NGINX Open Source is configured as a mail proxy, undisclosed traffic can cause a use-after-free in an nginx worker process. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.

Impact:
A remote unauthenticated attacker may crash an nginx worker process or corrupt its memory, disrupting service. Remote code execution is a potential impact. There is no control plane exposure; this is a data plane issue only.



Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', published_date = '2026-11-18', cvss_score = 8.1 WHERE cve_id = 'CVE-TEST-2026-0003';

-- Insert the remaining 17 CVE records.
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2024-38474', 'Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to execute scripts in
directories permitted by the configuration but not directly reachable by any URL or source disclosure of scripts meant to only to be executed as CGI.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

Some RewriteRules that capture and substitute unsafely will now fail unless rewrite flag "UnsafeAllow3F" is specified.', '2024-07-01', 9.8);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2024-38475', 'Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.

Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.', '2024-07-01', 9.1);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2024-38476', 'Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications whose response headers are malicious or exploitable.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.', '2024-07-01', 9.8);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2024-38477', 'null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash the server via a malicious request.
Users are recommended to upgrade to version 2.4.60, which fixes this issue.', '2024-07-01', 7.5);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2024-39573', 'Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe RewriteRules to unexpectedly setup URL''s to be handled by mod_proxy.
Users are recommended to upgrade to version 2.4.60, which fixes this issue.', '2024-07-01', 7.5);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-15467', 'Issue summary: Parsing CMS AuthEnvelopedData or EnvelopedData message with maliciously crafted AEAD parameters can trigger a stack buffer overflow.  Impact summary: A stack buffer overflow may lead to a crash, causing Denial of Service, or potentially remote code execution.  When parsing CMS (Auth)EnvelopedData structures that use AEAD ciphers such as AES-GCM, the IV (Initialization Vector) encoded in the ASN.1 parameters is copied into a fixed-size stack buffer without verifying that its length fits the destination. An attacker can supply a crafted CMS message with an oversized IV, causing a stack-based out-of-bounds write before any authentication or tag verification occurs.  Applications and services that parse untrusted CMS or PKCS#7 content using AEAD ciphers (e.g., S/MIME (Auth)EnvelopedData with AES-GCM) are vulnerable. Because the overflow occurs prior to authentication, no valid key material is required to trigger it. While exploitability to remote code execution depends on platform and toolchain mitigations, the stack-based write primitive represents a severe risk.  The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this issue, as the CMS implementation is outside the OpenSSL FIPS module boundary.  OpenSSL 3.6, 3.5, 3.4, 3.3 and 3.0 are vulnerable to this issue.  OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.', '2026-01-27', 8.8);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-68160', 'Issue summary: Writing large, newline-free data into a BIO chain using the line-buffering filter where the next BIO performs short writes can trigger a heap-based out-of-bounds write.  Impact summary: This out-of-bounds write can cause memory corruption which typically results in a crash, leading to Denial of Service for an application.  The line-buffering BIO filter (BIO_f_linebuffer) is not used by default in TLS/SSL data paths. In OpenSSL command-line applications, it is typically only pushed onto stdout/stderr on VMS systems. Third-party applications that explicitly use this filter with a BIO chain that can short-write and that write large, newline-free data influenced by an attacker would be affected. However, the circumstances where this could happen are unlikely to be under attacker control, and BIO_f_linebuffer is unlikely to be handling non-curated data controlled by an attacker. For that reason the issue was assessed as Low severity.  The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this issue, as the BIO implementation is outside the OpenSSL FIPS module boundary.  OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0, 1.1.1 and 1.0.2 are vulnerable to this issue.', '2026-01-27', 4.7);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-69419', 'Issue summary: Calling PKCS12_get_friendlyname() function on a maliciously crafted PKCS#12 file with a BMPString (UTF-16BE) friendly name containing non-ASCII BMP code point can trigger a one byte write before the allocated buffer.  Impact summary: The out-of-bounds write can cause a memory corruption which can have various consequences including a Denial of Service.  The OPENSSL_uni2utf8() function performs a two-pass conversion of a PKCS#12 BMPString (UTF-16BE) to UTF-8. In the second pass, when emitting UTF-8 bytes, the helper function bmp_to_utf8() incorrectly forwards the remaining UTF-16 source byte count as the destination buffer capacity to UTF8_putc(). For BMP code points above U+07FF, UTF-8 requires three bytes, but the forwarded capacity can be just two bytes. UTF8_putc() then returns -1, and this negative value is added to the output length without validation, causing the length to become negative. The subsequent trailing NUL byte is then written at a negative offset, causing write outside of heap allocated buffer.  The vulnerability is reachable via the public PKCS12_get_friendlyname() API when parsing attacker-controlled PKCS#12 files. While PKCS12_parse() uses a different code path that avoids this issue, PKCS12_get_friendlyname() directly invokes the vulnerable function. Exploitation requires an attacker to provide a malicious PKCS#12 file to be parsed by the application and the attacker can just trigger a one zero byte write before the allocated buffer. For that reason the issue was assessed as Low severity according to our Security Policy.  The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this issue, as the PKCS#12 implementation is outside the OpenSSL FIPS module boundary.  OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0 and 1.1.1 are vulnerable to this issue.  OpenSSL 1.0.2 is not affected by this issue.', '2026-01-27', 7.4);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-69420', 'Issue summary: A type confusion vulnerability exists in the TimeStamp Response verification code where an ASN1_TYPE union member is accessed without first validating the type, causing an invalid or NULL pointer dereference when processing a malformed TimeStamp Response file.  Impact summary: An application calling TS_RESP_verify_response() with a malformed TimeStamp Response can be caused to dereference an invalid or NULL pointer when reading, resulting in a Denial of Service.  The functions ossl_ess_get_signing_cert() and ossl_ess_get_signing_cert_v2() access the signing cert attribute value without validating its type. When the type is not V_ASN1_SEQUENCE, this results in accessing invalid memory through the ASN1_TYPE union, causing a crash.  Exploiting this vulnerability requires an attacker to provide a malformed TimeStamp Response to an application that verifies timestamp responses. The TimeStamp protocol (RFC 3161) is not widely used and the impact of the exploit is just a Denial of Service. For these reasons the issue was assessed as Low severity.  The FIPS modules in 3.5, 3.4, 3.3 and 3.0 are not affected by this issue, as the TimeStamp Response implementation is outside the OpenSSL FIPS module boundary.  OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0 and 1.1.1 are vulnerable to this issue.  OpenSSL 1.0.2 is not affected by this issue.', '2026-01-27', 7.5);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-69421', 'Issue summary: Processing a malformed PKCS#12 file can trigger a NULL pointer dereference in the PKCS12_item_decrypt_d2i_ex() function.  Impact summary: A NULL pointer dereference can trigger a crash which leads to Denial of Service for an application processing PKCS#12 files.  The PKCS12_item_decrypt_d2i_ex() function does not check whether the oct parameter is NULL before dereferencing it. When called from PKCS12_unpack_p7encdata() with a malformed PKCS#12 file, this parameter can be NULL, causing a crash. The vulnerability is limited to Denial of Service and cannot be escalated to achieve code execution or memory disclosure.  Exploiting this issue requires an attacker to provide a malformed PKCS#12 file to an application that processes it. For that reason the issue was assessed as Low severity according to our Security Policy.  The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this issue, as the PKCS#12 implementation is outside the OpenSSL FIPS module boundary.  OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0, 1.1.1 and 1.0.2 are vulnerable to this issue.', '2026-01-27', 7.5);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2025-9230', 'Issue summary: An application trying to decrypt CMS messages encrypted using password based encryption can trigger an out-of-bounds read and write.  Impact summary: This out-of-bounds read may trigger a crash which leads to Denial of Service for an application. The out-of-bounds write can cause a memory corruption which can have various consequences including a Denial of Service or Execution of attacker-supplied code.  Although the consequences of a successful exploit of this vulnerability could be severe, the probability that the attacker would be able to perform it is low. Besides, password based (PWRI) encryption support in CMS messages is very rarely used. For that reason the issue was assessed as Moderate severity according to our Security Policy.  The FIPS modules in 3.5, 3.4, 3.3, 3.2, 3.1 and 3.0 are not affected by this issue, as the CMS implementation is outside the OpenSSL FIPS module boundary.', '2025-09-30', 9.8);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-121810', 'Description:
This issue affects NGINX Plus and NGINX Open Source configurations that use HTTP/3. A remote, unauthenticated attacker can cause a use-after-free condition in the NGINX worker process, leading to a restart. Exploitation also depends on conditions beyond the attacker’s control. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.

Impact:
This vulnerability may allow remote attackers to cause a denial-of-service (DoS) on the NGINX system or to possibly trigger a code execution. There is no control plane exposure; this is a data plane issue only.



Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-11-18', 8.1);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-123007', 'This issue affects NGINX Plus or NGINX Open Source configurations that use HTTP/2. When NGINX processes undisclosed traffic, the flow control window can exceed the allowed threshold, potentially resulting in a heap buffer overflow typically followed by an NGINX worker segmentation fault. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.

Impact: An attacker could leverage this vulnerability to crash the NGINX worker process, corrupt its memory, or potentially execute code remotely. There is no control plane exposure; this is a data plane issue only.



Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-11-18', 8.1);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-27654', 'NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_dav_module module that might allow an attacker to trigger a buffer overflow to the NGINX worker process; this vulnerability may result in termination of the NGINX worker process or modification of source or destination file names outside the document root. This issue affects NGINX Open Source and NGINX Plus when the configuration file uses DAV module MOVE or COPY methods, prefix location (nonregular expression location configuration), and alias directives. The integrity impact is constrained because the NGINX worker process user has low privileges and does not have access to the entire system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-03-24', 8.2);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-42055', 'NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_proxy_v2_module and ngx_http_grpc_module modules. This vulnerability exists when the proxy_http_version to 2 or grpc_pass directives are used to proxy HTTP/2 traffic, the ignore_invalid_headers directive is set to off, and the large_client_header_buffers directive size is larger than 2 megabytes. A remote, unauthenticated attacker, along with conditions beyond their control, could send large headers while creating an upstream request. This may cause a heap-based buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-06-17', 8.1);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-42945', 'NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-05-13', 8.1);
INSERT INTO CVE (cve_id, description, published_date, cvss_score) VALUES ('CVE-2026-60005', 'NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_slice_module module. When the slice directive and unnamed regex captures are configured or when a background cache update happens, unauthenticated attackers can send requests that may cause uninitialized memory access in the NGINX worker process, leading to limited disclosure of memory or a restart.

Impact:
This vulnerability may allow remote, unauthenticated attackers to have limited control to disclose memory contents or restart the NGINX worker process. There is no control plane exposure; this is a data plane issue only.
Note: The ngx_http_slice_module module is not enabled by default; it''s enabled with the --with-http_slice_module configuration parameter.

Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.', '2026-07-15', 8.2);

-- Add CWE classifications. Names are identifiers; descriptions link
-- to the authoritative MITRE CWE definitions.
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-116', 'CWE-116', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/116.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-120', 'CWE-120', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/120.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-122', 'CWE-122', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/122.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-125', 'CWE-125', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/125.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-131', 'CWE-131', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/131.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-191', 'CWE-191', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/191.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-20', 'CWE-20', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/20.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-416', 'CWE-416', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/416.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-476', 'CWE-476', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/476.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-754', 'CWE-754', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/754.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-787', 'CWE-787', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/787.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-829', 'CWE-829', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/829.html');
INSERT INTO CWE (cwe_id, name, description) VALUES ('CWE-908', 'CWE-908', 'NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/908.html');

-- Link CVEs to CWE classifications.
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-38473', 'CWE-116');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-38474', 'CWE-116');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-38475', 'CWE-116');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-38476', 'CWE-829');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-38477', 'CWE-476');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-39573', 'CWE-20');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-9143', 'CWE-125');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2024-9143', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-15467', 'CWE-120');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-15467', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-68160', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-69419', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-69420', 'CWE-754');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-69421', 'CWE-476');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-9230', 'CWE-125');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2025-9230', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-113425', 'CWE-416');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-121810', 'CWE-416');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-123007', 'CWE-191');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-123007', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-27654', 'CWE-120');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-27654', 'CWE-122');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-42055', 'CWE-122');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-42055', 'CWE-131');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-42055', 'CWE-787');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-42945', 'CWE-122');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-42945', 'CWE-131');
INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES ('CVE-2026-60005', 'CWE-908');

-- Store the NVD and vendor reference URLs.
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38473', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38473', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38473', 'http://www.openwall.com/lists/oss-security/2024/07/01/6') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38474', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38474', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38474', 'http://www.openwall.com/lists/oss-security/2024/07/01/7') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'http://www.openwall.com/lists/oss-security/2024/07/01/8') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://github.com/apache/httpd/commit/9a6157d1e2f7ab15963020381054b48782bc18cf') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0018') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://www.blackhat.com/us-24/briefings/schedule/index.html#confusion-attacks-exploiting-hidden-semantic-ambiguity-in-apache-http-server-pre-recorded-40227') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38475', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-38475') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38476', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38476', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38476', 'http://seclists.org/fulldisclosure/2024/Oct/11') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38476', 'http://www.openwall.com/lists/oss-security/2024/07/01/9') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38477', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38477', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38477', 'http://seclists.org/fulldisclosure/2024/Oct/11') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-38477', 'http://www.openwall.com/lists/oss-security/2024/07/01/10') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-39573', 'https://httpd.apache.org/security/vulnerabilities_24.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-39573', 'https://security.netapp.com/advisory/ntap-20240712-0001/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-39573', 'http://seclists.org/fulldisclosure/2024/Oct/11') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-39573', 'http://www.openwall.com/lists/oss-security/2024/07/01/11') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2024-9143', 'https://nvd.nist.gov/vuln/detail/CVE-2024-9143') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-15467', 'https://nvd.nist.gov/vuln/detail/CVE-2025-15467') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-68160', 'https://nvd.nist.gov/vuln/detail/CVE-2025-68160') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-69419', 'https://nvd.nist.gov/vuln/detail/CVE-2025-69419') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-69420', 'https://nvd.nist.gov/vuln/detail/CVE-2025-69420') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-69421', 'https://nvd.nist.gov/vuln/detail/CVE-2025-69421') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2025-9230', 'https://nvd.nist.gov/vuln/detail/CVE-2025-9230') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-113425', 'https://my.f5.com/manage/s/article/K000163931') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-113425', 'https://cert-portal.siemens.com/productcert/html/ssa-935812.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-121810', 'https://my.f5.com/manage/s/article/K000163927') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-121810', 'https://cert-portal.siemens.com/productcert/html/ssa-935812.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://my.f5.com/manage/s/article/K000163926') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://access.redhat.com/security/cve/cve-2026-123007') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://cyberscoop.com/nginx-critical-vulnerabilities-exploits/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/Azure/aks-app-routing-operator/issues/623') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/advisories/GHSA-m4q8-cf44-f42r') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/chainguard-forks/ingress-nginx/pull/69') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/nginx/nginx/commit/b89c4100bf6762a45e4a6463eaf4b70368277c94') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/nginx/nginx/issues/2002') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://github.com/openresty/openresty/issues/1165') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://news.ycombinator.com/item?id=50547374') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://nginx.org/en/CHANGES') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://nginx2root.com') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://ubuntu.com/security/CVE-2026-123007') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://xint.io/blog/nginx2root-remote-code-execution') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-123007', 'https://cert-portal.siemens.com/productcert/html/ssa-935812.html') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://my.f5.com/manage/s/article/K000160382') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:10065') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:13634') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:13680') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:13839') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:14836') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:15942') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:15943') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:15945') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:15966') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:6906') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:6907') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:6923') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:7002') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:7343') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/errata/RHSA-2026:8346') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://access.redhat.com/security/cve/CVE-2026-27654') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://bugzilla.redhat.com/show_bug.cgi?id=2450776') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-27654', 'https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-27654.json') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://my.f5.com/manage/s/article/K000161584') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:27197') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:36331') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:36364') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:36618') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:36639') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:38847') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:44481') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:46836') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/errata/RHSA-2026:58981') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://access.redhat.com/security/cve/CVE-2026-42055') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://bugzilla.redhat.com/show_bug.cgi?id=2489866') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42055', 'https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-42055.json') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://my.f5.com/manage/s/article/K000161019') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://depthfirst.com/nginx-rift') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://github.com/DepthFirstDisclosures/Nginx-Rift') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17417') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17751') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17752') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17753') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17790') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17791') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17792') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17793') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:17794') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:18029') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:18041') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:18063') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:19159') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:19371') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:19372') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:19374') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:20442') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:20444') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:21275') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22382') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22383') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22388') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22389') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22390') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22393') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22394') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:22396') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/errata/RHSA-2026:58981') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://access.redhat.com/security/cve/CVE-2026-42945') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://bugzilla.redhat.com/show_bug.cgi?id=2477116') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-42945', 'https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-42945.json') ON CONFLICT DO NOTHING;
INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES ('CVE-2026-60005', 'https://my.f5.com/manage/s/article/K000162100') ON CONFLICT DO NOTHING;

-- Map each CVE to its verified affected product version.
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-38473', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-38474', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-38475', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-38476', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-38477', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-39573', 1, '2.4.59');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2024-9143', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-15467', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-68160', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-69419', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-69420', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-69421', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2025-9230', 2, '3.0.15');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-113425', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-121810', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-123007', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-27654', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-42055', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-42945', 3, '1.26.1');
INSERT INTO CVE_PRODUCT_VERSION (cve_id, product_id, version_number) VALUES ('CVE-2026-60005', 3, '1.26.1');

COMMIT;

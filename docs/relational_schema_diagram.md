# İlişkisel Şema Diyagramı

Bu diyagram, Siber Tehdit İstihbaratı ve Zafiyet Yönetim Sistemi'nin ilişkisel şemasını göstermektedir. Kavramsal ER/EER modeli ayrı olarak `conceptual_model.md` dosyasında açıklanmıştır.

## 1. İlişkisel Şema

```mermaid
erDiagram
    CVE {
        string cve_id PK
        string description
        date published_date
        decimal cvss_score
    }

    CWE {
        string cwe_id PK
        string name
        string description
    }

    VENDOR {
        bigint vendor_id PK
        string name
        string website
    }

    PRODUCT {
        bigint product_id PK
        bigint vendor_id FK
        string name
    }

    PRODUCT_VERSION {
        bigint product_id PK, FK
        string version_number PK
        date release_date
    }

    PATCH {
        string patch_id PK
        string cve_id FK
        date release_date
    }

    CVE_REFERENCE {
        string cve_id PK, FK
        string reference_url PK
    }

    CVE_CWE {
        string cve_id PK, FK
        string cwe_id PK, FK
    }

    CVE_PRODUCT_VERSION {
        string cve_id PK, FK
        bigint product_id PK, FK
        string version_number PK, FK
    }

    ASSET {
        bigint asset_id PK
        string asset_name
        string building
        string floor
        string room
        bigint owner_id FK
    }

    SERVER {
        bigint asset_id PK, FK
        string operating_system
        string server_role
    }

    ENDPOINT {
        bigint asset_id PK, FK
        string username
    }

    CLOUD {
        bigint asset_id PK, FK
        string provider
        string region
    }

    ASSET_PRODUCT_VERSION {
        bigint asset_id PK, FK
        bigint product_id PK, FK
        string version_number PK, FK
        date install_date
    }

    PATCH_APPLICATION {
        bigint application_id PK
        bigint asset_id FK
        string patch_id FK
        date applied_date
    }

    AUDIT_LOG {
        bigint audit_log_id PK
        bigint application_id FK, UK
        datetime created_at
        string event_type
    }

    USER_ACCOUNT {
        bigint user_id PK
        string name
        string email UK
        string role
    }

    ANALYST_REVIEW {
        bigint user_id PK, FK
        bigint asset_id PK, FK
        string cve_id PK, FK
        string review_status
        date review_date
    }

    OWNER {
        bigint owner_id PK
        string owner_type
    }

    DEPARTMENT {
        bigint owner_id PK, FK
        string name
    }

    SUPPLIER {
        bigint owner_id PK, FK
        string name
    }

    VENDOR ||--o{ PRODUCT : produces
    PRODUCT ||--o{ PRODUCT_VERSION : has
    CVE ||--o{ PATCH : has
    CVE ||--o{ CVE_REFERENCE : has
    CVE ||--o{ CVE_CWE : classified_as
    CWE ||--o{ CVE_CWE : classifies
    CVE ||--o{ CVE_PRODUCT_VERSION : affects
    PRODUCT_VERSION ||--o{ CVE_PRODUCT_VERSION : affected_by
    ASSET ||--o{ ASSET_PRODUCT_VERSION : uses
    PRODUCT_VERSION ||--o{ ASSET_PRODUCT_VERSION : installed_on
    ASSET ||--o{ PATCH_APPLICATION : receives
    PATCH ||--o{ PATCH_APPLICATION : applied_as
    PATCH_APPLICATION ||--|| AUDIT_LOG : generates
    USER_ACCOUNT ||--o{ ANALYST_REVIEW : performs
    ASSET ||--o{ ANALYST_REVIEW : reviewed_on
    CVE ||--o{ ANALYST_REVIEW : reviewed
    OWNER ||--o{ ASSET : owns
    OWNER ||--o| DEPARTMENT : represented_by
    OWNER ||--o| SUPPLIER : represented_by
    ASSET ||--o| SERVER : is
    ASSET ||--o| ENDPOINT : is
    ASSET ||--o| CLOUD : is
```

---

## 2. EER Modelleme Kuralları

### 2.1. Zayıf Varlık: ProductVersion

- ProductVersion, Product varlığına bağımlıdır.
- Kısmi anahtarı `version_number` niteliğidir.
- Birincil anahtarı `(product_id, version_number)` bileşimidir.

### 2.2. Uzmanlaşma: Asset

Asset üst varlığı üç alt türe ayrılır:

- Server
- Endpoint
- Cloud

Uzmanlaşma total ve disjoint olarak tanımlanmıştır.
Her Asset tam olarak bir alt türe ait olmalıdır. Mermaid ER gösterimi bu iki kısıtı tek başına ifade edemediğinden, bu açıklama modelin bağlayıcı kuralıdır. Alt tür üyeliğinin zorunlu ve birbirini dışlayan yapısı uygulama katmanında doğrulanacaktır.

### 2.3. Kategori / Union Type: Owner

Owner kategorisi Department ve Supplier varlıklarının birleşiminden oluşur.
- OWNER.owner_type yalnızca `DEPARTMENT` veya `SUPPLIER` değerini alabilir.
- owner_type ile ilgili alt tür kaydının eşleşmesi uygulama katmanında doğrulanır.

- Her Asset tam olarak bir Owner'a bağlıdır.
- Bir Owner, Department veya Supplier türünde olmalıdır.
- Bir Owner aynı anda hem Department hem Supplier olamaz.
- Bir Department veya Supplier birden fazla Asset'e sahip olabilir.
- Her Owner tam olarak bir Department veya Supplier tarafından temsil edilmelidir; iki türde birden temsil edilemez. Mermaid ER gösterimi bu category kısıtını tek başına ifade edemediğinden, bu açıklama modelin bağlayıcı kuralıdır. owner_type ile alt tür tablosunun eşleşmesi ve alt tür üyeliği uygulama katmanında doğrulanacaktır.

### 2.4. Üçlü İlişki: AnalystReview

AnalystReview, User, Asset ve CVE arasındaki üçlü ilişkiyi temsil eder. BR-10 gereğince ilişkiye katılan User'ın role değeri Analyst olmalıdır. Bu kural veritabanı trigger'ı ile doğrulanır.

- Aynı User–Asset–CVE birleşimi için tek inceleme kaydı tutulur.
- review_status yalnızca `Open`, `In_Review` veya `Closed` değerlerini alabilir. Bu kural CHECK kısıtıyla sağlanır.

### 2.5. PatchApplication ve AuditLog

- PatchApplication, Asset ile Patch arasındaki M:N ilişkinin uygulama kaydıdır.
- Her Asset–Patch çifti için tek uygulama kaydı tutulur. Bu kural ilişkisel şemada UNIQUE(asset_id, patch_id) kısıtıyla sağlanır.
- Her PatchApplication için tam olarak bir AuditLog kaydı oluşturulur.
- AuditLog, PatchApplication ile 1:1 ilişkilidir.
- İlişkisel şemada AUDIT_LOG.application_id alanı NOT NULL, UNIQUE ve FOREIGN KEY kısıtlarına sahip olacaktır. Her PatchApplication için AuditLog oluşturulması BR-06 trigger'ı ile sağlanacaktır.

## 3. Özel Nitelik Kuralları

- CVE severity, CVSS skorundan türetilir.
- CVE reference çok değerli niteliktir ve CVE_REFERENCE ile modellenmiştir.
- Asset location, building, floor ve room alt niteliklerinden oluşur.
- AnalystReview kavramsal olarak üçlü ilişkidir; ilişkisel modele aktarılırken ayrı tabloya dönüştürülür.

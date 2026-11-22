# Kavramsal ER/EER Modeli (Conceptual Model)

## 1. Modelin Amacı ve Kapsamı

**Proje:** Siber Tehdit İstihbaratı ve Zafiyet Yönetim Sistemi

**Ders:** BİM 381 - Veritabanı Sistemleri

**Amaç:** Kurumsal varlıkların kullandığı ürün sürümlerini, güvenlik açıklarını, yamaları, yama uygulamalarını ve analist incelemelerini ilişkisel veritabanı tasarımına temel oluşturacak şekilde kavramsal olarak modellemek.

Bu belge, ER (Entity-Relationship) ve EER (Enhanced Entity-Relationship) modelini tanımlar. Fiziksel tablo yapısı ve PostgreSQL veri tipleri bu belgenin kapsamı dışındadır.

## 2. Varlıklar ve Nitelikleri

### 2.1. CVE

**Açıklama:** Güvenlik açıklarını temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| cve_id | Anahtar | CVE kimliği |
| description | Basit | Güvenlik açığının açıklaması |
| published_date | Basit | Yayın tarihi |
| cvss_score | Basit | CVSS v3.1 puanı |
| severity | Türetilmiş | CVSS puanından hesaplanan ciddiyet seviyesi |
| references | Çok değerli | Güvenlik açığına ait referans bağlantıları |

Ciddiyet seviyeleri:
- 0.0: None
- 0.1–3.9: Low
- 4.0–6.9: Medium
- 7.0–8.9: High
- 9.0–10.0: Critical

### 2.2. CWE

**Açıklama:** Güvenlik zayıflığı türlerini temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| cwe_id | Anahtar | CWE kimliği |
| name | Basit | Zayıflık türünün adı |
| description | Basit | Zayıflık açıklaması |

### 2.3. Vendor

**Açıklama:** Ürün üreticilerini temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| vendor_id | Anahtar | Üretici kimliği |
| name | Basit | Üretici adı |
| website | Basit | Web adresi |

### 2.4. Product

**Açıklama:** Üreticilere ait ürünleri temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| product_id | Anahtar | Ürün kimliği |
| name | Basit | Ürün adı |

Ürünün üreticisi, Vendor ile kurulan ilişki üzerinden belirlenir.

### 2.5. ProductVersion

**Açıklama:** Bir ürüne ait sürümleri temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| version_number | Kısmi anahtar | Ürün içindeki sürüm numarası |
| release_date | Basit | Sürümün çıkış tarihi |

ProductVersion, Product varlığına bağımlı bir zayıf varlıktır. Sürüm numarası tek başına benzersiz değildir. Kimliği, sahibi olan Product ile birlikte belirlenir.

### 2.6. Patch

**Açıklama:** Güvenlik açıklarına yönelik yamaları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| patch_id | Anahtar | Yama kimliği |
| release_date | Basit | Yamanın yayın tarihi |

Her Patch tam olarak bir CVE'ye bağlıdır.

### 2.7. Asset

**Açıklama:** Kurumun takip ettiği bilişim varlıklarını temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| asset_id | Anahtar | Varlık kimliği |
| asset_name | Basit | Varlık adı |
| location | Bileşik | Varlığın konumu |
| building | location alt niteliği | Bina |
| floor | location alt niteliği | Kat |
| room | location alt niteliği | Oda |

Asset, Server, Endpoint ve Cloud alt türlerinin üst varlığıdır.

### 2.8. PatchApplication

**Açıklama:** Bir yamanın belirli bir bilişim varlığına uygulanmasını temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| application_id | Anahtar | Yama uygulaması kimliği |
| applied_date | Basit | Yamanın uygulanma tarihi |

PatchApplication, Asset ve Patch arasındaki M:N ilişkiyi temsil eder.
Her Asset–Patch çifti için tek uygulama kaydı tutulur.

### 2.9. AuditLog

**Açıklama:** Yama uygulaması sonucunda oluşturulan denetim kaydını temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| audit_log_id | Anahtar | Denetim kaydı kimliği |
| created_at | Basit | Kaydın oluşturulma zamanı |
| event_type | Basit | Gerçekleştirilen olay türü |

Her PatchApplication için tam olarak bir AuditLog kaydı oluşturulur. Her AuditLog yalnızca bir PatchApplication'a bağlıdır. İlişkisel şemada AUDIT_LOG.application_id alanı NOT NULL, UNIQUE ve FOREIGN KEY kısıtlarıyla tanımlanacaktır.

### 2.10. Server

**Açıklama:** Sunucu türündeki varlıkları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| operating_system | Basit | İşletim sistemi |
| server_role | Basit | Sunucunun rolü |

Server, Asset alt türüdür.

### 2.11. Endpoint

**Açıklama:** Uç nokta türündeki varlıkları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| username | Basit | İlgili kullanıcı adı |

Endpoint, Asset alt türüdür.

### 2.12. Cloud

**Açıklama:** Bulut ortamındaki varlıkları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| provider | Basit | Bulut sağlayıcısı |
| region | Basit | Bulut bölgesi |

Cloud, Asset alt türüdür.

### 2.13. User

**Açıklama:** Sistemdeki kullanıcıları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| user_id | Anahtar | Kullanıcı kimliği |
| name | Basit | Kullanıcı adı |
| email | Benzersiz | E-posta adresi |
| role | Basit | Admin, Analyst veya IT rolü |

### 2.14. Department

**Açıklama:** Kurum içindeki departmanları temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| owner_id | Anahtar (OWNER ile paylaşılan) | Ortak sorumlu kimliği |
| name | Basit | Departman adı |


### 2.15. Supplier

**Açıklama:** Kurum dışındaki tedarikçileri temsil eder.

| Nitelik | Tür | Açıklama |
|---|---|---|
| owner_id | Anahtar (OWNER ile paylaşılan) | Ortak sorumlu kimliği |
| name | Basit | Tedarikçi adı |


## 3. İlişkiler ve Kardinaliteler

| İlişki | Varlıklar | Kardinalite | Açıklama |
|---|---|---|---|
| Produces | Vendor - Product | 1:N | Bir üretici birden fazla ürün sunabilir. Her ürün bir üreticiye bağlıdır. |
| HasVersion | Product - ProductVersion | 1:N | Bir ürünün birden fazla sürümü olabilir. Tanımlayıcı ilişkidir. |
| ClassifiedAs | CVE - CWE | M:N | Bir CVE birden fazla CWE ile ilişkilendirilebilir. Ters yönde de çoklu ilişki varsayılmıştır. |
| Affects | CVE - ProductVersion | M:N | Bir CVE birden fazla ürün sürümünü etkileyebilir. |
| HasPatch | CVE - Patch | 1:N | Bir CVE için birden fazla yama bulunabilir. Her yama bir CVE'ye bağlıdır. |
| Uses | Asset - ProductVersion | M:N | Bir varlık birden fazla ürün sürümü kullanabilir. İlişki niteliği: install_date. |
| Applies / PatchApplication | Asset - Patch | M:N | Asset–Patch M:N ilişkisi, applied_date niteliği taşıdığı ve AuditLog ile 1:1 ilişki kurduğu için PatchApplication ilişkisel varlığına dönüştürülmüştür. |
| Owns | Owner - Asset | 1:N | Her varlığın bir sorumlusu vardır. Bir sorumlu birden fazla varlığa sahip olabilir. |
| Generates | PatchApplication - AuditLog | 1:1 | Her yama uygulaması için tam olarak bir denetim kaydı oluşturulur. |

### 3.1. AnalystReview Üçlü İlişkisi

Analist incelemesi üç varlık arasında kurulur:

- User
- Asset
- CVE

İlişkinin nitelikleri:

| Nitelik | Açıklama |
|---|---|
| review_status | İnceleme durumu |
| review_date | İnceleme tarihi |

Bu yapı üçlü (ternary) ilişki olarak modellenir. DR-15 ve FR-14 gereğince incelemeyi yapan kullanıcının rolü Analyst olmalıdır. Bu kural BR-10 kapsamında veritabanı trigger'ı ile doğrulanacaktır.

### 3.2. İlişki Katılımı ve Kardinalite

İlişkilerde minimum ve maksimum katılım değerleri aşağıdaki gibidir:

| İlişki | Birinci taraf | İkinci taraf |
|---|---|---|
| Produces | Vendor: 0..N (Partial) | Product: 1..1 (Total) |
| HasVersion | Product: 0..N (Partial) | ProductVersion: 1..1 (Total) |
| ClassifiedAs | CVE: 0..N (Partial) | CWE: 0..N (Partial) |
| Affects | CVE: 0..N (Partial) | ProductVersion: 0..N (Partial) |
| HasPatch | CVE: 0..N (Partial) | Patch: 1..1 (Total) |
| Uses | Asset: 0..N (Partial) | ProductVersion: 0..N (Partial) |
| Owns | Owner: 0..N (Partial) | Asset: 1..1 (Total) |
| PatchApplication | Asset: 0..N (Partial) | Patch: 0..N (Partial) |
| Generates | PatchApplication: 1..1 (Total) | AuditLog: 1..1 (Total) |

0..N sıfır veya daha fazla, 1..1 tam olarak bir katılımı ifade eder.
Total zorunlu, Partial isteğe bağlı katılımdır.

AnalystReview üçlü ilişkisinde User, Asset ve CVE taraflarının katılımı
kısmi kabul edilmiştir. Aynı User–Asset–CVE kombinasyonu için yalnızca
bir inceleme kaydı tutulur.

Her Product tam olarak bir Vendor'a, her ProductVersion tam olarak bir
Product'a ve her Patch tam olarak bir CVE'ye bağlıdır.
Her Asset tam olarak bir alt türe ve bir Owner'a bağlıdır. Alt tür üyeliği ve Owner kategorisinin doğru alt türle eşleşmesi uygulama katmanında doğrulanır.

## 4. EER Özel Yapıları

### 4.1. Weak Entity - ProductVersion

ProductVersion, Product'a bağımlı zayıf varlıktır.

- Sahip varlık: Product
- Kısmi anahtar: version_number
- Tanımlayıcı ilişki: HasVersion
- ProductVersion, sahibi olan Product olmadan tanımlanamaz.

İlişkisel modele dönüşümde kimlik, product_id ve version_number birlikte kullanılarak oluşturulacaktır.

### 4.2. Specialization - Asset

Asset üst varlığı üç alt türe ayrılır:

- Server
- Endpoint
- Cloud

Kısıtlar:

- **Total specialization:** Her Asset mutlaka bir alt türe ait olmalıdır.
- **Disjoint specialization:** Bir Asset aynı anda yalnızca bir alt türe ait olabilir.

Bu karar DR-11 ve BR-08 gereksinimlerine dayanır.

### 4.3. Category / Union Type - Owner

Owner, iki farklı varlık kümesinin birleşimini temsil eder:

- Department
- Supplier

Her Owner tam olarak bir Department veya Supplier tarafından temsil edilmelidir; aynı Owner hem Department hem Supplier olamaz. Bu, Owner kategorisinin total ve disjoint olmasını ifade eder. Her Asset tam olarak bir Owner'a bağlıdır.

Her Asset'in yalnızca bir Owner'ı vardır. Bir Department veya Supplier birden fazla Asset'in sorumlusu olabilir.

### 4.4. Özel Nitelikler

| Nitelik | Varlık | Tür |
|---|---|---|
| severity | CVE | Türetilmiş |
| references | CVE | Çok değerli |
| location | Asset | Bileşik |
| version_number | ProductVersion | Kısmi anahtar |

### 4.5. AuditLog ve PatchApplication

PatchApplication, Asset ile Patch arasındaki M:N ilişkiyi temsil eden
ilişkisel bir varlık olarak modellenir.

PatchApplication nitelikleri:
- application_id: Birincil kimlik
- applied_date: Yamanın uygulanma tarihi

Aynı Asset–Patch çifti için tek uygulama kaydı tutulur. Bu tasarım kararı ilişkisel şemada UNIQUE(asset_id, patch_id) kısıtıyla uygulanacaktır.

Her PatchApplication için otomatik olarak bir AuditLog kaydı oluşturulur.
Her AuditLog kaydı yalnızca bir PatchApplication ile ilişkilidir.
Bu ilişki 1:1 ve her iki tarafta total katılımlıdır.

AuditLog nitelikleri:
- audit_log_id: Birincil kimlik
- created_at: Denetim kaydının oluşturulma zamanı
- event_type: Gerçekleştirilen olay türü

Bu yapı BR-06 gereksinimini karşılamak için önerilmiştir.
AuditLog kaydı veritabanı trigger mekanizmasıyla oluşturulacaktır. Trigger, her PatchApplication INSERT işleminde ilişkili AuditLog kaydını otomatik oluşturacaktır.

## 5. İş Kuralları ve Bütünlük Kısıtları

| Kural | Modeldeki karşılığı |
|---|---|
| BR-01 | CVSS puanı 0.0–10.0 aralığında olmalıdır. |
| BR-02 | applied_date, Patch release_date değerinden önce olamaz. |
| BR-03 | Aynı Product altında version_number tekrarlanamaz. |
| BR-04 | CVE silindiğinde ilişkili CVE–ProductVersion kayıtları silinmelidir. |
| BR-05 | Her Patch bir CVE'ye bağlı olmalıdır. |
| BR-06 | Her Patch uygulaması için otomatik denetim kaydı oluşturulmalıdır. |
| BR-07 | User e-posta adresleri benzersiz olmalıdır. |
| BR-08 | Her Asset yalnızca bir alt türe ve bir Owner'a ait olmalıdır. |
| BR-09 | Patch yalnızca ilişkili CVE'den etkilenen bir ProductVersion kullanan Asset'e uygulanabilir. |
| BR-10 | AnalystReview kaydı oluşturan kullanıcının rolü Analyst olmalıdır. |

BR-02, BR-06, BR-09 ve BR-10 kurallarının uygulanmasında veritabanı trigger mekanizmaları kullanılacaktır.

## 6. Gereksinim - Model Eşleştirmesi

| Gereksinim | Modeldeki karşılığı |
|---|---|
| DR-01 | CVE varlığı ve nitelikleri |
| DR-02 | CVE.severity türetilmiş niteliği |
| DR-03 | CWE varlığı ve CVE–CWE ilişkisi |
| DR-04 | CVE.references çok değerli niteliği |
| DR-05 | Vendor varlığı |
| DR-06 | Product varlığı ve Vendor–Product ilişkisi |
| DR-07 | ProductVersion zayıf varlığı |
| DR-08 | CVE–ProductVersion M:N ilişkisi |
| DR-09 | Patch varlığı ve CVE–Patch ilişkisi |
| DR-10 | Asset varlığı ve location bileşik niteliği |
| DR-11 | Asset specialization |
| DR-12 | Asset–ProductVersion M:N ilişkisi ve install_date |
| DR-13 | Asset–Patch M:N ilişkisi ve applied_date |
| DR-14 | User varlığı |
| DR-15 | User–Asset–CVE üçlü ilişkisi |
| DR-16 | Owner category ve Asset–Owner ilişkisi |
| DR-17 | PatchApplication–AuditLog 1:1 ilişkisi ve denetim kaydı nitelikleri |

## 7. Tasarım Kararları ve Varsayımlar

1. CVE–CWE ilişkisi M:N olarak modellenmiştir. DR-03, bir CVE'nin birden fazla CWE ile ilişkili olabileceğini belirtir. Bir CWE'nin de birden fazla CVE ile ilişkilendirilebilmesi tasarım varsayımıdır.
2. ProductVersion zayıf varlıktır ve Product'a bağımlıdır.
3. Asset alt türleri total ve disjoint specialization olarak modellenmiştir.
4. Owner, Department ve Supplier kümelerinden oluşan category yapısıdır.
5. Patch, bağlı olduğu CVE'nin etkilediği tüm ürün sürümleri için geçerli kabul edilir. Ayrı Patch–ProductVersion uygulanabilirlik ilişkisi kurulmaz.
6. AnalystReview, User–Asset–CVE üçlü ilişkisidir. Aynı üçlü kombinasyon için tek kayıt tutulur; yeni incelemede review_status ve review_date güncellenir.
7. Department ve Supplier kimlik/ad nitelikleri DR-16 kapsamında tanımlanmıştır.
8. AuditLog alanları DR-17 kapsamında tanımlanmıştır. Her PatchApplication için AuditLog kaydı BR-06 doğrultusunda veritabanı trigger'ı ile otomatik oluşturulur.

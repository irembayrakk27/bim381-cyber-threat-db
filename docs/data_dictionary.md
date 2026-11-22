# Veri Sözlüğü (Data Dictionary)

## 1. Genel Bilgiler

**Proje:** Siber Tehdit İstihbaratı ve Zafiyet Yönetim Sistemi

**Veritabanı:** PostgreSQL

**Amaç:** Projede kullanılacak tabloların, sütunların,
veri tiplerinin, anahtarlarının ve bütünlük kısıtlarının
tanımlanması.

### 1.1. Tasarım Kuralları

- Tablo ve sütun adlarında İngilizce ve snake_case kullanılacaktır.
- Her tablo için birincil anahtar (PK) tanımlanacaktır.
- Tablolar arasındaki ilişkiler yabancı anahtarlarla (FK) kurulacaktır.
- Gereksiz veri tekrarından kaçınılacaktır.
- Türetilmiş nitelikler mümkün olduğunca hesaplanarak elde edilecektir.

## 2. Tablo Envanteri

| Grup | Tablolar |
|---|---|
| Temel varlıklar | CVE, CWE, VENDOR, PRODUCT, PRODUCT_VERSION, PATCH, USER_ACCOUNT |
| Varlık ve alt türleri | ASSET, SERVER, ENDPOINT, CLOUD |
| İşlem ve denetim | PATCH_APPLICATION, AUDIT_LOG |
| İlişki ve referans | CVE_REFERENCE, CVE_CWE, CVE_PRODUCT_VERSION, ASSET_PRODUCT_VERSION |
| İnceleme | ANALYST_REVIEW |
| Sorumluluk | OWNER, DEPARTMENT, SUPPLIER |

**Toplam tablo sayısı: 21**

## 3. Temel Varlıklar

### 3.1. CVE

**Amaç:** Güvenlik açıklarına ait kimlik, açıklama,
yayın tarihi ve CVSS v3.1 puanını saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| cve_id | VARCHAR(30) | PRIMARY KEY | CVE kimliği |
| description | TEXT | NOT NULL | Güvenlik açığının açıklaması |
| published_date | DATE | NOT NULL | Yayın tarihi |
| cvss_score | NUMERIC(3,1) | NOT NULL, CHECK (cvss_score BETWEEN 0.0 AND 10.0) | CVSS v3.1 puanı |

**Tasarım Notları:**

- cve_id, her güvenlik açığını benzersiz olarak tanımlar.
- cvss_score değeri 0.0 ile 10.0 arasında olmalıdır.
- Severity (ciddiyet seviyesi), CVSS puanından türetilir.
  Ayrı bir sütunda saklanmaz.

### 3.2. CWE

**Amaç:** Güvenlik açıklarının ilişkili olduğu zayıflık türlerini
kimlik, ad ve açıklama bilgileriyle saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| cwe_id | VARCHAR(20) | PRIMARY KEY | CWE kimliği |
| name | VARCHAR(255) | NOT NULL | Zayıflık türünün adı |
| description | TEXT | NOT NULL | Zayıflık türünün açıklaması |

**Tasarım Notları:**

- cwe_id, `CWE-79` gibi metinsel bir kimliktir.
- Bir CVE birden fazla CWE ile ilişkilendirilebilir.
  Bu çoktan çoğa ilişki ayrıca CVE_CWE tablosunda tutulacaktır.

### 3.3. VENDOR

**Amaç:** Ürünleri geliştiren veya sağlayan üreticilerin bilgilerini
saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| vendor_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Üretici kimliği |
| name | VARCHAR(255) | NOT NULL | Üretici adı |
| website | TEXT | NULL | Üreticinin web adresi |

**Tasarım Notları:**

- vendor_id, PostgreSQL tarafından otomatik üretilen sayısal kimliktir.
- Bir üretici birden fazla ürüne sahip olabilir.
- Üretici web adresi zorunlu tutulmamıştır.

### 3.4. PRODUCT

**Amaç:** Üreticilere ait ürünlerin bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| product_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Ürün kimliği |
| name | VARCHAR(255) | NOT NULL | Ürün adı |
| vendor_id | BIGINT | NOT NULL, FOREIGN KEY REFERENCES VENDOR(vendor_id) ON DELETE RESTRICT ON UPDATE CASCADE | Üretici kimliği |

**Tasarım Notları:**

- product_id, PostgreSQL tarafından otomatik üretilir.
- Her ürün tam olarak bir üreticiye bağlıdır.
- vendor_id yabancı anahtarı, ürünün geçerli bir üreticiye bağlı olmasını sağlar.

### 3.5. PRODUCT_VERSION

**Amaç:** Ürünlere ait sürüm numaralarını ve yayın tarihlerini
saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| product_id | BIGINT | NOT NULL, FOREIGN KEY REFERENCES PRODUCT(product_id) ON DELETE CASCADE ON UPDATE CASCADE | Ürün kimliği |
| version_number | VARCHAR(100) | NOT NULL | Ürün sürüm numarası |
| release_date | DATE | NOT NULL | Sürümün yayın tarihi |

**Birincil Anahtar:** PRIMARY KEY (product_id, version_number)

**Tasarım Notları:**

- PRODUCT_VERSION zayıf varlık olarak modellenmiştir.
- Birincil anahtar (product_id, version_number) bileşik anahtardır.
- Aynı ürün için aynı sürüm numarası tekrar kaydedilemez.
- version_number metin olarak saklanır; sürüm numaraları sayısal olmayan karakterler içerebilir.
- product_id aynı zamanda PRODUCT tablosuna yabancı anahtardır.

### 3.6. PATCH

**Amaç:** Güvenlik açıklarına yönelik yamaların kimlik ve yayın
tarihi bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| patch_id | VARCHAR(100) | PRIMARY KEY | Yama kimliği |
| cve_id | VARCHAR(30) | NOT NULL, FOREIGN KEY REFERENCES CVE(cve_id) ON DELETE RESTRICT ON UPDATE CASCADE | İlişkili güvenlik açığı |
| release_date | DATE | NOT NULL | Yamanın yayın tarihi |

**Tasarım Notları:**

- Her yama tam olarak bir CVE kaydına bağlıdır.
- Bir CVE için birden fazla yama tanımlanabilir.
- patch_id, farklı üreticilerin yama kimliklerini desteklemek amacıyla metin olarak saklanır.
- Yama ile ürün sürümü arasındaki uygulanabilirlik ayrıca modellenmez; yama, ilişkili CVE'nin etkilediği ürün sürümleri için geçerli kabul edilir.

### 3.7. USER_ACCOUNT

**Amaç:** Sistemde işlem yapan kullanıcıların kimlik, e-posta ve rol
bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| user_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Kullanıcı kimliği |
| name | VARCHAR(150) | NOT NULL | Kullanıcının adı |
| email | VARCHAR(255) | NOT NULL, UNIQUE | Kullanıcının e-posta adresi |
| role | VARCHAR(20) | NOT NULL, CHECK (role IN ('Admin', 'Analyst', 'IT')) | Kullanıcı rolü |

**Tasarım Notları:**

- user_id, PostgreSQL tarafından otomatik üretilir.
- Her kullanıcının e-posta adresi benzersiz olmalıdır.
- Kullanıcı rolü yalnızca Admin, Analyst veya IT olabilir.
- Bu tabloda parola veya kimlik doğrulama bilgisi tutulmaz; gerçek kimlik doğrulama kapsam dışıdır.

### 3.8. ASSET

**Amaç:** Kurumun takip ettiği bilişim varlıklarının ortak kimlik,
ad ve konum bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| asset_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Varlık kimliği |
| asset_name | VARCHAR(255) | NOT NULL | Varlık adı |
| building | VARCHAR(100) | NOT NULL | Bulunduğu bina |
| floor | VARCHAR(20) | NOT NULL | Bulunduğu kat |
| room | VARCHAR(50) | NOT NULL | Bulunduğu oda |
| owner_id | BIGINT | NOT NULL, FOREIGN KEY REFERENCES OWNER(owner_id) ON DELETE RESTRICT ON UPDATE CASCADE | Varlığın sorumlusu |

**Tasarım Notları:**

- location, building, floor ve room sütunlarına ayrıştırılmıştır.
- Her varlığın tam olarak bir sorumlusu bulunmalıdır.
- owner_id, OWNER tablosuna yabancı anahtardır.
- Her varlık tam olarak bir alt türe (SERVER, ENDPOINT veya CLOUD) ait olmalıdır.
- Alt tür üyeliğinin zorunlu ve birbirini dışlayan yapısı uygulama katmanında doğrulanacaktır; bu proje kapsamında constraint trigger kullanılmayacaktır.

### 3.9. SERVER

**Amaç:** Sunucu türündeki varlıklara özgü bilgileri saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| asset_id | BIGINT | PRIMARY KEY, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE CASCADE ON UPDATE CASCADE | Üst varlık kimliği |
| operating_system | VARCHAR(100) | NOT NULL | İşletim sistemi |
| server_role | VARCHAR(100) | NOT NULL | Sunucunun rolü |

**Tasarım Notları:**

- SERVER, ASSET tablosunun alt türüdür.
- asset_id hem birincil hem yabancı anahtardır.

### 3.10. ENDPOINT

**Amaç:** Uç nokta türündeki varlıklara özgü bilgileri saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| asset_id | BIGINT | PRIMARY KEY, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE CASCADE ON UPDATE CASCADE | Üst varlık kimliği |
| username | VARCHAR(150) | NOT NULL | İlgili kullanıcı adı |

**Tasarım Notları:**

- ENDPOINT, ASSET tablosunun alt türüdür.
- asset_id hem birincil hem yabancı anahtardır.

### 3.11. CLOUD

**Amaç:** Bulut ortamındaki varlıklara özgü bilgileri saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| asset_id | BIGINT | PRIMARY KEY, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE CASCADE ON UPDATE CASCADE | Üst varlık kimliği |
| provider | VARCHAR(100) | NOT NULL | Bulut sağlayıcısı |
| region | VARCHAR(100) | NOT NULL | Bulut bölgesi |

**Tasarım Notları:**

- CLOUD, ASSET tablosunun alt türüdür.
- asset_id hem birincil hem yabancı anahtardır.

### 3.12. OWNER

**Amaç:** Departman ve tedarikçi türündeki sorumluları ortak bir
kimlik altında temsil etmek.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| owner_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Sorumlu kimliği |
| owner_type | VARCHAR(20) | NOT NULL, CHECK (owner_type IN ('DEPARTMENT', 'SUPPLIER')) | Sorumlu türü |

**Tasarım Notları:**

- OWNER, Department ve Supplier varlıklarının birleşim kategorisini temsil eder.
- Her OWNER kaydı yalnızca bir sorumlu türüne ait olmalıdır.
- Her OWNER kaydı tam olarak bir alt türe (DEPARTMENT veya SUPPLIER) ait olmalıdır.
- owner_type ile alt tür tablosunun eşleşmesi ve alt tür üyeliğinin zorunluluğu uygulama katmanında doğrulanacaktır; bu proje kapsamında constraint trigger kullanılmayacaktır.

### 3.13. DEPARTMENT

**Amaç:** Kurum içindeki departmanların bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| owner_id | BIGINT | PRIMARY KEY, FOREIGN KEY REFERENCES OWNER(owner_id) ON DELETE CASCADE ON UPDATE CASCADE | Ortak sorumlu kimliği |
| name | VARCHAR(255) | NOT NULL | Departman adı |

**Tasarım Notları:**

- DEPARTMENT, OWNER tablosunun alt türüdür.
- owner_id hem birincil hem yabancı anahtardır.

### 3.14. SUPPLIER

**Amaç:** Kurum dışındaki tedarikçilerin bilgilerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| owner_id | BIGINT | PRIMARY KEY, FOREIGN KEY REFERENCES OWNER(owner_id) ON DELETE CASCADE ON UPDATE CASCADE | Ortak sorumlu kimliği |
| name | VARCHAR(255) | NOT NULL | Tedarikçi adı |

**Tasarım Notları:**

- SUPPLIER, OWNER tablosunun alt türüdür.
- owner_id hem birincil hem yabancı anahtardır.

## 4. İlişki Tabloları

### 4.1. CVE_REFERENCE

**Amaç:** Bir CVE kaydına ait birden fazla referans bağlantısını saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| cve_id | VARCHAR(30) | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES CVE(cve_id) ON DELETE CASCADE ON UPDATE CASCADE | İlgili CVE kimliği |
| reference_url | TEXT | PRIMARY KEY (bileşik), NOT NULL | Referans bağlantısı |

**Tasarım Notları:**

- Bir CVE birden fazla referans bağlantısına sahip olabilir.
- Bileşik birincil anahtar (cve_id, reference_url) aynı bağlantının aynı CVE için tekrar eklenmesini önler.
- İlgili CVE silindiğinde referans kayıtları da silinir.

### 4.2. CVE_CWE

**Amaç:** CVE ve CWE kayıtları arasındaki çoktan çoğa ilişkiyi saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| cve_id | VARCHAR(30) | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES CVE(cve_id) ON DELETE CASCADE ON UPDATE CASCADE | CVE kimliği |
| cwe_id | VARCHAR(20) | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES CWE(cwe_id) ON DELETE CASCADE ON UPDATE CASCADE | CWE kimliği |

**Tasarım Notları:**

- Bir CVE birden fazla CWE ile ilişkilendirilebilir.
- Bir CWE birden fazla CVE ile ilişkilendirilebilir.
- Bileşik birincil anahtar (cve_id, cwe_id) aynı ilişkinin tekrar eklenmesini önler.
- CVE silindiğinde ona ait ilişki kayıtları da silinir.

### 4.3. CVE_PRODUCT_VERSION

**Amaç:** CVE kayıtları ile etkilenen ürün sürümleri arasındaki çoktan çoğa ilişkiyi saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| cve_id | VARCHAR(30) | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES CVE(cve_id) ON DELETE CASCADE ON UPDATE CASCADE | CVE kimliği |
| product_id | BIGINT | PRIMARY KEY (bileşik), NOT NULL, bileşik FOREIGN KEY | Ürün kimliği |
| version_number | VARCHAR(100) | PRIMARY KEY (bileşik), NOT NULL, bileşik FOREIGN KEY | Ürün sürüm numarası |

**Bileşik yabancı anahtar:**

- (product_id, version_number) → PRODUCT_VERSION(product_id, version_number) [ON DELETE CASCADE, ON UPDATE CASCADE]

**Tasarım Notları:**

- Bir CVE birden fazla ürün sürümünü etkileyebilir.
- Bir ürün sürümü birden fazla CVE'den etkilenebilir.
- Bileşik birincil anahtar (cve_id, product_id, version_number) aynı etkinin tekrar kaydedilmesini önler.
- CVE silindiğinde ilgili ürün sürümü ilişki kayıtları da silinir.
- Ürün sürümünün kimliği, PRODUCT_VERSION tablosundaki bileşik anahtarla belirlenir.

### 4.4. ASSET_PRODUCT_VERSION

**Amaç:** Kurum varlıklarına yüklenmiş ürün sürümlerini ve kurulum tarihlerini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| asset_id | BIGINT | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE CASCADE ON UPDATE CASCADE | Varlık kimliği |
| product_id | BIGINT | PRIMARY KEY (bileşik), NOT NULL, bileşik FOREIGN KEY | Ürün kimliği |
| version_number | VARCHAR(100) | PRIMARY KEY (bileşik), NOT NULL, bileşik FOREIGN KEY | Ürün sürüm numarası |
| install_date | DATE | NOT NULL | Kurulum tarihi |

**Bileşik yabancı anahtar:**

- (product_id, version_number) → PRODUCT_VERSION(product_id, version_number) [ON DELETE CASCADE, ON UPDATE CASCADE]

**Tasarım Notları:**

- Bir varlıkta birden fazla ürün sürümü bulunabilir.
- Aynı ürün sürümü birden fazla varlığa kurulabilir.
- Bileşik birincil anahtar (asset_id, product_id, version_number) aynı kurulum kaydının tekrar eklenmesini önler.
- install_date, Asset–ProductVersion ilişkisinin niteliğidir.
- Bir varlık silindiğinde ona ait ürün sürümü ilişki kayıtları da silinir.

### 4.5. PATCH_APPLICATION

**Amaç:** Bir yamanın hangi bilişim varlığına hangi tarihte uygulandığını saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| application_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Uygulama kaydı kimliği |
| asset_id | BIGINT | NOT NULL, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE RESTRICT ON UPDATE CASCADE | Yamanın uygulandığı varlık |
| patch_id | VARCHAR(100) | NOT NULL, FOREIGN KEY REFERENCES PATCH(patch_id) ON DELETE RESTRICT ON UPDATE CASCADE | Uygulanan yama |
| applied_date | DATE | NOT NULL | Yamanın uygulanma tarihi |

**Ek Kısıtlar:**

- UNIQUE (asset_id, patch_id)

**Tasarım Notları:**

- Her uygulama kaydı bir varlığa ve bir yamaya bağlıdır.
- Aynı yama aynı varlığa birden fazla kez uygulama kaydı olarak eklenemez.
- applied_date, yamanın yayın tarihinden önce olamaz. Bu kural trigger ile denetlenecektir.
- Yama yalnızca ilişkili CVE'nin etkilediği ürün sürümünü kullanan varlığa uygulanabilir. Bu kural trigger ile denetlenecektir.

### 4.6. AUDIT_LOG

**Amaç:** Yama uygulama işlemlerine ilişkin denetim kayıtlarını saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| audit_log_id | BIGINT | PRIMARY KEY, GENERATED ALWAYS AS IDENTITY | Denetim kaydı kimliği |
| application_id | BIGINT | NOT NULL, UNIQUE, FOREIGN KEY REFERENCES PATCH_APPLICATION(application_id) ON DELETE RESTRICT ON UPDATE CASCADE | İlgili yama uygulaması |
| created_at | TIMESTAMPTZ | NOT NULL | Denetim kaydının oluşturulma zamanı |
| event_type | VARCHAR(100) | NOT NULL | Gerçekleşen işlem türü |

**Tasarım Notları:**

- Her denetim kaydı bir PATCH_APPLICATION kaydına bağlıdır.
- application_id üzerindeki UNIQUE kısıtı, her uygulama için en fazla bir denetim kaydı bulunmasını sağlar.
- Her yama uygulaması için denetim kaydı otomatik oluşturulacaktır. Bu işlem trigger ile gerçekleştirilecektir.
- created_at alanında TIMESTAMPTZ kullanılarak zaman dilimi bilgisi korunur.

### 4.7. ANALYST_REVIEW

**Amaç:** Bir kullanıcının belirli bir bilişim varlığı üzerindeki belirli bir CVE'ye ilişkin değerlendirmesini saklamak.

| Sütun | Veri Tipi | Kısıt | Açıklama |
|---|---|---|---|
| user_id | BIGINT | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES USER_ACCOUNT(user_id) ON DELETE RESTRICT ON UPDATE CASCADE | Değerlendirmeyi yapan kullanıcı |
| asset_id | BIGINT | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES ASSET(asset_id) ON DELETE RESTRICT ON UPDATE CASCADE | Değerlendirilen varlık |
| cve_id | VARCHAR(30) | PRIMARY KEY (bileşik), NOT NULL, FOREIGN KEY REFERENCES CVE(cve_id) ON DELETE RESTRICT ON UPDATE CASCADE | Değerlendirilen güvenlik açığı |
| review_status | VARCHAR(50) | NOT NULL, CHECK (review_status IN ('Open', 'In_Review', 'Closed')) | Değerlendirme durumu |
| review_date | DATE | NOT NULL | Değerlendirme tarihi |

**Tasarım Notları:**

- Her değerlendirme bir kullanıcı, bir varlık ve bir CVE ile ilişkilidir.
- Bileşik birincil anahtar (user_id, asset_id, cve_id), aynı üçlü için birden fazla değerlendirme kaydı oluşturulmasını önler.
- Aynı üçlüye ilişkin yeni değerlendirme yapıldığında mevcut kaydın durumu ve tarihi güncellenir.
- review_status yalnızca Open, In_Review veya Closed değerlerinden birini alabilir.
- İnceleme kaydı oluşturan kullanıcının role değeri Analyst olmalıdır. Bu kural BR-10 kapsamında trigger ile doğrulanacaktır.

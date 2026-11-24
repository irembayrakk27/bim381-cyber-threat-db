# Normalizasyon (Normalization)

## 1. Birinci Normal Form (1NF)

Bir ilişkisel tablonun Birinci Normal Formda (1NF) olması için:

- Her sütundaki değerler atomik olmalıdır.
- Bir hücrede birden fazla bağımsız değer veya tekrarlayan değer grubu tutulmamalıdır.
- Her kayıt, birincil anahtar aracılığıyla diğer kayıtlardan ayırt edilebilmelidir.
- Aynı niteliğe ait tekrarlayan sütun grupları kullanılmamalıdır.

### 1.1. Projede 1NF Uygulaması

Projede tanımlanan 21 tablonun tamamı, atomik sütun değerleri ve birincil anahtarlar esas alınarak modellenmiştir.

**Çok değerli niteliklerin ayrıştırılması**

- CVE kayıtlarına ait birden fazla referans bağlantısı, tek bir sütunda liste olarak tutulmamış; her bağlantı ayrı satır olacak şekilde `CVE_REFERENCE` tablosuna aktarılmıştır.
- CVE ile CWE arasındaki çoktan çoğa ilişki `CVE_CWE` tablosuyla temsil edilmiştir.
- CVE ile etkilenen ürün sürümleri arasındaki çoktan çoğa ilişki `CVE_PRODUCT_VERSION` tablosuyla temsil edilmiştir.
- Varlıkların kullandığı ürün sürümleri `ASSET_PRODUCT_VERSION` tablosunda ayrı kayıtlar olarak tutulmuştur.

**Bileşik niteliklerin ayrıştırılması**

- ASSET tablosundaki konum bilgisi tek bir `location` sütununda tutulmamış; `building`, `floor` ve `room` sütunlarına ayrılmıştır.

**İlişki niteliklerinin uygun tablolarda tutulması**

- Ürün sürümünün yayın tarihi `PRODUCT_VERSION` tablosunda tutulur.
- Varlığa ürün sürümü kurulum tarihi `ASSET_PRODUCT_VERSION.install_date` sütununda tutulur.
- Yama uygulama tarihi `PATCH_APPLICATION.applied_date` sütununda tutulur.
- Analist değerlendirme durumu ve tarihi `ANALYST_REVIEW` tablosunda tutulur.

**Varlık ve alt türlerin ayrıştırılması**

- Ortak varlık bilgileri `ASSET` tablosunda tutulur.
- Sunucu, uç nokta ve bulut türlerine özgü bilgiler sırasıyla `SERVER`, `ENDPOINT` ve `CLOUD` tablolarında saklanır.
- Alt tür tablolarında `asset_id`, hem birincil anahtar hem de `ASSET` tablosuna yabancı anahtar olarak kullanılır.

### 1.2. Birincil Anahtar Kullanımı

Tablolardaki kayıtların benzersiz biçimde tanımlanması için tek sütunlu veya bileşik birincil anahtarlar kullanılmıştır.

Bileşik anahtar örnekleri:

- `PRODUCT_VERSION`: `(product_id, version_number)`
- `CVE_REFERENCE`: `(cve_id, reference_url)`
- `CVE_CWE`: `(cve_id, cwe_id)`
- `CVE_PRODUCT_VERSION`: `(cve_id, product_id, version_number)`
- `ASSET_PRODUCT_VERSION`: `(asset_id, product_id, version_number)`
- `ANALYST_REVIEW`: `(user_id, asset_id, cve_id)`

### 1.3. Sonuç

Projede çok değerli nitelikler ayrı tablolara ayrılmış, bileşik nitelikler atomik sütunlara dönüştürülmüş ve her tablonun kayıtları birincil anahtarlarla tanımlanmıştır. Bu tasarım kararlarıyla 21 tablonun tamamı Birinci Normal Form (1NF) koşullarını karşılayacak şekilde modellenmiştir.

İkinci ve Üçüncü Normal Form incelemeleri bu belgenin sonraki bölümlerinde ayrıca ele alınacaktır.

## 2. Fonksiyonel Bağımlılıkların Analizi

Fonksiyonel bağımlılık (FD), bir tablodaki bir veya daha fazla niteliğin
başka nitelikleri benzersiz biçimde belirlemesini ifade eder.
Gösterimde X → Y, X'in Y'yi belirlediğini gösterir.

Analiz, schema.sql dosyasında tanımlanan birincil anahtarlar ve
UNIQUE kısıtları esas alınarak gerçekleştirilmiştir.

### 2.1. Tablolara Göre Fonksiyonel Bağımlılıklar

| Tablo | Fonksiyonel Bağımlılık |
|---|---|
| CVE | cve_id → description, published_date, cvss_score |
| CWE | cwe_id → name, description |
| VENDOR | vendor_id → name, website |
| USER_ACCOUNT | user_id → name, email, role; email → user_id, name, role |
| OWNER | owner_id → owner_type |
| PRODUCT | product_id → name, vendor_id |
| PRODUCT_VERSION | (product_id, version_number) → release_date |
| PATCH | patch_id → cve_id, release_date |
| ASSET | asset_id → asset_name, building, floor, room, owner_id |
| SERVER | asset_id → operating_system, server_role |
| ENDPOINT | asset_id → username |
| CLOUD | asset_id → provider, region |
| DEPARTMENT | owner_id → name |
| SUPPLIER | owner_id → name |
| CVE_REFERENCE | (cve_id, reference_url) → anahtar dışı nitelik yok |
| CVE_CWE | (cve_id, cwe_id) → anahtar dışı nitelik yok |
| CVE_PRODUCT_VERSION | (cve_id, product_id, version_number) → anahtar dışı nitelik yok |
| ASSET_PRODUCT_VERSION | (asset_id, product_id, version_number) → install_date |
| PATCH_APPLICATION | application_id → asset_id, patch_id, applied_date; (asset_id, patch_id) → application_id, applied_date |
| AUDIT_LOG | audit_log_id → application_id, created_at, event_type; application_id → audit_log_id, created_at, event_type |
| ANALYST_REVIEW | (user_id, asset_id, cve_id) → review_status, review_date |

### 2.2. Aday Anahtarlar ve Alternatif Anahtarlar

- USER_ACCOUNT tablosunda user_id birincil anahtar, email ise NOT NULL ve UNIQUE kısıtları nedeniyle alternatif aday anahtardır.
- PATCH_APPLICATION tablosunda application_id birincil anahtar; (asset_id, patch_id) ise UNIQUE kısıtı nedeniyle alternatif aday anahtardır.
- AUDIT_LOG tablosunda audit_log_id birincil anahtar, application_id ise NOT NULL ve UNIQUE kısıtları nedeniyle alternatif aday anahtardır.
- Diğer tablolarda aday anahtarlar, tanımlanan birincil anahtarlarla belirlenmiştir.

### 2.3. Fonksiyonel Bağımlılık Analizi Sonucu

Analiz, schema.sql dosyasında tanımlanan birincil anahtarlar ve UNIQUE
kısıtları esas alınarak gerçekleştirilmiştir. Foreign Key ilişkileri tek
başına aynı tablo içinde fonksiyonel bağımlılık oluşturmaz. İlişkili
varlıkların nitelikleri kendi tablolarında tutulmuştur.
## 3. İkinci Normal Form (2NF)

Bir tablonun 2NF koşullarını karşılaması için:

- Öncelikle 1NF koşullarını sağlaması gerekir.
- Anahtar olmayan her nitelik, aday anahtarın tamamına tam fonksiyonel bağımlı olmalıdır.
- Bileşik aday anahtarın yalnızca bir bölümüne bağlı olan anahtar dışı nitelik bulunmamalıdır.

### 3.1. Projede 2NF Uygulaması

Projede bileşik birincil anahtara sahip tablolar özellikle incelenmiştir:

- `PRODUCT_VERSION` tablosundaki `release_date`, `(product_id, version_number)` anahtarının tamamına bağlıdır.
- `ASSET_PRODUCT_VERSION` tablosundaki `install_date`, `(asset_id, product_id, version_number)` anahtarının tamamına bağlıdır.
- `ANALYST_REVIEW` tablosundaki `review_status` ve `review_date`, `(user_id, asset_id, cve_id)` anahtarının tamamına bağlıdır.
- `CVE_REFERENCE`, `CVE_CWE` ve `CVE_PRODUCT_VERSION` tablolarında bileşik anahtar dışında nitelik bulunmadığından kısmi bağımlılık oluşmamaktadır.

`PATCH_APPLICATION` tablosundaki `applied_date`, hem `application_id` birincil anahtarına hem de `(asset_id, patch_id)` alternatif aday anahtarına tam bağımlıdır. Tek sütunlu aday anahtarlara sahip diğer tablolarda da kısmi bağımlılık oluşamaz.

### 3.2. 2NF Sonucu

Bileşik aday anahtarlara sahip tablolarda anahtar olmayan niteliklerin anahtarın tamamına bağlı olduğu görülmüştür. Tek sütunlu aday anahtarlarda ise kısmi bağımlılık mümkün değildir. Bu nedenle projedeki 21 tablonun tamamı 2NF koşullarını karşılamaktadır.

## 4. Üçüncü Normal Form (3NF)

Bir tablonun 3NF koşullarını karşılaması için:

- Öncelikle 2NF koşullarını sağlaması gerekir.
- Anahtar olmayan bir nitelik, başka bir anahtar olmayan nitelik üzerinden aday anahtara geçişli olarak bağımlı olmamalıdır.

### 4.1. Projede 3NF Uygulaması

Tablolardaki fonksiyonel bağımlılıklar incelendiğinde:

- `PRODUCT` tablosunda yalnızca ürün bilgileri tutulur. Üreticiye ait ayrıntılar `VENDOR` tablosunda saklanır.
- `ASSET` tablosunda sahiplik bilgisi `owner_id` üzerinden ilişkilendirilir. Departman ve tedarikçi adları kendi tablolarında tutulur.
- `PATCH` tablosunda CVE ilişkisi `cve_id` ile kurulur; CVE'nin açıklama ve diğer bilgileri `CVE` tablosunda tutulur.
- `USER_ACCOUNT` tablosundaki `email`, UNIQUE ve NOT NULL kısıtları nedeniyle alternatif aday anahtardır; geçişli bağımlılık oluşturmaz.
- `PATCH_APPLICATION` ve `AUDIT_LOG` tablolarındaki alternatif aday anahtarlar da geçişli bağımlılık oluşturmaz.

Belirlenen fonksiyonel bağımlılıklarda, anahtar olmayan bir niteliğin başka bir anahtar olmayan niteliği belirlediği bir bağımlılık bulunmamaktadır.

### 4.2. 3NF Sonucu

Birincil ve alternatif aday anahtarlar esas alınarak yapılan incelemede, anahtar olmayan nitelikler arasında geçişli bağımlılık tespit edilmemiştir. Bu nedenle projedeki 21 tablonun tamamı 3NF koşullarını karşılamaktadır.

## 5. Genel Normalizasyon Sonucu

Projenin ilişkisel şeması 1NF, 2NF ve 3NF koşulları açısından incelenmiştir. Çok değerli ve bileşik nitelikler uygun biçimde ayrıştırılmış, bileşik anahtarlardaki kısmi bağımlılıklar ve anahtar olmayan nitelikler arasındaki geçişli bağımlılıklar değerlendirilmiştir.

Yapılan inceleme sonucunda, mevcut şemadaki 21 tablonun tamamının Üçüncü Normal Form (3NF) koşullarını karşıladığı değerlendirilmiştir. Analiz, `schema.sql` dosyasında tanımlanan anahtarlar ve kısıtlarla belirlenen fonksiyonel bağımlılıklarla sınırlıdır.

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

# Gereksinim Analizi

## 1. Proje Senaryosu
Orta ölçekli bir teknoloji şirketinin teknolojik varlıklarını,
kullandığı ürünleri, güvenlik açıklarını ve yayımlanan yamaları
merkezi bir veritabanı üzerinden takip etmesini sağlayan sistemdir.

## 2. Kullanıcı Rolleri
- Admin: Sistem ve kayıt yönetimi.
- Analyst: Güvenlik açığı ve yama bilgilerinin incelenmesi.
- IT: Kurumsal varlıkların ve kullanılan ürünlerin takibi.

## 3. Veri Gereksinimleri
- DR-01: CVE kimliği, açıklama, yayın tarihi ve CVSS puanı tutulmalıdır.
- DR-02: CWE kimliği, zayıflık türü ve açıklaması tutulmalıdır.
- DR-03: Ürün adı, üretici ve sürüm bilgileri tutulmalıdır.
- DR-04: Güvenlik açıklarının etkilediği ürün ve sürümler kaydedilmelidir.
- DR-05: Yama bilgileri ve yayın tarihleri tutulmalıdır.
- DR-06: Kurumsal varlıkların adı, türü ve konumu kaydedilmelidir.
- DR-07: Varlıklarda kullanılan ürün ve sürümler takip edilmelidir.
- DR-08: Varlık, ürün, güvenlik açığı ve yama ilişkileri izlenebilmelidir.

## 4. Fonksiyonel Gereksinimler
- FR-01: Güvenlik açığı eklenebilmelidir.
- FR-02: Güvenlik açıkları görüntülenebilmelidir.
- FR-03: Güvenlik açığı kayıtları güncellenebilmeli ve silinebilmelidir.
- FR-04: CWE kayıtları yönetilebilmelidir.
- FR-05: Ürün ve sürüm kayıtları yönetilebilmelidir.
- FR-06: Güvenlik açıkları etkilenen ürünlerle ilişkilendirilebilmelidir.
- FR-07: Yama bilgileri kaydedilebilmelidir.
- FR-08: Kurumsal varlıklar sisteme eklenebilmelidir.
- FR-09: Varlıkların kullandığı ürünler takip edilebilmelidir.
- FR-10: Bir varlıkla ilişkili güvenlik açıkları listelenebilmelidir.
- FR-11: Güvenlik açıkları CVSS puanına göre filtrelenebilmelidir.
- FR-12: Yama durumu ve etkilenen varlıklar raporlanabilmelidir.

## 5. Kapsam Dışı
- Canlı zafiyet taraması
- Sızma testi
- Yapay zekâ destekli analiz
- RAG ve chatbot entegrasyonu
- Otomatik saldırı tespiti

## 6. Proje Teknolojileri
- PostgreSQL
- SQL
- Python (gerektiğinde)
- Git ve GitHub

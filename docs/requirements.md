# Gereksinim Analizi

## 1. Müşteri ve Problem Tanımı

**Müşteri:** Orta ölçekli bir teknoloji şirketinin BT ve güvenlik ekibi.

**Problemler:**
- Güvenlik açıkları, ürünler ve yamalar farklı ortamlarda dağınık
  tutulmaktadır.
- Hangi kurumsal varlığın hangi güvenlik açıklarından etkilendiği
  kolayca takip edilememektedir.
- Bir güvenlik açığına ait yamanın hangi varlıklara uygulandığı düzenli
  olarak izlenememektedir.
- Raporlama için gerekli bilgiler farklı kaynaklardan manuel olarak
  toplanmaktadır.

**Çözüm:** Güvenlik açıkları, ürünler, sürümler, yamalar ve kurumsal
varlıklarla ilgili bilgileri merkezi ve tutarlı bir ilişkisel
veritabanında toplamak.

## 2. Proje Senaryosu

Şirket; güvenlik açıklarını (CVE), zayıflık türlerini (CWE), üreticileri,
ürünleri, ürün sürümlerini, yamaları ve kurumsal varlıklarını merkezi bir
veritabanı üzerinden takip eder.

Sistem, güvenlik açıklarının etkilenen ürün sürümleriyle
ilişkilendirilmesini, bu sürümlerin hangi kurumsal varlıklarda
kullanıldığının belirlenmesini ve ilgili yamaların uygulanma
durumlarının izlenmesini sağlar.

Projenin temel amacı siber güvenlik süreçlerini otomatikleştirmek
değil, siber güvenlik temalı bir senaryo üzerinden ilişkisel veritabanı
tasarımı ve SQL uygulamalarını gerçekleştirmektir.

## 3. Kullanıcı Rolleri

- **Admin:** Kullanıcıların ve sistem kayıtlarının temel yönetim
  işlemlerini gerçekleştirir.
- **Analist:** Güvenlik açığı ve zayıflık bilgilerini girer, inceler ve
  raporlar.
- **BT:** Kurumsal varlıkları, kullanılan ürün sürümlerini ve yama
  uygulamalarını takip eder.

Sistem kapsamında kullanıcı ekleme, listeleme, güncelleme ve silme
işlemleri bulunacaktır. Gerçek kimlik doğrulama, parola yönetimi ve
gelişmiş yetkilendirme mekanizmaları geliştirilmeyecektir.

## 4. Veri Gereksinimleri

- **DR-01:** Güvenlik açığı (CVE) için CVE kimliği, açıklama, yayın
  tarihi ve CVSS v3.1 puanı tutulmalıdır.

- **DR-02:** Güvenlik açığının ciddiyet seviyesi CVSS v3.1 puanından
  türetilmelidir:
  - 0.0: None
  - 0.1–3.9: Low
  - 4.0–6.9: Medium
  - 7.0–8.9: High
  - 9.0–10.0: Critical

- **DR-03:** Zayıflık türü (CWE) için kimlik, ad ve açıklama
  tutulmalıdır. Bir güvenlik açığı birden fazla CWE kaydıyla
  ilişkilendirilebilir.

- **DR-04:** Bir güvenlik açığına ait birden fazla referans bağlantısı
  tutulabilmelidir.

- **DR-05:** Üretici için ad ve web adresi tutulmalıdır.

- **DR-06:** Ürün için ad ve üretici bilgisi tutulmalıdır. Bir üretici
  birden fazla ürün sunabilir.

- **DR-07:** Ürün sürümü için sürüm numarası ve çıkış tarihi
  tutulmalıdır. Her sürüm yalnızca bir ürüne bağlı olmalıdır. Aynı ürün
  için aynı sürüm numarası tekrar kaydedilememelidir.

- **DR-08:** Bir güvenlik açığı birden fazla ürün sürümünü etkileyebilir.
  Bir ürün sürümü de birden fazla güvenlik açığından etkilenebilir.

- **DR-09:** Yama için kimlik ve yayın tarihi tutulmalıdır. Her yama
  yalnızca bir güvenlik açığına bağlı olmalıdır. Bir güvenlik açığı için
  birden fazla yama bulunabilir. Yama, bağlı olduğu güvenlik açığının etkilediği
  tüm ürün sürümleri için geçerli kabul edilir. Yama ve sürüm arasındaki uygulanabilirlik ayrıca modellenmeyecektir.

- **DR-10:** Kurumsal varlık için ad, tür ve konum bilgisi (bina, kat,
  oda) tutulmalıdır.

- **DR-11:** Varlık türüne özel bilgiler tutulmalıdır:


 - Sunucu: İşletim sistemi ve sunucu rolü.
  - Uç nokta: Kullanıcı adı.
  - Bulut: Sağlayıcı ve bölge.

  Her varlık yalnızca bir varlık türüne ait olmalıdır.

- **DR-12:** Bir varlık birden fazla ürün sürümü kullanabilir. Bir ürün
  sürümü de birden fazla varlıkta kullanılabilir. Ürün sürümünün varlığa
  kurulum tarihi tutulmalıdır.

- **DR-13:** Bir yamanın hangi varlığa ne zaman uygulandığı
  kaydedilmelidir. Yama uygulama tarihi tutulmalıdır. İlgili kayıt
  bulunmuyorsa yama, o varlıkta uygulanmamış kabul edilmelidir.

- **DR-14:** Kullanıcı için ad, benzersiz e-posta adresi ve rol bilgisi
  tutulmalıdır. Kullanıcı rolleri Admin, Analyst ve IT olmalıdır.

- **DR-15:** Bir analistin belirli bir varlık üzerindeki belirli bir
  güvenlik açığını incelediği kaydedilmelidir. İnceleme durumu ve tarihi
  tutulmalıdır.

- **DR-16:** Bir kurumsal varlığın sorumlusu bir iç departman veya dış
  tedarikçi olabilir. Her varlığın yalnızca bir sorumlusu bulunmalıdır.
  Bir departman veya tedarikçi birden fazla varlıktan sorumlu olabilir.

## 4.1. İş Kuralları

- **BR-01:** CVSS v3.1 puanı 0.0 ile 10.0 arasında olmalıdır. (CHECK)

- **BR-02:** Yama uygulama tarihi, ilgili yamanın yayın tarihinden önce
  olamaz. (TRIGGER)

- **BR-03:** Aynı ürün için aynı sürüm numarası iki kez kaydedilemez.
  (UNIQUE)

- **BR-04:** Bir güvenlik açığı silindiğinde ona bağlı etkilenen ürün
  sürümü ilişki kayıtları da silinmelidir. (ON DELETE CASCADE)

- **BR-05:** Her yama bir güvenlik açığına bağlı olmalıdır.
  (NOT NULL + FOREIGN KEY)

- **BR-06:** Bir yama uygulaması kaydedildiğinde otomatik olarak denetim
  kaydı oluşturulmalıdır. (TRIGGER)

- **BR-07:** Kullanıcı e-posta adresleri benzersiz olmalıdır. (UNIQUE)

- **BR-08:** Bir varlık yalnızca bir varlık türüne ve bir sorumluya ait
  olmalıdır.
- **BR-09:** Bir yama, yalnızca bağlı olduğu güvenlik açığından etkilenen
  bir ürün sürümünü kullanan varlığa uygulanabilir. (TRIGGER)

## 5. Fonksiyonel Gereksinimler

Her maddenin sonunda ilgili rol ve SQL karşılığı belirtilmiştir.

- **FR-01:** Güvenlik açığı eklenebilmeli.
  (Rol: Admin, Analist | SQL: INSERT)
- **FR-02:** Güvenlik açığı güncellenebilmeli.
  (Rol: Admin, Analist | SQL: UPDATE)
- **FR-03:** Güvenlik açığı silinebilmeli.
  (Rol: Admin | SQL: DELETE)
- **FR-04:** Güvenlik açıkları CVSS puanına göre filtrelenebilmeli.
  (Rol: Analist | SQL: SELECT / WHERE)
- **FR-05:** Bir güvenlik açığı, ilişkili zayıflık türleri ve etkilenen
  ürün sürümleriyle listelenebilmeli.
  (Rol: Analist | SQL: JOIN)
- **FR-06:** Ürün ve sürüm kayıtları yönetilebilmeli.
  (Rol: Admin | SQL: INSERT / UPDATE)
- **FR-07:** Kurumsal varlık eklenebilmeli ve kullandığı ürün sürümleri
  kaydedilebilmeli.
  (Rol: BT | SQL: INSERT)
- **FR-08:** Bir varlığı etkileyen güvenlik açıkları listelenebilmeli.
  (Rol: BT, Analist | SQL: Çok tablolu JOIN)
- **FR-09:** Belirli bir varlıkta uygulanmamış yaması bulunan güvenlik
  açıkları listelenebilmeli.
  (Rol: BT, Analist | SQL: İç içe sorgu)
- **FR-10:** Ürün başına etkilenen benzersiz güvenlik açığı sayısı ve
  ortalama CVSS puanı hesaplanabilmeli.
  (Rol: Analist | SQL: GROUP BY / HAVING)
- **FR-11:** Herhangi bir güvenlik açığından etkilenmeyen varlıklar
  listelenebilmeli.
  (Rol: BT | SQL: OUTER JOIN)
- **FR-12:** Kritik seviyedeki güvenlik açıklarının özeti sunulabilmeli.
  (Rol: Analist | SQL: VIEW)
- **FR-13:** Yama uygulaması kaydedilebilmeli ve otomatik denetim kaydı
  oluşturulmalı.
  (Rol: BT | SQL: INSERT + TRIGGER)
- **FR-14:** Analist incelemeleri kaydedilebilmeli ve listelenebilmeli.
  (Rol: Analist | SQL: INSERT / SELECT)
- **FR-15:** Kullanıcı ekleme, listeleme, güncelleme ve silme işlemleri
  gerçekleştirilebilmeli.
  (Rol: Admin | SQL: INSERT / SELECT / UPDATE / DELETE)

## 6. Kapsam Dışı

- Canlı güvenlik açığı taraması ve sızma testi.
- Yapay zekâ destekli güvenlik analizi.
- RAG ve chatbot entegrasyonu.
- Otomatik saldırı tespiti.
- Güvenlik süreçlerinin otomasyonu (triyaj iş akışı, risk skorlaması ve
  SLA takibi).
- NVD verilerinin tamamının sisteme aktarılması. Prototip kapsamında
  yaklaşık 20–30 örnek güvenlik açığı kullanılacaktır.
- Gerçek kullanıcı kimlik doğrulama, parola ve oturum yönetimi.
- Yamaların ürün sürümü bazında uygulanabilirliğinin ayrıca modellenmesi.

## 7. Proje Teknolojileri

- PostgreSQL
- SQL
- Python (gerektiğinde)
- Git ve GitHub

## 8. Ders Konuları Kapsama Matrisi

- **Zayıf varlık (Weak Entity):** Ürün sürümü (Ürün'e bağımlı)
- **1:N ilişki:** Üretici → Ürün, Ürün → Sürüm, CVE → Yama
- **M:N ilişki:** CVE ↔ CWE, CVE ↔ Sürüm, Varlık ↔ Sürüm,
  Varlık ↔ Yama
- **Çok değerli nitelik:** CVE referans bağlantıları
- **Bileşik nitelik:** Varlık konumu (bina, kat, oda)
- **Türetilmiş nitelik:** CVSS puanından türetilen ciddiyet seviyesi
- **Üçlü ilişki:** Analist – Varlık – CVE incelemesi
- **Specialization:** Varlık → Sunucu / Uç Nokta / Bulut
- **Union Type (Category):** Varlık sorumlusu → Departman veya Tedarikçi
- **Kısıtlar:** BR-01 … BR-08
- **Trigger:** BR-02, BR-06
- **View:** FR-12
- **Karmaşık sorgular:** FR-05, FR-08, FR-09, FR-10, FR-11
- **Normalizasyon:** Örnek başlangıç veri yapısından 1NF → 2NF → 3NF
  dönüşümü
- **CRUD işlemleri:** Güvenlik açığı, ürün, varlık ve kullanıcı
  kayıtlarının yönetimi
- **Trigger:** BR-02, BR-06, BR-09

## 9. Proje Başarı Ölçütleri

- Gereksinimlere uygun ER/EER diyagramının hazırlanması.
- İlişkisel şemanın oluşturulması ve normalizasyonun gösterilmesi.
- PostgreSQL üzerinde tabloların ve bütünlük kısıtlarının uygulanması.
- Örnek verilerin sisteme eklenmesi.
- Fonksiyonel gereksinimlerde belirtilen SQL sorgularının çalıştırılması.
- Trigger ve View mekanizmalarının test edilmesi.
- Proje sonuçlarının rapor ve sunum ile açıklanabilmesi.



Proje kapsamında, bir yama ilişkili olduğu güvenlik açığının etkilediği
ürün sürümleri için geçerli kabul edilmiştir. Yama ve ürün sürümü arasındaki
uygulanabilirlik ayrıca modellenmemiştir. Bu tercih, veritabanı tasarımını
sade tutmak amacıyla yapılmıştır.

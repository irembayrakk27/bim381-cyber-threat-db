# Veri Kaynakları (Data Sources)

## 1. Amaç

Bu belge, Siber Tehdit İstihbaratı ve Zafiyet Yönetim Sistemi
projesinde kullanılacak verilerin kaynaklarını ve kullanım
amaçlarını tanımlar.

Prototip kapsamında sınırlı sayıda örnek kayıt kullanılacaktır.
Tüm dış kaynakların sisteme otomatik aktarılması hedeflenmemektedir.

## 2. Dış Veri Kaynakları

| Kaynak | Sağladığı Veri | Kullanım Amacı |
|---|---|---|
| National Vulnerability Database (NVD) | CVE, CVSS ve zafiyetlerle ilişkili ek bilgiler | Güvenlik açığı kayıtlarının oluşturulması |
| MITRE Common Weakness Enumeration (CWE) | CWE kimliği, adı ve açıklaması | Zafiyetlerin zayıflık türleriyle ilişkilendirilmesi |
| Üreticilerin resmî güvenlik duyuruları | Etkilenen ürün/sürümler ve yayımlanan yamalar | Ürün, sürüm ve yama bilgilerinin doğrulanması |

## 3. Kurum İçi Veri Kaynakları

| Veri | Kaynak | Kullanım Amacı |
|---|---|---|
| Asset | Şirketin varlık envanteri | Sunucu, uç nokta ve bulut varlıklarının kaydı |
| User | Şirket kullanıcı kayıtları | Sistemde işlem yapan kullanıcıların tanımlanması |
| Department | Şirket organizasyon kayıtları | Varlıkların kurum içi sahipliğinin belirlenmesi |
| Supplier | Şirket tedarikçi kayıtları | Varlıkların dış tedarikçi sahipliğinin belirlenmesi |
| PatchApplication | Sistem kullanıcılarının uygulama kayıtları | Yama uygulama geçmişinin tutulması |
| AnalystReview | Analistlerin inceleme kayıtları | Varlık ve zafiyet değerlendirmelerinin saklanması |

## 4. Veri Kullanım ve Doğrulama İlkeleri

- CVE ve CVSS bilgileri için NVD esas alınacaktır.
- CWE tanımları için MITRE CWE kataloğu esas alınacaktır.
- Ürün, sürüm ve yama bilgileri mümkün olduğunda üreticinin
  resmî duyurularıyla doğrulanacaktır.
- Kurum içi veriler proje kapsamında örnek kayıtlarla temsil edilecektir.
- Kaynaklardan alınan bilgiler prototipte gerektiği ölçüde
  manuel olarak sisteme girilecektir.
- Kaynak verilerinin tamamının otomatik içe aktarılması
  proje kapsamı dışındadır.

## 5. Resmî Kaynaklar

1. NIST National Vulnerability Database:
   https://nvd.nist.gov/

2. NVD Data Feeds and APIs:
   https://nvd.nist.gov/vuln/data-feeds

3. MITRE Common Weakness Enumeration:
   https://cwe.mitre.org/

4. MITRE CWE Downloads:
   https://cwe.mitre.org/data/downloads.html

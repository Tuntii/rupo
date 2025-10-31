# SifreDB

Rust tabanlı alan-bazlı şifreleme kütüphanesi.

## Özellikler

- 🔐 AEAD şifreleme (ChaCha20-Poly1305, AES-GCM)
- 🔍 Kör indeks (blind index) ile aranabilir şifreleme
- 🔑 Envelope encryption (KEK/DEK ayrımı)
- 🔄 Anahtar rotasyonu desteği
- 🏢 Multi-tenant izolasyonu
- 🛡️ Deterministik şifreleme (eşitlik sorguları için)

## Kurulum

```toml
[dependencies]
sifredb = "0.1"
```

## Kullanım

```rust
use sifredb::prelude::*;

// Key provider oluştur
let provider = FileKeyProvider::new("./keys")?;
let vault = Vault::new(provider, CipherMode::default());

// Context tanımla
let context = EncryptionContext::new("users", "email")
    .with_tenant("tenant_123");

// Şifrele
let ciphertext = vault.encrypt(b"alice@example.com", &context)?;

// Deşifrele
let plaintext = vault.decrypt(&ciphertext, &context)?;
```

## Lisans

Apache-2.0 OR MIT

## Durum

🚧 Aktif geliştirme aşamasında

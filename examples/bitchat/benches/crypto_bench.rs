//! Criterion benchmarks for BitChat crypto operations
//!
//! Run with: cargo bench --features std

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

use sha2::{Sha256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, Signer, Verifier};

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            b.iter(|| {
                black_box(Sha256::digest(data))
            })
        });
    }

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let key = Key::from_slice(&[0x42u8; 32]);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    for size in [64, 128, 256, 512, 1024, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let plaintext = vec![0u8; *size];
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        group.bench_with_input(BenchmarkId::new("chacha20poly1305_encrypt", size), &plaintext, |b, data| {
            b.iter(|| {
                black_box(cipher.encrypt(nonce, data.as_ref()))
            })
        });

        group.bench_with_input(BenchmarkId::new("chacha20poly1305_decrypt", size), &ciphertext, |b, data| {
            b.iter(|| {
                black_box(cipher.decrypt(nonce, data.as_ref()))
            })
        });
    }

    group.finish();
}

fn bench_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");

    // X25519
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_public = PublicKey::from(&StaticSecret::random_from_rng(rand::thread_rng()));

    group.bench_function("x25519_dh", |b| {
        b.iter(|| {
            black_box(alice_secret.diffie_hellman(&bob_public))
        })
    });

    group.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let secret = StaticSecret::random_from_rng(rand::thread_rng());
            black_box(PublicKey::from(&secret))
        })
    });

    group.finish();
}

fn bench_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("signatures");

    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let message = [0u8; 64];
    let signature = signing_key.sign(&message);

    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(signing_key.sign(&message))
        })
    });

    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(verifying_key.verify(&message, &signature))
        })
    });

    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            black_box(SigningKey::generate(&mut rand::thread_rng()))
        })
    });

    group.finish();
}

fn bench_combined_message_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_flow");

    // Simulate full message encryption flow
    let key = Key::from_slice(&[0x42u8; 32]);
    let cipher = ChaCha20Poly1305::new(key);
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    group.bench_function("sign_then_encrypt_256b", |b| {
        let message = [0u8; 256];
        b.iter(|| {
            // Sign message
            let signature = signing_key.sign(&message);

            // Combine message + signature
            let mut payload = Vec::with_capacity(256 + 64);
            payload.extend_from_slice(&message);
            payload.extend_from_slice(signature.to_bytes().as_ref());

            // Generate nonce and encrypt
            let nonce = Nonce::from_slice(&[0u8; 12]);
            let ciphertext = cipher.encrypt(nonce, payload.as_ref()).unwrap();

            black_box(ciphertext)
        })
    });

    group.bench_function("decrypt_then_verify_256b", |b| {
        let message = [0u8; 256];
        let signature = signing_key.sign(&message);
        let mut payload = Vec::with_capacity(256 + 64);
        payload.extend_from_slice(&message);
        payload.extend_from_slice(signature.to_bytes().as_ref());
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ciphertext = cipher.encrypt(nonce, payload.as_ref()).unwrap();

        let verifying_key = signing_key.verifying_key();

        b.iter(|| {
            // Decrypt
            let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

            // Extract message and signature
            let msg = &decrypted[..256];
            let sig_bytes: [u8; 64] = decrypted[256..].try_into().unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            // Verify
            black_box(verifying_key.verify(msg, &sig))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hashing,
    bench_encryption,
    bench_key_exchange,
    bench_signatures,
    bench_combined_message_flow,
);

criterion_main!(benches);

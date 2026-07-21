# Cryptographic Security Audit Findings

## Finding 1: Missing Public Key Validation in `uECC_shared_secret` (Critical)

**File:** `uwb-ios/third_party/micro-ecc/uECC.c`, lines 1048-1091

**Vulnerable Code:**
```c
int uECC_shared_secret(const uint8_t *public_key,
                       const uint8_t *private_key,
                       uint8_t *secret,
                       uECC_Curve curve) {
    uECC_word_t _public[uECC_MAX_WORDS * 2];
    uECC_word_t _private[uECC_MAX_WORDS];
    // ...
    uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve->num_n_bits));
    uECC_vli_bytesToNative(_public, public_key, num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public_key + num_bytes, num_bytes);

    // NO CALL to uECC_valid_point() here!

    carry = regularize_k(_private, _private, tmp, curve);
    // ...
    EccPoint_mult(_public, _public, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);
    // ...
    return !EccPoint_isZero(_public, curve);
}
```

**Why it's exploitable:** `uECC_shared_secret` does NOT validate that the supplied public key is a valid point on the curve before performing scalar multiplication. While `uECC_valid_public_key()` exists (line 1155), it is never called inside `uECC_shared_secret`. An attacker can supply a crafted point of small order on a different curve (an invalid curve attack), or a point not on the curve at all, to recover the private key through repeated ECDH operations.

**Impact:** Complete private key recovery via invalid-curve attack. If an attacker can invoke ECDH with arbitrary public keys (e.g., during a UWB pairing protocol), they can recover the device's static ECDH private key in ~100 queries.

**Attack path:** Attacker sends malformed public key points during UWB ranging/secure channel establishment → `uECC_shared_secret` performs scalar multiplication on invalid point → attacker observes resulting shared secret (or authentication pass/fail behavior) → Chinese Remainder Theorem recovers private key bits.

---

## Finding 2: Weak "Encrypted" Private Key Export - No Password, 1 Iteration (High)

**File:** `uwb-ios/internal/crypto_cros/ec_private_key.cc`, lines 131-154

**Vulnerable Code:**
```cpp
bool ECPrivateKey::ExportEncryptedPrivateKey(
    std::vector<uint8_t>* output) const {
  // ...
  if (!CBB_init(cbb.get(), 0) ||
      !PKCS8_marshal_encrypted_private_key(
          cbb.get(), NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
          nullptr /* cipher */, nullptr /* no password */, 0 /* pass_len */,
          nullptr /* salt */, 0 /* salt_len */, 1 /* iterations */,
          key_.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
```

**Why it's exploitable:** The function encrypts a private key with:
- **No password** (`nullptr`, length 0)
- **No salt** (`nullptr`, length 0)
- **1 iteration** of the PBE KDF
- **3DES-CBC** (deprecated cipher)

This means the "encryption" is completely deterministic and trivially reversible. The encryption key is derived from an empty password with no salt in a single iteration — it's effectively a constant.

**Impact:** Any private key "encrypted" via this function provides zero confidentiality. If these encrypted keys are stored on disk or transmitted, they can be instantly decrypted by anyone who reads the blob.

**Attack path:** Attacker gains read access to stored encrypted key blobs (file system, backup, memory dump) → derives the deterministic encryption key from empty password/salt/single iteration → decrypts private key → impersonates device in UWB protocols.

---

## Finding 3: CBC Encryption Without Authentication (Padding Oracle) (High)

**File:** `uwb-ios/internal/crypto_cros/encryptor.cc`, lines 164-200  
**File:** `uwb-ios/third_party/securemessage/securemessage/cpp/src/securemessage/crypto_ops_openssl.cc`, lines 183-261

**Vulnerable Code (encryptor.cc):**
```cpp
absl::optional<size_t> Encryptor::Crypt(bool do_encrypt,
                                        absl::Span<const uint8_t> input,
                                        absl::Span<uint8_t> output) {
  // ...
  if (!EVP_CipherFinal_ex(ctx.get(), output.data() + out_len, &tail_len))
    return absl::nullopt;  // Returns failure on padding error
  // ...
}
```

The header (`encryptor.h`, line 66) explicitly warns:
> "WARNING: In CBC mode, Decrypt() returns false if it detects the padding in the decrypted plaintext is wrong... But successful decryption does not imply the authenticity of the data."

**Why it's exploitable:** The `Encryptor` class provides AES-CBC without any MAC/authentication. If callers use `Decrypt()` and propagate the success/failure result to an attacker (directly or through observable behavior), it creates a classic padding oracle. The header warning acknowledges this but the code still exists and is available for callers to misuse.

The securemessage `Aes256CBCDecrypt` (crypto_ops_openssl.cc, line 245) similarly reports padding errors distinctly from other failures.

**Impact:** Padding oracle allows full plaintext recovery of any AES-CBC ciphertext encrypted with a known key, one byte at a time, with ~128 queries per byte on average.

**Attack path:** Attacker intercepts encrypted UWB protocol messages → submits modified ciphertexts and observes whether decryption succeeds or fails (or different error behavior/timing) → iteratively recovers plaintext through standard padding oracle technique.

---

## Finding 4: CTR Mode Counter Mutation Enables Keystream Reuse (Medium-High)

**File:** `uwb-ios/internal/crypto_cros/encryptor.cc`, lines 202-226

**Vulnerable Code:**
```cpp
absl::optional<size_t> Encryptor::CryptCTR(bool do_encrypt,
                                           absl::Span<const uint8_t> input,
                                           absl::Span<uint8_t> output) {
  // ...
  uint8_t ecount_buf[AES_BLOCK_SIZE] = {0};
  unsigned int block_offset = 0;

  // Note AES_ctr128_encrypt() will update |iv_|.
  AES_ctr128_encrypt(input.data(), output.data(), input.size(), &aes_key,
                     iv_.data(), ecount_buf, &block_offset);
  return input.size();
}
```

**Why it's exploitable:** `AES_ctr128_encrypt()` modifies `iv_` in-place (it increments the counter). However, `ecount_buf` and `block_offset` are discarded after each call (they're local variables). If a caller invokes `Encrypt` or `Decrypt` multiple times on the same `Encryptor` instance without calling `SetCounter()` in between, the counter will continue from where it left off — but if they DO call `SetCounter()` with the same initial value, or if the `Encryptor` is reused with the same key+counter across messages, the exact same keystream is produced. The class provides no safeguard against counter reuse.

More critically, if `CryptCTR` is called with a message that doesn't fill a complete block, the partial block state (`ecount_buf`, `block_offset`) is lost. A subsequent call would re-encrypt starting at the next full block boundary of the counter, but the leftover keystream bytes from the partial block are lost, potentially causing incorrect encryption (not a confidentiality issue but an integrity issue).

**Impact:** If the `Encryptor` is reused with `SetCounter()` called with the same nonce value, XOR of two ciphertexts reveals XOR of plaintexts, breaking confidentiality entirely.

**Attack path:** Protocol reuses CTR counter values across sessions or messages (common in UWB ranging where counters might reset) → attacker captures two ciphertexts with same counter → XORs them to recover plaintext XOR → applies crib-dragging or known-plaintext to recover individual messages.

---

## Finding 5: Unchecked Protobuf Deserialization Return Values (Medium)

**File:** `uwb-ios/third_party/securemessage/securemessage/cpp/src/securemessage/secure_message_parser.cc`, lines 84-91, 112-119

**Vulnerable Code:**
```cpp
std::unique_ptr<HeaderAndBody> SecureMessageParser::ParseSignedCleartextMessage(
    // ...
  if (header_and_body_bytes != nullptr) {
    HeaderAndBody *header_and_body = new HeaderAndBody();
    header_and_body->ParseFromString(*header_and_body_bytes);  // Return value UNCHECKED
    return std::unique_ptr<HeaderAndBody>(header_and_body);
  }
```

And identically at line 114:
```cpp
    HeaderAndBody *header_and_body = new HeaderAndBody();
    header_and_body->ParseFromString(*header_and_body_bytes);  // Return value UNCHECKED
    return std::unique_ptr<HeaderAndBody>(header_and_body);
```

**Why it's exploitable:** After signature verification passes in `RawSecureMessageParser`, the resulting bytes are deserialized into a `HeaderAndBody` proto without checking if `ParseFromString` succeeded. If the verified bytes produce a partial or malformed proto (e.g., due to protobuf field confusion or a legitimate but unusual encoding), the caller receives a partially-initialized `HeaderAndBody` object. Missing required fields would have default/zero values rather than being flagged as invalid.

**Impact:** An attacker who can craft a message that passes signature verification but contains a malformed protobuf body could cause the consumer to operate on default/zero field values. This could lead to logic bypasses depending on how downstream code interprets the fields.

**Attack path:** Attacker signs a valid message with carefully crafted binary content that is valid for signature verification but causes protobuf parsing to partially fail → application receives proto with default field values → potentially bypasses access control checks that depend on field contents.

---

## Finding 6: Signature Verification Timing Leak in `VerifyHeaderAndBody` (Medium)

**File:** `uwb-ios/third_party/securemessage/securemessage/cpp/src/securemessage/raw_secure_message_parser.cc`, lines 134-179

**Vulnerable Code:**
```cpp
bool RawSecureMessageParser::VerifyHeaderAndBody(
    const string& signature, const string& header_and_body,
    const CryptoOps::Key& verification_key, CryptoOps::SigType sig_type,
    CryptoOps::EncType enc_type, const string& associated_data,
    bool suppress_associated_data) {

  string signed_data = header_and_body;
  if (!suppress_associated_data) {
    signed_data.append(associated_data);
  }
  bool verified =
      CryptoOps::Verify(sig_type, verification_key, signature, signed_data);

  unique_ptr<string> header =
      SecureMessageWrapper::ParseHeader(header_and_body);

  if (header == nullptr) {
    Util::LogError("message must have header");
    return false;  // EARLY RETURN before timing-safe checks
  }

  // Does not return early in order to avoid timing attacks
  verified &= SecureMessageWrapper::GetSigScheme(sig_type) == ...
  verified &= SecureMessageWrapper::GetEncScheme(enc_type) == ...
  verified &= associated_data.length() == ...
```

**Why it's exploitable:** The comment says "Does not return early in order to avoid timing attacks" — yet there IS an early return at line `if (header == nullptr) { return false; }`. This early return breaks the constant-time property. While the CryptoOps::Verify for HMAC uses constant-time comparison (`ByteBuffer::Equals`), the early return on `ParseHeader` failure creates a timing difference observable to an attacker: messages with unparseable headers return faster than messages with parseable headers but invalid signatures.

**Impact:** An attacker can distinguish between "message has no valid header" vs "message has valid header structure but wrong signature," which leaks structural information about expected message format and could be used to guide further attacks.

**Attack path:** Attacker submits messages and measures response times → distinguishes header-parse-failure (fast) from signature-check-failure (slower) → uses this oracle to understand expected message structure for further forgery attempts.

---

## Finding 7: `uECC_sign_with_k` Exposes Deterministic Nonce API (Medium)

**File:** `uwb-ios/third_party/micro-ecc/uECC.c`, lines 1330-1339

**Vulnerable Code:**
```c
/* For testing - sign with an explicitly specified k value */
int uECC_sign_with_k(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uint8_t *k,
                            uint8_t *signature,
                            uECC_Curve curve) {
    uECC_word_t k2[uECC_MAX_WORDS];
    bits2int(k2, k, BITS_TO_BYTES(curve->num_n_bits), curve);
    return uECC_sign_with_k_internal(private_key, message_hash, hash_size, k2, signature, curve);
}
```

**Why it's exploitable:** This function is explicitly labeled "For testing" but is compiled into the production library (it is not guarded by any `#ifdef TEST` or similar conditional). It allows signing with a caller-specified `k` value. If any code path calls this with a reused or predictable `k`, the private key is immediately recoverable via the standard ECDSA nonce-reuse attack: `private_key = (s*k - hash) / r mod n`.

**Impact:** If this function is ever called in production with a reused nonce value, the ECDSA private key is fully recovered from two signatures.

**Attack path:** If any caller of this function reuses `k` for two different messages (or uses a predictable k) → attacker observes two signatures (r, s1) and (r, s2) with same r → computes k and then recovers private key algebraically.

---

## Finding 8: No Subgroup Order Validation in `uECC_verify` for Public Key (Medium)

**File:** `uwb-ios/third_party/micro-ecc/uECC.c`, lines 1489-1599

**Vulnerable Code:**
```c
int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve) {
    // ...
    // Parses public key directly from input
    uECC_vli_bytesToNative(_public, public_key, curve->num_bytes);
    uECC_vli_bytesToNative(
        _public + num_words, public_key + curve->num_bytes, curve->num_bytes);
    // ...
    // NO validation that _public is a valid curve point
    // Proceeds directly to signature verification math
```

**Why it's exploitable:** `uECC_verify` does not call `uECC_valid_point()` on the supplied public key before using it in the signature verification computation. While this doesn't directly allow forging signatures for a legitimate public key, it means that if an attacker can substitute an invalid public key (e.g., a point not on the curve or the identity point), the verification math may produce unexpected results. Combined with the `uECC_vli_isZero` check for r and s, certain degenerate inputs could cause the function to accept invalid signatures for crafted public keys.

**Impact:** In protocols where the public key is received from an untrusted source alongside the signature (rather than being pre-provisioned), an attacker can potentially craft a (public_key, signature, message) triple that passes verification even though no legitimate signer produced the signature.

**Attack path:** Attacker supplies both public key and signature in a protocol message → uses a carefully chosen invalid curve point as public key → crafts signature values that pass the mathematical checks → bypasses signature verification for attacker-controlled "identity."

---

## Summary

| # | Finding | Severity | File |
|---|---------|----------|------|
| 1 | Missing public key validation in ECDH | Critical | uECC.c:1048 |
| 2 | Encrypted key export with no password | High | ec_private_key.cc:131 |
| 3 | CBC without authentication (padding oracle) | High | encryptor.cc:164 |
| 4 | CTR counter reuse enabling keystream reuse | Medium-High | encryptor.cc:202 |
| 5 | Unchecked protobuf deserialization | Medium | secure_message_parser.cc:84 |
| 6 | Timing leak via early return in verification | Medium | raw_secure_message_parser.cc:134 |
| 7 | Test-only sign-with-k in production code | Medium | uECC.c:1330 |
| 8 | No public key validation in signature verify | Medium | uECC.c:1489 |

# Security Audit: Nearby Share, Fast Pair, and Presence — New Findings

## Finding 1: HMAC Key Commitment Uses All-Zero Key — Authentication Bypass (Sharing Certificates)

**File:** `sharing/certificates/nearby_share_decrypted_public_certificate.cc`
**Lines:** 110–119

```cpp
bool VerifyMetadataEncryptionKeyTag(
    absl::Span<const uint8_t> decrypted_metadata_key,
    absl::Span<const uint8_t> metadata_encryption_key_tag) {
  // This array of 0x00 is used to conform with the GmsCore implementation.
  std::vector<uint8_t> key(kNearbyShareNumBytesMetadataEncryptionKeyTag, 0x00);

  std::vector<uint8_t> result(kNearbyShareNumBytesMetadataEncryptionKeyTag);
  crypto::HMAC hmac(crypto::HMAC::HashAlgorithm::SHA256);
  return hmac.Init(key) &&
         hmac.Verify(decrypted_metadata_key, metadata_encryption_key_tag);
}
```

The HMAC key used for the metadata encryption key tag is a hardcoded 32-byte array of `0x00`. This same zero key is used in the tag creation function in `nearby_share_private_certificate.cc:83`. An HMAC's security relies on a secret key; using a fixed, publicly known key (all zeros) means any party can compute a valid HMAC tag for any metadata encryption key. The "verification" provides no cryptographic authentication — it is equivalent to an unkeyed hash.

**Impact:** An attacker who intercepts or crafts a `PublicCertificate` can compute the correct `metadata_encryption_key_tag` for any chosen `metadata_encryption_key`, bypassing the key commitment check in `DecryptPublicCertificate()` (line 165). This allows forging certificates that decrypt successfully.

**Severity:** High

---

## Finding 2: Presence AES-GCM Uses Deterministic Nonce Derived From Key Seed (credential_manager_impl.cc)

**File:** `presence/implementation/credential_manager_impl.cc`
**Lines:** 310, 333

```cpp
auto iv = CustomizeBytesSize(key_seed, CredentialManagerImpl::kAesGcmIVSize);
```

The AES-256-GCM nonce (IV) for encrypting/decrypting device identity metadata is deterministically derived from `key_seed` using HKDF (via `CustomizeBytesSize`). Since `key_seed` is the `secret_key` of the `LocalCredential` (set once at credential creation, line 219), the same nonce is used every time metadata is encrypted with that credential. AES-GCM requires unique nonces for each encryption under the same key; reusing a nonce allows an attacker who observes two ciphertexts encrypted with the same key and nonce to XOR them and recover plaintext, and can also lead to authentication key recovery.

Additionally, `CustomizeBytesSize` uses HKDF with an all-zero salt (line 91: `std::string(kAuthenticityKeyByteSize, 0)`), which weakens the key derivation.

**Impact:** Nonce reuse under AES-GCM breaks both confidentiality and authenticity of encrypted device identity metadata. If `EncryptDeviceIdentityMetaData` is called more than once with the same credential (e.g., during credential refresh or re-encryption), an attacker can recover plaintext metadata and forge authenticated ciphertexts.

**Severity:** High

---

## Finding 3: `DecryptDeviceIdentityMetaData` Dereferences `std::optional` Without Checking for Failure (credential_manager_impl.cc)

**File:** `presence/implementation/credential_manager_impl.cc`
**Lines:** 315–320

```cpp
auto result = aead.Open(encrypted_metadata_bytes,
                        /*nonce=*/iv_bytes,
                        /*additional_data=*/absl::Span<uint8_t>());

return std::string(result.value().begin(), result.value().end());
```

`aead.Open()` returns an `std::optional<std::vector<uint8_t>>`. If decryption fails (e.g., tampered ciphertext, wrong key, or corrupted nonce), the optional is empty. Calling `.value()` on an empty `std::optional` throws `std::bad_optional_access` or is undefined behavior depending on the configuration. There is no check for `result.has_value()` before dereferencing.

Note: The already-reported "Unchecked optional after AEAD failure" in `credential_manager_impl.cc` refers to a different code path. This finding specifically targets `DecryptDeviceIdentityMetaData` at line 320, which is a separate function from the previously reported issue.

**Impact:** A corrupted or maliciously crafted credential causes a crash (unhandled exception or UB) when the Presence system attempts to decrypt device identity metadata. This is a denial-of-service vector that can be triggered by providing invalid `SharedCredential` data.

**Severity:** Medium

---

## Finding 4: Fast Pair API Client — Array Out-of-Bounds Access on Untrusted Proto Enum (fast_pair_client_impl.cc)

**File:** `fastpair/server_access/fast_pair_client_impl.cc`
**Lines:** 65–66, 116

```cpp
const char* GetObservedDeviceMode[3] = {"MODE_UNKNOWN", "MODE_RELEASE",
                                        "MODE_DEBUG"};
// ...
params.push_back({std::string(kMode), GetObservedDeviceMode[request.mode()]});
```

`GetObservedDeviceMode` is a C-style array of 3 elements (indices 0–2). `request.mode()` returns a protobuf enum value of type `GetObservedDeviceRequest::Mode`. While the proto defines values 0, 1, and 2, protobuf enums in C++ are integer types that can hold any value received on the wire. A malformed or maliciously crafted `GetObservedDeviceRequest` with `mode()` set to 3 or higher results in an out-of-bounds array access with no bounds check.

**Impact:** Out-of-bounds read on a stack/static array. Can crash the process or leak adjacent memory contents into the HTTP query parameter, potentially exposing sensitive data in the API request URL.

**Severity:** Medium

---

## Finding 5: Fast Pair API Client — Hardcoded API Key in Source Code (fast_pair_client_impl.cc)

**File:** `fastpair/server_access/fast_pair_client_impl.cc`
**Lines:** 51–52

```cpp
constexpr absl::string_view kClientId =
    "AIzaSyBv7ZrOlX5oIJLVQrZh-WkZFKm5L6FlStQ";
```

A Google API key is hardcoded in the source code and sent as a query parameter (`key=...`) in every API request (line 309). This key is embedded in a public/open-source repository. Hardcoded API keys in source code violate security best practices: the key cannot be rotated without a code change, and anyone with access to the source can use the key, potentially exhausting quotas or performing unauthorized API calls.

**Impact:** API key exposure enables quota abuse, unauthorized data access to the Fast Pair backend, and makes key rotation operationally difficult.

**Severity:** Medium

---

## Finding 6: Fast Pair API Client — URL Path Injection via `hex_account_key` (fast_pair_client_impl.cc)

**File:** `fastpair/server_access/fast_pair_client_impl.cc`
**Lines:** 246–247

```cpp
CreateV1RequestUrl(std::string(kUserDeleteDevicePath) +
                   "/" + request.hex_account_key()),
```

The `hex_account_key` from the `UserDeleteDeviceRequest` proto is directly concatenated into the URL path without any validation or sanitization. While `hex_account_key` is expected to be a hex-encoded string, if an attacker can control this field (e.g., via a compromised paired device or malformed backend response), they could inject path traversal sequences (`../`) or other URL components to redirect the DELETE request to an unintended API endpoint.

**Impact:** A malicious `hex_account_key` containing `/` or `..` characters can manipulate the target URL path, potentially causing deletion of unintended resources on the backend or making requests to arbitrary API endpoints under the same host.

**Severity:** Medium

---

## Finding 7: Unencrypted KEEP_ALIVE Frames Accepted on Encrypted Channel (base_endpoint_channel.cc)

**File:** `connections/implementation/base_endpoint_channel.cc`
**Lines:** 150–166

```cpp
// It could be a protocol race, where remote party sends a KEEP_ALIVE
// before encryption is setup on their side...
result = {};
auto parsed = parser::FromBytes(ByteArray(input));
if (parsed.ok()) {
  if (parser::GetFrameType(parsed.result()) ==
      location::nearby::connections::V1Frame::KEEP_ALIVE) {
    NEARBY_LOGS(INFO)
        << __func__
        << ": Read unencrypted KEEP_ALIVE on encrypted channel.";
    result = ByteArray(input);
```

After encryption is enabled, if decryption of an incoming message fails, the code falls back to parsing the raw (unencrypted) bytes. If the frame is a `KEEP_ALIVE`, it is accepted and processed as if it were legitimate. The TODO comment acknowledges this should happen "at most once per session," but no such enforcement exists. An active attacker on the communication channel can inject arbitrary unencrypted `KEEP_ALIVE` frames, which will be accepted on the encrypted channel without any authentication.

**Impact:** An active MITM attacker can inject unauthenticated `KEEP_ALIVE` frames to keep a connection alive indefinitely, preventing idle timeouts and potentially maintaining access to a stale session. The lack of a "once per session" check means this can be exploited repeatedly.

**Severity:** Medium

---

## Finding 8: Fast Pair AES-ECB Encryption Uses Debug-Only Key Validation (fast_pair_encryption.cc / fast_pair_decryption.cc)

**File:** `fastpair/crypto/fast_pair_encryption.cc:157`, `fastpair/crypto/fast_pair_decryption.cc:43`

```cpp
// fast_pair_encryption.cc:157
DCHECK(aes_key_was_set == 0) << "Invalid AES key size.";

// fast_pair_decryption.cc:43
CHECK(aes_key_was_set == 0) << "Invalid AES key size.";
```

In `fast_pair_encryption.cc`, the AES key validity check uses `DCHECK`, which is compiled out in release builds. If `AES_set_encrypt_key` fails (returns non-zero) in a release build, execution continues with an uninitialized `AES_KEY` structure, and `AES_encrypt` is called with this corrupted key state. This produces garbage ciphertext that appears encrypted but provides no security.

In `fast_pair_decryption.cc`, the check uses `CHECK` (which terminates in release builds), creating an inconsistency: encryption silently produces bad output while decryption crashes.

**Impact:** In release builds, if a malformed AES key is passed to `EncryptBytes`, the function silently produces corrupted ciphertext with an uninitialized key schedule. This could lead to data being transmitted in a weakly-encrypted or predictable form. The inconsistency between `DCHECK` and `CHECK` means encryption fails silently while decryption crashes.

**Severity:** Medium

---

## Finding 9: Presence Advertisement Decoder Accepts Crafted Data Elements That Leak Heap State (advertisement_decoder_impl.cc)

**File:** `presence/implementation/advertisement_decoder_impl.cc`
**Lines:** 127–153

```cpp
absl::StatusOr<DataElement> ParseDataElement(const absl::string_view input,
                                             size_t& index) {
  // ...
  uint8_t data_type = GetDataElementType(header);
  size_t length = GetDataElementTrueLength(header);
  ++index;
  size_t start = index;
  index += length;
  if (index > input.size()) {
    return absl::OutOfRangeError(...);
  }
  return DataElement(data_type, input.substr(start, length));
}
```

While the bounds check at line 144 prevents direct out-of-bounds reads, the `GetDataElementTrueLength` function (lines 111–125) adds fixed offsets to the header-encoded length for encrypted identities (`+kEncryptedIdentityAdditionalLength = +18`) and Eddystone IDs (`+kEddystoneAdditionalLength = +20`). The `IsDataElementAllowed` function (line 135) performs range checks on the header-encoded length but these checks do not account for the additional length added by `GetDataElementTrueLength`. For example, an encrypted identity with header-encoded length 6 passes `IsDataElementAllowed` (line 67: `length >= 2 && length <= 6`), but the true length becomes 24 (6+18). If the advertisement payload has exactly `start + 6` bytes remaining, the bounds check at line 144 will catch this, but the error message leaks the exact advertisement size and hex contents via `absl::BytesToHexString(input)` (lines 131, 146), which exposes raw advertisement bytes in error logs.

**Impact:** Crafted advertisements with carefully chosen data element lengths can trigger error paths that log the full raw advertisement bytes in hex, leaking sensitive advertisement content (including encrypted payloads) to system logs. An attacker with log access can recover encrypted advertisement data.

**Severity:** Low–Medium

---

## Finding 10: Presence Broadcast Salt Reuse After 128 Retries (broadcast_manager.cc)

**File:** `presence/implementation/broadcast_manager.cc`
**Lines:** 66–81

```cpp
std::string SelectSalt(LocalCredential& credential,
                       absl::string_view preferred_salt) {
  constexpr int kMaxSaltSelectRetries = 128;

  uint16_t s = SaltToInt(preferred_salt);
  for (int i = 0; i < kMaxSaltSelectRetries; i++) {
    if (!credential.consumed_salts().contains(s)) {
      break;
    }
    s = nearby::RandData<uint16_t>();
  }
  credential.mutable_consumed_salts()->insert({s, true});
  return SaltFromInt(s);
}
```

After 128 random attempts, if no unused salt is found, the function returns the last randomly generated salt regardless of whether it was already consumed. With a 16-bit salt space (65,536 possible values) and no check after the loop exits, once a credential has consumed a significant fraction of salts, reuse becomes likely. Salt reuse in LDT-encrypted Presence advertisements enables correlation attacks: an observer who sees the same salt used with the same credential can link advertisements to the same device, defeating the privacy guarantees of encrypted advertisements.

**Impact:** Salt reuse enables advertisement linkability, allowing an attacker to track a device across time by correlating repeated salt values. This undermines the privacy protections of encrypted Presence advertisements.

**Severity:** Medium

---

## Finding 11: Sharing Certificate `DecryptPublicCertificate` Does Not Verify Certificate Validity Period (nearby_share_decrypted_public_certificate.cc)

**File:** `sharing/certificates/nearby_share_decrypted_public_certificate.cc`
**Lines:** 126–192

```cpp
std::optional<NearbyShareDecryptedPublicCertificate>
NearbyShareDecryptedPublicCertificate::DecryptPublicCertificate(
    const nearby::sharing::proto::PublicCertificate& public_certificate,
    const NearbyShareEncryptedMetadataKey& encrypted_metadata_key) {
  // ...
  if (!IsDataValid(not_before, not_after, public_key, secret_key.get(), id,
                   encrypted_metadata, metadata_encryption_key_tag)) {
    return std::nullopt;
  }
  // Decrypts and returns successfully — no time validity check
```

The `DecryptPublicCertificate` function validates structural data (key sizes, non-empty fields, time ordering via `not_before < not_after`) but does not check whether the certificate is currently valid (i.e., whether the current time falls within `[not_before, not_after]`). While `IsDataValid` checks `not_before < not_after`, it does not compare against the current time. This means expired certificates are successfully decrypted and returned as valid.

Note: While expired certificate acceptance was reported for `nearby_share_certificate_manager_impl.cc`, this finding identifies that the decryption function itself — the core certificate validation gate — lacks any temporal check, meaning expired certificates pass through even if higher-level code attempts filtering.

**Impact:** Expired or not-yet-valid certificates can be used to successfully authenticate devices, undermining certificate revocation and rotation. An attacker with an old certificate can continue to impersonate a device after the certificate should have been retired.

**Severity:** Medium (distinct from the already-reported manager-level finding; this is a defense-in-depth gap in the core decryption path)

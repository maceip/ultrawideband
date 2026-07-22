# Security Vulnerability Audit Report — iOS Nearby Connections

**Date:** 2026-07-22
**Scope:** `uwb-ios/connections/swift/`, `uwb-ios/internal/platform/implementation/apple/`, `uwb-ios/connections/c/`, `uwb-ios/connections/dart/`, Example app

This report covers NEW findings only. Previously reported issues (default delegate auto-accept, BLE `NSUInteger` underflow, `GNCInputStream` buffer over-read, `GNSSocket` unbounded reassembly, `GNCMBleUtils.mm` parsing crash, `client_socket.cc` unchecked `.value()`, `bluetooth_adapter.cc` `SNPrintF` UB) are not duplicated.

---

## Finding 1 — CPPInputStream::Read uses uninitialized heap buffer

**File:** `connections/swift/NearbyCoreAdapter/Sources/CPPInputStream.mm:30-40`
**Severity:** High
**Type:** Use of uninitialized memory / potential information leak

```cpp
ExceptionOr<ByteArray> CPPInputStream::Read(std::int64_t size) {
  std::vector<uint8_t> buffer;
  buffer.reserve(size);                               // (1) reserve — does NOT zero-fill
  NSInteger numberOfBytesRead = [iStream_ read:buffer.data() maxLength:size];  // (2) writes into raw capacity
  ...
  return ExceptionOr<ByteArray>(ByteArray((const char *)buffer.data(), numberOfBytesRead));
}
```

`reserve()` allocates capacity but does **not** initialize the memory and does not change the vector's size. The call at (2) writes into the raw capacity area, which is technically valid at the pointer level, but if `[iStream_ read:maxLength:]` returns fewer bytes than `size`, the `ByteArray` at (3) is constructed with `numberOfBytesRead` bytes — this is *correct in count* but the vector's internal bookkeeping (`.size()`) remains 0, so any later operation that queries `buffer.size()` would return 0. More critically, if a custom `NSInputStream` subclass writes **fewer** bytes than it reports (or if the underlying read partially fails and leaves gaps), the buffer contains uninitialized heap data that gets forwarded into a `ByteArray` and transmitted to a remote peer, constituting an **information disclosure** of heap contents.

**Remediation:** Replace `reserve` with `resize` to zero-initialize the buffer, or use `resize` and then truncate with `numberOfBytesRead`.

---

## Finding 2 — GNCCoreAdapter uses `defaultCStringEncoding` for service/endpoint IDs

**File:** `connections/swift/NearbyCoreAdapter/Sources/GNCCoreAdapter.mm:139, 197, 240, 286, 331, 349, 377, 401`
**Severity:** Medium
**Type:** Data corruption / potential crash from encoding mismatch

Throughout `GNCCoreAdapter.mm`, NSString-to-C++ conversions use:
```objc
std::string service_id = [serviceID cStringUsingEncoding:[NSString defaultCStringEncoding]];
```

`[NSString defaultCStringEncoding]` returns a **locale-dependent** encoding (e.g., `NSISOLatin1StringEncoding` on some systems). If the string contains characters that cannot be represented in the default encoding, `cStringUsingEncoding:` returns `NULL`. This NULL is then passed to the `std::string` constructor, triggering **undefined behavior** (constructing `std::string` from a null pointer). This can crash the application.

On a Japanese-locale device, for example, the default encoding might be `NSShiftJISStringEncoding`, and even ASCII-representable strings may behave differently across locales.

**Remediation:** Use `NSUTF8StringEncoding` consistently, and check the return value for `nil` before constructing `std::string`.

---

## Finding 3 — Dangling pointer to stack-local data in `NcAcceptConnection` payload callback

**File:** `connections/c/nc.cc:476-497`
**Severity:** High
**Type:** Use-after-free / dangling pointer

```cpp
cpp_payload_listener.payload_cb =
    [=](absl::string_view endpoint_id, ::nearby::connections::Payload payload) {
      NC_PAYLOAD nc_payload;
      ...
      if (nc_payload.type == NC_PAYLOAD_TYPE_BYTES) {
        nearby::ByteArray bytes = payload.AsBytes();      // (1) local variable
        nc_payload.content.bytes.content.data = bytes.data();  // (2) pointer into local
        nc_payload.content.bytes.content.size = bytes.size();
      } else if (nc_payload.type == NC_PAYLOAD_TYPE_FILE) {
        nc_payload.content.file.file_name =
            (char*)payload.GetFileName().c_str();           // (3) temporary string
        nc_payload.content.file.parent_folder =
            (char*)payload.GetParentFolder().c_str();       // (4) temporary string
        ...
      }
      payload_listener.received_callback(
          instance, convertStringToInt(endpoint_id), &nc_payload);  // (5) callback uses dangling ptrs
    };
```

At (1), `bytes` is a local `ByteArray`. At (2), its internal data pointer is stored. At (3)–(4), `GetFileName()` and `GetParentFolder()` return **temporary `std::string` objects** whose lifetime ends at the semicolon — making the stored `char*` pointers immediately dangling. At (5), the callback dereferences these dangling pointers.

For the `NC_PAYLOAD_TYPE_BYTES` path, the `ByteArray bytes` local variable is still alive when the callback fires (same scope), so that specific path is technically safe. However, for `NC_PAYLOAD_TYPE_FILE`, **the `file_name` and `parent_folder` pointers are dangling** because the temporary strings returned by `GetFileName()` / `GetParentFolder()` are destroyed before the callback invocation at (5).

**Remediation:** Store the filename and parent folder strings in local `std::string` variables that outlive the callback invocation.

---

## Finding 4 — `GetCppConnectionRequestInfo` passes pointer to callback-scoped temporary data

**File:** `connections/c/nc.cc:125-148`
**Severity:** High
**Type:** Dangling pointer / use-after-free

```cpp
cpp_connection_listener.initiated_cb =
    [=](const std::string &endpoint_id,
        const ::nearby::connections::ConnectionResponseInfo &info) {
      NC_CONNECTION_RESPONSE_INFO connection_response_info;
      connection_response_info.remote_endpoint_info.data =
          (char*)info.remote_endpoint_info.data();     // pointer into info
      ...
      connection_response_info.authentication_token.data =
          (char*)info.authentication_token.data();     // pointer into info
      ...
      connection_request_info.initiated_callback(
          instance, convertStringToInt(endpoint_id),
          &connection_response_info);                  // passes stack pointer
    };
```

The `connection_response_info` struct holds raw pointers into `info`'s internal string buffers. Since `info` is passed by const reference from the C++ core, the pointers are valid only as long as the callback scope is executing. If the user-supplied `initiated_callback` stores the `NC_CONNECTION_RESPONSE_INFO*` for later use (which is a natural pattern in async code), it will dereference freed memory.

Furthermore, the `NC_CONNECTION_RESPONSE_INFO` struct itself is stack-allocated and the callback receives a **pointer** to it — if the callback dispatches asynchronously (common in UI code), the pointer becomes invalid.

**Remediation:** Copy the data into heap-allocated buffers, or document clearly that the pointer is only valid during callback execution and provide a copy API.

---

## Finding 5 — `core_adapter.cc` `SendPayload` only sends to the first endpoint, ignoring the rest

**File:** `connections/c/core_adapter.cc:225-237`
**Severity:** Medium
**Type:** Logic bug / potential security bypass

```cpp
void SendPayload(connections::Core *pCore,
                 const char **endpoint_ids, size_t endpoint_ids_size,
                 PayloadW payloadw, ResultCallbackW callback) {
  ...
  std::string payloadData = std::string(*endpoint_ids);  // (1) only first endpoint
  absl::Span<const std::string> span{&payloadData, 1};   // (2) span of size 1
  pCore->SendPayload(span, ...);
}
```

The function signature accepts an array of endpoint IDs (`endpoint_ids_size` count), but the implementation at (1) only dereferences the first element and creates a span of size 1. All additional endpoint IDs are silently ignored. If an application relies on multi-cast payload delivery for security-critical operations (e.g., sending a key rotation to all connected peers), some peers would never receive the payload without any error indication.

**Remediation:** Iterate over all `endpoint_ids_size` elements and build a properly-sized vector/span.

---

## Finding 6 — `core_adapter.cc` `GetLocalEndpointId` leaks allocated memory

**File:** `connections/c/core_adapter.cc:270-278`
**Severity:** Low
**Type:** Memory leak

```cpp
const char *GetLocalEndpointId(connections::Core *pCore) {
  ...
  std::string endpoint_id = pCore->GetLocalEndpointId();
  char *result = new char[endpoint_id.length() + 1];
  absl::SNPrintF(result, endpoint_id.length() + 1, "%s", endpoint_id);
  return result;
}
```

The function allocates memory with `new[]` but there is no mechanism for the caller to free it. Every call leaks `endpoint_id.length() + 1` bytes. Over time in a long-running application, this constitutes a denial-of-service via memory exhaustion.

**Remediation:** Use a caller-provided buffer, or return a `std::string`, or document the ownership transfer and require the caller to `delete[]`.

---

## Finding 7 — WiFi LAN server socket listens with TLS explicitly disabled

**File:** `internal/platform/implementation/apple/Mediums/WiFiLAN/GNCWiFiLANServerSocket.m:114-118`
**Severity:** Medium
**Type:** Cleartext communication / lack of transport security

```objc
nw_parameters_t parameters =
    nw_parameters_create_secure_tcp(/*tls*/ NW_PARAMETERS_DISABLE_PROTOCOL,
                                    /*tcp*/ NW_PARAMETERS_DEFAULT_CONFIGURATION);
```

All WiFi LAN connections (both server and client, see also `GNCWiFiLANMedium.m:126-128` and `277-279`) are created with TLS explicitly disabled. This means all data transferred over the WiFi LAN medium travels in **cleartext**. While the Nearby Connections protocol may layer its own encryption on top, if that encryption is not applied (e.g., for control frames or during handshake), or if an application sends sensitive data before the encrypted channel is established, an attacker on the same network can eavesdrop on or tamper with the traffic.

**Remediation:** Enable TLS at the transport layer or clearly document that application-layer encryption is mandatory.

---

## Finding 8 — Example app auto-accepts all incoming connections without verification

**File:** `connections/swift/NearbyConnections/Example/iOS Example/Model/Model.swift:143-155`
**Severity:** Medium
**Type:** Authentication bypass

```swift
func advertiser(_ advertiser: Advertiser, didReceiveConnectionRequestFrom endpointID: EndpointID,
    with context: Data, connectionRequestHandler: @escaping (Bool) -> Void) {
    ...
    connectionRequestHandler(true)   // always accepts
}
```

The example app's `AdvertiserDelegate` implementation unconditionally calls `connectionRequestHandler(true)` for every incoming connection request without any user interaction or validation. While this is distinct from the previously-reported default delegate auto-accept (which is about the SDK's default `connectionManager(didReceive:verificationCode:)` method), this is in the **application layer** — the example app also never checks the verification code shown in `connectionManager(didReceive:verificationCode:from:verificationHandler:)`.

Since this example app is the reference implementation that developers copy, this pattern will propagate to production apps, enabling any nearby attacker to connect and send payloads without authorization.

**Remediation:** Add user-facing confirmation UI and require explicit user approval before calling `connectionRequestHandler(true)`.

---

## Finding 9 — `GNCMBleConnection` missing bounds check before `subdataWithRange:` on peer-controlled data

**File:** `internal/platform/implementation/apple/Mediums/Ble/GNCMBleConnection.m:129-134`
**Severity:** Medium (note: the underflow at line 129/134 is already reported, but this is a distinct issue)
**Type:** Missing validation of peer-supplied prefix length against actual data length

```objc
if (![[data subdataWithRange:NSMakeRange(0, prefixLength)] isEqual:_serviceIDHash]) {
    return;  // discards
}
packet = [NSMutableData
    dataWithData:[data subdataWithRange:NSMakeRange(prefixLength, data.length - prefixLength)]];
```

While the underflow crash at line 129/134 is already reported, there is a separate issue: the code on line 129 performs `subdataWithRange:NSMakeRange(0, prefixLength)` without first checking that `data.length >= prefixLength`. If a malicious BLE peer sends a packet shorter than `prefixLength` bytes, `subdataWithRange:` will throw an `NSRangeException`, crashing the app. The previously reported issue covers the integer underflow at the subtraction `data.length - prefixLength`; this finding covers the **prior** `subdataWithRange:` call on line 129 which also crashes but via a different code path (exception rather than underflow).

**Remediation:** Add `if (data.length < prefixLength) return;` before line 129.

---

## Finding 10 — Dart adapter `ListenerPayloadCB` uses pointer into C++ temporary for file path

**File:** `connections/dart/nc_adapter_dart.cc:322-331`
**Severity:** Medium
**Type:** Use-after-free

```cpp
case NC_PAYLOAD_TYPE_FILE: {
    ...
    std::string path = payload->content.file.file_name;  // (1) copy into local
    Dart_CObject dart_object_path;
    dart_object_path.type = Dart_CObject_kString;
    dart_object_path.value.as_string = const_cast<char *>(path.c_str());  // (2) pointer into local
    ...
    Dart_PostCObject_DL(..., &dart_object_payload);  // (3) async post
```

The `path` string is a local variable. `Dart_PostCObject_DL` is an asynchronous operation — it posts the object to a Dart port for processing on the Dart side. If the Dart runtime does not immediately copy the string data before `ListenerPayloadCB` returns, the `path.c_str()` pointer becomes dangling, leading to use-after-free when the Dart side reads the file path string. Whether this is exploitable depends on Dart VM internals, but it's a correctness and safety hazard.

**Remediation:** Ensure the string data is copied into a buffer that outlives the async post, or use `Dart_CObject_kExternalTypedData` with proper release semantics.

---

## Finding 11 — Dart adapter `SendPayloadDart` uses dangling pointer for file payload

**File:** `connections/dart/nc_adapter_dart.cc:749-770`
**Severity:** Medium
**Type:** Use-after-free

```cpp
case PAYLOAD_TYPE_FILE:
    std::string file_name_str(payload_dart.data.data, payload_dart.data.size);  // (1) local
    NC_PAYLOAD payload{};
    ...
    payload.content.file.file_name = const_cast<char *>(file_name_str.c_str()); // (2) ptr into local
    payload.content.file.parent_folder = nullptr;
    ...
    NcSendPayload(instance, endpoint_ids.size(), endpoint_ids_ptr,
                  &moved_payload, [](NC_STATUS status) { ... });  // (3) async call
```

`file_name_str` is a local `std::string`. Its `.c_str()` pointer is stored in `payload.content.file.file_name`. `NcSendPayload` may invoke the C++ core asynchronously, which would then dereference the `file_name` pointer after `file_name_str` has been destroyed when `SendPayloadDart` returns.

**Remediation:** Ensure the filename string's lifetime extends beyond the async operation.

---

## Finding 12 — `NcCloseService` deletes `core` after `core->StopAllEndpoints` callback, creating potential use-after-free

**File:** `connections/c/nc.cc:172-187`
**Severity:** Medium
**Type:** Potential use-after-free / race condition

```cpp
void NcCloseService(NC_INSTANCE instance) {
  NcContext* nc_context = GetContext(instance);
  ...
  nc_context->core->StopAllEndpoints([](::nearby::connections::Status status) {
    NEARBY_LOGS(INFO) << "Stopping all endpoints with status " << status.ToString();
  });

  kNcContextMap->erase(nc_context->core);
  delete nc_context->router;
  delete nc_context->core;
}
```

`StopAllEndpoints` is called with a callback lambda, but the code immediately proceeds to erase and delete `core` and `router` **before** the callback has necessarily fired. If `StopAllEndpoints` operates asynchronously (which it may, depending on the service controller implementation), the callback lambda may fire after `core` is deleted. Additionally, any in-flight callbacks (advertising, discovery, connection, payload listeners) registered on this `core` instance may fire after deletion.

**Remediation:** Wait for the `StopAllEndpoints` callback to complete before deleting `core` and `router`, or ensure the callback is synchronous.

---

## Summary

| # | Finding | Severity | File |
|---|---------|----------|------|
| 1 | Uninitialized heap buffer in `CPPInputStream::Read` | High | `CPPInputStream.mm` |
| 2 | Locale-dependent encoding → NULL → UB in `GNCCoreAdapter` | Medium | `GNCCoreAdapter.mm` |
| 3 | Dangling pointer to temporary strings in `NcAcceptConnection` file payload | High | `nc.cc` |
| 4 | Stack-pointer escape in `GetCppConnectionRequestInfo` initiated callback | High | `nc.cc` |
| 5 | `SendPayload` ignores all endpoints after the first | Medium | `core_adapter.cc` |
| 6 | Memory leak in `GetLocalEndpointId` | Low | `core_adapter.cc` |
| 7 | WiFi LAN connections with TLS explicitly disabled | Medium | `GNCWiFiLANServerSocket.m` |
| 8 | Example app auto-accepts all connections without verification | Medium | `Model.swift` |
| 9 | Missing bounds check before `subdataWithRange:` on BLE data | Medium | `GNCMBleConnection.m` |
| 10 | Dart adapter async post with dangling string pointer (file path) | Medium | `nc_adapter_dart.cc` |
| 11 | Dart adapter `SendPayloadDart` dangling file_name pointer | Medium | `nc_adapter_dart.cc` |
| 12 | `NcCloseService` use-after-free from async `StopAllEndpoints` | Medium | `nc.cc` |

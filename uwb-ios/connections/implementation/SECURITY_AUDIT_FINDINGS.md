# Security Audit: Nearby Connections C++ Core — New Findings

## Finding 1: BLE v2 PSM Byte Serialization Truncates High Byte (ble_v2/ble_advertisement.cc)

**File:** `connections/implementation/mediums/ble_v2/ble_advertisement.cc`
**Lines:** 298–300

```cpp
data[0] = psm_ & 0xFF00;
data[1] = psm_ & 0x00FF;
```

The high byte of the 16-bit PSM value is not right-shifted before assignment. `psm_ & 0xFF00` produces a value in the range `0x0100–0xFF00`, which when cast to `char` truncates to zero for any PSM whose high nibble is zero. The correct code should be `data[0] = (psm_ >> 8) & 0xFF`. This identical bug also exists in `ble_advertisement_header.cc:148–149`.

**Impact:** L2CAP PSM values are silently corrupted during serialization. A remote device decoding the advertisement will receive a wrong PSM, causing L2CAP connections to fail or connect to the wrong PSM channel. An attacker can exploit the predictable corruption to redirect L2CAP connections.

**Severity:** Medium

---

## Finding 2: BLE v2 PSM Byte Serialization Truncates High Byte (ble_advertisement_header.cc)

**File:** `connections/implementation/mediums/ble_v2/ble_advertisement_header.cc`
**Lines:** 148–149

```cpp
data[0] = psm_ & 0xFF00;
data[1] = psm_ & 0x00FF;
```

Same missing right-shift bug as Finding 1, duplicated in the advertisement header serialization path.

**Impact:** Same as Finding 1 — corrupt PSM in the BLE advertisement header used during GATT-backed advertising.

**Severity:** Medium

---

## Finding 3: Encryption Runner Captures Raw `this` Pointer in Lambda with Async Lifetime (encryption_runner.cc)

**File:** `connections/implementation/encryption_runner.cc`
**Lines:** 94–97 and 232–235

```cpp
CancelableAlarm timeout_alarm(
    "EncryptionRunner.StartServer() timeout",
    [this]() { CancelableAlarmRunnable(client_, endpoint_id_, channel_); },
    kTimeout, alarm_executor_);
```

The `ServerRunnable` and `ClientRunnable` classes capture `this` in a lambda passed to `CancelableAlarm`, but `alarm_executor_` is owned by the parent `EncryptionRunner` object. If the `EncryptionRunner` is destroyed while a runnable is blocked on a channel read (lines 108, 156, 270), the timeout alarm may fire after the runnable's stack frame has been destroyed — the alarm references the executor which outlives the runnable but the lambda captures the now-destroyed `this` pointer of the runnable.

**Impact:** Use-after-free if the alarm fires after the runnable's operator() returns but before the alarm is cancelled, or if the EncryptionRunner is destroyed mid-handshake. The alarm callback dereferences `client_`, `endpoint_id_`, and `channel_` from the destroyed runnable.

**Severity:** Medium

---

## Finding 4: ConnectionsAuthenticationTransport Uses `const_cast` to Strip Const, No Null Safety (connections_authentication_transport.cc)

**File:** `connections/implementation/connections_authentication_transport.cc`
**Lines:** 28–29

```cpp
ConnectionsAuthenticationTransport::ConnectionsAuthenticationTransport(
    const EndpointChannel& channel) {
  channel_ = const_cast<EndpointChannel*>(&channel);
}
```

The constructor takes a `const` reference and immediately casts away const-ness. This defeats the type system's const-correctness guarantee. If the caller passes a temporary or a stack-local `EndpointChannel`, the stored raw pointer becomes a dangling pointer. Additionally, `WriteMessage` (line 36) writes through this potentially-dangling pointer without checking the return value of `channel_->Write()`, silently discarding write errors during authentication.

**Impact:** Dangling pointer / const-correctness violation. If the `EndpointChannel` goes out of scope before the transport is used, authentication messages are written to freed memory. Write failures during authentication are silently ignored.

**Severity:** Medium

---

## Finding 5: WifiLan Port Generation Has Integer Sign-Extension Vulnerability (wifi_lan.cc)

**File:** `connections/implementation/mediums/wifi_lan.cc`
**Lines:** 418–426

```cpp
const std::string service_id_hash =
    std::string(Utils::Sha256Hash(service_id, 4));

std::uint32_t uint_of_service_id_hash =
    service_id_hash[0] << 24 | service_id_hash[1] << 16 |
    service_id_hash[2] << 8 | service_id_hash[3];
```

`service_id_hash[0]` has type `char`, which is `signed char` on most platforms. When a byte value >= 0x80 is left-shifted by 24 bits, it first gets sign-extended to `int`, then shifted, producing undefined behavior (shifting a negative `int` by 24) or unintended sign-extension that contaminates the upper bits of `uint_of_service_id_hash` via the `|` operator. This can cause the generated port to fall outside the expected `port_range`, or produce a negative intermediate.

**Impact:** For certain service IDs, the generated port can be incorrect or fall outside the valid port range (0–65535), leading to connection failures or binding to an unexpected port. On systems where `char` is signed, this is technically undefined behavior.

**Severity:** Low–Medium

---

## Finding 6: Instant-On-Lost Hash Count Truncated to 3 Bits — Silent Data Loss (instant_on_lost_advertisement.cc)

**File:** `connections/implementation/mediums/ble_v2/instant_on_lost_advertisement.cc`
**Lines:** 78

```cpp
uint8_t count = static_cast<uint8_t>(hashes_.size() & kHashCountBitmask);
```

Where `kHashCountBitmask = 0x007`. This truncates the hash count to 3 bits (values 0–7). If `hashes_.size()` exceeds 7, the serialized count wraps around, producing a mismatch between the declared count and the actual number of hashes appended. On deserialization (line 118), the length check `count * kAdvertisementHashLength + 2 != bytes.length()` will correctly reject the malformed packet — but the *serialization* path silently produces corrupt output without any error.

**Impact:** If more than 7 endpoints are lost simultaneously, the on-lost advertisement is silently corrupted. A receiver may fail to process on-lost notifications, leaving stale endpoints visible to users.

**Severity:** Low

---

## Finding 7: BleV2 Advertising Logs Raw Advertisement Bytes in Hex (ble_v2.cc)

**File:** `connections/implementation/mediums/ble_v2.cc`
**Lines:** 929–932

```cpp
NEARBY_LOGS(ERROR) << "Failed to turn on BLE fast advertising with "
                      "advertisement bytes="
                   << absl::BytesToHexString(
                          medium_advertisement_bytes.data());
```

Same pattern at lines 972 and 1054–1057. Raw BLE advertisement bytes (which contain service ID hashes, endpoint data, and device tokens) are logged on error paths. This leaks device-identifying information and connection metadata to logs.

**Impact:** Information disclosure through logs. The advertisement bytes contain service ID hashes and device tokens that can be used to track devices or correlate sessions.

**Severity:** Low

---

## Finding 8: WifiLanBwuHandler Logs IP Address Bytes in Cleartext (wifi_lan_bwu_handler.cc)

**File:** `connections/implementation/wifi_lan_bwu_handler.cc`
**Lines:** 127–130

```cpp
NEARBY_LOGS(INFO)
    << "WifiLanBwuHandler retrieved WIFI_LAN credentials. IP addr: "
    << ip_address[0] << "." << ip_address[1] << "." << ip_address[2] << "."
    << ip_address[3] << ",  Port: " << port;
```

The raw IP address bytes are printed as individual characters (not as integers). Since `ip_address` is a raw binary string (not a dotted-decimal string), this prints the character codes, not the decimal octets, producing garbled output. More critically, this logs internal network addressing information in cleartext.

**Impact:** Information disclosure of internal network IP addresses in logs. The malformed output also indicates the IP address is being misinterpreted, which could cause connection issues if the logged values are used for debugging or audit.

**Severity:** Low

---

## Finding 9: Client Proxy Endpoint ID Uses Modulo Bias (client_proxy.cc)

**File:** `connections/implementation/client_proxy.cc`
**Lines:** 196–198

```cpp
for (int i = 0; i < kEndpointIdLength; i++) {
    id += kEndpointIdChars[prng.NextUint32() % sizeof(kEndpointIdChars)];
}
```

`sizeof(kEndpointIdChars)` is 36 (A-Z, 0-9). Since `2^32 % 36 != 0`, the modulo operation introduces bias: some characters are slightly more likely than others (`2^32 mod 36 = 4`, so the first 4 characters have probability `(119304648+1)/2^32` while the rest have `119304647/2^32`). For a 4-character endpoint ID, this modestly reduces the entropy below the theoretical ~20.68 bits.

**Impact:** Slightly reduced entropy in endpoint IDs makes brute-force guessing marginally easier. While not a critical vulnerability on its own, it combines with the already short (4-char) endpoint ID to make collision/prediction more feasible.

**Severity:** Low

---

## Finding 10: WebRTC Signaling Frame Deserialization Has No Size Limit (webrtc.cc)

**File:** `connections/implementation/mediums/webrtc.cc`
**Lines:** 431–433

```cpp
location::nearby::mediums::WebRtcSignalingFrame frame;
if (!frame.ParseFromString(std::string(message))) {
```

The incoming Tachyon signaling message is parsed as a protobuf with no size limit. Protobuf's `ParseFromString` will attempt to allocate memory proportional to the message size. A malicious Tachyon peer could send an extremely large signaling frame, causing excessive memory allocation.

Additionally, at lines 448–451, a received "offer" from a peer we have an outgoing connection with triggers both `ReceiveOffer` and `SendAnswer`. This unexpected offer-from-answerer path is not part of the normal WebRTC flow and could be exploited to force a session description renegotiation, potentially downgrading security parameters.

**Impact:** Memory exhaustion via oversized signaling frames. Session description confusion from unexpected offer/answer role reversal.

**Severity:** Medium

---

## Finding 11: BLE v2 Fast Advertisement Data Size Uses Single Unsigned Byte — No Overflow Check (ble_v2/ble_advertisement.cc)

**File:** `connections/implementation/mediums/ble_v2/ble_advertisement.cc`
**Lines:** 132–135

```cpp
int expected_data_size =
    fast_advertisement
        ? static_cast<int>(
              base_input_stream.ReadBytes(kFastDataSizeLength).data()[0])
        : static_cast<int>(base_input_stream.ReadUint32());
```

For fast advertisements, the data size is read as a single byte via `.data()[0]`. Since `char` is signed on most platforms, a byte value >= 0x80 becomes a negative `int` after the `static_cast<int>`. While the code checks `if (expected_data_size < 0)` on line 137, the conversion from `unsigned char` → `char` → `int` relies on implementation-defined behavior. On platforms where `char` is unsigned, values 128–255 become legitimate but potentially excessive data sizes that bypass the negative check.

**Impact:** On signed-char platforms, fast advertisements with data size 128–255 are silently rejected (masking legitimate large fast ads). On unsigned-char platforms, the full range works but there's no upper bound check against `kMaxFastAdvertisementLength` at this deserialization point.

**Severity:** Low

---

## Finding 12: AnalyticsRecorder Captures `this` by Raw Pointer in Executor Lambdas (analytics_recorder.cc)

**File:** `connections/implementation/analytics/analytics_recorder.cc`
**Lines:** 707–718

```cpp
serial_executor_.Execute(
    "analytics-recorder", [this, error_code = error_code.release()]() {
        ConnectionsLog connections_log;
        // ...
        event_logger_->Log(connections_log);
    });
```

Multiple lambdas capture `this` (the `AnalyticsRecorder*`) and are posted to `serial_executor_`. If the `AnalyticsRecorder` destructor runs while these lambdas are queued (between lines 113–114 where `serial_executor_.Shutdown()` is called and `mutex_` is locked), there is a window where queued lambdas may try to access the destroyed object. The `Sync()` method (line 1333–1337) uses a stack-local `latch` captured by reference in a lambda posted to the executor, creating a use-after-free risk if `Sync()` times out or the thread is interrupted.

**Impact:** Potential use-after-free during analytics recorder shutdown, or when `Sync()` doesn't block long enough.

**Severity:** Low–Medium

---

## Finding 13: WebRTC Connection Flow State Machine Has No Protection Against State Replay (connection_flow.cc)

**File:** `connections/implementation/mediums/webrtc/connection_flow.cc`
**Lines:** 478–491

```cpp
bool ConnectionFlow::TransitionState(State current_state, State new_state) {
  CHECK(IsRunningOnSignalingThread());
  if (current_state != state_) {
    NEARBY_LOGS(WARNING) << "Invalid state transition...";
    return false;
  }
  state_ = new_state;
  return true;
}
```

The state machine uses a simple compare-and-set pattern without any monotonicity enforcement. While individual transitions check the expected current state, there's no prevention against replaying signaling messages that reset the state machine to an earlier state. The `OnConnectionChange` handler (line 460–471) transitions directly to `kEnded` for `kDisconnected` states, but a race between `kDisconnected` transitioning to `kEnded` and a late-arriving ICE candidate being cached (lines 327–332) could leave stale candidates that are applied if a new connection is established on the same `ConnectionFlow` object.

**Impact:** Stale ICE candidates from a previous connection could be applied to a new session, potentially routing media through an attacker-controlled relay.

**Severity:** Medium

---

## Finding 14: Bluetooth Device Name Truncation Without Notification (bluetooth_device_name.cc)

**File:** `connections/implementation/bluetooth_device_name.cc`
**Lines:** 180–187

```cpp
ByteArray usable_endpoint_info(endpoint_info_);
if (endpoint_info_.size() > kMaxEndpointInfoLength) {
    NEARBY_LOGS(INFO)
        << "While serializing Advertisement, truncating Endpoint Name "
        << absl::BytesToHexString(endpoint_info_.data()) << " ("
        << endpoint_info_.size() << " bytes) down to " << kMaxEndpointInfoLength
        << " bytes";
    usable_endpoint_info.SetData(endpoint_info_.data(), kMaxEndpointInfoLength);
}
```

When `endpoint_info_` exceeds `kMaxEndpointInfoLength`, it is silently truncated during serialization. The raw `endpoint_info_` bytes (which may contain user-specified device names with PII) are logged in full hex. Additionally, the truncation means a deserializer could produce a different endpoint info than intended, potentially causing identity confusion between devices.

**Impact:** Information disclosure of full endpoint info in logs. Silent truncation could cause identity mismatch if two devices differ only in the truncated portion of their endpoint names.

**Severity:** Low

---

## Finding 15: DiscoveredPeripheralTracker Destructor–Executor Deadlock (discovered_peripheral_tracker.cc)

**File:** `connections/implementation/mediums/ble_v2/discovered_peripheral_tracker.cc`
**Lines:** 69–78 (destructor) and 651–657 (lambda) and 786–805 (FetchRawAdvertisementsInThread)

```cpp
// Destructor (lines 69-78):
DiscoveredPeripheralTracker::~DiscoveredPeripheralTracker() {
  if (...) {
    MutexLock lock(&mutex_);       // <--- acquires mutex_
    if (executor_ != nullptr) {
      executor_->Shutdown();        // <--- blocks waiting for executor tasks
    }
  }
}

// Lambda posted to executor (lines 651-657):
executor_->Execute(
    [this, ...]() mutable {
      FetchRawAdvertisementsInThread(...);
    });

// FetchRawAdvertisementsInThread (lines 786-805):
{
  MutexLock lock(&mutex_);          // <--- tries to acquire mutex_ (DEADLOCK)
  ...
}
```

The destructor acquires `mutex_` (line 73) and then calls `executor_->Shutdown()` (line 75), which blocks waiting for any running executor tasks to complete. However, `FetchRawAdvertisementsInThread` (which runs on the executor) also acquires `mutex_` at lines 787 and 805. If the executor task is running and waiting to acquire `mutex_` while the destructor holds `mutex_` and waits for the executor to finish, a classic ABBA deadlock occurs.

**Impact:** Complete hang of the BLE v2 advertising and discovery subsystem. The deadlock prevents the tracker from being destroyed, blocking the calling thread indefinitely. This can be triggered whenever a BLE scan is in progress and a GATT advertisement fetch is running while the tracker is being torn down.

**Severity:** Medium

---

## Finding 16: BLE Peripheral Captured by Reference in Async Lambda — Dangling Reference (p2p_cluster_pcp_handler.cc)

**File:** `connections/implementation/p2p_cluster_pcp_handler.cc`
**Lines:** 527–534 and 619–626

```cpp
void P2pClusterPcpHandler::BlePeripheralDiscoveredHandler(
    ClientProxy* client, BlePeripheral& peripheral,
    const std::string& service_id, ...) {
  RunOnPcpHandlerThread(
      "p2p-ble-device-discovered",
      [this, client, &peripheral, service_id, ...]() {
          // peripheral may be destroyed by the time this runs
          ...
          found_ble_endpoints_.emplace(peripheral.GetName(), ...);
      });
}
```

`peripheral` is passed by reference to the handler and then captured by reference (`&peripheral`) in a lambda that is posted to the PCP handler thread for asynchronous execution. By the time the lambda executes, the caller's `BlePeripheral` reference may be invalid, as the BLE scanning callback that invoked this handler may have returned and its stack frame destroyed.

The same pattern appears in `BlePeripheralLostHandler` (line 626): `[this, client, service_id, &peripheral]()`.

**Impact:** Use of a dangling reference to `BlePeripheral` on the PCP handler thread. This can cause reads from freed memory, crashes, or memory corruption when accessing the peripheral's name or other properties.

**Severity:** Medium

---

## Finding 17: WifiLanServiceInfo Deserialization Continues After Invalid PCP (wifi_lan_service_info.cc)

**File:** `connections/implementation/wifi_lan_service_info.cc`
**Lines:** 110–119

```cpp
pcp_ = static_cast<Pcp>(version_and_pcp_byte & kPcpBitmask);
switch (pcp_) {
    case Pcp::kP2pCluster:
    case Pcp::kP2pStar:
    case Pcp::kP2pPointToPoint:
      break;
    default:
      NEARBY_LOGS(INFO)
          << "Cannot deserialize WifiLanServiceInfo: unsupported V1 PCP "
          << static_cast<int>(pcp_);
      // BUG: no return statement here
}

// Execution continues — sets endpoint_id_ and service_id_hash_
endpoint_id_ = std::string{base_input_stream.ReadBytes(kEndpointIdLength)};
service_id_hash_ = base_input_stream.ReadBytes(kServiceIdHashLength);
```

Unlike the version check (which returns on invalid version at line 107), the PCP validation switch statement logs the error but does **not** `return` or clear state. Execution falls through to set `endpoint_id_` and `service_id_hash_`, making the `WifiLanServiceInfo` object appear valid (`IsValid()` checks `endpoint_id_` is not empty). A remote device advertising with an invalid PCP value will have its service info accepted and processed as if it were valid.

**Impact:** A malicious device can advertise with an arbitrary PCP value and still be treated as a valid endpoint. This bypasses the protocol compatibility check and allows endpoints using unexpected connection topologies to be discovered and potentially connected to.

**Severity:** Low–Medium

---

## Finding 18: BluetoothBwuHandler Logs Bluetooth MAC Address in Cleartext (bluetooth_bwu_handler.cc)

**File:** `connections/implementation/bluetooth_bwu_handler.cc`
**Lines:** 56–59, 63–67, 74–76, 81–83

```cpp
NEARBY_VLOG(1) << "BluetoothBwuHandler is attempting to connect to "
                  "available Bluetooth device ("
               << service_name << ", " << mac_address << ") for endpoint "
               << endpoint_id << " and service ID " << service_id;
```

Bluetooth MAC addresses are logged in cleartext at multiple points during the bandwidth upgrade flow. MAC addresses are persistent hardware identifiers that can be used for device tracking and fingerprinting. The same pattern appears at lines 63–67 (device not valid), 74–76 (connection failure), and 81–83 (connection success).

**Impact:** Information disclosure of persistent device identifiers (Bluetooth MAC addresses) through log output. This enables device tracking and correlation across sessions.

**Severity:** Low

---

## Finding 19: WebRtcSocket Captures `this` in Callbacks Offloaded from Signaling Thread (webrtc_socket_impl.cc)

**File:** `connections/implementation/mediums/webrtc/webrtc_socket_impl.cc`
**Lines:** 107–135 and 136–150 and 152–156

```cpp
void WebRtcSocket::OnStateChange() {
  switch (data_channel_->state()) {
    case ...::kClosed:
      socket_listener_.socket_closed_cb(this);  // May trigger destruction
      if (!closed_.Set(true)) {
        OffloadFromSignalingThread([this] { ClosePipe(); });  // Use-after-free
      }
      break;
  }
}

void WebRtcSocket::OnMessage(const webrtc::DataBuffer& buffer) {
  OffloadFromSignalingThread(
      [this, buffer = ByteArray(...)] {  // this captured
        if (!pipe_output_->Write(buffer).Ok()) {
          Close();
        }
      });
}
```

The `OnStateChange` callback (line 128) invokes `socket_closed_cb(this)`, which may trigger destruction of the `WebRtcSocket` by its owner. Immediately after, if the socket wasn't already marked closed, it offloads `ClosePipe()` via a lambda capturing `this` (line 131). If the socket is destroyed between the callback and the offloaded lambda's execution, the lambda dereferences a dangling `this` pointer.

The `OnMessage` callback (line 139–149) and `OnBufferedAmountChange` callback (line 155) also capture `this` in lambdas posted to `single_thread_executor_`. If the socket is destroyed before these execute, the result is use-after-free.

**Impact:** Use-after-free when the WebRTC data channel closes or receives messages during socket teardown. This can lead to crashes or memory corruption in the signaling/executor threads.

**Severity:** Medium

---

## Finding 20: InstantOnLostManager Captures `this` and Reacquires Mutex in CancelableAlarm (instant_on_lost_manager.cc)

**File:** `connections/implementation/mediums/ble_v2/instant_on_lost_manager.cc`
**Lines:** 193–203

```cpp
stop_advertising_alarm_ = std::make_unique<CancelableAlarm>(
    "stop_instant_on_lost_advertising",
    [this]() {
      MutexLock lock(&mutex_);          // <--- re-acquires mutex_
      StopOnLostAdvertising();
      active_on_lost_advertising_list_.clear();
      is_on_lost_advertising_ = false;
    },
    kInstantOnLostAdvertiseDuration, &executor_);
```

The `CancelableAlarm` callback captures `this` and acquires `mutex_`. This alarm is created while `mutex_` is already held by `StartInstantOnLostAdvertisement` (called from `OnAdvertisingStopped`, which takes the lock at line 93). If `mutex_` is non-recursive and the alarm fires synchronously (e.g., if the timeout is already expired or fires during creation), this would deadlock. More critically, if `Shutdown()` (line 128–148) is called between alarm creation and alarm firing, the `Shutdown` method holds `mutex_` and cancels the alarm (line 137), but there's a TOCTOU race: the alarm can fire after the cancel check but before the actual cancel takes effect, accessing a partially-destroyed `InstantOnLostManager`.

**Impact:** Potential deadlock or use-after-free during shutdown if the alarm callback races with `Shutdown()`.

**Severity:** Low–Medium

# Security Vulnerability Report — UWB Android App

**Date:** 2026-07-22  
**Scope:** `/workspace/uwb-android/` — all Kotlin sources, proto definitions, build configs, manifest  
**Methodology:** Manual static source code review. Every finding was verified by reading actual source code.

> **Excluded (already reported):**
> 1. UWB session keys using non-cryptographic `Random` (`NearbyControllerConnector.kt:30, 68-69`)
> 2. Auto-accepts all Nearby Connections without auth token verification (`NearbyConnections.kt:56-59`)

---

## Finding 1 — Proximity Lock Bypass via UWB Peer Disconnect

| Field | Value |
|---|---|
| **Severity** | **Critical** |
| **Location** | `uwb-android/app/src/main/java/com/google/apps/hellouwb/ui/control/ControlViewModel.kt` |
| **Verified** | Yes — read source code directly |

### Title
Proximity-based lock remains permanently unlocked when UWB peer disconnects

### Description
The `ControlViewModel` implements a proximity-based lock/unlock mechanism used for device control (e.g., car door lock demo). The lock transitions are driven solely by `PositionUpdated` ranging events (lines 52-65). When the peer moves close (distance < 0.25m), the device unlocks. When the peer moves far (distance > 2.0m), it re-locks.

However, the `observeRangingResults()` collector at line 54 only filters for `EndpointEvents.PositionUpdated`. It does **not** handle `EndpointEvents.UwbDisconnected` or `EndpointEvents.EndpointLost`. The secondary collector at lines 67-74 only watches `isRunning`, which stays `true` while the ranging session is active even after a peer disconnects.

When a UWB peer disconnects (goes out of range, is powered off, or is intentionally disrupted), `PositionUpdated` events stop flowing. The lock state freezes at whatever it was — if the device was unlocked, it stays unlocked **indefinitely** because no re-locking condition is ever evaluated.

### Impact
An attacker operating as a UWB peer can unlock the controlled resource (simulated lock/door) by briefly moving into close proximity, then immediately disconnecting (e.g., powering off their device or jamming the UWB signal). The lock remains in the unlocked state permanently until the user manually restarts ranging or changes the device type setting.

### Attack Path
1. Attacker establishes a UWB connection with the target device (facilitated by auto-accept).
2. Attacker moves within 0.25m of the target to trigger unlock (`ControlUiState.LockState(isLocked = false)`).
3. Attacker immediately disconnects (powers off device, or jams UWB signal).
4. No more `PositionUpdated` events are emitted; `isRunning` remains `true`.
5. Lock state remains permanently unlocked.

### Evidence
- `ControlViewModel.kt:52-65` — only `PositionUpdated` events processed; no handler for `UwbDisconnected` or `EndpointLost`
- `ControlViewModel.kt:67-74` — `isRunning` collector only locks on ranging stop, not on peer disconnect
- `UwbSessionScopeImpl.kt:100-101` — `UwbDisconnected` events are emitted by the ranging layer but never consumed by ControlViewModel
- `UwbRangingControlSourceImpl.kt:56-58` — `isRunning` only flipped by explicit `start()`/`stop()` calls, not by peer disconnects

### Remediation
Handle `EndpointEvents.UwbDisconnected` and `EndpointEvents.EndpointLost` in the `startLockObserving()` flow by re-locking immediately when a peer disconnects. Remove the `filterIsInstance<EndpointEvents.PositionUpdated>()` and use a `when` block that also processes disconnect events.

---

## Finding 2 — Attacker-Controlled UWB Session Configuration Injection on Controlee

| Field | Value |
|---|---|
| **Severity** | **High** |
| **Location** | `uwb-android/uwbranging/src/main/java/com/google/apps/uwbranging/impl/NearbyControleeConnector.kt` |
| **Verified** | Yes — read source code directly |

### Title
Controlee accepts all UWB session parameters from remote peer without validation

### Description
When the controlee receives a `Control` message from the controller peer (lines 63-83), it directly uses all session configuration values without any validation:

- `configuration.configId` (line 68, used at line 79) — used as the UWB config type
- `configuration.sessionId` (line 79) — used as the session identifier
- `configuration.channel` and `configuration.preambleIndex` (line 78) — determine the radio channel
- `configuration.securityInfo` (line 80) — used as the session key material
- `sessionInfo.localAddress` (line 77) — converted to `UwbAddress` via truncating `.toShort()`

All of these values flow unvalidated into `UwbOobEvent.UwbEndpointFound` and then into `RangingParameters` at `UwbSessionScopeImpl.kt:80-88`, which starts the actual UWB ranging session.

### Impact
A malicious controller can force a controlee device into arbitrary UWB configurations: using a specific channel/preamble index for radio-level eavesdropping, choosing a `configId` that disables security features, or providing attacker-known `securityInfo` bytes so the attacker can decrypt all subsequent UWB ranging frames.

### Attack Path
1. Attacker runs a modified controller app that advertises via Nearby Connections.
2. Target controlee app discovers and auto-connects to attacker (facilitated by auto-accept).
3. Controlee sends its capabilities; attacker receives them.
4. Attacker crafts a `Control` protobuf with: attacker-chosen `sessionId`, `channel`, `preambleIndex`, and `securityInfo`.
5. Controlee blindly accepts all parameters and starts a UWB session with attacker-controlled keys and configuration.
6. Attacker can now eavesdrop on or manipulate the UWB ranging session.

### Evidence
- `NearbyControleeConnector.kt:63-83` — `processUwbSessionInfo` uses all remote fields directly
- `NearbyControleeConnector.kt:77` — `sessionInfo.localAddress.toShort()` — no range validation
- `NearbyControleeConnector.kt:78-80` — channel, preambleIndex, sessionId, securityInfo used as-is
- `UwbSessionScopeImpl.kt:80-88` — parameters flow directly into `RangingParameters` constructor
- `uwbinfo.proto:33-39` — `UwbConfiguration` fields are all simple scalars with no constraints

### Remediation
Validate all incoming session parameters:
- Verify `configId` is in the controlee's own `supportedConfigIdsList`.
- Validate `channel` and `preambleIndex` against known-good values from UWB spec (e.g., channel 5 or 9).
- Validate `sessionId` is non-zero.
- Verify `securityInfo` is the expected length (8 bytes).
- Validate `localAddress` fits in a 16-bit unsigned range before conversion.

---

## Finding 3 — Temp File Leak with World-Readable Received Images

| Field | Value |
|---|---|
| **Severity** | **Medium** |
| **Location** | `uwb-android/app/src/main/java/com/google/apps/hellouwb/ui/send/SendViewModel.kt` |
| **Verified** | Yes — read source code directly |

### Title
Received image data written to temp files that are never deleted

### Description
In `SendViewModel.onImageReceived()` (lines 89-94), when image data is received from a remote UWB peer, a temp file is created via `File.createTempFile(RECEIVED_FILE_PATH, null)` using the default system temp directory. The received image bytes are written to this file. However, the file is **never deleted** — not in `clear()` (lines 53-58), not in `onCleared()` (no override exists), and not anywhere else in the codebase.

Each received image creates a new temp file. The `clear()` method resets the UI state and restarts the receiving job, but does not clean up previously written files.

### Impact
1. **Data persistence:** Sensitive image data received from peers persists on the filesystem indefinitely, even after the user "clears" the UI. An attacker with physical device access or a malicious app with storage access can recover all previously received images.
2. **Storage exhaustion:** An attacker repeatedly sending images via UWB OOB messages can fill up the device's temp directory, causing DoS.
3. **Predictable file names:** `File.createTempFile("received", null)` generates files like `received1234567890.tmp` with a predictable prefix in the default temp directory.

### Attack Path
1. Attacker establishes UWB connection with target.
2. Attacker repeatedly sends image payloads via OOB messages.
3. Each payload creates a new temp file that is never cleaned up.
4. Files accumulate with sensitive content that can be recovered by any process with access to the app's temp directory.

### Evidence
- `SendViewModel.kt:92` — `File.createTempFile(RECEIVED_FILE_PATH, null)` creates temp file
- `SendViewModel.kt:93` — `contentResolver.openOutputStream(file.toUri())?.use { it.write(imageBytes) }` writes untrusted data
- `SendViewModel.kt:53-58` — `clear()` method does not delete temp files
- `SendViewModel.kt:38` — `RECEIVED_FILE_PATH = "received"` — predictable prefix
- No `onCleared()` override or file cleanup anywhere in `SendViewModel`

### Remediation
- Track all created temp files and delete them in `clear()` and in a `ViewModel.onCleared()` override.
- Use the app's internal cache directory (`context.cacheDir`) rather than the system temp directory.
- Consider processing images in memory without writing to disk, or use `File.deleteOnExit()` as a safety net.

---

## Finding 4 — Unbounded Protobuf Deserialization Enables OOM Denial of Service

| Field | Value |
|---|---|
| **Severity** | **Medium** |
| **Location** | `uwb-android/uwbranging/src/main/java/com/google/apps/uwbranging/impl/NearbyConnector.kt` |
| **Verified** | Yes — read source code directly |

### Title
No size limits on incoming protobuf message parsing

### Description
In `NearbyConnector`, the methods `tryParseOobMessage()` (lines 49-56) and `tryParseUwbSessionInfo()` (lines 58-65) call `Oob.parseFrom(payload)` on raw byte arrays received from remote peers via Nearby Connections. There is no size validation on the incoming `payload` before parsing.

The `payload` originates from `NearbyConnections.payloadCallback.onPayloadReceived()` (NearbyConnections.kt:75-77), which converts the Nearby Connections `Payload` to bytes and dispatches them. The `Oob` protobuf message contains a `bytes` field (`Data.message`) that can hold arbitrarily large data, and the `Control.metadata` field is also `bytes` with no proto-level size constraint.

Protobuf-lite's `parseFrom(byte[])` will attempt to parse the entire array, and the resulting parsed objects hold all data in memory.

### Impact
A malicious peer can send a very large payload (limited only by Nearby Connections' payload size limit) that causes excessive memory allocation during protobuf parsing, leading to OutOfMemoryError and app crash (denial of service).

### Attack Path
1. Attacker connects to the target via Nearby Connections.
2. Attacker sends a crafted protobuf `Oob` message with a multi-megabyte `Data.message` or `Control.metadata` field.
3. `NearbyConnections.payloadCallback` receives it and converts to byte array.
4. `NearbyConnector.processPayload()` calls `Oob.parseFrom(payload)` which allocates the full parsed message in memory.
5. Repeated sends exhaust the app's heap, causing OOM crash.

### Evidence
- `NearbyConnector.kt:51` — `Oob.parseFrom(payload)` with no size check
- `NearbyConnector.kt:60` — second `Oob.parseFrom(payload)` call, also unbounded
- `NearbyConnections.kt:76` — `payload.asBytes()` converts entire NC payload to byte array
- `uwbinfo.proto:58-59` — `Data { bytes message = 1; }` — no max_size constraint
- `uwbinfo.proto:50-54` — `Control { bytes metadata = 2; }` — no max_size constraint

### Remediation
- Check `payload.size` against a reasonable maximum (e.g., 64KB for control messages, a configured limit for data messages) before calling `parseFrom()`.
- Use `Oob.parseFrom(CodedInputStream)` with `CodedInputStream.setSizeLimit()` to enforce parsing limits.
- Consider using Nearby Connections' streaming payload API for large transfers instead of byte payloads.

---

## Finding 5 — Remote Endpoint ID Injection for UI Spoofing

| Field | Value |
|---|---|
| **Severity** | **Medium** |
| **Location** | `uwb-android/uwbranging/src/main/java/com/google/apps/uwbranging/impl/NearbyControllerConnector.kt` |
| **Verified** | Yes — read source code directly |

### Title
Remote peer's self-declared ID and metadata are trusted and displayed in UI without sanitization

### Description
When the controller or controlee receives a `Control` protobuf from the remote peer, it creates a `UwbEndpoint` using the peer's self-declared `id` and `metadata` fields directly:

- `NearbyControllerConnector.kt:65` — `UwbEndpoint(sessionInfo.id, sessionInfo.metadata.toByteArray())`
- `NearbyControleeConnector.kt:71` — `UwbEndpoint(sessionInfo.id, sessionInfo.metadata.toByteArray())`

The `id` field is a free-form `string` in the protobuf (`uwbinfo.proto:51`). This ID is then displayed in the UI:

- `HomeScreen.kt:184` — `endpoint.id.split("|")[0]` shown as endpoint name
- `SendViewModel.kt:111` — `event.endpoint.id.split("|")[0]` shown in Toast as `endpointDisplayName`

The endpoint ID format is expected to be `"displayName|uuid"` (set at `AppContainerImpl.kt:50`), but a malicious peer can set any string as their ID.

### Impact
An attacker can impersonate a trusted device by setting their endpoint ID to match an expected device name (e.g., `"MyCarKey|fake-uuid"`). This could trick the user into believing they are connected to a legitimate device while actually being connected to the attacker's device. The attacker could also inject excessively long strings or special characters to cause UI rendering issues.

### Attack Path
1. Attacker modifies their app to set the endpoint ID to a trusted device name (e.g., `"Alice's Phone|attacker-uuid"`).
2. Attacker connects to the target via Nearby Connections.
3. Attacker sends a `Control` message with the spoofed `id` field.
4. Target device creates a `UwbEndpoint` with the attacker's spoofed ID.
5. Target's UI shows the attacker as the trusted device name.
6. User trusts the connection and may send sensitive data (images) to the attacker.

### Evidence
- `NearbyControllerConnector.kt:65` — `UwbEndpoint(sessionInfo.id, ...)` — peer-supplied ID trusted
- `NearbyControleeConnector.kt:71` — same pattern on controlee side
- `uwbinfo.proto:51` — `string id = 1;` — unconstrained string field
- `HomeScreen.kt:184` — `endpoint.id.split("|")[0]` — displayed to user
- `SendViewModel.kt:111` — `event.endpoint.id.split("|")[0]` — displayed in Toast message
- `AppContainerImpl.kt:50` — legitimate format is `displayName + "|" + uuid`

### Remediation
- Do not use peer-supplied identifiers for display or trust decisions.
- Bind the endpoint ID to a verified identity from the Nearby Connections authentication token.
- Sanitize displayed strings: limit length, strip control characters, and escape special characters.
- Show a visual indicator distinguishing verified vs. unverified peer names.

---

## Finding 6 — Race Conditions from Unsynchronized Mutable State in Ranging Control

| Field | Value |
|---|---|
| **Severity** | **Medium** |
| **Location** | `uwb-android/app/src/main/java/com/google/apps/hellouwb/data/UwbRangingControlSourceImpl.kt` |
| **Verified** | Yes — read source code directly |

### Title
Unsynchronized read/write of `rangingJob` and `uwbSessionScope` creates TOCTOU race conditions

### Description
`UwbRangingControlSourceImpl` manages `rangingJob` (a coroutine `Job?`) and `uwbSessionScope` across multiple methods that can be called concurrently from different dispatchers:

- `start()` (lines 101-111): reads `rangingJob`, then conditionally creates and assigns it — no atomicity.
- `stop()` (lines 113-118): reads `rangingJob`, cancels it, and nulls it — no atomicity.
- `deviceType` setter (lines 77-83): calls `stop()` then reassigns `uwbSessionScope` — can race with `start()`.
- `configType` setter (lines 85-91): same pattern as `deviceType`.
- `updateEndpointId()` (lines 93-99): calls `stop()`, creates new `uwbEndpoint`, creates new `uwbSessionScope`.

The `deviceType` and `configType` properties use `Delegates.observable`, which is invoked from the `SettingsStore` DataStore flow running on `Dispatchers.IO` (`AppContainerImpl.kt:48`). Meanwhile, `start()`/`stop()` can be called from the UI thread via `RangingViewModel`. There is no synchronization (no mutex, no `synchronized`, no atomic reference).

### Impact
- **Double-start:** Two concurrent `start()` calls can both see `rangingJob == null` and launch duplicate ranging sessions, causing resource leaks and duplicate event emissions.
- **Use-after-cancel:** `stop()` can cancel a job while `start()` is in the process of creating it, leaving a dangling `rangingJob` reference.
- **Scope swap during active ranging:** A `deviceType` change can reassign `uwbSessionScope` while an active `rangingJob` is still collecting from the old scope, leading to undefined behavior.

### Attack Path
1. Attacker rapidly triggers settings changes (device type, config type) while ranging is active.
2. Race between `stop()` → `uwbSessionScope` reassignment and the active coroutine using the old scope.
3. Results in multiple active ranging sessions or crash from concurrent modification.

### Evidence
- `UwbRangingControlSourceImpl.kt:101-102` — `if (rangingJob == null)` check-then-act without synchronization
- `UwbRangingControlSourceImpl.kt:113-114` — `val job = rangingJob ?: return` without synchronization
- `UwbRangingControlSourceImpl.kt:77-83` — `deviceType` observable calls `stop()` then reassigns `uwbSessionScope`
- `UwbRangingControlSourceImpl.kt:104-106` — ranging coroutine captures `uwbSessionScope` which can be swapped mid-flight
- `AppContainerImpl.kt:48-59` — settings collection runs on `Dispatchers.IO`, driving `deviceType`/`configType` changes

### Remediation
- Use a `Mutex` to protect all accesses to `rangingJob`, `uwbSessionScope`, and `uwbEndpoint`.
- Alternatively, confine all state mutations to a single-threaded dispatcher (e.g., `Dispatchers.Main.immediate` or a dedicated single-thread dispatcher).
- Consider using `AtomicReference` for `rangingJob` with compare-and-set for the start/stop check.

---

## Finding 7 — Non-Thread-Safe Mutable Collections in NearbyConnector

| Field | Value |
|---|---|
| **Severity** | **Medium** |
| **Location** | `uwb-android/uwbranging/src/main/java/com/google/apps/uwbranging/impl/NearbyConnector.kt` |
| **Verified** | Yes — read source code directly |

### Title
`peerMap` HashMap accessed concurrently from multiple coroutines without synchronization

### Description
`NearbyConnector` maintains a `peerMap = mutableMapOf<String, UwbEndpoint>()` (line 35) that is accessed from multiple coroutine contexts without any synchronization:

- `addEndpoint()` (line 37-39) — writes to map, called from `processUwbSessionInfo()` in subclass implementations
- `lookupEndpoint()` (line 41-43) — reads from map, called from `processPayload()`
- `lookupEndpointId()` (line 45-47) — iterates the entire map, called from `sendMessage()`
- `processEndpointLost()` (line 76-79) — removes from map

These are called from the `channelFlow` collector in `start()` (line 81) which processes `NearbyEvent` instances. The `NearbyConnections` class dispatches events from `coroutineScope.launch` blocks running on the injected `dispatcher` (typically `Dispatchers.IO` — a thread pool). Meanwhile, `sendMessage()` (line 113) can be called from any thread by the app layer.

`HashMap` is not thread-safe; concurrent read/write or write/write operations can cause `ConcurrentModificationException` or silent data corruption (lost entries, infinite loops in hash chains).

Similarly, in `UwbSessionScopeImpl.kt`:
- `remoteDeviceMap` (line 42) — `mutableMapOf` accessed from multiple launched coroutines
- `activeJobs` (line 44) — `mutableMapOf` written in one coroutine, read/cancelled in another
- `localAddresses` (line 40) — `mutableSetOf` written and read concurrently

### Impact
Concurrent operations can corrupt internal data structures, leading to:
- Crash via `ConcurrentModificationException`
- Silent endpoint misrouting (messages sent to wrong peer, or lost)
- Orphaned ranging sessions that are never cancelled

### Evidence
- `NearbyConnector.kt:35` — `mutableMapOf<String, UwbEndpoint>()` — not thread-safe
- `NearbyConnector.kt:37-39` — `addEndpoint` writes without lock
- `NearbyConnector.kt:45-47` — `lookupEndpointId` iterates without lock
- `NearbyConnector.kt:76-79` — `peerMap.remove` without lock
- `NearbyConnector.kt:113-122` — `sendMessage` calls `lookupEndpointId` from arbitrary caller thread
- `UwbSessionScopeImpl.kt:40-44` — three more unsynchronized mutable collections

### Remediation
- Replace `mutableMapOf()` with `ConcurrentHashMap()` for thread-safe maps.
- Or use a `Mutex` around all map/set accesses.
- Or confine all accesses to a single-threaded dispatcher.

---

## Summary Table

| # | Severity | Title | File |
|---|----------|-------|------|
| 1 | **Critical** | Proximity lock bypass via UWB peer disconnect | `ControlViewModel.kt` |
| 2 | **High** | Attacker-controlled UWB session config injection on controlee | `NearbyControleeConnector.kt` |
| 3 | **Medium** | Temp file leak with received images never deleted | `SendViewModel.kt` |
| 4 | **Medium** | Unbounded protobuf deserialization enables OOM DoS | `NearbyConnector.kt` |
| 5 | **Medium** | Remote endpoint ID injection for UI spoofing | `NearbyControllerConnector.kt` |
| 6 | **Medium** | Race conditions from unsynchronized mutable state | `UwbRangingControlSourceImpl.kt` |
| 7 | **Medium** | Non-thread-safe mutable collections accessed concurrently | `NearbyConnector.kt` |

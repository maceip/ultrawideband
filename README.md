<img src="ultra.png" alt="ultra" width="200"/>

# ultrawideband: native, mobile, p2p

a p2p demo with ios <=> android interop



> [!WARNING]
> simulators dont work, you need real hw


to build on ios
```bash
open ultrawideband/uwb-ios/connections/swift/NearbyConnections/Example/p2px-ios.xcodeproj/project.xcworkspace
```
to build on android
```
cd ultrawideband/uwb-android &&  ./gradlew build
```
****
> [!NOTE]  
> google's nearby lib needs a flag set to get ios interop working</br>
>```nearby/connections/implementation/flags/nearby_connections_feature_flags.h```

```cpp
// Disable/Enable BLE v2 in Nearby Connections SDK.
constexpr auto kEnableBleV2 =
    flags::Flag<bool>(kConfigPackage, "45401515", true);
```
set this to true ^


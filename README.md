<img src="ultra.png" alt="ultra" width="200"/>

# ultrawideband: p2p without the mitm

works with android and ios:

> [!NOTE]  
> google's nearby lib needs a flag compiled to get ios interop working</br>
>```nearby/connections/implementation/lags/nearby_connections_feature_flags.h```

```cpp
// Disable/Enable BLE v2 in Nearby Connections SDK.
constexpr auto kEnableBleV2 =
    flags::Flag<bool>(kConfigPackage, "45401515", true);
```
set this to true ^


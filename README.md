# fnhook
A simple, batteries included library for hooking standard library functions from an external program on macOS. Currently only supports aarch64.

## !! NOTE !!
You will need to sign whatever application you include this in with the `com.apple.security.cs.debugger` entitlement. This library depends on `task_for_pid`, which requires
said entitlement. This can be done via `codesign`, like so:
```sh
codesign -s "my-trusted-cert-for-signing-code" -f --entitlements ./Entitlements.plist --timestamp --options=runtime ../target/debug/my-application-that-hooks
```

Additionally, if you are using this to debug an application that has the `Hardened Runtime` enabled, you will need to re-sign that application with the following entitlements:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
   <dict>
      <key>com.apple.security.get-task-allow</key>
      <true/>
      <key>com.apple.security.cs.disable-library-validation</key>
      <true/>
      <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
      <true/>
   </dict>
</plist>
```

This can be done via `codesign`, like so:
```sh
codesign -f -s "my-trusted-cert-for-signing-code" --preserve-metadata=identifier,requirements,flags,runtime,launch-constraints,library-constraints --entitlements ./the_entitlements_above.plist
```

### TODO
- [ ] support fat binaries (e.g. universal binaries)
- [ ] support x86_64 hooking
- [ ] cross-platform support (?)
- [ ] allow for dynamic payloads
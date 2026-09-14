import NetworkExtension
import Darwin
import Mobile

/// System VPN entry point. The Go core (Mobile.xcframework) runs WireGuard/AmneziaWG
/// entirely in-process, talking to the TURN relay through an in-memory pipe — there is
/// no local loopback socket to exclude from the tunnel, unlike a separate relay process.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var started = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let conf = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        guard let configJSON = conf["configJSON"] as? String,
              let wgText = conf["wgText"] as? String,
              let mtu = conf["mtu"] as? Int else {
            completionHandler(NSError(domain: "FreeTurn", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing provider configuration"]))
            return
        }

        var paramsErr: NSError?
        guard let params = MobileParseTunnelConfig(wgText, mtu, &paramsErr) else {
            completionHandler(paramsErr ?? NSError(domain: "FreeTurn", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "failed to parse tunnel config"]))
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let addrList = params.addresses.split(separator: ",").map(String.init)
        var v4Addrs: [String] = []
        var v4Masks: [String] = []
        for a in addrList {
            let parts = a.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]) else { continue }
            v4Addrs.append(String(parts[0]))
            v4Masks.append(cidrToMask(prefix))
        }
        if v4Addrs.isEmpty {
            completionHandler(NSError(domain: "FreeTurn", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "no tunnel addresses"]))
            return
        }
        let ipv4 = NEIPv4Settings(addresses: v4Addrs, subnetMasks: v4Masks)

        let allowedList = params.allowedIPs.split(separator: ",").map(String.init)
        var routes: [NEIPv4Route] = []
        for a in allowedList {
            let parts = a.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]) else { continue }
            routes.append(NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: cidrToMask(prefix)))
        }
        ipv4.includedRoutes = routes.isEmpty ? [NEIPv4Route.default()] : routes
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: params.mtu > 0 ? params.mtu : mtu)

        let dnsList = params.dns.split(separator: ",").map(String.init).filter { !$0.isEmpty }
        if !dnsList.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: dnsList)
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                completionHandler(error)
                return
            }
            guard let self = self else { return }

            guard let fd = self.getTunnelFileDescriptor() else {
                completionHandler(NSError(domain: "FreeTurn", code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "could not find tun file descriptor"]))
                return
            }

            let sink = TunnelEventSink()
            MobileSetEventSink(sink)
            self.eventSink = sink

            var startErr: NSError?
            MobileStartTunnel(configJSON, Int(fd), &startErr)
            if let startErr = startErr {
                completionHandler(startErr)
                return
            }

            self.started = true
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if started {
            MobileStop()
            started = false
        }
        completionHandler()
    }

    private var eventSink: TunnelEventSink?

    /// Extracts the raw file descriptor backing this extension's utun interface.
    /// NEPacketTunnelFlow does not expose it publicly; every userspace-WireGuard iOS
    /// app (WireGuard, AmneziaWG) relies on this same scan — the interface is a
    /// PF_SYSTEM/SYSPROTO_CONTROL "utun" control socket among the process's open fds.
    private func getTunnelFileDescriptor() -> Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, FT_CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }
}

private func cidrToMask(_ prefix: Int) -> String {
    guard prefix >= 0, prefix <= 32 else { return "255.255.255.255" }
    let mask: UInt32 = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
}

/// Minimal EventSink — logs go through Mobile's own ring buffer (DumpLogs), this just
/// needs to exist so the Go side has somewhere to push OnState/OnCaptcha without a nil
/// pointer. The extension has no UI of its own to render state changes into.
private final class TunnelEventSink: NSObject, MobileEventSinkProtocol {
    func onState(_ state: String?, streams: Int, total: Int, errMsg: String?) {}
    func onLog(_ level: String?, msg: String?, unixMillis: Int64) {}
    func onCaptcha(_ url: String?) {}
}

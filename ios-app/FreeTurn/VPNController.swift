import Foundation
import NetworkExtension
import Combine

private struct TurnCfg: Codable { var n: Int; var transport: String }
private struct VKCfg: Codable { var links: [String]; var streamsPerCred: Int; var manualCaptcha: Bool; var platform: String }
private struct ObfCfg: Codable { var profile: String; var key: String }
private struct DNSCfg: Codable { var mode: String; var servers: [String] }
private struct LogCfg: Codable { var debug: Bool }
private struct TunnelCfg: Codable { var mode: String; var config: String; var mtu: Int }

private struct ClientConfig: Codable {
    var peer: String
    var clientId: String
    var provider: String
    var turn: TurnCfg
    var vk: VKCfg
    var obf: ObfCfg
    var dns: DNSCfg
    var log: LogCfg
    var tunnel: TunnelCfg
}

@MainActor
final class VPNController: ObservableObject {
    @Published var status: String = "Disconnected"
    @Published var active = false
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private let extensionBundleId = "com.shndo1337.freeturn.tunnel"

    init() {
        NotificationCenter.default.addObserver(
            self, selector: #selector(statusChanged),
            name: .NEVPNStatusDidChange, object: nil)
        Task { await load() }
    }

    private func load() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = managers.first
        refreshStatus()
    }

    /// Builds the relay+tunnel JSON config and the wg-quick text for the embedded
    /// AmneziaWG core, then starts the system VPN via the packet-tunnel extension.
    func start(peer: String, vkLink: String, obfKey: String,
               clientId: String, wgPrivateKey: String, wgAddress: String,
               peerPublicKey: String, peerPresharedKey: String, mtu: Int = 1280) {
        let wgText = """
        [Interface]
        PrivateKey = \(wgPrivateKey)
        Address = \(wgAddress)
        MTU = \(mtu)
        Jc = 4
        Jmin = 8
        Jmax = 80
        S1 = 50
        S2 = 60
        S3 = 0
        S4 = 0
        H1 = 1000
        H2 = 2000
        H3 = 3000
        H4 = 4000

        [Peer]
        PublicKey = \(peerPublicKey)
        PresharedKey = \(peerPresharedKey)
        AllowedIPs = 0.0.0.0/0
        Endpoint = 127.0.0.1:1
        """

        let cfg = ClientConfig(
            peer: peer,
            clientId: clientId,
            provider: "vk",
            turn: TurnCfg(n: 6, transport: "tcp"),
            vk: VKCfg(links: [vkLink], streamsPerCred: 12, manualCaptcha: false, platform: "mobile"),
            obf: ObfCfg(profile: "rtpopus3", key: obfKey),
            dns: DNSCfg(mode: "plain", servers: ["8.8.8.8"]),
            log: LogCfg(debug: false),
            tunnel: TunnelCfg(mode: "awg", config: wgText, mtu: mtu)
        )

        guard let configData = try? JSONEncoder().encode(cfg),
              let configJSON = String(data: configData, encoding: .utf8) else {
            lastError = "Failed to encode config"
            return
        }

        Task {
            let m = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = extensionBundleId
            proto.serverAddress = "FreeTurn"
            proto.providerConfiguration = [
                "configJSON": configJSON,
                "wgText": wgText,
                "mtu": mtu,
            ]
            m.protocolConfiguration = proto
            m.localizedDescription = "FreeTurn"
            m.isEnabled = true
            do {
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
                self.manager = m
                try m.connection.startVPNTunnel()
            } catch {
                self.status = "Error: \(error.localizedDescription)"
                self.lastError = error.localizedDescription
            }
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    @objc private func statusChanged() { refreshStatus() }

    private func refreshStatus() {
        guard let conn = manager?.connection else { active = false; status = "Disconnected"; return }
        switch conn.status {
        case .connected:     status = "Connected";     active = true
        case .connecting:    status = "Connecting…";   active = true
        case .disconnecting: status = "Disconnecting…"; active = true
        case .reasserting:   status = "Reasserting…";  active = true
        default:             status = "Disconnected";  active = false
        }
    }
}

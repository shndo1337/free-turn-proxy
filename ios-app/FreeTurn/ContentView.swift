import SwiftUI

struct ContentView: View {
    @StateObject private var vpn = VPNController()

    @AppStorage("clientId") private var clientId: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    @AppStorage("peer") private var peer: String = "45.9.2.176:56000"
    @AppStorage("vkLink") private var vkLink: String = ""
    @AppStorage("obfKey") private var obfKey: String = "53f48d2b0da9a4e736de24c9b1cacb74aba696763303f15c133ae6ed1056b8e4"
    @AppStorage("wgPrivateKey") private var wgPrivateKey: String = "gHORWGTv1NUSiwWSDWFpbBxpamziEuJBuMEWdtasHV0="
    @AppStorage("wgAddress") private var wgAddress: String = "10.0.0.16/32"
    @AppStorage("peerPublicKey") private var peerPublicKey: String = "qAV8pHk4WQigmyqHNiTKz+q9mq3pOmjpp3CNGbv56wM="
    @AppStorage("peerPresharedKey") private var peerPresharedKey: String = "j4ZBwJPenYrQlH+d7x/I7bn6iXnXgJC6TETGwCWcDX0="

    private var canStart: Bool {
        !vkLink.trimmingCharacters(in: .whitespaces).isEmpty && !peer.isEmpty && !obfKey.isEmpty
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 16) {
                    statusHeader

                    field(title: "VK Call link", placeholder: "https://vk.ru/call/join/...", text: $vkLink)
                    field(title: "Server (peer)", placeholder: "ip:port", text: $peer)
                    field(title: "Obfuscation key", placeholder: "64 hex chars", text: $obfKey)

                    DisclosureGroup("Advanced (WireGuard keys)") {
                        VStack(spacing: 10) {
                            field(title: "Client ID", placeholder: "", text: $clientId)
                            field(title: "WG private key", placeholder: "", text: $wgPrivateKey)
                            field(title: "WG address", placeholder: "10.0.0.x/32", text: $wgAddress)
                            field(title: "Peer public key", placeholder: "", text: $peerPublicKey)
                            field(title: "Peer preshared key", placeholder: "", text: $peerPresharedKey)
                        }.padding(.top, 8)
                    }

                    controls

                    if let err = vpn.lastError {
                        Text(err).font(.caption).foregroundColor(.red)
                    }
                }
                .padding()
            }
            .navigationTitle("FreeTurn")
        }
        .navigationViewStyle(.stack)
    }

    private var controls: some View {
        VStack(spacing: 12) {
            if vpn.active {
                Button(role: .destructive) { vpn.stop() } label: {
                    Label("Stop VPN", systemImage: "bolt.slash.fill").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button {
                    vpn.start(peer: peer, vkLink: vkLink, obfKey: obfKey, clientId: clientId,
                              wgPrivateKey: wgPrivateKey, wgAddress: wgAddress,
                              peerPublicKey: peerPublicKey, peerPresharedKey: peerPresharedKey)
                } label: {
                    Label("Start VPN", systemImage: "bolt.fill").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canStart)
            }
        }
    }

    private func field(title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundColor(.secondary)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .textFieldStyle(.roundedBorder)
                .disabled(vpn.active)
        }
    }

    private var statusHeader: some View {
        HStack {
            Circle()
                .fill(vpn.status == "Connected" ? Color.green : (vpn.active ? Color.orange : Color.gray))
                .frame(width: 12, height: 12)
            Text(vpn.status).font(.headline)
            Spacer()
        }
    }
}

#Preview {
    ContentView()
}

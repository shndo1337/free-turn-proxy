import Foundation

/// Simple append-only log file in the shared App Group container, since the
/// extension is a separate process from the main app and Mobile's own
/// DumpLogs() ring buffer lives in whichever process calls it.
enum SharedLog {
    static let groupID = "group.com.shndo1337.freeturn"
    static let fileName = "tunnel.log"

    private static var url: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupID)?
            .appendingPathComponent(fileName)
    }

    private static let queue = DispatchQueue(label: "sharedlog")

    static func write(_ line: String) {
        queue.async {
            guard let url = url else { return }
            let ts = ISO8601DateFormatter().string(from: Date())
            let entry = "\(ts) \(line)\n"
            guard let data = entry.data(using: .utf8) else { return }
            if FileManager.default.fileExists(atPath: url.path) {
                if let handle = try? FileHandle(forWritingTo: url) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    try? handle.close()
                }
            } else {
                try? data.write(to: url)
            }
        }
    }

    static func clear() {
        queue.async {
            guard let url = url else { return }
            try? "".data(using: .utf8)?.write(to: url)
        }
    }

    static func read() -> String {
        guard let url = url, let data = try? Data(contentsOf: url) else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }
}

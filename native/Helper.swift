import Foundation
import Darwin
import SystemConfiguration
import Security
import CryptoKit

// A session-scoped helper, launched through macOS Authorization Services by
// osascript. Only the exact Electron main PID that requested authorization may
// use its socket. No shell, executable path or filesystem command is exposed.
let runtimeDirectory = "/var/run/levik-vpn"
let anchor = "com.apple/000.levikvpn"
let dnsKey = "State:/Network/Service/com.leviknet.vpn/DNS" as CFString
let helperURL = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
let resourcesURL = helperURL.deletingLastPathComponent().deletingLastPathComponent()
let bundleURL = resourcesURL.deletingLastPathComponent().deletingLastPathComponent()
let coreURL = resourcesURL.appendingPathComponent("xray/xray")

struct HelperError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw HelperError(message) }
}

func run(_ path: String, _ arguments: [String], input: Data? = nil, timeout: Double = 15) throws -> (Int32, String) {
    try autoreleasepool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "XRAY_LOCATION_ASSET": coreURL.deletingLastPathComponent().path, "GOMEMLIMIT": "64MiB"]
        let output = Pipe()
        let incoming = Pipe()
        process.standardOutput = output
        process.standardError = output
        process.standardInput = incoming
        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }
        try process.run()
        if let input { incoming.fileHandleForWriting.write(input) }
        try? incoming.fileHandleForWriting.close()
        // Drain output concurrently so verbose child output cannot deadlock wait.
        let collected = OutputCollector(output.fileHandleForReading)
        collected.start()
        if completed.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if completed.wait(timeout: .now() + 2) == .timedOut { kill(process.processIdentifier, SIGKILL); process.waitUntilExit() }
            throw HelperError("Системная операция превысила время ожидания")
        }
        return (process.terminationStatus, collected.finish())
    }
}

final class OutputCollector {
    private let handle: FileHandle
    private let done = DispatchSemaphore(value: 0)
    private var data = Data()
    init(_ handle: FileHandle) { self.handle = handle }
    func start() {
        DispatchQueue.global().async {
            while autoreleasepool(invoking: {
                let bytes = self.handle.availableData
                if bytes.isEmpty { return false }
                if self.data.count < 262144 { self.data.append(bytes.prefix(262144 - self.data.count)) }
                return true
            }) {}
            self.done.signal()
        }
    }
    func finish() -> String {
        done.wait()
        return String(decoding: data, as: UTF8.self)
    }
}

// Store only known error categories, never log lines, endpoints or credentials.
func coreErrorCategory(_ line: String) -> String? {
    let text = line.lowercased()
    let categories: [(String, String)] = [
        ("failed to update interface", "Не найден исходящий сетевой интерфейс"),
        ("iface == nil", "Не найден исходящий сетевой интерфейс"),
        ("network is unreachable", "Сеть VPN-сервера недоступна"),
        ("no route to host", "Нет маршрута к VPN-серверу"),
        ("connection refused", "VPN-сервер отклонил соединение"),
        ("certificate", "Ошибка сертификата VPN-сервера"),
        ("authentication", "Ошибка авторизации на VPN-сервере"),
        ("invalid user", "VPN-сервер отклонил профиль"),
        ("reality", "Ошибка согласования REALITY"),
        ("failed to lookup", "Не удалось разрешить адрес VPN-сервера"),
        ("dns", "Ошибка DNS внутри туннеля"),
        ("timeout", "VPN-сервер не ответил вовремя"),
        ("eof", "VPN-сервер закрыл соединение"),
    ]
    guard text.contains("failed") || text.contains("error") || text.contains("warning") || text.contains("iface == nil") else { return nil }
    return categories.first(where: { text.contains($0.0) })?.1
}

final class CoreDiagnostics {
    private let lock = NSLock()
    private var categories: [String] = []
    func consume(_ line: String) {
        guard let category = coreErrorCategory(line) else { return }
        lock.lock(); defer { lock.unlock() }
        if !categories.contains(category) { categories.append(category) }
    }
    func summary() -> String {
        lock.lock(); defer { lock.unlock() }
        return categories.prefix(3).joined(separator: "; ")
    }
    func drain(_ pipe: Pipe) {
        DispatchQueue.global().async {
            var buffer = Data()
            while autoreleasepool(invoking: {
                let data = pipe.fileHandleForReading.availableData
                if data.isEmpty { return false }
                buffer.append(data)
                while let newline = buffer.firstIndex(of: 10) {
                    self.consume(String(decoding: buffer.prefix(upTo: newline), as: UTF8.self))
                    buffer.removeSubrange(...newline)
                }
                if buffer.count > 65536 { buffer.removeAll() }
                return true
            }) {}
        }
    }
}

final class DNSAudit {
    let process = Process()
    private let lock = NSLock()
    private var packets = 0
    private let drained = DispatchSemaphore(value: 0)
    private var stopped = false
    init(interface: String) throws {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        try require(getifaddrs(&addresses) == 0, "Не удалось прочитать адреса интерфейса")
        defer { freeifaddrs(addresses) }
        var sources: [String] = []
        var current = addresses
        while let item = current {
            defer { current = item.pointee.ifa_next }
            guard String(cString: item.pointee.ifa_name) == interface,
                  let addr = item.pointee.ifa_addr, [AF_INET, AF_INET6].contains(Int32(addr.pointee.sa_family)) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: buffer).components(separatedBy: "%")[0]
                if isIP(ip) { sources.append("src host \(ip)") }
            }
        }
        try require(!sources.isEmpty, "Нет адресов для проверки DNS")
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        process.arguments = ["-p", "-n", "-q", "-tt", "-l", "-i", interface, "(" + sources.joined(separator: " or ") + ") and (udp port 53 or tcp port 53 or tcp port 853)"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        DispatchQueue.global().async {
            defer { self.drained.signal() }
            var buffer = Data()
            while autoreleasepool(invoking: {
                let data = pipe.fileHandleForReading.availableData
                if data.isEmpty { return false }
                buffer.append(data)
                while let newline = buffer.firstIndex(of: 10) {
                    let line = String(decoding: buffer.prefix(upTo: newline), as: UTF8.self)
                    if isCapturedPacket(line) { self.lock.lock(); self.packets += 1; self.lock.unlock() }
                    buffer.removeSubrange(...newline)
                }
                if buffer.count > 65536 { buffer.removeAll() }
                return true
            }) {}
        }
        Thread.sleep(forTimeInterval: 0.2)
        try require(process.isRunning, "Захват DNS недоступен")
    }
    func stop() -> Int {
        if stopped { lock.lock(); defer { lock.unlock() }; return packets }
        stopped = true
        if process.isRunning {
            process.terminate()
            let deadline = Date().addingTimeInterval(2)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
        }
        if drained.wait(timeout: .now() + 2) == .timedOut { return -1 }
        lock.lock(); defer { lock.unlock() }
        return packets
    }
}

func isCapturedPacket(_ line: String) -> Bool {
    // tcpdump -tt prefixes packets with epoch timestamps. Ignore empty lines
    // and capture status output; neither represents a packet on the interface.
    return line.range(of: "^[0-9]+\\.[0-9]+ IP6? ", options: .regularExpression) != nil
}

func isIP(_ value: String) -> Bool {
    var v4 = in_addr(); var v6 = in6_addr()
    return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
}

func primaryOutboundInterface() throws -> String {
    // Resolve before TUN routes are installed; otherwise a zero-prefix TUN
    // route can become the primary interface for scoped Darwin sockets.
    let result = try run("/sbin/route", ["-n", "get", "default"])
    guard result.0 == 0,
          let line = result.1.split(separator: "\n").first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") }),
          let name = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces),
          name.range(of: "^[A-Za-z][A-Za-z0-9]{0,15}$", options: .regularExpression) != nil,
          name != "lo0", if_nametoindex(name) != 0 else { throw HelperError("Не найден исходящий сетевой интерфейс") }
    return name
}

func isDNSHTTPSAddress(_ value: String) -> Bool {
    guard value.utf8.count <= 2048,
          value.rangeOfCharacter(from: .whitespacesAndNewlines.union(.controlCharacters)) == nil,
          !value.contains("\\"),
          let url = URLComponents(string: value), url.scheme == "https",
          let host = url.host, !host.isEmpty,
          url.user == nil, url.password == nil, url.fragment == nil else { return false }
    return url.port.map { (1...65535).contains($0) } ?? true
}

func inspectJSON(_ value: Any, depth: Int = 0, path: [String] = []) throws {
    try require(depth < 40, "Конфигурация слишком сложная")
    if let object = value as? [String: Any] {
        for (key, item) in object {
            let lowered = key.lowercased()
            try require(!lowered.contains("file") && !["exec", "command", "include", "unix", "masterkeylog"].contains(lowered), "Файловые параметры ядра запрещены")
            if ["address", "listen", "redirect"].contains(lowered), let text = item as? String {
                // Xray DNS server addresses may be HTTPS URLs. This exception
                // must not permit URL/file/socket paths in outbound addresses.
                let isDNSURL = path == ["dns", "servers", "*"] && key == "address" && isDNSHTTPSAddress(text)
                try require(isDNSURL || (!text.contains("/") && !text.contains("\\") && text.utf8.count <= 512), "Некорректный сетевой адрес")
            }
            try inspectJSON(item, depth: depth + 1, path: path + [key])
        }
    } else if let array = value as? [Any] {
        try require(array.count <= 10000, "Слишком много параметров ядра")
        for item in array { try inspectJSON(item, depth: depth + 1, path: path + ["*"]) }
    } else if let text = value as? String {
        try require(!text.hasPrefix("ext:") && !text.contains("\0"), "Внешние файлы конфигурации запрещены")
    }
}

func validateConfig(_ config: [String: Any]) throws {
    try inspectJSON(config)
    let allowed: Set<String> = ["log", "api", "dns", "inbounds", "outbounds", "routing", "policy", "stats"]
    try require(Set(config.keys).isSubset(of: allowed), "Неподдерживаемая конфигурация ядра")
    guard let inbound = config["inbounds"] as? [[String: Any]], inbound.count == 1,
          inbound[0]["protocol"] as? String == "tun", inbound[0]["tag"] as? String == "levik-tun-in",
          let outbounds = config["outbounds"] as? [[String: Any]], !outbounds.isEmpty, outbounds.count <= 12 else {
        throw HelperError("Некорректный VPN-профиль")
    }
    let protocols: Set<String> = ["vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "freedom", "blackhole", "dns"]
    for outbound in outbounds {
        try require(protocols.contains(outbound["protocol"] as? String ?? ""), "Протокол не поддерживается")
    }
}

func firewallRules(group: gid_t, interface: String?, killSwitch: Bool, dns: Bool) -> String {
    var rules = ["pass quick on lo0 all"]
    if let interface { rules.append("pass out quick on \(interface) all") }
    // DNS must remain inside TUN even for Xray/helper sockets. Bootstrap uses
    // HTTPS with an IP literal, so it needs no physical port 53/853 exception.
    if dns { rules.append("block drop out quick proto { tcp udp } to any port { 53 853 } label \"levik-dns\"") }
    // PF matches the socket's effective group. Only this authorized helper and
    // its Xray child run in the dedicated, membership-free system group.
    rules += ["pass out quick proto { tcp udp } group \(group) keep state",
              "pass out quick inet proto udp from any port 68 to any port 67 keep state",
              "pass out quick inet6 proto icmp6 icmp6-type { 133 134 135 136 }"]
    if killSwitch { rules.append("block drop out quick all label \"levik-kill-switch\"") }
    return rules.joined(separator: "\n") + "\n"
}

func verifiedBundleHash(_ url: URL, expectedVersion: String? = nil) throws -> Data {
    var code: SecStaticCode?
    try require(SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, "Не удалось проверить приложение")
    guard let code else { throw HelperError("Подпись приложения отсутствует") }
    try require(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate), nil) == errSecSuccess, "Файлы приложения изменены. Переустановите Levik VPN.")
    var info: CFDictionary?
    try require(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess, "Ошибка проверки подписи")
    guard let values = info as? [String: Any], values[kSecCodeInfoIdentifier as String] as? String == "com.leviknet.vpn.macos",
          let hash = values[kSecCodeInfoUnique as String] as? Data else { throw HelperError("Неизвестное приложение") }
    if let expectedVersion {
        let plistURL = url.appendingPathComponent("Contents/Info.plist")
        guard let plist = NSDictionary(contentsOf: plistURL),
              plist["CFBundleIdentifier"] as? String == "com.leviknet.vpn.macos",
              plist["CFBundleShortVersionString"] as? String == expectedVersion else {
            throw HelperError("Версия приложения не совпадает с обновлением")
        }
    }
    return hash
}

func signedBundleHash() throws -> Data { try verifiedBundleHash(bundleURL) }

func validUpdateVersion(_ value: String) -> Bool {
    value.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil
}

func sameProcess(_ pid: pid_t, started: UInt64) -> Bool {
    var info = proc_bsdinfo()
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 && info.pbi_start_tvsec == started
}

func launchApplication(_ application: URL, uid: uid_t) throws {
    // launchctl selects the interactive GUI bootstrap; sudo drops the root
    // credentials because launchctl asuser intentionally does not change UID.
    let result = try run("/bin/launchctl", ["asuser", String(uid), "/usr/bin/sudo", "-u", "#\(uid)", "--", "/usr/bin/open", "-n", application.path], timeout: 30)
    try require(result.0 == 0, "Не удалось перезапустить Levik VPN")
}

func installUpdate(parent: pid_t, stagedPath: String, expectedVersion: String, readyPath: String) throws {
    try require(getuid() == 0 && parent > 1 && validUpdateVersion(expectedVersion), "Некорректный запрос обновления")
    var parentExecutable = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    try require(proc_pidpath(parent, &parentExecutable, UInt32(parentExecutable.count)) > 0, "Приложение не найдено")
    let currentApplication = bundleURL.standardizedFileURL.resolvingSymlinksInPath()
    let expectedExecutable = currentApplication.appendingPathComponent("Contents/MacOS/Levik VPN").path
    try require(String(cString: parentExecutable) == expectedExecutable && currentApplication.path.hasPrefix("/Applications/"), "Запустите установленное приложение")
    var parentInfo = proc_bsdinfo()
    try require(proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &parentInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 && parentInfo.pbi_uid != 0, "Некорректный владелец приложения")
    let uid = parentInfo.pbi_uid
    let parentStarted = parentInfo.pbi_start_tvsec
    guard let account = getpwuid(uid), let homePointer = account.pointee.pw_dir else { throw HelperError("Пользователь приложения не найден") }
    let allowedRoot = URL(fileURLWithPath: String(cString: homePointer)).appendingPathComponent("Library/Application Support/levik-vpn-macos/update-staging", isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    let stagedApplication = URL(fileURLWithPath: stagedPath).standardizedFileURL.resolvingSymlinksInPath()
    let marker = URL(fileURLWithPath: readyPath).standardizedFileURL
    try require(stagedApplication.path.hasPrefix(allowedRoot.path + "/") && marker == stagedApplication.deletingLastPathComponent().appendingPathComponent(".installer-ready"), "Некорректный путь обновления")
    var stagedInfo = stat()
    try require(lstat(stagedApplication.path, &stagedInfo) == 0 && (stagedInfo.st_mode & S_IFMT) == S_IFDIR && stagedInfo.st_uid == uid, "Небезопасный каталог обновления")
    _ = try verifiedBundleHash(stagedApplication, expectedVersion: expectedVersion)
    let candidate = currentApplication.deletingLastPathComponent().appendingPathComponent(".Levik-VPN-update-\(UUID().uuidString).app")
    var swapped = false
    do {
        // Copy into the root-owned Applications directory before signalling
        // readiness. The user-writable staging tree is never trusted again.
        try FileManager.default.copyItem(at: stagedApplication, to: candidate)
        _ = try verifiedBundleHash(candidate, expectedVersion: expectedVersion)
        try Data("ready\n".utf8).write(to: marker, options: .atomic)
        chmod(marker.path, 0o644)
        let exitDeadline = Date().addingTimeInterval(120)
        while sameProcess(parent, started: parentStarted) && Date() < exitDeadline { Thread.sleep(forTimeInterval: 0.1) }
        try require(!sameProcess(parent, started: parentStarted), "Приложение не завершилось для установки")
        let result = candidate.path.withCString { source in
            currentApplication.path.withCString { destination in renamex_np(source, destination, UInt32(RENAME_SWAP)) }
        }
        try require(result == 0, "Не удалось атомарно заменить приложение")
        swapped = true
        _ = try verifiedBundleHash(currentApplication, expectedVersion: expectedVersion)
        try launchApplication(currentApplication, uid: uid)
        try? FileManager.default.removeItem(at: candidate)
        try? FileManager.default.removeItem(at: stagedApplication.deletingLastPathComponent())
    } catch {
        if swapped {
            _ = candidate.path.withCString { source in
                currentApplication.path.withCString { destination in renamex_np(source, destination, UInt32(RENAME_SWAP)) }
            }
        }
        try? FileManager.default.removeItem(at: candidate)
        if !sameProcess(parent, started: parentStarted) { try? launchApplication(currentApplication, uid: uid) }
        throw error
    }
}

func tunnelGroup() throws -> gid_t {
    let name = "_levikvpn"
    if let existing = getgrnam(name) {
        let group = existing.pointee
        try require(group.gr_gid >= 400 && group.gr_gid < 500 && group.gr_mem.pointee == nil, "Группа VPN имеет посторонних участников")
        let marker = try run("/usr/bin/dscl", [".", "-read", "/Groups/\(name)", "RealName"])
        try require(marker.0 == 0 && marker.1.contains("Levik VPN isolated tunnel"), "Имя системной группы VPN уже занято")
        let nested = try run("/usr/bin/dscl", [".", "-read", "/Groups/\(name)", "NestedGroups", "GroupMembers"])
        try require(!nested.1.contains("NestedGroups:") && !nested.1.contains("GroupMembers:"), "Группа VPN не изолирована")
        return group.gr_gid
    }
    guard let group = (400..<500).reversed().first(where: { getgrgid(gid_t($0)) == nil }) else { throw HelperError("Нет свободной системной группы") }
    for arguments in [[".", "-create", "/Groups/\(name)"], [".", "-create", "/Groups/\(name)", "PrimaryGroupID", String(group)], [".", "-create", "/Groups/\(name)", "RealName", "Levik VPN isolated tunnel"], [".", "-create", "/Groups/\(name)", "Password", "*"]] {
        try require(try run("/usr/bin/dscl", arguments).0 == 0, "Не удалось создать системную группу VPN")
    }
    return gid_t(group)
}

final class TunnelSession {
    let group: gid_t
    let signature: Data
    var child: Process?
    var exitCode: Int32?
    var interface: String?
    var killSwitch = false
    var dnsProtection = false
    var pfToken: String?
    var dnsServer = "1.1.1.1"
    var store: SCDynamicStore?
    var shouldExit = false
    var diagnostics = CoreDiagnostics()
    var outboundInterface = ""
    var dnsAudit: DNSAudit?

    init(group: gid_t, signature: Data) throws {
        self.group = group; self.signature = signature
        try recoverOrphanedCore()
        if let data = try? Data(contentsOf: URL(fileURLWithPath: runtimeDirectory + "/pf-token")), let token = String(data: data, encoding: .utf8), token.allSatisfy({ $0.isNumber }), !token.isEmpty { pfToken = token }
        if let data = try? Data(contentsOf: URL(fileURLWithPath: runtimeDirectory + "/protection.json")), let marker = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { killSwitch = marker["killSwitch"] as? Bool ?? false }
        store = SCDynamicStoreCreateWithOptions(nil, "Levik VPN" as CFString, [kSCDynamicStoreUseSessionKeys: true] as CFDictionary, nil, nil)
        try require(store != nil, "Системное управление DNS недоступно")
    }

    func status() throws -> [String: Any] {
        let running = child?.isRunning ?? false
        if let child, !running { exitCode = child.terminationStatus; self.child = nil }
        let rules = (killSwitch || dnsProtection) ? try run("/sbin/pfctl", ["-a", anchor, "-sr"]).1 : ""
        let enabled = (killSwitch || dnsProtection) ? try run("/sbin/pfctl", ["-s", "info"]).1.contains("Status: Enabled") : false
        return ["running": running, "killSwitch": killSwitch && enabled && rules.contains("levik-kill-switch"), "dnsProtection": dnsProtection && enabled && rules.contains("levik-dns"), "pid": child.map { Int($0.processIdentifier) } as Any? ?? NSNull(), "exitCode": exitCode.map { Int($0) } as Any? ?? NSNull()]
    }

    func start(_ supplied: [String: Any], killSwitch: Bool, dns: Bool) throws {
        try validateConfig(supplied)
        try require(try signedBundleHash() == signature, "Приложение обновилось. Перезапустите Levik VPN.")
        try stop()
        outboundInterface = try primaryOutboundInterface()
        var config = supplied
        // All privileged settings are constructed here, never accepted from IPC.
        guard let number = (30..<240).first(where: { if_nametoindex("utun\($0)") == 0 }) else { throw HelperError("Нет свободного VPN-интерфейса") }
        interface = "utun\(number)"
        config["log"] = ["access": "none", "error": "", "loglevel": "info"]
        config["api"] = ["tag": "levik-api", "listen": "127.0.0.1:47185", "services": ["StatsService"]]
        config["inbounds"] = [["tag": "levik-tun-in", "protocol": "tun", "settings": ["name": interface!, "mtu": 1500, "gateway": ["10.89.0.1/30"], "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"], "autoOutboundsInterface": outboundInterface], "sniffing": ["enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true]]]
        var inbounds = config["inbounds"] as! [[String: Any]]
        inbounds.append(["tag": "levik-connectivity", "listen": "127.0.0.1", "port": 47186, "protocol": "socks", "settings": ["auth": "noauth", "udp": false]])
        config["inbounds"] = inbounds
        var dnsConfig = config["dns"] as? [String: Any] ?? [:]
        var hosts = dnsConfig["hosts"] as? [String: Any] ?? [:]
        var outbounds = config["outbounds"] as? [[String: Any]] ?? []
        for index in outbounds.indices {
            for host in endpointHosts(outbounds[index]["settings"] ?? [:]) where !isIP(host) {
                hosts[host] = try resolveEndpoint(host)
            }
            if !["freedom", "blackhole", "dns"].contains(outbounds[index]["protocol"] as? String ?? "") {
                var stream = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
                var options = stream["sockopt"] as? [String: Any] ?? [:]
                options["domainStrategy"] = "UseIP"
                stream["sockopt"] = options
                outbounds[index]["streamSettings"] = stream
            }
        }
        dnsConfig["hosts"] = hosts
        config["dns"] = dnsConfig
        config["outbounds"] = outbounds
        guard let selectedTag = outbounds.first?["tag"] as? String,
              !["freedom", "blackhole", "dns"].contains(outbounds.first?["protocol"] as? String ?? "") else { throw HelperError("Не выбран VPN-сервер") }
        var routing = config["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "inboundTag": ["levik-connectivity"], "outboundTag": selectedTag], at: 0)
        routing["rules"] = rules
        config["routing"] = routing
        let bytes = try JSONSerialization.data(withJSONObject: config)
        let validation = try run(coreURL.path, ["run", "-test", "-format", "json", "-config", "stdin:"], input: bytes)
        try require(validation.0 == 0, "Xray отклонил VPN-профиль")
        self.killSwitch = killSwitch; self.dnsProtection = dns
        try applyFirewall(flushExisting: true)
        let process = Process()
        process.executableURL = coreURL
        process.arguments = ["run", "-format", "json", "-config", "stdin:"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "XRAY_LOCATION_ASSET": coreURL.deletingLastPathComponent().path, "GOMEMLIMIT": "64MiB"]
        let input = Pipe()
        let output = Pipe()
        diagnostics = CoreDiagnostics()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output
        try process.run()
        diagnostics.drain(output)
        child = process; exitCode = nil
        var coreInfo = proc_bsdinfo()
        try require(proc_pidinfo(process.processIdentifier, PROC_PIDTBSDINFO, 0, &coreInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0, "Не удалось проверить VPN-процесс")
        try JSONSerialization.data(withJSONObject: ["pid": Int(process.processIdentifier), "started": coreInfo.pbi_start_tvsec]).write(to: URL(fileURLWithPath: runtimeDirectory + "/core.json"), options: .atomic)
        chmod(runtimeDirectory + "/core.json", 0o600)
        input.fileHandleForWriting.write(bytes)
        try input.fileHandleForWriting.close()
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline && process.isRunning {
            if if_nametoindex(interface!) != 0,
               let health = try? run(coreURL.path, ["api", "statsquery", "--server=127.0.0.1:47185", "-pattern", "inbound>>>levik-tun-in>>>"], timeout: 2), health.0 == 0 {
                do { try verifyConnectivity() }
                catch { try stop(); throw error }
                if dns { try applyDNS() }
                return
            }
            Thread.sleep(forTimeInterval: 0.15)
        }
        try stop()
        throw HelperError("VPN-туннель не запустился. Защита сохраняется до отключения VPN.")
    }

    func verifyConnectivity() throws {
        // SOCKS routes this HTTPS request through the selected outbound even
        // with per-app bypass rules or another VPN present on the host.
        let result = try run("/usr/bin/curl", ["--proxy", "socks5://127.0.0.1:47186", "--noproxy", "", "--connect-timeout", "5", "--max-time", "8", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}", "https://1.1.1.1/cdn-cgi/trace"], timeout: 10)
        guard result.0 == 0 && result.1 == "200" else {
            let detail = diagnostics.summary()
            throw HelperError("VPN-сервер не передаёт данные" + (detail.isEmpty ? " (HTTPS: \(result.0)). Выберите другой сервер." : ": \(detail).") + " Выход: \(outboundInterface).")
        }
    }

    func stop() throws {
        if let child, child.isRunning {
            child.terminate()
            let deadline = Date().addingTimeInterval(5)
            while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL); child.waitUntilExit() }
        }
        child = nil
        try? FileManager.default.removeItem(atPath: runtimeDirectory + "/core.json")
        if let store { SCDynamicStoreRemoveValue(store, dnsKey) }
        // utun routes disappear with the descriptor even after SIGKILL. PF is
        // deliberately retained across replacement and unexpected core exit.
    }

    func protection(killSwitch: Bool, dns: Bool) throws {
        self.killSwitch = killSwitch; self.dnsProtection = dns
        try applyFirewall(flushExisting: false)
        if dns && child?.isRunning == true { try applyDNS() }
        else if let store { SCDynamicStoreRemoveValue(store, dnsKey) }
    }

    func disconnect() throws {
        _ = dnsAudit?.stop(); dnsAudit = nil
        try stop()
        try protection(killSwitch: false, dns: false)
    }

    func applyDNS() throws {
        guard let store else { throw HelperError("Системное управление DNS недоступно") }
        let resolver: [String: Any] = ["ServerAddresses": [dnsServer], "SupplementalMatchDomains": [""], "SupplementalMatchOrders": [0], "SupplementalMatchDomainsNoSearch": 1, "SearchOrder": 0]
        try require(SCDynamicStoreSetValue(store, dnsKey, resolver as CFDictionary), "Не удалось включить защищённый DNS")
    }

    func applyFirewall(flushExisting: Bool) throws {
        if !killSwitch && !dnsProtection {
            try require(try run("/sbin/pfctl", ["-a", anchor, "-F", "rules"]).0 == 0, "Не удалось снять сетевую защиту")
            if let token = pfToken {
                try require(try run("/sbin/pfctl", ["-X", token]).0 == 0, "Не удалось освободить сетевую защиту")
                pfToken = nil
                try? FileManager.default.removeItem(atPath: runtimeDirectory + "/pf-token")
            }
            try saveMarker()
            return
        }
        let root = try run("/sbin/pfctl", ["-sr"])
        try require(root.0 == 0 && root.1.contains("anchor \"com.apple/*\""), "Системные правила PF изменены. Не удалось безопасно подключить Kill Switch.")
        let rules = Data(firewallRules(group: group, interface: interface, killSwitch: killSwitch, dns: dnsProtection).utf8)
        try require(try run("/sbin/pfctl", ["-a", anchor, "-nf", "-"], input: rules).0 == 0, "PF отклонил правила защиты")
        try require(try run("/sbin/pfctl", ["-a", anchor, "-f", "-"], input: rules).0 == 0, "Не удалось включить правила защиты")
        if let token = pfToken, !(try run("/sbin/pfctl", ["-s", "info"]).1.contains("Status: Enabled")) {
            _ = try run("/sbin/pfctl", ["-X", token])
            pfToken = nil
        }
        if pfToken == nil {
            let enabled = try run("/sbin/pfctl", ["-E"])
            guard enabled.0 == 0, let match = enabled.1.range(of: "Token : [0-9]+", options: .regularExpression) else { throw HelperError("Не удалось включить PF") }
            pfToken = String(enabled.1[match]).components(separatedBy: " ").last
            try Data(pfToken!.utf8).write(to: URL(fileURLWithPath: runtimeDirectory + "/pf-token"), options: .atomic)
            chmod(runtimeDirectory + "/pf-token", 0o600)
        }
        try saveMarker()
        if flushExisting {
            // Previously established physical-interface states must not bypass
            // new protection rules. Flush only states originating at this Mac's
            // physical IPs, preserving other hosts' forwarded connections.
            var addresses: UnsafeMutablePointer<ifaddrs>?
            if getifaddrs(&addresses) == 0 {
                defer { freeifaddrs(addresses) }
                var current = addresses
                while let item = current {
                    defer { current = item.pointee.ifa_next }
                    let name = String(cString: item.pointee.ifa_name)
                    guard !name.hasPrefix("utun"), name != "lo0", let addr = item.pointee.ifa_addr,
                          [AF_INET, AF_INET6].contains(Int32(addr.pointee.sa_family)) else { continue }
                    var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                        let ip = String(cString: buffer).components(separatedBy: "%")[0]
                        _ = try run("/sbin/pfctl", ["-k", ip])
                    }
                }
            }
        }
    }

    func saveMarker() throws {
        try JSONSerialization.data(withJSONObject: ["killSwitch": killSwitch]).write(to: URL(fileURLWithPath: runtimeDirectory + "/protection.json"), options: .atomic)
        chmod(runtimeDirectory + "/protection.json", 0o644)
    }

    func recoverOrphanedCore() throws {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: runtimeDirectory + "/core.json")),
              let saved = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pidValue = saved["pid"] as? Int32, pidValue > 1,
              let started = saved["started"] as? UInt64 else { return }
        var info = proc_bsdinfo()
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidinfo(pidValue, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0,
              info.pbi_uid == 0, info.pbi_gid == group, info.pbi_start_tvsec == started,
              proc_pidpath(pidValue, &path, UInt32(path.count)) > 0,
              String(cString: path) == coreURL.path else { return }
        kill(pidValue, SIGTERM)
        let deadline = Date().addingTimeInterval(5)
        while kill(pidValue, 0) == 0 && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if kill(pidValue, 0) == 0 { kill(pidValue, SIGKILL) }
        try? FileManager.default.removeItem(atPath: runtimeDirectory + "/core.json")
    }
}

func endpointHosts(_ value: Any) -> Set<String> {
    if let object = value as? [String: Any] {
        var result: Set<String> = []
        if let address = object["address"] as? String { result.insert(address) }
        for (_, child) in object { result.formUnion(endpointHosts(child)) }
        return result
    }
    if let array = value as? [Any] { return array.reduce(into: Set<String>()) { $0.formUnion(endpointHosts($1)) } }
    return []
}

func resolveEndpoint(_ host: String) throws -> [String] {
    try require(host.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$", options: .regularExpression) != nil, "Некорректное имя VPN-сервера")
    // Use an IP-literal HTTPS bootstrap so reconnect does not depend on a DNS
    // resolver behind the stopped tunnel. curl keeps CFNetwork and its caches
    // out of this long-lived privileged process.
    let response = try run("/usr/bin/curl", ["--connect-timeout", "5", "--max-time", "8", "--silent", "--show-error", "--fail", "--header", "Accept: application/dns-json", "https://1.1.1.1/dns-query?name=\(host)&type=A"], timeout: 10)
    guard response.0 == 0,
          let object = try? JSONSerialization.jsonObject(with: Data(response.1.utf8)) as? [String: Any],
          object["Status"] as? Int == 0,
          let answers = object["Answer"] as? [[String: Any]] else { throw HelperError("Не удалось определить адрес VPN-сервера") }
    let result = answers.compactMap { $0["data"] as? String }.filter(isIP)
    try require(!result.isEmpty, "Не удалось определить адрес VPN-сервера")
    return result
}

func serve(parent: pid_t) throws {
    try require(getuid() == 0 && parent > 1, "Нужны системные права")
    var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    try require(proc_pidpath(parent, &path, UInt32(path.count)) > 0, "Приложение не найдено")
    let expected = bundleURL.appendingPathComponent("Contents/MacOS/Levik VPN").path
    try require(String(cString: path) == expected && expected.hasPrefix("/Applications/"), "Запустите установленное приложение")
    let signature = try signedBundleHash()
    var parentInfo = proc_bsdinfo()
    try require(proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &parentInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 && parentInfo.pbi_uid != 0, "Некорректный владелец приложения")
    let uid = parentInfo.pbi_uid
    if mkdir(runtimeDirectory, 0o755) != 0 { try require(errno == EEXIST, "Не удалось создать каталог VPN") }
    var directoryInfo = stat()
    try require(lstat(runtimeDirectory, &directoryInfo) == 0 && directoryInfo.st_uid == 0 && (directoryInfo.st_mode & S_IFMT) == S_IFDIR && (directoryInfo.st_mode & 0o022) == 0, "Небезопасный системный каталог")
    let lock = open(runtimeDirectory + "/session.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
    try require(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0, "VPN уже запущен")
    defer { close(lock) }
    let group = try tunnelGroup()
    try require(setgroups(0, nil) == 0 && setgid(group) == 0, "Не удалось изолировать VPN-процесс")
    let session = try TunnelSession(group: group, signature: signature)
    let server = socket(AF_UNIX, SOCK_STREAM, 0)
    try require(server >= 0, "Не удалось создать канал VPN")
    defer { close(server); unlink(runtimeDirectory + "/control.sock") }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let socketPath = runtimeDirectory + "/control.sock"
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: socketPath.utf8CString.map { UInt8(bitPattern: $0) }) }
    unlink(socketPath)
    let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(server, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    try require(bound == 0 && chmod(socketPath, 0o600) == 0 && chown(socketPath, uid, 0) == 0 && listen(server, 4) == 0, "Не удалось открыть канал VPN")
    var accepted: Int32 = -1
    let deadline = Date().addingTimeInterval(20)
    while Date() < deadline && accepted == -1 {
        var poller = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
        if poll(&poller, 1, 500) <= 0 { continue }
        let client = accept(server, nil, nil)
        if client < 0 { continue }
        var peerUID: uid_t = 0; var peerGID: gid_t = 0; var peerPID: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        if getpeereid(client, &peerUID, &peerGID) == 0 && peerUID == uid && getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &size) == 0 && peerPID == parent { accepted = client }
        else { close(client) }
    }
    try require(accepted >= 0, "Приложение не подключилось к VPN-помощнику")
    defer {
        close(accepted)
        _ = session.dnsAudit?.stop()
        try? session.stop()
        if !session.killSwitch { try? session.disconnect() }
    }
    var input = Data()
    var buffer = [UInt8](repeating: 0, count: 65536)
    while !session.shouldExit {
        var poller = pollfd(fd: accepted, events: Int16(POLLIN), revents: 0)
        if poll(&poller, 1, 1000) <= 0 { if kill(parent, 0) != 0 { break }; continue }
        let count = read(accepted, &buffer, buffer.count)
        if count <= 0 { break }
        input.append(contentsOf: buffer.prefix(count))
        if input.count > 2 * 1024 * 1024 { break }
        while let newline = input.firstIndex(of: 10) {
            let line = Data(input.prefix(upTo: newline))
            input.removeSubrange(...newline)
            var id = 0
            var response: [String: Any] = [:]
            autoreleasepool {
                do {
                    guard let object = try JSONSerialization.jsonObject(with: line) as? [String: Any], let requestID = object["id"] as? Int, requestID > 0, let command = object["command"] as? String else { throw HelperError("Некорректный запрос") }
                    id = requestID
                    var result: Any?
                    switch command {
                    case "start":
                        guard let config = object["config"] as? [String: Any], let killSwitch = object["killSwitch"] as? Bool, let dns = object["dnsProtection"] as? Bool else { throw HelperError("Некорректный VPN-профиль") }
                        if let dnsServer = object["dnsServer"] as? String { try require(isIP(dnsServer), "Некорректный DNS"); session.dnsServer = dnsServer }
                        try session.start(config, killSwitch: killSwitch, dns: dns)
                    case "stop": try session.stop()
                    case "protection":
                        guard let killSwitch = object["killSwitch"] as? Bool, let dns = object["dnsProtection"] as? Bool else { throw HelperError("Некорректные параметры защиты") }
                        try session.protection(killSwitch: killSwitch, dns: dns)
                    case "status": break
                    case "audit-start":
                        _ = session.dnsAudit?.stop()
                        try require(session.child?.isRunning == true, "Для проверки нужен активный туннель")
                        session.dnsAudit = try DNSAudit(interface: session.outboundInterface)
                    case "audit-stop":
                        guard let audit = session.dnsAudit else { throw HelperError("Проверка DNS не запущена") }
                        let packets = audit.stop(); session.dnsAudit = nil
                        result = ["physicalDNSPackets": packets]
                    case "audit-rules":
                        let rules = try run("/sbin/pfctl", ["-sr"])
                        try require(rules.0 == 0, "Не удалось прочитать правила PF")
                        result = ["rootRulesSHA256": SHA256.hash(data: Data(rules.1.utf8)).map { String(format: "%02x", $0) }.joined()]
                    case "abort-core":
                        guard let child = session.child, child.isRunning else { throw HelperError("VPN-ядро не запущено") }
                        kill(child.processIdentifier, SIGKILL)
                        child.waitUntilExit()
                    case "shutdown": try session.disconnect(); session.shouldExit = true
                    default: throw HelperError("Неизвестная команда")
                    }
                    response = ["id": id, "result": try result ?? session.status()]
                } catch {
                    response = ["id": id, "error": (error as? HelperError)?.description ?? "Системная операция VPN не выполнена"]
                }
            }
            var bytes = try JSONSerialization.data(withJSONObject: response); bytes.append(10)
            var offset = 0
            while offset < bytes.count {
                let sent = bytes.withUnsafeBytes { write(accepted, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
                if sent <= 0 { return }
                offset += sent
            }
        }
    }
}

func selfTest() throws {
    let config: [String: Any] = ["inbounds": [["protocol": "tun", "tag": "levik-tun-in"]], "outbounds": [["protocol": "freedom"]]]
    try validateConfig(config)
    var dohConfig = config
    dohConfig["dns"] = ["servers": [["address": "https://1.1.1.1/dns-query", "skipFallback": false], "1.1.1.1"]]
    try validateConfig(dohConfig)
    for address in ["file:///etc/passwd", "unix:///tmp/socket", "http://example.com/dns-query", "https://user:password@example.com/dns-query", "https:///dns-query", "https://example.com:70000/dns-query"] {
        try require(!isDNSHTTPSAddress(address), "Unsafe DNS URL accepted")
    }
    for value: [String: Any] in [["tlsSettings": ["keyFile": "/etc/master.passwd"]], ["address": "/tmp/socket"], ["rules": ["ext:/etc/passwd:test"]]] {
        do { try inspectJSON(value); throw HelperError("Validation regression") }
        catch let error as HelperError { if error.description == "Validation regression" { throw error } }
    }
    let rules = firewallRules(group: 499, interface: "utun30", killSwitch: true, dns: true)
    try require(rules.contains("group 499") && rules.contains("on utun30") && rules.contains("levik-kill-switch") && rules.contains("levik-dns"), "Firewall generation failed")
    try require(rules.range(of: "levik-dns")!.lowerBound < rules.range(of: "group 499")!.lowerBound, "Core DNS must not bypass protection")
    try require(isCapturedPacket("1788794670.123456 IP 192.0.2.1.1234 > 192.0.2.2.53: UDP, length 40") && isCapturedPacket("1788794670.123456 IP6 ::1.1234 > ::2.53: UDP, length 40") && !isCapturedPacket("") && !isCapturedPacket("1 packet captured"), "DNS capture counting failed")
    try require(!firewallRules(group: 499, interface: nil, killSwitch: false, dns: true).contains("levik-kill-switch"), "DNS-only policy regression")
    try require(isIP("1.1.1.1") && isIP("::1") && !isIP("999.1.1.1"), "Address validation failed")
    try require(coreErrorCategory("[Warning] failed to dial: connection refused at private.example with credential") == "VPN-сервер отклонил соединение", "Diagnostic classification failed")
    try require(coreErrorCategory("private profile payload") == nil, "Diagnostic privacy regression")
    try require(validUpdateVersion("1.2.3") && !validUpdateVersion("1.2") && !validUpdateVersion("1.2.3-beta"), "Update version validation failed")
    print("Native helper self-tests passed")
}

signal(SIGPIPE, SIG_IGN)
do {
    if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--self-test" { try selfTest() }
    else if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--validate-config" {
        // Non-privileged integration check. Does not launch Xray or change the network.
        let data = try FileHandle.standardInput.read(upToCount: 2 * 1024 * 1024 + 1) ?? Data()
        try require(data.count <= 2 * 1024 * 1024, "Конфигурация слишком большая")
        guard let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw HelperError("Некорректный VPN-профиль") }
        try validateConfig(config)
        print("Native configuration validation passed")
    }
    else if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--verify-bundle" { _ = try signedBundleHash(); print("Application bundle verified") }
    else if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--serve", let parent = Int32(CommandLine.arguments[2]) { try serve(parent: parent) }
    else if CommandLine.arguments.count == 6 && CommandLine.arguments[1] == "--install-update", let parent = Int32(CommandLine.arguments[2]) {
        try installUpdate(parent: parent, stagedPath: CommandLine.arguments[3], expectedVersion: CommandLine.arguments[4], readyPath: CommandLine.arguments[5])
    }
    else { throw HelperError("Unsupported invocation") }
} catch {
    let message = (error as? HelperError)?.description ?? "Native VPN operation failed"
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

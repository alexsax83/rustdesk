// Protocollo di RemoteX per la condivisione dello schermo di iPhone/iPad.
//
// Sicurezza, due livelli indipendenti:
//  1. TLS con chiave pre-condivisa (PSK). La chiave viene dal codice di
//     abbinamento (10 caratteri, ~50 bit, rafforzati con PBKDF2-SHA256 a
//     600.000 iterazioni) oppure, dopo il primo abbinamento, da una chiave
//     casuale a 256 bit del dispositivo conservata nel Portachiavi.
//  2. Dentro il TLS, uno scambio X25519 effimero a ogni connessione (segretezza
//     in avanti) mescolato con la stessa PSK tramite HKDF, poi ogni messaggio è
//     cifrato e autenticato con ChaCha20-Poly1305 con contatore (niente replay,
//     niente riordino). Chi non ha la PSK non ricava le chiavi di sessione,
//     anche se riuscisse a interporsi.

import Foundation
import Network
import CryptoKit
import CommonCrypto
import Security
#if os(iOS)
import UIKit
#endif

enum RemoteXRete {
    static let servizioAbbinamento = "_remotex._tcp"     // collegamento con codice
    static let servizioAbbinati = "_remotexp._tcp"       // aiutanti già riconosciuti (chiave del dispositivo)
    static let portaAbbinamento: NWEndpoint.Port = 47812
    static let portaAbbinati: NWEndpoint.Port = 47813
    static let portaInterna: NWEndpoint.Port = 47811    // estensione ↔ app sullo stesso iPhone
    static let servizioRichiesta = "_remotexr._tcp"     // prima volta senza codice: richiesta da confermare
    static let portaRichiesta: NWEndpoint.Port = 47814
    static let portaTrasmissione: NWEndpoint.Port = 47815  // lo schermo arriva dall'estensione di iOS, anche ad app chiusa
    static let portaJpeg: NWEndpoint.Port = 47816          // stesso schermo in JPEG, senza TLS (solo cifratura del Canale)
    static let portaVideo: NWEndpoint.Port = 47818         // chi guarda ascolta qui: è l'iPhone che si collega
    static let portaSonda: NWEndpoint.Port = 47817         // UDP: «chi c'è?» per Windows e Android, che non usano Bonjour
    static let sonda = Data("RemoteX-chi-c-e-v1".utf8)

    /// Richiesta senza codice: la cifratura c'è sempre (X25519 + ChaCha20-Poly1305),
    /// l'autenticazione la dà la persona che tocca «Consenti» dopo aver confrontato
    /// il numero di controllo (come l'abbinamento Bluetooth).
    static let chiaveRichiesta = SymmetricKey(data: SHA256.hash(data: Data("RemoteX-richiesta-v1".utf8)))

    static func parametriAperti() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let p = NWParameters(tls: nil, tcp: tcp)
        p.includePeerToPeer = true
        return p
    }

    /// Codice di 10 caratteri senza simboli ambigui, es. "K7QM3-XWPA9".
    static func nuovoCodice() -> String {
        let alfabeto = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        var c: [Character] = []
        for _ in 0..<10 {
            var b: UInt8 = 0
            repeat { _ = SecRandomCopyBytes(kSecRandomDefault, 1, &b) } while b >= 224   // niente sbilanciamento
            c.append(alfabeto[Int(b) % alfabeto.count])
        }
        return String(c[0..<5]) + "-" + String(c[5..<10])
    }

    static func normalizza(_ codice: String) -> String { codice.uppercased().filter { $0.isLetter || $0.isNumber } }

    /// Chiave dal codice: PBKDF2 lento apposta, per rendere inutile la forza bruta.
    static func chiave(daCodice codice: String) -> SymmetricKey {
        let pw = Array(normalizza(codice).utf8)
        let sale = Array("RemoteX-abbinamento-v2".utf8)
        var out = [UInt8](repeating: 0, count: 32)
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { CChar(bitPattern: $0) }, pw.count, sale, sale.count,
                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000, &out, out.count)
        return SymmetricKey(data: out)
    }

    static func chiaveCasuale() -> SymmetricKey { SymmetricKey(size: .bits256) }

    /// Parametri di rete: TCP senza ritardi. La sicurezza la dà il Canale: la chiave
    /// condivisa entra nella derivazione delle chiavi (chi non la conosce non supera la
    /// conferma) e ogni messaggio è cifrato e autenticato con ChaCha20-Poly1305.
    static func parametri(chiave: SymmetricKey) -> NWParameters { parametriAperti() }

    static func parametriInterni() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let p = NWParameters(tls: nil, tcp: tcp)
        p.requiredInterfaceType = .loopback
        return p
    }
}

// MARK: - Da fuori casa (Internet)

/// iPhone e iPad raggiungibili anche da fuori casa, con un codice usa e getta.
/// I due dispositivi si incontrano su un ripetitore pubblico (lo stesso usato dal motore di
/// Remote X per computer e telefoni): passa solo byte cifrati. La chiave nasce dal codice,
/// che resta sui due dispositivi; in più c'è sempre «Accetta» sull'iPhone.
enum RemoteXInternet {
    static let host = "rs-ny.rustdesk.com"
    static let porta: NWEndpoint.Port = 21117
    static let chiaveServer = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="

    /// 10 cifre, es. "4821937065" (si mostra come "48219 37065").
    static func nuovoCodice() -> String {
        var c = ""
        while c.count < 10 {
            var b: UInt8 = 0
            repeat { _ = SecRandomCopyBytes(kSecRandomDefault, 1, &b) } while b >= 250
            let cifra = Int(b) % 10
            if c.isEmpty && cifra == 0 { continue }
            c.append(Character(String(cifra)))
        }
        return c
    }
    static func soloCifre(_ c: String) -> String { c.filter(\.isNumber) }
    static func leggibile(_ c: String) -> String {
        let d = soloCifre(c); guard d.count == 10 else { return d }
        return String(d.prefix(5)) + " " + String(d.suffix(5))
    }
    /// Un codice da iPhone/iPad: 10 cifre senza trattino (quelli dei computer hanno il trattino).
    static func eCodiceIPhone(_ testo: String) -> Bool {
        let t = testo.filter { !$0.isWhitespace }
        return t.count == 10 && t.allSatisfy(\.isNumber)
    }
    static func uuid(_ codice: String, _ tipo: String) -> String {
        SHA256.hash(data: Data("RemoteX-internet-v1|\(tipo)|\(soloCifre(codice))".utf8)).map { String(format: "%02x", $0) }.joined()
    }
    /// Chiave dal codice (PBKDF2, lento apposta contro i tentativi).
    static func chiave(_ codice: String) -> SymmetricKey {
        let pw = Array(soloCifre(codice).utf8)
        let sale = Array("RemoteX-internet-v1".utf8)
        var out = [UInt8](repeating: 0, count: 32)
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { CChar(bitPattern: $0) }, pw.count, sale, sale.count,
                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 200_000, &out, out.count)
        return SymmetricKey(data: out)
    }
    private static func varint(_ v: Int) -> Data {
        var v = v; var d = Data()
        while v >= 0x80 { d.append(UInt8(v & 0x7f) | 0x80); v >>= 7 }
        d.append(UInt8(v)); return d
    }
    private static func campo(_ n: Int, _ dati: Data) -> Data { varint(n << 3 | 2) + varint(dati.count) + dati }
    /// Richiesta al ripetitore: «mettimi in contatto con chi usa lo stesso identificativo».
    static func richiesta(uuid: String) -> Data {
        let interna = campo(2, Data(uuid.utf8)) + campo(6, Data(chiaveServer.utf8))
        let m = campo(18, interna)
        var h = Data()
        let n = m.count
        if n <= 0x3F { h.append(UInt8(n << 2)) }
        else { let v = UInt16(n << 2) | 1; h.append(UInt8(v & 0xff)); h.append(UInt8(v >> 8)) }
        return h + m
    }
    static func connessione() -> NWConnection {
        NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: porta), using: RemoteXRete.parametriAperti())
    }
}

// MARK: - Portachiavi

enum Portachiavi {
    /// Gruppo condiviso tra app ed estensione (valore espanso da Xcode nell'Info.plist).
    static var gruppoCondiviso: String? { Bundle.main.object(forInfoDictionaryKey: "RemoteXGruppoPortachiavi") as? String }

    static func leggi(_ nome: String, gruppo: String? = nil) -> Data? {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "RemoteX",
                                kSecAttrAccount as String: nome, kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        if let gruppo { q[kSecAttrAccessGroup as String] = gruppo }
        var r: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &r) == errSecSuccess ? r as? Data : nil
    }

    @discardableResult
    static func scrivi(_ dati: Data, _ nome: String, gruppo: String? = nil) -> Bool {
        cancella(nome, gruppo: gruppo)
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "RemoteX",
                                kSecAttrAccount as String: nome, kSecValueData as String: dati]
        #if os(iOS)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        if let gruppo { q[kSecAttrAccessGroup as String] = gruppo }
        return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
    }

    static func cancella(_ nome: String, gruppo: String? = nil) {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "RemoteX",
                                kSecAttrAccount as String: nome]
        if let gruppo { q[kSecAttrAccessGroup as String] = gruppo }
        SecItemDelete(q as CFDictionary)
    }

    /// Restituisce la chiave salvata o ne crea una nuova a 256 bit.
    static func chiave(_ nome: String, gruppo: String? = nil) -> SymmetricKey {
        if let d = leggi(nome, gruppo: gruppo), d.count == 32 { return SymmetricKey(data: d) }
        let k = RemoteXRete.chiaveCasuale()
        scrivi(k.withUnsafeBytes { Data($0) }, nome, gruppo: gruppo)
        return k
    }
}

// MARK: - Messaggi

enum TipoMessaggio: UInt8 {
    case formato = 1            // SPS/PPS H.264
    case frame = 2              // 1 byte keyframe + dati AVCC
    case tocco = 3              // x, y normalizzati (Float32 big endian)
    case richiestaChiave = 4    // chiede un keyframe
    case chiaveDispositivo = 5  // 32 byte: chiave per i collegamenti futuri senza codice
    case conferma = 6           // prova che entrambi hanno le stesse chiavi di sessione
    case richiesta = 7          // nome di chi chiede di vedere lo schermo
    case consenso = 8           // la persona ha toccato «Consenti»
    case sessione = 9           // 32 byte: chiave della sessione per collegarsi alla trasmissione
    case jpeg = 10              // un'immagine JPEG dello schermo (per Windows, Android e l'app iPhone)
    case diagnostica = 11       // testo: a che punto è la trasmissione sull'iPhone
    case puntatore = 13         // x, y della freccia di chi aiuta (negativi = nascondi)
    case videoQui = 12          // 2 byte porta + 1 byte formato (1 H.264, 2 JPEG): dove mandare lo schermo
}

struct Messaggio {
    let tipo: TipoMessaggio
    let dati: Data
}

extension Data {
    mutating func appendUInt32(_ v: UInt32) { var b = v.bigEndian; Swift.withUnsafeBytes(of: &b) { append(contentsOf: $0) } }
    mutating func appendUInt64(_ v: UInt64) { var b = v.bigEndian; Swift.withUnsafeBytes(of: &b) { append(contentsOf: $0) } }
    func uint32(at i: Int) -> UInt32 {
        let b = [UInt8](self[(startIndex + i)..<(startIndex + i + 4)])
        return b.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }
}

func codificaTocco(x: Float, y: Float) -> Data {
    var d = Data(); d.appendUInt32(x.bitPattern); d.appendUInt32(y.bitPattern); return d
}

func decodificaTocco(_ d: Data) -> (Float, Float)? {
    guard d.count == 8 else { return nil }
    return (Float(bitPattern: d.uint32(at: 0)), Float(bitPattern: d.uint32(at: 4)))
}

// MARK: - Canale cifrato

/// Connessione con messaggi incorniciati, cifrati e autenticati.
/// Sul filo: 4 byte di lunghezza + blocco ChaCha20-Poly1305 (nonce = contatore).
/// Il primo blocco di ciascun lato è in chiaro (dentro il TLS): la chiave pubblica X25519 effimera.
final class Canale {
    let connessione: NWConnection
    var onMessaggio: ((Messaggio) -> Void)?
    var onStato: ((NWConnection.State) -> Void)?
    /// Chiamato quando lo scambio di chiavi è riuscito e verificato.
    var onPronto: (() -> Void)?
    /// Numero di controllo di 4 cifre, uguale sui due dispositivi solo se nessuno si è messo in mezzo.
    private(set) var numeroControllo: String?

    /// Dati da mandare prima di tutto (la richiesta al ripetitore, da fuori casa).
    var preambolo: Data?
    private let psk: SymmetricKey
    private let effimera = Curve25519.KeyAgreement.PrivateKey()
    private let lock = NSLock()
    private var chiaveInvio: SymmetricKey?
    private var chiaveRicezione: SymmetricKey?
    private var contInvio: UInt64 = 0
    private var contRicezione: UInt64 = 0
    private var inAttesa: [(TipoMessaggio, Data)] = []
    private var confermato = false
    private var inVolo = 0

    init(_ c: NWConnection, psk: SymmetricKey) {
        connessione = c
        self.psk = psk
    }

    func avvia(coda: DispatchQueue) {
        connessione.stateUpdateHandler = { [weak self] s in self?.onStato?(s) }
        connessione.start(queue: coda)
        if let p = preambolo {
            connessione.send(content: p, completion: .contentProcessed { _ in })
            coda.asyncAfter(deadline: .now() + 0.3) { [weak self] in
                guard let self else { return }
                self.lock.lock(); self.scriviBlocco(self.effimera.publicKey.rawRepresentation); self.lock.unlock()
            }
        } else {
            // Chiave pubblica effimera, in chiaro dentro il TLS.
            lock.lock(); scriviBlocco(effimera.publicKey.rawRepresentation); lock.unlock()
        }
        ricevi()
    }

    func chiudi() { connessione.cancel() }

    var codaInUscita: Int { lock.lock(); defer { lock.unlock() }; return inVolo }

    func invia(_ tipo: TipoMessaggio, _ dati: Data) {
        lock.lock(); defer { lock.unlock() }
        guard confermato else {
            if inAttesa.count < 60 { inAttesa.append((tipo, dati)) }   // non accumulare video prima della verifica
            return
        }
        inviaCifratoBloccato(tipo, dati)
    }

    // Da chiamare con il lock preso: cifratura e invio nello stesso ordine del contatore.
    private func inviaCifratoBloccato(_ tipo: TipoMessaggio, _ dati: Data) {
        guard let k = chiaveInvio else { return }
        var chiaro = Data([tipo.rawValue]); chiaro.append(dati)
        guard let busta = try? ChaChaPoly.seal(chiaro, using: k, nonce: nonce(contInvio)) else { return }
        contInvio += 1
        scriviBlocco(busta.ciphertext + busta.tag)
    }

    private func scriviBlocco(_ d: Data) {
        var pacchetto = Data(); pacchetto.appendUInt32(UInt32(d.count)); pacchetto.append(d)
        inVolo += 1
        connessione.send(content: pacchetto, completion: .contentProcessed { [weak self] _ in
            guard let self else { return }
            self.lock.lock(); self.inVolo -= 1; self.lock.unlock()
        })
    }

    private func nonce(_ n: UInt64) -> ChaChaPoly.Nonce {
        var d = Data(repeating: 0, count: 4); d.appendUInt64(n)
        return try! ChaChaPoly.Nonce(data: d)
    }

    private func ricevi() {
        connessione.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, fine, errore in
            guard let self else { return }
            guard errore == nil, let data, data.count == 4 else {
                if fine || errore != nil { self.connessione.cancel() }
                return
            }
            let n = Int(data.uint32(at: 0))
            guard n > 0, n < 16_000_000 else { self.connessione.cancel(); return }
            self.connessione.receive(minimumIncompleteLength: n, maximumLength: n) { corpo, _, _, err in
                guard err == nil, let corpo, corpo.count == n, self.elabora(Data(corpo)) else { self.connessione.cancel(); return }
                self.ricevi()
            }
        }
    }

    /// Restituisce false se qualcosa non torna: la connessione viene chiusa.
    private func elabora(_ blocco: Data) -> Bool {
        lock.lock()
        if chiaveRicezione == nil {
            // Primo blocco: chiave pubblica dell'altro lato.
            guard let altra = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: blocco),
                  let segreto = try? effimera.sharedSecretFromKeyAgreement(with: altra) else { lock.unlock(); return false }
            let mia = effimera.publicKey.rawRepresentation
            let sale = psk.withUnsafeBytes { Data($0) }
            chiaveInvio = segreto.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sale,
                                                          sharedInfo: Data("RemoteX-sessione".utf8) + mia + blocco, outputByteCount: 32)
            chiaveRicezione = segreto.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sale,
                                                              sharedInfo: Data("RemoteX-sessione".utf8) + blocco + mia, outputByteCount: 32)
            let coppia = [mia, blocco].sorted { $0.lexicographicallyPrecedes($1) }
            let v = segreto.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sale,
                                                    sharedInfo: Data("RemoteX-controllo".utf8) + coppia[0] + coppia[1], outputByteCount: 4)
            let n = v.withUnsafeBytes { $0.reduce(UInt32(0)) { $0 << 8 | UInt32($1) } } % 10000
            numeroControllo = String(format: "%04u", n)
            inviaCifratoBloccato(.conferma, Data("ok".utf8))
            lock.unlock()
            return true
        }
        guard blocco.count > 16, let k = chiaveRicezione else { lock.unlock(); return false }
        let n = nonce(contRicezione)
        guard let busta = try? ChaChaPoly.SealedBox(nonce: n, ciphertext: blocco.dropLast(16), tag: blocco.suffix(16)),
              let chiaro = try? ChaChaPoly.open(busta, using: k), let primo = chiaro.first else { lock.unlock(); return false }
        contRicezione += 1
        let dati = Data(chiaro.dropFirst())

        if primo == TipoMessaggio.conferma.rawValue {
            guard !confermato else { lock.unlock(); return true }
            confermato = true
            let coda = inAttesa; inAttesa.removeAll()
            for (t, d) in coda { inviaCifratoBloccato(t, d) }
            lock.unlock()
            onPronto?()
            return true
        }
        let ok = confermato
        lock.unlock()
        guard ok else { return false }
        if let tipo = TipoMessaggio(rawValue: primo) { onMessaggio?(Messaggio(tipo: tipo, dati: dati)) }
        return true
    }
}

// MARK: - Indirizzo nella rete Wi-Fi

/// Indirizzo IPv4 di questo dispositivo nella rete locale (Wi-Fi o cavo), es. "192.168.1.20".
func indirizzoLocale() -> String? {
    var lista: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&lista) == 0, let primo = lista else { return nil }
    defer { freeifaddrs(lista) }
    var trovato: String?
    for p in sequence(first: primo, next: { $0.pointee.ifa_next }) {
        let i = p.pointee
        guard let a = i.ifa_addr, a.pointee.sa_family == UInt8(AF_INET) else { continue }
        let nome = String(cString: i.ifa_name)
        guard nome.hasPrefix("en") else { continue }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        if getnameinfo(a, socklen_t(a.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
            let ip = String(cString: host)
            if nome == "en0" { return ip }
            trovato = trovato ?? ip
        }
    }
    return trovato
}

/// Nome di questo dispositivo da mostrare all'altra persona.
func nomeDispositivo() -> String {
    #if os(macOS)
    return Host.current().localizedName ?? "Mac"
    #else
    return UIDevice.current.name
    #endif
}

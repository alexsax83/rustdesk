// Remote X su iPhone/iPad: accoglie chi aiuta (scoperta automatica, «Consenti»,
// codice o dispositivo riconosciuto). Dopo il consenso crea la chiave della sessione,
// la passa all'estensione di trasmissione tramite il Portachiavi e avvia la
// trasmissione: da lì lo schermo va direttamente dall'estensione a chi aiuta.

import Foundation
import Network
import SwiftUI
import UIKit
import AVFoundation
import CryptoKit
import ReplayKit
import UserNotifications
import AVKit

@MainActor
final class Ponte: ObservableObject {
    @Published var codice = RemoteXRete.nuovoCodice()
    @Published var stato = "Un momento…"
    @Published var aiutanteCollegato = false
    @Published var richiesta: RichiestaInArrivo?
    /// Lo schermo è in trasmissione (iOS lo segnala con UIScreen.isCaptured).
    @Published var trasmissioneAttiva = UIScreen.main.isCaptured
    /// Messaggio breve dopo «Termina», così si vede che è finita davvero.
    @Published var avviso: String?
    /// Finestrella con la freccia di chi aiuta (si può spegnere nelle Impostazioni).
    @Published var frecciaVisibile = UserDefaults.standard.bool(forKey: "frecciaVisibile2") {
        didSet { UserDefaults.standard.set(frecciaVisibile, forKey: "frecciaVisibile2") }
    }

    private let coda = DispatchQueue(label: "remotex.ponte")
    private var ascoltoAbbinamento: NWListener?
    private var ascoltoAbbinati: NWListener?
    private var ascoltoRichieste: NWListener?
    private var inAttesaDiConsenso: Canale?
    private var aiutante: Canale?
    private var inCorso: Canale?        // abbinamento in corso: uno solo alla volta
    private var avviato = false
    private var tentativiFalliti = 0
    private var bloccatoFino = Date.distantPast

    private var chiaveDispositivo: SymmetricKey { Portachiavi.chiave("dispositivo") }

    func avvia() {
        guard !avviato else { return }
        avviato = true
        NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.trasmissioneAttiva = UIScreen.main.isCaptured
                if !UIScreen.main.isCaptured { PuntatoreRemoto.shared.ferma() }
                if UIScreen.main.isCaptured && self.richiesta != nil { self.consenti() }
                // Condivisione partita: Remote X si toglie di mezzo e torna alla schermata Home.
                if UIScreen.main.isCaptured && self.aiutante != nil { self.vaiInBackground() }
            }
        }
        avviaAbbinati()
        avviaAbbinamento()
        avviaRichieste()
        avviaSonda()
    }

    /// Windows e Android cercano gli iPhone chiedendo a tutta la rete «chi c'è?» (UDP):
    /// si risponde con il nome. Nessun dato personale, nessun collegamento.
    private var sonda: NWListener?
    private func avviaSonda() {
        let p = NWParameters.udp
        p.allowLocalEndpointReuse = true
        guard let l = try? NWListener(using: p, on: RemoteXRete.portaSonda) else { return }
        let coda = self.coda
        let risposta = Data(("RemoteX-io-v1\n" + nomeDispositivo()).utf8)
        l.newConnectionHandler = { c in
            c.start(queue: coda)
            c.receiveMessage { d, _, _, _ in
                guard d == RemoteXRete.sonda else { c.cancel(); return }
                c.send(content: risposta, completion: .contentProcessed { _ in c.cancel() })
            }
        }
        l.start(queue: coda)
        sonda = l
    }

    func rigeneraCodice() {
        codice = RemoteXRete.nuovoCodice()
        ascoltoAbbinamento?.cancel(); ascoltoAbbinamento = nil
        avviaAbbinamento()
    }

    /// Nuova chiave del dispositivo: tutti i aiutanti riconosciuti dovranno usare di nuovo il codice.
    func dimenticaAiutanti() {
        Portachiavi.cancella("dispositivo")
        aiutante?.chiudi(); aiutante = nil
        aiutanteCollegato = false
        ascoltoAbbinati?.cancel(); ascoltoAbbinati = nil
        avviaAbbinati()
        stato = "Fatto: d'ora in poi servirà di nuovo il codice"
    }

    // MARK: Aiutanti in rete

    /// Aiutanti già riconosciuti: si collegano con la chiave a 256 bit del dispositivo.
    private func avviaAbbinati() {
        avviaAscolto(chiave: chiaveDispositivo, porta: RemoteXRete.portaAbbinati,
                     servizio: RemoteXRete.servizioAbbinati, conCodice: false) { [weak self] l in self?.ascoltoAbbinati = l }
    }

    /// Primo collegamento con il codice. La chiave PBKDF2 si calcola fuori dal main thread.
    private func avviaAbbinamento() {
        let c = codice
        stato = "Preparo il codice…"
        DispatchQueue.global(qos: .userInitiated).async {
            let k = RemoteXRete.chiave(daCodice: c)
            Task { @MainActor in
                guard self.codice == c else { return }
                self.avviaAscolto(chiave: k, porta: RemoteXRete.portaAbbinamento,
                                  servizio: RemoteXRete.servizioAbbinamento, conCodice: true) { [weak self] l in self?.ascoltoAbbinamento = l }
                if !self.aiutanteCollegato { self.stato = "Nessuno collegato" }
            }
        }
    }

    private func avviaAscolto(chiave: SymmetricKey, porta: NWEndpoint.Port, servizio: String, conCodice: Bool,
                              salva: (NWListener) -> Void) {
        guard let l = try? NWListener(using: RemoteXRete.parametri(chiave: chiave), on: porta) else {
            stato = "Wi‑Fi non disponibile: controlla di essere collegato al Wi‑Fi"; return
        }
        l.service = NWListener.Service(name: UIDevice.current.name, type: servizio)
        l.newConnectionHandler = { [weak self] c in
            Task { @MainActor in self?.nuovoAiutante(c, chiave: chiave, conCodice: conCodice) }
        }
        l.stateUpdateHandler = { [weak self] s in
            if case .failed = s { Task { @MainActor in self?.stato = "Wi‑Fi non disponibile: controlla di essere collegato al Wi‑Fi" } }
        }
        l.start(queue: coda)
        salva(l)
    }

    private func nuovoAiutante(_ c: NWConnection, chiave: SymmetricKey, conCodice: Bool) {
        if conCodice && Date() < bloccatoFino { c.cancel(); return }
        // Collegamento 1 a 1: se c'è già un aiutante (o uno sta entrando) gli altri vengono rifiutati.
        guard aiutante == nil, inCorso == nil else { c.cancel(); return }
        let ch = Canale(c, psk: chiave)
        inCorso = ch
        let pronto = Bandiera()
        // Un tentativo lasciato a metà non deve bloccare il dispositivo.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self, weak ch] in
            guard let self, let ch, self.inCorso === ch, !pronto.valore else { return }
            ch.chiudi()
        }
        ch.onPronto = { [weak self] in
            Task { @MainActor in
                guard let self, self.inCorso === ch else { ch.chiudi(); return }
                pronto.valore = true
                self.tentativiFalliti = 0
                // Senza risposta entro un minuto la richiesta scade.
                DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self, weak ch] in
                    guard let self, let ch, self.inCorso === ch else { return }
                    ch.chiudi()
                }
            }
        }
        ch.onMessaggio = { [weak self] m in
            Task { @MainActor in
                guard let self else { return }
                if m.tipo == .videoQui { self.ricordaDestinazione(ch, m.dati) }
                if self.aiutante === ch, let t = decodificaTocco(m.dati) {
                    if m.tipo == .puntatore { PuntatoreRemoto.shared.punta(t.0, t.1) }
                    if m.tipo == .tocco { PuntatoreRemoto.shared.tocca(t.0, t.1) }
                }
                guard m.tipo == .richiesta else { return }
                self.mostraRichiesta(ch, nome: String(decoding: m.dati.prefix(80), as: UTF8.self), conCodice: conCodice)
            }
        }
        ch.onStato = { [weak self] s in
            switch s {
            case .failed, .cancelled:
                Task { @MainActor in
                    if self?.inAttesaDiConsenso === ch { self?.annullaRichiesta() }
                    self?.aiutanteChiuso(ch, eraPronto: pronto.valore, conCodice: conCodice)
                }
            default: break
            }
        }
        ch.avvia(coda: coda)
    }

    private func aiutanteChiuso(_ ch: Canale, eraPronto: Bool, conCodice: Bool) {
        if inCorso === ch { inCorso = nil }
        if aiutante === ch {
            PuntatoreRemoto.shared.ferma()
            aiutante = nil
            aiutanteCollegato = false
            stato = "Nessuno collegato"
        }
        if conCodice && !eraPronto {
            // Codice sbagliato o tentativo ostile: dopo 5 errori codice nuovo e pausa di 60 secondi.
            tentativiFalliti += 1
            if tentativiFalliti >= 5 {
                tentativiFalliti = 0
                bloccatoFino = Date().addingTimeInterval(60)
                rigeneraCodice()
                stato = "Troppi codici sbagliati: ho creato un codice nuovo. Aspetta un minuto e riprova."
            }
        }
    }

    // MARK: Prima volta senza codice: richiesta da confermare

    private func avviaRichieste() {
        guard let l = try? NWListener(using: RemoteXRete.parametriAperti(), on: RemoteXRete.portaRichiesta) else { return }
        l.service = NWListener.Service(name: UIDevice.current.name, type: RemoteXRete.servizioRichiesta)
        l.newConnectionHandler = { [weak self] c in
            Task { @MainActor in self?.nuovoRichiedente(c) }
        }
        l.start(queue: coda)
        ascoltoRichieste = l
    }

    private func nuovoRichiedente(_ c: NWConnection) {
        // 1 a 1, e una sola richiesta alla volta.
        guard aiutante == nil, inCorso == nil, Date() >= bloccatoFino else { c.cancel(); return }
        let ch = Canale(c, psk: RemoteXRete.chiaveRichiesta)
        inCorso = ch
        ch.onMessaggio = { [weak self] m in
            Task { @MainActor in
                guard let self else { return }
                if m.tipo == .videoQui { self.ricordaDestinazione(ch, m.dati) }
                if self.aiutante === ch, let t = decodificaTocco(m.dati) {
                    if m.tipo == .puntatore { PuntatoreRemoto.shared.punta(t.0, t.1) }
                    if m.tipo == .tocco { PuntatoreRemoto.shared.tocca(t.0, t.1) }
                }
                guard m.tipo == .richiesta else { return }
                self.mostraRichiesta(ch, nome: String(decoding: m.dati.prefix(80), as: UTF8.self), conCodice: false)
            }
        }
        ch.onStato = { [weak self] s in
            switch s {
            case .failed, .cancelled:
                Task { @MainActor in
                    guard let self else { return }
                    if self.inAttesaDiConsenso === ch { self.annullaRichiesta() }
                    self.aiutanteChiuso(ch, eraPronto: true, conCodice: false)
                }
            default: break
            }
        }
        ch.avvia(coda: coda)
        // Senza risposta entro un minuto la richiesta scade.
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self, weak ch] in
            guard let self, let ch, self.aiutante !== ch, self.inCorso === ch else { return }
            ch.chiudi()
        }
    }

    /// Torna alla schermata Home (come premere il tasto Home). Per un'app installata
    /// direttamente sui propri dispositivi va bene; non è una funzione per l'App Store.
    private func vaiInBackground() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
            guard UIApplication.shared.applicationState == .active else { return }
            UIControl().sendAction(NSSelectorFromString("suspend"), to: UIApplication.shared, for: nil)
        }
    }

    private var richiestaConCodice = false
    private var destinazioni: [ObjectIdentifier: String] = [:]

    /// Chi guarda dice su quale porta aspetta lo schermo: l'estensione si collegherà lì
    /// (iOS non lascia sempre ricevere collegamenti a un'estensione, uscire sì).
    private func ricordaDestinazione(_ ch: Canale, _ d: Data) {
        guard d.count == 3, case let .hostPort(host, _)? = ch.connessione.currentPath?.remoteEndpoint else { return }
        let porta = Int(d[d.startIndex]) << 8 | Int(d[d.startIndex + 1])
        destinazioni[ObjectIdentifier(ch)] = "\(host)|\(porta)|\(d[d.startIndex + 2])"
    }

    private var ultimoStato = ""
    private var timerStato: Timer?
    /// Inoltra a chi guarda a che punto è la trasmissione (utile se lo schermo non arriva).
    private func seguiStato() {
        timerStato?.invalidate()
        timerStato = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, let ch = self.aiutante ?? self.inAttesaDiConsenso else { return }
                let t = Portachiavi.leggi("statoTrasmissione", gruppo: Portachiavi.gruppoCondiviso).map { String(decoding: $0, as: UTF8.self) } ?? ""
                if !t.isEmpty && t != self.ultimoStato { self.ultimoStato = t; ch.invia(.diagnostica, Data(t.utf8)) }
            }
        }
    }
    private var chiaveInAttesa: Data?

    /// Compare il messaggio «… vuole vedere il tuo schermo» con Accetta e Rifiuta.
    /// La chiave della sessione si prepara subito (resta solo su questo iPhone), così
    /// la trasmissione può partire nello stesso istante in cui si tocca Accetta.
    private func mostraRichiesta(_ ch: Canale, nome: String, conCodice: Bool) {
        guard inCorso === ch, richiesta == nil, aiutante == nil else { return }
        inAttesaDiConsenso = ch
        richiestaConCodice = conCodice
        let k = RemoteXRete.chiaveCasuale().withUnsafeBytes { Data($0) }
        chiaveInAttesa = k
        if !UIScreen.main.isCaptured { Portachiavi.scrivi(k, "sessione", gruppo: Portachiavi.gruppoCondiviso) }
        Portachiavi.cancella("statoTrasmissione", gruppo: Portachiavi.gruppoCondiviso)
        ultimoStato = ""
        if let dest = destinazioni[ObjectIdentifier(ch)] {
            Portachiavi.scrivi(Data(dest.utf8), "destinazione", gruppo: Portachiavi.gruppoCondiviso)
        }
        seguiStato()
        richiesta = RichiestaInArrivo(nome: nome.isEmpty ? "Un dispositivo" : nome, numero: ch.numeroControllo ?? "----")
    }

    private func annullaRichiesta() {
        inAttesaDiConsenso = nil
        richiesta = nil
        chiaveInAttesa = nil
        if aiutante == nil && !UIScreen.main.isCaptured { Portachiavi.cancella("sessione", gruppo: Portachiavi.gruppoCondiviso) }
    }

    /// Accetta: chi aiuta riceve la chiave della sessione e lo schermo parte.
    func consenti() {
        guard let ch = inAttesaDiConsenso, let k = chiaveInAttesa else { richiesta = nil; return }
        inAttesaDiConsenso = nil
        chiaveInAttesa = nil
        richiesta = nil
        if inCorso === ch { inCorso = nil }
        guard aiutante == nil else { ch.chiudi(); return }
        aiutante = ch
        aiutanteCollegato = true
        stato = "Una persona sta guardando il tuo schermo"
        ch.invia(.consenso, Data())
        // Da ora chi aiuta è riconosciuto: la chiave del dispositivo è a 256 bit.
        ch.invia(.chiaveDispositivo, chiaveDispositivo.withUnsafeBytes { Data($0) })
        if richiestaConCodice { rigeneraCodice() }   // il codice usato non vale più
        if UIScreen.main.isCaptured {
            // Trasmissione già attiva: si usa la chiave con cui è partita.
            if let attuale = Portachiavi.leggi("sessione", gruppo: Portachiavi.gruppoCondiviso) {
                ch.invia(.sessione, attuale)
                if frecciaVisibile { PuntatoreRemoto.shared.avvia(chiave: attuale) }
            }
        } else {
            Portachiavi.scrivi(k, "sessione", gruppo: Portachiavi.gruppoCondiviso)
            ch.invia(.sessione, k)
            if frecciaVisibile { PuntatoreRemoto.shared.avvia(chiave: k) }
        }
    }

    func terminaAiutante() {
        PuntatoreRemoto.shared.ferma()
        avviso = "Condivisione terminata: nessuno vede più il tuo schermo"
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in self?.avviso = nil }
        // Senza chiave di sessione l'estensione chiude da sola la trasmissione.
        Portachiavi.cancella("sessione", gruppo: Portachiavi.gruppoCondiviso)
        aiutante?.chiudi()
        aiutante = nil
        aiutanteCollegato = false
        stato = "Nessuno collegato"
    }

    func rifiuta() {
        let ch = inAttesaDiConsenso
        annullaRichiesta()
        ch?.chiudi()
    }

}

final class Bandiera: @unchecked Sendable { var valore = false }

struct RichiestaInArrivo: Identifiable {
    let id = UUID()
    let nome: String
    let numero: String
}

/// Il pulsante di sistema che avvia la trasmissione, steso su tutta la sua area:
/// sta (invisibile) sopra il pulsante «Accetta», così un solo tocco accetta e
/// apre la conferma obbligatoria di iOS «Inizia condivisione».
final class SelettorePieno: RPSystemBroadcastPickerView {
    var alTocco: (() -> Void)?
    private var agganciati = Set<ObjectIdentifier>()

    override init(frame: CGRect) {
        super.init(frame: frame)
        preferredExtension = (Bundle.main.bundleIdentifier ?? "") + ".Broadcast"
        showsMicrophoneButton = false
    }
    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func layoutSubviews() {
        super.layoutSubviews()
        for v in subviews {
            v.frame = bounds
            if let b = v as? UIButton, !agganciati.contains(ObjectIdentifier(b)) {
                agganciati.insert(ObjectIdentifier(b))
                b.addTarget(self, action: #selector(toccato), for: .touchUpInside)
            }
        }
    }

    @objc private func toccato() { alTocco?() }

    /// Preme il pulsante di sistema come se lo toccasse la persona.
    func premi() {
        layoutIfNeeded()
        for case let b as UIButton in subviews { b.sendActions(for: .touchUpInside) }
    }
}

/// Un solo pulsante di sistema, sempre presente nella finestra (quasi invisibile):
/// dopo «Accetta» l'app lo preme e iOS mostra «Inizia condivisione».
@MainActor
enum AvvioTrasmissione {
    static let selettore = SelettorePieno(frame: CGRect(x: 0, y: 0, width: 4, height: 4))
    static func avvia() {
        guard !UIScreen.main.isCaptured else { return }
        selettore.premi()
    }
}

// MARK: - Puntatore di chi aiuta, visibile sull'iPhone

/// Vista il cui strato mostra immagini già pronte (serve al Picture in Picture).
final class VistaStrato: UIView {
    override class var layerClass: AnyClass { AVSampleBufferDisplayLayer.self }
    var strato: AVSampleBufferDisplayLayer { layer as! AVSampleBufferDisplayLayer }
}

/// iOS non permette di disegnare sopra le altre app. L'unico modo per far vedere
/// dove indica chi aiuta è una piccola finestra mobile (Picture in Picture): mostra
/// lo schermo in miniatura con la freccia di chi aiuta e un cerchio dove tocca.
/// Si sposta, si ingrandisce con due dita o si nasconde a lato con un gesto.
@MainActor
final class PuntatoreRemoto: NSObject, AVPictureInPictureSampleBufferPlaybackDelegate {
    static let shared = PuntatoreRemoto()
    let vista: VistaStrato = {
        let v = VistaStrato(frame: CGRect(x: 0, y: 0, width: 30, height: 60))
        v.strato.videoGravity = .resizeAspect
        v.backgroundColor = .black
        v.layer.cornerRadius = 4
        v.clipsToBounds = true
        return v
    }()
    private var pip: AVPictureInPictureController?
    private var ascolto: NWListener?
    private var canale: Canale?
    private var miniatura: CGImage?
    private var punto: CGPoint?
    private var ultimoMovimento = Date.distantPast
    private var tocchi: [(CGPoint, Date)] = []
    private var timer: Timer?
    private var attivo = false
    private let codaRete = DispatchQueue(label: "remotex.puntatore")

    func avvia(chiave: Data) {
        guard !attivo else { return }
        attivo = true
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .default, options: [.mixWithOthers])
        try? AVAudioSession.sharedInstance().setActive(true)
        ascolta(chiave: SymmetricKey(data: chiave))
        timer = Timer.scheduledTimer(withTimeInterval: 1.0 / 15, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.disegna() }
        }
        disegna()
        if pip == nil, AVPictureInPictureController.isPictureInPictureSupported() {
            let p = AVPictureInPictureController(contentSource: .init(sampleBufferDisplayLayer: vista.strato, playbackDelegate: self))
            p.canStartPictureInPictureAutomaticallyFromInline = true
            p.requiresLinearPlayback = true
            pip = p
        }
        if UIApplication.shared.applicationState == .active { prova(5) }
        attivazione = NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification,
                                                             object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.prova(3) }
        }
    }
    private var attivazione: NSObjectProtocol?

    /// Il Picture in Picture parte solo quando è pronto: si riprova qualche volta.
    private func prova(_ volte: Int) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in
            guard let self, self.attivo, let p = self.pip, !p.isPictureInPictureActive else { return }
            if p.isPictureInPicturePossible { p.startPictureInPicture() } else if volte > 0 { self.prova(volte - 1) }
        }
    }

    func ferma() {
        guard attivo else { return }
        attivo = false
        pip?.stopPictureInPicture()
        if let a = attivazione { NotificationCenter.default.removeObserver(a); attivazione = nil }
        timer?.invalidate(); timer = nil
        ascolto?.cancel(); ascolto = nil
        canale?.chiudi(); canale = nil
        miniatura = nil; punto = nil; tocchi = []
        vista.strato.flushAndRemoveImage()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    func punta(_ x: Float, _ y: Float) {
        if x < 0 || y < 0 { punto = nil; return }
        punto = CGPoint(x: CGFloat(min(max(x, 0), 1)), y: CGFloat(min(max(y, 0), 1)))
        ultimoMovimento = Date()
    }

    func tocca(_ x: Float, _ y: Float) {
        let p = CGPoint(x: CGFloat(min(max(x, 0), 1)), y: CGFloat(min(max(y, 0), 1)))
        punto = p
        ultimoMovimento = Date()
        tocchi.append((p, Date()))
    }

    /// Miniature dello schermo dall'estensione, sullo stesso iPhone, cifrate con la chiave della sessione.
    private func ascolta(chiave: SymmetricKey) {
        // Solo 127.0.0.1 (IPv4): è lì che si collega l'estensione.
        let par = RemoteXRete.parametriInterni()
        par.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: RemoteXRete.portaInterna)
        par.allowLocalEndpointReuse = true
        guard let l = try? NWListener(using: par) else { return }
        l.newConnectionHandler = { [weak self] c in
            let ch = Canale(c, psk: chiave)
            ch.onMessaggio = { m in
                guard m.tipo == .jpeg, let img = UIImage(data: m.dati)?.cgImage else { return }
                Task { @MainActor in self?.miniatura = img }
            }
            Task { @MainActor in
                self?.canale?.chiudi()
                self?.canale = ch
                ch.avvia(coda: self?.codaRete ?? .main)
            }
        }
        l.start(queue: codaRete)
        ascolto = l
    }

    private func disegna() {
        guard attivo else { return }
        let w = 360
        let h = miniatura.map { max(200, Int(Double($0.height) * 360 / Double(max($0.width, 1)))) } ?? 780
        var pb: CVPixelBuffer?
        CVPixelBufferCreate(nil, w, h, kCVPixelFormatType_32BGRA,
                            [kCVPixelBufferIOSurfacePropertiesKey: [:]] as CFDictionary, &pb)
        guard let pb else { return }
        CVPixelBufferLockBaseAddress(pb, [])
        if let ctx = CGContext(data: CVPixelBufferGetBaseAddress(pb), width: w, height: h, bitsPerComponent: 8,
                               bytesPerRow: CVPixelBufferGetBytesPerRow(pb), space: CGColorSpaceCreateDeviceRGB(),
                               bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue) {
            let tutto = CGRect(x: 0, y: 0, width: w, height: h)
            ctx.setFillColor(UIColor(white: 0.12, alpha: 1).cgColor)
            ctx.fill(tutto)
            if let m = miniatura { ctx.draw(m, in: tutto) }
            let ora = Date()
            let indica = punto != nil && ora.timeIntervalSince(ultimoMovimento) < 6
            let didascalia: String? = miniatura == nil ? "Aspetto l'immagine dello schermo…"
                : (indica ? nil : "Qui vedrai dove indica chi ti aiuta")
            if let t = didascalia {
                ctx.saveGState()
                ctx.translateBy(x: 0, y: CGFloat(h)); ctx.scaleBy(x: 1, y: -1)
                UIGraphicsPushContext(ctx)
                let fascia = CGRect(x: 0, y: 0, width: CGFloat(w), height: 54)
                UIColor.black.withAlphaComponent(0.65).setFill()
                UIRectFill(fascia)
                let st = NSMutableParagraphStyle(); st.alignment = .center
                (t as NSString).draw(in: fascia.insetBy(dx: 10, dy: 15), withAttributes: [
                    .font: UIFont.systemFont(ofSize: 19, weight: .semibold),
                    .foregroundColor: UIColor.white, .paragraphStyle: st])
                UIGraphicsPopContext()
                ctx.restoreGState()
            }
            tocchi.removeAll { ora.timeIntervalSince($0.1) > 0.9 }
            for (p, t) in tocchi {
                let eta = CGFloat(ora.timeIntervalSince(t)) / 0.9
                let c = CGPoint(x: p.x * CGFloat(w), y: (1 - p.y) * CGFloat(h))
                let r = 10 + eta * 40
                ctx.setStrokeColor(UIColor.systemOrange.withAlphaComponent(1 - eta).cgColor)
                ctx.setLineWidth(5)
                ctx.strokeEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
            }
            if let p = punto, ora.timeIntervalSince(ultimoMovimento) < 6 {
                let c = CGPoint(x: p.x * CGFloat(w), y: (1 - p.y) * CGFloat(h))
                // Alone rosso che pulsa, per trovarla subito.
                let fase = CGFloat(sin(ora.timeIntervalSinceReferenceDate * 6) * 0.5 + 0.5)
                let alone = 16 + fase * 8
                ctx.setFillColor(UIColor.systemRed.withAlphaComponent(0.35).cgColor)
                ctx.fillEllipse(in: CGRect(x: c.x - alone, y: c.y - alone, width: 2 * alone, height: 2 * alone))
                // Freccia classica con la punta esattamente sul punto.
                let punte: [(CGFloat, CGFloat)] = [(0, 0), (0, -26), (6.5, -20), (11, -30), (15.5, -28), (11, -18.5), (19, -18.5)]
                let forma = punte.map { CGPoint(x: c.x + $0.0, y: c.y + $0.1) }
                ctx.beginPath(); ctx.addLines(between: forma); ctx.closePath()
                ctx.setFillColor(UIColor.white.cgColor)
                ctx.setStrokeColor(UIColor.black.cgColor)
                ctx.setLineWidth(2)
                ctx.drawPath(using: .fillStroke)
            }
        }
        CVPixelBufferUnlockBaseAddress(pb, [])

        var formato: CMVideoFormatDescription?
        CMVideoFormatDescriptionCreateForImageBuffer(allocator: nil, imageBuffer: pb, formatDescriptionOut: &formato)
        guard let formato else { return }
        var tempi = CMSampleTimingInfo(duration: CMTime(value: 1, timescale: 15),
                                       presentationTimeStamp: CMClockGetTime(CMClockGetHostTimeClock()), decodeTimeStamp: .invalid)
        var sb: CMSampleBuffer?
        CMSampleBufferCreateReadyWithImageBuffer(allocator: nil, imageBuffer: pb, formatDescription: formato,
                                                 sampleTiming: &tempi, sampleBufferOut: &sb)
        guard let sb else { return }
        if let arr = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: true), CFArrayGetCount(arr) > 0 {
            let d = unsafeBitCast(CFArrayGetValueAtIndex(arr, 0), to: CFMutableDictionary.self)
            CFDictionarySetValue(d, Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                                 Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }
        if vista.strato.status == .failed { vista.strato.flush() }
        vista.strato.enqueue(sb)
    }

    // Una finestra «dal vivo»: niente pausa, niente avanti/indietro.
    nonisolated func pictureInPictureController(_ c: AVPictureInPictureController, setPlaying playing: Bool) {}
    nonisolated func pictureInPictureControllerTimeRangeForPlayback(_ c: AVPictureInPictureController) -> CMTimeRange {
        CMTimeRange(start: .negativeInfinity, duration: .positiveInfinity)
    }
    nonisolated func pictureInPictureControllerIsPlaybackPaused(_ c: AVPictureInPictureController) -> Bool { false }
    nonisolated func pictureInPictureController(_ c: AVPictureInPictureController, didTransitionToRenderSize s: CMVideoDimensions) {}
    nonisolated func pictureInPictureController(_ c: AVPictureInPictureController, skipByInterval i: CMTime,
                                                completion: @escaping () -> Void) { completion() }
}

/// Piccola anteprima nella barra in alto (serve anche ad avviare la finestra mobile).
struct AnteprimaPuntatore: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        let c = UIView(frame: CGRect(x: 0, y: 0, width: 30, height: 60))
        let v = PuntatoreRemoto.shared.vista
        v.removeFromSuperview()
        v.frame = c.bounds
        v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        c.addSubview(v)
        return c
    }
    func updateUIView(_ uiView: UIView, context: Context) {}
}

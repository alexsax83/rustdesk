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

@MainActor
final class Ponte: ObservableObject {
    @Published var codice = RemoteXRete.nuovoCodice()
    @Published var stato = "Un momento…"
    @Published var aiutanteCollegato = false
    @Published var richiesta: RichiestaInArrivo?
    /// Lo schermo è in trasmissione (iOS lo segnala con UIScreen.isCaptured).
    @Published var trasmissioneAttiva = UIScreen.main.isCaptured

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
                if UIScreen.main.isCaptured && self.richiesta != nil { self.consenti() }
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
                guard let self, m.tipo == .richiesta else { return }
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
                guard let self, m.tipo == .richiesta else { return }
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

    private var richiestaConCodice = false
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
        // Serve per far sapere dove indica chi aiuta, anche quando si usa un'altra app.
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
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
            if let attuale = Portachiavi.leggi("sessione", gruppo: Portachiavi.gruppoCondiviso) { ch.invia(.sessione, attuale) }
        } else {
            Portachiavi.scrivi(k, "sessione", gruppo: Portachiavi.gruppoCondiviso)
            ch.invia(.sessione, k)
            // Apre subito la conferma di iOS «Avvia trasmissione».
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { AvvioTrasmissione.avvia() }
        }
    }

    func terminaAiutante() {
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
/// apre la conferma obbligatoria di iOS «Avvia trasmissione».
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
/// dopo «Accetta» l'app lo preme e iOS mostra «Avvia trasmissione».
@MainActor
enum AvvioTrasmissione {
    static let selettore = SelettorePieno(frame: CGRect(x: 0, y: 0, width: 4, height: 4))
    static func avvia() {
        guard !UIScreen.main.isCaptured else { return }
        selettore.premi()
    }
}

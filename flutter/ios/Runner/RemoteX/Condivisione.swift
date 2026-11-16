// Remote X su iPhone/iPad: la parte che mostra lo schermo a chi aiuta.
// Gira accanto all'interfaccia principale (quella che comanda Mac, PC e Android).
// Quando qualcuno sullo stesso Wi‑Fi chiede di vedere lo schermo compare un solo
// messaggio, Accetta o Rifiuta. Accetta avvia anche la condivisione; iOS chiede poi
// la sua conferma obbligatoria «Avvia trasmissione». Dopo, nessun'altra finestra.

import UIKit
import SwiftUI
import Combine
import ReplayKit

@MainActor
final class RemoteXCondivisione {
    static let shared = RemoteXCondivisione()
    let ponte = Ponte()
    private weak var finestra: UIWindow?
    private var richiestaVista: UIHostingController<RichiestaSchermo>?
    private var barraVista: UIHostingController<BarraCondivisione>?
    private var osserva: AnyCancellable?

    func avvia(in window: UIWindow?) {
        guard let window, finestra == nil else { return }
        finestra = window
        ponte.avvia()
        osserva = ponte.objectWillChange.sink { [weak self] _ in
            DispatchQueue.main.async { self?.aggiorna() }
        }
        aggiorna()
    }

    private func aggiorna() {
        guard let w = finestra else { return }
        // Messaggio Accetta / Rifiuta, a tutto schermo.
        if let r = ponte.richiesta {
            if richiestaVista?.rootView.richiesta.id != r.id {
                richiestaVista?.view.removeFromSuperview()
                let h = UIHostingController(rootView: RichiestaSchermo(ponte: ponte, richiesta: r))
                h.view.backgroundColor = .clear
                h.view.frame = w.bounds
                h.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
                w.addSubview(h.view)
                richiestaVista = h
            }
        } else if let h = richiestaVista {
            h.view.removeFromSuperview()
            richiestaVista = nil
        }
        // Barretta in basso solo mentre lo schermo è condiviso (o manca l'ultimo passo).
        let serve = ponte.trasmissioneAttiva || ponte.aiutanteCollegato
        if serve {
            if barraVista == nil {
                let h = UIHostingController(rootView: BarraCondivisione(ponte: ponte))
                h.view.backgroundColor = .clear
                w.addSubview(h.view)
                barraVista = h
            }
            if let h = barraVista {
                let larghezza = min(w.bounds.width - 24, 420)
                let altezza: CGFloat = 52
                h.view.frame = CGRect(x: (w.bounds.width - larghezza) / 2,
                                      y: w.bounds.height - w.safeAreaInsets.bottom - altezza - 8,
                                      width: larghezza, height: altezza)
                h.view.autoresizingMask = [.flexibleLeftMargin, .flexibleRightMargin, .flexibleTopMargin]
                w.bringSubviewToFront(h.view)
            }
        } else if let h = barraVista {
            h.view.removeFromSuperview()
            barraVista = nil
        }
        if let r = richiestaVista { w.bringSubviewToFront(r.view) }
    }
}

/// «… vuole vedere il tuo schermo»: Accetta o Rifiuta.
/// Accetta è anche il pulsante di sistema che fa partire la condivisione.
struct RichiestaSchermo: View {
    @ObservedObject var ponte: Ponte
    let richiesta: RichiestaInArrivo

    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            VStack(spacing: 22) {
                Image(systemName: "rectangle.on.rectangle").font(.system(size: 44)).foregroundColor(.accentColor)
                Text("«\(richiesta.nome)» vuole vedere il tuo schermo")
                    .font(.title2.bold()).multilineTextAlignment(.center)
                VStack(spacing: 4) {
                    Text("Numero di controllo").font(.callout).foregroundColor(.secondary)
                    Text(richiesta.numero).font(.system(size: 44, weight: .bold, design: .monospaced))
                    Text("Deve essere uguale a quello sull'altro schermo.")
                        .font(.footnote).foregroundColor(.secondary)
                }
                VStack(spacing: 8) {
                    ZStack {
                        Text("Accetta")
                            .font(.title3.bold()).foregroundColor(.white)
                            .frame(maxWidth: .infinity, minHeight: 56)
                            .background(RoundedRectangle(cornerRadius: 14).fill(Color.green))
                        PulsanteSistema { ponte.consenti() }.opacity(0.02)
                    }
                    .frame(height: 56)
                    Text("Subito dopo iPhone chiede ancora una conferma: tocca «Avvia trasmissione».")
                        .font(.footnote).foregroundColor(.secondary).multilineTextAlignment(.center)
                }
                Button { ponte.rifiuta() } label: {
                    Text("Rifiuta").font(.title3).frame(maxWidth: .infinity, minHeight: 50)
                }
                .buttonStyle(.bordered)
            }
            .padding(28)
            .frame(maxWidth: 460)
        }
    }
}

/// Barretta in basso: lo schermo è condiviso, con Termina.
struct BarraCondivisione: View {
    @ObservedObject var ponte: Ponte

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(ponte.trasmissioneAttiva ? Color.red : Color.orange).frame(width: 10, height: 10)
            Text(ponte.trasmissioneAttiva ? "Stai mostrando il tuo schermo" : "Manca «Avvia trasmissione»")
                .font(.callout.weight(.medium)).lineLimit(1).minimumScaleFactor(0.8)
            Spacer(minLength: 4)
            if !ponte.trasmissioneAttiva {
                ZStack {
                    Text("Riprova").font(.callout.bold()).padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Capsule().fill(Color.orange.opacity(0.25)))
                    PulsanteSistema {}.opacity(0.02)
                }
                .fixedSize()
            }
            Button("Termina") { ponte.terminaAiutante() }
                .font(.callout.bold()).foregroundColor(.white)
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(Capsule().fill(Color.red))
        }
        .padding(.horizontal, 14)
        .frame(maxHeight: .infinity)
        .background(Capsule().fill(.regularMaterial))
        .overlay(Capsule().stroke(Color.primary.opacity(0.08)))
    }
}

/// Il pulsante di sistema che apre la conferma «Avvia trasmissione».
struct PulsanteSistema: UIViewRepresentable {
    let alTocco: () -> Void
    func makeUIView(context: Context) -> SelettorePieno {
        let v = SelettorePieno(frame: .zero)
        v.alTocco = alTocco
        return v
    }
    func updateUIView(_ v: SelettorePieno, context: Context) { v.alTocco = alTocco }
}

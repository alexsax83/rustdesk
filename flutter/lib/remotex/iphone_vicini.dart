// Remote X: guardare lo schermo di un iPhone o iPad (Windows, Android, Mac, iPhone, iPad).
//
// Apple non permette di comandare un iPhone da remoto: chi aiuta vede lo schermo e
// indica i punti con un tocco (sull'iPhone arriva una notifica con la posizione).
// Protocollo uguale a quello dell'app Remote X per Mac:
//   47817/udp  «chi c'è?»  → l'iPhone risponde con il suo nome
//   47814/tcp  richiesta: la persona sull'iPhone vede il nome e il numero di controllo
//              e sceglie Accetta o Rifiuta; con Accetta arriva la chiave della sessione
//   47816/tcp  lo schermo in JPEG, cifrato con la chiave della sessione
// Cifratura: X25519 effimera + HKDF-SHA256 (sale = chiave condivisa) + ChaCha20-Poly1305.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

const int _portaRichiesta = 47814;
const int _portaVideo = 47818; // qui ascolta chi guarda: si collega l'iPhone
const int _portaSonda = 47817;

class _Tipo {
  static const tocco = 3;
  static const richiestaChiave = 4;
  static const conferma = 6;
  static const richiesta = 7;
  static const consenso = 8;
  static const sessione = 9;
  static const jpeg = 10;
  static const diagnostica = 11;
  static const videoQui = 12;
  static const puntatore = 13;
}

// ---------------------------------------------------------------------------
// Canale cifrato (identico a Canale in Protocollo.swift)
// ---------------------------------------------------------------------------

class _Canale {
  final Socket _socket;
  final List<int> _psk;
  final _x25519 = X25519();
  final _aead = Chacha20.poly1305Aead();
  late SimpleKeyPair _coppia;
  late List<int> _mia;
  SecretKey? _chiaveInvio;
  SecretKey? _chiaveRicezione;
  int _contInvio = 0;
  int _contRicezione = 0;
  bool confermato = false;
  bool chiuso = false;
  String? numeroControllo;
  final List<List<int>> _inAttesa = [];
  Uint8List _buffer = Uint8List(0);
  Future<void> _codaRicezione = Future.value();
  Future<void> _codaInvio = Future.value();
  int inVolo = 0;

  void Function()? onPronto;
  void Function(int tipo, Uint8List dati)? onMessaggio;
  void Function()? onChiuso;

  _Canale._(this._socket, this._psk);

  static Future<_Canale> collega(String host, int porta, List<int> psk) async {
    final s = await Socket.connect(host, porta, timeout: const Duration(seconds: 4));
    return daSocket(s, psk);
  }

  static Future<_Canale> daSocket(Socket s, List<int> psk) async {
    try {
      s.setOption(SocketOption.tcpNoDelay, true);
    } catch (_) {}
    final c = _Canale._(s, psk);
    c._coppia = await c._x25519.newKeyPair();
    c._mia = (await c._coppia.extractPublicKey()).bytes;
    c._scriviBlocco(c._mia);
    s.listen(c._ricevuti, onDone: c.chiudi, onError: (_) => c.chiudi(), cancelOnError: true);
    return c;
  }

  void chiudi() {
    if (chiuso) return;
    chiuso = true;
    try {
      _socket.destroy();
    } catch (_) {}
    onChiuso?.call();
  }

  void _scriviBlocco(List<int> d) {
    if (chiuso) return;
    final h = ByteData(4)..setUint32(0, d.length);
    final b = BytesBuilder(copy: false)
      ..add(h.buffer.asUint8List())
      ..add(d);
    try {
      _socket.add(b.takeBytes());
    } catch (_) {
      chiudi();
    }
  }

  List<int> _nonce(int n) {
    final b = ByteData(12);
    b.setUint32(4, (n >> 32) & 0xffffffff);
    b.setUint32(8, n & 0xffffffff);
    return b.buffer.asUint8List();
  }

  void invia(int tipo, List<int> dati) {
    if (chiuso) return;
    if (!confermato) {
      if (_inAttesa.length < 60) _inAttesa.add([tipo, ...dati]);
      return;
    }
    _inviaCifrato([tipo, ...dati]);
  }

  void _inviaCifrato(List<int> chiaro) {
    final n = _contInvio++;
    final k = _chiaveInvio;
    if (k == null) return;
    inVolo++;
    _codaInvio = _codaInvio.then((_) async {
      final busta = await _aead.encrypt(chiaro, secretKey: k, nonce: _nonce(n));
      _scriviBlocco([...busta.cipherText, ...busta.mac.bytes]);
    }).catchError((_) {}).whenComplete(() {
      inVolo--;
    });
  }

  void _ricevuti(Uint8List dati) {
    final b = BytesBuilder(copy: false)
      ..add(_buffer)
      ..add(dati);
    _buffer = b.takeBytes();
    while (_buffer.length >= 4) {
      final n = ByteData.sublistView(_buffer, 0, 4).getUint32(0);
      if (n == 0 || n > 16000000) {
        chiudi();
        return;
      }
      if (_buffer.length < 4 + n) break;
      final blocco = Uint8List.fromList(_buffer.sublist(4, 4 + n));
      _buffer = Uint8List.fromList(_buffer.sublist(4 + n));
      _codaRicezione = _codaRicezione.then((_) => _elabora(blocco)).catchError((_) => chiudi());
    }
  }

  static int _confronta(List<int> a, List<int> b) {
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] != b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }

  Future<void> _elabora(Uint8List blocco) async {
    if (chiuso) return;
    if (_chiaveRicezione == null) {
      if (blocco.length != 32) return chiudi();
      final segreto = await _x25519.sharedSecretKey(
          keyPair: _coppia, remotePublicKey: SimplePublicKey(blocco, type: KeyPairType.x25519));
      final h32 = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      final info = utf8.encode('RemoteX-sessione');
      _chiaveInvio = await h32.deriveKey(secretKey: segreto, nonce: _psk, info: [...info, ..._mia, ...blocco]);
      _chiaveRicezione = await h32.deriveKey(secretKey: segreto, nonce: _psk, info: [...info, ...blocco, ..._mia]);
      final primo = _confronta(_mia, blocco) < 0 ? _mia : blocco;
      final secondo = identical(primo, _mia) ? blocco : _mia;
      final h4 = Hkdf(hmac: Hmac.sha256(), outputLength: 4);
      final v = await (await h4.deriveKey(
              secretKey: segreto, nonce: _psk, info: [...utf8.encode('RemoteX-controllo'), ...primo, ...secondo]))
          .extractBytes();
      final n = ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) % 10000;
      numeroControllo = n.toString().padLeft(4, '0');
      _inviaCifrato([_Tipo.conferma, ...utf8.encode('ok')]);
      return;
    }
    if (blocco.length <= 16) return chiudi();
    final busta = SecretBox(blocco.sublist(0, blocco.length - 16),
        nonce: _nonce(_contRicezione), mac: Mac(blocco.sublist(blocco.length - 16)));
    final chiaro = await _aead.decrypt(busta, secretKey: _chiaveRicezione!);
    _contRicezione++;
    if (chiaro.isEmpty) return chiudi();
    final tipo = chiaro[0];
    if (tipo == _Tipo.conferma) {
      if (confermato) return;
      confermato = true;
      final coda = List<List<int>>.from(_inAttesa);
      _inAttesa.clear();
      for (final m in coda) {
        _inviaCifrato(m);
      }
      onPronto?.call();
      return;
    }
    if (!confermato) return chiudi();
    onMessaggio?.call(tipo, Uint8List.fromList(chiaro.sublist(1)));
  }
}

// ---------------------------------------------------------------------------
// Ricerca degli iPhone e iPad sulla stessa rete
// ---------------------------------------------------------------------------

class DispositivoVicino {
  final String nome;
  final String ip;
  /// Codice usa e getta dell'iPhone/iPad (10 cifre): si guarda da fuori casa.
  final String? codice;
  DispositivoVicino(this.nome, this.ip, {this.codice});
}

// ---------------------------------------------------------------------------
// Da fuori casa: i due dispositivi si incontrano su un ripetitore pubblico, che passa
// solo byte cifrati (la chiave nasce dal codice, che resta sui due dispositivi).
// ---------------------------------------------------------------------------

class RemoteXInternet {
  static const host = 'rs-ny.rustdesk.com';
  static const porta = 21117;
  static const chiaveServer = 'OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=';

  static String soloCifre(String c) => c.replaceAll(RegExp(r'[^0-9]'), '');
  static bool eCodiceIPhone(String t) => RegExp(r'^[0-9]{10}$').hasMatch(t.replaceAll(RegExp(r'\s'), ''));
  static String leggibile(String c) {
    final d = soloCifre(c);
    return d.length == 10 ? '${d.substring(0, 5)} ${d.substring(5)}' : d;
  }

  static Future<String> uuid(String codice, String tipo) async {
    final h = await Sha256().hash(utf8.encode('RemoteX-internet-v1|$tipo|${soloCifre(codice)}'));
    return h.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static Future<List<int>> chiave(String codice) async {
    final k = await Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 200000, bits: 256).deriveKeyFromPassword(
        password: soloCifre(codice), nonce: utf8.encode('RemoteX-internet-v1'));
    return k.extractBytes();
  }

  static List<int> _varint(int v) {
    final o = <int>[];
    while (v >= 0x80) {
      o.add((v & 0x7f) | 0x80);
      v >>= 7;
    }
    o.add(v);
    return o;
  }

  static List<int> _campo(int n, List<int> d) => [..._varint(n << 3 | 2), ..._varint(d.length), ...d];

  static List<int> richiesta(String uuid) {
    final m = _campo(18, [..._campo(2, utf8.encode(uuid)), ..._campo(6, utf8.encode(chiaveServer))]);
    final n = m.length;
    final h = n <= 0x3F ? [n << 2] : [((n << 2) | 1) & 0xff, ((n << 2) | 1) >> 8];
    return [...h, ...m];
  }

  /// Collegamento al ripetitore con la richiesta già mandata.
  static Future<Socket> collega(String uuid) async {
    final s = await Socket.connect(host, porta, timeout: const Duration(seconds: 8));
    s.add(richiesta(uuid));
    await s.flush();
    await Future.delayed(const Duration(milliseconds: 300));
    return s;
  }
}

/// Ricerca degli iPhone e iPad con Remote X aperta (usata anche da «Dispositivi sulla stessa rete»).
typedef RicercaIPhone = _Ricerca;

class _Ricerca {
  RawDatagramSocket? _socket;
  Timer? _timer;
  final Map<String, DispositivoVicino> trovati = {};
  final Map<String, DateTime> _visto = {};
  final Set<String> _mieiIp = {};
  void Function()? onCambio;

  Future<void> avvia() async {
    try {
      _socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      _socket!.broadcastEnabled = true;
      _socket!.listen((e) {
        if (e != RawSocketEvent.read) return;
        final d = _socket?.receive();
        if (d == null) return;
        final testo = utf8.decode(d.data, allowMalformed: true);
        if (!testo.startsWith('RemoteX-io-v1\n')) return;
        final ip = d.address.address;
        if (_mieiIp.contains(ip)) return;
        final nome = testo.substring(14).trim();
        _visto[ip] = DateTime.now();
        if (trovati[ip]?.nome != nome) {
          trovati[ip] = DispositivoVicino(nome.isEmpty ? ip : nome, ip);
          onCambio?.call();
        }
      });
    } catch (_) {
      return;
    }
    await _chiedi();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _chiedi());
  }

  Future<void> _chiedi() async {
    final s = _socket;
    if (s == null) return;
    final sonda = utf8.encode('RemoteX-chi-c-e-v1');
    // Chi non risponde da 10 secondi sparisce dall'elenco.
    final ora = DateTime.now();
    final vecchi = _visto.entries.where((e) => ora.difference(e.value).inSeconds > 10).map((e) => e.key).toList();
    if (vecchi.isNotEmpty) {
      for (final ip in vecchi) {
        _visto.remove(ip);
        trovati.remove(ip);
      }
      onCambio?.call();
    }
    try {
      s.send(sonda, InternetAddress('255.255.255.255'), _portaSonda);
    } catch (_) {}
    List<NetworkInterface> interfacce = [];
    try {
      interfacce = await NetworkInterface.list(type: InternetAddressType.IPv4);
    } catch (_) {}
    for (final i in interfacce) {
      for (final a in i.addresses) {
        final p = a.rawAddress;
        if (p.length != 4) continue;
        final privato = p[0] == 10 || (p[0] == 172 && p[1] >= 16 && p[1] <= 31) || (p[0] == 192 && p[1] == 168);
        if (!privato) continue;
        _mieiIp.add(a.address);
        for (var h = 1; h <= 254; h++) {
          if (h == p[3]) continue;
          try {
            s.send(sonda, InternetAddress('${p[0]}.${p[1]}.${p[2]}.$h'), _portaSonda);
          } catch (_) {}
        }
      }
    }
  }

  void ferma() {
    _timer?.cancel();
    _socket?.close();
    _socket = null;
  }
}

// ---------------------------------------------------------------------------
// Sessione: richiesta, Accetta, schermo
// ---------------------------------------------------------------------------

enum StatoSessione { collegamento, attesaAccetta, attesaTrasmissione, schermo, finita }

class _Sessione extends ChangeNotifier {
  final DispositivoVicino dispositivo;
  StatoSessione stato = StatoSessione.collegamento;
  String messaggio = 'Collegamento in corso…';
  String? numero;
  Uint8List? immagine;
  Size? dimensioni;
  _Canale? _richiesta;
  _Canale? _video;
  ServerSocket? _ascolto;
  Socket? _inAttesa;
  List<int>? _chiaveSessione;
  bool _terminata = false;

  _Sessione(this.dispositivo);

  void _aggiorna(StatoSessione s, String m) {
    if (_terminata && s != StatoSessione.finita) return;
    stato = s;
    messaggio = m;
    notifyListeners();
  }

  static Future<String> _mioNome() async {
    try {
      if (Platform.isAndroid) {
        final a = await DeviceInfoPlugin().androidInfo;
        return '${a.manufacturer} ${a.model}'.trim();
      }
      if (Platform.isIOS) {
        return (await DeviceInfoPlugin().iosInfo).name;
      }
    } catch (_) {}
    return Platform.localHostname;
  }

  Timer? _vivo;
  bool get _internet => dispositivo.codice != null;

  Future<void> _videoInternet() async {
    if (_terminata || _chiaveSessione == null || _video != null) return;
    try {
      final s = await RemoteXInternet.collega(await RemoteXInternet.uuid(dispositivo.codice!, 'video'));
      await _attacca(s);
    } catch (_) {
      if (!_terminata) Future.delayed(const Duration(seconds: 2), _videoInternet);
    }
  }

  Future<void> _avviaInternet() async {
    final nome = await _mioNome();
    try {
      final psk = await RemoteXInternet.chiave(dispositivo.codice!);
      final s = await RemoteXInternet.collega(await RemoteXInternet.uuid(dispositivo.codice!, 'controllo'));
      final c = await _Canale.daSocket(s, psk);
      _richiesta = c;
      c.onPronto = () {
        c.invia(_Tipo.videoQui, [0, 0, 2]);
        c.invia(_Tipo.richiesta, utf8.encode(nome));
        numero = c.numeroControllo;
        // Il ripetitore chiude i collegamenti fermi da 30 secondi.
        _vivo = Timer.periodic(const Duration(seconds: 10), (_) => c.invia(_Tipo.puntatore, _xy(-1, -1)));
        _aggiorna(StatoSessione.attesaAccetta, 'Sull\'altro dispositivo deve toccare «Accetta»');
      };
      c.onMessaggio = (tipo, dati) {
        if (tipo == _Tipo.consenso) {
          _aggiorna(StatoSessione.attesaTrasmissione, 'Accettato. Ora sull\'altro dispositivo deve toccare «Inizia condivisione».');
        } else if (tipo == _Tipo.sessione && dati.length == 32 && _chiaveSessione == null) {
          _chiaveSessione = dati;
          _aggiorna(StatoSessione.attesaTrasmissione, 'Accettato. Aspetto lo schermo…');
          _videoInternet();
        } else if (tipo == _Tipo.diagnostica && stato != StatoSessione.schermo) {
          _aggiorna(stato, utf8.decode(dati, allowMalformed: true));
        }
      };
      c.onChiuso = () {
        _vivo?.cancel();
        if (_chiaveSessione == null && !_terminata) {
          _aggiorna(StatoSessione.finita,
              'Non risponde nessuno con questo codice, oppure l\'altra persona non ha accettato. Controlla il codice e riprova.');
        }
      };
    } catch (_) {
      _aggiorna(StatoSessione.finita, 'Non riesco a collegarmi. Controlla la connessione a Internet e riprova.');
    }
  }

  Future<void> avvia() async {
    if (_internet) return _avviaInternet();
    final psk = (await Sha256().hash(utf8.encode('RemoteX-richiesta-v1'))).bytes;
    final nome = await _mioNome();
    // Lo schermo arriva qui: è l'iPhone che si collega a questo dispositivo.
    try {
      _ascolto = await ServerSocket.bind(InternetAddress.anyIPv4, _portaVideo, shared: true);
      _ascolto!.listen((s) {
        if (_video != null || _terminata) {
          s.destroy();
        } else if (_chiaveSessione != null) {
          _attacca(s);
        } else {
          _inAttesa?.destroy();
          _inAttesa = s;
        }
      });
    } catch (_) {
      _aggiorna(StatoSessione.finita, 'Non riesco a ricevere lo schermo: un\'altra app usa la porta 47818.');
      return;
    }
    try {
      final c = await _Canale.collega(dispositivo.ip, _portaRichiesta, psk);
      _richiesta = c;
      c.onPronto = () {
        c.invia(_Tipo.videoQui, [_portaVideo >> 8, _portaVideo & 0xff, 2]);
        c.invia(_Tipo.richiesta, utf8.encode(nome));
        numero = c.numeroControllo;
        _aggiorna(StatoSessione.attesaAccetta, 'Sull\'altro dispositivo deve toccare «Accetta»');
      };
      c.onMessaggio = (tipo, dati) {
        if (tipo == _Tipo.consenso) {
          _aggiorna(StatoSessione.attesaTrasmissione, 'Accettato. Ora sull\'altro dispositivo deve toccare «Inizia condivisione».');
        } else if (tipo == _Tipo.sessione && dati.length == 32 && _chiaveSessione == null) {
          _chiaveSessione = dati;
          _aggiorna(StatoSessione.attesaTrasmissione, 'Accettato. Aspetto che l\'iPhone si colleghi…');
          final s = _inAttesa;
          _inAttesa = null;
          if (s != null) _attacca(s);
        } else if (tipo == _Tipo.diagnostica && stato != StatoSessione.schermo) {
          _aggiorna(stato, utf8.decode(dati, allowMalformed: true));
        }
      };
      c.onChiuso = () {
        if (_chiaveSessione == null && !_terminata) {
          _aggiorna(StatoSessione.finita, 'L\'altra persona non ha accettato, oppure il tempo è scaduto. Puoi riprovare.');
        }
      };
    } catch (_) {
      _aggiorna(StatoSessione.finita,
          'Non riesco a collegarmi. Controlla che sull\'altro dispositivo Remote X sia aperta e che siate sullo stesso Wi‑Fi.');
    }
  }

  Future<void> _attacca(Socket socket) async {
    if (_terminata || _chiaveSessione == null || _video != null) {
      socket.destroy();
      return;
    }
    final v = await _Canale.daSocket(socket, _chiaveSessione!);
    _video = v;
    v.onPronto = () => v.invia(_Tipo.richiestaChiave, const []);
    v.onMessaggio = (tipo, dati) {
      if (tipo != _Tipo.jpeg) return;
      immagine = dati;
      dimensioni = _misuraJpeg(dati) ?? dimensioni;
      if (stato != StatoSessione.schermo) {
        _aggiorna(StatoSessione.schermo, '');
      } else {
        notifyListeners();
      }
    };
    v.onChiuso = () {
      if (_terminata) return;
      if (stato == StatoSessione.schermo) {
        _aggiorna(StatoSessione.finita, 'L\'altra persona ha terminato la condivisione.');
      } else {
        _video = null;
        // Da fuori casa l'iPhone può arrivare sul ripetitore più tardi: si riprova.
        if (_internet) Future.delayed(const Duration(seconds: 1), _videoInternet);
      }
    };
  }

  static List<int> _xy(double x, double y) {
    final d = ByteData(8)
      ..setFloat32(0, x)
      ..setFloat32(4, y);
    return d.buffer.asUint8List();
  }

  /// Un tocco: sull'iPhone compare un cerchio nella finestrella mobile.
  void indica(double x, double y) => _richiesta?.invia(_Tipo.tocco, _xy(x, y));

  /// La freccia di chi aiuta (null = nascondi), al massimo 20 volte al secondo.
  DateTime _ultimaFreccia = DateTime(2000);
  void punta(Offset? p) {
    final ora = DateTime.now();
    if (p != null && ora.difference(_ultimaFreccia).inMilliseconds < 50) return;
    _ultimaFreccia = ora;
    _richiesta?.invia(_Tipo.puntatore, p == null ? _xy(-1, -1) : _xy(p.dx, p.dy));
  }

  void termina() {
    _terminata = true;
    _vivo?.cancel();
    _inAttesa?.destroy();
    _ascolto?.close();
    _video?.chiudi();
    _richiesta?.chiudi();
  }

  /// Larghezza e altezza scritte nell'intestazione del JPEG (marcatore SOF).
  static Size? _misuraJpeg(Uint8List d) {
    var i = 2;
    while (i + 9 < d.length) {
      if (d[i] != 0xFF) {
        i++;
        continue;
      }
      final m = d[i + 1];
      if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
        final h = (d[i + 5] << 8) | d[i + 6];
        final w = (d[i + 7] << 8) | d[i + 8];
        return Size(w.toDouble(), h.toDouble());
      }
      final l = (d[i + 2] << 8) | d[i + 3];
      i += 2 + l;
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Interfaccia
// ---------------------------------------------------------------------------

/// Riga da mettere nella schermata principale: apre l'elenco degli iPhone e iPad vicini.
class RemoteXIPhoneVicini extends StatelessWidget {
  const RemoteXIPhoneVicini({super.key});

  static Future<String?> mioIndirizzo() async {
    // L'indirizzo del Wi‑Fi (en0), non quello della rete cellulare o di una VPN.
    try {
      String? altro;
      final elenco = await NetworkInterface.list(type: InternetAddressType.IPv4);
      elenco.sort((a, b) => (a.name.startsWith('en') ? 0 : 1).compareTo(b.name.startsWith('en') ? 0 : 1));
      for (final i in elenco) {
        if (i.name.startsWith('pdp_ip') || i.name.startsWith('utun') || i.name.startsWith('ipsec')) continue;
        for (final a in i.addresses) {
          final p = a.rawAddress;
          if (p[0] == 192 && p[1] == 168) return a.address;
          if (p[0] == 10 || (p[0] == 172 && p[1] >= 16 && p[1] <= 31)) altro ??= a.address;
        }
      }
      return altro;
    } catch (_) {}
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final lista = Card(
      margin: const EdgeInsets.symmetric(vertical: 8),
      child: ListTile(
        leading: const Icon(Icons.phone_iphone),
        title: const Text('Guarda lo schermo di un iPhone o iPad'),
        subtitle: const Text('Sullo stesso Wi‑Fi. Vedi lo schermo e indichi i punti con un tocco.'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const PaginaIPhoneVicini())),
      ),
    );
    return lista;
  }
}

class PaginaIPhoneVicini extends StatefulWidget {
  const PaginaIPhoneVicini({super.key});

  @override
  State<PaginaIPhoneVicini> createState() => _PaginaIPhoneViciniState();
}

class _PaginaIPhoneViciniState extends State<PaginaIPhoneVicini> {
  final _ricerca = _Ricerca();
  final _ip = TextEditingController();

  @override
  void initState() {
    super.initState();
    _ricerca.onCambio = () {
      if (mounted) setState(() {});
    };
    _ricerca.avvia();
  }

  @override
  void dispose() {
    _ricerca.ferma();
    _ip.dispose();
    super.dispose();
  }

  void _apri(DispositivoVicino d) {
    Navigator.of(context).push(MaterialPageRoute(builder: (_) => PaginaSchermoIPhone(dispositivo: d)));
  }

  @override
  Widget build(BuildContext context) {
    final elenco = _ricerca.trovati.values.toList()..sort((a, b) => a.nome.compareTo(b.nome));
    return Scaffold(
      appBar: AppBar(title: const Text('iPhone e iPad vicini')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text('Sull\'iPhone o iPad deve essere aperta Remote X, sullo stesso Wi‑Fi. '
              'Tocca il suo nome: sull\'altro schermo comparirà Accetta o Rifiuta.'),
          const SizedBox(height: 16),
          if (elenco.isEmpty)
            const ListTile(
              leading: SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2)),
              title: Text('Cerco…'),
            ),
          for (final d in elenco)
            Card(
              child: ListTile(
                leading: const Icon(Icons.phone_iphone),
                title: Text(d.nome),
                subtitle: Text(d.ip),
                trailing: FilledButton(onPressed: () => _apri(d), child: const Text('Collegati')),
                onTap: () => _apri(d),
              ),
            ),
          const SizedBox(height: 24),
          ExpansionTile(
            title: const Text('Non compare? Scrivi il suo indirizzo'),
            children: [
              Padding(
                padding: const EdgeInsets.all(8),
                child: Row(children: [
                  Expanded(
                    child: TextField(
                      controller: _ip,
                      decoration: const InputDecoration(hintText: 'es. 192.168.1.30'),
                      keyboardType: TextInputType.number,
                    ),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: () {
                      final ip = _ip.text.trim();
                      if (ip.isNotEmpty) _apri(DispositivoVicino(ip, ip));
                    },
                    child: const Text('Collegati'),
                  ),
                ]),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(8, 0, 8, 12),
                child: Text('L\'indirizzo si trova sull\'iPhone in Impostazioni › Wi‑Fi › (i) accanto alla rete.'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class PaginaSchermoIPhone extends StatefulWidget {
  final DispositivoVicino dispositivo;
  const PaginaSchermoIPhone({super.key, required this.dispositivo});

  @override
  State<PaginaSchermoIPhone> createState() => _PaginaSchermoIPhoneState();
}

class _Tocco {
  final Offset punto;
  final int id;
  _Tocco(this.punto, this.id);
}

class _PaginaSchermoIPhoneState extends State<PaginaSchermoIPhone> {
  late final _Sessione _s = _Sessione(widget.dispositivo);
  final List<_Tocco> _tocchi = [];
  int _contatore = 0;

  @override
  void initState() {
    super.initState();
    _s.addListener(_cambio);
    _s.avvia();
  }

  void _cambio() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _s.removeListener(_cambio);
    _s.termina();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final guardando = _s.stato == StatoSessione.schermo;
    return Scaffold(
      backgroundColor: guardando ? Colors.black : null,
      body: SafeArea(
        child: Column(children: [
          Container(
            color: Colors.red.withOpacity(0.15),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            child: Row(children: [
              const Icon(Icons.circle, color: Colors.red, size: 12),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  guardando
                      ? 'Stai guardando lo schermo di «${widget.dispositivo.nome}»'
                      : 'Collegamento con «${widget.dispositivo.nome}»',
                  style: TextStyle(fontWeight: FontWeight.w600, color: guardando ? Colors.white : null),
                ),
              ),
              if (Platform.isWindows || Platform.isMacOS || Platform.isLinux)
                IconButton(
                  tooltip: 'Tutto schermo',
                  icon: Icon(Icons.fullscreen, color: guardando ? Colors.white : null),
                  onPressed: () async {
                    try {
                      await windowManager.setFullScreen(!await windowManager.isFullScreen());
                    } catch (_) {}
                  },
                ),
              FilledButton(
                style: FilledButton.styleFrom(backgroundColor: Colors.red),
                onPressed: () async {
                  try {
                    if (await windowManager.isFullScreen()) await windowManager.setFullScreen(false);
                  } catch (_) {}
                  if (mounted) Navigator.of(context).pop();
                },
                child: const Text('Termina'),
              ),
            ]),
          ),
          Expanded(child: guardando ? _schermo() : _attesa()),
        ]),
      ),
    );
  }

  Widget _attesa() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Text(_s.messaggio, textAlign: TextAlign.center, style: Theme.of(context).textTheme.titleLarge),
          if (_s.stato == StatoSessione.attesaAccetta && _s.numero != null) ...[
            const SizedBox(height: 18),
            const Text('Controllate che il numero sia uguale su entrambi gli schermi:', textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Text(_s.numero!,
                style: const TextStyle(fontSize: 52, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
          ],
          const SizedBox(height: 22),
          if (_s.stato != StatoSessione.finita) const CircularProgressIndicator(),
          if (_s.stato == StatoSessione.finita)
            FilledButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Chiudi')),
        ]),
      ),
    );
  }

  Widget _schermo() {
    return LayoutBuilder(builder: (context, c) {
      final dim = _s.dimensioni ?? const Size(9, 19.5);
      final scala = (c.maxWidth / dim.width) < (c.maxHeight / dim.height)
          ? c.maxWidth / dim.width
          : c.maxHeight / dim.height;
      final w = dim.width * scala, h = dim.height * scala;
      final area = Rect.fromLTWH((c.maxWidth - w) / 2, (c.maxHeight - h) / 2, w, h);
      Offset? normalizza(Offset p) =>
          area.contains(p) ? Offset((p.dx - area.left) / area.width, (p.dy - area.top) / area.height) : null;
      return MouseRegion(
        onHover: (e) => _s.punta(normalizza(e.localPosition)),
        onExit: (_) => _s.punta(null),
        child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onPanUpdate: (d) => _s.punta(normalizza(d.localPosition)),
        onTapUp: (d) {
          final p = d.localPosition;
          if (!area.contains(p)) return;
          _s.indica((p.dx - area.left) / area.width, (p.dy - area.top) / area.height);
          final t = _Tocco(p, _contatore++);
          setState(() => _tocchi.add(t));
          Future.delayed(const Duration(milliseconds: 700), () {
            if (mounted) setState(() => _tocchi.remove(t));
          });
        },
        child: Stack(children: [
          Positioned.fromRect(
            rect: area,
            child: _s.immagine == null
                ? const SizedBox()
                : Image.memory(_s.immagine!, gaplessPlayback: true, fit: BoxFit.fill, filterQuality: FilterQuality.medium),
          ),
          for (final t in _tocchi)
            Positioned(
              key: ValueKey(t.id),
              left: t.punto.dx - 30,
              top: t.punto.dy - 30,
              child: IgnorePointer(
                child: TweenAnimationBuilder<double>(
                  tween: Tween(begin: 0, end: 1),
                  duration: const Duration(milliseconds: 650),
                  builder: (_, v, __) => Opacity(
                    opacity: 1 - v,
                    child: Transform.scale(
                      scale: 0.4 + v * 0.8,
                      child: Container(
                        width: 60,
                        height: 60,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: Colors.orange.withOpacity(0.35),
                          border: Border.all(color: Colors.orange, width: 3),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
        ]),
      ));
    });
  }
}

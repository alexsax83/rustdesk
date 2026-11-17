// Remote X: «Il tuo codice», uguale su tutti i dispositivi (come sul Mac).
// Indirizzo + codice usa e getta in un'unica riga, con Copia e Nuovo codice.
// Su iPhone e iPad (che si possono solo guardare) c'è l'indirizzo nella rete.

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/remotex/iphone_vicini.dart';

class CodiceRemoteX extends StatefulWidget {
  const CodiceRemoteX({super.key});

  @override
  State<CodiceRemoteX> createState() => _CodiceRemoteXState();
}

class _CodiceRemoteXState extends State<CodiceRemoteX> {
  Timer? _timer;
  String _id = '';
  String _codice = '';
  String? _ip;
  bool _copiato = false;

  @override
  void initState() {
    super.initState();
    _aggiorna();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) => _aggiorna());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _aggiorna() async {
    final ip = await RemoteXIPhoneVicini.mioIndirizzo();
    String id = '', codice = '';
    if (!Platform.isIOS) {
      id = (await bind.mainGetMyId()).replaceAll(' ', '');
      codice = await bind.mainGetTemporaryPassword();
    }
    if (!mounted) return;
    if (id != _id || codice != _codice || ip != _ip) {
      setState(() {
        _id = id;
        _codice = codice;
        _ip = ip;
      });
    }
  }

  String get _leggibile {
    final i = _id.length == 9 ? '${_id.substring(0, 3)} ${_id.substring(3, 6)} ${_id.substring(6)}' : _id;
    return _codice.isEmpty ? i : '$i · $_codice';
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final ios = Platform.isIOS;
    final pronto = ios ? _ip != null : _id.length >= 6;
    final testo = ios ? (_ip ?? '') : _leggibile;
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 8),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 12, 12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(ios ? 'Il tuo indirizzo' : 'Il tuo codice',
              style: t.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          Row(children: [
            Expanded(
              child: pronto
                  ? SelectableText(testo,
                      style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w600, letterSpacing: 0.5))
                  : const Text('··· ··· ··· · ······',
                      style: TextStyle(fontSize: 30, fontWeight: FontWeight.w600, color: Colors.grey)),
            ),
            if (pronto)
              TextButton(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: ios ? testo : (_codice.isEmpty ? _id : '$_id-$_codice')));
                  setState(() => _copiato = true);
                  Future.delayed(const Duration(seconds: 2), () {
                    if (mounted) setState(() => _copiato = false);
                  });
                },
                child: Text(_copiato ? 'Copiato' : 'Copia'),
              ),
            if (!ios && _codice.isNotEmpty)
              TextButton(
                onPressed: () async {
                  await bind.mainUpdateTemporaryPassword();
                  Future.delayed(const Duration(milliseconds: 600), _aggiorna);
                },
                child: const Text('Nuovo codice'),
              ),
          ]),
          const SizedBox(height: 4),
          Text(
            ios
                ? 'Sulla stessa rete Wi‑Fi chi ti aiuta ti trova da solo.'
                : 'Dai questo codice a chi ti aiuta da fuori casa: vale per un solo collegamento. Sulla stessa rete Wi‑Fi non serve.',
            style: const TextStyle(fontSize: 13, color: Colors.grey),
          ),
          if (_ip != null && !ios)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text('IP di questo dispositivo: $_ip', style: const TextStyle(fontSize: 12, color: Colors.grey)),
            ),
        ]),
      ),
    );
  }
}

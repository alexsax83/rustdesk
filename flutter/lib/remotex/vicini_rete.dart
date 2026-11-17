// Remote X: un'unica voce chiara, «Dispositivi sulla stessa rete», su tutti i sistemi.
// Mac, PC Windows, Android e iPhone/iPad con Remote X aperta si trovano da soli:
// la ricerca si ripete ogni pochi secondi finché la schermata è aperta.

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/remotex/iphone_vicini.dart';

class DispositiviStessaRete extends StatefulWidget {
  const DispositiviStessaRete({super.key});

  @override
  State<DispositiviStessaRete> createState() => _DispositiviStessaReteState();
}

class _DispositiviStessaReteState extends State<DispositiviStessaRete> {
  Timer? _timer;
  Timer? _timerScan;
  // Su iPhone e iPad la ricerca normale può non arrivare (regole di rete di iOS):
  // in più si cercano direttamente nella rete i computer con Remote X aperta.
  final Map<String, String> _trovati = {};

  Future<void> _scansiona() async {
    final mio = await RemoteXIPhoneVicini.mioIndirizzo();
    if (mio == null) return;
    final base = mio.substring(0, mio.lastIndexOf('.') + 1);
    final nuovi = <String, String>{};
    await Future.wait(List.generate(254, (i) async {
      final ip = '$base${i + 1}';
      if (ip == mio) return;
      try {
        final s = await Socket.connect(ip, 21118, timeout: const Duration(milliseconds: 700));
        s.destroy();
        String nome = ip;
        try {
          final r = await InternetAddress(ip).reverse().timeout(const Duration(seconds: 2));
          nome = r.host.replaceAll('.local', '').replaceAll('.lan', '');
        } catch (_) {}
        nuovi[ip] = nome;
      } catch (_) {}
    }));
    if (mounted) setState(() { _trovati..clear()..addAll(nuovi); });
  }

  @override
  void initState() {
    super.initState();
    if (Platform.isIOS) {
      _scansiona();
      _timerScan = Timer.periodic(const Duration(seconds: 12), (_) => _scansiona());
    }
    bind.mainDiscover();
    _timer = Timer.periodic(const Duration(seconds: 4), (_) {
      bind.mainDiscover();
      bind.mainLoadLanPeers();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _timerScan?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(4, 14, 4, 2),
          child: Row(children: [
            const Icon(Icons.wifi, size: 20),
            const SizedBox(width: 8),
            Text('Dispositivi sulla stessa rete',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
          ]),
        ),
        const Padding(
          padding: EdgeInsets.fromLTRB(4, 0, 4, 8),
          child: Text('Compaiono da soli quando su di loro è aperta Remote X. Toccane uno per collegarti.',
              style: TextStyle(fontSize: 13, color: Colors.grey)),
        ),
        for (final e in _trovati.entries)
          Card(
            child: ListTile(
              leading: const Icon(Icons.computer),
              title: Text(e.value),
              subtitle: Text(e.key),
              trailing: FilledButton(onPressed: () => connect(context, e.key), child: const Text('Collegati')),
            ),
          ),
        Expanded(child: DiscoveredPeersView()),
      ],
    );
  }
}

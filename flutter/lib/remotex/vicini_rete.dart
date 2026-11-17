// Remote X: un'unica voce chiara, «Dispositivi sulla stessa rete», su tutti i sistemi.
// Mac, PC Windows, Android e iPhone/iPad con Remote X aperta si trovano da soli:
// la ricerca si ripete ogni pochi secondi finché la schermata è aperta.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/models/platform_model.dart';

class DispositiviStessaRete extends StatefulWidget {
  const DispositiviStessaRete({super.key});

  @override
  State<DispositiviStessaRete> createState() => _DispositiviStessaReteState();
}

class _DispositiviStessaReteState extends State<DispositiviStessaRete> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    bind.mainDiscover();
    _timer = Timer.periodic(const Duration(seconds: 4), (_) {
      bind.mainDiscover();
      bind.mainLoadLanPeers();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
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
        Expanded(child: DiscoveredPeersView()),
      ],
    );
  }
}

# Architecture & Spécification — Version Android de MyNet Filter

Ce document prépare le développement de l'application Android **MyNet Filter Mobile** et décrit le contrat d'API déjà implémenté dans `mynet_filter_core.py` (`RemoteAPIServer`).

---

## 1. Contraintes système Android

Sur Android **non rooté** (Android 10–15+), SELinux et le noyau interdisent :
- l'ouverture de sockets bruts `AF_PACKET` (`CAP_NET_RAW`) ;
- la lecture de `/proc/net/arp` ;
- la modification de `iptables`/`tc`/`ip_forward`.

L'application Android adopte donc une **architecture modulaire en 3 modes** :

1. **Mode Companion (Sans Root — 100 % des smartphones)** : pilote à distance le démon MyNet Filter tournant sur un PC Linux, un PC Windows ou un Raspberry Pi du réseau local via l'API REST authentifiée déjà intégrée.
2. **Mode Autonome Root / Hotspot (Magisk / KernelSU)** : embarque un helper natif Rust/Go cross-compilé (`arm64-v8a` / `armeabi-v7a`) lancé via `su` et un `ForegroundService` Android (excellent en partage de connexion où le smartphone est la passerelle).
3. **Mode API Routeur (Sans Root)** : connecteurs optionnels vers les API locales des box (Freebox OS, OpenWrt ubus/LuCI, MikroTik, UniFi).

---

## 2. Contrat API REST Companion (prêt côté serveur v1.1)

### Démarrage côté PC Linux / Raspberry Pi

```bash
sudo mynet-filter daemon --api-bind 0.0.0.0 --api-port 8443
```

Le démon affiche automatiquement une URI d'appairage destinée à être encodée en QR Code :

```text
mynetfilter://pair?host=192.168.1.20&port=8443&token=<TOKEN_256_BITS>&name=MyNetFilter-PC&v=1
```

### Authentification

Toutes les routes (sauf `/api/v1/health`) exigent l'en-tête :

```http
Authorization: Bearer <TOKEN>
```

### Endpoints v1

| Méthode | Route | Corps JSON | Réponse |
|---|---|---|---|
| `GET` | `/api/v1/health` | — | `{"ok": true, "version": "1.1.0", "name": "..."}` |
| `GET` | `/api/v1/status` | — | État complet : `iface`, `my_ip`, `gateway`, `ipv6_active`, `devices[]`, `targets[]`, `safe[]`, `aliases{}`, `total_kbit`, `errors[]` |
| `GET` | `/api/v1/safe` | — | Liste des cibles protégées |
| `GET` | `/api/v1/aliases` | — | Dictionnaire `{mac_ou_ip: nom}` |
| `POST` | `/api/v1/rescan` | `{}` | Lance un balayage ARP actif |
| `POST` | `/api/v1/set` | `{"targets": "192.168.1.25", "mode": "pause"\|"limit"\|"free", "rate": 500, "duration": 600}` | Applique pause/limit/free (durée optionnelle en secondes) |
| `POST` | `/api/v1/free_all` | `{}` | Libère immédiatement tous les appareils |
| `POST` | `/api/v1/safe/add` | `{"target": "192.168.1.25"}` | Ajoute au Safe Mode |
| `POST` | `/api/v1/safe/remove` | `{"target": "192.168.1.25"}` | Retire du Safe Mode |
| `POST` | `/api/v1/aliases/set` | `{"target": "aa:bb:cc:dd:ee:ff", "name": "TV Salon"}` | Enregistre ou supprime un nom personnalisé |

---

## 3. Structure recommandée du futur dépôt / dossier `android/`

```text
android/
├── app/                          # Kotlin + Jetpack Compose (Material 3)
│   ├── ui/                       # Écrans : Scan QR, Liste Appareils, Safe Mode, Paramètres
│   ├── data/
│   │   ├── CompanionClient.kt    # Client OkHttp/Ktor vers /api/v1/* + découverte mDNS (NsdManager)
│   │   └── RootEngineBridge.kt   # Communication Unix socket avec le binaire natif root
│   └── service/
│       └── MyNetFilterService.kt  # ForegroundService + notification persistante "Tout libérer"
└── native-engine/                # Crate Rust (ou Go) cross-compilé arm64-v8a / armeabi-v7a
    ├── src/arp.rs                # Découverte & ARP spoofing (AF_PACKET)
    ├── src/hotspot.rs            # Mode AP/Hotspot direct (sans ARP spoofing)
    └── src/shaper.rs             # iptables / tc HTB / fallback NFQUEUE TokenBucket
```

---

## 4. Checklist sécurité Android avant publication

- Chiffrement TLS (certificat auto-signé avec pinning SHA-256 inclus dans le QR Code d'appairage) pour tout usage hors LAN de confiance.
- Stockage du jeton Bearer dans `EncryptedSharedPreferences` / Android Keystore.
- Notification persistante obligatoire avec action rapide **Tout libérer** dès qu'une règle est active.
- Libération automatique (restauration ARP + purge iptables) lors de la perte de connexion Wi-Fi (`ConnectivityManager.NetworkCallback.onLost`) ou de l'arrêt du service.

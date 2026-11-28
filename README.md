# MyNet Filter — Contrôleur de bande passante Wi-Fi / LAN (Linux, Windows & Android)

Quand les autres appareils du réseau saturent la connexion et que vos appels,
uploads ou agents IA ralentissent, **MyNet Filter** vous redonne la priorité : il
**met en pause** ou **plafonne le débit** des appareils de votre choix, avec un
tableau de bord temps réel (cartes KPI, graphique de débit, Mode Focus, Safe Mode,
alias, minuteurs et export CSV/JSON).

![Interface](gui_screenshot.png)

---

## Table des matières

1. [Installation sur Linux](#1-installation-sur-linux)
2. [Installation sur Windows (guide complet)](#2-installation-sur-windows-guide-complet)
3. [Installation sur Android (APK Companion)](#3-installation-sur-android-apk-companion)
4. [Utilisation (GUI, Console, CLI)](#4-utilisation)
5. [Builds automatiques GitHub Actions](#5-builds-automatiques-github-actions)
6. [Sécurité, réversibilité & limites honnêtes](#6-sécurité-réversibilité--limites-honnêtes)
7. [Architecture des fichiers](#7-architecture-des-fichiers)

---

## 1. Installation sur Linux

### Ce qu'il faut installer

| Dépendance | Rôle | Paquet Debian / Ubuntu | Paquet Fedora (`dnf`) | Paquet Arch (`pacman`) |
|---|---|---|---|---|
| **Python 3.10+** | Exécution du moteur et de l'interface | `python3` `python3-pip` | `python3` `python3-pip` | `python` `python-pip` |
| **Tkinter** | Interface graphique (`mynet-filter-gui`) | `python3-tk` | `python3-tkinter` | `tk` |
| **Scapy >= 2.5** | Découverte et paquets réseau locaux | `python3-scapy` | `python3-scapy` | `python-scapy` |
| **iptables** | Règles de mise en pause (`DROP`) | `iptables` | `iptables` | `iptables` |
| **iproute2 (`ip`, `tc`)** | Détection interface + bridage HTB (`limit`) | `iproute2` | `iproute` | `iproute2` |
| **tcpdump** | Support capture réseau | `tcpdump` | `tcpdump` | `tcpdump` |
| **PolicyKit (`pkexec`)** *(optionnel)* | Démarrer le service depuis la GUI | `policykit-1` / `pkexec` | `polkit` | `polkit` |

### Installation automatique (recommandée)

```bash
git clone https://github.com/NiceMank/mynet-filter.git
cd mynet-filter
bash install.sh
```

Ce que fait `install.sh` :
1. Installe automatiquement les paquets système et Python manquants (`apt`, `dnf` ou `pacman`).
2. Crée le groupe système `mynet-filter` et y ajoute votre utilisateur (pour utiliser `mynet-filter-gui` **sans `sudo`**).
3. Active `net.ipv4.ip_forward=1`.
4. Installe les modules dans `/usr/local/lib/mynet-filter`, crée les commandes `mynet-filter` et `mynet-filter-gui`, ajoute le raccourci bureau et le service `systemd`.
5. Exécute `sudo mynet-filter doctor` pour vérifier que tout est opérationnel.

> **Important :** après l'installation, reconnectez votre session (ou exécutez `newgrp mynet-filter`) pour activer l'accès au socket `/run/mynet-filter.sock` sans `sudo`.

### Lancement Linux

```bash
sudo mynet-filter doctor            # vérifie toutes les dépendances + IPv6
sudo mynet-filter daemon            # ou en service permanent : sudo systemctl enable --now mynet-filter
mynet-filter-gui                    # interface graphique (en utilisateur normal, SANS sudo)
```

---

## 2. Installation sur Windows (guide complet)

### Option A — Utiliser l'exécutable prêt à l'emploi (recommandé, sans Python)

#### Étape 1 : Installer le prérequis obligatoire (**Npcap**)

MyNet Filter Windows a besoin du pilote réseau **Npcap** pour découvrir les appareils du LAN et contrôler le débit.

1. Téléchargez **Npcap** depuis le site officiel : <https://npcap.com/#download>
2. Lancez l'installeur `npcap-x.xx.exe` en tant qu'administrateur.
3. **Cochez impérativement** l'option :
   - `[x] Install Npcap in WinPcap API-compatible Mode`
4. Terminez l'installation (un redémarrage n'est généralement pas nécessaire).

> Sans Npcap, MyNet Filter Windows affiche un message guidé dès le démarrage.

#### Étape 2 : Télécharger et lancer `MyNet-Filter-GUI.exe`

1. Allez dans l'onglet **Actions → Build Windows release** du dépôt GitHub et téléchargez l'artefact **`mynet-filter-windows-release`** (`MyNet-Filter-Windows-<date>.zip` + `SHA256SUMS.txt`).
2. Extrayez l'archive ZIP dans un dossier (ex. `C:\Program Files\MyNet Filter\` ou sur votre Bureau).
3. Double-cliquez sur **`MyNet-Filter-GUI.exe`**.
4. Acceptez l'invite **Contrôle de compte d'utilisateur (UAC)** : les droits **Administrateur** sont demandés automatiquement (requis pour Npcap et les règles pare-feu).
5. Si Windows Defender / SmartScreen affiche un avertissement (exécutable non signé), cliquez sur **Informations complémentaires → Exécuter quand même**.

#### Prérequis système Windows (Option A)

- Windows 10 ou Windows 11 **64 bits**
- **Npcap** installé en mode compatible WinPcap
- Droits **Administrateur** (élévation UAC automatique)
- **Pare-feu Windows Defender** actif (utilisé pour le mode Pause ; nettoyage PowerShell indépendant de la langue de Windows)
- **Aucun** Python, Scapy ou PowerShell manuel requis.

---

### Option B — Lancer ou compiler Windows depuis les sources

Si vous souhaitez exécuter depuis le code source ou générer vous-même `MyNet-Filter-GUI.exe` :

#### Prérequis à installer

1. **Python 3.12 (64 bits)** depuis <https://www.python.org/downloads/windows/>
   - Cochez **`[x] Add python.exe to PATH`** et **`[x] tcl/tk and IDLE`** (nécessaire pour Tkinter).
2. **Npcap** (<https://npcap.com/#download>) avec **`[x] Install Npcap in WinPcap API-compatible Mode`**.
3. **Git for Windows** (<https://git-scm.com/download/win>) *(optionnel, pour cloner le dépôt)*.

#### Lancer depuis les sources (PowerShell en Administrateur)

```powershell
git clone https://github.com/NiceMank/mynet-filter.git
cd mynet-filter
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python mynet_filter_windows_gui.py
```

#### Compiler votre propre `MyNet-Filter-GUI.exe` + ZIP + SHA256

```powershell
.\build-windows.ps1
```

Le script exécute `pytest`, vérifie la syntaxe, compile `dist\MyNet-Filter-GUI.exe` avec l'icône `assets\mynet-filter.ico` et crée `dist\release\MyNet-Filter-Windows-<date>.zip` + `SHA256SUMS.txt`.

### Fonctionnalités incluses sur Windows

- Découverte passive + **balayage actif (`F5`)** filtré strictement sur le sous-réseau local
- Tableau de bord moderne : **4 cartes KPI**, **graphique temps réel**, **filtres** (`Tous` / `Actifs` / `Restreints` / `Protégés`), **tri multi-colonnes**, **menu contextuel clic droit**, **export CSV/JSON**
- **Mode Pause** + **Mode Limite en kb/s** (relais L2 Npcap + Token Bucket) + **Mode Focus** + **minuteur automatique**
- **Safe Mode persistant** (votre PC et la passerelle sont toujours protégés) et **alias personnalisés**
- **Bouton Appairage Android** intégré pour piloter votre PC Windows depuis votre téléphone Android

---

## 3. Installation sur Android (APK Companion)

L'application **MyNet Filter Companion** (Kotlin + Jetpack Compose Material 3) fonctionne sur **100 % des téléphones Android (Android 8.0+ / API 26+, SANS root)** en pilotant votre serveur MyNet Filter (PC Linux, PC Windows ou Raspberry Pi) sur le même réseau Wi-Fi.

### Option A — Installer l'APK compilé automatiquement (recommandé)

1. Allez dans l'onglet **Actions → Build Android APK** sur GitHub et téléchargez l'artefact **`mynet-filter-android-apk`** (`MyNet-Filter-Android-<date>.apk`).
2. Transférez le fichier `.apk` sur votre téléphone Android (ou téléchargez-le directement depuis le navigateur du téléphone).
3. Ouvrez le fichier `.apk`. Si Android le demande, autorisez **Installer des applications inconnues** pour votre navigateur / gestionnaire de fichiers.
4. Installez puis ouvrez **MyNet Filter Companion**.

### Option B — Compiler l'APK soi-même depuis les sources

#### Prérequis à installer sur votre PC

- **Android Studio** (Ladybug / Hedgehog ou plus récent) : <https://developer.android.com/studio>
  - Inclut le **JDK 17** et le **Android SDK (API 35)**.
- *(En ligne de commande sans Android Studio)* : **JDK 17** (`temurin-17`), **Android Command-Line Tools** (`platform-tools`, `platforms;android-35`, `build-tools;35.0.0`) et **Gradle 8.10.2**.

```bash
cd android
gradle --no-daemon assembleDebug
# APK généré dans : android/app/build/outputs/apk/debug/app-debug.apk
```

### Appairage Android ↔ PC (2 étapes)

1. **Démarrez l'API sur votre PC** :
   - Sur **Linux** :
     ```bash
     sudo mynet-filter daemon --api-bind 0.0.0.0 --api-port 8443
     ```
     *(Assurez-vous que le port TCP `8443` est ouvert dans votre pare-feu local, ex. `sudo ufw allow 8443/tcp` sur votre LAN).*
   - Sur **Windows** : cliquez simplement sur le bouton **`Appairage Android`** en haut à droite de `MyNet-Filter-GUI.exe` (l'URI est copiée automatiquement dans le presse-papiers ; autorisez le port `8443` dans le Pare-feu Windows sur le réseau privé si demandé).
2. **Collez l'URI dans l'application Android** (`mynetfilter://pair?host=192.168.x.x&port=8443&token=...`) puis appuyez sur **Se connecter au serveur**.

Consultez [docs/ANDROID_ARCHITECTURE.md](docs/ANDROID_ARCHITECTURE.md) pour la spécification complète de l'API REST et la feuille de route du mode Root/Hotspot.

---

## 4. Utilisation

### a) Interface graphique (Linux & Windows)

```bash
mynet-filter-gui          # Linux (utilisateur normal)
```

- **Tableau de bord** : 4 cartes KPI, graphique d'activité réseau en temps réel, filtres (`Tous`, `Actifs`, `Restreints`, `Protégés`), recherche instantanée et tri sur toutes les colonnes.
- **Presets & Focus** : `Éco 150k`, `Web 1M`, `Vidéo 2.5M`, `Mode Focus (250k)` en un clic.
- **Menu clic droit** : Pause, Limiter, Libérer, Safe Mode, Renommer, Copier IP/MAC.
- **Raccourcis** : `F5` / `Ctrl+R` (balayage actif), `Ctrl+A` (tout sélectionner), `Ctrl+D` (désélectionner), `Ctrl+clic` (sélection multiple).

### b) Console interactive (Linux / SSH)

```bash
sudo mynet-filter watch
```

| Touche | Effet |
|---|---|
| `1`, `2`, …, `12` | pause / reprendre l'appareil n° X |
| `l` | limiter **tous les appareils non protégés** (500 kb/s par défaut) |
| `p` | mettre **tous les appareils non protégés** en pause |
| `f` | tout libérer |
| `r` | lancer un balayage actif du réseau |
| `q` | quitter **et restaurer le réseau** |

### c) Ligne de commande Linux (scriptable)

```bash
sudo mynet-filter scan                       # découvrir les appareils (--json dispo)
sudo mynet-filter pause 3                    # coupe l'appareil n°3
sudo mynet-filter pause 3 --duration 600     # pause automatique de 10 minutes
sudo mynet-filter pause 2,4                  # plusieurs appareils d'un coup
sudo mynet-filter pause local                # coupe tous les appareils non protégés
sudo mynet-filter limit 3 --rate 200         # 200 kb/s maxi
sudo mynet-filter free 3                     # rend l'appareil à la normale
sudo mynet-filter free all                   # tout le monde
sudo mynet-filter safe add 192.168.1.25      # protège un appareil en Safe Mode
sudo mynet-filter alias set 192.168.1.25 "TV Salon"
sudo mynet-filter status --json              # état courant au format JSON
sudo mynet-filter quit                       # arrête le service + restaure tout
```

---

## 5. Builds automatiques GitHub Actions

Le dépôt inclut 3 workflows automatisés dans `.github/workflows/` :

| Workflow | Fichier | Déclenchement | Artefact produit |
|---|---|---|---|
| **CI** | `ci.yml` | Chaque `push` et `pull_request` | Lint `ruff` + `pytest` sur Linux (Python 3.10 & 3.12) et Windows (Python 3.12) |
| **Build Windows release** | `build-windows.yml` | Manuel (`workflow_dispatch`), tags `v*`, ou push sur fichiers Windows/core/UI | `mynet-filter-windows-release` (`MyNet-Filter-Windows-<date>.zip` + `SHA256SUMS.txt`) |
| **Build Android APK** | `build-android.yml` | Manuel (`workflow_dispatch`), tags `v*`, ou push sur `android/**` | `mynet-filter-android-apk` (`MyNet-Filter-Android-<date>.apk` + `SHA256SUMS.txt`) |

Pour créer une release Linux localement :

```bash
bash build-release.sh
# Produit dist/release/MyNet Filter-<date>.tar.gz (démon + GUI) + SHA256SUMS.txt
```

---

## 6. Sécurité, réversibilité & limites honnêtes

- **Sécurité IPC** : le socket `/run/mynet-filter.sock` est restreint au groupe `mynet-filter` (`0660`), toutes les commandes système s'exécutent sans shell (`shell=False`) avec validation stricte IPv4/MAC/interface.
- **Sortie propre** : à `q`, `Ctrl-C`, `quit` ou `systemctl stop`, les tables ARP sont restaurées, les règles `iptables`/`ip6tables`/`tc` (ou Pare-feu Windows) sont supprimées et `net.ipv4.ip_forward` est remis à son état initial. Filet de sécurité Linux : `sudo mynet-filter clean`.
- **Désinstallation Linux** : `bash uninstall.sh`.
- **IPv6 & AP Isolation** : `sudo mynet-filter doctor` signale si IPv6 est actif sur le Wi-Fi. Si la box active l'isolation des clients Wi-Fi (AP Isolation), vérifiez avec `sudo mynet-filter selftest <IP>`.
- **Usage responsable** : n'utilisez cet outil que sur **votre propre réseau** et sur des appareils dont vous êtes responsable.

---

## 7. Architecture des fichiers

| Fichier / Dossier | Rôle |
|---|---|
| `mynet_filter_core.py` | Noyau partagé (validation stricte, OUI, alias, minuteurs, TokenBucket, IPC, API Companion Android) |
| `mynet_filter_ui_common.py` | Composants UX partagés (thème sombre, cartes KPI, graphique temps réel, filtres, tri, export CSV/JSON) |
| `mynet_filter.py` | Moteur Linux, démon IPC, CLI & TUI console |
| `mynet_filter_gui.py` | Interface graphique Tkinter Linux |
| `mynet_filter_windows.py` | Backend natif Windows (Npcap, relais L2 TokenBucket, Pare-feu PowerShell multi-langues) |
| `mynet_filter_windows_gui.py` | Interface graphique Tkinter Windows |
| `android/` | Projet Android Studio complet (Kotlin + Jetpack Compose Material 3) |
| `assets/` | Icônes (`svg`, `png`, `ico`) et base OUI hors-ligne (`oui.txt`) |
| `docs/ANDROID_ARCHITECTURE.md` | Spécification technique & contrat API Android |
| `install.sh` / `uninstall.sh` | Installation et désinstallation Linux |
| `mynet-filter.service` | Unité systemd sécurisée |
| `build-release.sh` / `build-windows.ps1` | Scripts de packaging Linux et Windows |
| `tests/` | Suite de tests automatisés `pytest` (31 tests) |

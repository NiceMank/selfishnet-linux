# SelfishNet-Linux — l'équivalent Linux de SelfishNet

Quand les autres appareils du wifi saturent la connexion et que vos agents IA
(ou vos uploads, vos visios, vos git push) rament, cet outil vous redonne la
priorité : il **met en pause** ou **plafonne le débit** des appareils de votre
choix, exactement comme SelfishNet sous Windows.

![Interface](gui_screenshot.png)

---

## 1. Installation (2 minutes)

```bash
cd selfishnet-linux
bash install.sh
```

Le script installe `python3-scapy`, `iptables`, `iproute2`, active
`net.ipv4.ip_forward`, et crée la commande `selfishnet`.

Installation manuelle si vous préférez :

```bash
sudo apt install python3-scapy iptables iproute2 tcpdump
sudo python3 selfishnet.py doctor     # vérifie que tout est prêt
```

## 2. Utilisation

### a) Version graphique (comme SelfishNet Windows)

```bash
sudo selfishnet-gui
```
Boutons de sélection rapide :

| Bouton | Effet |
|---|---|
| **Tout cocher** (ou `Ctrl+A`) | coche **tous** les appareils listés → puis « Mettre en pause » / « Limiter » |
| **Tout décocher** (ou `Ctrl+D`) | vide la sélection |
| **■ BLOQUER TOUT** | coupe **immédiatement tout le monde** sauf vous et la box (avec confirmation) |
| **Limiter tout** / **Libérer tout** | plafonne ou rétablit tous les appareils d'un clic |

`Ctrl+clic` / `Maj+clic` pour une sélection multiple fine, puis : **Mettre en pause**,
**Limiter** (débit en kb/s), ou **Libérer**.

### b) Console interactive (la plus fiable, marche en SSH)

```bash
sudo selfishnet watch
```

| Touche | Effet |
|---|---|
| `1`, `2`, … | pause / reprendre l'appareil n° X |
| `l` | limiter **tout le monde** (500 kb/s par défaut) |
| `p` | mettre tout le monde en pause |
| `f` | tout libérer |
| `p` | **bloquer tout** (sauf vous et la box) |
| `q` | quitter **et restaurer le réseau** |

### c) En ligne de commande (scriptable, cron, alias)

```bash
sudo selfishnet scan                 # découvrir les appareils
sudo selfishnet pause 3              # coupe l'appareil n°3
sudo selfishnet pause 2,4            # plusieurs d'un coup
sudo selfishnet pause local          # bloque TOUT le monde sauf moi + la box
sudo selfishnet pause all            # tout, sans exception
sudo selfishnet limit 3 --rate 200   # 200 kb/s maxi
sudo selfishnet free 3               # rend l'appareil à la normale
sudo selfishnet free all             # tout le monde
sudo selfishnet status               # état courant
sudo selfishnet quit                 # arrête le service + restaure
```

Les commandes `pause/limit/free/status` ont besoin que le service tourne.
Lancez-le une fois dans un terminal dédié :

```bash
sudo selfishnet daemon          # ou en service permanent :
sudo systemctl enable --now selfishnet
```

…puis utilisez les commandes courtes depuis n'importe quel autre terminal.

## 3. Les trois modes

| Mode | Effet réel | Usage |
|---|---|---|
| **pause** | L'appareil est totalement coupé (ARP spoofing + `DROP` par IP **et** par MAC quand le noyau le permet) | « coupe-le 10 minutes, je bosse » |
| **limit** | Débit plafonné en kb/s, montant **et** descendant | l'appareil croit avoir du réseau mais ne peut plus saturer la ligne |
| **free** | Retour à la normale (ARP restauré, règles supprimées) | dès que vous avez fini |

## 4. Comment ça marche (et pourquoi c'est réversible)

1. **Découverte** : écoute passive du réseau (ARP + IP) → liste des IP, MAC,
   débit et nombre de paquets de chaque appareil. Aucun scan agressif.
2. **ARP spoofing** : pour la cible choisie, votre machine se présente comme la
   passerelle (et inversement), ce qui force son trafic à passer par vous.
   `net.ipv4.ip_forward=1` étant activé, le trafic des appareils **non** ciblés
   continue de circuler normalement.
3. **Application** :
   * pause → règles `iptables` `DROP` sur l'IP **et** sur la MAC source
     (`-m mac --mac-source`) : changer d'adresse IP ne suffit donc pas à
     contourner le blocage. Si le noyau n'a pas le module `mac`
     (certains VPS/containers), repli automatique sur le blocage par IP seul
     et l'interface l'indique ;
   * limit → `tc` (HTB descendant + police ingress montant) si le noyau le
     permet, sinon repli automatique sur `iptables -m limit` (*mode
     compatibilité*, débit approximatif) ;
4. **Sortie propre** : à `q`, `Ctrl‑C`, `quit` ou `systemctl stop`, les tables
   ARP des cibles sont restaurées (5 ARP correctifs), les chaînes
   `SELFISHNET` sont supprimées et le `qdisc` racine est retiré.
   Filet de sécurité : `sudo selfishnet clean`.

### Limites honnêtes

* **Isolation des clients (AP isolation)** : si votre box l'active, les
  appareils ne peuvent pas se parler → l'ARP spoofing ne fonctionne pas.
  Testez : `sudo selfishnet selftest <IP d'un appareil>` (affiche le % de
  pertes avant/après).
* En **wifi**, votre carte et la box peuvent envoyer des trames plus vite que
  le débit réel : « pause » est fiable, « limit » est précis en filaire et
  approximatif en wifi (le mode compatibilité compte les paquets).
* Ce n'est pas un contournement de la box : si l'appareil visé crypte/épingle
  la MAC de la passerelle, ou si le réseau est en WPA3-Enterprise/802.1X avec
  filtrage MAC, il faudra passer par l'interface d'administration du routeur.
* Tout appareil **câblé** sur le même switch est aussi visible et gérable.

## 5. Le cas « j'ai mon propre routeur / hotspot »

C'est la configuration idéale (aucune limite AP isolation) : vous êtes le
routeur, l'outil fonctionne à 100 %.

```bash
# sur la machine qui partage la connexion
sudo selfishnet --iface wlan0 watch      # ou ap0 / br0 selon votre config
```

Pour un partage de connexion **depuis votre téléphone** (hotspot), lancez
l'outil sur le PC connecté au hotspot : le téléphone n'est alors pas gérable
(c'est lui le routeur), mais tous les autres clients du hotspot le sont.

## 6. Désinstallation

```bash
bash uninstall.sh
# ou, à la main :
sudo selfishnet clean && sudo rm /usr/local/sbin/selfishnet*
```

## 7. Avertissement

Cet outil modifie le réseau local. Ne l'utilisez que sur **votre** réseau et sur
des appareils dont vous êtes responsable (votre box, votre partage de
connexion, votre famille). Couper l'accès d'un tiers (cybercafé, wifi public,
voisin) peut être illégal selon la législation locale et vous exposer à des
poursuites. Si le problème vient d'un voisin qui vole votre wifi : changez le
mot de passe, cachez le SSID, activez le filtrage MAC ou baissez la puissance
d'émission de la box — c'est plus simple et plus sûr.

## 8. Fichiers

| Fichier | Rôle |
|---|---|
| `selfishnet.py` | moteur + CLI + console interactive |
| `selfishnet_tui.py` | interface graphique Tkinter |
| `install.sh` / `uninstall.sh` | installation / retrait |
| `selfishnet.service` | unité systemd (démarrage au boot) |
| `requirements.txt` | scapy |

PortGuard

🇬🇧 PortGuard (English)

PortGuard shields your server from port scans using iptables + ipset.
Only your allowed ports stay open; scanners are auto-blacklisted (all ports look closed to them).

⚡️ Quick Install

wget -qO /tmp/portguard.sh https://raw.githubusercontent.com/wissjinatech/PortGuard/main/secure_ports_scan.sh \
&& sed -i 's/\r$//' /tmp/portguard.sh \
&& chmod +x /tmp/portguard.sh \
&& sudo /tmp/portguard.sh


🧭 Menu

1) Apply security (configure ports & thresholds)
2) Add IP to whitelist
3) Add IP to blacklist
4) Show whitelist & config
5) Show blacklist
0) Exit

Config at /etc/portguard.conf; persistence across reboots enabled.

✅ Requirements: Linux, root, iptables, ipset.




PortGuard protège votre serveur contre les scans de ports (iptables + ipset).
Il autorise uniquement les ports que vous déclarez et bannit automatiquement les scanneurs (pour eux, tous les ports paraissent fermés).
EN below.

⚡️ Installation rapide

wget -qO /tmp/portguard.sh https://raw.githubusercontent.com/wissjinatech/PortGuard/main/secure_ports_scan.sh \
&& sed -i 's/\r$//' /tmp/portguard.sh \
&& chmod +x /tmp/portguard.sh \
&& sudo /tmp/portguard.sh


🧭 Utilisation (menu)

1) Appliquer la sécurité (config ports & seuils)
2) Ajouter IP à la whitelist
3) Ajouter IP à la blacklist
4) Afficher whitelist & config
5) Afficher blacklist
0) Quitter

Config sauvegardée dans /etc/portguard.conf (modifiable à la main ou via l’option 1).

Persistance au reboot : ipset-restore.service + netfilter-persistent (ou service fallback auto).

✅ Prérequis

Linux (Debian/Ubuntu, RHEL/Alma/Rocky, openSUSE), root, iptables + ipset.


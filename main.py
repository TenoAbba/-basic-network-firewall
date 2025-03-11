# Importer les bibliothèques nécessaires
from scapy.all import *  # Pour l'analyse des paquets réseau
import logging  # Pour enregistrer les activités
import json     # Pour lire les règles depuis un fichier JSON

# Configurer le système de journalisation
logging.basicConfig(
    filename='firewall.log',  # Fichier de logs
    level=logging.INFO,       # Niveau de log (INFO)
    format='%(asctime)s - %(message)s'  # Format des entrées de log
)

# Charger les règles depuis le fichier JSON
with open('firewall_rules.json', 'r') as f:
    RULES = json.load(f)

def block_packet(packet):
    """Fonction pour analyser et bloquer les paquets indésirables"""
    # Vérifier les adresses IP bloquées
    if packet.haslayer(IP):
        src_ip = packet[IP].src  # IP source
        dst_ip = packet[IP].dst  # IP destination
        
        # Bloquer si IP source ou destination est dans la liste
        if src_ip in RULES['blocked_ips'] or dst_ip in RULES['blocked_ips']:
            logging.warning(f"IP bloquée : {src_ip} -> {dst_ip}")
            return True

    # Vérifier les ports bloqués (TCP/UDP)
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        dport = packet.dport  # Port destination
        sport = packet.sport  # Port source
        
        # Bloquer si port dans la liste
        if dport in RULES['blocked_ports'] or sport in RULES['blocked_ports']:
            logging.warning(f"Port bloqué : {dport}/{sport}")
            return True

    # Bloquer les pings ICMP si activé
    if packet.haslayer(ICMP) and RULES['block_icmp']:
        logging.warning("Ping ICMP bloqué")
        return True

    return False  # Ne pas bloquer le paquet

def start_firewall():
    """Démarrer la surveillance du réseau"""
    sniff(
        filter="ip",          # Filtrer seulement le trafic IP
        prn=lambda p: block_packet(p),  # Appliquer la fonction à chaque paquet
        store=0               # Ne pas stocker les paquets en mémoire
    )

if __name__ == "__main__":
    print("[*] Démarrage du pare-feu...")
    start_firewall()

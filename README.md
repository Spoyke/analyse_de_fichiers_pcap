# TP1 — Analyse de trames réseau DroneID
Projet issu du TP de Logiciel embarqué et sécurisé permettant d'analyser des trames Wi-Fi beacon issues de fichiers PCAP, avec extraction et export des données de localisation de drones (DroneID). Réalisé par **Simon REMY** et **Talha FAYYAZ**.

## Fonctionnalités

- Lecture et parsing de fichiers `.pcap` / `.pcapng`
- Détection des trames **beacon 802.11**
- Extraction des informations DroneID : identifiant, latitude, longitude, altitude
- Export des résultats en **JSON**, **YAML** ou **CSV**
- Affichage en console si aucun fichier de sortie n'est spécifié

## Utilisation

### Analyser un fichier PCAP

```bash
cargo run -- pcap <chemin_vers_fichier.pcap>
```

### Sauvegarder les résultats dans un fichier

```bash
# Format JSON (par défaut)
cargo run -- pcap <chemin_vers_fichier.pcap> --output results.json --format json

# Format YAML
cargo run -- pcap <chemin_vers_fichier.pcap> --output results.yaml --format yaml

# Format CSV
cargo run -- pcap <chemin_vers_fichier.pcap> --output results.csv --format csv
```

### Options disponibles

| Option | Raccourci | Description | Valeur par défaut |
|---|---|---|---|
| `--output` | `-o` | Fichier de sortie | *(affichage console)* |
| `--format` | `-f` | Format de sortie (`json`, `yaml`, `csv`) | `json` |

## Structure du projet

```
src/
├── main.rs      # Point d'entrée, gestion des arguments CLI (clap)
├── frame.rs     # Parsing des trames PCAP et structures de données
└── file.rs      # Sérialisation et sauvegarde des résultats
```

### Modules

- **`frame`** : ouverture du fichier PCAP, parsing des trames beacon 802.11, extraction des tags TLV, décodage des données DroneID (coordonnées GPS, altitude, identifiant).
- **`file`** : sérialisation des trames parsées vers JSON (`serde_json`), YAML (`serde_yaml`) ou CSV (`csv`), et écriture sur disque.


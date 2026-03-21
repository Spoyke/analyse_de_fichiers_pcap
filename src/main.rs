use clap::{Parser, Subcommand};
use pcap;

#[derive(Subcommand)]
enum Commands {
    /// Affiche des données du fichier '.pcapng' du 'path'
    Pcap { path: String },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// Traite le contenu d'un header au format tlv : extrait et affiche des informations sur le header
fn process_tlv(data: &[u8]) {
    let mut offset = 0;

    while offset < data.len() {
        // la taille du tag est stocké sur l'octet suivant le type de tag
        let tag_len = data[offset + 1] as usize;

        match data[offset] {
            0x00 => {
                let ssid_hex = &data[offset + 2..offset + 2 + tag_len];
                let ssid_text = String::from_utf8_lossy(ssid_hex);
                println!("SSID : {ssid_text}");
            }
            _ => {}
        }

        // On incrémente l'offset de la taille des données du tag + 1 pour l'octet stockant la taille + 1 pour passer au tag suivant
        offset += (tag_len + 1) + 1;
    }
}

/// Traite une trame du fichier pcap fournit en affichant les données demandées par l'énoncé
fn process_frame(frame: &[u8]) -> () {
    let radiotap_len = (frame[2] as usize) | ((frame[3] as usize) << 8);

    // Si le premier octet de l'en-tête 802.11 MAC (après l'en-tête Radiotap) vaut 0x80, il s'agit d'une trame de type 'beacon'
    if frame[radiotap_len] != 0x80 {
        return;
    }

    println!("--- Trame de type 'beacon' ---");

    // Offset par rapport au début de la trame où commence l'adresse mac de l'envoyeur
    let offset_mac_addr_transmitter = radiotap_len + 10;
    let len_mac_addr = 6;
    print!("MAC  : ");
    for data in &frame[offset_mac_addr_transmitter..offset_mac_addr_transmitter + len_mac_addr] {
        print!("{:02x} ", data);
    }
    println!();

    let mac_header_len = 24;
    let fixed_management_header = 12;
    let variable_management_header =
        &frame[radiotap_len + mac_header_len + fixed_management_header..];

    process_tlv(variable_management_header);
}

/// Traite le fichier pcap fournit par le cli
fn process_pcap(path: String) -> () {
    let Ok(res) = pcap::Capture::from_file(path) else {
        println!("Échec de la lecture du fichier pcap");
        return;
    };

    let mut cap = res;
    while let Ok(packet) = cap.next_packet() {
        process_frame(packet.data);
        return;
    }
}

fn main() {
    let args = Args::parse();

    match &args.command {
        Commands::Pcap { path } => {
            process_pcap(path.to_string());
        }
    }
}

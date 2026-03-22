use clap::{Parser, Subcommand};
use pcap;

mod frame;

#[derive(Subcommand)]
enum Commands {
    /// Affiche des données du fichier '.pcapng' du 'path'
    Pcap { path: String },
    /// Spécifie le fichier dans lequel les données doivent êtres sauvegarder
    OutputFile { path: String },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

fn main() {
    let args = Args::parse();

    match &args.command {
        Commands::Pcap { path } => {
            process_pcap(path);
        }
        Commands::OutputFile { path } => {}
    }
}

/// Ouvre le fichier pcapng et traite trame par trame son contenu
fn process_pcap(path: &str) {
    let Ok(mut cap) = pcap::Capture::from_file(path) else {
        println!("Échec de la lecture du fichier pcap");
        return;
    };

    while let Ok(packet) = cap.next_packet() {
        if let Some(frame) = frame::parse_frame(packet.data) {
            println!("{}", frame);
        }
    }
}

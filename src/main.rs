use clap::{Parser, Subcommand};
use pcap;

mod frame;

#[derive(Subcommand)]
enum Commands {
    /// Affiche des données du fichier '.pcapng' du 'path'
    Pcap {
        path: String,

        /// Fichier de sortie optionnel
        #[arg(short, long)]
        output: Option<String>,

        /// Format du fichier de sortie
        #[arg(short, long, default_value = "json")]
        format: OutputFormat,
    },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Json,
    Yaml,
    Csv,
}

fn main() {
    let args = Args::parse();

    match &args.command {
        Commands::Pcap {
            path,
            output,
            format,
        } => {
            let frames = process_pcap(path);

            if let Some(output_path) = output {
                save_frames(&frames, output_path, format);
            } else {
                for frame in frames {
                    println!("{}", frame);
                }
            }
        }
    }
}

/// Ouvre le fichier pcapng et traite trame par trame son contenu
fn process_pcap(path: &str) -> Vec<frame::Frame> {
    let Ok(mut cap) = pcap::Capture::from_file(path) else {
        println!("Échec de la lecture du fichier pcap");
        return Vec::new();
    };

    let mut frames = Vec::new();
    while let Ok(packet) = cap.next_packet() {
        if let Some(frame) = frame::parse_frame(packet.data) {
            frames.push(frame);
        }
    }
    frames
}

/// Sauvegarde les trames dans un fichier JSON
fn save_frames(frames: &[frame::Frame], path: &str, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            let content = serde_json::to_string_pretty(frames).expect("Erreur JSON");
            std::fs::write(path, content).expect("Erreur de sauvegarde");
        }
        OutputFormat::Yaml => {
            let content = serde_yaml::to_string(frames).expect("Erreur YAML");
            std::fs::write(path, content).expect("Erreur de sauvegarde");
        }
        OutputFormat::Csv => frames_to_csv(frames, path),
    };
    println!("{} trames sauvegardées dans {}", frames.len(), path);
}

fn frames_to_csv(frames: &[frame::Frame], path: &str) {
    let mut wtr = csv::Writer::from_path(path).expect("Erreur de création du fichier CSV");

    wtr.write_record([
        "kind",
        "src_mac",
        "ssid",
        "drone_id",
        "latitude",
        "longitude",
        "altitude",
    ])
    .expect("Erreur d'écriture des en-têtes");

    for frame in frames {
        let (drone_id, latitude, longitude, altitude) = match &frame.extra_data {
            frame::ExtraData::DroneData { drone } => (
                drone.id.clone(),
                drone.latitude.to_string(),
                drone.longitude.to_string(),
                drone.altitude.to_string(),
            ),
            frame::ExtraData::None => (String::new(), String::new(), String::new(), String::new()),
        };

        wtr.serialize((
            frame.kind,
            format!("{:?}", frame.src_mac),
            &frame.ssid,
            drone_id,
            latitude,
            longitude,
            altitude,
        ))
        .expect("Erreur de sérialisation CSV");
    }

    wtr.flush().expect("Erreur de flush");
}

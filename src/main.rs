mod file;
mod frame;

use clap::{Parser, Subcommand};

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
            let frames = frame::process_pcap(path);

            if let Some(output_path) = output {
                file::save_frames(&frames, output_path, format);
            } else {
                for frame in frames {
                    println!("{}", frame);
                }
            }
        }
    }
}

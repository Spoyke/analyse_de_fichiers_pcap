use std::fmt;

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

struct Frame {
    type_: &'static str,
    mac: [u8; 6],
    ssid: String,
    drone_data: Option<DroneData>,
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d, e, g] = self.mac;
        write!(
            f,
            "--- TRAME REÇUE ---\nType: {}\nMAC:  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\nSSID: {}\n",
            self.type_, a, b, c, d, e, g, self.ssid
        )?;

        if let Some(d) = &self.drone_data {
            write!(
                f,
                "\nID: {}\nLongitude: {}\nLatitude: {}\nAltitude: {}\nVitesse: {}\n",
                d.id, d.longitude, d.latitude, d.altitude, d.speed
            )?;
        }

        write!(f, "-------------------")
    }
}

struct Tag {
    type_: u8,
    data: Vec<u8>,
}

#[derive(Default)]
struct DroneData {
    id: String,
    longitude: f64,
    latitude: f64,
    altitude: f64,
    speed: f64,
}

fn main() {
    let args = Args::parse();

    match &args.command {
        Commands::Pcap { path } => {
            process_pcap(path);
        }
    }
}

/// Ouvre le fichier pcapng et traite trame par trame son contenu
fn process_pcap(path: &str) {
    let Ok(mut cap) = pcap::Capture::from_file(path) else {
        println!("Échec de la lecture du fichier pcap");
        return;
    };

    while let Ok(packet) = cap.next_packet() {
        if let Some(frame) = process_frame(packet.data) {
            println!("{}", frame);
        }
    }
}

fn process_frame(frame: &[u8]) -> Option<Frame> {
    let radiotap_len = (frame[2] as usize) | ((frame[3] as usize) << 8);

    // Si le premier octet de l'en-tête 802.11 MAC (après l'en-tête Radiotap) vaut 0x80, il s'agit d'une trame de type 'beacon'
    if frame.get(radiotap_len)? != &0x80 {
        return None;
    }

    // L'adresse MAC de l'envoyeur se trouve à l'indice 'radiotap_len + 10' de frame
    let offset_mac = radiotap_len + 10;
    let mac: [u8; 6] = frame.get(offset_mac..offset_mac + 6)?.try_into().ok()?;

    // Les tags commencent après 'Radiotap', les 24 octets de l'en-tête MAC et des 12 octets de la partie fixe de l'en-tête de gestion
    let tags = get_tags(frame.get(radiotap_len + 36..)?);
    let mut ssid = String::new();
    let mut drone_data: Option<DroneData> = None;

    for tag in &tags {
        match tag.type_ {
            0x00 => {
                ssid = String::from_utf8_lossy(&tag.data).into_owned();
            }
            0xdd => {
                if let Some(data) = parse_drone_data(&tag.data) {
                    drone_data = Some(data);
                }
            }
            _ => {}
        }
    }

    Some(Frame {
        type_: "beacon",
        mac,
        ssid,
        drone_data,
    })
}

fn get_tags(data: &[u8]) -> Vec<Tag> {
    let mut offset = 0;
    let mut tags = Vec::new();

    while offset + 2 <= data.len() {
        let tag_type = data[offset];
        let tag_len = data[offset + 1] as usize;
        let end = offset + 2 + tag_len;

        if end > data.len() {
            break;
        }

        tags.push(Tag {
            type_: tag_type,
            data: data[offset + 2..end].to_vec(),
        });

        offset = end;
    }

    tags
}

fn parse_drone_data(data: &[u8]) -> Option<DroneData> {
    // Fonctions permettant de convertir les tableaux d'octets en entier (trouvé sur internet)
    let parse_i32 = |bytes: &[u8]| -> Option<i32> {
        Some(i32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?))
    };

    let parse_i16 = |bytes: &[u8]| -> Option<i16> {
        Some(i16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?))
    };

    let mut drone = DroneData::default();

    for tag in get_tags(&data[4..]) {
        match tag.type_ {
            0x02 => {
                if let Some(slice) = tag.data.get(7..) {
                    drone.id = String::from_utf8_lossy(slice).into_owned();
                }
            }
            0x04 => {
                if let Some(raw) = parse_i32(&tag.data) {
                    drone.latitude = raw as f64 / 1e5;
                }
            }
            0x05 => {
                if let Some(raw) = parse_i32(&tag.data) {
                    drone.longitude = raw as f64 / 1e5;
                }
            }
            0x06 => {
                if let Some(raw) = parse_i16(&tag.data) {
                    drone.altitude = raw as f64 / 10.0;
                }
            }
            0x10 => {
                if let Some(raw) = parse_i32(&tag.data) {
                    drone.speed = raw as f64 / 100.0;
                }
            }
            _ => {}
        }
    }

    if drone.id.is_empty() {
        return None;
    }

    Some(drone)
}

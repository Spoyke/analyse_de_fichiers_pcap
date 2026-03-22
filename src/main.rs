use std::fmt::{self};

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
    type_: String,
    mac: [u8; 6],
    ssid: String,
    drone_data: Option<DroneData>,
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mac_fmt = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        );

        write!(
            f,
            "--- TRAME REÇUE ---\nType: {}\nMAC:  {}\nSSID: {}\n",
            self.type_, mac_fmt, self.ssid
        )?;

        match &self.drone_data {
            Some(d) => write!(
                f,
                "\nID: {}\nLongitude: {}\nLatitude: {}\nAltitude: {}\nVitesse: {}\n",
                d.id, d.longitude, d.latitude, d.altitude, d.speed
            )?,
            None => {}
        }

        write!(f, "-------------------")
    }
}

#[derive(Debug)]
struct Tag {
    type_: u8,
    data: Vec<u8>,
}

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
            process_pcap(path.to_string());
        }
    }
}

/// Ouvre le fichier pcapng et traite trame par trame son contenu
fn process_pcap(path: String) -> () {
    let Ok(res) = pcap::Capture::from_file(path) else {
        println!("Échec de la lecture du fichier pcap");
        return;
    };

    let mut cap = res;
    while let Ok(packet) = cap.next_packet() {
        match process_frame(packet.data) {
            Some(frame) => println!("{}", frame),
            None => {}
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
    let mac: [u8; 6] = (&frame[offset_mac..offset_mac + 6])
        .try_into()
        .expect("Erreur lors de la conversion de l'adresse MAC ");

    // Les tags commencent après 'Radiotap', les 24 octets de l'en-tête MAC (énoncé) et des 12 octets de la partie fixe de l'en-tête de gestion
    // let tags_offset = radiotap_len + 24 + 12;
    let tags = get_tags(&frame[radiotap_len + 24 + 12..]);
    let mut ssid: String = "".to_string();
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

    // Dans le code actuelle, on garde uniquement les trames de type 'beacon'
    Some(Frame {
        type_: "beacon".to_string(),
        mac: mac,
        ssid: ssid,
        drone_data: drone_data,
    })
}

fn get_tags(data: &[u8]) -> Vec<Tag> {
    let mut offset = 0;
    let mut tags: Vec<Tag> = Vec::new();

    while offset < data.len() {
        if offset + 2 > data.len() {
            break;
        }

        let tag_type = data[offset];
        let tag_len = data[offset + 1] as usize;
        let end = offset + 2 + tag_len;

        if end > data.len() {
            break;
        }

        let tag_data = &data[offset + 2..offset + 2 + tag_len];

        tags.push(Tag {
            type_: tag_type,
            data: tag_data.to_vec(),
        });

        offset += tag_len + 2;
    }
    tags
}

fn parse_drone_data(data: &[u8]) -> Option<DroneData> {
    if data.len() < 4 {
        return None;
    }

    let mut id: String = "".to_string();
    let mut latitude: f64 = 0.;
    let mut longitude: f64 = 0.;
    let mut altitude: f64 = 0.;
    let mut speed: f64 = 0.;

    for tag in get_tags(&data[4..]) {
        match tag.type_ {
            0x02 => {
                if let Some(slice) = tag.data.get(7..) {
                    id = String::from_utf8_lossy(slice).into_owned();
                }
            }
            0x04 => {
                if let Some(bytes) = tag.data.get(0..4) {
                    let raw = i32::from_be_bytes(bytes.try_into().unwrap());
                    latitude = raw as f64 / 1e5;
                }
            }
            0x05 => {
                if let Some(bytes) = tag.data.get(0..4) {
                    let raw = i32::from_be_bytes(bytes.try_into().unwrap());
                    longitude = raw as f64 / 1e5;
                }
            }
            0x06 => {
                if let Some(bytes) = tag.data.get(0..2) {
                    let raw = i16::from_be_bytes(bytes.try_into().unwrap());
                    altitude = raw as f64 / 10.0;
                }
            }
            0x10 => {
                if let Some(bytes) = tag.data.get(0..4) {
                    let raw = i32::from_be_bytes(bytes.try_into().unwrap());
                    speed = raw as f64 / 100.0;
                }
            }
            _ => {}
        }
    }

    if id == "".to_string() {
        return None;
    }

    Some(DroneData {
        id: id,
        longitude: longitude,
        latitude: latitude,
        altitude: altitude,
        speed: speed,
    })
}

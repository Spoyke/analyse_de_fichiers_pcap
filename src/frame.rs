use std::fmt;

pub struct Frame {
    kind: u8,
    src_mac: [u8; 6],
    ssid: String,
    extra_data: ExtraData,
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "--- TRAME REÇUE ---\nType: {:02x}\nSSID: {}\nSource MAC: {:?}\n",
            self.kind, self.ssid, self.src_mac
        )?;

        match &self.extra_data {
            ExtraData::DroneData { drone } => {
                write!(
                    f,
                    "\nDrone ID: {}\nLatitude: {}\nLongitude: {}\nAltitude: {}\n",
                    drone.id, drone.latitude, drone.longitude, drone.altitude
                )?;
            }
            ExtraData::None => {}
        }

        write!(f, "-------------------")
    }
}

enum ExtraData {
    DroneData { drone: Drone },
    None,
}

#[derive(Default)]
struct Drone {
    id: String,
    latitude: f64,
    longitude: f64,
    altitude: f64,
}

struct Tag {
    kind: u8,
    data: Vec<u8>,
}

pub fn parse_frame(data: &[u8]) -> Option<Frame> {
    let radiotap_len = (data[2] as usize) | ((data[3] as usize) << 8);

    // Si le premier octet de l'en-tête 802.11 MAC (après l'en-tête Radiotap)
    // vaut 0x80, il s'agit d'une trame de type 'beacon'
    if data[radiotap_len] != 0x80 {
        return None;
    }

    // L'adresse MAC de la source se trouve à l'indice 'radiotap_len + 10'
    // de frame
    let src_mac: [u8; 6] = data[radiotap_len + 10..radiotap_len + 16].try_into().ok()?;

    // Les tags commencent après 'Radiotap', les 24 octets de l'en-tête MAC
    // et des 12 octets de la partie fixe de l'en-tête de gestion
    let tags = get_tags(&data[radiotap_len + 36..]);

    let ssid = tags
        .iter()
        .find(|t| t.kind == 0x00)
        .map(|t| String::from_utf8_lossy(&t.data).into_owned())
        .unwrap_or_default();

    let extra_data = tags
        .iter()
        .find(|t| t.kind == 0xdd)
        .and_then(|t| parse_drone(t))
        .map_or(ExtraData::None, |drone| ExtraData::DroneData { drone });

    Some(Frame {
        kind: data[radiotap_len],
        src_mac,
        ssid,
        extra_data,
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
            kind: tag_type,
            data: data[offset + 2..end].to_vec(),
        });

        offset = end;
    }

    tags
}

fn parse_drone(tag: &Tag) -> Option<Drone> {
    // On ne prend pas les 4 premiers octets qui ne sont pas des tags du drone
    let inner_tags = get_tags(&tag.data[4..]);

    let id = inner_tags
        .iter()
        .find(|t| t.kind == 0x02)
        .and_then(|t| parse_string(&t.data))?;
    let latitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x04)
        .and_then(|t| parse_i32_coord(&t.data))
        .unwrap_or_default();
    let longitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x05)
        .and_then(|t| parse_i32_coord(&t.data))
        .unwrap_or_default();
    let altitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x06)
        .and_then(|t| parse_i16_alt(&t.data))
        .unwrap_or_default();

    Some(Drone {
        id,
        latitude,
        longitude,
        altitude,
    })
}

fn parse_string(data: &[u8]) -> Option<String> {
    if let Some(slice) = data.get(7..) {
        Some(String::from_utf8_lossy(slice).into_owned())
    } else {
        None
    }
}

fn parse_i32_coord(data: &[u8]) -> Option<f64> {
    Some(i32::from_be_bytes(data.get(0..4)?.try_into().ok()?) as f64 / 1e5)
}

fn parse_i16_alt(data: &[u8]) -> Option<f64> {
    Some(i16::from_be_bytes(data.get(0..2)?.try_into().ok()?) as f64 / 10.0)
}

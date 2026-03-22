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
    let frame_type: u8 = data[radiotap_len];

    // Si le premier octet de l'en-tête 802.11 MAC (après l'en-tête Radiotap)
    // vaut 0x80, il s'agit d'une trame de type 'beacon'
    if frame_type != 0x80 {
        return None;
    }

    // L'adresse MAC de la source se trouve à l'indice 'radiotap_len + 10'
    // de frame
    let offset_mac = radiotap_len + 10;
    let src_mac: [u8; 6] = data[offset_mac..offset_mac + 6]
        .try_into()
        .expect("Erreur lors de la récupération de l'adresse MAC");

    // Les tags commencent après 'Radiotap', les 24 octets de l'en-tête MAC
    // et des 12 octets de la partie fixe de l'en-tête de gestion
    let tags = get_tags(&data[radiotap_len + 36..]);

    let mut ssid: String = String::new();
    if let Some(tag) = tags.iter().find(|t| t.kind == 0x00) {
        ssid = String::from_utf8_lossy(&tag.data).into_owned();
    }

    let drone_tag = tags.iter().find(|t| t.kind == 0xdd);

    if drone_tag.is_none() {
        return Some(Frame {
            kind: frame_type,
            src_mac,
            ssid,
            extra_data: ExtraData::None,
        });
    }

    let drone_tags = drone_tag.unwrap();
    // On ne prend pas les 4 premiers octets qui ne sont pas des tags du drone
    let inner_tags = get_tags(&drone_tags.data[4..]);

    let drone_id = inner_tags
        .iter()
        .find(|t| t.kind == 0x02)
        .and_then(|t| parse_string(&t.data));
    let latitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x04)
        .and_then(|t| parse_i32_coord(&t.data));
    let longitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x05)
        .and_then(|t| parse_i32_coord(&t.data));
    let altitude = inner_tags
        .iter()
        .find(|t| t.kind == 0x06)
        .and_then(|t| parse_i16_alt(&t.data));

    let extra_data = match drone_id {
        None => ExtraData::None,
        Some(id) => ExtraData::DroneData {
            drone: Drone {
                id,
                latitude: latitude.unwrap_or_default(),
                longitude: longitude.unwrap_or_default(),
                altitude: altitude.unwrap_or_default(),
            },
        },
    };

    Some(Frame {
        kind: frame_type,
        src_mac,
        ssid: ssid,
        extra_data: extra_data,
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

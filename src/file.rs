use crate::frame;
use crate::OutputFormat;

/// Sauvegarde les trames dans un fichier JSON
pub fn save_frames(frames: &[frame::Frame], path: &str, format: &OutputFormat) {
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

/// Ecrit les données des trames dans un fichier au format csv
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

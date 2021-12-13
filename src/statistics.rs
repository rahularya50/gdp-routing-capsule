use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::LineWriter;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use capsule::metrics;
use metrics_core::{Builder, Observe};
use metrics_observer_yaml::YamlBuilder;
use metrics_runtime::Measurement::Counter;

fn print_stats_diff(
    current_m: &mut HashMap<String, u64>,
    history_m: &mut HashMap<String, Vec<u64>>,
) {
    let mut observer = YamlBuilder::new().build();
    metrics::global().controller().observe(&mut observer);
    let snapshot = metrics::global().controller().snapshot();
    println!("---------------------------");
    snapshot.into_measurements().iter().for_each(|(k, v)| {
        let (name, labels) = k.to_owned().into_parts();
        let labels = format!(
            "{} {}",
            name,
            labels
                .iter()
                .map(|label| format!("{}={}", label.key(), label.value()))
                .collect::<Vec<_>>()
                .join(",")
        );
        if let Counter(value) = v {
            let diff = value - current_m.insert(labels.clone(), *value).unwrap_or(0);
            println!("{}: {}", labels, diff,);
            history_m.entry(labels).or_insert(Vec::new()).push(diff);
        }
    });
}

pub fn make_print_stats() -> (impl Fn(), Arc<Mutex<HashMap<String, Vec<u64>>>>) {
    let stats_map_ref: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let history_map_ref: Arc<Mutex<HashMap<String, Vec<u64>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let history_map_copy = history_map_ref.clone();
    (
        move || {
            print_stats_diff(
                &mut *stats_map_ref.lock().unwrap(),
                &mut *history_map_ref.lock().unwrap(),
            )
        },
        history_map_copy,
    )
}

pub fn dump_history(map: &HashMap<String, Vec<u64>>) -> Result<()> {
    // Dump statistics to a statistics.csv

    let file = File::create("statistics.tsv")?;
    let mut file = LineWriter::new(file);

    // Write all the headers
    // Let's be sane and sort the keys
    let mut map_keys = map.keys().map(|s| &**s).collect::<Vec<_>>();
    if map_keys.is_empty() {
        return Ok(());
    }
    map_keys.sort_unstable();

    file.write_all((map_keys.join("\t") + "\n").as_bytes())?;

    // now write all the values
    let upto = map.get(map_keys[0]).map(|vec| vec.len()).unwrap_or(0);

    for i in 0..upto {
        let vals = map_keys
            .iter()
            .map(|k| {
                map.get(*k)
                    .map(|vec| vec.get(i).unwrap_or(&0))
                    .unwrap_or(&0)
                    .to_string()
            })
            .collect::<Vec<_>>();
        file.write_all((vals.join("\t") + "\n").as_bytes())?;
    }
    file.flush()?;

    Ok(())
}

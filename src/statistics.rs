use capsule::batch::Batch;

use capsule::metrics;

use capsule::packets::Packet;

use metrics_core::{Builder, Observe};
use metrics_observer_yaml::YamlBuilder;
use metrics_runtime::Measurement::Counter;
use std::collections::HashMap;

use std::sync::Mutex;

fn print_stats_diff(m: &mut HashMap<String, u64>) {
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
            println!(
                "{}: {}",
                labels,
                value - m.insert(labels.clone(), *value).unwrap_or(0)
            );
        }
    });
}

pub fn make_print_stats() -> impl Fn() {
    let stats_map: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    move || print_stats_diff(&mut stats_map.lock().unwrap())
}

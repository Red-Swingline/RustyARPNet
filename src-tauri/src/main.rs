// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod arp_scanner;
mod port_scanner;
use crate::port_scanner::scan_ports;
use serde_json::Value;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use tauri::api::dialog::FileDialogBuilder;
use tauri::AppHandle;
use tauri::Manager;
use tokio::time::Duration;

#[tauri::command(rename_all = "snake_case")]
async fn save_report(
    app: AppHandle,
    report_data: Vec<Value>, // Assume we receive a Vec of serde_json::Value objects representing the data
) {
    let _window = app.get_window("main").unwrap();

    // Use FileDialogBuilder to save a file
    FileDialogBuilder::new()
        .set_title("Save your report")
        .add_filter("Text file", &["txt"])
        .save_file(move |path: Option<PathBuf>| {
            if let Some(path) = path {
                // Attempt to create and write to the file
                match File::create(path) {
                    Ok(file) => {
                        let mut writer = BufWriter::new(file);
                        for entry in report_data {
                            // Assume `entry` is a JSON object with "ip_address" and "open_ports"
                            if let (Some(ip), Some(ports)) = (
                                entry.get("ip_address").and_then(Value::as_str),
                                entry.get("open_ports").and_then(Value::as_array),
                            ) {
                                // Convert open ports to a string
                                let ports_str = ports
                                    .iter()
                                    .map(|p| p.as_u64().unwrap_or(0).to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let line =
                                    format!("IP Address: {}, Open Ports: {}\n", ip, ports_str);
                                if writer.write_all(line.as_bytes()).is_err() {
                                    eprintln!("Failed to write to the report file");
                                    return;
                                }
                            }
                        }
                    }
                    Err(_) => eprintln!("Failed to create the report file"),
                }
            }
        });
}
#[tauri::command]
async fn arp_scan(
    app: AppHandle,
    interface_name: String,
    source_ip: String,
    subnet: String,
) -> Result<String, String> {
    arp_scanner::arp_scan(app, interface_name, source_ip, subnet)
}
#[tauri::command]
fn get_network_interfaces() -> Result<Vec<String>, String> {
    Ok(arp_scanner::get_interface_names())
}

#[tauri::command(rename_all = "snake_case")]
async fn scan_ports_for_ip(
    app: AppHandle,
    ip_address: String,
    scan_common: bool, // Flag to determine whether to scan common ports or all ports
) -> Result<Vec<u16>, String> {
    let target_ip = ip_address
        .parse::<IpAddr>()
        .map_err(|_| "Invalid IP address format".to_string())?;

    let concurrency = 1000; // Adjust the concurrency level based on your requirements
    let timeout = Duration::from_secs(5); // Adjust the timeout duration as needed

    // Call the scan_ports function with the appropriate parameters
    let open_ports = scan_ports(target_ip, scan_common, concurrency, timeout).await;

    // Send the result back to the frontend
    let result = serde_json::json!({
        "ip_address": ip_address,
        "open_ports": open_ports,
    });
    app.emit_all("port-scan-result", &result)
        .map_err(|e| e.to_string())?;

    Ok(open_ports)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_network_interfaces,
            arp_scan,
            scan_ports_for_ip,
            save_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

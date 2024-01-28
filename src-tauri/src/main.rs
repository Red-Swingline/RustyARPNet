// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod arp_scanner;
mod port_scanner;
use crate::port_scanner::scan_ports;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::BufWriter;
use std::net::IpAddr;
use std::path::PathBuf;
use printpdf::*;
use tauri::api::dialog::FileDialogBuilder;
use tauri::AppHandle;
use tauri::Manager;
use tokio::time::Duration;
use nix::unistd::{Uid, Gid, chown};

#[tauri::command(rename_all = "snake_case")]
async fn save_report(app: AppHandle, report_data: Vec<Value>) {
    let window = app.get_window("main").unwrap();

    // Determine the home directory path and user details for file ownership
    let (home_dir_path, user_uid, user_gid) = if cfg!(target_os = "windows") {
        (env::var("USERPROFILE").unwrap_or_else(|_| "".into()), 1000, 1000)
    } else {
        let real_user = env::var("SUDO_USER").unwrap_or_else(|_| env::var("USER").unwrap());
        let home_dir = format!("/home/{}", real_user);
        let uid = env::var("SUDO_UID").unwrap_or_else(|_| "1000".to_string()).parse::<u32>().unwrap_or(1000);
        let gid = env::var("SUDO_GID").unwrap_or_else(|_| "1000".to_string()).parse::<u32>().unwrap_or(1000);

        (home_dir, uid, gid)
    };

    FileDialogBuilder::new()
        .set_title("Save your report")
        .set_directory(&home_dir_path)
        .add_filter("PDF file", &["pdf"])
        .save_file(move |path: Option<PathBuf>| {
            if let Some(path) = path {
                let (doc, page1, layer1) = PdfDocument::new("Rusty ARP Report", Mm(210.0), Mm(297.0), "Layer 1");
                let current_layer = doc.get_page(page1).get_layer(layer1);
                let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();

                let mut y_position = Mm(297.0 - 20.0); // Start position for the first entry

                for (index, entry) in report_data.iter().enumerate() {
                    if index != 0 {
                        y_position -= Mm(10.0); // Space before each new entry
                    }

                    let ip_address = entry.get("ip_address").and_then(Value::as_str).unwrap_or("");
                    let mac_address = entry.get("mac_address").and_then(Value::as_str).unwrap_or("");
                    let header_text = format!("IP Address: {}, MAC Address: {}", ip_address, mac_address);

                    current_layer.use_text(header_text, 12.0, Mm(10.0), y_position, &font);
                    y_position -= Mm(5.0); // Move down for the port list

                    if let Some(ports) = entry.get("open_ports").and_then(Value::as_array) {
                        for port in ports {
                            let port_str = format!("• {}", port);
                            y_position -= Mm(5.0); // Move down for each port
                            current_layer.use_text(port_str, 10.0, Mm(15.0), y_position, &font);
                        }
                    }
                }

                let mut file = File::create(&path).expect("Failed to create PDF file");
                doc.save(&mut BufWriter::new(&mut file)).expect("Failed to save PDF");

                // Change the ownership of the file to the actual user
                if cfg!(target_os = "linux") {
                    let user_uid = Uid::from_raw(env::var("SUDO_UID").unwrap_or_default().parse::<u32>().unwrap_or(1000)); 
                    let user_gid = Gid::from_raw(env::var("SUDO_GID").unwrap_or_default().parse::<u32>().unwrap_or(1000)); 

                    match chown(&path, Some(user_uid), Some(user_gid)) {
                        Ok(_) => println!("Changed file ownership successfully."),
                        Err(e) => eprintln!("Failed to change file owner: {}", e),
                    }
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

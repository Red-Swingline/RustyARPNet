// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod arp_scanner;
mod port_scanner;
use arp_scanner::get_interface_names;
use crate::port_scanner::scan_ports;
use pnet::datalink;
use serde_json::json;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use tokio::time::Duration;
use tauri::AppHandle;
use tauri::Manager;

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
    let timeout = Duration::from_secs(3); // Adjust the timeout duration as needed

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
            scan_ports_for_ip
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

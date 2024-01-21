// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod arp_scanner;
use tauri::AppHandle;

#[tauri::command]
async fn arp_scan(app: AppHandle,interface_name: String, source_ip: String, subnet: String) -> Result<String, String> {
    arp_scanner::arp_scan(app,interface_name, source_ip, subnet)
}
#[tauri::command]
fn get_network_interfaces() -> Result<Vec<String>, String> {
    Ok(arp_scanner::get_interface_names())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_network_interfaces, arp_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
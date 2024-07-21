use std::fs::File;
use std::io::BufWriter;
use nix::unistd::{Uid, Gid, chown};
use printpdf::{BuiltinFont, Mm, PdfDocument};
use tauri::{AppHandle, Emitter, Manager};
use serde_json::{json, Value};
use log::{info, error, debug};
use tauri_plugin_dialog::DialogExt;
use std::env;
use std::net::IpAddr;
use std::time::Duration;

mod arp_scanner;
mod port_scanner;

use crate::port_scanner::scan_ports;

#[tauri::command]
async fn save_report(app: tauri::AppHandle, report_data: Vec<Value>) -> Result<(), String> {
    let (home_dir_path, user_uid, user_gid) = if cfg!(target_os = "windows") {
        (env::var("USERPROFILE").unwrap_or_else(|_| "".into()), 1000, 1000)
    } else {
        let real_user = env::var("SUDO_USER").unwrap_or_else(|_| env::var("USER").unwrap());
        let home_dir = format!("/home/{}", real_user);
        let uid = env::var("SUDO_UID").unwrap_or_else(|_| "1000".to_string()).parse::<u32>().unwrap_or(1000);
        let gid = env::var("SUDO_GID").unwrap_or_else(|_| "1000".to_string()).parse::<u32>().unwrap_or(1000);
        (home_dir, uid, gid)
    };

    let (tx, rx) = std::sync::mpsc::channel();

    app.dialog()
        .file()
        .add_filter("PDF file", &["pdf"])
        .set_directory(&home_dir_path)
        .save_file(move |file_path| {
            tx.send(file_path).unwrap();
        });

    let path = rx.recv().unwrap().ok_or_else(|| "File save canceled".to_string())?;

    let (doc, page1, layer1) = PdfDocument::new("Rusty ARP Report", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);
    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();

    let mut y_position = Mm(297.0 - 20.0);

    for (index, entry) in report_data.iter().enumerate() {
        if index != 0 {
            y_position -= Mm(10.0);
        }

        let ip_address = entry.get("ip_address").and_then(Value::as_str).unwrap_or("");
        let mac_address = entry.get("mac_address").and_then(Value::as_str).unwrap_or("");
        let header_text = format!("IP Address: {}, MAC Address: {}", ip_address, mac_address);

        current_layer.use_text(header_text, 12.0, Mm(10.0), y_position, &font);
        y_position -= Mm(5.0);

        if let Some(ports) = entry.get("open_ports").and_then(Value::as_array) {
            for port in ports {
                let port_str = format!("• {}", port);
                y_position -= Mm(5.0);
                current_layer.use_text(port_str, 10.0, Mm(15.0), y_position, &font);
            }
        }
    }

    let mut file = File::create(&path).map_err(|e| e.to_string())?;
    doc.save(&mut BufWriter::new(&mut file)).map_err(|e| e.to_string())?;

    if cfg!(target_os = "linux") {
        let user_uid = Uid::from_raw(user_uid);
        let user_gid = Gid::from_raw(user_gid);

        chown(&path, Some(user_uid), Some(user_gid))
            .map_err(|e| format!("Failed to change file owner: {}", e))?;
    }

    Ok(())
}


#[tauri::command]
async fn arp_scan(
    app: AppHandle,
    interface_name: String,
    source_ip: String,
    subnet: String,
) -> Result<String, String> {
    info!("Starting ARP scan with interface: {}, source IP: {}, subnet: {}", interface_name, source_ip, subnet);
    
    let result = if env::var("USE_MOCK_DATA").is_ok() {
        info!("Using mock data for ARP scan");
        json!([
            {"ip_address": "192.168.1.1", "mac_address": "00:11:22:33:44:55"},
            {"ip_address": "192.168.1.2", "mac_address": "AA:BB:CC:DD:EE:FF"}
        ]).to_string()
    } else {
        match arp_scanner::arp_scan(app.clone(), interface_name, source_ip, subnet) {
            Ok(scan_result) => scan_result,
            Err(e) => {
                error!("ARP scan error: {}", e);
                "[]".to_string() // Return empty array instead of null
            }
        }
    };

    debug!("ARP scan result: {}", result);
    app.emit("debug", format!("ARP scan result: {}", result))
        .map_err(|e| format!("Failed to emit debug event: {}", e))?;
    
    Ok(result)
}

#[tauri::command]
fn get_network_interfaces() -> Result<Vec<String>, String> {
    if env::var("USE_MOCK_DATA").is_ok() {
        info!("Using mock data for network interfaces");
        Ok(vec!["eth0".to_string(), "wlan0".to_string()])
    } else {
        let interfaces = arp_scanner::get_interface_names();
        debug!("Retrieved network interfaces: {:?}", interfaces);
        Ok(interfaces)
    }
}

#[tauri::command]
async fn scan_ports_for_ip(
    app: tauri::AppHandle,
    ip_address: String,
    scan_common: bool,
) -> Result<Vec<u16>, String> {
    info!("Starting port scan for IP: {}, scan common: {}", ip_address, scan_common);

    if env::var("USE_MOCK_DATA").is_ok() {
        info!("Using mock data for port scan");
        let mock_ports = vec![80, 443, 8080];
        let result = json!({
            "ip_address": ip_address,
            "open_ports": mock_ports,
        });
        app.emit("port-scan-result", &result)
            .map_err(|e| format!("Failed to emit port scan result: {}", e))?;
        return Ok(mock_ports);
    }

    let target_ip = ip_address
        .parse::<IpAddr>()
        .map_err(|_| "Invalid IP address format".to_string())?;

    let concurrency = 1000;
    let timeout = Duration::from_secs(5);

    let open_ports = scan_ports(target_ip, scan_common, concurrency, timeout).await;

    let result = json!({
        "ip_address": ip_address,
        "open_ports": open_ports,
    });
    app.emit("port-scan-result", &result)
        .map_err(|e| format!("Failed to emit port scan result: {}", e))?;

    debug!("Port scan result for {}: {:?}", ip_address, open_ports);
    Ok(open_ports)
}


fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
                info!("Opened DevTools in debug mode");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_network_interfaces,
            arp_scan,
            scan_ports_for_ip,
            save_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
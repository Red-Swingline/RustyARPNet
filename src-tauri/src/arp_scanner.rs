extern crate ipnetwork;
extern crate pnet;
extern crate serde_json;

use ipnetwork::Ipv4Network;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
pub(crate) use tauri::{AppHandle, Manager};

fn listen_for_replies(
    app: AppHandle,
    rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    source_ip: Ipv4Addr,
    timeout: Duration,
) {
    let start_time = std::time::Instant::now();

    loop {
        {
            let mut rx_guard = rx.lock().unwrap();
            match rx_guard.next() {
                Ok(packet) => { // Directly handle the packet
                    if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                        if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                                if arp_packet.get_operation() == ArpOperations::Reply
                                    && arp_packet.get_sender_proto_addr() != source_ip
                                {
                                    let result = json!({
                                        "ip_address": arp_packet.get_sender_proto_addr().to_string(),
                                        "mac_address": arp_packet.get_sender_hw_addr().to_string(),
                                    });
                                    if let Err(e) = send_scan_result_to_frontend(&app, result) {
                                        eprintln!("Error sending scan result to frontend: {}", e);
                                    }
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }

        if start_time.elapsed() > timeout {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}



fn send_scan_result_to_frontend(app: &AppHandle, result: serde_json::Value) -> Result<(), String> {
    app.emit_all("arp-scan-result", &result)
        .map_err(|e| e.to_string())
}
pub fn arp_scan(app: AppHandle, interface_name: String, source_ip: String, subnet: String) -> Result<String, String> {
    let source_ip = source_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid source IP address format".to_string())?;
    let subnet = subnet
        .parse::<Ipv4Network>()
        .map_err(|_| "Invalid subnet CIDR format".to_string())?;

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or("Failed to find interface".to_string())?;

    let source_mac = interface.mac.ok_or("No MAC address found for interface".to_string())?;

    let (mut tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".to_string()),
        Err(e) => return Err(e.to_string()),
    };

    let rx = Arc::new(Mutex::new(rx));

    let rx_clone = Arc::clone(&rx);
    let listener_handle = thread::spawn(move || {
        let timeout = Duration::from_secs(3);
        listen_for_replies(app,rx_clone, source_ip, timeout)
    });

    for ip in subnet.iter() {
        let target_ip = ip;

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination([0xff, 0xff, 0xff, 0xff, 0xff, 0xff].into());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr([0, 0, 0, 0, 0, 0].into());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        let packet_data = ethernet_packet.packet();
        if let Some(Err(e)) = tx.send_to(packet_data, Some(interface.clone())) {
            eprintln!("Failed to send ARP request: {}", e);
        }
    }

    let results = listener_handle
        .join()
        .expect("Listener thread has panicked");

    Ok(serde_json::to_string(&results).unwrap())
}

pub fn get_interface_names() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|interface| interface.name)
        .collect()
}

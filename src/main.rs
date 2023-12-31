extern crate ipnetwork;
extern crate pnet;

use ipnetwork::Ipv4Network;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::env;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn listen_for_replies(
    rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    source_ip: Ipv4Addr,
    timeout: Duration,
) {
    let start_time = std::time::Instant::now();
    println!("{:<20} {:<20}", "IP Address", "MAC Address");
    println!("{:-<42}", ""); // Print a dividing line

    loop {
        let mut rx_lock = rx.lock().unwrap();
        if let Ok(packet) = rx_lock.next() {
            if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                        if arp_packet.get_operation() == ArpOperations::Reply
                            && arp_packet.get_sender_proto_addr() != source_ip
                        {
                            println!(
                                "{:<20} {:<20}",
                                arp_packet.get_sender_proto_addr().to_string(),
                                arp_packet.get_sender_hw_addr().to_string()
                            );
                        }
                    }
                }
            }
        }

        drop(rx_lock);

        if start_time.elapsed() > timeout {
            break;
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        return Err("Usage: arp_scanner <interface_name> <source_ip> <subnet_cidr>".into());
    }

    let interface_name = &args[1];
    let source_ip = args[2]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid source IP address format")?;
    let subnet = args[3]
        .parse::<Ipv4Network>()
        .map_err(|_| "Invalid subnet CIDR format")?;

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .ok_or("Failed to find interface")?;

    let source_mac = interface.mac.ok_or("No MAC address found for interface")?;

    let (mut tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".into()),
        Err(e) => return Err(e.into()),
    };

    let rx = Arc::new(Mutex::new(rx));

    // Spawn a thread to listen for replies
    let rx_clone = Arc::clone(&rx);
    let listener_handle = thread::spawn(move || {
        let timeout = Duration::from_secs(15);
        listen_for_replies(rx_clone, source_ip, timeout);
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

    // Wait for the listener thread to complete
    listener_handle
        .join()
        .expect("Listener thread has panicked");

    Ok(())
}

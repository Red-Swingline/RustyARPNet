# ARP Scanner

ARP Scanner is a simple Rust application that scans a specified subnet for devices and retrieves their IP and MAC addresses using ARP requests. It utilizes the pnet and ipnetwork crates for networking functionality.

## Usage

To run the ARP Scanner, you need to provide three command-line arguments:

1. `interface_name`: The name of the network interface you want to use for scanning.
2. `source_ip`: The source IP address from which ARP requests will be sent.
3. `subnet_cidr`: The CIDR notation of the subnet you want to scan.

Here is an example of how to run the application:

```bash
$ sudo ./arp <interface_name> <source_ip> <subnet_cidr>
```

### Example

```bash
$ sudo ./arp eth0 192.168.1.10 192.168.1.0/24
```

## Output

The ARP Scanner will send ARP requests to all IP addresses within the specified subnet and display the responses in the following format:

```
IP Address         MAC Address
------------------------------------------
192.168.1.1        00:11:22:33:44:55
192.168.1.2        00:aa:bb:cc:dd:ee
...
```

## Dependencies

This application depends on the following Rust crates:

- `pnet`: Provides low-level networking capabilities.
- `ipnetwork`: Allows parsing and working with CIDR notation for subnets.


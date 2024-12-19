from scapy.all import conf

# List interfaces with detailed information
print("Available interfaces:")
for iface_name, iface_data in conf.ifaces.items():
    print(f"Name: {iface_name}")
    print(f"    Description: {iface_data.description}")
    print(f"    MAC: {iface_data.mac}")
    print(f"    IP: {iface_data.ip}")
    print()

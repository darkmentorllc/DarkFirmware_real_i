#!/usr/bin/env python3
# Variant of RTL8761B_usbbluetooth_Patch_Writer.py that:
#   1. ALWAYS uses rtl8761b_config_set_bdaddr_only_1337.bin regardless of
#      the dongle's USB VID:PID. The original picks 1337 only for
#      0bda:a728 (ZEXMTE) and falls through to 1338 for everything else
#      including 2550:8761, 0bda:a729, 2c0a:8761, 2357:0604.
#   2. Optionally targets a specific dongle by USB serial number (--serial)
#      so that multi-dongle hosts can pick which Realtek to flash with the
#      LMP-capable custom firmware (other Realtek dongles stay stock).
#   3. Optionally targets a specific dongle by USB sysfs id (--usb-sysfs-id,
#      e.g. "1-1.3"), which is more stable than serial in some setups.
#
# Used by central_app_launcher.py's cycle_realtek_adapter() after each PPPS
# power cycle, since the patches are RAM-only and need re-flashing on every
# fresh power-up. See DarkFirmware_real_i/04_custom_patch_writer/README.md
# for the underlying mechanism.
#
# Build/run: same prerequisites as RTL8761B_usbbluetooth_Patch_Writer.py —
#   pip install scapy-usbbluetooth==0.1.0 usbbluetooth==0.1.3
#
# By Xeno Kovah, Copyright 2025 Dark Mentor LLC - https://darkmentor.com
# 1337-only variant: copyright same, derived from upstream Patch_Writer.

import argparse
import os
import sys

import usbbluetooth
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, XLEIntField, XStrLenField
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Event_Command_Complete
from scapy.layers.bluetooth import HCI_Cmd_Reset, HCI_Cmd_Read_Local_Version_Information

# Resolve files relative to this script's directory so it works regardless of CWD.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_FW_BIN_PATH = os.path.join(_SCRIPT_DIR, "rtl8761bu_fw.bin")
_CONFIG_1337_PATH = os.path.join(_SCRIPT_DIR, "rtl8761b_config_set_bdaddr_only_1337.bin")


class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    name = "Realtek Read Memory"
    fields_desc = [
        ByteField("size", 0x20),
        XLEIntField("address", 0x80000000)
    ]

class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    name = "Realtek Write Memory"
    fields_desc = [
        ByteField("size", 0x20),
        XLEIntField("address", 0x80000000),
        XLEIntField("data_to_write", 0x33221100)
    ]

class HCI_Cmd_VSC_Realtek_Download_Patch(Packet):
    name = "Realtek Download Patch"
    fields_desc = [
        ByteField("index", 0x00),
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    name = 'Realtek Read Memory complete'
    fields_desc = [
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Write_Mem(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [
        XStrLenField("data", 0, length_from=lambda pkt: pkt.underlayer.underlayer.len)
    ]

class HCI_Cmd_Complete_VSC_Realtek_Download_Patch(Packet):
    name = 'Realtek Write Memory complete'
    fields_desc = [
        ByteField("index", 0x00),
    ]

bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Download_Patch, ogf=0x3f, ocf=0x0020)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3f, ocf=0x0061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3f, ocf=0x0062)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Download_Patch, opcode=0xfc20)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem, opcode=0xfc61)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Write_Mem, opcode=0xfc62)


_KNOWN_REALTEK_VID_PIDS = {
    (0x0bda, 0xa728),  # ZEXMTE
    (0x0bda, 0xa729),
    (0x2c0a, 0x8761),
    (0x2550, 0x8761),
    (0x2357, 0x0604),
}


def find_realtek_device(serial=None, sysfs_id=None):
    """Return the first usbbluetooth controller that matches the filters.

    Filter precedence: --serial > --usb-sysfs-id > VID:PID match against the
    set of Realtek dongles we know how to patch.

    Multi-dongle hosts: pass --serial (most precise, survives renumbering)
    or --usb-sysfs-id (stable as long as cabling doesn't change). With no
    filter the first Realtek match wins, which is fine for single-dongle
    hosts but ambiguous on multi-dongle ones.
    """
    controllers = usbbluetooth.list_controllers()
    for c in controllers:
        if (c.vendor_id, c.product_id) not in _KNOWN_REALTEK_VID_PIDS:
            continue
        if serial is not None:
            c_serial = getattr(c, "serial_number", None)
            if c_serial != serial:
                continue
        if sysfs_id is not None:
            # The usbbluetooth Controller exposes attributes that vary by
            # version; try a few common sysfs-id-ish attribute names.
            c_sysfs = getattr(c, "sysfs_path", None) or getattr(c, "sysfs_id", None) or getattr(c, "port_numbers", None)
            if c_sysfs is None or sysfs_id not in str(c_sysfs):
                continue
        return c
    return None


def reset(socket):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
    response = socket.sr1(pkt, verbose=0)
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return False
    return True


def read(socket, address=0x80000000):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=address)
    response = socket.sr1(pkt, verbose=0)
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    return response.data


def write(socket, address=0x80000000, data=0x33221100):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Write_Mem(address=address, data_to_write=data)
    response = socket.sr1(pkt, verbose=0)
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None


g_patch_data = None
g_patch_start = None
g_patch_end = None
g_patch_version = None
def read_patch_file(selection_index=1):
    global g_patch_data
    global g_patch_start
    global g_patch_end
    global g_patch_version
    try:
        with open(_FW_BIN_PATH, "rb") as f:
            g_patch_data = bytearray(f.read())
    except FileNotFoundError:
        print(f"Patch file not found: {_FW_BIN_PATH}")
        sys.exit(1)

    g_patch_version = g_patch_data[8:12]
    print(f"Patch version: 0x{int.from_bytes(g_patch_version, 'little'):08x}")

    chip_array_len = int.from_bytes(g_patch_data[12:14], 'little')
    print("Number of chip revisions in patch:", chip_array_len)
    chip_ids_begin_index = 14

    chip_ids = []
    for i in range(0, chip_array_len):
        chip_id = int.from_bytes(g_patch_data[chip_ids_begin_index+i*2:chip_ids_begin_index+i*2+2], 'little')
        chip_ids.append(chip_id)

    patch_lenths_begin_index = chip_ids_begin_index + chip_array_len * 2
    patch_lenths = []
    for i in range(0, chip_array_len):
        patch_len = int.from_bytes(g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2], 'little')
        patch_lenths.append(patch_len)

    patch_start_offsets_index = patch_lenths_begin_index + chip_array_len * 2
    patch_start_offsets = []
    for i in range(0, chip_array_len):
        patch_start_offset = int.from_bytes(g_patch_data[patch_start_offsets_index+i*4:patch_start_offsets_index+i*4+4], 'little')
        patch_start_offsets.append(patch_start_offset)

    g_patch_start = patch_start_offsets[selection_index]
    g_patch_end = g_patch_start + patch_lenths[selection_index]
    print(f"Selected patch start: 0x{g_patch_start:08x}, end: 0x{g_patch_end:08x}")


def write_patch_file(selection_index=1, updated_patch_chunk=None):
    global g_patch_data
    global g_patch_start
    global g_patch_end
    global g_patch_version

    if updated_patch_chunk is None:
        print("No updated patch chunk provided to write_patch_file()!")
        return

    chip_array_len = int.from_bytes(g_patch_data[12:14], 'little')
    chip_ids_begin_index = 14

    chip_ids = []
    for i in range(0, chip_array_len):
        chip_id = int.from_bytes(g_patch_data[chip_ids_begin_index+i*2:chip_ids_begin_index+i*2+2], 'little')
        chip_ids.append(chip_id)

    patch_lenths_begin_index = chip_ids_begin_index + chip_array_len * 2
    patch_lenths = []
    for i in range(0, chip_array_len):
        patch_len = int.from_bytes(g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2], 'little')
        if i == selection_index:
            new_patch_len = len(updated_patch_chunk)
            g_patch_data[patch_lenths_begin_index+i*2:patch_lenths_begin_index+i*2+2] = new_patch_len.to_bytes(2, 'little')
        patch_lenths.append(patch_len)

    patch_start_offsets_index = patch_lenths_begin_index + chip_array_len * 2
    patch_start_offsets = []
    for i in range(0, chip_array_len):
        patch_start_offset = int.from_bytes(g_patch_data[patch_start_offsets_index+i*4:patch_start_offsets_index+i*4+4], 'little')
        patch_start_offsets.append(patch_start_offset)

    g_patch_start = patch_start_offsets[selection_index]
    g_patch_end = g_patch_start + patch_lenths[selection_index]


g_config_data = None
def read_config_file(filename):
    global g_config_data
    try:
        with open(filename, "rb") as f:
            g_config_data = f.read()
    except FileNotFoundError:
        print(f"Config file not found: {filename}")
        sys.exit(2)


def download_patches(socket):
    patch_data_from_file = bytearray(g_patch_data[g_patch_start:g_patch_end])
    patch_data_from_file[-4:] = g_patch_version

    data_before_poc_len = len(patch_data_from_file) + len(g_config_data)
    if (data_before_poc_len % 4) != 0:
        alignment_padding_bytes = bytearray([0x41 * (4 - (data_before_poc_len % 4))])
    else:
        alignment_padding_bytes = bytearray()
    final_full_data = bytearray(patch_data_from_file + g_config_data + alignment_padding_bytes + g_poc_buf)
    final_offset_len = data_before_poc_len + len(alignment_padding_bytes)

    patch_buf_offset = 0x4306 + 2
    patch_buf_insert_size = 0x08
    poc_mem_address = list((0x8010a001 + final_offset_len).to_bytes(4, 'little'))
    print("POC Start Address = 0x" + ''.join("%02x" % b for b in reversed(poc_mem_address)))
    final_full_data[patch_buf_offset:patch_buf_offset+patch_buf_insert_size] = bytearray([
        0x01, 0xb3,
        0x80, 0xeb,
    ] + poc_mem_address)
    final_full_data = bytes(final_full_data)
    write_patch_file(selection_index=1, updated_patch_chunk=final_full_data)

    offset = 0
    frag_index = 0
    done = False
    while not done:
        length = min(len(final_full_data) - offset, 252)
        frag_data = final_full_data[offset:offset+length]

        if (offset + length) == len(final_full_data):
            frag_index |= 0x80
            done = True

        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Download_Patch(index=frag_index, data=frag_data)
        response = socket.sr1(pkt, verbose=0)
        if HCI_Event_Command_Complete not in response or response[HCI_Event_Command_Complete].status != 0 or HCI_Cmd_Complete_VSC_Realtek_Download_Patch not in response:
            return None
        else:
            print(f"Success for patch fragment {frag_index & 0x7F} at offset 0x{offset:04x} with length 0x{length:02x}")

        frag_index += 1
        offset += length

    return True


def read_local_version_info(socket):
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Read_Local_Version_Information()
    response = socket.sr1(pkt, verbose=0)
    if not HCI_Event_Command_Complete in response or response[HCI_Event_Command_Complete].status != 0:
        return None
    else:
        print(f"HCI Version: 0x{response.hci_version:02x}")
        print(f"HCI Revision: 0x{response.hci_subversion:02x}")
        print(f"LMP Version: 0x{response.lmp_version:02x}")
        print(f"Manufacturer: 0x{response.company_identifier:02x}")
        print(f"LMP Subversion: 0x{response.lmp_subversion:02x}")


# See poc2.asm in the parent repo for instructions on how to extract the byte strings.
g_poc_buf = bytearray([0x5b,0xb3,0x80,0x9b,0x5c,0xb2,0x80,0xda,0x20,0xf0,0x01,0x0a,0x40,0xdb,0x00,0x65,0x58,0xb3,0x80,0x9b,0x59,0xb2,0x80,0xda,0x80,0xf0,0x19,0x0a,0x40,0xdb,0x09,0x97,0x08,0x91,0x07,0x90,0x00,0xef,0x05,0x63,0xfc,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0x62,0x00,0x65,0x60,0xac,0x3f,0xf6,0x02,0x73,0x00,0x65,0x2f,0x61,0xfc,0x63,0x01,0xd4,0x02,0xd5,0x03,0xd6,0x04,0xd7,0x05,0xd2,0x06,0xd3,0xc2,0xa4,0xa4,0x67,0x03,0x4d,0x00,0x65,0x4e,0x0c,0x00,0x65,0x49,0xb2,0x40,0xea,0x00,0x65,0x01,0x94,0xc2,0xa4,0xff,0x6c,0x4a,0x0d,0x00,0x65,0x4e,0xb2,0x40,0xea,0x00,0x65,0x00,0x6c,0x47,0x0d,0x0a,0x6e,0x03,0x6f,0x00,0x65,0xfd,0x63,0x64,0x6a,0x04,0xd2,0x00,0x6a,0x05,0xd2,0x00,0x65,0x41,0xb2,0x40,0xea,0x00,0x65,0x00,0x65,0x03,0x63,0x01,0x94,0x02,0x95,0x03,0x96,0x04,0x97,0x05,0x92,0x06,0x93,0x04,0x63,0x03,0x95,0xfd,0x65,0x02,0x96,0x01,0x95,0x00,0x94,0x04,0x63,0x33,0xb3,0x60,0x9b,0x80,0xeb,0x00,0x65,0xfc,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd0,0x04,0xd1,0x05,0x62,0xfe,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd2,0x38,0x6e,0xcc,0x6d,0x36,0x0c,0x00,0x65,0x2c,0xb2,0x40,0xea,0x00,0x65,0x03,0x92,0x02,0x96,0x01,0x95,0x00,0x94,0x02,0x63,0x31,0x0a,0x00,0x65,0x3e,0xb3,0x60,0xda,0x81,0xda,0x60,0x9c,0x62,0xda,0x61,0x9c,0x63,0xda,0x64,0x8c,0x68,0xca,0x00,0x65,0x3a,0xb3,0x65,0xda,0x04,0x67,0x00,0x65,0x68,0x8a,0x80,0xf4,0x00,0x73,0x00,0x65,0x13,0x61,0x00,0x65,0x82,0x9a,0x60,0x9c,0x66,0xda,0x61,0x9c,0x67,0xda,0x62,0x9c,0x68,0xda,0x63,0x9c,0x69,0xda,0x64,0x9c,0x6a,0xda,0x65,0x9c,0x6b,0xda,0x66,0x9c,0x6c,0xda,0x00,0x65,0x2e,0xb3,0x6d,0xda,0xfe,0x63,0x00,0xd4,0x01,0xd5,0x02,0xd6,0x03,0xd2,0xff,0x6c,0x1a,0x0d,0x38,0x6e,0x18,0xb2,0x40,0xea,0x00,0x65,0x03,0x92,0x02,0x96,0x01,0x95,0x00,0x94,0x02,0x63,0x90,0x67,0x05,0x91,0xf9,0x65,0x00,0x94,0x01,0x95,0x02,0x96,0x03,0x90,0x04,0x91,0x04,0x63,0x00,0x65,0x05,0xb3,0x60,0x9b,0x80,0xeb,0x00,0x65,0x10,0x0f,0x12,0x80,0xd4,0xae,0x12,0x80,0xfc,0x3f,0x13,0x80,0xf8,0x3f,0x13,0x80,0x5d,0xe8,0x00,0x80,0x8d,0xe9,0x00,0x80,0x80,0x04,0x00,0x00,0xe5,0x11,0x06,0x80,0x27,0x00,0xde,0xad,0xbe,0xef,0xca,0xfe,0x13,0x37,0xde,0xad,0xbe,0xef,0xca,0xfe,0x13,0x37,0x00,0x65,0x71,0xd0,0x01,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41,0x41,0x41,0x41,0x42,0x42,0x42,0x42,0x43,0x43,0x43,0x43,
0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58,0x58])


def main():
    parser = argparse.ArgumentParser(description="Patch a Realtek BT dongle with DarkFirmware_real_i + the 1337 BD-addr config (regardless of dongle VID:PID).")
    parser.add_argument("--serial", help="Match dongle by USB serial number (most precise; survives renumbering).")
    parser.add_argument("--usb-sysfs-id", help="Match dongle by USB sysfs path containing this id (e.g. '1-1.3').")
    args = parser.parse_args()

    print("[+] Locating a Realtek device...")
    controller = find_realtek_device(serial=args.serial, sysfs_id=args.usb_sysfs_id)
    if controller is None:
        print("[!] No matching Realtek device. Filters: serial=%r sysfs_id=%r" % (args.serial, args.usb_sysfs_id))
        return 1

    print(f"[+] Selected dongle: VID:PID = {controller.vendor_id:04x}:{controller.product_id:04x}")
    print("[+] Opening socket...")
    socket = UsbBluetoothSocket(controller)

    print("[+] Resetting the controller...")
    if not reset(socket):
        print("[!] Could not reset the device!")

    dst_write_addr = 0x80120494
    data = read(socket, dst_write_addr)
    data_int = int.from_bytes(data, 'little') if data is not None else None
    print(f"Address that should be our hook1 fptr: 0x{data_int:08x}")

    read_local_version_info(socket)
    read_patch_file()
    # 1337-only variant: always use the 1337 config regardless of VID:PID.
    read_config_file(filename=_CONFIG_1337_PATH)
    download_patches(socket)
    read_local_version_info(socket)

    # Confirm code execution
    ok = True
    for dst_write_addr, expected in [(0x80133FFC, 0x8010d891), (0x80133FF8, 0x8010DFB1)]:
        data = read(socket, dst_write_addr)
        data_int = int.from_bytes(data, 'little') if data is not None else None
        if data is None:
            print("[-] Read failed at confirmation step.")
            ok = False
            continue
        if data_int != expected:
            print(f"[-] Code execution unconfirmed at 0x{dst_write_addr:08x}: got 0x{data_int:08x}, expected 0x{expected:08x}")
            ok = False
        else:
            print(f"[+] Code execution confirmed at 0x{dst_write_addr:08x} (= 0x{expected:08x})")

    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())

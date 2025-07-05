import frida
import socket
import subprocess
import sys
import time
import os

# -------- CONFIG --------
APP_PACKAGE = "com.example"  # package name of application
FRIDA_PORT = 27042
CHUNK_SIZE = 16 * 1024 * 1024
OUTPUT_FILE = f"./{APP_PACKAGE.replace('.', '_')}_full_memory_dump.bin"
# ------------------------

def check_adb_device_connected():
    result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, text=True)
    devices = [line.split()[0] for line in result.stdout.strip().splitlines()[1:] if "device" in line]
    if not devices:
        print("[!] No ADB devices connected.")
        sys.exit(1)
    print(f"[+] ADB device connected: {devices[0]}")

def setup_frida_port_forward():
    subprocess.run(["adb", "forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"])

def is_frida_running(host="127.0.0.1", port=FRIDA_PORT, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def dump_all_memory(session):
    script = session.create_script("""
        rpc.exports = {
            ranges: function() {
                return Process.enumerateRanges({ protection: 'r--', coalesce: true });
            },
            safeRead: function(addr, size) {
                try {
                    Memory.readU8(ptr(addr));  // test read
                    return Memory.readByteArray(ptr(addr), size);
                } catch (e) {
                    throw new Error("ACCESS_VIOLATION");
                }
            }
        };
    """)
    script.load()
    api = script.exports

    ranges = api.ranges()
    print(f"[+] Found {len(ranges)} readable regions.")

    with open(OUTPUT_FILE, "wb") as f:
        for i, region in enumerate(ranges):
            base = int(region['base'], 16)
            size = int(region['size'])

            print(f"  → Reading region {i}: 0x{base:x} ({size} bytes)")

            offset = 0
            while offset < size:
                read_size = min(CHUNK_SIZE, size - offset)
                try:
                    chunk = api.safe_read(base + offset, read_size)
                    if chunk:
                        f.write(bytes(chunk))
                except frida.core.RPCException as e:
                    if "ACCESS_VIOLATION" in str(e):
                        print(f"[!] Skipping unreadable region at 0x{base + offset:x}")
                        break
                    else:
                        print(f"[!] Frida RPC Error at 0x{base + offset:x}: {e}")
                        break
                except Exception as e:
                    print(f"[!] Unknown Error: {e}")
                    break
                offset += read_size

    print(f"[✓] Full memory dump saved as: {OUTPUT_FILE}")

def main():
    check_adb_device_connected()
    setup_frida_port_forward()

    if not is_frida_running():
        print("[!] Frida server not detected on device.")
        print("💡 Run this on device: /data/local/tmp/frida-server &")
        sys.exit(1)

    try:
        device = frida.get_remote_device()
        print(f"[+] Connected to Frida device: {device.name}")

        pid = device.spawn([APP_PACKAGE])
        session = device.attach(pid)
        device.resume(pid)
        time.sleep(2)

        dump_all_memory(session)
        session.detach()

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

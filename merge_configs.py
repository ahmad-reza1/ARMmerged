import json
import base64
import re
from urllib.parse import urlparse, parse_qs

INPUT_FILE = "links.txt"         
OUTPUT_CONFIG = "merged_config.json"

def parse_vless(link):
    if not link.startswith("vless://"):
        return None
    without_proto = link[8:]
    at_index = without_proto.find('@')
    if at_index == -1:
        return None
    uuid = without_proto[:at_index]
    rest = without_proto[at_index+1:]
    m = re.match(r'([^:]+):(\d+)(\?.*)?', rest)
    if not m:
        return None
    address = m.group(1)
    port = int(m.group(2))
    query_part = m.group(3) or ''
    params = parse_qs(query_part[1:]) 

    encryption = params.get('encryption', ['none'])[0]
    security = params.get('security', [''])[0]
    flow = params.get('flow', [''])[0]
    sni = params.get('sni', [''])[0]
    fingerprint = params.get('fp', ['chrome'])[0]
    network = params.get('type', ['tcp'])[0]
    path = params.get('path', ['/'])[0]
    host = params.get('host', [''])[0]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": encryption,
                    "flow": flow if flow else ""
                }]
            }]
        },
        "streamSettings": {
            "network": network,
            "security": security,
        }
    }
    if security == "tls":
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint
        }
    if network == "tcp":
        pass
    elif network == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "path": path,
            "headers": {"Host": host if host else address}
        }
    elif network == "xhttp":
        outbound["streamSettings"]["xhttpSettings"] = {
            "path": path
        }
    return outbound

def parse_ss(link):
    if not link.startswith("ss://"):
        return None
    content = link[5:]
    at_index = content.find('@')
    if at_index == -1:
        return None
    encoded = content[:at_index]
    rest = content[at_index+1:]
    try:
        missing = len(encoded) % 4
        if missing:
            encoded += '=' * (4 - missing)
        decoded = base64.b64decode(encoded).decode('utf-8')
        # decoded به صورت method:password
        method_pass = decoded.split(':', 1)
        if len(method_pass) != 2:
            return None
        method = method_pass[0]
        password = method_pass[1]
    except:

        return None


    m = re.match(r'([^:]+):(\d+)(\?.*)?', rest)
    if not m:
        return None
    address = m.group(1)
    port = int(m.group(2))
    query_part = m.group(3) or ''
    params = parse_qs(query_part[1:])


    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": address,
                "port": port,
                "method": method,
                "password": password
            }]
        }
    }
    return outbound

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        links = [line.strip() for line in f if line.strip()]

    outbounds = []
    tags = []
    for idx, link in enumerate(links):
        if link.startswith("vless://"):
            ob = parse_vless(link)
            proto = "vless"
        elif link.startswith("ss://"):
            ob = parse_ss(link)
            proto = "ss"
        else:
            print(f"نوع ناشناخته: {link[:50]}...")
            continue
        if ob:
            tag = f"{proto}_node_{idx+1}"
            ob["tag"] = tag
            outbounds.append(ob)
            tags.append(tag)
            print(f"✅ {tag} added")
        else:
            print(f"❌ parse failed: {link[:50]}...")

    if not outbounds:
        print("هیچ outbound سالمی پیدا نشد.")
        return

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "tag": "socks-in"
            },
            {
                "port": 10809,
                "protocol": "http",
                "settings": {},
                "tag": "http-in"
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "balancers": [
                {
                    "tag": "load_balancer",
                    "selector": tags,
                    "strategy": {"type": "roundrobin"}
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "load_balancer"
                }
            ]
        }
    }

    with open(OUTPUT_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    print(f"\n✅ فایل {OUTPUT_CONFIG} با {len(outbounds)} خروجی ساخته شد.")
    print("برای اجرا:")
    print(f"  xray -config {OUTPUT_CONFIG}")
    print("سپس مرورگر یا اپ خود را روی پروکسی SOCKS5 127.0.0.1:10808 تنظیم کنید.")

if __name__ == "__main__":
    main()
import json
import base64
import re
from urllib.parse import parse_qs

INPUT_FILE = "links.txt"
OUTPUT_CONFIG = "merged_config_android.json"

def parse_vless(link):
    # همان تابع قبلی (بدون تغییر)
    ...

def parse_ss(link):
    # همان تابع قبلی
    ...

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
            continue
        if ob:
            tag = f"{proto}_node_{idx+1}"
            ob["tag"] = tag
            outbounds.append(ob)
            tags.append(tag)

    if not outbounds:
        print("هیچ outboundی ساخته نشد.")
        return

    config = {
        "log": {"loglevel": "warning"},
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

    with open(OUTPUT_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"✅ فایل {OUTPUT_CONFIG} ساخته شد. حالا آن را در v2rayNG با 'Import Config from File' وارد کنید.")

if __name__ == "__main__":
    main()
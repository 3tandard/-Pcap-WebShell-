import pyshark
import sys

def extract_http_requests(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http.request")
    
    for packet in cap:
        try:
            http_layer = packet.http
            method = http_layer.get("request_method", "UNKNOWN")
            host = http_layer.get("host", "UNKNOWN")
            uri = http_layer.get("request_uri", "UNKNOWN")
            user_agent = http_layer.get("User-Agent", "UNKNOWN")

            print(f"[{method}] {host}{uri}")
            print(f"User-Agent: {user_agent}\n")
        except AttributeError:
            continue

    cap.close()

# 使用你的 pcapng 文件路径

scriptName = sys.argv[0]
pcap_path = sys.argv[1]
#pcap_path = "/root/liuLiang/weevely/weevely3_4_B.pcapng"
extract_http_requests(pcap_path)


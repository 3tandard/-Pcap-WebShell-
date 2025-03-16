import pyshark
import sys
from scapy.all import rdpcap, TCP, IP
import binascii
import re

# WebShell 关键特征
WEEVELY_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) weevely",
    "Mozilla/5.0 (X11; U; Linux x86_64; es-ES; rv:1.9.2.12) Gecko/20101026 SUSE/3.6.12-0.7.1 Firefox/3.6.12"
]

# WebShell POST 数据特征
WEBSHELL_PATTERNS = [
    "GBMB",
    r"\160\x68\141\x72\72\57\57",  # "phar://"
    "__HALT_COMPILER();",
    "basename(__FILE__).",
    "include",
]

# 存储可疑 POST 请求
suspicious_posts = []

# 解析 HTTP 请求（包括 POST 数据）
def extract_http_requests(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http.request")

    for packet in cap:
        try:
            http_layer = packet.http
            method = http_layer.get("request_method", "UNKNOWN")
            host = http_layer.get("host", "UNKNOWN")
            uri = http_layer.get("request_uri", "UNKNOWN")
            user_agent = http_layer.get("User-Agent", "UNKNOWN")
            post_data = getattr(http_layer, "file_data", None) if method == "POST" else None

            print(f"\n[{method}] {host}{uri}")
            print(f"User-Agent: {user_agent}")

            detected_patterns = []
            decoded_data = ""

            # 如果是 POST 请求，尝试解码十六进制数据并检测 WebShell 特征
            if method == "POST" and post_data:
                # 移除 `:` 和空格，转换十六进制为 ASCII
                hex_data = re.sub(r'[^0-9a-fA-F]', '', post_data)
                try:
                    decoded_data = binascii.unhexlify(hex_data).decode(errors='ignore')
                except binascii.Error:
                    decoded_data = post_data  # 如果无法转换，则原样输出

                # 检测 WebShell 关键特征
                for pattern in WEBSHELL_PATTERNS:
                    if re.search(re.escape(pattern), decoded_data):
                        detected_patterns.append(pattern)

                print(f"POST Data (ASCII): {decoded_data}")

                # 如果检测到 WebShell 相关特征，则存入 suspicious_posts
                if detected_patterns:
                    suspicious_posts.append({
                        "url": f"{host}{uri}",
                        "user_agent": user_agent,
                        "post_data": decoded_data,
                        "matches": detected_patterns
                    })

            # 检测 Weevely WebShell
            if user_agent in WEEVELY_USER_AGENTS:
                print("[⚠] Detected potential Weevely WebShell traffic!")

        except AttributeError:
            continue

    cap.close()


# 解析 TCP 层信息（源 IP、目标 IP、端口）
def analyze_tcp_traffic(pcap_file):
    packets = rdpcap(pcap_file)
    http_requests = {}

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            # 统计 IP+端口 出现次数
            key = f"{ip_src}:{port_src} -> {ip_dst}:{port_dst}"
            http_requests[key] = http_requests.get(key, 0) + 1

    print("\n🔍 TCP 连接统计（HTTP 请求行为）:")
    for key, count in http_requests.items():
        print(f"{key}  - {count} 次请求")


# 打印可疑的 POST 请求
def print_suspicious_posts():
    if suspicious_posts:
        print("\n🚨 可疑的 POST 请求 🚨")
        for i, post in enumerate(suspicious_posts, start=1):
            print(f"\n🔴 [可疑 POST {i}]\nURL: {post['url']}")
            print(f"User-Agent: {post['user_agent']}")
            print(f"POST Data: {post['post_data']}")
            print(f"⚠ 匹配特征: {', '.join(post['matches'])}")


# 主程序
if __name__ == "__main__":
    script_name = sys.argv[0]
    pcap_path = sys.argv[1]

    print("\n📌 分析 HTTP 请求：")
    extract_http_requests(pcap_path)

    #print("\n📌 分析 TCP 连接信息：")
    #analyze_tcp_traffic(pcap_path)

    # 统一输出所有可疑 POST 请求
    print_suspicious_posts()


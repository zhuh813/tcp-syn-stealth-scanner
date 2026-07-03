#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
from scapy.all import IP, TCP, RandShort, sr

def get_safe_filename(hostname):
    clean_name = hostname.replace("https://", "").replace("http://", "").replace("www.", "")
    clean_name = clean_name.split("/")[0]
    domain_prefix = clean_name.split(".")[0]
    return f"{domain_prefix}_result.csv"

def get_service_name(port_num):
    """改用 Python 內建 socket 查詢服務名稱，完美避開 Scapy 版本相容性問題"""
    try:
        return socket.getservbyport(port_num, "tcp")
    except Exception:
        return "unknown"

def interactive_port_scan():
    print("==================================================")
    print("      TCP SYN 隱身掃描與自動分析工具 (1-1024)     ")
    print("==================================================")
    
    while True:
        target_host = input(">> 請輸入要掃描的目標網址或 IP: ").strip()
        if target_host:
            break
        print("[!] 網址不能為空，請重新輸入！")
        
    print(f"\n[*] 正在開始掃描 {target_host}...")
    
    # 建立 1 到 1024 的 Port 範圍
    tport = (1, 1024)
    askTcp = IP(dst=target_host) / TCP(sport=RandShort(), dport=tport, flags="S")
    
    print("[*] 封包全力噴發中，請稍候...")
    # 把 timeout 從 2 秒改回 5 秒，確保網路波動時能抓到所有回應
    ans, unans = sr(askTcp, timeout=5, inter=0, verbose=0)
    print(f"[*] 掃描結束！共收到 {len(ans)} 個回應封包。")
    print("--------------------------------------------------")
    
    print("[+] 線上（OPEN）的通訊埠檢視結果：")
    sa_packets = ans.filter(lambda req, res: res.haslayer(TCP) and res[TCP].flags == "SA")
    
    if len(sa_packets) > 0:
        sa_packets.summary()
    else:
        print("    (無。在 1-1024 範圍內沒有發現任何開啟的 Port)")
    print("--------------------------------------------------")
    
    output_filename = get_safe_filename(target_host)
    
    try:
        with open(output_filename, "w") as f:
            f.write("Target_IP,Target_Port,Service_Name,Response_Flag,Status\n")
            
            for req, res in ans:
                if res.haslayer(TCP):
                    port_num = req.dport
                    flag_status = res[TCP].flags
                    
                    # 呼叫修復後的服務查詢函式
                    service_name = get_service_name(port_num)
                    
                    if flag_status == "SA":
                        status = "OPEN"
                    elif "R" in flag_status:
                        status = "CLOSED"
                    else:
                        status = "FILTERED"
                        
                    f.write(f"{req.dst},{port_num},{service_name},{str(flag_status)},{status}\n")
                    
        print(f"[✔] 備份完畢！已將「全部的掃描結果（包含 RA & SA）」儲存。")
        print(f"[✔] 輸出 CSV 檔案路徑: {os.path.abspath(output_filename)}")
        
    except Exception as e:
        print(f"[-] 儲存 CSV 檔案時發生錯誤: {e}")
        
    print("==================================================")

if __name__ == "__main__":
    interactive_port_scan()

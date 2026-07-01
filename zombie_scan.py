#!/usr/bin/env python3
import time
from scapy.all import IP, TCP, sr1, send

# ==================== 設定參數 ====================
DETECTOR_IP = "192.168.132.X"  # 你的 Kali IP (Scapy 會自動處理，維持不填即可)
ZOMBIE_IP   = "192.168.132.143"  # 調整為 WXP 的實際 IP
TARGET_IP   = "192.168.132.133"  # 調整為 SS 的實際 IP
TARGET_PORT = 22                # 調整為要刺探的 SSH 服務連接埠
ZOMBIE_PORT = 777               # 用來探測 Zombie 的閒置 Port
# ==================================================

print(f"[*] 開始對目標 {TARGET_IP}:{TARGET_PORT} 進行殭屍掃描 (使用 Zombie: {ZOMBIE_IP})...")

# --------------------------------------------------
# 步驟 1: 第一階段探測 - 獲取 Zombie 的初始 IPID
# --------------------------------------------------
# 向 Zombie 發送 SYN/ACK (SA)，誘騙其回應 RST
probe1 = IP(dst=ZOMBIE_IP)/TCP(dport=ZOMBIE_PORT, flags="SA")
ans1 = sr1(probe1, timeout=2, verbose=0)

if not ans1:
    print("[-] 錯誤：無法從 Zombie 獲取初始回應，請確認 Zombie 是否存活且為 Idle 狀態。")
    exit(1)

initial_ipid = ans1[IP].id
print(f"[+] 步驟 1 完成 -> Zombie 初始 IPID = {initial_ipid}")


# --------------------------------------------------
# 步驟 2: 第二階段掃描 - 假冒 Zombie 身份向 Target 發送 SYN
# --------------------------------------------------
print(f"[*] 步驟 2 -> 正在偽造 Zombie 身份向 Target 發送 SYN...")
# 核心關鍵：src 改成 ZOMBIE_IP (IP Spoofing)
spoofed_packet = IP(src=ZOMBIE_IP, dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="S")
send(spoofed_packet, verbose=0)

# 微調延遲（給兩台虛擬機一些時間完成封包互動，設 0.05 秒）
time.sleep(0.05)


# --------------------------------------------------
# 步驟 3: 第三階段驗證 - 再次探測 Zombie 獲取最終 IPID
# --------------------------------------------------
print(f"[*] 步驟 3 -> 再次探測 Zombie 以獲取最終 IPID...")
probe2 = IP(dst=ZOMBIE_IP)/TCP(dport=ZOMBIE_PORT, flags="SA")
ans2 = sr1(probe2, timeout=2, verbose=0)

if not ans2:
    print("[-] 錯誤：無法從 Zombie 獲取最終回應。")
    exit(1)

final_ipid = ans2[IP].id
print(f"[+] 步驟 3 完成 -> Zombie 最終 IPID = {final_ipid}")


# --------------------------------------------------
# 步驟 4: 結果判定邏輯
# --------------------------------------------------
delta = final_ipid - initial_ipid
print("\n" + "="*40)
print(f"最終 IPID : {final_ipid}")
print(f"初始 IPID : {initial_ipid}")
print(f"增量      : {delta}")
print("-"*40)

if delta == 2:
    print(f"-> 🎯 結論：目標連接埠 {TARGET_PORT} 是【 OPEN (開啟) 】!")
elif delta == 1:
    print(f"-> 🔒 結論：目標連接埠 {TARGET_PORT} 是【 CLOSE (關閉) 】!")
else:
    print(f"-> ⚠️ 警告：增量為 {delta}，可能受到網路背景流量干擾，結果不可信。")
print("="*40)

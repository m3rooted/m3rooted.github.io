---
title: (Vietnamese) ATBMHTTT CN04 | PTIT-Lab 2.3 The most effective SYN Flood defense measures in 2025
date: 2026-03-04 12:00:00 +0700
categories: [Analysis]
tags: [SYN FLOOD, SYN Cookies, SYN Proxy, Rate Limiting, iptables, nftables]

image:
  path: /assets/img/2026-03-06-PTIT-LAB1/sym1.png

description: "4 biện pháp phòng thủ SYN Flood hiệu quả nhất năm 2025 và những điều bạn cần biết về các biện pháp phòng thủ này"
---

## Overview of the lab

SYN Flood vẫn là một trong những kỹ thuật DDoS lớp vận chuyển (Layer 4) phổ biến vì nó khai thác trực tiếp cơ chế bắt tay TCP 3 bước. Trong cuộc tấn công này, đối tượng tấn công gửi số lượng lớn gói SYN nhưng không hoàn tất phiên bắt tay, làm tiêu hao SYN backlog, bảng trạng thái kết nối hoặc tài nguyên của firewall/load balancer. Cloudflare mô tả SYN flood là dạng “half-open attack” nhằm làm cạn tài nguyên phục vụ kết nối hợp lệ.

Tính đến năm 2025, bốn biện pháp được đánh giá hiệu quả và thực tế nhất trong môi trường sản xuất là:

**SYN Cookies**

**SYN Proxy tại firewall/load balancer**

**Rate Limiting kết hợp Connection Tracking**

**Cloud DDoS Protection như Cloudflare, AWS Shield**

Trong triển khai thực tế, không có biện pháp đơn lẻ nào là tối ưu cho mọi kịch bản. Mô hình được doanh nghiệp áp dụng hiệu quả nhất là phòng thủ nhiều lớp: bảo vệ tại cloud edge, lọc ở firewall, giảm tải bằng rate limit, và bật SYN cookies ở máy chủ như tuyến phòng thủ cuối cùng. AWS cũng mô tả SYN cookies và TCP SYN proxy là các kỹ thuật cốt lõi để chống cạn bảng trạng thái do SYN flood.

## Cơ chế tấn công SYN Flood

Bắt tay TCP bình thường gồm 3 bước:

Client gửi `SYN`

Server trả `SYN-ACK`

Client trả `ACK`

![TCPH](/assets/img/2026-03-06-PTIT-LAB1/sym2.png)

Trong SYN Flood, kẻ tấn công gửi lượng lớn SYN, thường với IP giả mạo hoặc không phản hồi ACK, khiến server giữ nhiều kết nối “half-open”. Khi hàng đợi pending connections đầy, client hợp lệ sẽ bị timeout hoặc từ chối kết nối. AWS mô tả đây là kiểu làm “state table exhaustion”, còn Linux kernel docs cho biết SYN cookies được thiết kế để xử lý chính bài toán này.

## Phân tích 4 biện pháp phòng thủ

![TCPH](/assets/img/2026-03-06-PTIT-LAB1/sym3.png)

### 1) SYN Cookies

SYN Cookies là cơ chế bảo vệ ở mức TCP stack của hệ điều hành nhằm chống lại SYN Flood khi hàng đợi kết nối (SYN backlog) bị quá tải. Thay vì lưu trạng thái cho mỗi kết nối SYN, server mã hóa thông tin kết nối vào sequence number của gói SYN-ACK. Khi client gửi ACK hợp lệ, server mới tạo kết nối thật.

Luồng logic:

```bash
Client  -> SYN -----------------> Server
Client  <- SYN-ACK(cookie) ----- Server
Client  -> ACK -----------------> Server
Server  -> validate cookie -> create established connection
```

Cơ chế này giúp giảm nguy cơ cạn tài nguyên do các kết nối half-open, đồng thời không yêu cầu phần cứng hoặc thiết bị bảo mật bổ sung.

Ví dụ bật SYN Cookies trên Linux

```bash
sysctl -w net.ipv4.tcp_syncookies=1
```

Bật SYN Cookies tạm thời

```bash
sudo sysctl -w net.ipv4.tcp_syncookies=1
```

Bật vĩnh viễn

```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-synflood.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_synack_retries = 3
EOF

sudo sysctl --system
```

**Ưu điểm**

Ngăn đầy SYN backlog
Không cần lưu trạng thái kết nối tạm thời
Có sẵn trên hầu hết hệ điều hành

**Hạn chế**

Một số TCP extension có thể bị hạn chế
Chỉ kích hoạt khi backlog gần đầy

### 2) SYN Proxy (Firewall)

SYN Proxy là kỹ thuật trong firewall hoặc load balancer, trong đó firewall đứng ra thực hiện bắt tay TCP thay server. Chỉ khi client hoàn tất handshake hợp lệ, firewall mới chuyển kết nối đến server thật.

```Bash
Attacker/Client -> SYN ------> Firewall SYN Proxy
Firewall        -> SYN-ACK --> Client
Client          -> ACK ------> Firewall
Firewall validates ACK
Firewall -> opens real TCP connection to backend server
```

Cơ chế này giúp server tránh phải xử lý các SYN giả mạo và giảm tải tài nguyên trong quá trình tấn công.

Ví dụ cấu hình SYN Proxy với nftables

```bash
sudo modprobe nf_synproxy_core
sudo modprobe nft_synproxy
sudo modprobe nf_conntrack

nft add rule inet filter input tcp dport {80,443} synproxy mss 1460 wscale 7 timestamp sack-perm
```

Mẫu cấu hình với iptables SYNPROXY

```Bash
sudo modprobe nf_conntrack
sudo modprobe nf_synproxy_core

sudo iptables -t raw -A PREROUTING -p tcp --syn --dport 80 -j CT --notrack
sudo iptables -A INPUT -p tcp --dport 80 -m state --state INVALID,UNTRACKED \
  -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
sudo iptables -A INPUT -p tcp --dport 80 -m state --state INVALID -j DROP
```

**Ưu điểm**

Bảo vệ server khỏi SYN giả
Giảm tải xử lý handshake cho backend
Hiệu quả trong môi trường doanh nghiệp

**Hạn chế**

Cấu hình phức tạp hơn
Cần điều chỉnh tham số TCP phù hợp

### 3) Rate Limiting + Connection Tracking

Biện pháp này sử dụng firewall để giới hạn số lượng gói SYN hoặc số kết nối từ một IP trong một khoảng thời gian. Mục tiêu là phát hiện và chặn lưu lượng bất thường trước khi gây quá tải hệ thống.

Ví dụ Rate Limiting bằng iptables và nftables

```Bash
# Cho phép tối đa 25 SYN/giây, burst 50 cho HTTP/HTTPS
sudo iptables -A INPUT -p tcp -m multiport --dports 80,443 --syn \
  -m limit --limit 25/second --limit-burst 50 -j ACCEPT

# Log nhẹ trước khi drop
sudo iptables -A INPUT -p tcp -m multiport --dports 80,443 --syn \
  -m limit --limit 5/min -j LOG --log-prefix "SYN-FLOOD-DROP: " --log-level 4

# Drop phần vượt ngưỡng
sudo iptables -A INPUT -p tcp -m multiport --dports 80,443 --syn -j DROP
```

```Bash
sudo nft add table inet ddos

sudo nft 'add chain inet ddos input { type filter hook input priority 0; policy accept; }'

sudo nft add rule inet ddos input tcp dport {80,443} tcp flags syn limit rate 25/second burst 50 packets accept
sudo nft add rule inet ddos input tcp dport {80,443} tcp flags syn counter drop
```

Ví dụ giới hạn số kết nối/IP

```Bash
iptables -A INPUT -p tcp --dport 80 \
-m connlimit --connlimit-above 50 -j REJECT
```

**Ưu điểm**

Dễ triển khai
Hiệu quả với tấn công quy mô nhỏ hoặc trung bình

**Hạn chế**

Có thể chặn nhầm người dùng hợp lệ
Không đủ chống DDoS quy mô lớn

### 4) Cloud DDoS Protection

Cloud DDoS Protection sử dụng các dịch vụ bảo vệ trên nền tảng cloud như Cloudflare, AWS Shield hoặc Google Cloud Armor. Các hệ thống này hoạt động ở biên mạng toàn cầu, hấp thụ và lọc lưu lượng tấn công trước khi đến server thật.

Nhờ sử dụng mạng Anycast và scrubbing center, các dịch vụ này có thể phát hiện và giảm thiểu SYN Flood quy mô lớn.

Mẫu Kiến trúc

```Text
Internet
   |
   v
[Cloud DDoS Protection / CDN / Anycast Edge]
   |
   v
[WAF / Firewall / Load Balancer with SYN Proxy]
   |
   v
[Reverse Proxy / App Servers]
   |
   v
[Linux TCP Stack with SYN Cookies enabled]
```

Kiểm tra Shield qua CLI

```Bash
aws shield describe-subscription
```
Liệt kê các tài nguyên đang được bảo vệ

```Bash
aws shield list-protections
```
**Ưu điểm**

Chống được DDoS lớn
Không cần triển khai hạ tầng phức tạp
Có hệ thống giám sát và phân tích

**Hạn chế**

Chi phí dịch vụ
Phụ thuộc nhà cung cấp

## 4. So sánh tổng hợp

| Biện pháp                     | Vị trí triển khai  | Cơ chế chính                       | Mức hiệu quả   | Chi phí            | Ghi chú                          |
|-------------------------------|--------------------|------------------------------------|----------------|--------------------|---------------------------------|
| SYN Cookies                   | OS/TCP stack       | Không giữ state tạm cho SYN mới    | Cao            | Thấp               | Nên bật mặc định trên server     |
| SYN Proxy                     | Firewall/LB        | Bắt tay TCP thay backend           | Rất cao        | Trung bình-cao     | Rất tốt cho dịch vụ công khai    |
| Rate Limiting + Conn Tracking | Firewall host/edge | Giới hạn SYN, số kết nối/IP        | Trung bình-cao | Thấp               | Cần tuning tránh false positive  |
| Cloud DDoS Protection         | Edge/Cloud         | Anycast, scrubbing, TCP protection | Rất cao        | Trung bình-rất cao | Chống được volumetric attack lớn |

### Kết luận

Bốn biện pháp phòng thủ SYN Flood hiệu quả nhất năm 2025 gồm SYN Cookies, SYN Proxy, Rate Limiting + Connection Tracking, và Cloud DDoS Protection. Trong đó:

SYN Cookies là lớp bảo vệ nhẹ, rẻ, nên bật ở mọi server public
SYN Proxy đặc biệt hiệu quả khi muốn bảo vệ backend khỏi handshake giả
Rate Limiting + Conn Tracking giúp giảm tải và chặn hành vi bất thường ở lớp host/firewall
Cloud DDoS Protection là giải pháp mạnh nhất khi đối mặt với tấn công quy mô lớn

Giải pháp tốt nhất không phải là chọn một kỹ thuật riêng lẻ, mà là kết hợp cả bốn theo kiến trúc nhiều lớp. Đây là mô hình có hiệu quả vận hành, khả năng mở rộng và sức chịu đựng cao nhất trước SYN flood hiện đại 
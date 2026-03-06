---
title: (Vietnamese) ATBMHTTT CN04 | PTIT-Lab 2.1 TCP 3-way Handshake, SYN Flood
date: 2026-03-03 23:59:00 +0700
categories: [Analysis]
tags: [SYN FLOOD, TCP 3-way Handshake]

image:
  path: /assets/img/2026-03-06-PTIT-LAB1/tcp1.png

description: "Bài này trình bày cơ chế thiết lập kết nối của giao thức TCP thông qua TCP three-way handshake gồm ba bước: SYN, SYN-ACK và ACK. Đồng thời phân tích cách tấn công SYN Flood khai thác điểm yếu của quá trình handshake bằng cách gửi nhiều gói SYN nhưng không hoàn tất kết nối. Điều này làm server giữ nhiều kết nối half-open và có thể làm đầy backlog queue. Cuối cùng, bài toán tính toán thời gian để queue bị đầy khi server bị tấn công với tốc độ SYN cao"
---

## Sơ đồ TCP 3-way Handshake

![Check](/assets/img/2026-03-06-PTIT-LAB1/tcp2.png)

## Giải thích chi tiết TCP 3-way Handshake

![Check](/assets/img/2026-03-06-PTIT-LAB1/tcp3.png)

TCP 3-way handshake là quá trình thiết lập kết nối giữa client và server trước khi truyền dữ liệu.

Bước 1: SYN

Client gửi gói SYN đến server để yêu cầu tạo kết nối.
Gói này cho biết client muốn bắt đầu một phiên TCP và đồng bộ số thứ tự ban đầu.

Bước 2: SYN-ACK

Khi nhận được SYN, server phản hồi bằng gói SYN-ACK.
Gói này có 2 ý nghĩa:
`SYN`: server đồng ý tạo kết nối
`ACK`: xác nhận đã nhận được yêu cầu từ client
Lúc này, server sẽ giữ một kết nối ở trạng thái half-open trong backlog queue và chờ client phản hồi tiếp.

Bước 3: ACK

Client gửi lại gói ACK để xác nhận đã nhận được SYN-ACK từ server.
Sau bước này, kết nối TCP được thiết lập hoàn chỉnh và hai bên có thể trao đổi dữ liệu.

## SYN Flood khai thác điểm yếu nào của handshake

![Check](/assets/img/2026-03-06-PTIT-LAB1/tcp4.png)

Điểm yếu mà SYN Flood khai thác là:

- Trong bước 2, server phải giữ trạng thái kết nối tạm thời sau khi gửi SYN-ACK
- Server phải dành bộ nhớ và 1 slot trong backlog queue cho mỗi yêu cầu kết nối chưa hoàn tất
- Nếu client không gửi ACK cuối cùng, các kết nối này sẽ tồn tại đến khi timeout

Kẻ tấn công lợi dụng điều này bằng cách:

- Gửi rất nhiều gói SYN
- Dùng IP giả mạo (spoofed IP)
- Không hoàn tất bước ACK

Kết quả là server bị đầy hàng đợi half-open connections, làm người dùng hợp lệ không thể kết nối.

## Minh họa cơ chế SYN Flood

![Check](/assets/img/2026-03-06-PTIT-LAB1/tcp5.png)

## Tính toán thời gian queue đầy

### Dự kiện đề bài

- Backlog queue = 1024 kết nối half-open
- Mỗi SYN packet chiếm 1 slot
- Timeout = 60 giây
- Attacker gửi 2000 SYN packet/giây

### Thời gian để queue đầy

Vì mỗi giây attacker gửi 2000 SYN, mà queue chỉ chứa được 1024 slot:

$$
t = \frac{1024}{2000} = 0.512 \text{ giây}
$$

### Kết luận

Queue sẽ đầy sau khoảng:

$$
0.512 \text{ giây} \approx 0.51 \text{ giây}
$$

Tức là chỉ sau khoảng nửa giây, backlog queue đã bị lấp đầy.

## Server sẽ phản ứng thế nào

Khi queue bị đầy, server sẽ gặp các hiện tượng sau:

**Thứ nhất**: không nhận thêm kết nối mới hợp lệ

Các client thật gửi SYN đến sẽ không còn slot trống trong backlog queue, nên:

- bị bỏ qua
- bị từ chối
- hoặc phải chờ timeout/retry

**Thứ hai**: server vẫn giữ các kết nối half-open

Vì timeout là 60 giây, các entry giả này sẽ tiếp tục chiếm tài nguyên trong khoảng thời gian đó nếu không có cơ chế phòng thủ.

**Thứ ba**: hiệu năng dịch vụ suy giảm

Server có thể:

- phản hồi chậm
- mất kết nối
- không thể phục vụ người dùng hợp lệ
- trong trường hợp nặng có thể dẫn đến từ chối dịch vụ (DoS)

**Thứ tư**: nếu có cơ chế bảo vệ

Một số hệ thống có thể phản ứng bằng cách:

- kích hoạt SYN Cookies
- giảm thời gian chờ
- drop bớt SYN mới
- dùng firewall hoặc SYN Proxy để lọc

## Kết luận

TCP 3-way handshake là cơ chế thiết lập kết nối gồm `SYN → SYN-ACK → ACK`.
SYN Flood khai thác điểm yếu ở chỗ server phải giữ các kết nối `half-open` trước khi nhận ACK cuối cùng.

Với backlog queue = 1024, tốc độ tấn công 2000 SYN/giây, queue sẽ đầy sau:

$$
0.512 \text{ giây}
$$

Khi đó server sẽ không còn khả năng tiếp nhận các kết nối hợp lệ, gây ra tình trạng từ chối dịch vụ.


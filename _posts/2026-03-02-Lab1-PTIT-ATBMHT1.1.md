---
title: (Vietnamese) ATBMHTTT CN04 | PTIT-Lab 1.1 - 3 loại SQL Injection phổ biến
date: 2026-03-02 23:59:00 +0700
categories: [Analysis]
tags: [SQL Injection, Error-based, Union-based, Blind SQLi]

image:
  path: /assets/img/2026-03-06-PTIT-LAB1/ima1.png

description: "Giải thích ba dạng SQL Injection thường gặp gồm Error-based, Union-based và Blind SQL Injection (Boolean-based, Time-based), kèm ví dụ minh họa và cách phòng chống an toàn trong thực tế."
---

## Giải thích 3 loại SQL Injection phổ biến

## 1) Khái niệm chung

`SQL Injection` là lỗ hổng xuất hiện khi ứng dụng ghép trực tiếp dữ liệu đầu vào của người dùng vào câu lệnh SQL mà không kiểm soát đúng cách.

Khi đó, dữ liệu nhập vào không còn là “dữ liệu thuần” mà có thể trở thành một phần của cú pháp SQL, làm thay đổi ý nghĩa truy vấn ban đầu.

Ba loại SQL Injection phổ biến trong thực tế:

- `Error-based SQL Injection`
- `Union-based SQL Injection`
- `Blind SQL Injection` (gồm `Boolean-based` và `Time-based`)

---

## 2) Error-based SQL Injection

### Khái niệm Error-based SQL Injection

`Error-based SQL Injection` khai thác thông báo lỗi do hệ quản trị cơ sở dữ liệu (DBMS) trả về.

Nếu ứng dụng hiển thị lỗi SQL trực tiếp ra giao diện, kẻ tấn công có thể thu được thông tin quan trọng như:

- Tên bảng/cột
- Loại CSDL đang dùng (MySQL, PostgreSQL, MSSQL...)
- Cấu trúc truy vấn backend

### Ví dụ truy vấn gốc (Error-based)

```sql
SELECT * FROM users
WHERE username = '$username' AND password = '$password';
```

### Ví dụ đầu vào gây lỗi

```sql
'
```

### Vì sao Error-based hoạt động

Ký tự `'` làm chuỗi SQL bị đóng/mở sai dẫn đến lỗi cú pháp.
Nếu hệ thống không ẩn lỗi, attacker dùng thông tin lỗi để dò dần cấu trúc truy vấn và xác định điểm khai thác sâu hơn.

---

## 3) Union-based SQL Injection

### Khái niệm Union-based SQL Injection

`Union-based SQL Injection` tận dụng toán tử `UNION` để ghép kết quả từ truy vấn do kẻ tấn công tạo vào kết quả truy vấn hợp lệ của ứng dụng.

### Ví dụ truy vấn gốc

```sql
SELECT name, price FROM products
WHERE id = '$id';
```

### Ví dụ payload

```sql
1' UNION SELECT username, password FROM users --
```

### Vì sao thành công

Nếu số cột và kiểu dữ liệu giữa hai vế `UNION` tương thích, DB sẽ trả về dữ liệu từ bảng ngoài phạm vi truy vấn ban đầu.
Đây là kiểu SQLi thường dùng để trích xuất dữ liệu hàng loạt khi ứng dụng trả kết quả truy vấn ra giao diện.

---

## 4) Blind SQL Injection

### Khái niệm Blind SQL Injection

`Blind SQL Injection` xảy ra khi hệ thống không hiển thị lỗi SQL và cũng không trả dữ liệu trực tiếp.

Kẻ tấn công phải suy luận thông tin dựa vào hành vi phản hồi của ứng dụng.

### 4.1 Boolean-based Blind SQLi

Ví dụ payload:

```sql
1' AND '1'='1
```

Ý tưởng:

- Nếu điều kiện đúng, trang phản hồi “bình thường”
- Nếu điều kiện sai, nội dung/trạng thái phản hồi thay đổi

Từ khác biệt này, kẻ tấn công suy luận dữ liệu theo từng bit/ký tự.

### 4.2 Time-based Blind SQLi

Ví dụ payload:

```sql
1' AND IF(1=1, SLEEP(5), 0) --
```

Ý tưởng:

- Nếu điều kiện đúng, DB trì hoãn phản hồi (ví dụ 5 giây)
- Nếu điều kiện sai, phản hồi gần như ngay lập tức

Dựa vào độ trễ, kẻ tấn công có thể suy đoán dữ liệu ngay cả khi không thấy lỗi và không thấy dữ liệu trả về.

---

## 5) So sánh nhanh 3 loại

- `Error-based`: Dựa vào thông báo lỗi, khai thác nhanh nếu hệ thống lộ lỗi.
- `Union-based`: Dựa vào `UNION`, hiệu quả khi có thể hiển thị kết quả query ra giao diện.
- `Blind`: Dựa vào logic phản hồi/thời gian, chậm hơn nhưng vẫn khai thác được khi hệ thống đã ẩn lỗi.

| Loại SQLi | Cách khai thác chính | Điều kiện thành công | Tốc độ khai thác | Mức độ khó phát hiện |
| --- | --- | --- | --- | --- |
| `Error-based` | Quan sát lỗi SQL | Ứng dụng hiển thị lỗi DB | Nhanh | Trung bình |
| `Union-based` | Ghép kết quả bằng `UNION` | Số cột/kiểu dữ liệu tương thích, có output | Nhanh | Trung bình |
| `Blind` | Suy luận theo đúng/sai hoặc thời gian | Không cần lộ lỗi, chỉ cần khác biệt phản hồi | Chậm | Khó hơn |

---

## 6) Luồng tấn công điển hình

Trong một kịch bản phổ biến, kẻ tấn công thường đi theo các bước sau:

1. `Recon`: xác định tham số đầu vào nghi ngờ (query string, form đăng nhập, API params)
2. `Injection point`: thử payload đơn giản để phát hiện điểm tiêm (`'`, `"`, điều kiện `AND 1=1`)
3. `Technique selection`: chọn `Error-based`, `Union-based` hoặc `Blind` tùy phản hồi hệ thống
4. `Exfiltration`: suy luận/trích xuất dữ liệu mục tiêu (schema, tài khoản, thông tin nhạy cảm)

---

## 7) Phòng chống SQL Injection

Các biện pháp cốt lõi cần áp dụng đồng thời:

1. Dùng `Prepared Statements` / `Parameterized Queries` (quan trọng nhất)
2. Kiểm tra và ràng buộc dữ liệu đầu vào (độ dài, kiểu dữ liệu, whitelist)
3. Không hiển thị lỗi SQL chi tiết ra người dùng
4. Áp dụng nguyên tắc `Least Privilege` cho tài khoản kết nối DB
5. Theo dõi log bất thường và dùng `WAF` để giảm rủi ro khai thác tự động

### Ví dụ code an toàn với Prepared Statement (Python + SQLite)

```python
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()

username = input("Username: ")
password = input("Password: ")

cursor.execute(
    "SELECT id, username FROM users WHERE username = ? AND password = ?",
    (username, password),
)

user = cursor.fetchone()
if user:
    print("Đăng nhập thành công")
else:
    print("Sai thông tin đăng nhập")
```

Với cách này, giá trị đầu vào được truyền tách biệt với cú pháp SQL, nên không thể “bẻ” câu lệnh bằng payload chèn thêm.

---

## 8) Kết luận

Ba loại SQL Injection phổ biến là `Error-based`, `Union-based` và `Blind SQL Injection`.

Điểm chung của chúng là khai thác việc ứng dụng xử lý đầu vào không an toàn. Vì vậy, phòng chống hiệu quả phải bắt đầu từ thiết kế truy vấn đúng chuẩn (prepared statements), kết hợp kiểm soát input và cấu hình hệ thống không làm lộ thông tin nhạy cảm.

---
title: (Vietnamese) ATBMHTTT CN04 | PTIT-Lab 1.2 Phân tích code PHP bị SQL Injection
date: 2026-03-01 23:59:00 +0700
categories: [Analysis]
tags: [SQL Injection, PHP, mysqli, Prepared Statement]

image:
  path: /assets/img/2026-03-06-PTIT-LAB1/inj1.png

description: "Phân tích đoạn code PHP đăng nhập dễ bị SQL Injection, chỉ ra nguyên nhân và cách khắc phục bằng Prepared Statement trong mysqli."
---

## Bài 1.2 – Phân tích đoạn code PHP (SQL Injection)

## 1) Đoạn code ban đầu

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $sql);
?>
```

---

## 2) Điểm dễ bị tấn công

Đoạn code trên bị lỗi `SQL Injection` vì dữ liệu từ `$_POST` được nối trực tiếp vào câu lệnh SQL mà không có cơ chế ràng buộc tham số.

Kẻ tấn công có thể chèn payload vào `username` hoặc `password` để thay đổi logic truy vấn, ví dụ nhập:

```sql
' OR '1'='1
```

Khi đó điều kiện `WHERE` có thể luôn đúng và dẫn đến bỏ qua kiểm tra đăng nhập.

---

## 3) Khắc phục bằng Prepared Statement (mysqli)

```php
<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Đăng nhập thành công";
} else {
    echo "Sai tài khoản hoặc mật khẩu";
}

$stmt->close();
?>
```

Với `Prepared Statement`, dữ liệu đầu vào được truyền riêng với câu lệnh SQL nên payload không thể làm thay đổi cú pháp truy vấn.

---

## 4) Lưu ý bảo mật quan trọng

Ngoài chống SQL Injection, đoạn code vẫn còn vấn đề nếu mật khẩu được lưu dạng `plain text`.

Trong thực tế cần:

- Dùng `password_hash()` khi tạo/lưu mật khẩu
- Dùng `password_verify()` khi kiểm tra đăng nhập
- Gắn thêm giới hạn số lần đăng nhập sai và log cảnh báo bất thường

---

## 5) Kết luận

Nguyên nhân gốc của lỗ hổng là ghép chuỗi SQL trực tiếp từ input người dùng.
Giải pháp đúng là dùng `Prepared Statement` để tham số hóa truy vấn, kết hợp lưu mật khẩu an toàn bằng cơ chế hash.

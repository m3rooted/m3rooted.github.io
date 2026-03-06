---
title: (Vietnamese) ATBMHTTT CN04 | PTIT-Lab 1.4 So sánh biện pháp phòng SQL Injection
date: 2026-03-02 23:59:00 +0700
categories: [Analysis]
tags: [SQL Injection, Prepared Statement, Stored Procedure, Input Validation, Escaping]

image:
  path: /assets/img/2026-03-06-PTIT-LAB1/ptt1.png

description: "So sánh 4 biện pháp phòng ngừa SQL Injection theo mức độ hiệu quả: Prepared Statements, Stored Procedures kết hợp Least Privilege, Input Validation và Escaping."
---

## Bài 1.4 – So sánh 4 biện pháp phòng ngừa SQL Injection

## Thứ tự hiệu quả giảm dần

`Prepared Statements` → `Stored Procedures + Least Privilege` → `Input Validation` → `Escaping`

---

## 1) Prepared Statements (Hiệu quả nhất)

`Prepared Statements` tách phần **câu lệnh SQL** và **dữ liệu đầu vào**.
Dữ liệu người dùng được bind vào tham số nên không thể làm thay đổi cấu trúc câu lệnh SQL.

### Ví dụ (Python)

```python
def login(conn, username, password):
    sql = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor = conn.cursor()
    cursor.execute(sql, (username, password))
    return cursor.fetchone()
```

### Vì sao hiệu quả

- Ngăn SQL Injection từ gốc
- Không phụ thuộc việc lập trình viên tự escape thủ công
- Được hỗ trợ rộng rãi trong hầu hết framework/thư viện

---

## 2) Stored Procedures + Least Privilege

### 2.1 Stored Procedure

`Stored Procedure` là thủ tục SQL được định nghĩa sẵn trong database và gọi với tham số.

```sql
DELIMITER $$

CREATE PROCEDURE GetUserByUsername(IN p_username VARCHAR(50))
BEGIN
    SELECT id, username, email
    FROM users
    WHERE username = p_username;
END $$

DELIMITER ;
```

### 2.2 Least Privilege

Chỉ cấp quyền tối thiểu cần thiết cho tài khoản kết nối database.

```sql
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT SELECT ON mydb.users TO 'app_user'@'localhost';
GRANT EXECUTE ON PROCEDURE mydb.GetUserByUsername TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

### Ý nghĩa bảo mật

- Stored procedure giúp giảm việc viết SQL trực tiếp trong ứng dụng
- Least privilege giới hạn phạm vi thiệt hại nếu có khai thác thành công

---

## 3) Input Validation

`Input Validation` kiểm tra dữ liệu đầu vào đúng định dạng/phạm vi cho phép.

### Ví dụ Input Validation (Python)

```python
def get_user_by_id(conn, user_id):
    if not str(user_id).isdigit():
        raise ValueError("user_id phải là số nguyên")

    sql = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.cursor()
    cursor.execute(sql)
    return cursor.fetchall()
```

### Ý nghĩa bảo mật của Input Validation

- Giảm dữ liệu bất thường đi vào hệ thống
- Thu hẹp bề mặt tấn công
- Không thể thay thế `Prepared Statements`

---

## 4) Escaping (Yếu nhất)

`Escaping` xử lý ký tự đặc biệt để tránh phá vỡ cú pháp SQL.

### Ví dụ (PHP)

```php
<?php
$username = $_POST['username'];
$username_safe = $conn->real_escape_string($username);

$sql = "SELECT * FROM users WHERE username = '$username_safe'";
$result = $conn->query($sql);
?>
```

### Hạn chế

- Phụ thuộc DBMS và encoding
- Dễ sai sót khi escape không đầy đủ
- Không nên dùng như biện pháp chính

---

## 5) Kết luận

Thứ tự hiệu quả trong phòng chống SQL Injection:

`Prepared Statements` > `Stored Procedures + Least Privilege` > `Input Validation` > `Escaping`

Tổng kết thực hành:

- Ưu tiên bắt buộc: `Prepared Statements`
- Bổ sung bảo vệ hệ thống: `Stored Procedures` + `Least Privilege`
- Tăng chất lượng dữ liệu đầu vào: `Input Validation`
- Chỉ dùng hỗ trợ, không dùng độc lập: `Escaping`

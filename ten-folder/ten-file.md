1. Lỗ hổng SQL Injection là gì?
1.1. Định nghĩa

SQL Injection (SQLi) là một lỗ hổng an ninh web cho phép kẻ tấn công can thiệp trực tiếp vào các câu truy vấn mà ứng dụng gửi đến cơ sở dữ liệu (Database).

Lỗ hổng này cho phép kẻ tấn công:

Xem dữ liệu nhạy cảm mà bình thường họ không có quyền xem (dữ liệu của người dùng khác, thông tin kinh doanh bí mật).
Chỉnh sửa hoặc xóa dữ liệu, làm thay đổi vĩnh viễn nội dung và hành vi của hệ thống.
Leo thang đặc quyền để chiếm quyền điều khiển máy chủ backend hoặc hạ tầng bên dưới.
Tấn công từ chối dịch vụ (DoS) làm sập hệ thống cơ sở dữ liệu.
1.2. Mức độ tác động (Impact)

Một cuộc tấn công SQLi thành công có thể dẫn đến rò rỉ:

Mật khẩu đăng nhập (dưới dạng băm hoặc bản rõ).
Thông tin thẻ tín dụng, tài khoản ngân hàng.
Dữ liệu định danh cá nhân (PII - Personally Identifiable Information).

Trong lịch sử, SQLi là nguyên nhân của nhiều vụ vi phạm dữ liệu chấn động thế giới, gây thiệt hại nghiêm trọng về uy tín và khiến doanh nghiệp phải chịu các khoản phạt pháp lý khổng lồ. Kẻ tấn công thậm chí có thể cài cắm backdoor bền vững trên hệ thống trong thời gian dài mà không bị phát hiện.


2. Vì sao lỗ hổng tồn tại?
2.1. Bản chất: Nhập nhằng giữa "Lệnh" (Code) và "Dữ liệu" (Data)

Lỗ hổng phát sinh khi dữ liệu người dùng nhập vào được nối chuỗi trực tiếp (String Concatenation) vào câu lệnh SQL.

Trình phân tích cú pháp của database (SQL Parser) sử dụng các ký tự đặc biệt (như dấu nháy đơn ', dấu chấm phẩy ;, dấu comment --) để phân tách các thành phần câu lệnh. Khi dữ liệu của người dùng chứa các ký tự này, database sẽ hiểu nhầm đó là cú pháp điều khiển của lập trình viên, từ đó thực thi dữ liệu đó như mã lệnh.

2.2. Phân loại theo cơ chế: First-order vs Second-order SQLi
First-order SQLi: Input độc hại từ HTTP request được đưa trực tiếp vào câu lệnh SQL và thực thi ngay lập tức trong cùng chu kỳ xử lý request đó.
Second-order SQLi (Stored SQLi):
Input độc hại ban đầu được lưu trữ vào database mà chưa gây hại gì (thường do lúc lưu có dùng hàm lọc cơ bản).
Ở một chức năng khác sau này, ứng dụng đọc dữ liệu đã lưu từ database ra và tin tưởng sai lầm rằng dữ liệu trong database là "an toàn".
Ứng dụng nối chuỗi dữ liệu này vào một câu truy vấn SQL mới 
→
→ Lỗ hổng lúc này mới phát tác.
3. Vị trí xuất hiện & Các dạng khai thác chi tiết

SQL Injection có thể xuất hiện ở bất kỳ đâu tiếp nhận dữ liệu đưa vào câu SQL:

Trong câu lệnh SELECT: Tại mệnh đề WHERE, tên cột, tên bảng, hoặc mệnh đề ORDER BY.
Trong câu lệnh UPDATE: Tại giá trị cập nhật (SET col = '...') hoặc điều kiện WHERE.
Trong câu lệnh INSERT: Tại danh sách giá trị (VALUES ('...')).


4.SQL injection examples

Có nhiều lỗ hổng,cách tấn công , kĩ thuật SQLi xảy ra trong những tình huống khác nhau .Một vài ví dụ phổ biến về SQL injection bao gồm:


Dạng 1: Đọc dữ liệu ẩn (Retrieving hidden data)
Ngữ cảnh: Trang web bán hàng lọc sản phẩm theo danh mục (category), nhưng chỉ hiển thị các sản phẩm đã mở bán (released = 1).
URL gửi đi: https://insecure-website.com/products?category=Gifts
Truy vấn gốc:
sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
📌 Kỹ thuật 1A: Dùng dấu Comment --

URL tấn công: https://insecure-website.com/products?category=Gifts'--

Câu SQL sau khi bị can thiệp:

sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1

🔍 Phân tích chi tiết từng thành phần Payload Gifts'--:

Thành phần	Ý nghĩa & Cơ chế hoạt động
Gifts	Giá trị danh mục hợp lệ ban đầu.
'	Dấu nháy đơn dùng để đóng chuỗi ký tự của tham số category sớm hơn dự định.
--	Ký hiệu bắt đầu chú thích (Comment) trong SQL. Toàn bộ phần phía sau (' AND released = 1) bị loại bỏ hoàn toàn khỏi quá trình thực thi.

Kết quả: Truy vấn chỉ còn WHERE category = 'Gifts', hiển thị toàn bộ sản phẩm thuộc nhóm Gifts kể cả khi chưa phát hành (released = 0).

📌 Kỹ thuật 1B: Ép điều kiện luôn đúng (OR 1=1)

URL tấn công: https://insecure-website.com/products?category=Gifts'+OR+1=1--

Câu SQL sau khi bị can thiệp:

sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1

🔍 Phân tích chi tiết từng thành phần Payload Gifts'+OR+1=1--:

Thành phần	Ý nghĩa & Cơ chế hoạt động
Gifts	Giá trị danh mục ban đầu.
'	Đóng chuỗi literal mà server mở ra cho giá trị $category.
+	Đại diện cho khoảng trắng (Space) được mã hóa URL giữa các từ khóa.
OR	Toán tử logic SQL. Chỉ cần một trong hai vế đúng thì toàn bộ mệnh đề WHERE đúng.
1=1	Biểu thức toán học luôn trả về TRUE với mọi hàng dữ liệu trong bảng.
--	Vô hiệu hóa toàn bộ đoạn mã phía sau (' AND released = 1).

Kết quả: Do 1=1 luôn đúng, câu lệnh trả về tất cả sản phẩm của mọi danh mục trong hệ thống, bao gồm cả sản phẩm bị ẩn.

CAUTION

Cảnh báo an toàn khi pentest: Hết sức thận trọng khi inject OR 1=1. Nếu giá trị bạn nhập được hệ thống tái sử dụng trong một câu lệnh UPDATE hoặc DELETE, điều kiện OR 1=1 có thể cập nhật hoặc xóa sạch toàn bộ dữ liệu của cả bảng!


Dạng 2: Phá vỡ logic ứng dụng (Bypass xác thực đăng nhập)
Ngữ cảnh: Ứng dụng kiểm tra username và password của người dùng.
Truy vấn gốc:
sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
📌 Kỹ thuật khai thác:

Người dùng nhập vào ô Username: administrator'-- và để trống ô Password.

Câu SQL sau khi bị can thiệp:

sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''

🔍 Phân tích chi tiết từng thành phần Payload administrator'--:

Thành phần	Ý nghĩa & Cơ chế hoạt động
administrator	Tên tài khoản quản trị viên mục tiêu cần chiếm quyền.
'	Đóng chuỗi giá trị của username.
--	Comment toàn bộ phần kiểm tra mật khẩu phía sau (AND password = '...').

Kết quả: Server thực thi câu lệnh SELECT * FROM users WHERE username = 'administrator', tìm thấy tài khoản admin và cho phép đăng nhập thẳng mà không cần mật khẩu.


Dạng 3: Tấn công kết hợp bảng (UNION-based SQLi)

Khi ứng dụng hiển thị trực tiếp kết quả truy vấn ra màn hình, ta có thể dùng từ khóa UNION để ghép thêm một truy vấn mới nhằm rút trích dữ liệu từ các bảng khác.

Truy vấn gốc:

sql
SELECT name, description FROM products WHERE category = 'Gifts'

Payload tấn công:

text
' UNION SELECT username, password FROM users--

🔍 Phân tích chi tiết từng thành phần Payload:

Thành phần	Ý nghĩa & Cơ chế hoạt động
'	Đóng chuỗi giá trị danh mục ban đầu.
UNION	Toán tử gộp tập hợp kết quả của câu SELECT ban đầu với câu SELECT mới.
SELECT username, password	Lấy dữ liệu 2 cột tài khoản và mật khẩu (số cột phải bằng đúng số cột name, description của truy vấn gốc).
FROM users	Chỉ định bảng cần đánh cắp dữ liệu (users).
--	Bỏ qua phần còn lại của câu lệnh gốc.

Kết quả: Trang web sẽ hiển thị danh sách username và password của toàn bộ người dùng xen kẽ với danh sách sản phẩm.

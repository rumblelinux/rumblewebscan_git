# rumblewebscan_git

 Kiểm tra 3 loại lỗ hổng là SQL Injection, XSS và LFI trên từng URL

 Hướng dẫn sử dụng: python3 main.py -h 


Lưu ý những điều sau về tool này:
1. Chỉ có thể scan được các trang web có giao thức HTTP hoặc HTTPS. Những trang sử dụng giao thức khác (FTP, SMTP,...) sẽ không scan được.
2. Chỉ scan được các trang web cho phép truy cập công khai, không yêu cầu xác thực (như login). Những trang web yêu cầu đăng nhập sẽ không thể access được nội dung.
3. Chỉ có thể scan trang web đang hoạt động, không bị downtime. Trang web bị shutdown sẽ báo lỗi kết nối.
4. Các trang web có firewall chặn/giới hạn truy cập từ bên ngoài cũng có thể không cho phép scan.
5. Đối với các trang web có nhiều bot protection, chặn DDOS, có thể nhận biết traffic scan và chặn lại.
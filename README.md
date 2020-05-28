# Công cụ hỗ trợ thống kê dữ liệu hành vi malware
  Công cụ giúp thống kê dữ liệu trích xuất được từ công cụ AndroPyTool, Vẽ biểu đồ trực quan các những trường quan trọng
# Yêu cầu
  * Hệ điều hành Ubuntu hoắc Windows
  * Python3.6 trở lên
  * Folder chứa kết quả khi chạy AndroPyTool
### Clone về và coppy sang Folder kết quả
      Mở Terminal tại folder kết quả sau khi chạy AndroPyTool
      $ git clone https://github.com/viocuong/athdh.git
      $ cp athdh/tool.py ./
### Cài các module cần thiết
      $ sudo apt install python3-pip -y
      $ sudo pip3 insatll numpy
      $ sudo pip3 install matplotlib
      $ sudo pip3 install pandas
      $ sudo pip3 install pathlib
# Chạy
### Thống kê các dữ liệu cơ bản
      $ python3 tool.py
### Vẽ biều đồ
#### Ví dụ vẽ biểu đồ các Opcodes được sử dụng
      $ python3 tool.py -o
#### Để xem các đối số khác
      $ python3 tool.py -h
      
      

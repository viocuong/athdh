# Công cụ hỗ trợ thống kê dữ liệu hành vi malware
  Công cụ giúp thống kê, vẽ biểu đồ từ dữ liệu trích xuất được từ công cụ AndroPyTool
# Yêu cầu
  * Hệ điều hành Ubuntu hoắc Windows
  * Python3.6 trở lên
  * Folder chứa kết quả khi chạy AndroPyTool
### Clone và coppy sang Folder kết quả
      Mở Terminal tại folder kết quả sau khi chạy AndroPyTool
      $ git clone https://github.com/viocuong/athdh.git
      $ cp athdh/tool.py ./
### Cài các module cần thiết
      $ sudo apt install python3-pip -y
      $ sudo pip3 install numpy
      $ sudo pip3 install matplotlib
      $ sudo pip3 install pandas
      $ sudo pip3 install pathlib
# Chạy
### Thống kê các dữ liệu cơ bản
      $ python3 tool.py
### Vẽ biều đồ
#### Ví dụ vẽ biểu đồ các Opcodes được sử dụng
      $ python3 tool.py -o
### Vẽ biểu đồ kết hợp
#### tạo một folder chứa 4 file output trong thư mục Features_files của 4 thành viên trong nhóm
      ví dụ folder là output, gồm các file là:
##### 1 04c12809d3b1809c9980bd1e3e11e0f5-analysis.json
##### 2 04c12809d3b1809c9980bd1e3e11e0f6-analysis.json
##### 3 04c12809d3b1809c9980bd1e3e11e0f7-analysis.json
##### 4 04c12809d3b1809c9980bd1e3e11e0f8-analysis.json

      $ python3 tool.py -c  

#### Để xem các đối số khác
      $ python3 tool.py -h
      
      

# What is PHPimage　disk
　my frist data update test  😏
 web/
├── index.php         # 主要的PHP处理脚本
├── style.css         # CSS样式文件
├── uploads/          # 文件和文件夹存放的根目录 (需要Web服务器可写)
├── logs/             # 日志文件存放目录 (需要Web服务器可写)
│   └── uploads.log   # 上传日志文件
└── favicon.png       # 网站图标

##　easy　to build your mirror image storage website !

# setting your password🔐
open the index.php 
found define('PASSWORD_HASH', password_hash('your2005KO', PASSWORD_DEFAULT));
change your2005KO as your new password

# uploads 🔝
your flies will be stored in this folder.

# about logs 📝
It mainly stores the upload logs and IP addresses of website visitors and uploaders.

# website favicon 
upload favicon.png to the root directory.

# warning ❌
This project is not rigorously tested for safety！


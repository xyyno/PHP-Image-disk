<?php
session_start(); // 用于显示一次性消息

// --- 配置 ---
define('SITE_TITLE', '可爱猫咪资源站'); // 网站标题
define('ROOT_DIR', __DIR__ . '/uploads'); // 文件存储根目录 (确保Web服务器可写)
define('LOG_DIR', __DIR__ . '/logs'); // 日志目录 (确保Web服务器可写)
define('LOG_FILE', LOG_DIR . '/uploads.log'); // 上传日志文件
define('PASSWORD_HASH', password_hash('your2005KO', PASSWORD_DEFAULT));
define('MAX_UPLOAD_SIZE', 50 * 1024 * 1024); // 最大上传大小 (例如 50MB)
define('DISALLOWED_EXTENSIONS', ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'cgi', 'pl', 'py', 'sh', 'exe', 'bat', 'com', 'dll', 'vbs', 'js', 'jsp', 'asp', 'aspx', 'htaccess', 'htpasswd']); // 禁止上传的文件扩展名

// --- 安全与初始化 ---
if (!is_dir(ROOT_DIR)) {
    mkdir(ROOT_DIR, 0755, true);
}
if (!is_dir(LOG_DIR)) {
    mkdir(LOG_DIR, 0750, true); // 日志目录权限可以更严格
}
if (!file_exists(LOG_FILE)) {
    touch(LOG_FILE);
    chmod(LOG_FILE, 0640); // 日志文件权限
}

// --- 辅助函数 ---

// 获取并清理相对路径
function get_relative_path($base_path, $full_path) {
    $base_path = rtrim(realpath($base_path), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $full_path = realpath($full_path);

    if ($full_path && strpos($full_path, $base_path) === 0) {
        $relative = ltrim(substr($full_path, strlen($base_path)), DIRECTORY_SEPARATOR);
        return $relative === false ? '' : $relative;
    }
    return ''; // 不在根目录下或无效路径
}

// 获取当前目录的绝对路径，并进行安全检查
function get_current_dir() {
    // 校验根目录配置
    $root = realpath(ROOT_DIR);
    if ($root === false || !is_dir($root)) {
        throw new RuntimeException("系统配置错误：根目录无效");
    }

    // 过滤用户输入
    $raw_path = isset($_GET['path']) ? trim($_GET['path']) : '';
    
    // 防御层1：主动检测路径遍历特征
    if (preg_match('/\.\.(\/|\\\\)/', $raw_path)) {
        error_log("安全警报：检测到目录遍历尝试 IP: {$_SERVER['REMOTE_ADDR']}");
        header('HTTP/1.1 403 Forbidden');
        exit;
    }

    // 防御层2：路径规范化处理
    $safe_path = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $raw_path), DIRECTORY_SEPARATOR);
    $target_path = $root . DIRECTORY_SEPARATOR . $safe_path;

    // 防御层3：规范化验证
    $current_dir = realpath($target_path);
    if ($current_dir === false) {
        header('HTTP/1.1 400 Bad Request');
        exit;
    }

    // 防御层4：严格路径归属验证（修正括号问题）
    $is_inside = ($current_dir === $root) 
              || (strpos($current_dir, $root . DIRECTORY_SEPARATOR) === 0);

    // 防御层5：权限验证
    if (!$is_inside || !is_readable($current_dir)) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }

    return $current_dir;
}

// 格式化文件大小
function format_size($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

// 检查密码的安全实现
function check_password($entered_password) {
    // 使用密码学安全的方式验证密码
    return password_verify($entered_password, PASSWORD_HASH);
}

// 记录上传日志
function log_upload($filename, $ip) {
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = sprintf("%s|%s|%s|%s\n", $timestamp, $ip, $_SESSION['current_path_for_log'] ?? '', basename($filename)); // 添加路径信息
    // 使用文件锁防止并发写入问题
    $fp = fopen(LOG_FILE, 'a');
    if (flock($fp, LOCK_EX)) { // 获取独占锁
        fwrite($fp, $log_entry);
        flock($fp, LOCK_UN); // 释放锁
    }
    fclose($fp);
}

// 获取最近上传记录
function get_recent_uploads($limit = 10) {
    $lines = file(LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $uploads = [];
    if ($lines) {
        $reversed_lines = array_reverse($lines);
        $count = 0;
        foreach ($reversed_lines as $line) {
            if ($count >= $limit) break;
            $parts = explode('|', $line, 4); // 分割时间|IP|路径|文件名
            if (count($parts) === 4) {
                $uploads[] = [
                    'time' => $parts[0],
                    'ip' => $parts[1],
                    'path' => htmlspecialchars($parts[2], ENT_QUOTES, 'UTF-8'),
                    'filename' => htmlspecialchars($parts[3], ENT_QUOTES, 'UTF-8')
                ];
                $count++;
            }
        }
    }
    return $uploads;
}

// --- 动作处理 ---
$action = $_REQUEST['action'] ?? 'list';
$current_dir = get_current_dir();
$relative_path = get_relative_path(ROOT_DIR, $current_dir);
$_SESSION['current_path_for_log'] = $relative_path; // 用于日志记录当前路径
$message = $_SESSION['message'] ?? null; // 获取一次性消息
unset($_SESSION['message']); // 清除消息

// 处理文件下载
if ($action === 'download' && isset($_GET['file'])) {
    $file_path = realpath($current_dir . DIRECTORY_SEPARATOR . basename($_GET['file'])); // basename防止路径遍历

    // 安全检查：确保文件在当前目录下且存在
    if ($file_path && strpos($file_path, $current_dir) === 0 && is_file($file_path)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream'); // 通用二进制类型
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        ob_clean(); // 清除输出缓冲
        flush();
        readfile($file_path);
        exit;
    } else {
        $_SESSION['message'] = ['type' => 'error', 'text' => '文件未找到或无效.'];
        header('Location: ?path=' . urlencode($relative_path));
        exit;
    }
}

// 处理创建文件夹请求
if ($action === 'create_folder' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $folder_name = $_POST['folder_name'] ?? '';
    $password = $_POST['password'] ?? '';

    if (check_password($password)) {
        // 清理文件夹名称，移除危险字符和路径分隔符
        $clean_folder_name = preg_replace('/[^a-zA-Z0-9_\-\.\s]/', '', trim($folder_name));
        $clean_folder_name = trim($clean_folder_name); // 再次去除首尾空格

        if (!empty($clean_folder_name) && $clean_folder_name !== '.' && $clean_folder_name !== '..') {
            $new_folder_path = $current_dir . DIRECTORY_SEPARATOR . $clean_folder_name;
            if (!file_exists($new_folder_path)) {
                if (mkdir($new_folder_path, 0755)) {
                    $_SESSION['message'] = ['type' => 'success', 'text' => '文件夹 "' . htmlspecialchars($clean_folder_name) . '" 创建成功!'];
                } else {
                    $_SESSION['message'] = ['type' => 'error', 'text' => '无法创建文件夹，请检查权限.'];
                }
            } else {
                $_SESSION['message'] = ['type' => 'error', 'text' => '文件夹 "' . htmlspecialchars($clean_folder_name) . '" 已存在.'];
            }
        } else {
            $_SESSION['message'] = ['type' => 'error', 'text' => '无效的文件夹名称.'];
        }
    } else {
        $_SESSION['message'] = ['type' => 'error', 'text' => '口令错误!'];
    }
    header('Location: ?path=' . urlencode($relative_path));
    exit;
}

// 处理文件上传请求
if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';

    if (check_password($password)) {
        if (isset($_FILES['uploadedFile']) && $_FILES['uploadedFile']['error'] === UPLOAD_ERR_OK) {
            $file = $_FILES['uploadedFile'];
            $file_name = $file['name'];
            $file_tmp_name = $file['tmp_name'];
            $file_size = $file['size'];
            $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));

            // 1. 检查文件大小
            if ($file_size > MAX_UPLOAD_SIZE) {
                 $_SESSION['message'] = ['type' => 'error', 'text' => '错误：文件大小超过限制 (' . format_size(MAX_UPLOAD_SIZE) . ').'];
            }
            // 2. 检查禁止的扩展名 (重要安全措施)
            elseif (in_array($file_ext, DISALLOWED_EXTENSIONS)) {
                 $_SESSION['message'] = ['type' => 'error', 'text' => '错误：不允许上传此类型文件 (.' . $file_ext . ').'];
            } else {
                // 清理文件名，防止路径遍历和非法字符
                $safe_filename = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', basename($file_name));
                $safe_filename = trim($safe_filename);

                 if (empty($safe_filename) || $safe_filename === '.' || $safe_filename === '..') {
                    $_SESSION['message'] = ['type' => 'error', 'text' => '错误：无效的文件名.'];
                } else {
                    $destination = $current_dir . DIRECTORY_SEPARATOR . $safe_filename;

                    // 检查同名文件是否存在
                    if (file_exists($destination)) {
                        // 可选：添加时间戳或重命名逻辑，这里简单地报错
                         $_SESSION['message'] = ['type' => 'error', 'text' => '错误：文件 "' . htmlspecialchars($safe_filename) . '" 已存在.'];
                    } else {
                        if (move_uploaded_file($file_tmp_name, $destination)) {
                            $_SESSION['message'] = ['type' => 'success', 'text' => '文件 "' . htmlspecialchars($safe_filename) . '" 上传成功!'];
                            // 记录日志
                            log_upload($destination, $_SERVER['REMOTE_ADDR']);
                        } else {
                            $_SESSION['message'] = ['type' => 'error', 'text' => '上传文件时发生服务器内部错误.'];
                        }
                    }
                 }
            }
        } elseif (isset($_FILES['uploadedFile']) && $_FILES['uploadedFile']['error'] !== UPLOAD_ERR_NO_FILE) {
             $_SESSION['message'] = ['type' => 'error', 'text' => '上传错误代码：' . $_FILES['uploadedFile']['error']];
        } else {
            $_SESSION['message'] = ['type' => 'error', 'text' => '没有选择文件或上传出错.'];
        }
    } else {
        $_SESSION['message'] = ['type' => 'error', 'text' => '口令错误!'];
    }
    header('Location: ?path=' . urlencode($relative_path));
    exit;
}

// 获取目录内容
$items = [];
if ($handle = opendir($current_dir)) {
    while (false !== ($entry = readdir($handle))) {
        if ($entry != "." && $entry != "..") {
            $entry_path = $current_dir . DIRECTORY_SEPARATOR . $entry;
            $is_dir = is_dir($entry_path);
            $items[] = [
                'name' => $entry,
                'path' => $relative_path . ($relative_path ? '/' : '') . $entry,
                'is_dir' => $is_dir,
                'size' => $is_dir ? '-' : format_size(filesize($entry_path)),
                'modified' => date("Y-m-d H:i:s", filemtime($entry_path))
            ];
        }
    }
    closedir($handle);

    // 排序：文件夹在前，文件在后，按名称排序
    usort($items, function($a, $b) {
        if ($a['is_dir'] !== $b['is_dir']) {
            return $a['is_dir'] ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });
}

// 获取最近上传记录
$recent_uploads = get_recent_uploads(15); // 获取最近15条

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(SITE_TITLE); ?> - <?php echo htmlspecialchars($relative_path ? $relative_path : '根目录'); ?></title>
    <link rel="stylesheet" href="style.css">
    <link rel="icon" href="favicon.png" type="image/png">
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-title">
                <img src="favicon.png" alt="Logo" class="logo">
                <h1><?php echo htmlspecialchars(SITE_TITLE); ?></h1>
            </div>
            <div class="current-path">
                当前位置: <a href="?path=">根目录</a> /
                <?php
                $path_parts = explode('/', $relative_path);
                $current_breadcrumb_path = '';
                foreach ($path_parts as $part) {
                    if (empty($part)) continue;
                    $current_breadcrumb_path .= ($current_breadcrumb_path ? '/' : '') . $part;
                    echo '<a href="?path=' . urlencode($current_breadcrumb_path) . '">' . htmlspecialchars($part) . '</a> / ';
                }
                ?>
            </div>
        </header>

        <main class="main-content">
            <?php if ($message): ?>
            <div class="message <?php echo $message['type']; ?>">
                <?php echo htmlspecialchars($message['text']); ?>
            </div>
            <?php endif; ?>

            <div class="action-forms">
                <div class="form-container create-folder-form">
                    <h3><span class="icon">📁</span> 新建文件夹</h3>
                    <form action="?path=<?php echo urlencode($relative_path); ?>" method="post">
                        <input type="hidden" name="action" value="create_folder">
                        <input type="text" name="folder_name" placeholder="文件夹名称" required>
                        <input type="password" name="password" placeholder="输入口令" required>
                        <button type="submit">创建</button>
                    </form>
                </div>
                <div class="form-container upload-form">
                    <h3><span class="icon">⬆️</span> 上传文件到当前目录</h3>
                    <form action="?path=<?php echo urlencode($relative_path); ?>" method="post" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="upload">
                         <input type="hidden" name="MAX_FILE_SIZE" value="<?php echo MAX_UPLOAD_SIZE; ?>" />
                        <input type="file" name="uploadedFile" required>
                        <input type="password" name="password" placeholder="输入口令" required>
                        <button type="submit">上传</button>
                         <small>最大: <?php echo format_size(MAX_UPLOAD_SIZE); ?>, 禁止: <?php echo implode(', ', DISALLOWED_EXTENSIONS); ?></small>
                    </form>
                </div>
            </div>

            <h2>文件列表</h2>
            <table class="file-list">
                <thead>
                    <tr>
                        <th>名称</th>
                        <th>大小</th>
                        <th>修改时间</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($relative_path !== ''): // 显示返回上一级 ?>
                        <tr>
                            <td colspan="3">
                                <a href="?path=<?php echo urlencode(dirname($relative_path) === '.' ? '' : dirname($relative_path)); ?>" class="nav-link parent-dir">
                                    <span class="icon">↩️</span> 返回上一级
                                </a>
                            </td>
                        </tr>
                    <?php endif; ?>
                    <?php if (empty($items)): ?>
                        <tr>
                            <td colspan="3">这个文件夹是空的~ 📁</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($items as $item): ?>
                        <tr>
                            <td>
                                <?php if ($item['is_dir']): ?>
                                    <a href="?path=<?php echo urlencode($item['path']); ?>" class="nav-link dir-link">
                                        <span class="icon">📂</span> <?php echo htmlspecialchars($item['name']); ?>
                                    </a>
                                <?php else: ?>
                                    <a href="?action=download&path=<?php echo urlencode($relative_path); ?>&file=<?php echo urlencode($item['name']); ?>" class="nav-link file-link" download>
                                        <span class="icon">📄</span> <?php echo htmlspecialchars($item['name']); ?>
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td><?php echo $item['size']; ?></td>
                            <td><?php echo $item['modified']; ?></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </main>

        <aside class="sidebar">
            <h3><span class="icon">🕒</span> 最近上传</h3>
            <?php if (empty($recent_uploads)): ?>
                <p>还没有上传记录.</p>
            <?php else: ?>
                <ul class="timeline">
                    <?php foreach ($recent_uploads as $upload): ?>
                    <li>
                        <div class="time"><?php echo $upload['time']; ?></div>
                        <div class="details">
                            <span class="ip" title="上传者IP">(<?php echo htmlspecialchars($upload['ip']); ?>)</span>
                            上传了 <span class="filename"><?php echo $upload['filename']; ?></span>
                            <?php if($upload['path']): ?>
                                到 <span class="filepath">./<?php echo $upload['path']; ?></span>
                            <?php else: ?>
                                到 <span class="filepath">根目录</span>
                            <?php endif; ?>
                        </div>
                    </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </aside>
    </div>
</body>
</html>
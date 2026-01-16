# 快速安装指南 - 磁盘管理功能

本指南帮助你快速安装和配置 RockZero OS 的磁盘管理功能。

## 前提条件

- Armbian 系统（或其他 Debian/Ubuntu 系统）
- Root 权限
- 已安装 RockZero OS 基础服务

## 安装步骤

### 1. 复制文件到系统目录

```bash
# 进入项目目录
cd /path/to/rockzero

# 复制到系统目录
sudo cp -r . /opt/rockzero/

# 设置脚本权限
sudo chmod +x /opt/rockzero/scripts/*.sh
```

### 2. 安装系统服务

```bash
# 安装自动挂载服务
sudo cp /opt/rockzero/rockzero-automount.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rockzero-automount.service

# 安装安全关机服务
sudo cp /opt/rockzero/rockzero-safe-shutdown.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rockzero-safe-shutdown.service
```

### 3. 启动服务

```bash
# 启动自动挂载服务（立即挂载所有磁盘）
sudo systemctl start rockzero-automount.service

# 检查服务状态
sudo systemctl status rockzero-automount.service
sudo systemctl status rockzero-safe-shutdown.service
```

### 4. 验证安装

```bash
# 查看已挂载的磁盘
lsblk

# 查看挂载点
mount | grep /mnt

# 测试自动挂载脚本
sudo /opt/rockzero/scripts/auto-mount-disks.sh

# 测试安全关机脚本（不会真的关机）
sudo /opt/rockzero/scripts/safe-shutdown.sh
```

## 一键安装脚本

如果你使用的是 Armbian 系统，可以使用一键部署脚本：

```bash
cd /path/to/rockzero
sudo ./scripts/deploy-armbian.sh
```

此脚本会自动：
- 更新系统
- 安装依赖
- 配置 Docker
- 安装磁盘管理服务
- 配置防火墙

## 使用说明

### 自动挂载
系统启动后会自动挂载所有检测到的磁盘（不包括 VFAT 格式的启动分区）。

### 手动挂载
```bash
# 挂载所有未挂载的磁盘
sudo /opt/rockzero/scripts/auto-mount-disks.sh
```

### 安全关机
```bash
# 在关机前运行（确保数据安全）
sudo /opt/rockzero/scripts/safe-shutdown.sh

# 然后关机
sudo shutdown -h now
```

### UI 界面操作
1. 打开 RockZero OS UI
2. 进入 **Files** 页面
3. 查看 **Storage Devices**
4. 点击未挂载的磁盘进行挂载

## 配置选项

### 修改挂载位置
编辑 `/opt/rockzero/scripts/auto-mount-disks.sh`：
```bash
MOUNT_BASE="/your/custom/path"
```

### 禁用自动挂载
```bash
sudo systemctl disable rockzero-automount.service
```

### 禁用安全关机
```bash
sudo systemctl disable rockzero-safe-shutdown.service
```

## 故障排除

### 服务无法启动
```bash
# 查看详细日志
sudo journalctl -u rockzero-automount -n 50
sudo journalctl -u rockzero-safe-shutdown -n 50

# 检查脚本权限
ls -la /opt/rockzero/scripts/

# 重新设置权限
sudo chmod +x /opt/rockzero/scripts/*.sh
```

### 磁盘未自动挂载
```bash
# 检查磁盘是否被识别
lsblk

# 手动运行挂载脚本查看错误
sudo /opt/rockzero/scripts/auto-mount-disks.sh

# 检查文件系统类型
sudo blkid
```

### 卸载服务
```bash
# 停止并禁用服务
sudo systemctl stop rockzero-automount.service
sudo systemctl disable rockzero-automount.service
sudo systemctl stop rockzero-safe-shutdown.service
sudo systemctl disable rockzero-safe-shutdown.service

# 删除服务文件
sudo rm /etc/systemd/system/rockzero-automount.service
sudo rm /etc/systemd/system/rockzero-safe-shutdown.service

# 重新加载 systemd
sudo systemctl daemon-reload
```

## 更新

如果需要更新脚本或服务：

```bash
# 停止服务
sudo systemctl stop rockzero-automount.service

# 更新文件
sudo cp /path/to/new/scripts/*.sh /opt/rockzero/scripts/
sudo chmod +x /opt/rockzero/scripts/*.sh

# 更新服务文件
sudo cp /path/to/new/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# 重启服务
sudo systemctl start rockzero-automount.service
```

## 完整示例

```bash
# 1. 克隆或下载项目
git clone https://github.com/yourusername/rockzero.git
cd rockzero

# 2. 运行部署脚本
sudo ./scripts/deploy-armbian.sh

# 3. 启动 RockZero 服务
docker-compose up -d

# 4. 验证磁盘管理
sudo systemctl status rockzero-automount
lsblk
mount | grep /mnt

# 5. 访问 UI
# 打开浏览器访问 http://your-device-ip:8080
```

## 注意事项

1. **数据安全**：始终在关机前等待所有文件操作完成
2. **权限问题**：确保脚本有执行权限
3. **文件系统**：推荐使用 ext4 文件系统以获得最佳性能
4. **备份数据**：定期备份重要数据到多个存储设备
5. **系统更新**：定期更新系统和服务

## 支持的系统

- ✅ Armbian (Debian/Ubuntu based)
- ✅ Debian 11/12
- ✅ Ubuntu 20.04/22.04/24.04
- ✅ Raspberry Pi OS
- ⚠️ 其他 Linux 发行版（可能需要调整）

## 获取帮助

- 📖 详细文档：[DISK_MANAGEMENT.md](DISK_MANAGEMENT.md)
- 🐛 报告问题：GitHub Issues
- 💬 讨论：GitHub Discussions

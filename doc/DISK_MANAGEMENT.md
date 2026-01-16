# 磁盘管理指南

本文档说明如何在 RockZero OS 中管理磁盘，包括自动挂载、手动挂载和安全关机。

## 功能特性

### 1. 自动挂载
系统启动时自动挂载所有检测到的外部磁盘（不包括 VFAT/FAT 格式的启动分区）。

### 2. 手动挂载
在 UI 界面中点击未挂载的磁盘即可手动挂载。

### 3. 安全关机
关机前自动同步所有数据，确保数据完整性。

### 4. 过滤启动分区
自动过滤 VFAT/FAT32 格式的磁盘（通常是 /boot 分区），避免误操作。

## 系统服务

### 自动挂载服务
```bash
# 查看服务状态
systemctl status rockzero-automount

# 启动服务
systemctl start rockzero-automount

# 停止服务
systemctl stop rockzero-automount

# 启用开机自启
systemctl enable rockzero-automount

# 禁用开机自启
systemctl disable rockzero-automount
```

### 安全关机服务
```bash
# 查看服务状态
systemctl status rockzero-safe-shutdown

# 启用服务（推荐）
systemctl enable rockzero-safe-shutdown

# 禁用服务
systemctl disable rockzero-safe-shutdown
```

## 手动脚本

### 手动挂载所有磁盘
```bash
sudo /opt/rockzero/scripts/auto-mount-disks.sh
```

此脚本会：
- 检测所有未挂载的分区
- 自动识别文件系统类型
- 跳过 VFAT/FAT 格式的启动分区
- 跳过 swap 分区
- 使用合适的挂载选项挂载磁盘
- 设置正确的权限

### 安全关机
```bash
sudo /opt/rockzero/scripts/safe-shutdown.sh
```

此脚本会：
- 停止所有文件操作
- 多次同步文件系统
- 刷新磁盘缓存
- 安全卸载非系统文件系统
- 确保数据完整性

## 支持的文件系统

- **ext4/ext3/ext2**: Linux 原生文件系统（推荐）
- **NTFS**: Windows 文件系统
- **exFAT**: 跨平台文件系统
- **btrfs**: 高级 Linux 文件系统
- **XFS**: 高性能文件系统

## 挂载位置

所有外部磁盘默认挂载到 `/mnt/` 目录下：

- 如果磁盘有标签：`/mnt/<label>`
- 如果磁盘有 UUID：`/mnt/<uuid前8位>`
- 否则：`/mnt/<设备名>`

## UI 界面操作

### 查看磁盘
1. 打开 RockZero OS UI
2. 进入 **Files** 页面
3. 查看 **Storage Devices** 部分

### 挂载磁盘
1. 点击显示 "Not mounted" 的磁盘
2. 在弹出的对话框中点击 **Mount**
3. 等待挂载完成
4. 刷新页面查看挂载结果

### 访问磁盘文件
1. 挂载成功后，磁盘会显示在 Storage Devices 列表中
2. 点击磁盘卡片即可进入文件浏览
3. 可以查看、上传、下载、删除文件

## 数据安全

### 关机前的数据保护
系统关机时会自动执行以下操作：
1. 同步所有文件系统（多次）
2. 刷新所有磁盘缓存
3. 安全卸载外部磁盘
4. 确保所有数据写入完成

### 手动数据同步
如果需要手动同步数据：
```bash
# 同步所有文件系统
sync

# 刷新特定磁盘的缓存
sudo blockdev --flushbufs /dev/sda

# 运行完整的安全关机流程（不关机）
sudo /opt/rockzero/scripts/safe-shutdown.sh
```

## 故障排除

### 磁盘未自动挂载
1. 检查磁盘是否被系统识别：
   ```bash
   lsblk
   ```

2. 检查文件系统类型：
   ```bash
   sudo blkid /dev/sdX1
   ```

3. 手动运行挂载脚本：
   ```bash
   sudo /opt/rockzero/scripts/auto-mount-disks.sh
   ```

4. 查看系统日志：
   ```bash
   journalctl -u rockzero-automount -n 50
   ```

### 磁盘无法卸载
1. 检查是否有进程正在使用：
   ```bash
   sudo lsof /mnt/your-disk
   ```

2. 强制卸载（谨慎使用）：
   ```bash
   sudo umount -l /mnt/your-disk
   ```

### 数据丢失风险
**重要提示**：
- 始终在关机前等待所有文件操作完成
- 不要在文件传输过程中强制断电
- 使用 `safe-shutdown.sh` 脚本确保数据安全
- 定期备份重要数据

## 最佳实践

1. **使用 ext4 文件系统**：在 Linux 系统上性能最佳
2. **定期同步数据**：重要操作后手动运行 `sync`
3. **正确关机**：使用系统关机命令，不要直接断电
4. **监控磁盘健康**：定期检查磁盘 SMART 状态
5. **备份重要数据**：使用多个存储设备备份

## 高级配置

### 自定义挂载选项
编辑 `/opt/rockzero/scripts/auto-mount-disks.sh`，修改 `mount_opts` 变量。

### 自定义挂载位置
编辑脚本中的 `MOUNT_BASE` 变量：
```bash
MOUNT_BASE="/your/custom/path"
```

### 禁用自动挂载
```bash
sudo systemctl disable rockzero-automount
```

### 添加自定义挂载规则
编辑 `/etc/fstab` 添加永久挂载规则：
```
UUID=your-uuid  /mnt/your-disk  ext4  defaults,noatime  0  2
```

## 技术细节

### 挂载选项说明
- **noatime**: 不更新访问时间，提高性能
- **defaults**: 使用默认挂载选项
- **uid/gid**: 设置文件所有者（NTFS/exFAT）
- **umask**: 设置文件权限掩码
- **compress=zstd**: btrfs 压缩（节省空间）

### 安全关机流程
1. 停止文件操作进程
2. 第一次 sync
3. 等待 1 秒
4. 第二次 sync
5. 刷新所有磁盘缓存
6. 卸载非系统文件系统
7. 最终 sync

## 支持

如有问题，请：
1. 查看系统日志：`journalctl -xe`
2. 检查服务状态：`systemctl status rockzero-*`
3. 提交 Issue 到 GitHub 仓库

#!/bin/bash
# Auto-mount script for external disks
# This script automatically mounts all detected non-system disks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Mount directory base
MOUNT_BASE="/mnt"

# Create mount base if it doesn't exist
mkdir -p "$MOUNT_BASE"

# Function to check if a device is already mounted
is_mounted() {
    local device=$1
    mount | grep -q "^$device "
}

# Function to get filesystem type
get_fstype() {
    local device=$1
    blkid -o value -s TYPE "$device" 2>/dev/null || echo "unknown"
}

# Function to get device label
get_label() {
    local device=$1
    blkid -o value -s LABEL "$device" 2>/dev/null || echo ""
}

# Function to get device UUID
get_uuid() {
    local device=$1
    blkid -o value -s UUID "$device" 2>/dev/null || echo ""
}

# Function to mount a device
mount_device() {
    local device=$1
    local fstype=$2
    local label=$3
    local uuid=$4
    
    # Skip if already mounted
    if is_mounted "$device"; then
        log "$device is already mounted"
        return 0
    fi
    
    # Skip VFAT/FAT filesystems (usually boot partitions)
    if [[ "$fstype" == "vfat" ]] || [[ "$fstype" == "fat32" ]] || [[ "$fstype" == "fat16" ]]; then
        warn "Skipping $device (VFAT/FAT filesystem - likely boot partition)"
        return 0
    fi
    
    # Skip swap partitions
    if [[ "$fstype" == "swap" ]]; then
        log "Skipping $device (swap partition)"
        return 0
    fi

    # Skip eMMC boot partitions (mmcblk*boot0, mmcblk*boot1, mmcblk*rpmb)
    local dev_name=$(basename "$device")
    if [[ "$dev_name" == *"boot0"* ]] || [[ "$dev_name" == *"boot1"* ]] || [[ "$dev_name" == *"rpmb"* ]]; then
        warn "Skipping $device (eMMC boot/rpmb partition)"
        return 0
    fi

    # Skip system partitions that might cause issues
    if [[ "$device" == "/dev/mmcblk"*"p1" ]]; then
        # Check if this is likely a boot partition by size (< 512MB)
        local size_sectors=$(cat /sys/class/block/$dev_name/size 2>/dev/null || echo "0")
        local size_bytes=$((size_sectors * 512))
        local size_mb=$((size_bytes / 1024 / 1024))
        if [[ $size_mb -lt 512 ]]; then
            warn "Skipping $device (small partition, likely boot - ${size_mb}MB)"
            return 0
        fi
    fi
    
    # Determine mount point
    local mount_point
    if [[ -n "$label" ]]; then
        mount_point="$MOUNT_BASE/$label"
    elif [[ -n "$uuid" ]]; then
        mount_point="$MOUNT_BASE/${uuid:0:8}"
    else
        local dev_name=$(basename "$device")
        mount_point="$MOUNT_BASE/$dev_name"
    fi
    
    # Create mount point
    mkdir -p "$mount_point"
    
    # Mount options based on filesystem type
    local mount_opts=""
    case "$fstype" in
        ext4|ext3|ext2)
            mount_opts="-o defaults,noatime"
            ;;
        ntfs)
            mount_opts="-o defaults,noatime,uid=1000,gid=1000,umask=022"
            ;;
        exfat)
            mount_opts="-o defaults,noatime,uid=1000,gid=1000,umask=022"
            ;;
        btrfs)
            mount_opts="-o defaults,noatime,compress=zstd"
            ;;
        xfs)
            mount_opts="-o defaults,noatime"
            ;;
        *)
            mount_opts="-o defaults"
            ;;
    esac
    
    # Try to mount
    log "Mounting $device ($fstype) to $mount_point"
    if mount $mount_opts "$device" "$mount_point" 2>/dev/null; then
        log "Successfully mounted $device to $mount_point"
        
        # Set permissions
        chmod 755 "$mount_point"
        
        return 0
    else
        error "Failed to mount $device"
        rmdir "$mount_point" 2>/dev/null || true
        return 1
    fi
}

# Function to sync all mounted filesystems
sync_all() {
    log "Syncing all filesystems..."
    sync
    log "Filesystem sync complete"
}

# Main function
main() {
    log "Starting auto-mount script"
    
    # Get all block devices
    local devices=$(lsblk -nrpo NAME,TYPE,MOUNTPOINT | awk '$2=="part" && $3=="" {print $1}')
    
    if [[ -z "$devices" ]]; then
        log "No unmounted partitions found"
        return 0
    fi
    
    # Mount each device
    local mounted_count=0
    while IFS= read -r device; do
        # Skip if device doesn't exist
        [[ ! -b "$device" ]] && continue
        
        # Get device information
        local fstype=$(get_fstype "$device")
        local label=$(get_label "$device")
        local uuid=$(get_uuid "$device")
        
        # Skip if no filesystem detected
        if [[ "$fstype" == "unknown" ]] || [[ -z "$fstype" ]]; then
            warn "Skipping $device (no filesystem detected)"
            continue
        fi
        
        # Try to mount
        if mount_device "$device" "$fstype" "$label" "$uuid"; then
            ((mounted_count++))
        fi
    done <<< "$devices"
    
    log "Auto-mount complete: $mounted_count device(s) mounted"
    
    # Sync filesystems
    sync_all
}

# Run main function
main "$@"

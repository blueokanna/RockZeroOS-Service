#!/bin/bash
# Safe shutdown script - ensures all data is synced before shutdown
# This script should be called before system shutdown/reboot

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

# Function to sync all filesystems
sync_filesystems() {
    log "Syncing all filesystems..."
    sync
    sleep 1
    sync
    log "Filesystem sync complete"
}

# Function to flush disk caches
flush_caches() {
    log "Flushing disk caches..."
    
    # Flush all block device caches
    for device in /sys/block/*/device; do
        if [[ -e "$device" ]]; then
            local block_dev=$(basename $(dirname "$device"))
            if [[ ! "$block_dev" =~ ^(loop|ram|dm-) ]]; then
                echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
                blockdev --flushbufs "/dev/$block_dev" 2>/dev/null || true
                log "Flushed cache for /dev/$block_dev"
            fi
        fi
    done
    
    log "Cache flush complete"
}

# Function to safely unmount non-system filesystems
safe_unmount() {
    log "Safely unmounting non-system filesystems..."
    
    # Get all mounted filesystems except system ones
    local mounts=$(mount | grep -E "^/dev/(sd|nvme|mmc)" | grep -v " / " | grep -v " /boot " | awk '{print $3}')
    
    if [[ -z "$mounts" ]]; then
        log "No non-system filesystems to unmount"
        return 0
    fi
    
    local unmount_count=0
    while IFS= read -r mount_point; do
        [[ -z "$mount_point" ]] && continue
        
        log "Unmounting $mount_point..."
        
        # Sync before unmount
        sync
        
        # Try to unmount
        if umount "$mount_point" 2>/dev/null; then
            log "Successfully unmounted $mount_point"
            ((unmount_count++))
        else
            warn "Failed to unmount $mount_point (may be in use)"
            
            # Try lazy unmount as fallback
            if umount -l "$mount_point" 2>/dev/null; then
                warn "Lazy unmount successful for $mount_point"
                ((unmount_count++))
            else
                error "Could not unmount $mount_point"
            fi
        fi
    done <<< "$mounts"
    
    log "Unmounted $unmount_count filesystem(s)"
}

# Function to stop any running file operations
stop_file_operations() {
    log "Stopping file operations..."
    
    # Kill any running rsync/cp/mv operations
    pkill -SIGTERM rsync 2>/dev/null || true
    sleep 1
    
    log "File operations stopped"
}

# Main function
main() {
    log "Starting safe shutdown procedure"
    
    # Stop file operations
    stop_file_operations
    
    # Sync filesystems multiple times
    sync_filesystems
    sleep 1
    sync_filesystems
    
    # Flush caches
    flush_caches
    
    # Safely unmount non-system filesystems
    safe_unmount
    
    # Final sync
    sync_filesystems
    
    log "Safe shutdown procedure complete"
    log "System is ready for shutdown/reboot"
}

# Run main function
main "$@"

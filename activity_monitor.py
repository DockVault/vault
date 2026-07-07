"""
Activity Monitoring System
Provides real-time monitoring and tracking of user activities, file transfers, and system operations.
Uses Redis for pub/sub broadcasting and temporary data storage.
"""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from redis import Redis

from database import get_db, redis_client
from models import AuditLog, ActiveSession


class ActivityBroadcaster:
    """
    Broadcasts activity events to all connected WebSocket clients.
    Uses Redis pub/sub for real-time event distribution.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize the activity broadcaster.
        
        Args:
            redis_client: Redis client instance (uses global if None)
        """
        self.redis = redis_client or globals().get('redis_client')
        if not self.redis:
            raise ValueError("Redis client not available")
        self.channel = "activity_events"
    
    def broadcast_sync(self, event: dict):
        """
        Broadcast an event synchronously (for use in non-async contexts).
        
        Args:
            event: Event dictionary to broadcast
        """
        try:
            event_json = json.dumps(event, default=str)
            self.redis.publish(self.channel, event_json)
        except Exception as e:
            print(f"Error broadcasting event: {e}")
    
    async def broadcast(self, event: dict):
        """
        Broadcast an event asynchronously.
        
        Args:
            event: Event dictionary to broadcast
        """
        self.broadcast_sync(event)


class ProgressTracker:
    """
    Tracks file transfer progress using Redis.
    Provides methods to start, update, complete, and cancel operations.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize the progress tracker.
        
        Args:
            redis_client: Redis client instance (uses global if None)
        """
        self.redis = redis_client or globals().get('redis_client')
        if not self.redis:
            raise ValueError("Redis client not available")
        self.broadcaster = ActivityBroadcaster(self.redis)
        self.ttl = 3600  # 1 hour TTL for operation data
    
    def _get_operation_key(self, operation_id: str) -> str:
        """Get Redis key for operation."""
        return f"operation:{operation_id}"
    
    def start_operation(
        self,
        operation_id: str,
        user_id: int,
        username: str,
        operation_type: str,
        file_name: str,
        total_size: int
    ) -> Optional[Dict]:
        """
        Start tracking a new operation.
        
        Args:
            operation_id: Unique operation identifier
            user_id: User performing the operation
            username: Username
            operation_type: "upload" or "download"
            file_name: Name of file being transferred
            total_size: Total file size in bytes
        
        Returns:
            Operation data dict if successful, None otherwise
        """
        try:
            operation = {
                "operation_id": operation_id,
                "user_id": user_id,
                "username": username,
                "type": operation_type,
                "file_name": file_name,
                "total_size": total_size,
                "transferred": 0,
                "progress_pct": 0.0,
                "speed_bps": 0,
                "cancelled": False,
                "status": "in_progress",
                "start_time": time.time(),
                "last_update": time.time()
            }
            
            # Store in Redis
            key = self._get_operation_key(operation_id)
            self.redis.setex(key, self.ttl, json.dumps(operation))
            
            # Broadcast start event
            event = {
                "type": "operation_start",
                "operation_id": operation_id,
                "user_id": user_id,
                "username": username,
                "operation_type": operation_type,
                "file_name": file_name,
                "total_size": total_size,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.broadcaster.broadcast_sync(event)
            
            return operation
            
        except Exception as e:
            print(f"Error starting operation: {e}")
            return None
    
    def update_progress(
        self,
        operation_id: str,
        transferred_bytes: int
    ) -> Optional[Dict]:
        """
        Update operation progress.
        Only broadcasts if progress changed by at least 5%.
        
        Args:
            operation_id: Operation identifier
            transferred_bytes: Total bytes transferred so far
        
        Returns:
            Updated operation data if broadcast, None if throttled
        """
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.get(key)
            
            if not data:
                return None
            
            operation = json.loads(data)
            
            # Calculate progress
            total_size = operation["total_size"]
            old_progress = operation["progress_pct"]
            new_progress = (transferred_bytes / total_size * 100) if total_size > 0 else 0
            
            # Calculate speed
            current_time = time.time()
            time_diff = current_time - operation["last_update"]
            bytes_diff = transferred_bytes - operation["transferred"]
            speed_bps = int(bytes_diff / time_diff) if time_diff > 0 else 0
            
            # Update operation data
            operation["transferred"] = transferred_bytes
            operation["progress_pct"] = new_progress
            operation["speed_bps"] = speed_bps
            operation["last_update"] = current_time
            
            # Store updated data
            self.redis.setex(key, self.ttl, json.dumps(operation))
            
            # Only broadcast if progress changed by at least 5%
            if new_progress - old_progress >= 5.0 or new_progress >= 100:
                event = {
                    "type": "operation_progress",
                    "operation_id": operation_id,
                    "transferred": transferred_bytes,
                    "progress_pct": new_progress,
                    "speed_bps": speed_bps,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                self.broadcaster.broadcast_sync(event)
                return operation
            
            return None  # Throttled
            
        except Exception as e:
            print(f"Error updating progress: {e}")
            return None
    
    def complete_operation(
        self,
        operation_id: str,
        success: bool = True
    ) -> Optional[Dict]:
        """
        Mark operation as complete.
        
        Args:
            operation_id: Operation identifier
            success: Whether operation completed successfully
        
        Returns:
            Final operation data if successful, None otherwise
        """
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.get(key)
            
            if not data:
                return None
            
            operation = json.loads(data)
            operation["status"] = "completed" if success else "failed"
            operation["completed_time"] = time.time()
            
            # Broadcast completion
            event = {
                "type": "operation_complete",
                "operation_id": operation_id,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.broadcaster.broadcast_sync(event)
            
            # Delete from Redis after a short delay (allow clients to receive completion)
            self.redis.delete(key)
            
            return operation
            
        except Exception as e:
            print(f"Error completing operation: {e}")
            return None
    
    def is_cancelled(self, operation_id: str) -> bool:
        """
        Check if operation has been cancelled by admin.
        
        Args:
            operation_id: Operation identifier
        
        Returns:
            True if cancelled, False otherwise
        """
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.get(key)
            
            if not data:
                return False
            
            operation = json.loads(data)
            return operation.get("cancelled", False)
            
        except Exception as e:
            print(f"Error checking cancellation: {e}")
            return False
    
    def cancel_operation(self, operation_id: str, requester_id=None, is_admin=False) -> bool:
        """
        Mark an operation as cancelled.

        Authorization: the caller must OWN the operation (its stored user_id matches
        requester_id) or be an admin — otherwise a user could cancel another principal's
        in-flight transfer via a leaked/guessed operation id.

        Args:
            operation_id: Operation identifier
            requester_id: id of the calling principal (compared to the operation owner)
            is_admin: True bypasses the ownership check

        Returns:
            True if successfully cancelled, False otherwise
        """
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.get(key)

            if not data:
                return False

            operation = json.loads(data)

            # Ownership / admin gate: only the owner or an admin may cancel.
            owner_id = operation.get("user_id")
            if not is_admin and (requester_id is None or str(owner_id) != str(requester_id)):
                return False

            operation["cancelled"] = True
            operation["status"] = "cancelled"

            # Update in Redis
            self.redis.setex(key, self.ttl, json.dumps(operation))

            # Broadcast cancellation
            event = {
                "type": "operation_cancelled",
                "operation_id": operation_id,
                "cancelled_by": str(requester_id) if requester_id else "admin",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.broadcaster.broadcast_sync(event)

            return True
            
        except Exception as e:
            print(f"Error cancelling operation: {e}")
            return False
    
    def get_all_operations(self) -> List[Dict]:
        """
        Get all active operations.
        
        Returns:
            List of operation data dictionaries
        """
        try:
            operations = []
            pattern = "operation:*"
            
            for key in self.redis.scan_iter(match=pattern):
                data = self.redis.get(key)
                if data:
                    operation = json.loads(data)
                    operations.append(operation)
            
            return operations
            
        except Exception as e:
            print(f"Error getting operations: {e}")
            return []
    
    def get_operation(self, operation_id: str) -> Optional[Dict]:
        """
        Get specific operation data.
        
        Args:
            operation_id: Operation identifier
        
        Returns:
            Operation data dict if found, None otherwise
        """
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.get(key)
            
            if data:
                return json.loads(data)
            return None
            
        except Exception as e:
            print(f"Error getting operation: {e}")
            return None


class ActivityStats:
    """
    Aggregates and provides activity statistics.
    Tracks traffic, active users, and system metrics.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize activity stats tracker.
        
        Args:
            redis_client: Redis client instance (uses global if None)
        """
        self.redis = redis_client or globals().get('redis_client')
        if not self.redis:
            raise ValueError("Redis client not available")
        self.ttl = 3600  # 1 hour TTL for stats
    
    def record_traffic(self, bytes_transferred: int, direction: str):
        """
        Record traffic statistics.
        
        Args:
            bytes_transferred: Number of bytes transferred
            direction: "upload" or "download"
        """
        try:
            # Store per-minute granularity
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
            key = f"traffic:{direction}:{timestamp}"
            
            # Increment counter
            self.redis.incr(key, bytes_transferred)
            self.redis.expire(key, self.ttl)
            
        except Exception as e:
            print(f"Error recording traffic: {e}")
    
    def get_traffic_last_hour(self) -> Dict:
        """
        Get aggregated traffic for the last hour.
        
        Returns:
            Dictionary with upload_bytes and download_bytes
        """
        try:
            now = datetime.now(timezone.utc)
            upload_total = 0
            download_total = 0
            
            # Aggregate last 60 minutes
            for minutes_ago in range(60):
                timestamp = (now - timedelta(minutes=minutes_ago)).strftime("%Y%m%d%H%M")
                
                upload_key = f"traffic:upload:{timestamp}"
                download_key = f"traffic:download:{timestamp}"
                
                upload_bytes = self.redis.get(upload_key)
                download_bytes = self.redis.get(download_key)
                
                if upload_bytes:
                    upload_total += int(upload_bytes)
                if download_bytes:
                    download_total += int(download_bytes)
            
            return {
                "upload_bytes": upload_total,
                "download_bytes": download_total,
                "timestamp": now.isoformat()
            }
            
        except Exception as e:
            print(f"Error getting traffic stats: {e}")
            return {"upload_bytes": 0, "download_bytes": 0, "timestamp": None}
    
    def get_active_users_count(self) -> int:
        """
        Get count of active users (sessions active in last 30 minutes).
        
        Returns:
            Number of active users
        """
        try:
            db = next(get_db())
            recent_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            
            count = db.query(ActiveSession).filter(
                ActiveSession.is_active == True,  # type: ignore
                ActiveSession.last_activity >= recent_time
            ).count()
            
            return count
            
        except Exception as e:
            print(f"Error getting active users: {e}")
            return 0

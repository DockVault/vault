"""
Activity Monitoring System
Provides real-time monitoring and tracking of user activities, file transfers, and system operations.
Uses Redis for pub/sub broadcasting and temporary data storage.
"""
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict
from redis import Redis

from database import redis_client


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
    

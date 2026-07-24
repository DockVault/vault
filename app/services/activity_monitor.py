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

from app.core.database import redis_client


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
        total_size: int,
        temp_credential_id: Optional[str] = None,
        vault_id: Optional[str] = None,
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
                "temp_credential_id": (
                    str(temp_credential_id) if temp_credential_id is not None else None
                ),
                "vault_id": str(vault_id) if vault_id is not None else None,
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
        """Atomically transition a live operation to completed or failed."""
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.eval(
                """
                local raw = redis.call('GET', KEYS[1])
                if not raw then return false end
                local operation = cjson.decode(raw)
                if operation['status'] ~= 'in_progress'
                    or operation['cancelled'] == true then
                    return false
                end
                operation['status'] = ARGV[1]
                operation['completed_time'] = tonumber(ARGV[2])
                local encoded = cjson.encode(operation)
                redis.call('DEL', KEYS[1])
                return encoded
                """,
                1,
                key,
                "completed" if success else "failed",
                str(time.time()),
            )
            if not data:
                return None
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            operation = json.loads(data)

            event = {
                "type": "operation_complete",
                "operation_id": operation_id,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.broadcaster.broadcast_sync(event)
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
    
    def cancel_operation(
        self,
        operation_id: str,
        requester_id=None,
        requester_temp_credential_id=None,
        is_admin=False,
    ) -> bool:
        """Atomically cancel a live operation for its exact principal or a full admin."""
        try:
            key = self._get_operation_key(operation_id)
            data = self.redis.eval(
                """
                local raw = redis.call('GET', KEYS[1])
                if not raw then return false end
                local operation = cjson.decode(raw)
                if operation['status'] ~= 'in_progress'
                    or operation['cancelled'] == true then
                    return false
                end
                if ARGV[3] ~= '1' then
                    if ARGV[1] == '' or tostring(operation['user_id']) ~= ARGV[1] then
                        return false
                    end
                    local owner_credential = operation['temp_credential_id']
                    if owner_credential == nil or owner_credential == cjson.null then
                        owner_credential = ''
                    else
                        owner_credential = tostring(owner_credential)
                    end
                    if owner_credential ~= ARGV[2] then return false end
                end
                operation['cancelled'] = true
                operation['status'] = 'cancelled'
                operation['cancelled_time'] = tonumber(ARGV[5])
                local encoded = cjson.encode(operation)
                redis.call('SETEX', KEYS[1], tonumber(ARGV[4]), encoded)
                return encoded
                """,
                1,
                key,
                str(requester_id) if requester_id is not None else "",
                (
                    str(requester_temp_credential_id)
                    if requester_temp_credential_id is not None
                    else ""
                ),
                "1" if is_admin else "0",
                str(self.ttl),
                str(time.time()),
            )
            if not data:
                return False

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

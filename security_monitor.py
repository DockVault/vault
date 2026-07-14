"""
Real-time Security Monitoring and Alerting System

Monitors security events and detects suspicious patterns:
- Failed login attempts
- Rate limit violations
- Unusual access patterns
- Bulk file operations
- Rapid file deletions
- Multiple vault access attempts

Provides alerts through multiple channels:
- Logging (always enabled)
- Email notifications (configurable)
- Webhook notifications (configurable)
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from collections import defaultdict, deque
import time
import logging
import json

from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

from models import AuditLog, User, SecurityAlert
from database import redis_client
from config import settings

logger = logging.getLogger(__name__)

# Process-wide throttle for the "threat detection degraded" alert (see _signal_detection_degraded):
# emit at most once per cooldown window per process during a Redis outage.
_last_degraded_signal_at = 0.0


def _sanitize_for_log(value: Optional[str], max_len: int = 256) -> Optional[str]:
    """Neutralise a user-controlled value before it is embedded in a persisted SecurityAlert
    message/field (returned by the admin alerts API) or written to a log line. Strips control
    characters — including CR/LF, so a value can't forge log lines (CWE-117) — and bounds the
    length. Angle brackets are rejected at the input boundary (LoginRequest / UserCreate); this is
    the sink-side defence covering every ingress path."""
    if value is None:
        return value
    s = ''.join(ch for ch in str(value) if ch.isprintable())
    if len(s) > max_len:
        s = s[:max_len] + '...'
    return s


class SecurityEventType:
    """Security event type constants."""
    FAILED_LOGIN = "failed_login"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MULTIPLE_FAILED_LOGINS = "multiple_failed_logins"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    SUSPICIOUS_DOWNLOAD = "suspicious_download"
    BULK_FILE_DELETION = "bulk_file_deletion"
    RAPID_VAULT_ACCESS = "rapid_vault_access"
    ACCOUNT_LOCKOUT = "account_lockout"
    UNUSUAL_ACCESS_PATTERN = "unusual_access_pattern"
    # Raised when the durable Redis event counter is unavailable, so threshold-based detection
    # (brute-force / bulk-operation) is effectively blind -- operators must see this.
    DETECTION_DEGRADED = "detection_degraded"


class SecurityAlertLevel:
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class SecurityMonitor:
    """
    Real-time security monitoring and alerting.
    
    Features:
    - Pattern detection
    - Threshold-based alerting
    - Historical analysis
    - Real-time metrics
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.redis = redis_client
        
        # Thresholds (configurable via settings)
        self.failed_login_threshold_warning = getattr(settings, 'security_failed_login_warning', 5)
        self.failed_login_threshold_critical = getattr(settings, 'security_failed_login_critical', 10)
        self.failed_login_window_minutes = getattr(settings, 'security_failed_login_window', 10)
        
        self.rate_limit_threshold_warning = getattr(settings, 'security_rate_limit_warning', 5)
        self.rate_limit_threshold_critical = getattr(settings, 'security_rate_limit_critical', 10)

        # Alert dedup/cooldown: within this window, repeats of the same (event_type, username,
        # ip_address) collapse into one row (bumping a repeat counter) instead of flooding the table.
        self.alert_cooldown_seconds = getattr(settings, 'security_alert_cooldown_seconds', 300)
        
        self.bulk_deletion_threshold = getattr(settings, 'security_bulk_deletion_threshold', 10)
        self.bulk_deletion_window_seconds = getattr(settings, 'security_bulk_deletion_window', 60)
        
        self.rapid_vault_access_threshold = getattr(settings, 'security_rapid_vault_threshold', 5)
        self.rapid_vault_access_window_seconds = getattr(settings, 'security_rapid_vault_window', 30)
        
        # In-memory tracking for performance
        self._login_attempts = defaultdict(lambda: deque(maxlen=100))
        self._rate_limit_violations = defaultdict(int)
        self._file_deletions = defaultdict(lambda: deque(maxlen=100))
        self._vault_accesses = defaultdict(lambda: deque(maxlen=100))
    
    # ========================================================================
    # Event Recording
    # ========================================================================
    
    def record_failed_login(self, username: str, ip_address: str, reason: str):
        """
        Record a failed login attempt and check for suspicious patterns.
        
        Args:
            username: Username attempted
            ip_address: Source IP address
            reason: Failure reason
        """
        now = time.time()
        identifier = f"{username}:{ip_address}"

        # Keep an in-memory trail purely as a Redis-outage fallback (see _windowed_count).
        self._login_attempts[identifier].append(now)

        # Threshold decision reads the DURABLE Redis counter (shared across the per-request
        # monitor instances), not the fresh in-memory deque — otherwise it would always see 1.
        recent_attempts = self._windowed_count(
            f"security:failed_login:{identifier}",
            self.failed_login_window_minutes * 60,
            self._login_attempts[identifier],
        )

        # Counting above keyed off the raw values; from here on only embed sanitized copies in the
        # persisted alert record and the logs (a CRLF-carrying username must not forge log lines or
        # ride into the admin alerts JSON).
        username = _sanitize_for_log(username)
        ip_address = _sanitize_for_log(ip_address)

        if recent_attempts >= self.failed_login_threshold_critical:
            self._raise_alert(
                event_type=SecurityEventType.BRUTE_FORCE_ATTEMPT,
                severity=SecurityAlertLevel.CRITICAL,
                username=username,
                ip_address=ip_address,
                details={
                    'attempts': recent_attempts,
                    'window_minutes': self.failed_login_window_minutes,
                    'reason': reason
                },
                message=f"CRITICAL: Brute force attack detected - {recent_attempts} failed login attempts for {username} from {ip_address} in {self.failed_login_window_minutes} minutes"
            )
        elif recent_attempts >= self.failed_login_threshold_warning:
            self._raise_alert(
                event_type=SecurityEventType.MULTIPLE_FAILED_LOGINS,
                severity=SecurityAlertLevel.WARNING,
                username=username,
                ip_address=ip_address,
                details={
                    'attempts': recent_attempts,
                    'window_minutes': self.failed_login_window_minutes,
                    'reason': reason
                },
                message=f"WARNING: Multiple failed login attempts - {recent_attempts} failures for {username} from {ip_address}"
            )
        
        logger.info(f"Failed login recorded: {username} from {ip_address} ({recent_attempts} recent attempts)")
    
    def record_rate_limit_violation(self, identifier: str, ip_address: str, endpoint: str):
        """
        Record a rate limit violation.
        
        Args:
            identifier: User identifier or IP
            ip_address: Source IP address
            endpoint: API endpoint that was rate limited
        """
        self._rate_limit_violations[identifier] += 1
        
        # Store in Redis
        redis_key = f"security:rate_limit:{identifier}"
        count = self.redis.incr(redis_key)
        self.redis.expire(redis_key, 3600)  # 1 hour

        # The counter above used the raw identifier as its key; sanitize before embedding these
        # caller-controlled values in the persisted alert + logs.
        identifier = _sanitize_for_log(identifier)
        ip_address = _sanitize_for_log(ip_address)
        endpoint = _sanitize_for_log(endpoint)

        if count >= self.rate_limit_threshold_critical:
            self._raise_alert(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=SecurityAlertLevel.CRITICAL,
                ip_address=ip_address,
                details={
                    'violations': count,
                    'endpoint': endpoint,
                    'identifier': identifier
                },
                message=f"CRITICAL: Excessive rate limit violations - {count} violations from {ip_address} (endpoint: {endpoint})"
            )
        elif count >= self.rate_limit_threshold_warning:
            self._raise_alert(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=SecurityAlertLevel.WARNING,
                ip_address=ip_address,
                details={
                    'violations': count,
                    'endpoint': endpoint,
                    'identifier': identifier
                },
                message=f"WARNING: Rate limit violations detected - {count} violations from {ip_address}"
            )
        
        logger.info(f"Rate limit violation recorded: {identifier} from {ip_address} at {endpoint}")
    
    def record_file_deletion(self, user_id: str, vault_id: str, file_count: int = 1):
        """
        Record file deletion and detect bulk deletion patterns.
        
        Args:
            user_id: User performing deletion
            vault_id: Vault ID
            file_count: Number of files deleted (default 1)
        """
        now = time.time()
        identifier = f"{user_id}:{vault_id}"

        # In-memory trail is only the Redis-outage fallback (see _windowed_count).
        for _ in range(file_count):
            self._file_deletions[identifier].append(now)

        # Durable, cross-request window count (Redis) — a fresh per-request deque never trips.
        recent_deletions = self._windowed_count(
            f"security:file_deletion:{identifier}",
            self.bulk_deletion_window_seconds,
            self._file_deletions[identifier],
            amount=file_count,
        )

        if recent_deletions >= self.bulk_deletion_threshold:
            self._raise_alert(
                event_type=SecurityEventType.BULK_FILE_DELETION,
                severity=SecurityAlertLevel.WARNING,
                user_id=user_id,
                details={
                    'deletions': recent_deletions,
                    'vault_id': vault_id,
                    'window_seconds': self.bulk_deletion_window_seconds
                },
                message=f"WARNING: Bulk file deletion detected - {recent_deletions} files deleted from vault {vault_id} by user {user_id} in {self.bulk_deletion_window_seconds} seconds"
            )
        
        logger.info(f"File deletion recorded: {file_count} file(s) from vault {vault_id} by user {user_id}")
    
    def record_vault_access(self, user_id: str, vault_id: str, action: str):
        """
        Record vault access and detect rapid access patterns.
        
        Args:
            user_id: User accessing vault
            vault_id: Vault ID
            action: Action performed (open, read, write, etc.)
        """
        now = time.time()
        identifier = f"{user_id}:{vault_id}"

        # In-memory trail is only the Redis-outage fallback (see _windowed_count).
        self._vault_accesses[identifier].append(now)

        # Durable, cross-request window count (Redis) — a fresh per-request deque never trips.
        recent_accesses = self._windowed_count(
            f"security:vault_access:{identifier}",
            self.rapid_vault_access_window_seconds,
            self._vault_accesses[identifier],
        )

        if recent_accesses >= self.rapid_vault_access_threshold:
            self._raise_alert(
                event_type=SecurityEventType.RAPID_VAULT_ACCESS,
                severity=SecurityAlertLevel.INFO,
                user_id=user_id,
                details={
                    'accesses': recent_accesses,
                    'vault_id': vault_id,
                    'action': action,
                    'window_seconds': self.rapid_vault_access_window_seconds
                },
                message=f"INFO: Rapid vault access detected - {recent_accesses} accesses to vault {vault_id} by user {user_id} in {self.rapid_vault_access_window_seconds} seconds"
            )
        
        logger.debug(f"Vault access recorded: {action} on vault {vault_id} by user {user_id}")
    
    # ========================================================================
    # Analysis and Detection
    # ========================================================================
    
    def _count_recent_events(self, event_deque: deque, window_seconds: int) -> int:
        """Count events within the time window."""
        now = time.time()
        cutoff = now - window_seconds
        return sum(1 for timestamp in event_deque if timestamp >= cutoff)

    def _windowed_count(self, redis_key: str, window_seconds: int, fallback_deque: deque, amount: int = 1) -> int:
        """Return the count of events in the current window from a shared Redis counter.

        The threshold checks below MUST NOT read the per-instance in-memory deques: the monitor
        is re-instantiated on every request (get_security_monitor returns a fresh SecurityMonitor
        so its DB session stays request-scoped and thread-safe), so those deques only ever hold the
        single event from THIS request and the thresholds could never trip. The durable count lives
        in Redis, incremented once here per event with a window TTL. If Redis is unavailable we fall
        back to the in-memory deque count (degrading to at-most-this-request rather than raising and
        breaking the calling auth/delete path)."""
        try:
            count = self.redis.incrby(redis_key, amount)
            # Set the TTL only when THIS increment created the key (its value equals the amount we
            # just added) -> a true FIXED window that expires window_seconds after the FIRST event.
            # Re-asserting the TTL on every hit would make it a "since the last event" window that
            # over-counts events spaced wider than the window (false-positive alerts).
            if count == amount:
                self.redis.expire(redis_key, window_seconds)
            return int(count)
        except Exception as e:
            logger.warning(f"Security monitor Redis counter unavailable ({redis_key}): {e}; using in-memory fallback")
            # The in-memory deque only holds THIS request's events (the monitor is per-request), so
            # thresholds can no longer trip -> detection is effectively blind. Surface that to operators.
            self._signal_detection_degraded()
            return self._count_recent_events(fallback_deque, window_seconds)
    
    def analyze_user_activity(self, user_id: str, hours: int = 24) -> Dict[str, Any]:
        """
        Analyze a user's activity for unusual patterns.
        
        Args:
            user_id: User ID to analyze
            hours: Number of hours to analyze
            
        Returns:
            Analysis results dictionary
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Query audit logs
        logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= cutoff
            )
        ).all()
        
        # Analyze patterns
        analysis = {
            'user_id': user_id,
            'period_hours': hours,
            'total_actions': len(logs),
            'actions_by_type': defaultdict(int),
            'actions_by_hour': defaultdict(int),
            'failed_actions': 0,
            'ip_addresses': set(),
            'vaults_accessed': set(),
            'anomalies': []
        }
        
        for log in logs:
            analysis['actions_by_type'][log.action] += 1
            analysis['actions_by_hour'][log.timestamp.hour] += 1
            
            if log.status == 'failure':
                analysis['failed_actions'] += 1
            
            if log.ip_address:
                analysis['ip_addresses'].add(log.ip_address)
            
            if log.resource_type == 'vault' and log.resource_id:
                analysis['vaults_accessed'].add(log.resource_id)
        
        # Convert sets to lists for JSON serialization
        analysis['ip_addresses'] = list(analysis['ip_addresses'])
        analysis['vaults_accessed'] = list(analysis['vaults_accessed'])
        analysis['actions_by_type'] = dict(analysis['actions_by_type'])
        analysis['actions_by_hour'] = dict(analysis['actions_by_hour'])
        
        # Detect anomalies
        if analysis['failed_actions'] > 10:
            analysis['anomalies'].append({
                'type': 'high_failure_rate',
                'severity': 'warning',
                'message': f"High failure rate: {analysis['failed_actions']} failed actions"
            })
        
        if len(analysis['ip_addresses']) > 5:
            analysis['anomalies'].append({
                'type': 'multiple_ips',
                'severity': 'info',
                'message': f"Activity from {len(analysis['ip_addresses'])} different IP addresses"
            })
        
        # Check for unusual activity hours (late night/early morning)
        night_activity = sum(
            count for hour, count in analysis['actions_by_hour'].items()
            if hour < 6 or hour > 22
        )
        if night_activity > analysis['total_actions'] * 0.3:  # More than 30% at night
            analysis['anomalies'].append({
                'type': 'unusual_hours',
                'severity': 'info',
                'message': f"Significant activity during unusual hours ({night_activity} actions)"
            })
        
        return analysis
    
    def get_security_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security metrics for dashboard display.
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Metrics dictionary
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Query recent security events from audit log
        failed_logins = self.db.query(AuditLog).filter(
            and_(
                AuditLog.action == 'login_failure',
                AuditLog.timestamp >= cutoff
            )
        ).count()
        
        successful_logins = self.db.query(AuditLog).filter(
            and_(
                AuditLog.action == 'login_success',
                AuditLog.timestamp >= cutoff
            )
        ).count()
        
        # Query security alerts
        critical_alerts = self.db.query(SecurityAlert).filter(
            and_(
                SecurityAlert.severity == SecurityAlertLevel.CRITICAL,
                SecurityAlert.timestamp >= cutoff,
                SecurityAlert.resolved == False
            )
        ).count()
        
        warning_alerts = self.db.query(SecurityAlert).filter(
            and_(
                SecurityAlert.severity == SecurityAlertLevel.WARNING,
                SecurityAlert.timestamp >= cutoff,
                SecurityAlert.resolved == False
            )
        ).count()
        
        # Get top failed login IPs
        failed_login_logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.action == 'login_failure',
                AuditLog.timestamp >= cutoff
            )
        ).all()
        
        ip_failures = defaultdict(int)
        for log in failed_login_logs:
            if log.ip_address:
                ip_failures[log.ip_address] += 1
        
        top_failed_ips = sorted(
            ip_failures.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'period_hours': hours,
            'failed_logins': failed_logins,
            'successful_logins': successful_logins,
            'login_success_rate': round(
                successful_logins / (successful_logins + failed_logins) * 100, 2
            ) if (successful_logins + failed_logins) > 0 else 0,
            'critical_alerts': critical_alerts,
            'warning_alerts': warning_alerts,
            'total_alerts': critical_alerts + warning_alerts,
            'top_failed_ips': [
                {'ip': ip, 'count': count}
                for ip, count in top_failed_ips
            ]
        }
    
    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[SecurityAlert]:
        """
        Get recent security alerts.
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (optional)
            
        Returns:
            List of SecurityAlert objects
        """
        query = self.db.query(SecurityAlert)
        
        if severity:
            query = query.filter(SecurityAlert.severity == severity)
        
        alerts = query.order_by(desc(SecurityAlert.timestamp)).limit(limit).all()
        
        return alerts
    
    # ========================================================================
    # Alert Management
    # ========================================================================
    
    def _raise_alert(
        self,
        event_type: str,
        severity: str,
        message: str,
        username: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Raise a security alert.
        
        Args:
            event_type: Type of security event
            severity: Alert severity level
            message: Alert message
            username: Username involved (optional)
            user_id: User ID involved (optional)
            ip_address: IP address involved (optional)
            details: Additional details dictionary
        """
        # Dedup / cooldown: within the cooldown window, collapse a repeat of the SAME
        # (event_type, username, ip_address) into the existing alert -- bump a repeat counter instead
        # of inserting a new row -- so a sustained attack can't flood the alerts table or bury real
        # alerts. WARNING and CRITICAL use distinct event_types, so an escalation still opens its own
        # alert rather than being hidden inside a lower-severity row.
        try:
            since = datetime.now(timezone.utc) - timedelta(seconds=self.alert_cooldown_seconds)
            existing = self.db.query(SecurityAlert).filter(
                SecurityAlert.event_type == event_type,
                SecurityAlert.severity == severity,       # a CRITICAL escalation must open its OWN row,
                                                          # even when a path reuses one event_type for both
                SecurityAlert.username == username,
                SecurityAlert.ip_address == ip_address,
                SecurityAlert.user_id == user_id,         # events keyed by user_id (bulk-delete / rapid
                                                          # vault access) set no username/ip -> without this
                                                          # they'd all share a (type, NULL, NULL) key and
                                                          # collapse DIFFERENT users into one row
                SecurityAlert.resolved == False,          # never fold repeats into an already-resolved
                                                          # alert -> a renewed attack raises a fresh one
                SecurityAlert.timestamp >= since,
            ).order_by(SecurityAlert.timestamp.desc()).first()
        except Exception:
            self.db.rollback()
            existing = None
        if existing is not None:
            try:
                d = dict(existing.details or {})
                d['repeat_count'] = int(d.get('repeat_count', 1)) + 1
                d['last_repeat'] = datetime.now(timezone.utc).isoformat()
                existing.details = d
                self.db.commit()
            except Exception:
                self.db.rollback()
            return existing

        # Create alert in database
        alert = SecurityAlert(
            event_type=event_type,
            severity=severity,
            message=message,
            username=username,
            user_id=user_id,
            ip_address=ip_address,
            details=details or {},
            timestamp=datetime.now(timezone.utc),
            resolved=False
        )
        
        self.db.add(alert)
        self.db.commit()
        
        # Log the alert
        log_method = {
            SecurityAlertLevel.INFO: logger.info,
            SecurityAlertLevel.WARNING: logger.warning,
            SecurityAlertLevel.CRITICAL: logger.critical
        }.get(severity, logger.info)
        
        log_method(f"SECURITY ALERT [{severity.upper()}] {event_type}: {message}")
        
        # TODO: Send email notification if configured
        # TODO: Send webhook notification if configured
        
        # Broadcast to monitoring dashboard via Redis pub/sub
        self._broadcast_alert(alert)
        return alert

    def _signal_detection_degraded(self) -> None:
        """Emit a (deduped) WARNING so operators know threat detection is running BLIND: with the
        Redis event counter unavailable, the per-request in-memory fallback can never reach a
        brute-force / bulk-operation threshold, so those alerts silently stop firing. Best-effort:
        never let the degraded signal break the calling auth/delete path."""
        # Process-wide throttle: during a Redis outage EVERY request hits _windowed_count's fallback,
        # and each call here would be a SELECT+UPDATE+COMMIT contending on one hot alert row. Emit at
        # most once per cooldown window PER PROCESS (the _raise_alert DB dedup still collapses the row
        # across processes) so a high-volume outage doesn't hammer the DB.
        global _last_degraded_signal_at
        now = time.monotonic()  # interval throttle -> monotonic, immune to NTP / wall-clock steps
        if now - _last_degraded_signal_at < self.alert_cooldown_seconds:
            return
        try:
            self._raise_alert(
                event_type=SecurityEventType.DETECTION_DEGRADED,
                severity=SecurityAlertLevel.WARNING,
                message=("Threat detection degraded: the Redis event counter is unavailable, so "
                         "brute-force / bulk-operation thresholds cannot be evaluated. Preventive "
                         "controls (account lockout, rate-limit DB fallback) still apply."),
                details={'reason': 'redis_counter_unavailable'},
            )
            # Advance the throttle only AFTER a successful emit, so a transient DB failure during the
            # outage retries on the next fallback request rather than suppressing the operator's
            # "detection blind" signal for a whole cooldown window.
            _last_degraded_signal_at = now
        except Exception:
            try:
                self.db.rollback()
            except Exception:
                pass

    def _broadcast_alert(self, alert: SecurityAlert):
        """Broadcast alert to monitoring dashboard."""
        try:
            alert_data = {
                'id': str(alert.id),
                'event_type': alert.event_type,
                'severity': alert.severity,
                'message': alert.message,
                'username': alert.username,
                'ip_address': alert.ip_address,
                'timestamp': alert.timestamp.isoformat(),
                'details': alert.details
            }
            
            self.redis.publish('security_alerts', json.dumps(alert_data))
        except Exception as e:
            logger.error(f"Failed to broadcast security alert: {e}")
    
    def resolve_alert(self, alert_id: str, resolved_by: str, notes: Optional[str] = None):
        """
        Mark a security alert as resolved.
        
        Args:
            alert_id: Alert ID
            resolved_by: Username resolving the alert
            notes: Resolution notes (optional)
        """
        alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        
        if alert:
            alert.resolved = True
            alert.resolved_by = resolved_by
            alert.resolved_at = datetime.now(timezone.utc)
            alert.resolution_notes = notes
            
            self.db.commit()
            
            logger.info(f"Security alert {alert_id} resolved by {resolved_by}")
    
    # ========================================================================
    # Cleanup
    # ========================================================================
    
    def cleanup_old_alerts(self, days: int = 90):
        """
        Clean up old resolved alerts.
        
        Args:
            days: Keep alerts from last N days
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        deleted = self.db.query(SecurityAlert).filter(
            and_(
                SecurityAlert.resolved == True,
                SecurityAlert.timestamp < cutoff
            )
        ).delete()
        
        self.db.commit()
        
        logger.info(f"Cleaned up {deleted} old security alerts")
        
        return deleted


# Global security monitor instance (initialized with db session when needed)
_security_monitor_instance = None


def get_security_monitor(db: Session) -> SecurityMonitor:
    """Get or create security monitor instance."""
    return SecurityMonitor(db)

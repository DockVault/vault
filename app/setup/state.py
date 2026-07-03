"""
Setup Wizard State Management

Provides robust, atomic state management for the setup wizard.

Features:
- JSON-based state persistence
- Atomic file updates (write-to-temp, then rename)
- Validation checkpoints
- Error recovery
- Progress tracking
- Idempotent operations
- Thread-safe (file locking)

This ensures the wizard can recover from any failure without corruption.
"""
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from enum import Enum
import tempfile
import shutil
from contextlib import contextmanager
import threading

# Platform-specific imports for file locking
if sys.platform == 'win32':
    import msvcrt
else:
    import fcntl


class WizardStep(Enum):
    """Setup wizard steps in order.

    NOTE: the free build has NO license/product-key step — onboarding must complete
    without a key (community/unlimited, nothing enforced). State files written by
    older builds may still carry a "license" entry; the readers below skip step
    names that no longer exist instead of raising.
    """
    WELCOME = "welcome"
    DATABASE = "database"
    REDIS = "redis"
    SECURITY = "security"
    ADMIN = "admin"
    STORAGE = "storage"
    BRANDING = "branding"
    REVIEW = "review"
    COMPLETE = "complete"


class StepStatus(Enum):
    """Status of each wizard step."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class SetupWizardState:
    """
    Manages setup wizard state with robust persistence.
    
    Ensures state is never corrupted even if:
    - Process crashes
    - Disk is full
    - Network disconnects
    - User closes browser
    
    Uses atomic file operations and file locking for safety.
    """
    
    def __init__(self, state_file: str = None):
        """
        Initialize state manager.

        Args:
            state_file: Path to state file. Defaults to $SETUP_STATE_FILE, else
                "setup_state.json" (relative to app root). The env override lets a
                read-only-root-fs deployment point it at a writable/persistent path
                without changing the app-root default.
        """
        if state_file is None:
            state_file = os.environ.get("SETUP_STATE_FILE", "setup_state.json")
        self.state_file = Path(state_file)
        self.lock_file = Path(f"{state_file}.lock")
        self._ensure_state_file()
    
    # ============================================================
    # State File Management
    # ============================================================
    
    def _ensure_state_file(self):
        """Create state file with defaults if it doesn't exist."""
        if not self.state_file.exists():
            default_state = self._get_default_state()
            self._write_state_atomic(default_state)
    
    def _get_default_state(self) -> Dict[str, Any]:
        """
        Get default initial state.
        
        Returns:
            Dictionary with initial wizard state
        """
        return {
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "current_step": WizardStep.WELCOME.value,
            "completed_steps": [],
            "steps": {
                step.value: {
                    "status": StepStatus.NOT_STARTED.value,
                    "data": {},
                    "validation_errors": [],
                    "last_updated": None,
                    "attempt_count": 0
                }
                for step in WizardStep
            },
            "errors": [],
            "warnings": [],
            "metadata": {}
        }
    
    @contextmanager
    def _lock_file(self):
        """
        Context manager for file locking (cross-platform).
        
        Ensures only one process can modify state at a time.
        Works on both Windows and Unix systems.
        """
        lock_fd = None
        try:
            # Create/open lock file
            lock_fd = os.open(str(self.lock_file), os.O_CREAT | os.O_RDWR)
            
            # Acquire exclusive lock (platform-specific)
            if sys.platform == 'win32':
                # Windows file locking
                msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            else:
                # Unix file locking
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            
            yield
            
        finally:
            # Release lock
            if lock_fd is not None:
                if sys.platform == 'win32':
                    # Windows unlock
                    try:
                        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
                    except:
                        pass
                else:
                    # Unix unlock
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except:
                        pass
                
                os.close(lock_fd)
                
                # Clean up lock file
                try:
                    self.lock_file.unlink()
                except:
                    pass
    
    def _write_state_atomic(self, state: Dict[str, Any]):
        """
        Write state atomically using temp file + rename.
        
        This ensures state file is never corrupted, even if:
        - Process crashes during write
        - Disk becomes full
        - System loses power
        
        Args:
            state: State dictionary to write
        """
        # Update timestamp
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=".json",
            prefix="setup_state_",
            dir=self.state_file.parent
        )
        
        try:
            with os.fdopen(temp_fd, 'w') as f:
                json.dump(state, f, indent=2)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            
            # Atomic rename (overwrites existing file)
            # This is atomic on POSIX systems
            shutil.move(temp_path, self.state_file)
            
        except Exception as e:
            # Clean up temp file on error
            try:
                os.unlink(temp_path)
            except:
                pass
            raise e
    
    def _read_state(self) -> Dict[str, Any]:
        """
        Read current state from file.
        
        Returns:
            State dictionary
        """
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            # If state file is corrupted, return default state
            return self._get_default_state()
    
    # ============================================================
    # State Access Methods
    # ============================================================
    
    def get_state(self) -> Dict[str, Any]:
        """
        Get complete current state (thread-safe).
        
        Returns:
            Full state dictionary
        """
        with self._lock_file():
            return self._read_state()
    
    def get_current_step(self) -> WizardStep:
        """
        Get current wizard step.
        
        Returns:
            Current WizardStep enum
        """
        state = self.get_state()
        try:
            return WizardStep(state["current_step"])
        except ValueError:
            # State file from an older build (e.g. current_step "license", a step
            # that no longer exists) — restart from the beginning rather than 500.
            return WizardStep.WELCOME
    
    def get_step_data(self, step: WizardStep) -> Dict[str, Any]:
        """
        Get data for specific step.
        
        Args:
            step: WizardStep enum
            
        Returns:
            Step data dictionary
        """
        state = self.get_state()
        return state["steps"][step.value]["data"]
    
    def get_step_status(self, step: WizardStep) -> StepStatus:
        """
        Get status of specific step.
        
        Args:
            step: WizardStep enum
            
        Returns:
            StepStatus enum
        """
        state = self.get_state()
        return StepStatus(state["steps"][step.value]["status"])
    
    def get_completed_steps(self) -> List[WizardStep]:
        """
        Get list of completed steps.
        
        Returns:
            List of WizardStep enums
        """
        state = self.get_state()
        known = {m.value for m in WizardStep}
        return [WizardStep(s) for s in state["completed_steps"] if s in known]
    
    def get_progress_percentage(self) -> float:
        """
        Calculate overall progress percentage.
        
        Returns:
            Progress as float (0.0 to 100.0)
        """
        total_steps = len(WizardStep)
        completed = len(self.get_completed_steps())
        return (completed / total_steps) * 100
    
    # ============================================================
    # State Mutation Methods
    # ============================================================
    
    def set_current_step(self, step: WizardStep):
        """
        Set current wizard step (thread-safe).
        
        Args:
            step: WizardStep enum to set as current
        """
        with self._lock_file():
            state = self._read_state()
            state["current_step"] = step.value
            self._write_state_atomic(state)
    
    def update_step_data(
        self,
        step: WizardStep,
        data: Dict[str, Any],
        status: Optional[StepStatus] = None
    ):
        """
        Update data for specific step (thread-safe).
        
        This is idempotent - can be called multiple times safely.
        
        Args:
            step: WizardStep enum
            data: Data dictionary to merge with existing data
            status: Optional new status for the step
        """
        with self._lock_file():
            state = self._read_state()
            
            step_state = state["steps"][step.value]
            
            # Merge data (don't replace, merge)
            step_state["data"].update(data)
            
            # Update status if provided
            if status:
                step_state["status"] = status.value
            
            # Update timestamp
            step_state["last_updated"] = datetime.now(timezone.utc).isoformat()
            
            # Increment attempt counter
            step_state["attempt_count"] += 1
            
            self._write_state_atomic(state)
    
    def mark_step_completed(self, step: WizardStep):
        """
        Mark step as completed and advance to next step.
        
        Args:
            step: WizardStep enum to mark complete
        """
        with self._lock_file():
            state = self._read_state()
            
            # Mark step completed
            state["steps"][step.value]["status"] = StepStatus.COMPLETED.value
            
            # Add to completed list if not already there
            if step.value not in state["completed_steps"]:
                state["completed_steps"].append(step.value)
            
            # Clear errors for this step
            state["steps"][step.value]["validation_errors"] = []
            
            # Advance to next step if not at end
            current_step_index = list(WizardStep).index(step)
            if current_step_index < len(WizardStep) - 1:
                next_step = list(WizardStep)[current_step_index + 1]
                state["current_step"] = next_step.value
            
            self._write_state_atomic(state)
    
    def mark_step_failed(
        self,
        step: WizardStep,
        errors: List[str]
    ):
        """
        Mark step as failed with error messages.
        
        Args:
            step: WizardStep enum
            errors: List of error messages
        """
        with self._lock_file():
            state = self._read_state()
            
            state["steps"][step.value]["status"] = StepStatus.FAILED.value
            state["steps"][step.value]["validation_errors"] = errors
            
            # Add to global errors list
            state["errors"].extend([
                {
                    "step": step.value,
                    "message": error,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                for error in errors
            ])
            
            self._write_state_atomic(state)
    
    def add_warning(self, step: WizardStep, message: str):
        """
        Add warning message for a step.
        
        Args:
            step: WizardStep enum
            message: Warning message
        """
        with self._lock_file():
            state = self._read_state()
            
            state["warnings"].append({
                "step": step.value,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            self._write_state_atomic(state)
    
    def reset_step(self, step: WizardStep):
        """
        Reset a step to initial state (for retry).
        
        Args:
            step: WizardStep enum to reset
        """
        with self._lock_file():
            state = self._read_state()
            
            state["steps"][step.value] = {
                "status": StepStatus.NOT_STARTED.value,
                "data": {},
                "validation_errors": [],
                "last_updated": None,
                "attempt_count": 0
            }
            
            # Remove from completed list
            if step.value in state["completed_steps"]:
                state["completed_steps"].remove(step.value)
            
            self._write_state_atomic(state)
    
    def reset_all(self):
        """
        Reset entire wizard to initial state.
        
        ⚠️  WARNING: This clears all progress!
        """
        with self._lock_file():
            default_state = self._get_default_state()
            self._write_state_atomic(default_state)
    
    # ============================================================
    # Validation Methods
    # ============================================================
    
    def can_proceed_to_step(self, step: WizardStep) -> bool:
        """
        Check if wizard can proceed to given step.
        
        Rules:
        - Can always go to WELCOME
        - Can go to any completed step (for editing)
        - Can only go to next uncompleted step
        
        Args:
            step: WizardStep enum
            
        Returns:
            True if can proceed to step
        """
        if step == WizardStep.WELCOME:
            return True
        
        completed = self.get_completed_steps()
        
        # Can revisit completed steps
        if step in completed:
            return True
        
        # Can only proceed to immediate next step
        step_index = list(WizardStep).index(step)
        if step_index == 0:
            return True
        
        previous_step = list(WizardStep)[step_index - 1]
        return previous_step in completed
    
    def is_wizard_complete(self) -> bool:
        """
        Check if entire wizard is complete.
        
        Returns:
            True if all steps completed
        """
        completed = self.get_completed_steps()
        return WizardStep.COMPLETE in completed
    
    def get_next_required_step(self) -> Optional[WizardStep]:
        """
        Get next step that needs to be completed.
        
        Returns:
            WizardStep enum or None if all complete
        """
        if self.is_wizard_complete():
            return None
        
        for step in WizardStep:
            if self.get_step_status(step) != StepStatus.COMPLETED:
                return step
        
        return None
    
    # ============================================================
    # Metadata Methods
    # ============================================================
    
    def set_metadata(self, key: str, value: Any):
        """
        Set metadata value.
        
        Args:
            key: Metadata key
            value: Metadata value (must be JSON-serializable)
        """
        with self._lock_file():
            state = self._read_state()
            state["metadata"][key] = value
            self._write_state_atomic(state)
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata value.
        
        Args:
            key: Metadata key
            default: Default value if key doesn't exist
            
        Returns:
            Metadata value or default
        """
        state = self.get_state()
        return state["metadata"].get(key, default)


# ============================================================
# Global Instance
# ============================================================

# Create global state manager instance
wizard_state = SetupWizardState()


# ============================================================
# Convenience Functions
# ============================================================

def get_current_step() -> WizardStep:
    """Get current wizard step."""
    return wizard_state.get_current_step()


def get_progress() -> float:
    """Get progress percentage."""
    return wizard_state.get_progress_percentage()


def is_complete() -> bool:
    """Check if wizard is complete."""
    return wizard_state.is_wizard_complete()

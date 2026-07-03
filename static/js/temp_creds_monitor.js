/**
 * Temp Credentials and Live Monitor Management
 * Implements UI for temp credentials and real-time monitoring
 */

// ==========================
// TEMPORARY CREDENTIALS
// ==========================

let tempCredsRefreshInterval = null;
let tempCredTimers = {};
let isLoadingTempCreds = false;  // Prevent concurrent requests

/**
 * Load and display temporary credentials
 */
async function loadTempCredentials() {
    // Prevent concurrent requests
    if (isLoadingTempCreds) {
        console.log('⏭️ Skipping load - already in progress');
        return;
    }
    
    isLoadingTempCreds = true;
    console.log('Loading temp credentials list...');
    const container = document.getElementById('temp-creds-list');
    
    try {
        const response = await fetchAPI('/temp-creds/list');
        // API returns array directly, not wrapped in credentials property
        const tempCreds = Array.isArray(response) ? response : (response.credentials || []);
        
        console.log(`Loaded ${tempCreds.length} temporary credentials`);
        
        if (tempCreds.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <h3>⏱️ No Temporary Credentials</h3>
                    <p>Click "Generate New Credential" to create a temporary access credential</p>
                </div>
            `;
            return;
        }
        
        // Clear existing timers
        Object.values(tempCredTimers).forEach(timer => clearInterval(timer));
        tempCredTimers = {};
        
        // Sort by created date (newest first)
        tempCreds.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        
        // Render each credential
        container.innerHTML = tempCreds.map(cred => renderTempCredItem(cred)).join('');
        
        // Start countdown timers for active credentials
        tempCreds.forEach(cred => {
            if (cred.is_active && !cred.is_used) {
                startCountdownTimer(cred.temp_username, cred.expires_at);
            }
        });
        
        // Attach event listeners
        attachTempCredEventListeners();
        
    } catch (error) {
        console.error('Error loading temp credentials:', error);
        showTempCredsAlert(error.message, 'error');
        container.innerHTML = `
            <div class="alert alert-error">
                Failed to load temporary credentials: ${escapeHtml(error.message)}
            </div>
        `;
    } finally {
        // Always reset loading flag
        isLoadingTempCreds = false;
    }
}

/**
 * Render a single temp credential item
 */
function renderTempCredItem(cred) {
    // All dates from API are in UTC with 'Z' suffix
    // JavaScript Date constructor will correctly parse them as UTC
    const now = new Date();  // Current local time
    const deactivateAt = new Date(cred.deactivate_at);  // Parse UTC from API
    const expiresAt = new Date(cred.expires_at);  // Parse UTC from API
    
    // Debug logging removed to prevent console spam
    // Timezone handling: API returns UTC, browser Date() converts to local
    
    let status, statusClass, dataStatus;
    // Fixed logic: check time-based expiration BEFORE is_active flag
    // This prevents newly created credentials from incorrectly showing as "Expired"
    if (cred.is_used) {
        status = 'Used';
        statusClass = 'used';
        dataStatus = 'used';
    } else if (now > expiresAt) {
        // Actually expired based on time
        status = 'Expired';
        statusClass = 'expired';
        dataStatus = 'expired';
    } else if (!cred.is_active) {
        // Manually deactivated (but not yet time-expired)
        status = 'Deactivated';
        statusClass = 'expired';
        dataStatus = 'deactivated';
    } else {
        // Active and not expired
        status = 'Active';
        statusClass = 'active';
        dataStatus = 'active';
    }
    
    const canDeactivate = cred.is_active && !cred.is_used && now < expiresAt;
    const canDelete = true; // Can always delete
    // Show password button if credential has a password (new: based on has_password field)
    const canShowPassword = cred.has_password;
    
    // Debug logging removed to prevent console spam
    
    // SFTP Command section (always show for reference)
    let sftpSection = `
        <div class="temp-cred-detail" style="grid-column: 1 / -1;">
            <span>🔒 SFTP Command:</span>
            <code style="font-size: 12px; background: #f5f5f5; padding: 8px; border-radius: 4px; display: block;">sftp -P 2222 ${escapeHtml(cred.temp_username)}@localhost</code>
        </div>
    `;
    
    // Active sessions section (show for used credentials with active sessions)
    let sessionsSection = '';
    if (cred.active_session_count > 0) {
        const sessionsList = cred.active_sessions.map(session => {
            const startedAt = new Date(session.started_at);
            const lastActivity = new Date(session.last_activity);
            const duration = Math.floor((now - startedAt) / 1000); // seconds
            const durationStr = duration < 60 ? `${duration}s` : `${Math.floor(duration / 60)}m ${duration % 60}s`;
            
            return `
                <div style="font-size: 11px; color: #666; margin-left: 20px;">
                    • IP: ${escapeHtml(session.ip_address)} | Duration: ${durationStr} | Last: ${formatTime(lastActivity)}
                </div>
            `;
        }).join('');
        
        sessionsSection = `
            <div class="temp-cred-detail" style="grid-column: 1 / -1; background: #e8f5e9; padding: 8px; border-radius: 4px; border-left: 4px solid #4caf50;">
                <span style="font-weight: 600; color: #2e7d32;">🟢 Active Sessions (${cred.active_session_count}):</span>
                ${sessionsList}
            </div>
        `;
    }
    
    // Password is NOT shown by default - must click button
    let passwordSection = sftpSection + sessionsSection;
    
    return `
        <div class="temp-cred-item" data-username="${escapeHtml(cred.temp_username)}" data-status="${dataStatus}">
            <div class="temp-cred-header">
                <div class="temp-cred-username">${escapeHtml(cred.temp_username)}</div>
                <div class="temp-cred-status ${statusClass}">${status}</div>
            </div>
            <div class="temp-cred-details">
                <div class="temp-cred-detail">
                    <span>📅 Created:</span>
                    <span>${formatDateTime(cred.created_at)}</span>
                </div>
                <div class="temp-cred-detail">
                    <span>⏰ Expires:</span>
                    <span id="countdown-${escapeHtml(cred.temp_username)}">
                        ${formatDateTime(cred.expires_at)}
                    </span>
                </div>
                <div class="temp-cred-detail">
                    <span>👤 User:</span>
                    <span>${escapeHtml(cred.username)}</span>
                </div>
                ${passwordSection}
            </div>
            <div class="temp-cred-actions">
                ${canShowPassword ? `
                    <button class="btn btn-sm btn-secondary show-password-btn" 
                            data-username="${escapeHtml(cred.temp_username)}">
                        👁️ Show Password
                    </button>
                ` : ''}
                ${cred.active_session_count > 0 ? `
                    <button class="btn btn-sm btn-danger terminate-sessions-btn" 
                            data-username="${escapeHtml(cred.temp_username)}"
                            data-session-count="${cred.active_session_count}">
                        ⚠️ Terminate Sessions (${cred.active_session_count})
                    </button>
                ` : ''}
                ${canDeactivate ? `
                    <button class="btn btn-sm btn-warning deactivate-temp-cred-btn" 
                            data-username="${escapeHtml(cred.temp_username)}">
                        🚫 Deactivate
                    </button>
                ` : ''}
                ${canDelete ? `
                    <button class="btn btn-sm btn-danger delete-temp-cred-btn" 
                            data-username="${escapeHtml(cred.temp_username)}">
                        🗑️ Delete
                    </button>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Start countdown timer for a credential
 */
function startCountdownTimer(username, expiresAt) {
    const countdownId = `countdown-${username}`;
    const element = document.getElementById(countdownId);
    
    if (!element) return;
    
    const updateCountdown = () => {
        const now = new Date();
        const target = new Date(expiresAt);
        const diff = target - now;
        
        if (diff <= 0) {
            element.innerHTML = '<span style="color: #9E9E9E;">Expired</span>';
            if (tempCredTimers[username]) {
                clearInterval(tempCredTimers[username]);
                delete tempCredTimers[username];
            }
            // Don't reload - let the auto-refresh handle it
            return;
        }
        
        const minutes = Math.floor(diff / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);
        
        const color = minutes < 5 ? '#FF5722' : minutes < 10 ? '#FF9800' : '#4CAF50';
        element.innerHTML = `<span class="countdown-timer" style="color: ${color};">${minutes}m ${seconds}s remaining</span>`;
    };
    
    updateCountdown();
    tempCredTimers[username] = setInterval(updateCountdown, 1000);
}

/**
 * Attach event listeners to temp cred buttons
 */
function attachTempCredEventListeners() {
    // Show password buttons
    document.querySelectorAll('.show-password-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const username = e.target.dataset.username;
            
            try {
                // Fetch password from dedicated endpoint (supports ETag caching)
                const response = await fetchAPI(`/temp-creds/${username}/password`, {
                    method: 'GET'
                });
                
                const password = response.password;
                
                if (password) {
                    // Show password in custom modal with nice graphics
                    showPasswordModal(username, password);
                } else {
                    showTempCredsAlert('Password not available (expired or already used)', 'error');
                }
            } catch (error) {
                console.error('Error fetching password:', error);
                
                // Extract user-friendly message from error
                let errorMessage = 'Password not available';
                if (error.message) {
                    // Check if it's a 404 (expected for expired/used credentials)
                    if (error.message.includes('404') || error.message.includes('not found') || error.message.includes('Password not available')) {
                        errorMessage = 'Password not available. This credential has expired (65 minutes) or was already used.';
                    } else {
                        errorMessage = `Failed to fetch password: ${error.message}`;
                    }
                }
                
                // Show styled alert in the app
                showTempCredsAlert(errorMessage, 'error');
            }
        });
    });
    
    // Deactivate buttons
    document.querySelectorAll('.deactivate-temp-cred-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const username = e.target.dataset.username;
            if (confirm(`Deactivate credential "${username}"?\n\nThis CANNOT be undone.\nUser will lose all access immediately.`)) {
                await deactivateTempCredential(username);
            }
        });
    });
    
    // Terminate sessions buttons
    document.querySelectorAll('.terminate-sessions-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const username = e.target.dataset.username;
            const sessionCount = e.target.dataset.sessionCount;
            if (confirm(`Terminate ${sessionCount} active session(s) for "${username}"?\n\nThis will forcibly disconnect all active SFTP connections.`)) {
                await terminateSessions(username);
            }
        });
    });
    
    // Delete buttons
    document.querySelectorAll('.delete-temp-cred-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const username = e.target.dataset.username;
            if (confirm(`Permanently delete credential "${username}"?\n\nThis CANNOT be undone.`)) {
                await deleteTempCredential(username);
            }
        });
    });
}

/**
 * Show modern modal with new credential details
 */
function showCredentialModal(credentialData) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        animation: fadeIn 0.2s ease;
    `;
    
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        max-width: 500px;
        width: 90%;
        padding: 0;
        animation: slideUp 0.3s ease;
    `;
    
    modalContent.innerHTML = `
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 24px; border-radius: 12px 12px 0 0; color: white;">
            <h2 style="margin: 0 0 8px 0; font-size: 24px;">🎉 Credential Created!</h2>
            <p style="margin: 0; opacity: 0.9; font-size: 14px;">Save these details now - password won't be shown again</p>
        </div>
        
        <div style="padding: 24px;">
            <div style="margin-bottom: 20px;">
                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Username</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" readonly value="${escapeHtml(credentialData.temp_username)}" 
                           style="flex: 1; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 14px; background: #f7fafc;">
                    <button class="copy-btn" data-text="${escapeHtml(credentialData.temp_username)}"
                            style="padding: 12px 20px; background: #4299e1; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.2s; white-space: nowrap;">
                        📋 Copy
                    </button>
                </div>
            </div>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Password</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" readonly value="${escapeHtml(credentialData.credential)}" 
                           style="flex: 1; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 14px; background: #fff3cd; font-weight: bold;">
                    <button class="copy-btn" data-text="${escapeHtml(credentialData.credential)}"
                            style="padding: 12px 20px; background: #48bb78; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.2s; white-space: nowrap;">
                        📋 Copy
                    </button>
                </div>
            </div>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">SFTP Command</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" readonly value="sftp -P 2222 ${escapeHtml(credentialData.temp_username)}@localhost" 
                           style="flex: 1; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 12px; background: #f7fafc;">
                    <button class="copy-btn" data-text="sftp -P 2222 ${escapeHtml(credentialData.temp_username)}@localhost"
                            style="padding: 12px 20px; background: #4299e1; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.2s; white-space: nowrap;">
                        📋 Copy
                    </button>
                </div>
            </div>
            
            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px;">
                <p style="margin: 0; font-size: 13px; color: #78350f;">
                    <strong>⏰ Valid for ${credentialData.validity_minutes} minutes</strong><br>
                    Expires: ${formatDateTime(credentialData.deactivate_at)}
                </p>
            </div>
            
            <div style="display: flex; gap: 12px;">
                <button class="close-modal-btn"
                        style="flex: 1; padding: 14px; background: #e2e8f0; color: #2d3748; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 15px; transition: all 0.2s;">
                    Close
                </button>
            </div>
        </div>
    `;
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // Add event listeners for copy buttons
    modal.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const text = e.target.dataset.text;
            const originalHTML = e.target.innerHTML;
            const originalBg = e.target.style.background;
            
            try {
                await navigator.clipboard.writeText(text);
                e.target.innerHTML = '✅ Copied!';
                e.target.style.background = '#48bb78';
                
                setTimeout(() => {
                    e.target.innerHTML = originalHTML;
                    e.target.style.background = originalBg;
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
                e.target.innerHTML = '❌ Failed';
                e.target.style.background = '#f56565';
                
                setTimeout(() => {
                    e.target.innerHTML = originalHTML;
                    e.target.style.background = originalBg;
                }, 2000);
            }
        });
    });
    
    // Add event listener for close button
    modal.querySelector('.close-modal-btn').addEventListener('click', () => {
        modal.remove();
    });
    
    // Auto-copy password to clipboard
    setTimeout(async () => {
        try {
            await navigator.clipboard.writeText(credentialData.credential);
            console.log('✅ Password auto-copied to clipboard');
        } catch (err) {
            console.error('Failed to auto-copy:', err);
        }
    }, 300);
    
    // Close on overlay click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
    
    // Close on Escape key
    const escapeHandler = (e) => {
        if (e.key === 'Escape') {
            modal.remove();
            document.removeEventListener('keydown', escapeHandler);
        }
    };
    document.addEventListener('keydown', escapeHandler);
}

/**
 * Show password in a custom modal with nice graphics
 */
function showPasswordModal(username, password) {
    // Create modal overlay
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        animation: fadeIn 0.2s ease;
    `;
    
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        max-width: 450px;
        width: 90%;
        padding: 0;
        animation: slideUp 0.3s ease;
    `;
    
    modalContent.innerHTML = `
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 24px; border-radius: 12px 12px 0 0; color: white;">
            <h2 style="margin: 0 0 8px 0; font-size: 24px;">🔐 Credential Password</h2>
            <p style="margin: 0; opacity: 0.9; font-size: 14px;">${escapeHtml(username)}</p>
        </div>
        
        <div style="padding: 24px;">
            <div style="margin-bottom: 20px;">
                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Password</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" readonly value="${escapeHtml(password)}" 
                           style="flex: 1; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 16px; background: #fff3cd; font-weight: bold; color: #2d3748;">
                    <button class="copy-password-btn" data-text="${escapeHtml(password)}"
                            style="padding: 12px 20px; background: #48bb78; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.2s; white-space: nowrap;">
                        📋 Copy
                    </button>
                </div>
            </div>
            
            <div style="background: #e0e7ff; border-left: 4px solid #667eea; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px;">
                <p style="margin: 0; font-size: 13px; color: #3730a3;">
                    <strong>💡 Tip:</strong> Use this password with SFTP or SSH to authenticate as ${escapeHtml(username)}
                </p>
            </div>
            
            <div style="display: flex; gap: 12px;">
                <button class="close-password-modal-btn"
                        style="flex: 1; padding: 14px; background: #e2e8f0; color: #2d3748; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 15px; transition: all 0.2s;">
                    Close
                </button>
            </div>
        </div>
    `;
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // Add event listener for copy button
    modal.querySelector('.copy-password-btn').addEventListener('click', async (e) => {
        const text = e.target.dataset.text;
        const originalHTML = e.target.innerHTML;
        const originalBg = e.target.style.background;
        
        try {
            await navigator.clipboard.writeText(text);
            e.target.innerHTML = '✅ Copied!';
            e.target.style.background = '#48bb78';
            
            setTimeout(() => {
                e.target.innerHTML = originalHTML;
                e.target.style.background = originalBg;
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            e.target.innerHTML = '❌ Failed';
            e.target.style.background = '#f56565';
            
            setTimeout(() => {
                e.target.innerHTML = originalHTML;
                e.target.style.background = originalBg;
            }, 2000);
        }
    });
    
    // Add event listener for close button
    modal.querySelector('.close-password-modal-btn').addEventListener('click', () => {
        modal.remove();
    });
    
    // Close on overlay click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
    
    // Close on Escape key
    const escapeHandler = (e) => {
        if (e.key === 'Escape') {
            modal.remove();
            document.removeEventListener('keydown', escapeHandler);
        }
    };
    document.addEventListener('keydown', escapeHandler);
}

/**
 * Generate a new temporary credential
 */
async function handleCreateTempCredential() {
    try {
        showTempCredsAlert('Generating temporary credential...', 'info');
        
        const response = await fetchAPI('/auth/temp-credentials', {
            method: 'POST'
        });
        
        console.log('Temp credential created:', response);
        
        // Show modern modal with credentials
        showCredentialModal(response);
        
        // Reload the list immediately
        await loadTempCredentials();
        
    } catch (error) {
        console.error('Error creating temp credential:', error);
        showTempCredsAlert(`Failed to create credential: ${error.message}`, 'error');
    }
}

/**
 * Deactivate a temporary credential (cannot be undone)
 */
async function deactivateTempCredential(username) {
    try {
        showTempCredsAlert('Deactivating credential...', 'info');
        
        const response = await fetchAPI(`/temp-creds/${username}/deactivate`, {
            method: 'POST'
        });
        
        console.log('Credential deactivated:', response);
        showTempCredsAlert(`✅ ${response.message}`, 'success');
        
        // Reload the list
        await loadTempCredentials();
        
    } catch (error) {
        console.error('Error deactivating credential:', error);
        showTempCredsAlert(`Failed to deactivate: ${error.message}`, 'error');
    }
}

/**
 * Delete a temporary credential (cannot be undone)
 */
async function deleteTempCredential(username) {
    try {
        showTempCredsAlert('Deleting credential...', 'info');
        
        const response = await fetchAPI(`/temp-creds/${username}/delete`, {
            method: 'POST'
        });
        
        console.log('Credential deleted:', response);
        showTempCredsAlert(`✅ ${response.message}`, 'success');
        
        // Reload the list
        await loadTempCredentials();
        
    } catch (error) {
        console.error('Error deleting credential:', error);
        showTempCredsAlert(`Failed to delete: ${error.message}`, 'error');
    }
}

/**
 * Terminate all active sessions for a temporary credential
 */
async function terminateSessions(username) {
    try {
        showTempCredsAlert('Terminating sessions...', 'info');
        
        const response = await fetchAPI(`/temp-creds/${username}/terminate-sessions`, {
            method: 'POST'
        });
        
        showTempCredsAlert(response.message, 'success');
        
        // Reload the list to show updated session count
        await loadTempCredentials();
        
    } catch (error) {
        console.error('Error terminating sessions:', error);
        showTempCredsAlert(`Failed to terminate sessions: ${error.message}`, 'error');
    }
}

/**
 * Format time for display (just time, no date)
 */
function formatTime(date) {
    if (!date) return 'Never';
    const d = typeof date === 'string' ? new Date(date) : date;
    return d.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit',
        hour12: false 
    });
}

/**
 * Display temp credential in modal (reuse existing modal)
 */
function displayTempCredentialModal(data) {
    document.getElementById('temp-cred-username').textContent = data.temp_username;
    document.getElementById('temp-cred-password').textContent = data.credential;
    
    const expiresAt = new Date(data.deactivate_at);
    const minutes = data.validity_minutes;
    document.getElementById('temp-cred-expires').textContent = 
        `${formatDateTime(data.deactivate_at)} (${minutes} minutes)`;
    
    const sftpCommand = `sftp -P 2222 ${data.temp_username}@localhost`;
    document.getElementById('temp-cred-command').textContent = sftpCommand;
    
    // Show password by default (one-time display)
    const passwordField = document.getElementById('temp-cred-password');
    if (passwordField) {
        passwordField.style.filter = 'none';
        passwordField.setAttribute('data-visible', 'true');
    }
    
    // Store password temporarily in memory for copy functionality
    window._tempCredentialPassword = data.credential;
    
    openModal('temp-creds-modal');
}

/**
 * Retrieve password for a temp credential
 */
async function retrieveTempPassword(username) {
    try {
        // For now, we'll need to add this endpoint to the backend
        // This is a placeholder that shows the UI pattern
        showTempCredsAlert('Retrieving password...', 'info');
        
        const response = await fetchAPI(`/temp-creds/${username}/password`, {
            method: 'GET'
        });
        
        // Show password in a modal or alert
        if (response.password) {
            const confirmed = confirm(
                `Password for ${username}:\n\n${response.password}\n\n` +
                `This password will expire ${response.expires_in || 'soon'}.\n` +
                `Click OK to copy to clipboard.`
            );
            
            if (confirmed && navigator.clipboard) {
                await navigator.clipboard.writeText(response.password);
                showTempCredsAlert('Password copied to clipboard!', 'success');
            }
        } else {
            showTempCredsAlert('Password not available (expired or used)', 'warning');
        }
        
    } catch (error) {
        console.error('Error retrieving password:', error);
        if (error.message.includes('404')) {
            showTempCredsAlert('Password not available - credential may be expired or used', 'warning');
        } else {
            showTempCredsAlert(`Failed to retrieve password: ${error.message}`, 'error');
        }
    }
}

/**
 * Revoke a temporary credential
 */
async function revokeTempCredential(username) {
    try {
        await fetchAPI(`/temp-creds/${username}/delete`, {
            method: 'POST'
        });
        
        showTempCredsAlert(`Credential "${username}" revoked successfully`, 'success');
        await loadTempCredentials();
        
    } catch (error) {
        console.error('Error revoking credential:', error);
        showTempCredsAlert(`Failed to revoke credential: ${error.message}`, 'error');
    }
}

/**
 * Show alert in temp creds view
 */
function showTempCredsAlert(message, type = 'info') {
    const container = document.getElementById('temp-creds-alert-container');
    if (!container) return;
    
    const alertClass = `alert-${type}`;
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert ${alertClass}`;
    alertDiv.innerHTML = `
        ${escapeHtml(message)}
        <button class="alert-close">&times;</button>
    `;
    
    // Add click handler for close button
    const closeBtn = alertDiv.querySelector('.alert-close');
    closeBtn.addEventListener('click', () => alertDiv.remove());
    
    container.innerHTML = '';
    container.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds for non-error alerts
    if (type !== 'error') {
        setTimeout(() => {
            if (alertDiv.parentElement) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

/**
 * Start auto-refresh for temp credentials
 */
function startTempCredsRefresh() {
    // Only start if not already running
    if (tempCredsRefreshInterval) {
        console.log('⏭️ Auto-refresh already running, skipping...');
        return;
    }
    
    // Refresh every 5 seconds for real-time status updates
    tempCredsRefreshInterval = setInterval(() => {
        if (state.currentView === 'temp-creds') {
            console.log('🔄 Auto-refresh: loading credentials...');
            loadTempCredentials();
        } else {
            console.log('⏭️ Not on temp-creds view, skipping refresh');
        }
    }, 5000); // Refresh every 5 seconds
    console.log('✅ Auto-refresh started: 5 second interval');
}

/**
 * Stop auto-refresh for temp credentials
 */
function stopTempCredsRefresh() {
    if (tempCredsRefreshInterval) {
        console.log('🛑 Stopping auto-refresh');
        clearInterval(tempCredsRefreshInterval);
        tempCredsRefreshInterval = null;
    }
    
    // Clear all countdown timers
    Object.values(tempCredTimers).forEach(timer => clearInterval(timer));
    tempCredTimers = {};
}

// ==========================
// LIVE MONITOR
// ==========================

let monitorWebSocket = null;
let monitorReconnectTimeout = null;
let activityFeedItems = [];
const MAX_ACTIVITY_ITEMS = 50;

/**
 * Initialize live monitor view
 */
function initializeLiveMonitor() {
    console.log('Initializing live monitor...');
    connectMonitorWebSocket();
    
    // Setup clear activity button
    const clearBtn = document.getElementById('clear-activity-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            activityFeedItems = [];
            updateActivityFeed();
        });
    }
}

/**
 * Connect to monitoring WebSocket
 */
function connectMonitorWebSocket() {
    if (monitorWebSocket && monitorWebSocket.readyState === WebSocket.OPEN) {
        console.log('WebSocket already connected');
        return;
    }
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Security: Don't pass token in URL (prevents logging/leaking)
    const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
    
    console.log('Connecting to monitor WebSocket...');
    updateMonitorStatus('connecting');
    
    try {
        monitorWebSocket = new WebSocket(wsUrl);
        
        monitorWebSocket.onopen = () => {
            console.log('✅ Monitor WebSocket connected - sending authentication...');
            // Security: Send token in first message instead of URL
            monitorWebSocket.send(JSON.stringify({
                type: 'auth',
                token: state.token
            }));
        };
        
        monitorWebSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                // Handle authentication response
                if (data.type === 'connected') {
                    console.log('✅ Monitor WebSocket authenticated:', data.message);
                    updateMonitorStatus('connected');
                    
                    // Clear reconnect timeout
                    if (monitorReconnectTimeout) {
                        clearTimeout(monitorReconnectTimeout);
                        monitorReconnectTimeout = null;
                    }
                } else if (data.type === 'error' && data.message.includes('token')) {
                    console.error('❌ Monitor WebSocket authentication failed:', data.message);
                    updateMonitorStatus('disconnected');
                    // Don't reconnect on auth errors
                    return;
                } else {
                    handleMonitorEvent(data);
                }
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
        
        monitorWebSocket.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateMonitorStatus('disconnected');
        };
        
        monitorWebSocket.onclose = () => {
            console.log('WebSocket closed');
            updateMonitorStatus('disconnected');
            
            // Auto-reconnect if still on monitor view
            if (state.currentView === 'monitor') {
                monitorReconnectTimeout = setTimeout(() => {
                    console.log('Attempting to reconnect...');
                    connectMonitorWebSocket();
                }, 5000);
            }
        };
        
    } catch (error) {
        console.error('Error creating WebSocket:', error);
        updateMonitorStatus('disconnected');
    }
}

/**
 * Disconnect monitor WebSocket
 */
function disconnectMonitorWebSocket() {
    if (monitorWebSocket) {
        monitorWebSocket.close();
        monitorWebSocket = null;
    }
    
    if (monitorReconnectTimeout) {
        clearTimeout(monitorReconnectTimeout);
        monitorReconnectTimeout = null;
    }
    
    updateMonitorStatus('disconnected');
}

/**
 * Update monitor connection status indicator
 */
function updateMonitorStatus(status) {
    const statusElement = document.getElementById('monitor-status');
    if (!statusElement) return;
    
    const dot = statusElement.querySelector('.status-dot');
    const text = statusElement.querySelector('span:last-child');
    
    if (dot) {
        dot.className = `status-dot ${status}`;
    }
    
    if (text) {
        const statusText = {
            'connected': 'Connected',
            'connecting': 'Connecting...',
            'disconnected': 'Disconnected'
        };
        text.textContent = statusText[status] || status;
    }
}

/**
 * Handle incoming monitor event
 */
function handleMonitorEvent(event) {
    console.log('Monitor event:', event);
    
    switch (event.type) {
        case 'connected':
            // WebSocket connection established
            console.log('Monitor WebSocket connected');
            break;
        case 'stats':
            updateMonitorStats(event.data);
            break;
        case 'operation_start':
        case 'operation_update':
        case 'operation_complete':
            updateOperationsList(event.data);
            break;
        case 'activity':
            addActivityItem(event.data);
            break;
        default:
            console.log('Unknown event type:', event.type);
    }
}

/**
 * Update monitor statistics
 */
function updateMonitorStats(stats) {
    document.getElementById('stat-operations').textContent = stats.active_operations || 0;
    document.getElementById('stat-upload').textContent = formatBytes(stats.upload_traffic || 0);
    document.getElementById('stat-download').textContent = formatBytes(stats.download_traffic || 0);
    document.getElementById('stat-active-users').textContent = stats.active_users || 0;
}

/**
 * Update operations list
 */
function updateOperationsList(operations) {
    const container = document.getElementById('operations-list');
    if (!container) return;
    
    if (!operations || operations.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No active operations</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = operations.map(op => renderOperation(op)).join('');
}

/**
 * Render a single operation
 */
function renderOperation(op) {
    const progress = ((op.transferred_bytes || 0) / op.total_size * 100).toFixed(1);
    const typeClass = op.type === 'upload' ? 'upload' : 'download';
    const typeIcon = op.type === 'upload' ? '⬆️' : '⬇️';
    
    return `
        <div class="operation-item">
            <div class="operation-header">
                <div>
                    <span class="operation-user">${escapeHtml(op.username)}</span>
                    <span style="color: #999;"> ${typeIcon} ${op.type}</span>
                </div>
                <div class="operation-file">${escapeHtml(op.file_name)}</div>
            </div>
            <div class="operation-progress">
                <div class="progress-bar">
                    <div class="progress-fill ${typeClass}" style="width: ${progress}%"></div>
                    <div class="progress-text">${progress}%</div>
                </div>
            </div>
            <div class="operation-stats">
                <span>${formatBytes(op.transferred_bytes || 0)} / ${formatBytes(op.total_size)}</span>
                <span>${op.speed || 'Calculating...'}</span>
            </div>
        </div>
    `;
}

/**
 * Add item to activity feed
 */
function addActivityItem(activity) {
    activityFeedItems.unshift({
        ...activity,
        timestamp: new Date().toISOString()
    });
    
    // Keep only last MAX_ACTIVITY_ITEMS
    if (activityFeedItems.length > MAX_ACTIVITY_ITEMS) {
        activityFeedItems = activityFeedItems.slice(0, MAX_ACTIVITY_ITEMS);
    }
    
    updateActivityFeed();
}

/**
 * Update activity feed display
 */
function updateActivityFeed() {
    const container = document.getElementById('activity-feed');
    if (!container) return;
    
    if (activityFeedItems.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No recent activity</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = activityFeedItems.map(item => `
        <div class="activity-item">
            <div class="activity-time">${formatTime(item.timestamp)}</div>
            <div>
                <span class="activity-user">${escapeHtml(item.username || 'Unknown')}</span>
                <span class="activity-action">${escapeHtml(item.message || item.action)}</span>
            </div>
        </div>
    `).join('');
}

/**
 * Format bytes to human readable
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format time from ISO string
 */
function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

/**
 * Format date time
 */
function formatDateTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString();
}

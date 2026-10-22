// aTrust Client Frontend Controller
//
// 这套界面只服务 aTrust 后端（/api/atrust/*）。V5VPN 有一套独立的
// /v5vpn/，两边不共享 api 层、不共享页面结构，也不在运行时不按协议
// 隐藏控件——aTrust 没有的能力这里根本没有对应的 DOM。
(function() {
  // Application State
  let config = null;
  let currentGateway = null;
  let isConnected = false;
  let logPollTimer = null;

  // ==================== 协议过滤 ====================
  //
  // 只认 protocol === 'atrust' 的网关。与后端相反：后端把空串当作
  // V5VPN，所以这里绝不能"非 atrust 即本协议"，否则老配置里的
  // V5VPN 网关会出现在 aTrust 界面并打到 aTrust 端点（后端会 409）。
  function isATrustGateway(gw) {
    return !!(gw && gw.protocol === 'atrust');
  }

  // DOM Elements - Views
  const viewLogin = document.getElementById('view-login');
  const viewConnected = document.getElementById('view-connected');
  const loginAlert = document.getElementById('login-alert');

  // DOM Elements - Login View
  const loginForm = document.getElementById('login-form');
  const gatewaySelect = document.getElementById('gateway-select');
  const openSettingsBtn = document.getElementById('open-settings-btn');
  const gwIpPort = document.getElementById('gw-ip-port');
  const usernameInput = document.getElementById('username-input');
  const passwordInput = document.getElementById('password-input');
  const togglePwdBtn = document.getElementById('toggle-pwd-btn');
  const rememberPwdCheckbox = document.getElementById('remember-pwd-checkbox');
  const autoLoginCheckbox = document.getElementById('auto-login-checkbox');
  const connectBtn = document.getElementById('connect-btn');
  const connectBtnText = document.getElementById('connect-btn-text');
  const connectSpinner = connectBtn.querySelector('.btn-spinner');

  // DOM Elements - Connected View
  const connectedGwName = document.getElementById('connected-gw-name');
  const sessionUserVal = document.getElementById('session-user-val');
  const sessionIpVal = document.getElementById('session-ip-val');
  const sessionIdVal = document.getElementById('session-id-val');
  const resCount = document.getElementById('res-count');
  const resLoadingBadge = document.getElementById('res-loading-badge');
  const refreshResourcesBtn = document.getElementById('refresh-resources-btn');
  const resourceErrorBanner = document.getElementById('resource-error-banner');
  const resourceErrorText = document.getElementById('resource-error-text');
  const resourcesTbody = document.getElementById('resources-tbody');
  const disconnectBtn = document.getElementById('disconnect-btn');
  const toggleLogsBtn = document.getElementById('toggle-logs-btn');
  const logsPanel = document.getElementById('logs-panel');
  const closeLogsBtn = document.getElementById('close-logs-btn');
  const clearLogsBtn = document.getElementById('clear-logs-btn');
  const logConsole = document.getElementById('log-console');

  // DOM Elements - Settings Modal
  const settingsModal = document.getElementById('settings-modal');
  const closeModalBtn = document.getElementById('close-modal-btn');
  const modalDoneBtn = document.getElementById('modal-done-btn');
  const gatewaysTbody = document.getElementById('gateways-tbody');
  const addGwBtn = document.getElementById('add-gw-btn');

  // Backend Bridge API
  //
  // 只打 aTrust 的端点。注意几个「共用」端点是有意为之：
  //   /api/config、/api/gateways  —— 网关表只有一份（setting.xml）
  //   /api/logs                   —— 日志宿主是两个后端共用的 VPNService
  //   /api/window-size、/api/open-url、/api/check-updates —— 与协议无关
  const api = {
    async getConfig() {
      if (window.VPNService && window.VPNService.getConfig) {
        return await window.VPNService.getConfig();
      }
      const res = await fetch('/api/config');
      return await res.json();
    },
    // aTrust 的认证链是四个往返（authConfig → psw → authCheck → onlineInfo），
    // 冷启动网关上前两个就可能各花几秒，所以超时上限比 V5VPN 宽得多。
    // 资源拉取是异步的，不在这条链上。
    async login(gwId, username, password, remember, auto) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 40000);

      try {
        const res = await fetch('/api/atrust/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gwId, username, password, remember, auto }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        if (!res.ok) {
          const error = new Error(data.error || 'aTrust 登录失败');
          error.code = data.code || '';
          throw error;
        }
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('aTrust 网关响应超时(40s)，请检查网络与网关地址');
        }
        throw err;
      }
    },
    async logout() {
      if (window.ATrustService && window.ATrustService.logout) {
        return await window.ATrustService.logout();
      }
      const res = await fetch('/api/atrust/logout', { method: 'POST' });
      return await res.json();
    },
    async getStatus() {
      if (window.ATrustService && window.ATrustService.getStatus) {
        return await window.ATrustService.getStatus();
      }
      const res = await fetch('/api/atrust/status');
      return await res.json();
    },
    async getLogs() {
      if (window.VPNService && window.VPNService.getLogs) {
        return await window.VPNService.getLogs();
      }
      const res = await fetch('/api/logs');
      return await res.json();
    },
    async clearLogs() {
      if (window.VPNService && window.VPNService.clearLogs) {
        return await window.VPNService.clearLogs();
      }
      await fetch('/api/logs', { method: 'DELETE' });
    },
    async saveGateway(gw) {
      if (window.VPNService && window.VPNService.saveGateway) {
        return await window.VPNService.saveGateway(gw);
      }
      const res = await fetch('/api/gateways', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(gw)
      });
      return await res.json();
    },
    async deleteGateway(id) {
      if (window.VPNService && window.VPNService.deleteGateway) {
        return await window.VPNService.deleteGateway(id);
      }
      const res = await fetch(`/api/gateways/${encodeURIComponent(id)}`, { method: 'DELETE' });
      return await res.json();
    },
    async openURL(url) {
      if (window.VPNService && window.VPNService.openURL) {
        return await window.VPNService.openURL(url);
      }
      try {
        await fetch('/api/open-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
      } catch (e) {
        window.open(url, '_blank');
      }
    },
    async setWindowSize(mode) {
      try {
        await fetch('/api/window-size', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode })
        });
      } catch (_) {}
    },
    async checkUpdates() {
      if (window.VPNService && window.VPNService.checkForUpdates) {
        return await window.VPNService.checkForUpdates();
      }
      const res = await fetch('/api/check-updates', { method: 'POST' });
      return await res.json();
    },
    // 资源刷新走 aTrust 自己的端点：两个后端的资源树形状不同。
    async refreshResources() {
      const res = await fetch('/api/atrust/resources/refresh', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '重新拉取应用列表失败');
      return data;
    }
  };

  // Password visibility toggle
  togglePwdBtn.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
      passwordInput.type = 'text';
      togglePwdBtn.textContent = '🔒';
    } else {
      passwordInput.type = 'password';
      togglePwdBtn.textContent = '👁';
    }
  });

  // External links (GitHub footer etc.): open in system browser, not WebView
  document.querySelectorAll('.js-open-external').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const url = a.dataset.url || a.href;
      if (url) api.openURL(url);
    });
  });

  // Footer update buttons: trigger the update check with clear UI feedback
  document.querySelectorAll('.js-check-updates').forEach(btn => {
    btn.addEventListener('click', async () => {
      const original = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '⏳ 正在检查…';
      try {
        const res = await api.checkUpdates();
        if (res && res.error) {
          btn.innerHTML = '❌ 检查失败';
          alert('检查更新失败：\n' + res.error + '\n\n您可以手动前往 GitHub Releases 页面查看。');
        } else if (res && res.hasUpdate) {
          btn.innerHTML = '🎉 发现新版 ' + res.latestVersion;
          const notes = res.releaseNotes ? ('\n\n更新说明：\n' + res.releaseNotes) : '';
          const msg = `发现新版本 ${res.latestVersion}（当前版本: ${res.currentVersion}）${notes}\n\n是否打开浏览器前往下载？`;
          if (confirm(msg)) {
            await api.openURL(res.releaseURL || 'https://github.com/hygkui/v5vpn-rea-client/releases');
          }
        } else if (res) {
          btn.innerHTML = '✔ 已是最新版 (' + res.currentVersion + ')';
        } else {
          btn.innerHTML = '✔ 已是最新版本';
        }
      } catch (e) {
        btn.innerHTML = '❌ 检查异常';
        alert('检查更新异常：' + (e.message || e));
      } finally {
        setTimeout(() => {
          btn.innerHTML = original;
          btn.disabled = false;
        }, 3000);
      }
    });
  });

  // Modal Controls
  openSettingsBtn.addEventListener('click', () => {
    renderGatewayManagerTable();
    settingsModal.style.display = 'flex';
    api.setWindowSize('settings');
  });

  function closeSettingsModal() {
    settingsModal.style.display = 'none';
    api.setWindowSize(isConnected ? 'connected' : 'login');
  }

  closeModalBtn.addEventListener('click', closeSettingsModal);
  modalDoneBtn.addEventListener('click', closeSettingsModal);
  settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) closeSettingsModal();
  });

  // Logs Panel Toggle
  toggleLogsBtn.addEventListener('click', () => {
    const isVisible = logsPanel.style.display !== 'none';
    logsPanel.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
      logConsole.scrollTop = logConsole.scrollHeight;
    }
  });

  closeLogsBtn.addEventListener('click', () => {
    logsPanel.style.display = 'none';
  });

  clearLogsBtn.addEventListener('click', async () => {
    await api.clearLogs();
    logConsole.innerHTML = '';
  });

  // Gateway Selection & Population
  //
  // 只填充 aTrust 网关：V5VPN 网关在这一套界面里不出现，也选不中。
  function populateGateways(gateways, lastUsed) {
    gatewaySelect.innerHTML = '';
    const own = (gateways || []).filter(isATrustGateway);
    if (own.length === 0) {
      gatewaySelect.innerHTML = '<option value="">(暂无 aTrust 网关配置，请在设置中添加)</option>';
      gwIpPort.textContent = '--';
      currentGateway = null;
      return;
    }

    own.forEach(gw => {
      const opt = document.createElement('option');
      opt.value = gw.id || gw.name;
      opt.textContent = `${gw.name} (${gw.ip}:${gw.port})`;
      if (gw.name === lastUsed || gw.id === lastUsed) {
        opt.selected = true;
      }
      gatewaySelect.appendChild(opt);
    });

    onGatewayChanged();
  }

  function onGatewayChanged() {
    const selectedVal = gatewaySelect.value;
    if (!config || !config.gateways) return;
    const own = config.gateways.filter(isATrustGateway);
    currentGateway = own.find(g => (g.id === selectedVal || g.name === selectedVal));
    if (!currentGateway && own.length > 0) {
      currentGateway = own[0];
    }

    if (currentGateway) {
      gwIpPort.textContent = `${currentGateway.ip}:${currentGateway.port}`;

      // Auto-fill remembered accounts
      if (currentGateway.savedAccounts && currentGateway.savedAccounts.length > 0) {
        const lastUser = currentGateway.lastUserName || currentGateway.savedAccounts[0].username;
        const acc = currentGateway.savedAccounts.find(a => a.username === lastUser) || currentGateway.savedAccounts[0];
        usernameInput.value = acc.username || '';
        passwordInput.value = acc.password || '';
        rememberPwdCheckbox.checked = acc.remember !== false;
        autoLoginCheckbox.checked = acc.auto === true;
      } else {
        usernameInput.value = '';
        passwordInput.value = '';
      }
    }
  }

  gatewaySelect.addEventListener('change', onGatewayChanged);

  // Reload gateway configuration and re-render without resetting active modal or window size
  async function reloadGatewaysData() {
    try {
      config = await api.getConfig();
      populateGateways(config.gateways, config.lastUseGateway);
      renderGatewayManagerTable();
    } catch (err) {
      console.error('Failed to reload gateways:', err);
    }
  }

  // Render Gateways Table in Settings Modal
  //
  // 无「加密模式」列：aTrust 的 TLS 参数固定，这个字段对它没有意义。
  function renderGatewayManagerTable() {
    if (!config || !config.gateways) return;
    gatewaysTbody.innerHTML = '';
    const own = config.gateways.filter(isATrustGateway);
    if (own.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="5" class="empty-state" style="padding:24px; text-align:center; color:var(--text-dim);">暂无 aTrust 网关配置，请在下方添加</td>`;
      gatewaysTbody.appendChild(tr);
      return;
    }
    own.forEach(gw => {
      const tr = document.createElement('tr');
      const users = (gw.savedAccounts || []).map(a => a.username).join(', ') || '-';
      const isSelected = currentGateway && (currentGateway.id === gw.id || currentGateway.name === gw.name);

      tr.className = isSelected ? 'gw-row is-selected-row' : 'gw-row';
      tr.innerHTML = `
        <td title="${escapeHtml(gw.name)}">
          <div class="gw-name-cell">
            <span class="gw-dot ${isSelected ? 'dot-active' : ''}"></span>
            <strong class="gw-name-text">${escapeHtml(gw.name)}</strong>
          </div>
        </td>
        <td class="gw-ip-cell" title="${escapeHtml(gw.ip)}:${gw.port}">
          <code class="gw-code">${escapeHtml(gw.ip)}:${gw.port}</code>
        </td>
        <td><span class="algo-pill proto-atrust">aTrust</span></td>
        <td class="gw-users-cell" title="${escapeHtml(users)}">${escapeHtml(users)}</td>
        <td>
          <div class="action-btn-cell">
            ${isSelected
              ? '<span class="badge-current-gw">✓ 当前选中</span>'
              : `<button class="btn btn-select btn-sm select-gw-btn" data-id="${gw.id || gw.name}">切换</button>`}
            <button class="btn btn-delete btn-sm delete-gw-btn" data-id="${gw.id || gw.name}" title="删除此网关配置">删除</button>
          </div>
        </td>
      `;
      gatewaysTbody.appendChild(tr);
    });

    // Select Gateway
    gatewaysTbody.querySelectorAll('.select-gw-btn').forEach(b => {
      b.addEventListener('click', (e) => {
        const id = e.target.dataset.id;
        gatewaySelect.value = id;
        onGatewayChanged();
        closeSettingsModal();
      });
    });

    // Delete Gateway
    gatewaysTbody.querySelectorAll('.delete-gw-btn').forEach(b => {
      b.addEventListener('click', async (e) => {
        const id = e.target.dataset.id;
        if (confirm(`确定删除网关 ${id} 吗？`)) {
          await api.deleteGateway(id);
          await reloadGatewaysData();
        }
      });
    });
  }

  // Add Gateway
  //
  // 只加 aTrust 网关：协议由所在界面决定，表单里没有协议下拉，
  // 也没有加密算法——aTrust 的数据面固定走 TLS:441，与本表单无关。
  addGwBtn.addEventListener('click', async () => {
    const name = document.getElementById('new-gw-name').value.trim();
    const ip = document.getElementById('new-gw-ip').value.trim();
    const port = parseInt(document.getElementById('new-gw-port').value, 10) || 443;

    if (!name || !ip) {
      alert('请填写网关名称和 IP 地址');
      return;
    }
    if (name.length > 20) {
      alert('网关名称过长，请控制在 20 个字符以内');
      return;
    }

    await api.saveGateway({ name, ip, port, protocol: 'atrust' });
    document.getElementById('new-gw-name').value = '';
    document.getElementById('new-gw-ip').value = '';
    await reloadGatewaysData();
  });

  // Login Form Submission
  async function handleLogin() {
    const gwId = gatewaySelect.value;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const remember = rememberPwdCheckbox.checked;
    const auto = autoLoginCheckbox.checked;

    if (!gwId || !username || !password) {
      showLoginAlert('请输入网关、用户名和登录密码', 'error');
      return;
    }

    hideLoginAlert();
    setConnectingState(true);

    try {
      const res = await api.login(gwId, username, password, remember, auto);
      showConnectedView(res);
    } catch (err) {
      showLoginAlert(friendlyLoginError(err), 'error');
      setConnectingState(false);
    }
  }

  // friendlyLoginError 只映射 aTrust 后端会给出的码。
  //
  // mfa_required 是 aTrust 独有的：网关要求二次认证，本版本没有实现
  // 对应的交互，必须明确告诉用户而不是显示原始英文。
  function friendlyLoginError(err) {
    if (!err) return '未知错误';
    switch (err.code) {
      case 'mfa_required':
        return '网关要求多因素认证（MFA），当前版本尚未支持，请联系管理员或使用官方客户端。';
      case 'wrong_backend':
        return '该网关不是 aTrust 网关，请到 V5VPN 界面登录。';
      case 'not_atrust_gateway':
        return '该网关不是 aTrust 网关，请到 V5VPN 界面登录。';
      default:
        return err.message || '未知错误';
    }
  }

  loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    handleLogin();
  });

  connectBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleLogin();
  });

  function setConnectingState(connecting) {
    if (connecting) {
      connectBtn.disabled = true;
      connectSpinner.style.display = 'inline-block';
      connectBtnText.textContent = '正在连接网关...';
    } else {
      connectBtn.disabled = false;
      connectSpinner.style.display = 'none';
      connectBtnText.textContent = '立即连接';
    }
  }

  function showLoginAlert(msg, type) {
    loginAlert.textContent = msg;
    loginAlert.className = `alert-box alert-${type}`;
    loginAlert.style.display = 'block';
  }

  function hideLoginAlert() {
    loginAlert.style.display = 'none';
  }

  // Switch to Connected View
  function showConnectedView(info) {
    isConnected = true;
    viewLogin.style.display = 'none';
    viewConnected.style.display = 'flex';
    api.setWindowSize('connected');

    if (currentGateway) {
      connectedGwName.textContent = `${currentGateway.name} (${currentGateway.ip}:${currentGateway.port})`;
    }
    sessionUserVal.textContent = (info && info.username) || usernameInput.value.trim() || '-';
    if (info) {
      sessionIdVal.textContent = info.sessionId || '-';
      sessionIpVal.textContent = info.loginAddress || (currentGateway ? `${currentGateway.ip}:${currentGateway.port}` : '-');
      renderResources(info.resources || []);
      setResourceState(info.resourceState || 'ready', info.resourceError || '');
    }
    startResourcePolling();
    startStatusPolling();
  }

  // setResourceState drives the "loading / ready / failed" affordances in the
  // resource card. A failed fetch keeps the session connected and offers a
  // retry instead of forcing the user back to the login form.
  function setResourceState(state, message) {
    if (resLoadingBadge) {
      resLoadingBadge.style.display = state === 'loading' ? '' : 'none';
    }
    if (refreshResourcesBtn) {
      refreshResourcesBtn.style.display = state === 'error' ? '' : 'none';
    }
    if (resourceErrorBanner) {
      resourceErrorBanner.style.display = state === 'error' ? 'flex' : 'none';
    }
    if (resourceErrorText && state === 'error') {
      resourceErrorText.textContent = message || '网关未在超时时间内返回应用列表。';
    }
    if (state === 'loading') {
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            <span class="mini-spinner" style="display:inline-block;vertical-align:middle;margin-right:8px;"></span>
            正在从网关拉取受保护的应用，请稍候...
          </td>
        </tr>
      `;
    } else if (state === 'error' && (!resourcesTbody.children.length || resCount.textContent === '0')) {
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">应用列表获取失败，aTrust 会话仍有效。请点击「重新拉取应用」重试。</td>
        </tr>
      `;
    }
  }

  // Resource polling: while loading, poll the status endpoint until the
  // background fetch finishes or fails.
  let resourcePollTimer = null;
  let statusPollTimer = null;

  function startResourcePolling() {
    stopResourcePolling();
    let attempts = 0;
    resourcePollTimer = setInterval(async () => {
      attempts++;
      try {
        const st = await api.getStatus();
        if (st && st.status === 'Disconnected') {
          stopResourcePolling();
          showLoginView();
          return;
        }
        if (!st) {
          return;
        }
        const state = st.resourceState || 'ready';
        if (state === 'loading') {
          setResourceState('loading', '');
          return;
        }
        stopResourcePolling();
        setResourceState(state, st.resourceError || '');
        if (state === 'ready') {
          renderResources(st.resources || []);
        }
      } catch (_) {
        if (attempts > 40) stopResourcePolling();
      }
    }, 1000);
  }

  function stopResourcePolling() {
    if (resourcePollTimer) {
      clearInterval(resourcePollTimer);
      resourcePollTimer = null;
    }
  }

  function startStatusPolling() {
    stopStatusPolling();
    let disconnectedCount = 0;
    statusPollTimer = setInterval(async () => {
      if (!isConnected) {
        stopStatusPolling();
        return;
      }
      try {
        const st = await api.getStatus();
        if (st && st.status === 'Disconnected') {
          disconnectedCount++;
          if (disconnectedCount >= 2) {
            showLoginView();
          }
        } else {
          disconnectedCount = 0;
        }
      } catch (_) {}
    }, 1500);
  }

  function stopStatusPolling() {
    if (statusPollTimer) {
      clearInterval(statusPollTimer);
      statusPollTimer = null;
    }
  }

  // Reactive push hook called from Go runtime (e.g. system tray "Disconnect" click)
  window.onVPNDisconnected = function() {
    if (isConnected) {
      showLoginView();
    }
  };

  refreshResourcesBtn?.addEventListener('click', async () => {
    refreshResourcesBtn.disabled = true;
    refreshResourcesBtn.textContent = '正在重新拉取...';
    setResourceState('loading', '');
    try {
      const res = await api.refreshResources();
      setResourceState('ready', '');
      renderResources((res && res.resources) || []);
    } catch (err) {
      setResourceState('error', (err && err.message) || '重新拉取应用失败');
    } finally {
      refreshResourcesBtn.disabled = false;
      refreshResourcesBtn.textContent = '🔄 重新拉取应用';
    }
  });

  // Switch to Login View
  function showLoginView() {
    isConnected = false;
    stopResourcePolling();
    stopStatusPolling();
    viewConnected.style.display = 'none';
    viewLogin.style.display = 'flex';
    setConnectingState(false);
    renderResources([]);
    setResourceState('ready', '');
    api.setWindowSize('login');
  }

  // Disconnect Handler
  disconnectBtn.addEventListener('click', async () => {
    try {
      await api.logout();
    } finally {
      showLoginView();
    }
  });

  // Render Protected Resources Table
  function renderResources(resources) {
    resCount.textContent = resources.length;
    resourcesTbody.innerHTML = '';

    if (!resources || resources.length === 0) {
      resourcesTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">零信任会话中未发现受保护的 TCP 映射应用。</td>
        </tr>
      `;
      return;
    }

    resources.forEach(r => {
      const parts = (r.localProxy || '').split(':');
      const localPort = parts[parts.length - 1] || '';
      let accessUrl = r.accessUrl;
      if (!accessUrl) {
        const isHttps = r.remotePort === '443' || r.remotePort === '8443' || (r.name && (r.name.toLowerCase().includes('https') || r.name.includes('堡垒')));
        accessUrl = (isHttps ? 'https://127.0.0.1:' : 'http://127.0.0.1:') + localPort;
      }

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(r.name)}</strong></td>
        <td><span class="algo-pill">${escapeHtml(r.protocol)}</span></td>
        <td><code>${escapeHtml(r.remoteIp)}:${escapeHtml(r.remotePort)}</code></td>
        <td>
          <a href="${escapeHtml(accessUrl)}" class="proxy-link open-url-btn" data-url="${escapeHtml(accessUrl)}" title="点击在浏览器中打开">${escapeHtml(r.localProxy)}</a>
          <div class="proxy-subtext">${escapeHtml(accessUrl)}</div>
        </td>
        <td><span class="status-pill status-connected"><span class="status-dot"></span>${escapeHtml(r.status)}</span></td>
        <td>
          <div class="action-btn-cell">
            <button class="btn btn-primary btn-sm open-url-btn" data-url="${escapeHtml(accessUrl)}">🌐 在浏览器打开</button>
            <button class="btn btn-secondary btn-sm copy-proxy-btn" data-url="${escapeHtml(accessUrl)}">📋 复制</button>
          </div>
        </td>
      `;
      resourcesTbody.appendChild(tr);
    });

    resourcesTbody.querySelectorAll('.open-url-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const url = btn.dataset.url;
        if (url) api.openURL(url);
      });
    });

    resourcesTbody.querySelectorAll('.copy-proxy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const url = btn.dataset.url;
        navigator.clipboard.writeText(url);
        const originalText = btn.textContent;
        btn.textContent = '已复制!';
        setTimeout(() => { btn.textContent = originalText; }, 1500);
      });
    });
  }

  // Live Logs Poller
  async function pollLogs() {
    try {
      const logs = await api.getLogs();
      if (logs && logs.length > 0) {
        logConsole.innerHTML = '';
        logs.forEach(line => {
          const div = document.createElement('div');
          div.className = 'log-line';
          if (line.includes('[SUCCESS]')) div.className += ' log-success';
          else if (line.includes('[WARN]')) div.className += ' log-warn';
          else if (line.includes('[ERROR]')) div.className += ' log-error';
          else if (line.includes('[DEBUG]')) div.className += ' log-debug';
          else div.className += ' log-info';
          div.textContent = line;
          logConsole.appendChild(div);
        });
        logConsole.scrollTop = logConsole.scrollHeight;
      }
    } catch (_) {}
  }

  // App Initialization
  async function loadAppConfig() {
    try {
      config = await api.getConfig();
      populateGateways(config.gateways, config.lastUseGateway);
      rememberPwdCheckbox.checked = config.remember !== false;
      if (config.appVersion) {
        document.querySelectorAll('.version-badge').forEach(el => {
          el.textContent = config.appVersion;
        });
        document.querySelectorAll('.app-version-text').forEach(el => {
          el.textContent = config.appVersion;
        });
      }

      // Check current connection status in case app was already connected
      const st = await api.getStatus();
      if (st && st.status === 'Connected') {
        showConnectedView(st);
      } else if (settingsModal.style.display !== 'flex') {
        showLoginView();
      }
    } catch (err) {
      console.error('Failed to load app config:', err);
      if (settingsModal.style.display !== 'flex') {
        showLoginView();
      }
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Boot
  loadAppConfig().then(() => {
    logPollTimer = setInterval(pollLogs, 1500);
    pollLogs();
  });
})();

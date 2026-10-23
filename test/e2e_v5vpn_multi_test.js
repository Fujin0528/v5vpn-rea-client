const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { findBrowser } = require('./lib/find-browser');

const TARGET_URL = 'http://127.0.0.1:45678/v5vpn/';
const MOCK_GATEWAY = {
  name: '网御星云测试网关(多场景)',
  ip: '127.0.0.1',
  port: 8443,
  algo: 0 // 国际标准 TLS
};

const TEST_DIR = __dirname;
const RESULTS_DIR = path.join(TEST_DIR, 'results');
const SCREENSHOTS_DIR = path.join(RESULTS_DIR, 'screenshots');
const LOG_FILE = path.join(RESULTS_DIR, 'test.log');
const REPORT_FILE = path.join(RESULTS_DIR, 'report.html');
const REPO_ROOT = path.join(TEST_DIR, '..');

// Two distinct client certificates so the UI can tell a certificate-only login
// apart from the certificate factor of a password + certificate login. The
// alias is what the certificate list shows; the CN is what the gateway logs.
const TEST_CERTS = {
  single: {
    file: path.join(RESULTS_DIR, 'test-cert-single-factor.p12'),
    alias: '单因素证书登录',
    cn: 'SingleFactor-CertLogin-Test',
    password: '123456'
  },
  twoFactor: {
    file: path.join(RESULTS_DIR, 'test-cert-two-factor.p12'),
    alias: '双因素证书',
    cn: 'TwoFactor-Cert-Test',
    password: '123456'
  }
};

// 可选的额外截图归档目录（默认关闭；另一台机器用 ARTIFACT_SCREENSHOTS_DIR 指定）
const ARTIFACT_SCREENSHOTS_DIR = process.env.ARTIFACT_SCREENSHOTS_DIR || SCREENSHOTS_DIR;

// Ensure directories
[RESULTS_DIR, SCREENSHOTS_DIR, ARTIFACT_SCREENSHOTS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Logger
fs.writeFileSync(LOG_FILE, `=== V5VPN Comprehensive Multi-Scenario E2E Test Run Started at ${new Date().toISOString()} ===\n`);
function log(msg) {
  const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const line = `[${ts}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

// 可移植的清空并输入：Ctrl+A 只在 Windows 是全选，macOS 上光标留在末尾，
// Backspace 会误删末字符、输入变成追加。直接用 evaluate 清值避开平台差异。
async function clearAndType(page, selector, value) {
  await page.focus(selector);
  await page.$eval(selector, el => { el.value = ''; });
  await page.type(selector, value);
}

async function setMockMode(mode) {
  log(`[MockServer] Switching simulation mode to: ${mode}`);
  try {
    const res = await fetch(`https://127.0.0.1:8443/api/mode?mode=${mode}`, {
      method: 'POST',
    });
    return await res.json();
  } catch (err) {
    log(`[MockServer] Switch mode via fetch error: ${err.message}`);
  }
}

// Ensure self-signed certs ignored by node fetch
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const scenarios = [];

async function runScenario(scenarioMeta, fn) {
  const t0 = Date.now();
  log(`\n======================================================================`);
  log(`>>> [SCENARIO ${scenarioMeta.id}] ${scenarioMeta.title}`);
  log(`    Description: ${scenarioMeta.desc}`);
  log(`======================================================================`);

  const currentScenario = {
    id: scenarioMeta.id,
    title: scenarioMeta.title,
    desc: scenarioMeta.desc,
    mode: scenarioMeta.mode,
    steps: [],
    status: 'PASS',
    durationMs: 0
  };

  const stepRecorder = async (page, { stepId, title, desc, screenshotName, action }) => {
    const st0 = Date.now();
    log(`  >> [Step ${scenarioMeta.id}.${stepId}] ${title}`);
    let stepStatus = 'PASS';
    let details = '';
    let errorObj = null;

    try {
      if (action) details = await action();
    } catch (err) {
      stepStatus = 'FAIL';
      errorObj = err;
      currentScenario.status = 'FAIL';
      log(`  !! Step ${scenarioMeta.id}.${stepId} FAILED: ${err.message}`);
    }

    const sDuration = Date.now() - st0;

    // Screenshot
    const ssPath = path.join(SCREENSHOTS_DIR, screenshotName);
    await page.screenshot({ path: ssPath, fullPage: false });
    const artPath = path.join(ARTIFACT_SCREENSHOTS_DIR, screenshotName);
    fs.copyFileSync(ssPath, artPath);
    const ssBase64 = fs.readFileSync(ssPath).toString('base64');

    currentScenario.steps.push({
      stepId,
      title,
      desc,
      status: stepStatus,
      durationMs: sDuration,
      details: details || '',
      error: errorObj ? errorObj.message : null,
      screenshotName,
      screenshotBase64: `data:image/png;base64,${ssBase64}`
    });

    log(`  << [Step ${scenarioMeta.id}.${stepId}] ${stepStatus} (${sDuration}ms) - Screenshot: ${screenshotName}`);
    if (errorObj) throw errorObj;
  };

  try {
    await fn(stepRecorder);
  } catch (err) {
    currentScenario.status = 'FAIL';
    log(`!!! Scenario ${scenarioMeta.id} terminated with error: ${err.message}`);
  }

  currentScenario.durationMs = Date.now() - t0;
  log(`<<< [SCENARIO ${scenarioMeta.id}] Result: ${currentScenario.status} (${currentScenario.durationMs}ms)\n`);
  scenarios.push(currentScenario);
}

// Helpers for UI actions
async function ensureGatewayConfigured(page) {
  await page.evaluate(async (gw) => {
    // Check if mock gateway exists
    const res = await fetch('/api/config');
    const cfg = await res.json();
    const existing = (cfg.gateways || []).find(g => g.ip === gw.ip && g.port === gw.port);
    if (!existing) {
      await fetch('/api/gateways', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(gw)
      });
    }
  }, MOCK_GATEWAY);

  await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#gateway-select');

  await page.evaluate((gw) => {
    const select = document.getElementById('gateway-select');
    for (let i = 0; i < select.options.length; i++) {
      if (select.options[i].text.includes(gw.name) || select.options[i].text.includes(`${gw.ip}:${gw.port}`)) {
        select.selectedIndex = i;
        select.dispatchEvent(new Event('change'));
        break;
      }
    }
  }, MOCK_GATEWAY);
  await page.evaluate(() => new Promise(r => setTimeout(r, 400)));
}

function ensureCertFile(cert) {
  if (fs.existsSync(cert.file)) return;
  const goBin = process.platform === 'win32' ? 'go.exe' : 'go';
  log(`[Cert] Generating ${path.basename(cert.file)} (CN=${cert.cn})`);
  execFileSync(goBin, ['run', './test/gencert.go', '-out', cert.file, '-cn', cert.cn, '-pwd', cert.password], {
    cwd: REPO_ROOT,
    stdio: 'inherit'
  });
}

async function ensureCertImported(page) {
  for (const cert of Object.values(TEST_CERTS)) {
    ensureCertFile(cert);
  }

  await page.evaluate(async (certsToImport) => {
    const listRes = await fetch('/api/certs?source=0');
    const existing = await listRes.json();
    const names = new Set((existing || []).map(c => c.name));
    for (const cert of certsToImport) {
      if (names.has(cert.alias)) continue;
      await fetch('/api/certs/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: cert.file,
          alias: cert.alias,
          password: cert.password
        })
      });
    }
  }, Object.values(TEST_CERTS));
  await page.evaluate(() => new Promise(r => setTimeout(r, 400)));
}

// The challenge modal is the single surface for gateway challenges. Wait for
// it to be open and return the title text (each builder sets a distinct one).
async function waitForChallengeModal(page, timeout = 8000) {
  await page.waitForFunction(() => {
    const m = document.getElementById('challenge-modal');
    return m && m.style.display !== 'none';
  }, { timeout });
  return page.$eval('#challenge-title', el => el.textContent.trim());
}

// Select a certificate inside the challenge modal's list. Both the chain
// challenge (after code 2) and the standalone certificate login render the
// same #modal-cert-list, so one helper serves every certificate scenario.
async function selectCertInModal(page, alias) {
  await page.waitForFunction((a) => {
    return Array.from(document.querySelectorAll('#modal-cert-list .cert-item .cert-name'))
      .some(el => (el.textContent || '').includes(a));
  }, { timeout: 5000 }, alias);

  const selected = await page.evaluate((a) => {
    const items = Array.from(document.querySelectorAll('#modal-cert-list .cert-item'));
    const item = items.find(el => ((el.querySelector('.cert-name') || {}).textContent || '').includes(a));
    if (!item) return null;
    item.click();
    return ((item.querySelector('.cert-name') || {}).textContent || '').trim();
  }, alias);
  if (!selected) {
    throw new Error(`挑战模态中未找到测试证书「${alias}」`);
  }
  return selected;
}

async function safeDisconnect(page) {
  const isConnected = await page.evaluate(() => {
    const v = document.getElementById('view-connected');
    return v && v.style.display !== 'none';
  });
  if (isConnected) {
    // 直接在元素上派发 click：头部轮询刷新会引起布局抖动，坐标点击可能落空。
    await page.$eval('#disconnect-btn', el => el.click());
    await page.waitForFunction(() => {
      const v = document.getElementById('view-login');
      return v && v.style.display !== 'none';
    }, { timeout: 8000 });
  }
}

async function run() {
  const browserPath = findBrowser();
  if (!browserPath) throw new Error('未找到 Edge/Chrome；可用 EDGE_PATH 环境变量指定');
  log(`使用浏览器: ${browserPath}`);
  const browser = await puppeteer.launch({
    executablePath: browserPath,
    headless: 'new',
    defaultViewport: { width: 1280, height: 880 },
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--ignore-certificate-errors',
      '--window-size=1280,880'
    ]
  });

  const page = await browser.newPage();

  page.on('console', msg => {
    if (msg.text().includes('api/') || msg.text().includes('Auth')) {
      log(`[Browser Console] ${msg.text()}`);
    }
  });

  try {
    // =========================================================================
    // SCENARIO 1: 口令 + 证书两步双因素认证 (2FA Happy Path)
    // =========================================================================
    await runScenario({
      id: 1,
      title: '口令 + 证书两步双因素认证 (2FA)',
      desc: '固定表单提交口令后，网关返回 code=2 挑战：客户端弹出证书模态，选中证书呈递 mTLS 握手并加载内网资源。登录框高度全程恒定。',
      mode: 'pwd-cert'
    }, async (record) => {
      await setMockMode('pwd-cert');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '固定表单填入口令凭据',
        desc: '输入用户名 admin / 密码 admin123。表单只有网关+账号+口令，没有任何挑战组件。',
        screenshotName: 'sc1_step1_setup.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');
          await clearAndType(page, '#password-input', 'admin123');

          const btnText = await page.$eval('#connect-btn-text', el => el.textContent.trim());
          const modalHidden = await page.$eval('#challenge-modal', el => el.style.display === 'none');
          return `固定表单就绪。连接按钮: "${btnText}"，挑战模态未弹出: ${modalHidden}`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '提交口令触发证书挑战模态',
        desc: '点击连接，口令校验通过 (code=2)，客户端弹出「网关要求客户端证书」模态并选中双因素测试证书。',
        screenshotName: 'sc1_step2_cert_challenge_modal.png',
        action: async () => {
          await page.click('#connect-btn');
          const title = await waitForChallengeModal(page);
          if (!title.includes('客户端证书')) {
            throw new Error(`模态标题不是证书挑战: "${title}"`);
          }
          const certText = await selectCertInModal(page, TEST_CERTS.twoFactor.alias);
          return `证书挑战模态已弹出（标题: "${title}"），选中证书: "${certText}"`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '呈递证书完成双因素认证并获取资源',
        desc: '点击「呈递证书并连接」，客户端在挑战会话上执行 mTLS 证书握手，网关验证通过建立隧道并拉取 3 项内网资源。',
        screenshotName: 'sc1_step3_connected.png',
        action: async () => {
          await page.click('#modal-cert-submit');

          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `双因素认证成功！会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 2: 纯口令直接认证 (Single Factor - Password Only)
    // =========================================================================
    await runScenario({
      id: 2,
      title: '仅口令直接认证 (Password Only)',
      desc: '网关配置为纯口令模式（pwd-only），用户提交用户名密码后直接登录成功并建立隧道。',
      mode: 'pwd-only'
    }, async (record) => {
      await setMockMode('pwd-only');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '输入账号密码并准备单因素连接',
        desc: '固定表单输入 admin / admin123，连接按钮显示「立即连接」，无任何附加因子组件。',
        screenshotName: 'sc2_step1_password_panel.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');

          await clearAndType(page, '#password-input', 'admin123');

          const btnText = await page.$eval('#connect-btn-text', el => el.textContent.trim());
          return `口令表单就绪。连接按钮文字: "${btnText}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '纯口令直连成功并建立安全隧道',
        desc: '网关直接返回 code=0，无需客户端证书，会话即刻建立。',
        screenshotName: 'sc2_step2_connected_direct.png',
        action: async () => {
          await page.click('#connect-btn');
          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `纯口令直连成功！会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 3: 纯客户端证书免密认证 (Cert Only - mTLS)
    // =========================================================================
    await runScenario({
      id: 3,
      title: '仅客户端证书免密认证 (Cert Only)',
      desc: '点击常驻的「🪪 使用客户端证书直接登录」链接，证书模态以 standalone 模式打开；选中证书直接经 TLS 握手登录，全程无需口令（原厂 Opt_Cert 入口）。',
      mode: 'cert-only'
    }, async (record) => {
      await setMockMode('pwd-cert');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '证书入口打开证书模态并选中证书',
        desc: '点击「使用客户端证书直接登录」，模态标题为「证书直接登录」，列表中选中「单因素证书登录」测试证书。',
        screenshotName: 'sc3_step1_cert_modal.png',
        action: async () => {
          await page.click('#cert-only-link');
          const title = await waitForChallengeModal(page);
          if (!title.includes('证书直接登录')) {
            throw new Error(`模态标题不是证书直接登录: "${title}"`);
          }
          await page.waitForSelector('#modal-cert-list .cert-item', { visible: true, timeout: 5000 });
          const certName = await selectCertInModal(page, TEST_CERTS.single.alias);

          const certCards = await page.$$eval('#modal-cert-list .cert-item', els => els.length);
          const submitText = await page.$eval('#modal-cert-submit', el => el.textContent.trim());
          return `证书模态（standalone）就绪，选中证书: "${certName}"，可用证书数: ${certCards}，提交按钮: "${submitText}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '证书直连成功建立安全隧道',
        desc: '点击「证书安全连接」，客户端上送 TLS 客户端证书至 /vpn/user/auth/cert，网关校验通过，会话建立。',
        screenshotName: 'sc3_step2_cert_connected.png',
        action: async () => {
          await page.click('#modal-cert-submit');
          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `纯证书登录成功！会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 4: 账密错误异常拦截与告警 (Bad Credentials)
    // =========================================================================
    await runScenario({
      id: 4,
      title: '账密错误异常拦截与告警 (Bad Credentials)',
      desc: '用户输入错误口令，网关返回 0x8000001a 拒绝，客户端精准展示红色告警提示并保留在登录页。',
      mode: 'err-auth'
    }, async (record) => {
      await setMockMode('err-auth');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '输入错误密码并捕获告警条',
        desc: '输入密码 WrongPassword999，提交连接，捕获客户端页面顶部的错误提示条。',
        screenshotName: 'sc4_step1_bad_credentials_alert.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');

          await clearAndType(page, '#password-input', 'WrongPassword999');

          await page.click('#connect-btn');
          await page.waitForSelector('#login-alert', { visible: true, timeout: 8000 });

          const alertText = await page.$eval('#login-alert', el => el.textContent.trim());
          const btnDisabled = await page.$eval('#connect-btn', el => el.disabled);
          return `网关成功拦截错误账密。页面提示: "${alertText}"，按钮恢复状态: ${!btnDisabled}`;
        }
      });
    });

    // =========================================================================
    // SCENARIO 5: 口令过期强制在线改密与续连 (Password Expired & Change)
    // =========================================================================
    await runScenario({
      id: 5,
      title: '口令过期强制在线改密与自动续连',
      desc: '网关返回 code=256（口令过期），客户端弹出改密模态，用户输入新密码后一键改密并成功登录。',
      mode: 'pwd-change'
    }, async (record) => {
      await setMockMode('pwd-change');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '触发口令过期并弹出改密模态',
        desc: '输入原口令 admin123 尝试连接，网关返回 256 挑战码，客户端弹出「修改密码」模态。',
        screenshotName: 'sc5_step1_pwd_expired_challenge.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');

          await clearAndType(page, '#password-input', 'admin123');

          await page.click('#connect-btn');
          const title = await waitForChallengeModal(page);
          if (!title.includes('修改密码')) {
            throw new Error(`模态标题不是修改密码: "${title}"`);
          }

          const hint = await page.$eval('.challenge-hint', el => el.textContent.trim());
          return `成功触发改密流程。模态提示: "${hint}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '输入新密码完成改密并自动续连成功',
        desc: '在模态中输入新密码 admin456 并确认，提交改密并继续连接，网关更新密码并建立隧道。',
        screenshotName: 'sc5_step2_pwd_change_success_connected.png',
        action: async () => {
          await page.focus('#modal-new-password');
          await page.type('#modal-new-password', 'admin456');

          await page.focus('#modal-confirm-password');
          await page.type('#modal-confirm-password', 'admin456');

          await page.click('#modal-pwd-submit');

          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 12000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `改密并续连成功！会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 6: 图形验证码挑战与校验 (Captcha / Verifycode Flow)
    // =========================================================================
    await runScenario({
      id: 6,
      title: '图形验证码挑战与协议校验 (Verifycode)',
      desc: '网关返回 code=0x80 要求验证码，客户端展开图形验证码组件并展示随机动态验证码图片；验证错误验证码拦截与正确验证码登录。',
      mode: 'verifycode'
    }, async (record) => {
      await setMockMode('verifycode');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '首次提交触发验证码模态与动态图片渲染',
        desc: '未输入验证码提交登录，网关返回 0x80，客户端弹出「图形验证码」模态并渲染随机验证码图。',
        screenshotName: 'sc6_step1_verifycode_prompt.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');

          await clearAndType(page, '#password-input', 'admin456'); // updated password

          await page.click('#connect-btn');
          const title = await waitForChallengeModal(page);
          if (!title.includes('图形验证码')) {
            throw new Error(`模态标题不是图形验证码: "${title}"`);
          }
          await page.waitForFunction(() => {
            const img = document.getElementById('modal-verifycode-img');
            return img && img.style.display !== 'none' && img.src.startsWith('data:image');
          }, { timeout: 8000 });

          const hasImg = await page.$eval('#modal-verifycode-img', el => el.src.length > 50);
          return `验证码模态已弹出，随机图片渲染完成（图片存在: ${hasImg}）。模态标题: "${title}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '输入错误验证码被网关精准拦截',
        desc: '在模态中输入错误验证码 9999 提交，网关比对不匹配返回 0x80000021，模态重开并展示拦截原因与刷新后的验证码图片。',
        screenshotName: 'sc6_step2_verifycode_wrong_rejected.png',
        action: async () => {
          await clearAndType(page, '#modal-verifycode-input', '9999');

          await page.click('#modal-verifycode-submit');
          // The rejected code re-runs the login; the modal re-opens with the
          // gateway's reason and a fresh image.
          await page.waitForFunction(() => {
            const m = document.getElementById('challenge-modal');
            const alert = document.getElementById('modal-alert');
            return m && m.style.display !== 'none' && alert && alert.style.display !== 'none' &&
              alert.textContent.includes('验证码');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#modal-alert', el => el.textContent.trim());
          return `错误验证码被成功拦截，模态重开可重试。模态内提示: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '输入正确动态验证码成功完成登录',
        desc: '获取网关当前随机验证码，填入模态并提交，网关校验通过并建立安全隧道。',
        screenshotName: 'sc6_step3_verifycode_connected.png',
        action: async () => {
          let expectedCode = '1234';
          try {
            const r = await fetch('https://127.0.0.1:8443/api/verifycode');
            const data = await r.json();
            if (data && data.code) expectedCode = data.code;
          } catch (e) {
            log(`Fetch mock verifycode: ${e.message}`);
          }

          log(`  >> Entering active random verifycode: ${expectedCode}`);
          await clearAndType(page, '#modal-verifycode-input', expectedCode);

          await page.click('#modal-verifycode-submit');
          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `动态验证码 (${expectedCode}) 校验通过，成功连接！会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 7: 证书失效/过期异常拦截 (Cert Error Handling)
    // =========================================================================
    await runScenario({
      id: 7,
      title: '客户端证书过期异常拦截 (Cert Expired)',
      desc: '网关模拟证书已过期状态（code=0x106），客户端证书认证被拒绝并展示精准的证书过期提示。',
      mode: 'err-cert'
    }, async (record) => {
      await setMockMode('err-cert');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '提交证书并捕获证书过期告警',
        desc: '从证书入口提交认证，网关判定证书过期返回 0x106；模态保留并展示证书过期提示，用户可原地换证书重试。',
        screenshotName: 'sc7_step1_cert_expired_alert.png',
        action: async () => {
          await page.click('#cert-only-link');
          const title = await waitForChallengeModal(page);
          if (!title.includes('证书直接登录')) {
            throw new Error(`模态标题不是证书直接登录: "${title}"`);
          }
          await page.waitForSelector('#modal-cert-list .cert-item', { visible: true, timeout: 5000 });
          await selectCertInModal(page, TEST_CERTS.single.alias);

          await page.click('#modal-cert-submit');
          await page.waitForFunction(() => {
            const alert = document.getElementById('modal-alert');
            return alert && alert.style.display !== 'none' && alert.textContent.includes('过期');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#modal-alert', el => el.textContent.trim());
          const modalStillOpen = await page.$eval('#challenge-modal', el => el.style.display !== 'none');
          return `证书过期拦截生效，模态保留可换证书重试（模态可见: ${modalStillOpen}）。模态内提示: "${alertText}"`;
        }
      });
    });

    // =========================================================================
    // SCENARIO 8: 短信认证多因素挑战 (SMS MFA)
    // =========================================================================
    await runScenario({
      id: 8,
      title: '短信认证多因素挑战 (SMS MFA)',
      desc: '网关返回 code=8（多因素认证，短信认证）要求短信因子：客户端弹出短信认证模态，点击「发送短信」请求网关下发验证码；错误验证码被 0x10A 精准拦截，正确验证码完成登录并建立隧道。',
      mode: 'sms'
    }, async (record) => {
      await setMockMode('sms');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '口令登录触发短信认证挑战模态',
        desc: '输入 admin / admin456（场景 5 改密后的当前口令）点击连接，网关口令校验通过但返回 code=8，客户端弹出短信认证模态。',
        screenshotName: 'sc8_step1_sms_challenge.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');
          await clearAndType(page, '#password-input', 'admin456');

          await page.click('#connect-btn');
          const title = await waitForChallengeModal(page);
          if (!title.includes('短信认证')) {
            throw new Error(`模态标题不是短信认证: "${title}"`);
          }

          const hint = await page.$eval('.challenge-hint', el => el.textContent.trim());
          return `短信认证模态已弹出。模态提示: "${hint}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '请求网关下发短信验证码并进入重发倒计时',
        desc: '点击「📱 发送短信」，客户端经 GET /vpn/user/auth/send_smc 请求网关向用户手机下发验证码，按钮进入 60 秒重发倒计时。',
        screenshotName: 'sc8_step2_sms_sent_countdown.png',
        action: async () => {
          await page.click('#modal-sms-send');
          await page.waitForFunction(() => {
            const btn = document.getElementById('modal-sms-send');
            return btn && btn.disabled && /秒/.test(btn.textContent);
          }, { timeout: 8000 });

          const btnText = await page.$eval('#modal-sms-send', el => el.textContent.trim());
          const alertText = await page.$eval('#modal-alert', el => el.textContent.trim());
          return `网关已接受下发请求，按钮进入倒计时: "${btnText}"。模态内提示: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '错误短信验证码被 0x10A 精准拦截',
        desc: '输入错误验证码 000000 提交（POST /vpn/user/auth/smc），网关比对失败返回 0x10A 短信码错误，客户端保留模态允许原地重试。',
        screenshotName: 'sc8_step3_sms_wrong_rejected.png',
        action: async () => {
          await clearAndType(page, '#modal-sms-input', '000000');
          await page.click('#modal-sms-submit');

          await page.waitForFunction(() => {
            const alert = document.getElementById('modal-alert');
            return alert && alert.style.display !== 'none' && alert.textContent.includes('短信验证码错误');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#modal-alert', el => el.textContent.trim());
          const modalVisible = await page.$eval('#challenge-modal', el => el.style.display !== 'none');
          const inputCleared = await page.$eval('#modal-sms-input', el => el.value === '');
          return `错误验证码被拦截，模态保留可重试（模态可见: ${modalVisible}，输入已清空: ${inputCleared}）。模态内提示: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 4,
        title: '输入正确短信验证码完成多因素登录',
        desc: '从 mock 网关的测试接口读取刚下发的验证码（模拟用户查看手机短信），填入提交，网关校验通过建立隧道并拉取内网资源。',
        screenshotName: 'sc8_step4_sms_connected.png',
        action: async () => {
          let expectedCode = '123456';
          try {
            const r = await fetch('https://127.0.0.1:8443/api/smscode');
            const data = await r.json();
            if (data && data.code) expectedCode = data.code;
          } catch (e) {
            log(`Fetch mock smscode: ${e.message}`);
          }

          log(`  >> Entering active SMS code: ${expectedCode}`);
          await clearAndType(page, '#modal-sms-input', expectedCode);
          await page.click('#modal-sms-submit');

          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `短信认证成功！验证码 ${expectedCode} 校验通过，会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    // =========================================================================
    // SCENARIO 9: 口令 + 证书 + 短信三因素链 (Password + Cert + SMS)
    // =========================================================================
    await runScenario({
      id: 9,
      title: '口令 + 证书 + 短信三因素链 (Pwd+Cert+SMS)',
      desc: '网关驱动的最长认证链：口令 (code=2) -> 证书模态 -> 短信模态 (code=8) -> 完成 (code=0)。两个挑战模态先后替换、挑战会话不断；错码被 0x10A 拦截，正确验证码完成登录并按「口令+证书」记录会话。',
      mode: 'pwd-cert-sms'
    }, async (record) => {
      await setMockMode('pwd-cert-sms');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '口令提交触发证书模态，呈递证书后模态替换为短信',
        desc: '固定表单输入 admin / admin456 点击连接：口令通过 (code=2) 弹出证书模态；呈递双因素证书后网关追加 code=8，证书模态被短信模态原地替换。',
        screenshotName: 'sc9_step1_pwdcert_sms_challenge.png',
        action: async () => {
          await clearAndType(page, '#username-input', 'admin');
          await clearAndType(page, '#password-input', 'admin456');

          await page.click('#connect-btn');
          let title = await waitForChallengeModal(page, 10000);
          if (!title.includes('客户端证书')) {
            throw new Error(`第一跳模态标题不是证书挑战: "${title}"`);
          }
          const certText = await selectCertInModal(page, TEST_CERTS.twoFactor.alias);

          await page.click('#modal-cert-submit');
          // The certificate factor is accepted; the gateway appends the SMS
          // factor and the SAME modal surface is rebuilt for it.
          await page.waitForFunction(() => {
            const t = document.getElementById('challenge-title');
            return t && t.textContent.includes('短信认证');
          }, { timeout: 10000 });

          const hint = await page.$eval('.challenge-hint', el => el.textContent.trim());
          return `口令与证书因子均通过，证书模态已替换为短信模态。关联证书: "${certText}"，模态提示: "${hint}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '请求网关向预设手机号下发短信验证码',
        desc: '点击「📱 发送短信」，客户端在挑战会话上 GET /vpn/user/auth/send_smc，网关向账号预设手机号下发验证码，按钮进入 60 秒倒计时。',
        screenshotName: 'sc9_step2_sms_sent_countdown.png',
        action: async () => {
          await page.click('#modal-sms-send');
          await page.waitForFunction(() => {
            const btn = document.getElementById('modal-sms-send');
            return btn && btn.disabled && /秒/.test(btn.textContent);
          }, { timeout: 8000 });

          const btnText = await page.$eval('#modal-sms-send', el => el.textContent.trim());
          return `验证码已下发（手机号为网关侧账号预设属性），按钮倒计时: "${btnText}"`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '错误短信验证码被 0x10A 拦截且挑战保留',
        desc: '输入错误验证码 000000 提交，网关返回 0x10A 短信码错误；已呈递的口令与证书因子不清空，短信模态保留允许原地重试。',
        screenshotName: 'sc9_step3_sms_wrong_rejected.png',
        action: async () => {
          await clearAndType(page, '#modal-sms-input', '000000');
          await page.click('#modal-sms-submit');

          await page.waitForFunction(() => {
            const alert = document.getElementById('modal-alert');
            return alert && alert.style.display !== 'none' && alert.textContent.includes('短信验证码错误');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#modal-alert', el => el.textContent.trim());
          const modalVisible = await page.$eval('#challenge-modal', el => el.style.display !== 'none');
          return `错误验证码被拦截，口令+证书挑战保留（模态可见: ${modalVisible}）。模态内提示: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 4,
        title: '正确短信验证码完成三因素登录',
        desc: '从 mock 网关测试接口读取刚下发的验证码（模拟用户查看手机），提交后网关校验通过建立隧道，会话按「口令+证书」双因子记录。',
        screenshotName: 'sc9_step4_sms_connected.png',
        action: async () => {
          let expectedCode = '123456';
          try {
            const r = await fetch('https://127.0.0.1:8443/api/smscode');
            const data = await r.json();
            if (data && data.code) expectedCode = data.code;
          } catch (e) {
            log(`Fetch mock smscode: ${e.message}`);
          }

          log(`  >> Entering active SMS code: ${expectedCode}`);
          await clearAndType(page, '#modal-sms-input', expectedCode);
          await page.click('#modal-sms-submit');

          await page.waitForFunction(() => {
            const v = document.getElementById('view-connected');
            return v && v.style.display !== 'none';
          }, { timeout: 10000 });

          await page.waitForFunction(() => {
            const rows = document.querySelectorAll('#resources-tbody tr');
            const txt = rows[0]?.textContent || '';
            return rows.length > 0 && !txt.includes('正在从网关拉取');
          }, { timeout: 10000 });

          const sessionUser = await page.$eval('#session-user-val', el => el.textContent.trim());
          const sessionId = await page.$eval('#session-id-val', el => el.textContent.trim());
          const resCount = await page.$eval('#res-count', el => el.textContent.trim());
          const resNames = await page.$$eval('#resources-tbody tr', els => els.map(tr => tr.querySelector('td strong')?.textContent?.trim() || ''));
          return `三因素链完成！验证码 ${expectedCode} 校验通过，会话用户: ${sessionUser}，会话ID: ${sessionId}，内网资源数: ${resCount} 项 [${resNames.join(' | ')}]`;
        }
      });

      await safeDisconnect(page);
    });

    log(`\nAll ${scenarios.length} Scenarios executed! Total Scenarios: ${scenarios.length}`);

  } catch (err) {
    log(`FATAL RUNNER ERROR: ${err.stack || err.message}`);
  } finally {
    // Reset mock server to default pwd-cert mode
    await setMockMode('pwd-cert');
    await browser.close();
    log(`Browser closed.`);
  }

  // Generate Comprehensive HTML Report
  generateHtmlReport();
}

function generateHtmlReport() {
  log(`Generating Comprehensive HTML test report: ${REPORT_FILE}`);
  const passCount = scenarios.filter(s => s.status === 'PASS').length;
  const failCount = scenarios.filter(s => s.status === 'FAIL').length;
  const totalDuration = scenarios.reduce((acc, s) => acc + s.durationMs, 0);
  const totalSteps = scenarios.reduce((acc, s) => acc + s.steps.length, 0);

  const logContent = fs.existsSync(LOG_FILE) ? fs.readFileSync(LOG_FILE, 'utf-8') : '';

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V5VPN 客户端全场景自动化测试执行报告</title>
  <style>
    :root {
      --bg: #0b1120;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --accent: #818cf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 30px 20px;
    }
    .container { max-width: 1280px; margin: 0 auto; }

    header {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px 32px;
      margin-bottom: 24px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
    }
    .header-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      margin-bottom: 16px;
    }
    h1 { font-size: 24px; color: #fff; display: flex; align-items: center; gap: 10px; }
    .badge {
      display: inline-block;
      padding: 4px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
    }
    .badge-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-fail { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--card-border);
    }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
    .meta-value { font-size: 15px; font-weight: 600; color: #fff; margin-top: 4px; }

    .stats-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px 20px;
      text-align: center;
    }
    .stat-num { font-size: 32px; font-weight: 700; color: var(--primary); }
    .stat-num.pass { color: var(--success); }
    .stat-num.fail { color: var(--danger); }
    .stat-title { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

    .scenario-block {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 30px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    }
    .scenario-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid #334155;
    }
    .scenario-title-wrap { display: flex; align-items: center; gap: 12px; }
    .scenario-badge-num {
      background: var(--accent);
      color: #fff;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 14px;
    }
    .scenario-title { font-size: 18px; font-weight: 700; color: #fff; }
    .scenario-desc { color: var(--text-muted); font-size: 14px; margin-bottom: 20px; }

    .steps-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 20px;
    }
    .step-card {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
    }
    .step-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .step-name { font-size: 15px; font-weight: 600; color: #38bdf8; }
    .step-desc { font-size: 13px; color: var(--text-muted); margin-bottom: 10px; flex-grow: 0; }
    .step-details {
      background: #1e293b;
      border-left: 3px solid var(--success);
      padding: 8px 12px;
      font-size: 12px;
      color: #cbd5e1;
      border-radius: 0 4px 4px 0;
      margin-bottom: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .screenshot-thumb-box {
      margin-top: auto;
      text-align: center;
      background: #020617;
      border-radius: 6px;
      padding: 8px;
      border: 1px solid #1e293b;
    }
    .screenshot-thumb-box img {
      width: 100%;
      height: auto;
      border-radius: 4px;
      border: 1px solid #334155;
      cursor: zoom-in;
      transition: transform 0.2s;
    }
    .screenshot-thumb-box img:hover {
      transform: scale(1.02);
    }
    .screenshot-caption { font-size: 11px; color: var(--text-muted); margin-top: 6px; }

    .log-container {
      background: #0b0f19;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
      max-height: 400px;
      overflow-y: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #94a3b8;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .lightbox {
      display: none;
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.92);
      z-index: 99999;
      align-items: center;
      justify-content: center;
      cursor: zoom-out;
    }
    .lightbox.active { display: flex; }
    .lightbox img {
      max-width: 95%;
      max-height: 95%;
      border-radius: 8px;
      box-shadow: 0 0 35px rgba(0,0,0,0.8);
    }

    footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--card-border);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-top">
        <h1>🛡️ V5VPN 客户端全场景自动化测试执行报告</h1>
        <span class="badge ${failCount === 0 ? 'badge-pass' : 'badge-fail'}">
          ${failCount === 0 ? '✓ 全部场景 100% 通过 (ALL SCENARIOS PASSED)' : '✕ 存在失败场景'}
        </span>
      </div>
      <div class="meta-grid">
        <div class="meta-item">
          <span class="meta-label">被测目标</span>
          <span class="meta-value">V5VPN 安全客户端 (v0.4.0)</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">网关仿真环境</span>
          <span class="meta-value">网御星云多模式仿真网关 (127.0.0.1:8443)</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">自动化引擎</span>
          <span class="meta-value">Microsoft Edge + Puppeteer-Core</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">执行时间</span>
          <span class="meta-value">${new Date().toLocaleString('zh-CN')}</span>
        </div>
      </div>
    </header>

    <div class="stats-cards">
      <div class="stat-card">
        <div class="stat-num">${scenarios.length}</div>
        <div class="stat-title">覆盖测试场景</div>
      </div>
      <div class="stat-card">
        <div class="stat-num pass">${passCount}</div>
        <div class="stat-title">通过场景数</div>
      </div>
      <div class="stat-card">
        <div class="stat-num ${failCount > 0 ? 'fail' : ''}">${failCount}</div>
        <div class="stat-title">失败场景数</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">${totalSteps}</div>
        <div class="stat-title">总操作步骤</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">${(totalDuration / 1000).toFixed(2)}s</div>
        <div class="stat-title">总耗时</div>
      </div>
    </div>

    ${scenarios.map(sc => `
      <div class="scenario-block" id="scenario-${sc.id}">
        <div class="scenario-header">
          <div class="scenario-title-wrap">
            <span class="scenario-badge-num">场景 ${sc.id}</span>
            <span class="scenario-title">${sc.title}</span>
          </div>
          <div>
            <span class="badge ${sc.status === 'PASS' ? 'badge-pass' : 'badge-fail'}">${sc.status}</span>
            <span style="font-size: 13px; color: var(--text-muted); margin-left: 8px;">${sc.durationMs}ms</span>
          </div>
        </div>
        <p class="scenario-desc">${sc.desc}</p>

        <div class="steps-grid">
          ${sc.steps.map(st => `
            <div class="step-card">
              <div class="step-header">
                <span class="step-name">步骤 ${sc.id}.${st.stepId}：${st.title}</span>
                <span class="badge ${st.status === 'PASS' ? 'badge-pass' : 'badge-fail'}" style="font-size: 11px; padding: 2px 8px;">${st.status}</span>
              </div>
              <p class="step-desc">${st.desc}</p>
              <div class="step-details"><strong>结果：</strong>${st.details}</div>
              <div class="screenshot-thumb-box">
                <img src="${st.screenshotBase64}" alt="${st.screenshotName}" onclick="openLightbox(this.src)">
                <div class="screenshot-caption">📷 <code>${st.screenshotName}</code>（点击放大）</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `).join('')}

    <h2 style="font-size: 20px; margin: 30px 0 16px; color: #fff;">📋 完整自动化测试执行日志 (test.log)</h2>
    <div class="log-container">${logContent.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>

    <footer>
      Generated automatically by V5VPN Comprehensive Test Runner • ${new Date().toISOString()}
    </footer>
  </div>

  <div id="lightbox" class="lightbox" onclick="closeLightbox()">
    <img id="lightbox-img" src="" alt="Enlarged view">
  </div>

  <script>
    function openLightbox(src) {
      document.getElementById('lightbox-img').src = src;
      document.getElementById('lightbox').classList.add('active');
    }
    function closeLightbox() {
      document.getElementById('lightbox').classList.remove('active');
    }
  </script>
</body>
</html>`;

  fs.writeFileSync(REPORT_FILE, html);
  log(`Comprehensive HTML Report saved to: ${REPORT_FILE}`);
}

run();

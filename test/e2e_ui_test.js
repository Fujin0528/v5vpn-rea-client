const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const TARGET_URL = 'http://127.0.0.1:45678/index.html';
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
const CERT_FILE = path.join(RESULTS_DIR, 'test-client.p12');

const ARTIFACT_SCREENSHOTS_DIR = 'C:\\Users\\Administrator\\.gemini\\antigravity-cli\\brain\\0082d507-aeda-4641-9b43-2c96290f5b61\\screenshots';

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

async function ensureCertImported(page) {
  await page.evaluate(async (certPath) => {
    const listRes = await fetch('/api/certs?source=0');
    const certs = await listRes.json();
    if (!certs || certs.length === 0) {
      await fetch('/api/certs/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: certPath,
          alias: '网御自动化测试证书(Leadsec-Admin)',
          password: '123456'
        })
      });
    }
  }, CERT_FILE);
  await page.evaluate(() => new Promise(r => setTimeout(r, 400)));
}

async function safeDisconnect(page) {
  const isConnected = await page.evaluate(() => {
    const v = document.getElementById('view-connected');
    return v && v.style.display !== 'none';
  });
  if (isConnected) {
    await page.click('#disconnect-btn');
    await page.waitForFunction(() => {
      const v = document.getElementById('view-login');
      return v && v.style.display !== 'none';
    }, { timeout: 8000 });
  }
}

async function run() {
  log(`Launching Microsoft Edge: ${EDGE_PATH}`);
  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
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
      desc: '网关返回 code=2 挑战要求呈递客户端证书，客户端先后完成口令校验与 mTLS 证书握手并加载内网资源。',
      mode: 'pwd-cert'
    }, async (record) => {
      await setMockMode('pwd-cert');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '选择双因素 Tab 并填入凭据',
        desc: '切换至「🔐 口令+证书」认证 Tab，输入用户名 admin / 密码 admin123，绑定导入的客户端证书。',
        screenshotName: 'sc1_step1_setup.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="pwd-cert"]');
          await page.waitForSelector('#pwd-cert-group', { visible: true });

          await page.focus('#username-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#username-input', 'admin');

          await page.focus('#password-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#password-input', 'admin123');

          await page.click('#pwd-cert-refresh-btn');
          await page.evaluate(() => new Promise(r => setTimeout(r, 400)));

          const btnText = await page.$eval('#connect-btn-text', el => el.textContent.trim());
          const certText = await page.$eval('#pwd-cert-select', el => el.options[el.selectedIndex]?.text || '');
          return `已就绪。连接按钮: "${btnText}"，关联证书: "${certText}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '提交双因素认证并捕获握手过渡',
        desc: '点击连接，客户端依次与网关执行口令 Challenge 与客户端证书 Presentation。',
        screenshotName: 'sc1_step2_authenticating.png',
        action: async () => {
          await page.click('#connect-btn');
          await page.evaluate(() => new Promise(r => setTimeout(r, 200)));
          const disabled = await page.$eval('#connect-btn', el => el.disabled);
          return `双因素握手触发，按钮禁用状态: ${disabled}，客户端正在等待网关协商响应`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '认证成功建立安全隧道并获取资源',
        desc: '网关双因素验证通过，客户端显示会话信息并成功拉取 3 项内网业务资源。',
        screenshotName: 'sc1_step3_connected.png',
        action: async () => {
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
        desc: '切换到「👤 口令登录」Tab，输入 admin / admin123，连接按钮显示「立即连接」。',
        screenshotName: 'sc2_step1_password_panel.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="password"]');
          await page.focus('#username-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#username-input', 'admin');

          await page.focus('#password-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#password-input', 'admin123');

          const btnText = await page.$eval('#connect-btn-text', el => el.textContent.trim());
          return `口令面板就绪。连接按钮文字: "${btnText}"`;
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
      desc: '用户在「🪪 证书登录」Tab 中选中合法客户端证书，点击连接直接通过 TLS 握手登录，无需输入用户口令。',
      mode: 'cert-only'
    }, async (record) => {
      await setMockMode('pwd-cert');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);
      await ensureCertImported(page);

      await record(page, {
        stepId: 1,
        title: '切换到证书面板并选中客户端证书',
        desc: '点击「🪪 证书登录」Tab，证书列表中高亮选中已导入的测试证书。',
        screenshotName: 'sc3_step1_cert_panel.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="cert"]');
          await page.waitForSelector('#cert-panel', { visible: true });
          await page.evaluate(() => new Promise(r => setTimeout(r, 600)));
          await page.waitForSelector('.cert-item', { visible: true });
          await page.click('.cert-item');

          const certCards = await page.$$eval('.cert-item', els => els.length);
          const btnText = await page.$eval('#connect-btn-text', el => el.textContent.trim());
          return `证书登录面板就绪，可用证书数: ${certCards}，连接按钮: "${btnText}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '证书直连成功建立安全隧道',
        desc: '客户端上送 TLS 客户端证书至 /vpn/user/auth/cert，网关校验通过，会话建立。',
        screenshotName: 'sc3_step2_cert_connected.png',
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
          await page.click('.auth-tab[data-mode="password"]');
          await page.focus('#username-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#username-input', 'admin');

          await page.focus('#password-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#password-input', 'WrongPassword999');

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
      desc: '网关返回 code=256（口令过期），客户端自动弹出改密抽屉，用户输入新密码后一键改密并成功登录。',
      mode: 'pwd-change'
    }, async (record) => {
      await setMockMode('pwd-change');
      await page.goto(TARGET_URL, { waitUntil: 'networkidle0' });
      await ensureGatewayConfigured(page);

      await record(page, {
        stepId: 1,
        title: '触发口令过期并弹出改密抽屉',
        desc: '输入原口令 admin123 尝试连接，网关返回 256 挑战码，页面自动弹出修改新密码输入框。',
        screenshotName: 'sc5_step1_pwd_expired_challenge.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="password"]');
          await page.focus('#username-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#username-input', 'admin');

          await page.focus('#password-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#password-input', 'admin123');

          await page.click('#connect-btn');
          await page.waitForSelector('#password-change-panel', { visible: true, timeout: 8000 });

          const hint = await page.$eval('.password-change-hint', el => el.textContent.trim());
          return `成功触发改密流程。改密面板提示: "${hint}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '输入新密码完成改密并自动续连成功',
        desc: '输入新密码 admin456 并确认，提交改密并继续连接，网关更新密码并建立隧道。',
        screenshotName: 'sc5_step2_pwd_change_success_connected.png',
        action: async () => {
          await page.focus('#new-password-input');
          await page.type('#new-password-input', 'admin456');

          await page.focus('#confirm-password-input');
          await page.type('#confirm-password-input', 'admin456');

          await page.click('#change-password-btn');

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
        title: '首次提交触发验证码与动态图片渲染',
        desc: '未输入验证码提交登录，网关返回 0x80，客户端展开「图形验证码」输入组件并渲染随机验证码图。',
        screenshotName: 'sc6_step1_verifycode_prompt.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="password"]');
          await page.focus('#username-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#username-input', 'admin');

          await page.focus('#password-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#password-input', 'admin456'); // updated password

          await page.click('#connect-btn');
          await page.waitForSelector('#verifycode-group', { visible: true, timeout: 8000 });
          await page.waitForFunction(() => {
            const img = document.getElementById('verifycode-img');
            return img && img.style.display !== 'none' && img.src.startsWith('data:image');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#login-alert', el => el.textContent.trim());
          const hasImg = await page.$eval('#verifycode-img', el => el.src.length > 50);
          return `验证码输入框及随机图片已激活渲染（图片存在: ${hasImg}）。提示文案: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 2,
        title: '输入错误验证码被网关精准拦截',
        desc: '输入错误验证码 9999 提交，网关比对不匹配返回 0x80000021 错误，页面展示拦截告警并自动刷新验证码图片。',
        screenshotName: 'sc6_step2_verifycode_wrong_rejected.png',
        action: async () => {
          await page.focus('#verifycode-input');
          await page.type('#verifycode-input', '9999');

          await page.click('#connect-btn');
          await page.waitForFunction(() => {
            const alert = document.getElementById('login-alert');
            return alert && alert.style.display !== 'none' && alert.textContent.includes('验证码');
          }, { timeout: 8000 });

          const alertText = await page.$eval('#login-alert', el => el.textContent.trim());
          return `错误验证码被成功拦截。页面告警: "${alertText}"`;
        }
      });

      await record(page, {
        stepId: 3,
        title: '输入正确动态验证码成功完成登录',
        desc: '获取网关当前随机验证码，填入验证码并再次点击连接，网关校验通过并建立安全隧道。',
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
          await page.focus('#verifycode-input');
          await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
          await page.keyboard.press('Backspace');
          await page.type('#verifycode-input', expectedCode);

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
        desc: '在证书登录面板提交认证，网关判定证书过期返回 0x106，客户端展示错误提示。',
        screenshotName: 'sc7_step1_cert_expired_alert.png',
        action: async () => {
          await page.click('.auth-tab[data-mode="cert"]');
          await page.waitForSelector('#cert-panel', { visible: true });
          await page.evaluate(() => new Promise(r => setTimeout(r, 400)));

          await page.click('#connect-btn');
          await page.waitForSelector('#login-alert', { visible: true, timeout: 8000 });

          const alertText = await page.$eval('#login-alert', el => el.textContent.trim());
          return `证书过期拦截生效。页面告警提示: "${alertText}"`;
        }
      });
    });

    log(`\nAll 7 Scenarios executed! Total Scenarios: ${scenarios.length}`);

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
          <span class="meta-value">V5VPN 安全客户端 (v0.3.0)</span>
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

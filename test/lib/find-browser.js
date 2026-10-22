'use strict';

// 跨平台浏览器探测：两个 E2E 脚本共用。
//
// EDGE_PATH 环境变量在所有平台优先；否则按平台常见安装路径逐一探测，
// 覆盖 Windows（Edge/Chrome）、macOS（Chrome/Edge）、Linux（Chrome/Chromium）。
// 找不到返回 null，调用方负责给出带 EDGE_PATH 提示的错误。

const fs = require('fs');

function findBrowser() {
  const candidates = [
    process.env.EDGE_PATH,
    // Windows
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    // macOS
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    // Linux
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

module.exports = { findBrowser };

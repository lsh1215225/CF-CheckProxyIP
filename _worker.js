export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/resolve') {
      const proxyip = url.searchParams.get('proxyip');
      if (!proxyip) return new Response('Missing proxyip', { status: 400 });

      try {
        const targets = await handleResolve(proxyip);
        return new Response(JSON.stringify(targets), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
    }

    // 返回前端页面
    return new Response(generateHTML(), {
      headers: { 'Content-Type': 'text/html; charset=UTF-8' }
    });
  }
};

async function handleResolve(input) {
  let host = input;
  let port = 443;

  // 解析端口
  if (host.includes('[') && host.includes(']:')) {
    const parts = host.split(']:');
    port = parseInt(parts[1]);
    host = parts[0] + ']';
  } else if (host.includes(':')) {
    const parts = host.split(':');
    // 如果包含多个冒号且没有括号，说明是纯 IPv6，不应作为端口分割
    if (parts.length > 2 && !host.includes('[') && !host.includes(']')) {
      // 保持 host 不变，port 默认为 443
    } else {
      port = parseInt(parts[parts.length - 1]);
      host = parts.slice(0, -1).join(':');
    }
  }

  // 彩蛋 1: .tp1 指定端口为 1
  if (host.toLowerCase().includes('.tp1.')) {
    port = 1;
  }

  // 检查是否已经是 IP (简单判断)
  const isIPv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
  const isIPv6 = host.startsWith('[') && host.endsWith(']');
  const isRawIPv6 = /^[0-9a-fA-F:]+$/.test(host);

  if (isIPv4 || isIPv6 || isRawIPv6) {
    let finalHost = host;
    if (isRawIPv6 && !host.startsWith('[')) finalHost = `[${host}]`;
    return [`${finalHost}:${port}`];
  }

  // 彩蛋 2: .william 查询 TXT 记录
  if (host.toLowerCase().includes('.william.')) {
    const txtRecords = await DoH查询(host, 'TXT');
    if (txtRecords && txtRecords.length > 0) {
      // TXT 内容如 "221.156.228.221:30000,175.214.162.251:50000"
      const allTargets = [];
      for (const record of txtRecords) {
        const data = String(record.data);
        const parts = data.split(',');
        for (const p of parts) {
          if (p.trim()) allTargets.push(p.trim());
        }
      }
      return allTargets;
    }
  }

  // 普通域名查询 A 和 AAAA
  const [aRecords, aaaaRecords] = await Promise.all([
    DoH查询(host, 'A'),
    DoH查询(host, 'AAAA')
  ]);

  const results = [];
  aRecords.filter(r => r.type === 1).forEach(r => results.push(`${r.data}:${port}`));
  aaaaRecords.filter(r => r.type === 28).forEach(r => results.push(`[${r.data}]:${port}`));

  if (results.length === 0) {
    throw new Error('Could not resolve domain');
  }
  return results;
}

async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
  const 开始时间 = performance.now();
  console.log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
  try {
    // 记录类型字符串转数值
    const 类型映射 = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
    const qtype = 类型映射[记录类型.toUpperCase()] || 1;

    // 编码域名为 DNS wire format labels
    const 编码域名 = (name) => {
      const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
      const bufs = [];
      for (const label of parts) {
        const enc = new TextEncoder().encode(label);
        bufs.push(new Uint8Array([enc.length]), enc);
      }
      bufs.push(new Uint8Array([0]));
      const total = bufs.reduce((s, b) => s + b.length, 0);
      const result = new Uint8Array(total);
      let off = 0;
      for (const b of bufs) { result.set(b, off); off += b.length }
      return result;
    };

    // 构建 DNS 查询报文
    const qname = 编码域名(域名);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, 0);       // ID
    qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
    qview.setUint16(4, 1);       // QDCOUNT
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

    // 通过 POST 发送 dns-message 请求
    console.log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
    const response = await fetch(DoH解析服务, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
      },
      body: query,
    });
    if (!response.ok) {
      console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
      return [];
    }

    // 解析 DNS 响应报文
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    console.log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

    // 解析域名（处理指针压缩）
    const 解析域名 = (pos) => {
      const labels = [];
      let p = pos, jumped = false, endPos = -1, safe = 128;
      while (p < buf.length && safe-- > 0) {
        const len = buf[p];
        if (len === 0) { if (!jumped) endPos = p + 1; break }
        if ((len & 0xC0) === 0xC0) {
          if (!jumped) endPos = p + 2;
          p = ((len & 0x3F) << 8) | buf[p + 1];
          jumped = true;
          continue;
        }
        labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
        p += len + 1;
      }
      if (endPos === -1) endPos = p + 1;
      return [labels.join('.'), endPos];
    };

    // 跳过 Question Section
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = 解析域名(offset);
      offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
    }

    // 解析 Answer Section
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = 解析域名(offset);
      offset = /** @type {number} */ (nameEnd);
      const type = dv.getUint16(offset); offset += 2;
      offset += 2; // CLASS
      const ttl = dv.getUint32(offset); offset += 4;
      const rdlen = dv.getUint16(offset); offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;

      let data;
      if (type === 1 && rdlen === 4) {
        // A 记录
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        // AAAA 记录
        const segs = [];
        for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
        data = segs.join(':');
      } else if (type === 16) {
        // TXT 记录 (长度前缀字符串)
        let tOff = 0;
        const parts = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++];
          parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join('');
      } else if (type === 5) {
        // CNAME 记录
        const [cname] = 解析域名(offset - rdlen);
        data = cname;
      } else {
        data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      answers.push({ name, type, TTL: ttl, data, rdata });
    }
    const 耗时 = (performance.now() - 开始时间).toFixed(2);
    console.log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
    return answers;
  } catch (error) {
    const 耗时 = (performance.now() - 开始时间).toFixed(2);
    console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
    return [];
  }
}

function generateHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Check ProxyIP</title>
	<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
	<style>
		:root {
			--bg-color: #0f172a;
			--card-bg: rgba(30, 41, 59, 0.7);
			--primary-color: #38bdf8;
			--success-color: #22c55e;
			--error-color: #ef4444;
			--text-color: #f1f5f9;
			--border-radius: 12px;
		}

		* {
			box-sizing: border-box;
		}

		body {
			background-color: var(--bg-color);
			color: var(--text-color);
			font-family: 'Inter', system-ui, -apple-system, sans-serif;
			margin: 0;
			display: flex;
			flex-direction: column;
			align-items: center;
			min-height: 100vh;
			overflow-x: hidden;
		}

		header {
			padding: 2rem;
			text-align: center;
			width: 100%;
			background: linear-gradient(to bottom, rgba(30, 41, 59, 0.5), transparent);
		}

		h1 {
			margin: 0;
			font-size: 2.5rem;
			font-weight: 800;
			background: linear-gradient(to right, #38bdf8, #818cf8);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		main {
			width: 100%;
			max-width: 800px;
			padding: 0 1rem 2rem;
			display: flex;
			flex-direction: column;
			gap: 1.5rem;
		}

		.glass-card {
			background: var(--card-bg);
			backdrop-filter: blur(12px);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: var(--border-radius);
			padding: 1.5rem;
			box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
		}

		.input-wrapper {
			position: relative;
			width: 100%;
			margin-bottom: 1rem;
		}

		input[type="text"], textarea {
			width: 100%;
			padding: 0.75rem 2.5rem 0.75rem 0.75rem;
			background: rgba(15, 23, 42, 0.5);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 8px;
			color: white;
			box-sizing: border-box;
			font-family: inherit;
			transition: all 0.3s;
		}

		textarea {
			height: 150px;
			resize: vertical;
			padding-right: 0.75rem;
		}

		.history-toggle {
			position: absolute;
			right: 10px;
			top: 50%;
			transform: translateY(-50%);
			cursor: pointer;
			color: #94a3b8;
			padding: 5px;
			display: flex;
			align-items: center;
			justify-content: center;
			transition: color 0.2s;
		}

		.history-toggle:hover { color: white; }

		.history-dropdown {
			position: absolute;
			top: calc(100% + 5px);
			right: 0;
			width: 100%;
			background: #1e293b;
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 8px;
			display: none;
			z-index: 1000;
			box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
			max-height: 300px;
			overflow-y: auto;
		}

		.history-item {
			padding: 0.75rem 1rem;
			cursor: pointer;
			font-size: 0.9rem;
			border-bottom: 1px solid rgba(255, 255, 255, 0.05);
			transition: background 0.2s;
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}

		.history-item:last-child { border-bottom: none; }
		.history-item:hover { background: rgba(255, 255, 255, 0.1); }

		.action-group {
			display: flex;
			gap: 1rem;
			align-items: center;
		}

		.batch-toggle {
			display: flex;
			align-items: center;
			gap: 0.5rem;
			white-space: nowrap;
			font-size: 0.9rem;
			font-weight: 600;
			color: #94a3b8;
		}

		/* Switch Style */
		.switch {
			position: relative;
			display: inline-block;
			width: 44px;
			height: 22px;
		}

		.switch input { opacity: 0; width: 0; height: 0; }

		.slider {
			position: absolute;
			cursor: pointer;
			top: 0; left: 0; right: 0; bottom: 0;
			background-color: rgba(255, 255, 255, 0.1);
			transition: .4s;
			border-radius: 34px;
		}

		.slider:before {
			position: absolute;
			content: "";
			height: 16px; width: 16px;
			left: 3px; bottom: 3px;
			background-color: white;
			transition: .4s;
			border-radius: 50%;
		}

		input:checked + .slider { background-color: var(--primary-color); }
		input:checked + .slider:before { transform: translateX(22px); }

		button {
			flex: 1;
			padding: 0.75rem;
			border-radius: 8px;
			border: none;
			background: linear-gradient(to right, #38bdf8, #2563eb);
			color: white;
			font-weight: 600;
			cursor: pointer;
			transition: transform 0.2s, opacity 0.2s;
		}

		button:hover {
			transform: translateY(-2px);
			opacity: 0.9;
		}

		.progress-container {
			display: none;
			width: 100%;
			background: rgba(255, 255, 255, 0.05);
			border-radius: 50px;
			height: 24px;
			overflow: hidden;
			position: relative;
			margin-top: 1rem;
		}

		.progress-bar {
			width: 0%;
			height: 100%;
			background: linear-gradient(to right, #34d399, #10b981);
			transition: width 0.3s ease;
		}

		.progress-text {
			position: absolute;
			width: 100%;
			text-align: center;
			top: 0; left: 0;
			font-size: 0.8rem;
			line-height: 24px;
			font-weight: 700;
			color: white;
			text-shadow: 0 1px 2px rgba(0,0,0,0.5);
		}

		.results-list {
			display: flex;
			flex-direction: column;
			gap: 0.75rem;
		}

		.result-item {
			display: flex;
			flex-direction: column;
			padding: 1rem;
			border-radius: 8px;
			background: rgba(255, 255, 255, 0.05);
			border-left: 4px solid #475569;
			transition: background 0.3s;
		}

		.result-item.success { border-left-color: var(--success-color); }
		.result-item.error { border-left-color: var(--error-color); }

		.result-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.result-info { display: flex; flex-direction: column; }
		.result-ip { font-weight: 700; font-family: monospace; }
		.result-detail { font-size: 0.8rem; color: #94a3b8; }

		.status-badge {
			padding: 0.25rem 0.5rem;
			border-radius: 4px;
			font-size: 0.75rem;
			font-weight: 700;
			text-transform: uppercase;
		}
		.status-success { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
		.status-error { background: rgba(239, 68, 68, 0.2); color: #f87171; }
		.status-pending { background: rgba(234, 179, 8, 0.2); color: #facc15; }

		.exit-ip-btn {
			cursor: pointer;
			text-decoration: underline;
			color: var(--primary-color);
			margin-right: 0.5rem;
		}

		.map-container-wrapper {
			display: none;
			margin-top: 1rem;
			height: 350px;
			border-radius: 8px;
			overflow: hidden;
			border: 1px solid rgba(255, 255, 255, 0.1);
		}

		#map-template { display: none; }
		#global-map { height: 100%; width: 100%; }

		.leaflet-control-attribution, .leaflet-control-zoom { display: none !important; }

		footer {
			margin-top: auto;
			padding: 2rem;
			text-align: center;
			color: #64748b;
			font-size: 0.85rem;
			width: 100%;
			border-top: 1px solid rgba(255, 255, 255, 0.05);
			background: rgba(15, 23, 42, 0.3);
		}
	</style>
</head>
<body>
	<header>
		<h1>Check ProxyIP</h1>
		<p style="color: #94a3b8;">高性能 Cloudflare 代理 IP 检测工具</p>
	</header>

	<main>
		<div class="glass-card">
			<div class="input-wrapper" id="inputContainer">
				<input type="text" id="inputList" placeholder="请输入 IP 或域名 (例如: ProxyIP.CMLiussss.net)">
				<div class="history-toggle" id="historyBtn">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
				</div>
				<div class="history-dropdown" id="historyDropdown"></div>
			</div>
			
			<div class="action-group">
				<div class="batch-toggle">
					<span>批量检测</span>
					<label class="switch">
						<input type="checkbox" id="batchMode">
						<span class="slider"></span>
					</label>
				</div>
				<button id="checkBtn">开始检测</button>
			</div>

			<div id="progressContainer" class="progress-container">
				<div id="progressBar" class="progress-bar"></div>
				<div id="progressText" class="progress-text">0%</div>
			</div>
		</div>

		<div id="results" class="results-list"></div>
	</main>

	<footer>
		© 2026 Check ProxyIP - 基于 Cloudflare Workers 构建的高性能 ProxyIP 验证服务 | 由 cmliu 开发维护
	</footer>

	<!-- Global Hidden Map Element -->
	<div id="map-template">
		<div id="global-map"></div>
	</div>

	<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
	<script>
		const checkBtn = document.getElementById('checkBtn');
		let inputList = document.getElementById('inputList');
		const inputContainer = document.getElementById('inputContainer');
		const batchMode = document.getElementById('batchMode');
		const resultsDiv = document.getElementById('results');
		const progressContainer = document.getElementById('progressContainer');
		const progressBar = document.getElementById('progressBar');
		const progressText = document.getElementById('progressText');
		const globalMap = document.getElementById('global-map');
		const historyBtn = document.getElementById('historyBtn');
		const historyDropdown = document.getElementById('historyDropdown');

		let map = null;
		let markers = [];
		let totalTargets = 0;
		let completedCount = 0;
		let successCount = 0;

		function initMap() {
			if (map) return;
			map = L.map('global-map', {
				zoomControl: false,
				attributionControl: false
			}).setView([20, 0], 2);
			L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
		}

		// 批量模式切换
		batchMode.addEventListener('change', () => {
			const isBatch = batchMode.checked;
			const val = inputList.value;
			
			if (isBatch) {
				const textarea = document.createElement('textarea');
				textarea.id = 'inputList';
				textarea.placeholder = '请输入 IP 或域名，每行一个\\n例如:\\n8.223.63.150\\nProxyIP.CMLiussss.net';
				textarea.value = val;
				inputContainer.innerHTML = '';
				inputContainer.appendChild(textarea);
				inputList = textarea;
			} else {
				const input = document.createElement('input');
				input.type = 'text';
				input.id = 'inputList';
				input.placeholder = '请输入 IP 或域名 (例如: ProxyIP.CMLiussss.net)';
				input.value = val.split('\\n')[0]; // 只保留第一行
				inputContainer.innerHTML = '';
				inputContainer.appendChild(input);
				inputContainer.appendChild(historyBtn);
				inputContainer.appendChild(historyDropdown);
				inputList = input;
			}
		});

		// 历史记录逻辑
		function getHistory() {
			return JSON.parse(localStorage.getItem('cf_proxy_history') || '[]');
		}

		function saveHistory(val) {
			if (!val || val.includes('\\n')) return; // 批量模式不保存复杂历史
			let history = getHistory();
			history = history.filter(item => item !== val);
			history.unshift(val);
			history = history.slice(0, 10);
			localStorage.setItem('cf_proxy_history', JSON.stringify(history));
			renderHistory();
		}

		function renderHistory() {
			const history = getHistory();
			historyDropdown.innerHTML = history.length ? history.map(item => \`
				<div class="history-item" onclick="selectHistory('\${item}')">\${item}</div>
			\`).join('') : '<div class="history-item" style="color:#64748b;cursor:default;">暂无历史记录</div>';
		}

		window.selectHistory = (val) => {
			inputList.value = val;
			historyDropdown.style.display = 'none';
		};

		historyBtn.addEventListener('click', (e) => {
			e.stopPropagation();
			const isVisible = historyDropdown.style.display === 'block';
			historyDropdown.style.display = isVisible ? 'none' : 'block';
		});

		document.addEventListener('click', () => {
			if (historyDropdown) historyDropdown.style.display = 'none';
		});

		checkBtn.addEventListener('click', async () => {
			const value = inputList.value.trim();
			if (!value) return;

			const lines = batchMode.checked ? value.split('\\n').map(l => l.trim()).filter(l => l) : [value];
			
			if (!batchMode.checked) saveHistory(value);

			resultsDiv.innerHTML = '';
			progressContainer.style.display = 'block';
			progressBar.style.width = '0%';
			progressText.innerText = '正在解析...';
			
			completedCount = 0;
			successCount = 0;
			totalTargets = 0;

			try {
				const allResolvedTargets = [];
				for (const line of lines) {
					try {
						const res = await fetch(\`/resolve?proxyip=\${encodeURIComponent(line)}\`);
						const targets = await res.json();
						if (Array.isArray(targets)) {
							allResolvedTargets.push(...targets);
						}
					} catch (e) {
						console.error('Resolve error for', line, e);
					}
				}

				if (allResolvedTargets.length > 0) {
					totalTargets = allResolvedTargets.length;
					updateProgress();
					
					const checkPromises = allResolvedTargets.map(target => checkIP(target));
					await Promise.all(checkPromises);
					const failCount = totalTargets - successCount;
					progressText.innerText = \`总计: \${totalTargets} | 有效: \${successCount} | 失败: \${failCount}\`;
				} else {
					progressText.innerText = '解析失败';
				}
			} catch (e) {
				console.error(e);
				progressText.innerText = '系统错误';
			}
		});

		function updateProgress() {
			const percent = totalTargets > 0 ? Math.round((completedCount / totalTargets) * 100) : 0;
			progressBar.style.width = \`\${percent}%\`;
			progressText.innerText = \`\${completedCount} / \${totalTargets}\`;
		}

		async function checkIP(target) {
			const itemObj = addResultItem(target);
			try {
				const res = await fetch(\`https://api.090227.xyz/check?proxyip=\${encodeURIComponent(target)}\`);
				const data = await res.json();
				
				completedCount++;
				if (data.success) {
					successCount++;
					itemObj.el.className = 'result-item success';
					const exitIps = [];
					if (data.probe_results?.ipv4?.ok) exitIps.push({ ip: data.probe_results.ipv4.exit.ip, exitData: data.probe_results.ipv4.exit });
					if (data.probe_results?.ipv6?.ok) exitIps.push({ ip: data.probe_results.ipv6.exit.ip, exitData: data.probe_results.ipv6.exit });

					const countries = [...new Set(exitIps.map(ex => ex.exitData.country))].join('/');
					
					let exitHtml = '';
					exitIps.forEach(ex => {
						const exitDataStr = JSON.stringify(ex.exitData).replace(/"/g, '&quot;');
						exitHtml += \`<span class="exit-ip-btn" onclick="showDetails(this, '\${ex.ip}', \${exitDataStr})">\${ex.ip}</span>\`;
					});

					itemObj.info.innerHTML = \`
						<span class="result-ip">\${data.candidate}</span>
						<span class="result-detail">出口: \${exitHtml || '未知'} | 地区: \${countries || '未知'} | 延迟: \${data.responseTime}ms</span>
					\`;
					itemObj.badge.className = 'status-badge status-success';
					itemObj.badge.innerText = '可用';
				} else {
					itemObj.el.className = 'result-item error';
					itemObj.badge.className = 'status-badge status-error';
					itemObj.badge.innerText = '不可用';
					itemObj.info.innerHTML = \`
						<span class="result-ip">\${target}</span>
						<span class="result-detail">无法通过此代理访问 Cloudflare</span>
					\`;
				}
				updateProgress();
			} catch (e) {
				completedCount++;
				updateProgress();
				itemObj.el.className = 'result-item error';
				itemObj.badge.innerText = '失败';
			}
		}

		function addResultItem(ip) {
			const div = document.createElement('div');
			div.className = 'result-item';
			div.innerHTML = \`
				<div class="result-header">
					<div class="result-info">
						<span class="result-ip">\${ip}</span>
						<span class="result-detail">正在检测...</span>
					</div>
					<span class="status-badge status-pending">等待</span>
				</div>
				<div class="map-container-wrapper"></div>
			\`;
			resultsDiv.appendChild(div);
			return {
				el: div,
				info: div.querySelector('.result-info'),
				badge: div.querySelector('.status-badge'),
				mapContainer: div.querySelector('.map-container-wrapper')
			};
		}

		window.showDetails = (btn, ip, exitData) => {
			const item = btn.closest('.result-item');
			const container = item.querySelector('.map-container-wrapper');
			
			document.querySelectorAll('.map-container-wrapper').forEach(c => c.style.display = 'none');
			
			initMap();
			container.appendChild(globalMap);
			container.style.display = 'block';

			setTimeout(() => {
				map.invalidateSize();
				const loc = exitData.loc.split(',').map(Number);
				map.setView(loc, 6);

				markers.forEach(m => map.removeLayer(m));
				markers = [];

				const popupContent = \`
					<div style="font-family: inherit; font-size: 0.85rem; line-height: 1.4;">
						<b>落地IP:</b> \${ip}<br>
						<b>国家:</b> \${exitData.country}<br>
						<b>城市:</b> \${exitData.city}<br>
						<b>ASN:</b> AS\${exitData.asn}<br>
						<b>运营商:</b> \${exitData.asOrganization}
					</div>
				\`;

				const marker = L.marker(loc).addTo(map)
					.bindPopup(popupContent)
					.openPopup();
				markers.push(marker);
			}, 100);
		};

		window.onload = () => {
			renderHistory();
			const path = window.location.pathname.slice(1);
			if (path && path.length > 3) {
				const decodedPath = decodeURIComponent(path);
				if (decodedPath !== 'resolve' && decodedPath !== 'favicon.ico') {
					inputList.value = decodedPath;
					window.history.replaceState({}, '', '/');
					checkBtn.click();
				}
			}
		};
	</script>
</body>
</html>`;
}
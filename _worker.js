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
    return new Response(generateHTML(url.hostname), {
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

function generateHTML(hostname) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Cloudflare ProxyIP Checker</title>
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

		body {
			background-color: var(--bg-color);
			color: var(--text-color);
			font-family: 'Inter', system-ui, -apple-system, sans-serif;
			margin: 0;
			display: flex;
			flex-direction: column;
			min-height: 100vh;
		}

		header {
			padding: 2rem;
			text-align: center;
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
			flex: 1;
			max-width: 1200px;
			margin: 0 auto;
			width: 100%;
			padding: 0 1rem 2rem;
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 2rem;
		}

		@media (max-width: 900px) {
			main {
				grid-template-columns: 1fr;
			}
		}

		.glass-card {
			background: var(--card-bg);
			backdrop-filter: blur(12px);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: var(--border-radius);
			padding: 1.5rem;
			box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
		}

		textarea {
			width: 100%;
			height: 200px;
			background: rgba(15, 23, 42, 0.5);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 8px;
			color: white;
			padding: 1rem;
			font-family: monospace;
			resize: vertical;
			box-sizing: border-box;
			margin-bottom: 1rem;
		}

		button {
			width: 100%;
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

		button:active {
			transform: translateY(0);
		}

		#map {
			height: 400px;
			border-radius: var(--border-radius);
			z-index: 1;
		}

		.results-list {
			margin-top: 1rem;
			display: flex;
			flex-direction: column;
			gap: 0.75rem;
		}

		.result-item {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 0.75rem 1rem;
			border-radius: 8px;
			background: rgba(255, 255, 255, 0.05);
			border-left: 4px solid #475569;
			transition: background 0.3s;
		}

		.result-item.success {
			border-left-color: var(--success-color);
		}

		.result-item.error {
			border-left-color: var(--error-color);
		}

		.result-info {
			display: flex;
			flex-direction: column;
		}

		.result-ip {
			font-weight: 700;
			font-family: monospace;
		}

		.result-detail {
			font-size: 0.8rem;
			color: #94a3b8;
		}

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
		}

		.exit-ip-btn:hover {
			color: #7dd3fc;
		}

		.loading-overlay {
			display: none;
			position: fixed;
			top: 0; left: 0; right: 0; bottom: 0;
			background: rgba(15, 23, 42, 0.8);
			z-index: 1000;
			justify-content: center;
			align-items: center;
			flex-direction: column;
		}

		.spinner {
			width: 50px;
			height: 50px;
			border: 5px solid rgba(56, 189, 248, 0.3);
			border-top-color: var(--primary-color);
			border-radius: 50%;
			animation: spin 1s linear infinite;
		}

		@keyframes spin {
			to { transform: rotate(360deg); }
		}
	</style>
</head>
<body>
	<header>
		<h1>CF ProxyIP Checker</h1>
		<p style="color: #94a3b8;">高性能 Cloudflare 代理 IP 检测工具</p>
	</header>

	<main>
		<div class="glass-card">
			<input type="text" id="inputList" placeholder="请输入 IP 或域名 (例如: 8.223.63.150 或 PROXYIP.tp1.090227.xyz)" style="width: 100%; padding: 0.75rem; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; margin-bottom: 1rem; box-sizing: border-box;">
			<button id="checkBtn">开始检测</button>
			
			<div id="results" class="results-list">
				<!-- Results will appear here -->
			</div>
		</div>

		<div class="glass-card" style="display: flex; flex-direction: column; gap: 1rem;">
			<div id="map"></div>
			<div id="details" class="glass-card" style="background: rgba(15, 23, 42, 0.3); flex: 1; overflow-y: auto;">
				<h3 style="margin-top: 0;">落地详细参数</h3>
				<div id="detailContent">点击检测成功的出口 IP 查看详情...</div>
			</div>
		</div>
	</main>

	<div id="loading" class="loading-overlay">
		<div class="spinner"></div>
		<p style="margin-top: 1rem; font-weight: 600;">正在解析与探测...</p>
	</div>

	<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
	<script>
		const checkBtn = document.getElementById('checkBtn');
		const inputList = document.getElementById('inputList');
		const resultsDiv = document.getElementById('results');
		const loading = document.getElementById('loading');
		const detailContent = document.getElementById('detailContent');

		let map = L.map('map').setView([20, 0], 2);
		L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
			attribution: '&copy; OpenStreetMap &copy; CARTO'
		}).addTo(map);

		let markers = [];

		checkBtn.addEventListener('click', async () => {
			const line = inputList.value.trim();
			if (!line) return;

			resultsDiv.innerHTML = '';
			detailContent.innerHTML = '点击检测成功的出口 IP 查看详情...';
			loading.style.display = 'flex';
			
			// Clear markers
			markers.forEach(m => map.removeLayer(m));
			markers = [];

			try {
				const res = await fetch(\`/resolve?proxyip=\${encodeURIComponent(line)}\`);
				const targets = await res.json();
				if (Array.isArray(targets)) {
					const checkPromises = targets.map(target => checkIP(target));
					await Promise.all(checkPromises);
				} else {
					addResultItem(line, null, '解析失败', 'error');
				}
			} catch (e) {
				console.error('Global error', e);
				addResultItem(line, null, '系统错误', 'error');
			} finally {
				loading.style.display = 'none';
			}
		});

		async function checkIP(target) {
			const item = addResultItem(target, null, '检测中...', 'pending');
			try {
				const res = await fetch(\`https://api.090227.xyz/check?proxyip=\${encodeURIComponent(target)}\`);
				const data = await res.json();
				
				if (data.success) {
					item.className = 'result-item success';
					const exitIps = [];
					if (data.probe_results?.ipv4?.ok) exitIps.push({ ip: data.probe_results.ipv4.exit.ip, type: 'IPv4', exitData: data.probe_results.ipv4.exit });
					if (data.probe_results?.ipv6?.ok) exitIps.push({ ip: data.probe_results.ipv6.exit.ip, type: 'IPv6', exitData: data.probe_results.ipv6.exit });

					let exitHtml = '';
					exitIps.forEach(ex => {
						exitHtml += \` <span class="exit-ip-btn" onclick="showDetails('\${ex.ip}', \${JSON.stringify(ex.exitData).replace(/"/g, '&quot;')})">\${ex.ip}</span>\`;
					});

					const countries = [...new Set(exitIps.map(ex => ex.exitData.country))].join('/');

					item.innerHTML = \`
						<div class="result-info">
							<span class="result-ip">\${data.candidate}</span>
							<span class="result-detail">出口: \${exitHtml || '未知'} | 地区: \${countries || '未知'} | 延迟: \${data.responseTime}ms</span>
						</div>
						<span class="status-badge status-success">可用</span>
					\`;
				} else {
					item.className = 'result-item error';
					item.innerHTML = \`
						<div class="result-info">
							<span class="result-ip">\${target}</span>
							<span class="result-detail">无法通过此代理访问 Cloudflare</span>
						</div>
						<span class="status-badge status-error">不可用</span>
					\`;
				}
			} catch (e) {
				item.className = 'result-item error';
				item.innerHTML = \`
					<div class="result-info">
						<span class="result-ip">\${target}</span>
						<span class="result-detail">检测接口请求失败</span>
					</div>
					<span class="status-badge status-error">失败</span>
				\`;
			}
		}

		function addResultItem(ip, details, status, type) {
			const div = document.createElement('div');
			div.className = \`result-item \${type}\`;
			div.innerHTML = \`
				<div class="result-info">
					<span class="result-ip">\${ip}</span>
					<span class="result-detail">\${details || status}</span>
				</div>
				<span class="status-badge status-\${type}">\${status}</span>
			\`;
			resultsDiv.appendChild(div);
			return div;
		}

		window.showDetails = (ip, exitData) => {
			const loc = exitData.loc.split(',').map(Number);
			map.setView(loc, 6);
			
			const marker = L.marker(loc).addTo(map)
				.bindPopup(\`<b>落地 IP: \${ip}</b><br>\${exitData.city}, \${exitData.country}<br>\${exitData.asOrganization}\`)
				.openPopup();
			markers.push(marker);

			detailContent.innerHTML = \`
				<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; font-size: 0.9rem;">
					<b style="color: var(--primary-color);">IP:</b> <span>\${ip}</span>
					<b>国家:</b> <span>\${exitData.country}</span>
					<b>城市:</b> <span>\${exitData.city}</span>
					<b>ASN:</b> <span>AS\${exitData.asn}</span>
					<b>运营商:</b> <span>\${exitData.asOrganization}</span>
					<b>时间:</b> <span>\${exitData.time}</span>
					<b>经纬度:</b> <span>\${exitData.loc}</span>
				</div>
			\`;
		};
	</script>
</body>
</html>`;
}
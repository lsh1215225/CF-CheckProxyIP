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

		input[type="text"] {
			width: 100%;
			padding: 0.75rem;
			background: rgba(15, 23, 42, 0.5);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 8px;
			color: white;
			margin-bottom: 1rem;
			box-sizing: border-box;
			font-family: inherit;
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

		.progress-container {
			display: none;
			width: 100%;
			background: rgba(255, 255, 255, 0.05);
			border-radius: 50px;
			height: 24px;
			overflow: hidden;
			position: relative;
			margin-top: 0.5rem;
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
	</style>
</head>
<body>
	<header>
		<h1>CF ProxyIP Checker</h1>
		<p style="color: #94a3b8;">高性能 Cloudflare 代理 IP 检测工具</p>
	</header>

	<main>
		<div class="glass-card">
			<input type="text" id="inputList" placeholder="请输入 IP 或域名 (例如: ProxyIP.CMLiussss.net)">
			<button id="checkBtn">开始检测</button>
			<div id="progressContainer" class="progress-container">
				<div id="progressBar" class="progress-bar"></div>
				<div id="progressText" class="progress-text">0%</div>
			</div>
		</div>

		<div id="results" class="results-list"></div>
	</main>

	<!-- Global Hidden Map Element -->
	<div id="map-template">
		<div id="global-map"></div>
	</div>

	<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
	<script>
		const checkBtn = document.getElementById('checkBtn');
		const inputList = document.getElementById('inputList');
		const resultsDiv = document.getElementById('results');
		const progressContainer = document.getElementById('progressContainer');
		const progressBar = document.getElementById('progressBar');
		const progressText = document.getElementById('progressText');
		const globalMap = document.getElementById('global-map');

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

		checkBtn.addEventListener('click', async () => {
			const line = inputList.value.trim();
			if (!line) return;

			resultsDiv.innerHTML = '';
			progressContainer.style.display = 'block';
			progressBar.style.width = '0%';
			progressText.innerText = '正在解析...';
			completedCount = 0;
			
			try {
				const res = await fetch(\`/resolve?proxyip=\${encodeURIComponent(line)}\`);
				const targets = await res.json();
				
				if (Array.isArray(targets)) {
					totalTargets = targets.length;
					completedCount = 0;
					successCount = 0;
					updateProgress();
					
					const checkPromises = targets.map(target => checkIP(target));
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
				updateProgress();

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
			
			// If clicking the same IP and map is already there, do nothing or toggle? Let's just show.
			const isAlreadyShowing = container.style.display === 'block' && container.contains(globalMap);

			// Hide all map containers
			document.querySelectorAll('.map-container-wrapper').forEach(c => c.style.display = 'none');
			
			initMap();
			
			// Move map to this container
			container.appendChild(globalMap);
			container.style.display = 'block';

			// 使用 setTimeout 确保 DOM 渲染完成后再重算地图尺寸和中心
			setTimeout(() => {
				map.invalidateSize();
				const loc = exitData.loc.split(',').map(Number);
				map.setView(loc, 6);

				// Clear markers
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

		// 自动执行路径中的参数
		window.onload = () => {
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
export default {
	async fetch(request) {
		const url = new URL(request.url);

		if (url.pathname === '/resolve') {
			const proxyip = url.searchParams.get('proxyip');
			if (!proxyip) {
				return new Response('Missing proxyip', { status: 400 });
			}

			try {
				const targets = await handleResolve(proxyip);
				return new Response(JSON.stringify(targets), {
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*'
					}
				});
			} catch (error) {
				return new Response(JSON.stringify({ error: error.message }), {
					status: 500,
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*'
					}
				});
			}
		} else if (url.pathname === '/locations') return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
		return new Response(generateHTML(), {
			headers: { 'Content-Type': 'text/html; charset=UTF-8' }
		});
	}
};

async function handleResolve(input) {
	let { host, port } = parseTarget(input);

	const tpPortMatch = host.toLowerCase().match(/\.tp(\d{1,5})\./);
	if (tpPortMatch) {
		const tpPort = Number(tpPortMatch[1]);
		if (tpPort >= 1 && tpPort <= 65535) {
			port = tpPort;
		}
	}

	const bracketedIPv6 = host.startsWith('[') && host.endsWith(']');
	const rawIPv6 = /^[0-9a-fA-F:]+$/.test(host);
	if (isIPv4(host) || bracketedIPv6 || rawIPv6) {
		const finalHost = rawIPv6 && !bracketedIPv6 ? `[${host}]` : host;
		return [`${finalHost}:${port}`];
	}

	if (host.toLowerCase().includes('.william.')) {
		const txtRecords = await dohQuery(host, 'TXT');
		if (txtRecords.length) {
			const targets = [];
			for (const record of txtRecords) {
				const value = normalizeTxtValue(record.data);
				for (const part of value.split(',')) {
					const candidate = part.trim();
					if (candidate) targets.push(candidate);
				}
			}
			if (targets.length) {
				return targets;
			}
		}
	}

	const [aRecords, aaaaRecords] = await Promise.all([
		dohQuery(host, 'A'),
		dohQuery(host, 'AAAA')
	]);

	const results = [];
	for (const record of aRecords.filter(item => item.type === 1 && item.data)) {
		results.push(`${record.data}:${port}`);
	}
	for (const record of aaaaRecords.filter(item => item.type === 28 && item.data)) {
		results.push(`[${record.data}]:${port}`);
	}

	if (!results.length) {
		throw new Error('Could not resolve domain');
	}

	return results;
}

function parseTarget(input) {
	let host = String(input || '').split('#')[0].trim();
	let port = 443;

	if (host.startsWith('[')) {
		const ipv6PortIndex = host.lastIndexOf(']:');
		if (ipv6PortIndex !== -1) {
			const maybePort = Number(host.slice(ipv6PortIndex + 2));
			if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
				port = maybePort;
				host = host.slice(0, ipv6PortIndex + 1);
			}
		}
		return { host, port };
	}

	const colonMatches = host.match(/:/g) || [];
	if (colonMatches.length === 1) {
		const separatorIndex = host.lastIndexOf(':');
		const maybePort = Number(host.slice(separatorIndex + 1));
		if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
			port = maybePort;
			host = host.slice(0, separatorIndex);
		}
	}

	return { host, port };
}

function isIPv4(value) {
	const parts = value.split('.');
	return parts.length === 4 && parts.every(part => {
		if (!/^\d{1,3}$/.test(part)) return false;
		const num = Number(part);
		return num >= 0 && num <= 255;
	});
}

function normalizeTxtValue(value) {
	const text = String(value ?? '').trim();
	if (text.startsWith('"') && text.endsWith('"')) {
		return text.slice(1, -1).replace(/\\"/g, '"');
	}
	return text.replace(/\\"/g, '"');
}

async function dohQuery(name, type, endpoint = 'https://cloudflare-dns.com/dns-query') {
	const startedAt = performance.now();

	try {
		const response = await fetch(
			`${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
			{
				headers: {
					accept: 'application/dns-json'
				}
			}
		);

		if (!response.ok) {
			console.warn(`[DoH] ${name} ${type} failed with status ${response.status}`);
			return [];
		}

		const payload = await response.json();
		if (!Array.isArray(payload.Answer)) {
			console.log(`[DoH] ${name} ${type} returned 0 answers in ${(performance.now() - startedAt).toFixed(2)}ms`);
			return [];
		}

		const answers = payload.Answer.map(answer => ({
			name: answer.name || name,
			type: answer.type,
			TTL: answer.TTL,
			data: answer.type === 16 ? normalizeTxtValue(answer.data) : answer.data
		}));

		console.log(`[DoH] ${name} ${type} returned ${answers.length} answers in ${(performance.now() - startedAt).toFixed(2)}ms`);
		return answers;
	} catch (error) {
		console.error(`[DoH] ${name} ${type} error after ${(performance.now() - startedAt).toFixed(2)}ms`, error);
		return [];
	}
}

function generateHTML() {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="color-scheme" content="light dark">
	<title>Check ProxyIP</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
	<script>
		(function () {
			const storageKey = 'cf_proxy_theme';
			let theme = 'dark';
			try {
				const storedTheme = localStorage.getItem(storageKey);
				if (storedTheme === 'light' || storedTheme === 'dark') {
					theme = storedTheme;
				} else {
					theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
				}
			} catch (error) {
				theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
			}
			document.documentElement.dataset.theme = theme;
			document.documentElement.style.colorScheme = theme;
		})();
	</script>
	<style>
		:root {
			--bg-base: #07111d;
			--bg-deep: #0b1726;
			--panel: rgba(10, 24, 40, 0.78);
			--panel-strong: rgba(15, 31, 49, 0.92);
			--line: rgba(144, 180, 212, 0.18);
			--text: #edf7ff;
			--text-soft: #d4e4f3;
			--muted: #8ea6bc;
			--accent: #61dbff;
			--accent-strong: #2dd4bf;
			--accent-warm: #ffb869;
			--success: #34d399;
			--error: #fb7185;
			--warning: #fbbf24;
			--shadow: 0 24px 80px rgba(0, 0, 0, 0.34);
			--shadow-soft: 0 16px 44px rgba(0, 0, 0, 0.26);
			--radius-xl: 30px;
			--radius-lg: 24px;
			--radius-md: 20px;
		}

		html {
			color-scheme: dark;
		}

		html[data-theme='light'] {
			color-scheme: light;
			--bg-base: #eef6fb;
			--bg-deep: #ffffff;
			--panel: rgba(255, 255, 255, 0.72);
			--panel-strong: rgba(255, 255, 255, 0.92);
			--line: rgba(95, 123, 150, 0.18);
			--text: #10253d;
			--text-soft: #23415a;
			--muted: #61778f;
			--accent: #0ea5e9;
			--accent-strong: #14b8a6;
			--accent-warm: #f59e0b;
			--success: #059669;
			--error: #e11d48;
			--warning: #d97706;
			--shadow: 0 24px 64px rgba(43, 67, 91, 0.14);
			--shadow-soft: 0 16px 34px rgba(43, 67, 91, 0.1);
		}

		* {
			box-sizing: border-box;
		}

		html, body {
			margin: 0;
			min-height: 100%;
		}

		body {
			font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
			color: var(--text);
			background:
				radial-gradient(circle at top left, rgba(45, 212, 191, 0.18), transparent 28%),
				radial-gradient(circle at 85% 12%, rgba(97, 219, 255, 0.18), transparent 24%),
				radial-gradient(circle at 50% 110%, rgba(255, 184, 105, 0.16), transparent 30%),
				linear-gradient(180deg, #06101b 0%, #081321 38%, #0a1624 100%);
			overflow-x: hidden;
			transition: background 0.28s ease, color 0.28s ease;
		}

		body::before {
			content: '';
			position: fixed;
			inset: 0;
			pointer-events: none;
			background-image:
				linear-gradient(rgba(255, 255, 255, 0.035) 1px, transparent 1px),
				linear-gradient(90deg, rgba(255, 255, 255, 0.035) 1px, transparent 1px);
			background-size: 46px 46px;
			mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.38), transparent 92%);
			opacity: 0.12;
		}

		html[data-theme='light'] body {
			background:
				radial-gradient(circle at top left, rgba(20, 184, 166, 0.16), transparent 30%),
				radial-gradient(circle at 88% 12%, rgba(14, 165, 233, 0.14), transparent 24%),
				radial-gradient(circle at 50% 110%, rgba(245, 158, 11, 0.12), transparent 28%),
				linear-gradient(180deg, #f6fbff 0%, #eef5fb 44%, #e8f1f7 100%);
		}

		html[data-theme='light'] body::before {
			background-image:
				linear-gradient(rgba(16, 37, 61, 0.05) 1px, transparent 1px),
				linear-gradient(90deg, rgba(16, 37, 61, 0.05) 1px, transparent 1px);
			mask-image: linear-gradient(180deg, rgba(255, 255, 255, 0.68), transparent 92%);
			opacity: 0.28;
		}

		button,
		input,
		textarea {
			font: inherit;
		}

		body,
		.surface-card,
		.input-control,
		.history-toggle,
		.history-dropdown,
		.mode-card,
		.progress-container,
		.metric-card,
		.results-pill,
		.results-empty,
		.empty-visual,
		.guide-card,
		.guide-flow,
		.guide-step,
		.guide-tip,
		.result-item,
		.status-badge,
		.meta-chip,
		.exit-ip-btn,
		.map-container-wrapper,
		.theme-toggle {
			transition: background 0.28s ease, border-color 0.28s ease, color 0.28s ease, box-shadow 0.28s ease, opacity 0.28s ease;
		}

		.page-shell {
			position: relative;
			min-height: 100vh;
			padding: 32px 24px 40px;
		}

		.ambient {
			position: fixed;
			border-radius: 999px;
			filter: blur(80px);
			pointer-events: none;
			z-index: 0;
			opacity: 0.28;
		}

		.ambient-one {
			width: 34rem;
			height: 34rem;
			left: -9rem;
			top: 10rem;
			background: rgba(97, 219, 255, 0.22);
		}

		.ambient-two {
			width: 28rem;
			height: 28rem;
			right: -6rem;
			top: -3rem;
			background: rgba(45, 212, 191, 0.18);
		}

		html[data-theme='light'] .ambient-one {
			background: rgba(56, 189, 248, 0.2);
		}

		html[data-theme='light'] .ambient-two {
			background: rgba(45, 212, 191, 0.16);
		}

		.site-header,
		.site-main,
		.site-footer {
			position: relative;
			z-index: 1;
			max-width: 1200px;
			margin: 0 auto;
		}

		.site-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 24px;
			margin-bottom: 24px;
		}

		.brand {
			display: flex;
			flex-direction: column;
			gap: 12px;
		}

		.brand-chip {
			display: inline-flex;
			align-items: center;
			justify-content: space-between;
			gap: 14px;
			align-self: flex-start;
			padding: 8px 10px 8px 14px;
			border-radius: 999px;
			border: 1px solid rgba(97, 219, 255, 0.16);
			background: rgba(12, 26, 43, 0.66);
			color: #bfeeff;
			font-size: 0.78rem;
			letter-spacing: 0.08em;
			text-transform: uppercase;
			backdrop-filter: blur(12px);
		}

		.brand-chip-text {
			display: inline-flex;
			align-items: center;
			gap: 10px;
			min-width: 0;
		}

		.brand-dot {
			width: 8px;
			height: 8px;
			border-radius: 50%;
			background: linear-gradient(135deg, var(--accent), var(--accent-strong));
			box-shadow: 0 0 18px rgba(97, 219, 255, 0.7);
		}

		.brand-title {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-size: clamp(1.7rem, 4vw, 2.75rem);
			font-weight: 700;
			line-height: 0.98;
			letter-spacing: -0.04em;
			text-transform: uppercase;
			color: #f7fbff;
			text-wrap: balance;
		}

		.header-note {
			max-width: 420px;
			color: var(--muted);
			line-height: 1.7;
			text-align: right;
			flex: 0 1 420px;
		}

		.theme-toggle {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			padding: 0;
			border: none;
			border-radius: 0;
			background: transparent;
			color: var(--text);
			box-shadow: none;
			backdrop-filter: none;
			cursor: pointer;
			min-width: 0;
			transition: color 0.28s ease;
		}

		.theme-toggle:hover {
			transform: none;
		}

		.theme-toggle:focus-visible {
			outline: none;
		}

		.theme-toggle-switch {
			position: relative;
			width: 56px;
			height: 30px;
			flex: none;
			border-radius: 999px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.18), rgba(45, 212, 191, 0.12));
			box-shadow: 0 10px 24px rgba(0, 0, 0, 0.18);
			transition: transform 0.2s ease, background 0.28s ease, border-color 0.28s ease, box-shadow 0.28s ease;
		}

		.theme-toggle:hover .theme-toggle-switch {
			transform: translateY(-1px);
			border-color: rgba(97, 219, 255, 0.2);
			box-shadow: 0 12px 28px rgba(0, 0, 0, 0.22);
		}

		.theme-toggle:focus-visible .theme-toggle-switch {
			box-shadow: 0 0 0 4px rgba(97, 219, 255, 0.12), 0 10px 24px rgba(0, 0, 0, 0.18);
		}

		.theme-toggle-icon {
			position: absolute;
			top: 9px;
			width: 12px;
			height: 12px;
			color: rgba(255, 255, 255, 0.72);
			pointer-events: none;
		}

		.theme-toggle-icon-light {
			left: 8px;
			color: #ffd97d;
		}

		.theme-toggle-icon-dark {
			right: 8px;
			color: #d9efff;
		}

		.theme-toggle-thumb {
			position: absolute;
			top: 3px;
			left: 3px;
			width: 22px;
			height: 22px;
			border-radius: 50%;
			background: linear-gradient(135deg, #ffffff, #d9e9f7);
			box-shadow: 0 6px 14px rgba(0, 0, 0, 0.24);
			transform: translateX(28px);
			transition: transform 0.28s ease, background 0.28s ease, box-shadow 0.28s ease;
		}

		html[data-theme='light'] .theme-toggle-thumb {
			transform: translateX(0);
			background: linear-gradient(135deg, #fff9d9, #ffd88a);
			box-shadow: 0 8px 16px rgba(168, 116, 23, 0.18);
		}

		html[data-theme='light'] .theme-toggle-switch {
			border-color: rgba(84, 112, 139, 0.14);
			background: linear-gradient(135deg, rgba(254, 240, 138, 0.56), rgba(125, 211, 252, 0.34));
		}

		html[data-theme='light'] .theme-toggle-icon {
			color: #53708d;
		}

		html[data-theme='light'] .theme-toggle-icon-light {
			color: #d97706;
		}

		html[data-theme='light'] .theme-toggle-icon-dark {
			color: #2563eb;
		}

		.surface-card {
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.03), transparent 36%),
				var(--panel);
			border: 1px solid var(--line);
			border-radius: var(--radius-xl);
			box-shadow: var(--shadow);
			backdrop-filter: blur(18px);
		}

		.section-kicker {
			display: inline-flex;
			align-items: center;
			gap: 10px;
			margin: 0 0 18px;
			font-size: 0.82rem;
			letter-spacing: 0.14em;
			text-transform: uppercase;
			color: #9feaff;
		}

		.section-kicker::before {
			content: '';
			width: 26px;
			height: 1px;
			background: linear-gradient(90deg, transparent, rgba(97, 219, 255, 0.85));
		}

		.panel-copy,
		.field-hint,
		.summary-description,
		.results-subtitle,
		.empty-copy p,
		.site-footer {
			color: var(--muted);
			line-height: 1.8;
		}

		.summary-description,
		.empty-copy p {
			margin: 0;
		}

		.workspace-grid {
			display: grid;
			grid-template-columns: minmax(0, 1.55fr) minmax(320px, 0.9fr);
			gap: 24px;
			align-items: stretch;
			margin-top: 0;
			position: relative;
			z-index: 4;
		}

		.control-panel {
			padding: 30px;
			display: flex;
			flex-direction: column;
			min-height: 100%;
			position: relative;
			z-index: 5;
		}

		.panel-header,
		.results-header {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 20px;
		}

		.panel-title,
		.summary-title,
		.results-title,
		.empty-copy h3 {
			margin: 0;
			font-size: 1.45rem;
			font-weight: 700;
			letter-spacing: -0.02em;
		}

		.panel-copy {
			margin: 10px 0 0;
			max-width: 58ch;
		}

		.panel-badge {
			padding: 10px 14px;
			border-radius: 999px;
			background: rgba(97, 219, 255, 0.08);
			border: 1px solid rgba(97, 219, 255, 0.16);
			color: #c6f5ff;
			font-size: 0.82rem;
			white-space: nowrap;
		}

		.input-zone {
			margin-top: 24px;
		}

		.field-label {
			display: block;
			margin-bottom: 12px;
			font-size: 0.9rem;
			font-weight: 600;
			color: #d9efff;
		}

		.input-wrapper {
			position: relative;
		}

		.input-control {
			width: 100%;
			padding: 18px 64px 18px 20px;
			border: 1px solid var(--line);
			border-radius: 22px;
			background: rgba(4, 14, 24, 0.52);
			color: var(--text);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
			transition: border-color 0.24s ease, box-shadow 0.24s ease, background 0.24s ease;
		}

		.input-control::placeholder {
			color: #7390a9;
		}

		.input-control:focus {
			outline: none;
			background: rgba(5, 18, 29, 0.74);
			border-color: rgba(97, 219, 255, 0.34);
			box-shadow: 0 0 0 4px rgba(97, 219, 255, 0.08);
		}

		textarea.input-control {
			min-height: 188px;
			resize: vertical;
			padding-right: 20px;
			line-height: 1.75;
		}

		.field-hint {
			margin: 12px 0 0;
			font-size: 0.9rem;
		}

		.history-toggle {
			position: absolute;
			right: 16px;
			top: 50%;
			transform: translateY(-50%);
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 38px;
			height: 38px;
			border-radius: 14px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(255, 255, 255, 0.03);
			color: #b1c7db;
			cursor: pointer;
			transition: background 0.2s ease, color 0.2s ease, transform 0.2s ease;
		}

		.history-toggle:hover {
			color: #f7fbff;
			background: rgba(97, 219, 255, 0.08);
			transform: translateY(calc(-50% - 1px));
		}

		.history-dropdown {
			position: absolute;
			top: calc(100% + 10px);
			left: 0;
			right: 0;
			display: none;
			padding: 8px;
			border-radius: 20px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(8, 19, 32, 0.96);
			box-shadow: 0 18px 42px rgba(0, 0, 0, 0.42);
			max-height: 280px;
			overflow-y: auto;
			z-index: 80;
		}

		.history-item {
			width: 100%;
			padding: 13px 14px;
			border: none;
			background: transparent;
			border-radius: 14px;
			color: var(--text-soft);
			text-align: left;
			cursor: pointer;
			transition: background 0.2s ease, color 0.2s ease;
		}

		.history-item:hover {
			background: rgba(97, 219, 255, 0.08);
			color: #ffffff;
		}

		.history-item.is-empty {
			color: #69839a;
			cursor: default;
		}

		.control-row {
			display: flex;
			gap: 16px;
			align-items: stretch;
			margin-top: 18px;
		}

		.mode-card {
			min-width: 238px;
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 16px;
			padding: 18px 18px 18px 20px;
			border-radius: 22px;
			background: rgba(255, 255, 255, 0.03);
			border: 1px solid rgba(255, 255, 255, 0.07);
		}

		.mode-copy strong {
			display: block;
			margin-bottom: 6px;
			font-size: 0.98rem;
		}

		.mode-state {
			font-size: 0.88rem;
			color: var(--muted);
		}

		.switch {
			position: relative;
			display: inline-block;
			width: 54px;
			height: 30px;
			flex: none;
		}

		.switch input {
			opacity: 0;
			width: 0;
			height: 0;
		}

		.slider {
			position: absolute;
			inset: 0;
			cursor: pointer;
			border-radius: 999px;
			background: rgba(255, 255, 255, 0.12);
			border: 1px solid rgba(255, 255, 255, 0.08);
			transition: 0.28s ease;
		}

		.slider::before {
			content: '';
			position: absolute;
			width: 22px;
			height: 22px;
			left: 3px;
			top: 3px;
			border-radius: 50%;
			background: #ffffff;
			box-shadow: 0 6px 18px rgba(0, 0, 0, 0.24);
			transition: 0.28s ease;
		}

		.switch input:checked + .slider {
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.92), rgba(45, 212, 191, 0.84));
			border-color: transparent;
		}

		.switch input:checked + .slider::before {
			transform: translateX(24px);
		}

		.primary-btn {
			flex: 1;
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			gap: 4px;
			border: none;
			padding: 16px 20px;
			border-radius: 22px;
			background: linear-gradient(135deg, var(--accent), #8cf2ff 52%, var(--accent-warm));
			color: #052538;
			font-weight: 800;
			cursor: pointer;
			box-shadow: 0 18px 34px rgba(97, 219, 255, 0.28);
			transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
		}

		.primary-btn small {
			color: rgba(5, 37, 56, 0.78);
			font-size: 0.8rem;
			font-weight: 700;
			letter-spacing: 0.06em;
			text-transform: uppercase;
		}

		.primary-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 24px 42px rgba(97, 219, 255, 0.34);
		}

		.primary-btn:disabled {
			cursor: wait;
			transform: none;
			opacity: 0.74;
			box-shadow: 0 14px 26px rgba(97, 219, 255, 0.18);
		}

		.progress-container {
			display: grid;
			gap: 10px;
			margin-top: 18px;
			padding: 16px;
			border-radius: 22px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.035), rgba(255, 255, 255, 0.015)),
				rgba(255, 255, 255, 0.03);
		}

		.progress-head {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 12px;
			font-size: 0.92rem;
			color: var(--text-soft);
		}

		.progress-track {
			position: relative;
			height: 12px;
			border-radius: 999px;
			overflow: hidden;
			background: rgba(255, 255, 255, 0.08);
		}

		.progress-bar {
			width: 0%;
			height: 100%;
			border-radius: inherit;
			background: linear-gradient(90deg, var(--accent), var(--accent-strong), var(--accent-warm));
			transition: width 0.32s ease;
		}

		.side-column {
			display: grid;
			gap: 24px;
			min-height: 100%;
		}

		.side-card {
			padding: 26px;
			min-height: 100%;
		}

		.summary-description {
			margin-top: 10px;
		}

		.summary-grid {
			display: grid;
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: 12px;
			margin-top: 14px;
		}

		.metric-card {
			padding: 16px;
			border-radius: 18px;
			background: rgba(255, 255, 255, 0.03);
			border: 1px solid rgba(255, 255, 255, 0.06);
		}

		.metric-card span {
			display: block;
			margin-bottom: 6px;
			font-size: 0.82rem;
			color: var(--muted);
		}

		.metric-card strong {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-size: 1.65rem;
			letter-spacing: -0.04em;
		}

		.results-shell {
			margin-top: 24px;
			padding: 28px;
			position: relative;
			z-index: 1;
		}

		.results-subtitle {
			margin: 10px 0 0;
		}

		.results-pill {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			padding: 10px 14px;
			border-radius: 999px;
			font-size: 0.82rem;
			font-weight: 700;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			color: #e8f5ff;
			white-space: nowrap;
		}

		.results-pill.state-idle {
			color: #d5e6f6;
		}

		.results-pill.state-resolving {
			background: rgba(251, 191, 36, 0.12);
			border-color: rgba(251, 191, 36, 0.22);
			color: #ffd97d;
		}

		.results-pill.state-running {
			background: rgba(97, 219, 255, 0.12);
			border-color: rgba(97, 219, 255, 0.24);
			color: #bff4ff;
		}

		.results-pill.state-done {
			background: rgba(52, 211, 153, 0.12);
			border-color: rgba(52, 211, 153, 0.24);
			color: #abffd8;
		}

		.results-pill.state-empty,
		.results-pill.state-error {
			background: rgba(251, 113, 133, 0.1);
			border-color: rgba(251, 113, 133, 0.22);
			color: #ffc4d0;
		}

		.results-empty {
			display: grid;
			grid-template-columns: auto 1fr;
			gap: 18px;
			align-items: center;
			padding: 24px;
			margin-top: 22px;
			margin-bottom: 18px;
			border-radius: 24px;
			border: 1px dashed rgba(144, 180, 212, 0.22);
			background: rgba(255, 255, 255, 0.025);
		}

		.empty-visual {
			position: relative;
			width: 90px;
			height: 90px;
			border-radius: 26px;
			background:
				radial-gradient(circle at 30% 30%, rgba(97, 219, 255, 0.26), transparent 42%),
				linear-gradient(160deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.015));
			border: 1px solid rgba(255, 255, 255, 0.06);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
		}

		.empty-visual span {
			position: absolute;
			border-radius: 999px;
		}

		.empty-visual span:nth-child(1) {
			width: 44px;
			height: 44px;
			left: 10px;
			top: 14px;
			background: rgba(97, 219, 255, 0.24);
		}

		.empty-visual span:nth-child(2) {
			width: 18px;
			height: 18px;
			right: 18px;
			top: 18px;
			background: rgba(45, 212, 191, 0.48);
		}

		.empty-visual span:nth-child(3) {
			width: 56px;
			height: 10px;
			left: 18px;
			bottom: 18px;
			background: rgba(255, 255, 255, 0.12);
		}

		.results-list {
			display: grid;
			gap: 16px;
		}

		.guide-shell {
			margin-top: 24px;
			padding: 28px;
			position: relative;
			overflow: hidden;
			z-index: 1;
		}

		.guide-shell::before {
			content: '';
			position: absolute;
			inset: 0;
			background:
				radial-gradient(circle at top right, rgba(97, 219, 255, 0.14), transparent 30%),
				radial-gradient(circle at bottom left, rgba(45, 212, 191, 0.12), transparent 28%);
			pointer-events: none;
		}

		.guide-header,
		.guide-grid,
		.guide-flow,
		.guide-tip {
			position: relative;
			z-index: 1;
		}

		.guide-header {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 20px;
		}

		.guide-badge {
			display: inline-flex;
			align-items: center;
			align-self: flex-start;
			padding: 10px 14px;
			border-radius: 999px;
			background: rgba(97, 219, 255, 0.08);
			border: 1px solid rgba(97, 219, 255, 0.16);
			color: #c6f5ff;
			font-size: 0.82rem;
			font-weight: 600;
			white-space: nowrap;
		}

		.guide-grid {
			display: grid;
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: 16px;
			margin-top: 24px;
		}

		.guide-grid-secondary {
			margin-top: 18px;
		}

		.guide-card {
			padding: 24px;
			border-radius: 26px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.04), transparent 44%),
				rgba(8, 20, 34, 0.6);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
		}

		.guide-card-accent {
			background:
				radial-gradient(circle at top left, rgba(97, 219, 255, 0.16), transparent 38%),
				linear-gradient(180deg, rgba(255, 255, 255, 0.04), transparent 46%),
				rgba(9, 22, 37, 0.68);
		}

		.guide-card-warm {
			background:
				radial-gradient(circle at top right, rgba(255, 184, 105, 0.16), transparent 34%),
				linear-gradient(180deg, rgba(255, 255, 255, 0.04), transparent 46%),
				rgba(14, 23, 35, 0.72);
		}

		.guide-card-label {
			display: inline-flex;
			align-items: center;
			gap: 8px;
			margin-bottom: 14px;
			font-size: 0.74rem;
			font-weight: 700;
			letter-spacing: 0.14em;
			text-transform: uppercase;
			color: #9feaff;
		}

		.guide-card-label::before {
			content: '';
			width: 18px;
			height: 1px;
			background: rgba(97, 219, 255, 0.72);
		}

		.guide-card h3 {
			margin: 0;
			font-size: 1.18rem;
			line-height: 1.4;
			letter-spacing: -0.02em;
		}

		.guide-card p {
			margin: 14px 0 0;
			color: var(--muted);
			line-height: 1.8;
		}

		.guide-card a {
			color: #bff4ff;
			text-decoration: none;
			border-bottom: 1px solid rgba(191, 244, 255, 0.26);
		}

		.guide-card a:hover {
			color: #ffffff;
			border-bottom-color: rgba(255, 255, 255, 0.42);
		}

		.guide-quote {
			margin-top: 16px;
			padding: 14px 16px;
			border-radius: 20px;
			border: 1px solid rgba(251, 191, 36, 0.18);
			background: rgba(251, 191, 36, 0.1);
			color: #ffe7a7;
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			line-height: 1.6;
		}

		.guide-flow {
			display: grid;
			grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr);
			gap: 14px;
			align-items: center;
			margin-top: 18px;
			padding: 24px;
			border-radius: 28px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.035), transparent 60%),
				rgba(255, 255, 255, 0.03);
		}

		.guide-step {
			padding: 18px 16px;
			border-radius: 22px;
			text-align: center;
			border: 1px solid rgba(255, 255, 255, 0.07);
			background: rgba(255, 255, 255, 0.03);
		}

		.guide-step strong {
			display: block;
			font-size: 1rem;
			letter-spacing: -0.02em;
		}

		.guide-step span {
			display: block;
			margin-top: 8px;
			font-size: 0.9rem;
			color: var(--muted);
			line-height: 1.65;
		}

		.guide-step.is-source strong {
			color: #91ecff;
		}

		.guide-step.is-proxy strong {
			color: #8ef5d9;
		}

		.guide-step.is-target strong {
			color: #ffd08b;
		}

		.guide-arrow {
			font-size: 1.5rem;
			font-weight: 700;
			color: rgba(97, 219, 255, 0.82);
		}

		.guide-flow-caption {
			grid-column: 1 / -1;
			margin: 2px 0 0;
			text-align: center;
			color: var(--muted);
			line-height: 1.8;
		}

		.guide-list {
			margin: 14px 0 0;
			padding-left: 20px;
			color: var(--text-soft);
			line-height: 1.8;
		}

		.guide-list li + li {
			margin-top: 8px;
		}

		.guide-list li::marker {
			color: var(--accent-strong);
		}

		.guide-tip {
			margin-top: 18px;
			padding: 18px 20px;
			border-radius: 22px;
			border: 1px solid rgba(97, 219, 255, 0.16);
			background:
				linear-gradient(90deg, rgba(97, 219, 255, 0.1), rgba(45, 212, 191, 0.08), rgba(255, 184, 105, 0.08)),
				rgba(255, 255, 255, 0.02);
			color: #d7edf9;
			line-height: 1.8;
		}

		.guide-tip strong {
			color: #ffffff;
		}

		.result-item {
			position: relative;
			overflow: hidden;
			padding: 20px 22px;
			border-radius: 26px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.03), transparent 38%),
				var(--panel-strong);
			box-shadow: var(--shadow-soft);
		}

		.result-item > * {
			position: relative;
			z-index: 1;
		}

		.result-item::before {
			content: '';
			position: absolute;
			top: 0;
			left: 0;
			bottom: 0;
			width: 4px;
			background: rgba(147, 168, 189, 0.5);
		}

		.result-item.success::before {
			background: linear-gradient(180deg, #34d399, #10b981);
		}

		.result-item.error::before {
			background: linear-gradient(180deg, #fb7185, #ef4444);
		}

		.result-flag-overlay {
			position: absolute;
			top: 58px;
			right: -16px;
			width: 168px;
			height: 112px;
			border-radius: 28px;
			background-position: center;
			background-repeat: no-repeat;
			background-size: cover;
			opacity: 0;
			filter: blur(13px) saturate(1.08);
			transform: rotate(7deg) scale(1.18);
			transform-origin: top right;
			pointer-events: none;
			z-index: 0;
			transition: opacity 0.24s ease;
		}

		.result-item.success.has-flag .result-flag-overlay {
			opacity: 0.22;
		}

		.result-top {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 16px;
		}

		.result-info {
			display: flex;
			flex-direction: column;
			gap: 6px;
			min-width: 0;
		}

		.result-label {
			font-size: 0.74rem;
			letter-spacing: 0.14em;
			text-transform: uppercase;
			color: var(--muted);
		}

		.result-ip {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', monospace;
			font-size: 1.08rem;
			font-weight: 700;
			word-break: break-word;
		}

		.result-detail {
			color: var(--muted);
			font-size: 0.94rem;
			line-height: 1.75;
		}

		.result-detail.is-compact {
			font-size: 0.88rem;
		}

		.status-badge {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			min-width: 78px;
			padding: 10px 14px;
			border-radius: 999px;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			font-size: 0.82rem;
			font-weight: 700;
			color: #eef8ff;
			white-space: nowrap;
		}

		.status-success {
			background: rgba(52, 211, 153, 0.12);
			border-color: rgba(52, 211, 153, 0.24);
			color: #a5f3cf;
		}

		.status-error {
			background: rgba(251, 113, 133, 0.12);
			border-color: rgba(251, 113, 133, 0.24);
			color: #fecdd7;
		}

		.status-pending {
			background: rgba(251, 191, 36, 0.12);
			border-color: rgba(251, 191, 36, 0.22);
			color: #fde68a;
		}

		.result-meta {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			margin-top: 14px;
		}

		.meta-chip {
			display: inline-flex;
			align-items: center;
			gap: 8px;
			padding: 8px 12px;
			border-radius: 999px;
			background: rgba(97, 219, 255, 0.07);
			border: 1px solid rgba(97, 219, 255, 0.12);
			color: var(--text-soft);
			font-size: 0.82rem;
		}

		.meta-chip svg {
			width: 14px;
			height: 14px;
			flex: none;
			opacity: 0.92;
		}

		.meta-chip-strong {
			background: rgba(97, 219, 255, 0.12);
			border-color: rgba(97, 219, 255, 0.22);
			color: #dff9ff;
		}

		.meta-chip-danger {
			background: rgba(251, 113, 133, 0.1);
			border-color: rgba(251, 113, 133, 0.22);
			color: #ffd1d8;
		}

		.exit-list {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			margin-top: 14px;
			align-items: center;
		}

		.exit-list-label {
			color: var(--muted);
			font-size: 0.84rem;
		}

		.exit-ip-btn {
			border: 1px solid rgba(52, 211, 153, 0.22);
			border-radius: 999px;
			padding: 10px 14px;
			background: linear-gradient(135deg, rgba(52, 211, 153, 0.14), rgba(97, 219, 255, 0.08));
			color: var(--text);
			font-weight: 700;
			cursor: pointer;
			transition: transform 0.2s ease, border-color 0.2s ease, background 0.2s ease;
		}

		.exit-ip-btn:hover {
			transform: translateY(-1px);
			border-color: rgba(97, 219, 255, 0.32);
			background: linear-gradient(135deg, rgba(52, 211, 153, 0.18), rgba(97, 219, 255, 0.12));
		}

		.exit-ip-btn.is-active {
			border-color: rgba(97, 219, 255, 0.52);
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.26), rgba(52, 211, 153, 0.16));
			box-shadow: inset 0 0 0 1px rgba(97, 219, 255, 0.14), 0 0 0 1px rgba(97, 219, 255, 0.1);
		}

		.map-container-wrapper {
			display: none;
			margin-top: 16px;
			height: 330px;
			border-radius: 22px;
			overflow: hidden;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(255, 255, 255, 0.03);
		}

		#map-template {
			display: none;
		}

		#global-map {
			width: 100%;
			height: 100%;
			background: #09111d;
		}

		#global-map .leaflet-tile-pane {
			filter: invert(1) hue-rotate(180deg) brightness(0.92) contrast(0.96) saturate(0.88);
		}

		.map-popup {
			font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
			font-size: 0.88rem;
			line-height: 1.65;
			color: #10253d;
		}

		.map-popup b {
			color: #081826;
		}

		.leaflet-control-zoom {
			display: none !important;
		}

		.leaflet-control-attribution {
			display: block !important;
			margin: 0 !important;
			padding: 4px 8px !important;
			border-radius: 12px 0 0 0;
			background: rgba(9, 17, 29, 0.78) !important;
			backdrop-filter: blur(10px);
			box-shadow: 0 10px 24px rgba(3, 7, 18, 0.22);
			color: rgba(223, 240, 255, 0.84) !important;
			font-size: 11px;
			line-height: 1.4;
		}

		.leaflet-control-attribution a {
			color: inherit !important;
		}

		.site-footer {
			padding-top: 22px;
			font-size: 0.9rem;
		}

		.site-footer a,
		#visit-count {
			color: #bff4ff;
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-weight: 600;
			letter-spacing: -0.02em;
			font-variant-numeric: tabular-nums;
		}

		.site-footer a {
			text-decoration: none;
			border-bottom: 1px solid rgba(191, 244, 255, 0.28);
		}

		.site-footer a:hover {
			color: #ffffff;
			border-bottom-color: rgba(255, 255, 255, 0.42);
		}

		html[data-theme='light'] .brand-chip {
			border-color: rgba(86, 124, 158, 0.18);
			background: rgba(255, 255, 255, 0.76);
			color: #1d5d83;
		}

		html[data-theme='light'] .brand-title {
			color: #10253d;
		}

		html[data-theme='light'] .theme-toggle {
			background: transparent;
			border-color: transparent;
			box-shadow: none;
		}

		html[data-theme='light'] .surface-card {
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(255, 255, 255, 0.72)),
				var(--panel);
		}

		html[data-theme='light'] .section-kicker,
		html[data-theme='light'] .guide-card-label {
			color: #0f7ab8;
		}

		html[data-theme='light'] .section-kicker::before,
		html[data-theme='light'] .guide-card-label::before {
			background: linear-gradient(90deg, transparent, rgba(14, 165, 233, 0.72));
		}

		html[data-theme='light'] .panel-badge,
		html[data-theme='light'] .guide-badge {
			background: rgba(14, 165, 233, 0.08);
			border-color: rgba(14, 165, 233, 0.16);
			color: #0f5f8e;
		}

		html[data-theme='light'] .field-label {
			color: #17324a;
		}

		html[data-theme='light'] .input-control {
			background: rgba(255, 255, 255, 0.82);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
		}

		html[data-theme='light'] .input-control::placeholder {
			color: #7b8fa3;
		}

		html[data-theme='light'] .input-control:focus {
			background: #ffffff;
			border-color: rgba(14, 165, 233, 0.3);
			box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.1);
		}

		html[data-theme='light'] .history-toggle {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.78);
			color: #5b738b;
		}

		html[data-theme='light'] .history-toggle:hover {
			color: #10253d;
			background: rgba(14, 165, 233, 0.1);
		}

		html[data-theme='light'] .history-dropdown {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.96);
			box-shadow: 0 20px 36px rgba(43, 67, 91, 0.16);
		}

		html[data-theme='light'] .history-item:hover {
			background: rgba(14, 165, 233, 0.08);
			color: #10253d;
		}

		html[data-theme='light'] .history-item.is-empty {
			color: #7f92a6;
		}

		html[data-theme='light'] .mode-card,
		html[data-theme='light'] .progress-container,
		html[data-theme='light'] .metric-card,
		html[data-theme='light'] .results-empty,
		html[data-theme='light'] .guide-flow,
		html[data-theme='light'] .guide-step,
		html[data-theme='light'] .map-container-wrapper {
			background: rgba(255, 255, 255, 0.62);
			border-color: rgba(95, 123, 150, 0.14);
		}

		html[data-theme='light'] .slider {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(95, 123, 150, 0.14);
		}

		html[data-theme='light'] .slider::before {
			background: #ffffff;
			box-shadow: 0 6px 14px rgba(43, 67, 91, 0.18);
		}

		html[data-theme='light'] .primary-btn {
			box-shadow: 0 18px 34px rgba(14, 165, 233, 0.18);
		}

		html[data-theme='light'] .primary-btn:hover {
			box-shadow: 0 22px 40px rgba(14, 165, 233, 0.22);
		}

		html[data-theme='light'] .results-pill {
			border-color: rgba(95, 123, 150, 0.16);
			background: rgba(255, 255, 255, 0.72);
			color: #16324a;
		}

		html[data-theme='light'] .results-pill.state-idle {
			color: #365168;
		}

		html[data-theme='light'] .results-pill.state-resolving {
			background: rgba(245, 158, 11, 0.12);
			border-color: rgba(245, 158, 11, 0.18);
			color: #9a6706;
		}

		html[data-theme='light'] .results-pill.state-running {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(14, 165, 233, 0.18);
			color: #0f5f8e;
		}

		html[data-theme='light'] .results-pill.state-done {
			background: rgba(5, 150, 105, 0.12);
			border-color: rgba(5, 150, 105, 0.18);
			color: #047857;
		}

		html[data-theme='light'] .results-pill.state-empty,
		html[data-theme='light'] .results-pill.state-error {
			background: rgba(225, 29, 72, 0.1);
			border-color: rgba(225, 29, 72, 0.16);
			color: #be123c;
		}

		html[data-theme='light'] .empty-visual {
			background:
				radial-gradient(circle at 30% 30%, rgba(14, 165, 233, 0.18), transparent 42%),
				linear-gradient(160deg, rgba(255, 255, 255, 0.78), rgba(255, 255, 255, 0.4));
			border-color: rgba(95, 123, 150, 0.14);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.82);
		}

		html[data-theme='light'] .empty-visual span:nth-child(1) {
			background: rgba(14, 165, 233, 0.18);
		}

		html[data-theme='light'] .empty-visual span:nth-child(2) {
			background: rgba(20, 184, 166, 0.28);
		}

		html[data-theme='light'] .empty-visual span:nth-child(3) {
			background: rgba(16, 37, 61, 0.12);
		}

		html[data-theme='light'] .guide-shell::before {
			background:
				radial-gradient(circle at top right, rgba(14, 165, 233, 0.1), transparent 30%),
				radial-gradient(circle at bottom left, rgba(20, 184, 166, 0.08), transparent 28%);
		}

		html[data-theme='light'] .guide-card {
			border-color: rgba(95, 123, 150, 0.14);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(255, 255, 255, 0.56)),
				rgba(255, 255, 255, 0.74);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
		}

		html[data-theme='light'] .guide-card-accent {
			background:
				radial-gradient(circle at top left, rgba(14, 165, 233, 0.12), transparent 38%),
				linear-gradient(180deg, rgba(255, 255, 255, 0.9), rgba(255, 255, 255, 0.56)),
				rgba(255, 255, 255, 0.78);
		}

		html[data-theme='light'] .guide-card-warm {
			background:
				radial-gradient(circle at top right, rgba(245, 158, 11, 0.12), transparent 34%),
				linear-gradient(180deg, rgba(255, 255, 255, 0.9), rgba(255, 255, 255, 0.56)),
				rgba(255, 255, 255, 0.78);
		}

		html[data-theme='light'] .guide-card a,
		html[data-theme='light'] .site-footer a,
		html[data-theme='light'] #visit-count {
			color: #0f7ab8;
			border-bottom-color: rgba(14, 165, 233, 0.24);
		}

		html[data-theme='light'] .guide-card a:hover,
		html[data-theme='light'] .site-footer a:hover {
			color: #10253d;
			border-bottom-color: rgba(16, 37, 61, 0.2);
		}

		html[data-theme='light'] .guide-quote {
			border-color: rgba(245, 158, 11, 0.16);
			background: rgba(245, 158, 11, 0.08);
			color: #9a6706;
		}

		html[data-theme='light'] .guide-step.is-source strong {
			color: #0284c7;
		}

		html[data-theme='light'] .guide-step.is-proxy strong {
			color: #0f766e;
		}

		html[data-theme='light'] .guide-step.is-target strong {
			color: #b45309;
		}

		html[data-theme='light'] .guide-arrow {
			color: rgba(14, 165, 233, 0.56);
		}

		html[data-theme='light'] .guide-tip {
			border-color: rgba(14, 165, 233, 0.14);
			background:
				linear-gradient(90deg, rgba(14, 165, 233, 0.08), rgba(20, 184, 166, 0.06), rgba(245, 158, 11, 0.06)),
				rgba(255, 255, 255, 0.62);
			color: #365168;
		}

		html[data-theme='light'] .guide-tip strong {
			color: #10253d;
		}

		html[data-theme='light'] .result-item {
			border-color: rgba(95, 123, 150, 0.14);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.88), transparent 38%),
				var(--panel-strong);
		}

		html[data-theme='light'] .result-item::before {
			background: rgba(121, 140, 159, 0.38);
		}

		html[data-theme='light'] .status-badge {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.72);
			color: #16324a;
		}

		html[data-theme='light'] .status-success {
			background: rgba(5, 150, 105, 0.12);
			border-color: rgba(5, 150, 105, 0.16);
			color: #047857;
		}

		html[data-theme='light'] .status-error {
			background: rgba(225, 29, 72, 0.1);
			border-color: rgba(225, 29, 72, 0.16);
			color: #be123c;
		}

		html[data-theme='light'] .status-pending {
			background: rgba(245, 158, 11, 0.12);
			border-color: rgba(245, 158, 11, 0.16);
			color: #9a6706;
		}

		html[data-theme='light'] .meta-chip {
			background: rgba(14, 165, 233, 0.08);
			border-color: rgba(14, 165, 233, 0.12);
			color: #23415a;
		}

		html[data-theme='light'] .meta-chip-strong {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(14, 165, 233, 0.18);
			color: #075985;
		}

		html[data-theme='light'] .meta-chip-danger {
			background: rgba(225, 29, 72, 0.08);
			border-color: rgba(225, 29, 72, 0.14);
			color: #be123c;
		}

		html[data-theme='light'] .exit-ip-btn {
			border-color: rgba(5, 150, 105, 0.18);
			background: linear-gradient(135deg, rgba(5, 150, 105, 0.08), rgba(14, 165, 233, 0.08));
			color: #17324a;
		}

		html[data-theme='light'] .exit-ip-btn:hover {
			border-color: rgba(14, 165, 233, 0.24);
			background: linear-gradient(135deg, rgba(5, 150, 105, 0.12), rgba(14, 165, 233, 0.12));
		}

		html[data-theme='light'] .exit-ip-btn.is-active {
			border-color: rgba(14, 165, 233, 0.32);
			background: linear-gradient(135deg, rgba(14, 165, 233, 0.18), rgba(5, 150, 105, 0.12));
			box-shadow: inset 0 0 0 1px rgba(14, 165, 233, 0.1), 0 0 0 1px rgba(14, 165, 233, 0.08);
		}

		html[data-theme='light'] #global-map {
			background: #dfeaf3;
		}

		html[data-theme='light'] #global-map .leaflet-tile-pane {
			filter: none;
		}

		html[data-theme='light'] .leaflet-control-attribution {
			background: rgba(255, 255, 255, 0.92) !important;
			box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
			color: rgba(15, 23, 42, 0.72) !important;
		}

		@media (max-width: 980px) {
			.workspace-grid {
				grid-template-columns: 1fr;
			}

			.header-note {
				text-align: left;
				max-width: none;
			}

			.guide-grid {
				grid-template-columns: 1fr;
			}

		}

		@media (max-width: 720px) {
			.page-shell {
				padding: 22px 14px 32px;
			}

			.header-note {
				flex: none;
			}

			.results-list:not(:empty) {
				margin-top: 18px;
			}

			.site-header,
			.panel-header,
			.results-header,
			.guide-header,
			.control-row,
			.results-empty,
			.result-top {
				flex-direction: column;
			}

			.site-header,
			.panel-header,
			.results-header,
			.guide-header,
			.control-row {
				align-items: stretch;
			}

			.control-panel,
			.side-card,
			.results-shell,
			.guide-shell {
				padding: 22px;
			}

			.mode-card {
				min-width: 0;
			}

			.progress-head {
				flex-direction: column;
				align-items: flex-start;
			}

			.guide-flow {
				grid-template-columns: 1fr;
				padding: 20px;
			}

			.guide-arrow {
				display: none;
			}
		}

		@media (max-width: 560px) {
			.meta-chip,
			.exit-ip-btn {
				width: 100%;
				justify-content: center;
			}

			.results-empty {
				grid-template-columns: 1fr;
				text-align: center;
			}

			.empty-visual {
				margin: 0 auto;
			}

			.summary-grid {
				grid-template-columns: repeat(2, minmax(0, 1fr));
				gap: 10px;
			}

			.metric-card {
				padding: 14px;
			}
		}
	</style>
</head>
<body>
	<div class="page-shell">
		<div class="ambient ambient-one"></div>
		<div class="ambient ambient-two"></div>

		<header class="site-header">
			<div class="brand">
				<div class="brand-title">Check ProxyIP</div>
				<div class="brand-chip">
					<span class="brand-chip-text">
						<span class="brand-dot"></span>
						<span>Cloudflare Workers Toolkit</span>
					</span>
					<button class="theme-toggle" type="button" id="themeToggle" aria-label="切换日间和夜间模式" title="切换日间和夜间模式">
						<span class="theme-toggle-switch" aria-hidden="true">
							<svg class="theme-toggle-icon theme-toggle-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<circle cx="12" cy="12" r="4"></circle>
								<path d="M12 2v2"></path>
								<path d="M12 20v2"></path>
								<path d="m4.93 4.93 1.41 1.41"></path>
								<path d="m17.66 17.66 1.41 1.41"></path>
								<path d="M2 12h2"></path>
								<path d="M20 12h2"></path>
								<path d="m6.34 17.66-1.41 1.41"></path>
								<path d="m19.07 4.93-1.41 1.41"></path>
							</svg>
							<span class="theme-toggle-thumb"></span>
							<svg class="theme-toggle-icon theme-toggle-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"></path>
							</svg>
						</span>
					</button>
				</div>
			</div>
			<div class="header-note">基于 Cloudflare 的 ProxyIP 检测工具，支持单个或批量目标解析、可用性验证与出口信息查看。</div>
		</header>

		<main class="site-main">
			<section class="workspace-grid">
				<div class="surface-card control-panel">
					<div class="panel-header">
						<div>
							<p class="section-kicker">Workspace</p>
							<h2 class="panel-title">开始检测</h2>
							<p class="panel-copy">输入单个 IP、IPv6、域名或一整段列表。单条模式支持历史记录，批量模式适合直接粘贴多行目标。</p>
						</div>
						<div class="panel-badge">实时解析与验证</div>
					</div>

					<div class="input-zone">
						<label class="field-label" for="inputList">ProxyIP / 域名目标</label>
						<div class="input-wrapper" id="inputContainer">
							<input class="input-control" type="text" id="inputList" placeholder="例如：ProxyIP.CMLiussss.net 或 8.223.63.150:443">
							<button class="history-toggle" type="button" id="historyBtn" aria-label="查看历史记录">
								<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<circle cx="12" cy="12" r="10"></circle>
									<polyline points="12 6 12 12 16 14"></polyline>
								</svg>
							</button>
							<div class="history-dropdown" id="historyDropdown"></div>
						</div>
						<p class="field-hint" id="fieldHint">单条模式支持历史快速回填，按 Enter 可以直接开始检测。</p>
					</div>

					<div class="control-row">
						<div class="mode-card">
							<div class="mode-copy">
								<strong>批量检测</strong>
								<div class="mode-state" id="modeLabel">Single / 单目标</div>
							</div>
							<label class="switch">
								<input type="checkbox" id="batchMode">
								<span class="slider"></span>
							</label>
						</div>

						<button class="primary-btn" id="checkBtn" type="button">
							<span>开始检测</span>
							<small>Resolve + Check</small>
						</button>
					</div>

				</div>

				<aside class="side-column">
					<div class="surface-card side-card">
						<p class="section-kicker">Summary</p>
						<h3 class="summary-title" id="summaryHeadline">等待输入</h3>
						<p class="summary-description" id="summaryDescription">实时统计和检测概览。</p>
						<div id="progressContainer" class="progress-container">
							<div class="progress-head">
								<span>检测进度</span>
								<span id="progressText">尚未开始</span>
							</div>
							<div class="progress-track">
								<div id="progressBar" class="progress-bar"></div>
							</div>
						</div>
						<div class="summary-grid">
							<div class="metric-card">
								<span>目标数</span>
								<strong id="statTotal">0</strong>
							</div>
							<div class="metric-card">
								<span>有效</span>
								<strong id="statSuccess">0</strong>
							</div>
							<div class="metric-card">
								<span>待完成</span>
								<strong id="statPending">0</strong>
							</div>
							<div class="metric-card">
								<span>失败</span>
								<strong id="statFailed">0</strong>
							</div>
						</div>
					</div>
				</aside>
			</section>

			<section class="surface-card results-shell">
				<div class="results-header">
					<div>
						<p class="section-kicker">Results</p>
						<h2 class="results-title">检测结果</h2>
						<p class="results-subtitle" id="resultMeta">结果、落地 IP 和地图会在这里按检测进度逐步展开。</p>
					</div>
					<div class="results-pill state-idle" id="resultPill">Idle</div>
				</div>

				<div class="results-empty" id="resultsEmpty">
					<div class="empty-visual" aria-hidden="true">
						<span></span>
						<span></span>
						<span></span>
					</div>
					<div class="empty-copy">
						<h3 id="emptyStateTitle">等待开始检测</h3>
						<p id="emptyStateDescription">输入目标后，检测结果、出口信息和地图会在这里展示。</p>
					</div>
				</div>

				<div id="results" class="results-list"></div>
			</section>

			<section class="surface-card guide-shell">
				<div class="guide-header">
					<div>
						<p class="section-kicker">Guide</p>
						<h2 class="results-title">什么是 ProxyIP</h2>
						<p class="results-subtitle">用一段更接近实际部署场景的说明，快速理解 ProxyIP 的定义、作用和筛选标准。</p>
					</div>
					<div class="guide-badge">Cloudflare Workers / TCP</div>
				</div>

				<div class="guide-grid">
					<article class="guide-card guide-card-accent">
						<div class="guide-card-label">概念</div>
						<h3>ProxyIP 是一个可被验证的中转入口</h3>
						<p>在 Cloudflare Workers 的使用语境里，ProxyIP 通常指那些能够成功代理到 Cloudflare 服务的第三方 IP。它不是 Cloudflare 官方分配给你的接入地址，而是一个可以替你完成转发的外部节点。</p>
					</article>

					<article class="guide-card guide-card-warm">
						<div class="guide-card-label">限制来源</div>
						<h3>为什么很多场景会专门去找 ProxyIP</h3>
						<p>Cloudflare Workers 的 <a href="https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/" target="_blank" rel="noreferrer">TCP sockets 文档</a> 明确提到，指向 <a href="https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/" target="_blank" rel="noreferrer">Cloudflare IP ranges</a> 的出站 TCP 连接会被阻止。也就是说，某些依赖直连 Cloudflare IP 的链路，不能在 Workers 里直接打通。</p>
						<div class="guide-quote">Outbound TCP sockets to Cloudflare IP ranges are blocked.</div>
					</article>
				</div>

				<div class="guide-flow">
					<div class="guide-step is-source">
						<strong>Cloudflare Workers</strong>
						<span>发起请求，尝试访问目标服务</span>
					</div>
					<div class="guide-arrow" aria-hidden="true">→</div>
					<div class="guide-step is-proxy">
						<strong>ProxyIP 节点</strong>
						<span>位于第三方网络，负责中转和反向代理</span>
					</div>
					<div class="guide-arrow" aria-hidden="true">→</div>
					<div class="guide-step is-target">
						<strong>Cloudflare 服务</strong>
						<span>最终被访问的站点、边缘服务或 CDN 目标</span>
					</div>
					<p class="guide-flow-caption">实际作用可以理解为：让 Workers 先连到第三方节点，再由该节点替你把流量送到 Cloudflare 侧，绕开直连 Cloudflare IP 的限制。</p>
				</div>

				<div class="guide-grid guide-grid-secondary">
					<article class="guide-card">
						<div class="guide-card-label">应用场景</div>
						<h3>为什么像 edgetunnel、epeius 这类项目会用到它</h3>
						<p>当目标网站本身走的是 Cloudflare CDN 或 Cloudflare 边缘网络时，项目如果需要直接建立到目标地址的 TCP 连接，就可能因为上述限制而失败。配置可用的 ProxyIP 后，这类项目就能借助中转节点继续完成访问。</p>
					</article>

					<article class="guide-card">
						<div class="guide-card-label">有效特征</div>
						<h3>有效的 ProxyIP，通常至少满足这些条件</h3>
						<ul class="guide-list">
							<li>能够成功建立代理到指定端口（通常为 443）的 TCP 连接</li>
							<li>具备反向代理 Cloudflare IP 段的 HTTPS 服务能力</li>
						</ul>
					</article>
				</div>

				<div class="guide-tip">
					<strong>这页检测的意义：</strong>本工具不是只做静态解析，而是尽量模拟真实链路去验证目标是否真的可用，帮助你更快筛掉“看起来在线、实际不可做代理”的候选 IP。
				</div>
			</section>
		</main>

		<footer class="site-footer">
			<div>© 2025 - 2026 Check ProxyIP · 基于 Cloudflare Workers 构建与运行 · 今日访问人数：<span id="visit-count">···</span> · 站点维护：<a href="https://t.me/CMLiussss" target="_blank" rel="noreferrer">CMLiussss</a></div>
		</footer>
	</div>

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
		const progressBar = document.getElementById('progressBar');
		const progressText = document.getElementById('progressText');
		const globalMap = document.getElementById('global-map');
		const historyBtn = document.getElementById('historyBtn');
		const historyDropdown = document.getElementById('historyDropdown');
		const fieldHint = document.getElementById('fieldHint');
		const modeLabel = document.getElementById('modeLabel');
		const summaryHeadline = document.getElementById('summaryHeadline');
		const summaryDescription = document.getElementById('summaryDescription');
		const statTotal = document.getElementById('statTotal');
		const statSuccess = document.getElementById('statSuccess');
		const statPending = document.getElementById('statPending');
		const statFailed = document.getElementById('statFailed');
		const resultMeta = document.getElementById('resultMeta');
		const resultPill = document.getElementById('resultPill');
		const resultsEmpty = document.getElementById('resultsEmpty');
		const emptyStateTitle = document.getElementById('emptyStateTitle');
		const emptyStateDescription = document.getElementById('emptyStateDescription');
		const themeToggle = document.getElementById('themeToggle');
		const THEME_STORAGE_KEY = 'cf_proxy_theme';
		const systemThemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
		const BASE_MAP_TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
		const BASE_MAP_TILE_OPTIONS = {
			maxZoom: 19,
			attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer noopener">OpenStreetMap</a> contributors'
		};

		let map = null;
		let mapLayers = [];
		let mapSvgRenderer = null;
		let cfLocationIndex = new Map();
		let cfLocationsPromise = null;
		let mapRenderToken = 0;
		let totalTargets = 0;
		let completedCount = 0;
		let successCount = 0;
		let inputCount = 0;
		let appState = 'idle';
		const CHECK_CONCURRENCY = 32;

		function getStoredTheme() {
			try {
				const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
				return storedTheme === 'light' || storedTheme === 'dark' ? storedTheme : '';
			} catch {
				return '';
			}
		}

		function getSystemTheme() {
			return systemThemeQuery.matches ? 'dark' : 'light';
		}

		function applyTheme(theme, source) {
			const nextTheme = theme === 'light' ? 'light' : 'dark';
			const isDark = nextTheme === 'dark';

			document.documentElement.dataset.theme = nextTheme;
			document.documentElement.style.colorScheme = nextTheme;

			if (!themeToggle) return;

			themeToggle.setAttribute('aria-pressed', String(isDark));
			themeToggle.setAttribute(
				'aria-label',
				isDark
					? '当前为夜间模式，点击切换到日间模式。'
					: '当前为日间模式，点击切换到夜间模式。'
			);
			themeToggle.title = source === 'stored'
				? (isDark ? '夜间模式，已保存到本地' : '日间模式，已保存到本地')
				: (isDark ? '夜间模式，当前跟随系统' : '日间模式，当前跟随系统');
		}

		function initializeTheme() {
			const storedTheme = getStoredTheme();
			applyTheme(storedTheme || getSystemTheme(), storedTheme ? 'stored' : 'system');
		}

		initializeTheme();

		function getVisitStatsId() {
			const hostname = String(window.location.hostname || window.location.host || '').trim().toLowerCase();
			return hostname || 'unknown-host';
		}

		async function fetchVisitCount() {
			const visitCountElement = document.getElementById('visit-count');
			if (!visitCountElement) return;

			try {
				const response = await fetch('https://tongji.090227.xyz/?id=' + encodeURIComponent(getVisitStatsId()));
				if (!response.ok) {
					throw new Error('Failed to load visit count: ' + response.status);
				}

				const data = await response.json();
				if (data && data.visitCount !== undefined) {
					visitCountElement.textContent = data.visitCount;
					return;
				}

				throw new Error('visitCount is missing in response');
			} catch (error) {
				console.error('Failed to fetch visit count', error);
				visitCountElement.textContent = '加载失败';
			}
		}

		function initMap() {
			if (map) return;
			map = L.map('global-map', {
				zoomControl: false,
				attributionControl: true
			}).setView([20, 0], 2);
			map.attributionControl.setPrefix(false);
			// OpenStreetMap provides broader global coverage than AMap for international checks.
			L.tileLayer(BASE_MAP_TILE_URL, BASE_MAP_TILE_OPTIONS).addTo(map);
			mapSvgRenderer = L.svg();
			mapSvgRenderer.addTo(map);
		}

		function normalizeColoCode(value) {
			const code = String(value || '').trim().toUpperCase();
			return /^[A-Z0-9]{3,4}$/.test(code) ? code : '';
		}

		function isValidCoordinatePair(value) {
			return Array.isArray(value)
				&& value.length === 2
				&& value.every(function (entry) { return Number.isFinite(entry); })
				&& Math.abs(value[0]) <= 90
				&& Math.abs(value[1]) <= 180;
		}

		function parseCoordinatePair(value) {
			if (typeof value === 'string') {
				const parts = value.split(',').map(function (entry) {
					return Number(entry.trim());
				});
				return isValidCoordinatePair(parts) ? parts : null;
			}

			if (Array.isArray(value)) {
				const parts = value.map(function (entry) {
					return Number(entry);
				});
				return isValidCoordinatePair(parts) ? parts : null;
			}

			return null;
		}

		async function loadCfLocations() {
			if (cfLocationsPromise) {
				return cfLocationsPromise;
			}

			cfLocationsPromise = fetch('/locations')
				.then(function (response) {
					if (!response.ok) {
						throw new Error('Failed to load /locations: ' + response.status);
					}
					return response.json();
				})
				.then(function (payload) {
					const nextIndex = new Map();
					if (Array.isArray(payload)) {
						payload.forEach(function (entry) {
							const code = normalizeColoCode(entry?.iata);
							const lat = Number(entry?.lat);
							const lon = Number(entry?.lon);
							if (!code || !Number.isFinite(lat) || !Number.isFinite(lon)) {
								return;
							}
							nextIndex.set(code, {
								code: code,
								lat: lat,
								lon: lon,
								city: String(entry?.city || '').trim(),
								region: String(entry?.region || '').trim(),
								country: String(entry?.cca2 || '').trim()
							});
						});
					}
					cfLocationIndex = nextIndex;
					return nextIndex;
				})
				.catch(function (error) {
					console.error('Failed to preload Cloudflare locations', error);
					return cfLocationIndex;
				});

			return cfLocationsPromise;
		}

		function getCfLocation(coloCode) {
			const normalizedCode = normalizeColoCode(coloCode);
			if (!normalizedCode) {
				return null;
			}

			const location = cfLocationIndex.get(normalizedCode);
			return location ? {
				code: location.code,
				lat: location.lat,
				lon: location.lon,
				city: location.city,
				region: location.region,
				country: location.country
			} : null;
		}

		function clearMapLayers() {
			mapLayers.forEach(function (layer) {
				map.removeLayer(layer);
			});
			mapLayers = [];
		}

		function buildCfLocationLabel(cfLocation) {
			return [cfLocation?.city, cfLocation?.region, cfLocation?.country].filter(Boolean).join(', ');
		}

		function ensureRouteArrowMarkerDef() {
			const overlaySvg = map?.getPanes?.().overlayPane?.querySelector('svg');
			if (!overlaySvg) {
				return '';
			}

			const svgNamespace = 'http://www.w3.org/2000/svg';
			let defs = overlaySvg.querySelector('defs');
			if (!defs) {
				defs = document.createElementNS(svgNamespace, 'defs');
				overlaySvg.insertBefore(defs, overlaySvg.firstChild);
			}

			const markerId = 'route-flow-arrowhead';
			if (!overlaySvg.querySelector('#' + markerId)) {
				const marker = document.createElementNS(svgNamespace, 'marker');
				marker.setAttribute('id', markerId);
				marker.setAttribute('viewBox', '0 0 10 10');
				marker.setAttribute('refX', '8');
				marker.setAttribute('refY', '5');
				marker.setAttribute('markerWidth', '7');
				marker.setAttribute('markerHeight', '7');
				marker.setAttribute('orient', 'auto');
				marker.setAttribute('markerUnits', 'strokeWidth');

				const arrowPath = document.createElementNS(svgNamespace, 'path');
				arrowPath.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z');
				arrowPath.setAttribute('fill', '#8be9ff');
				arrowPath.setAttribute('fill-opacity', '0.95');

				marker.appendChild(arrowPath);
				defs.appendChild(marker);
			}

			return markerId;
		}

		function applyArrowStyleToPolyline(polyline) {
			const markerId = ensureRouteArrowMarkerDef();
			const pathElement = polyline?.getElement?.();
			if (!markerId || !pathElement) {
				return;
			}

			pathElement.setAttribute('marker-end', 'url(#' + markerId + ')');
			pathElement.setAttribute('stroke-linecap', 'round');
		}

		function createExitPopup(exitData) {
			const locationText = formatExitLocation(exitData) || 'Location unknown';
			const networkText = formatExitNetwork(exitData) || 'Network unknown';
			const coloCode = normalizeColoCode(exitData?.colo);
			const coloText = coloCode ? '<br>CF Colo: ' + escapeHtml(coloCode) : '';
			return '<div class="map-popup"><b>Exit IP</b><br>'
				+ escapeHtml(exitData?.ip || 'Unknown')
				+ '<br>' + escapeHtml(locationText)
				+ '<br>' + escapeHtml(networkText)
				+ coloText
				+ '</div>';
		}

		function createCfPopup(cfLocation) {
			const locationText = buildCfLocationLabel(cfLocation) || 'Location unknown';
			return '<div class="map-popup"><b>Cloudflare Colo</b><br>'
				+ escapeHtml(cfLocation?.code || 'Unknown')
				+ '<br>' + escapeHtml(locationText)
				+ '</div>';
		}

		function escapeHtml(value) {
			return String(value ?? '').replace(/[&<>"']/g, function (char) {
				return {
					'&': '&amp;',
					'<': '&lt;',
					'>': '&gt;',
					'"': '&quot;',
					"'": '&#39;'
				}[char];
			});
		}

		function getMetaChipIcon(iconName) {
			const icons = {
				prep: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8"></circle><path d="M12 8v4l3 2"></path></svg>',
				location: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s6-4.35 6-10a6 6 0 1 0-12 0c0 5.65 6 10 6 10z"></path><circle cx="12" cy="11" r="2.5"></circle></svg>',
				network: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"></rect><rect x="3" y="14" width="18" height="6" rx="2"></rect><circle cx="7" cy="7" r="1"></circle><circle cx="7" cy="17" r="1"></circle><path d="M12 10v4"></path></svg>',
				exits: '<svg viewBox="0 0 44 43" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M30.251 8.73438C30.251 6.13691 32.4057 4.03125 35.0635 4.03125C37.7214 4.03125 39.876 6.13691 39.876 8.73438C39.876 10.8649 38.4264 12.6646 36.4385 13.2427V15.4531C36.4385 19.1638 33.3605 22.1719 29.5635 22.1719H15.8135C13.5354 22.1719 11.6885 23.9767 11.6885 26.2031V29.7573C13.6764 30.3354 15.126 32.1351 15.126 34.2656C15.126 36.8631 12.9714 38.9688 10.3135 38.9688C7.65566 38.9688 5.50101 36.8631 5.50101 34.2656C5.50101 32.1351 6.95063 30.3354 8.93853 29.7573V13.2427C6.95063 12.6646 5.50101 10.8649 5.50101 8.73438C5.50101 6.13691 7.65566 4.03125 10.3135 4.03125C12.9714 4.03125 15.126 6.13691 15.126 8.73438C15.126 10.8649 13.6764 12.6646 11.6885 13.2427V20.8277C12.8376 19.9842 14.2658 19.4844 15.8135 19.4844H29.5635C31.8417 19.4844 33.6885 17.6795 33.6885 15.4531V13.2427C31.7006 12.6646 30.251 10.8649 30.251 8.73438Z" fill="currentColor"></path></svg>',
				error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path></svg>',
				info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 10v5"></path><circle cx="12" cy="7" r="1"></circle></svg>',
				retry: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 5v6h-6"></path><path d="M4 19v-6h6"></path><path d="M7 17a7 7 0 0 0 11-4"></path><path d="M17 7A7 7 0 0 0 6 11"></path></svg>'
			};
			return icons[iconName] || icons.info;
		}

		function buildMetaChip(text, iconName, modifierClass) {
			const className = modifierClass ? 'meta-chip ' + modifierClass : 'meta-chip';
			return '<span class="' + className + '">' + getMetaChipIcon(iconName) + '<span>' + escapeHtml(text) + '</span></span>';
		}

		function normalizeBatchInputValue(value) {
			return String(value ?? '')
				.replace(/\\r\\n?/g, '\\n')
				.replace(/[,\uFF0C]/g, '\\n')
				.split('\\n')
				.map(stripTargetLabel)
				.join('\\n');
		}

		function stripTargetLabel(value) {
			return String(value || '').split('#')[0].trim();
		}

		function parseClientTarget(input) {
			let host = stripTargetLabel(input);
			let port = 443;

			if (host.startsWith('[')) {
				const ipv6PortIndex = host.lastIndexOf(']:');
				if (ipv6PortIndex !== -1) {
					const maybePort = Number(host.slice(ipv6PortIndex + 2));
					if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
						port = maybePort;
						host = host.slice(0, ipv6PortIndex + 1);
					}
				}
				return { host, port };
			}

			const colonMatches = host.match(/:/g) || [];
			if (colonMatches.length === 1) {
				const separatorIndex = host.lastIndexOf(':');
				const maybePort = Number(host.slice(separatorIndex + 1));
				if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
					port = maybePort;
					host = host.slice(0, separatorIndex);
				}
			}

			return { host, port };
		}

		function isClientIPv4(value) {
			const parts = String(value || '').split('.');
			return parts.length === 4 && parts.every(function (part) {
				if (!/^\\d{1,3}$/.test(part)) return false;
				const num = Number(part);
				return num >= 0 && num <= 255;
			});
		}

		function isClientRawIPv6(value) {
			const text = String(value || '');
			return text.includes(':') && /^[0-9a-fA-F:]+$/.test(text);
		}

		function getDirectIpTarget(input) {
			const parsed = parseClientTarget(input);
			const bracketedIPv6 = parsed.host.startsWith('[') && parsed.host.endsWith(']');
			const bracketedIPv6Body = bracketedIPv6 ? parsed.host.slice(1, -1) : '';
			const rawIPv6 = isClientRawIPv6(parsed.host);

			if (isClientIPv4(parsed.host)) {
				return parsed.host + ':' + parsed.port;
			}

			if (rawIPv6) {
				return '[' + parsed.host + ']:' + parsed.port;
			}

			if (bracketedIPv6 && isClientRawIPv6(bracketedIPv6Body)) {
				return parsed.host + ':' + parsed.port;
			}

			return '';
		}

		function pushResolvedTargets(targetGroups, output) {
			targetGroups.forEach(function (group) {
				group.forEach(function (target) {
					output.push(target);
				});
			});
		}

		async function runWithConcurrency(items, limit, worker) {
			let nextIndex = 0;
			const workerCount = Math.min(Math.max(Number(limit) || 1, 1), items.length);
			const runners = [];

			async function runNext() {
				while (nextIndex < items.length) {
					const currentIndex = nextIndex++;
					await worker(items[currentIndex], currentIndex);
				}
			}

			for (let i = 0; i < workerCount; i++) {
				runners.push(runNext());
			}

			await Promise.all(runners);
		}

		function normalizeBatchInputControl(control) {
			if (!control || control.tagName !== 'TEXTAREA') return;

			const rawValue = control.value;
			const nextValue = normalizeBatchInputValue(rawValue);

			if (nextValue === rawValue) return;

			const selectionStart = control.selectionStart ?? rawValue.length;
			const selectionEnd = control.selectionEnd ?? rawValue.length;
			const nextSelectionStart = normalizeBatchInputValue(rawValue.slice(0, selectionStart)).length;
			const nextSelectionEnd = normalizeBatchInputValue(rawValue.slice(0, selectionEnd)).length;

			control.value = nextValue;
			control.setSelectionRange(nextSelectionStart, nextSelectionEnd);
		}

		function bindInputShortcut() {
			inputList.addEventListener('input', function () {
				if (!batchMode.checked) return;
				normalizeBatchInputControl(inputList);
			});

			inputList.addEventListener('keydown', function (event) {
				const shouldRunSingle = !batchMode.checked && event.key === 'Enter';
				const shouldRunBatch = batchMode.checked && event.key === 'Enter' && (event.ctrlKey || event.metaKey);

				if (shouldRunSingle || shouldRunBatch) {
					event.preventDefault();
					checkBtn.click();
				}
			});
		}

		function setModeVisuals(isBatch) {
			modeLabel.innerText = isBatch ? 'Batch / 多目标' : 'Single / 单目标';
			fieldHint.innerText = isBatch
				? '批量模式下每行一个目标，按 Ctrl + Enter 可以直接开始检测。'
				: '单条模式支持历史快速回填，按 Enter 可以直接开始检测。';
		}

		function showEmptyState(title, description) {
			emptyStateTitle.innerText = title;
			emptyStateDescription.innerText = description;
			resultsEmpty.style.display = 'grid';
		}

		function hideEmptyState() {
			resultsEmpty.style.display = 'none';
		}

		function setAppState(nextState) {
			appState = nextState;
			renderDashboard();
		}

		function renderDashboard() {
			const failCount = Math.max(completedCount - successCount, 0);
			const pendingCount = Math.max(totalTargets - completedCount, 0);

			statTotal.innerText = String(totalTargets);
			statSuccess.innerText = String(successCount);
			statPending.innerText = String(pendingCount);
			statFailed.innerText = String(failCount);

			let headline = '等待输入';
			let description = '当前阶段、实时统计。';
			let meta = '结果、落地 IP 和地图会在这里按检测进度逐步展开。';
			let pillText = 'Idle';

			if (appState === 'resolving') {
				headline = '正在解析目标';
				description = '已接收 ' + inputCount + ' 条输入，正在展开为可检测地址。';
				meta = '解析阶段进行中，准备把输入转换为候选目标。';
				pillText = 'Resolving';
			} else if (appState === 'running') {
				headline = '正在检测 ' + totalTargets + ' 个目标';
				description = '已完成 ' + completedCount + ' 个，当前有效 ' + successCount + ' 个。';
				meta = completedCount + ' / ' + totalTargets + ' 已完成，结果会持续追加。';
				pillText = 'Running';
			} else if (appState === 'done') {
				headline = '检测完成';
				description = '有效 ' + successCount + ' / ' + totalTargets + '，失败 ' + failCount + '。';
				meta = '本轮检测已结束，点击落地 IP 可展开地图详情。';
				pillText = 'Completed';
			} else if (appState === 'empty') {
				headline = '未解析到可检测目标';
				description = '请检查域名、IP 或端口格式后重新尝试。';
				meta = '这次输入没有得到有效候选目标。';
				pillText = 'Empty';
			} else if (appState === 'error') {
				headline = '检测过程中出现错误';
				description = '请求被中断或远端接口异常，可以稍后再试。';
				meta = '运行中断，结果可能不完整。';
				pillText = 'Error';
			}

			summaryHeadline.innerText = headline;
			summaryDescription.innerText = description;
			resultMeta.innerText = meta;
			resultPill.innerText = pillText;
			resultPill.className = 'results-pill state-' + appState;
		}

		function updateProgress() {
			const percent = totalTargets > 0 ? Math.round((completedCount / totalTargets) * 100) : 0;
			progressBar.style.width = percent + '%';
			progressText.innerText = completedCount + ' / ' + totalTargets;
			renderDashboard();
		}

		function getHistory() {
			try {
				const parsed = JSON.parse(localStorage.getItem('cf_proxy_history') || '[]');
				return Array.isArray(parsed) ? parsed : [];
			} catch {
				return [];
			}
		}

		function saveHistory(value) {
			if (!value || value.includes('\\n')) return;
			let history = getHistory();
			history = history.filter(function (item) {
				return item !== value;
			});
			history.unshift(value);
			history = history.slice(0, 10);
			localStorage.setItem('cf_proxy_history', JSON.stringify(history));
			renderHistory();
		}

		function selectHistory(value) {
			inputList.value = value;
			historyDropdown.style.display = 'none';
			inputList.focus();
		}

		function renderHistory() {
			const history = getHistory();
			historyDropdown.innerHTML = '';

			if (!history.length) {
				const emptyItem = document.createElement('button');
				emptyItem.type = 'button';
				emptyItem.className = 'history-item is-empty';
				emptyItem.innerText = '暂无历史记录';
				historyDropdown.appendChild(emptyItem);
				return;
			}

			history.forEach(function (item) {
				const button = document.createElement('button');
				button.type = 'button';
				button.className = 'history-item';
				button.innerText = item;
				button.addEventListener('click', function () {
					selectHistory(item);
				});
				historyDropdown.appendChild(button);
			});
		}

		function createInputControl(isBatch, value) {
			let control;

			if (isBatch) {
				control = document.createElement('textarea');
				control.placeholder = '每行一个目标，例如：\\n8.223.63.150\\n[2606:4700::]:443\\nProxyIP.CMLiussss.net';
			} else {
				control = document.createElement('input');
				control.type = 'text';
				control.placeholder = '例如：ProxyIP.CMLiussss.net 或 8.223.63.150:443';
			}

			control.id = 'inputList';
			control.className = 'input-control';
			control.value = isBatch ? normalizeBatchInputValue(value || '') : (value || '');
			return control;
		}

		function swapInputMode(isBatch) {
			const currentValue = inputList.value;
			const nextValue = isBatch ? currentValue : currentValue.split('\\n')[0];
			const nextControl = createInputControl(isBatch, nextValue);

			inputContainer.innerHTML = '';
			inputContainer.appendChild(nextControl);

			if (!isBatch) {
				inputContainer.appendChild(historyBtn);
				inputContainer.appendChild(historyDropdown);
			}

			inputList = nextControl;
			historyDropdown.style.display = 'none';
			setModeVisuals(isBatch);
			bindInputShortcut();
		}

		function formatLatency(value) {
			if (value === undefined || value === null || value === '') {
				return '延迟未知';
			}
			const text = String(value);
			return text.includes('ms') ? text : text + ' ms';
		}

		function joinUniqueValues(values, fallback) {
			const uniqueValues = Array.from(new Set(values.filter(Boolean)));
			return uniqueValues.length ? uniqueValues.join(' / ') : fallback;
		}

		function formatExitLocation(exitData) {
			const country = String(exitData?.country || '').trim();
			const city = String(exitData?.city || '').trim();
			return [country, city].filter(Boolean).join(' · ');
		}

		function formatExitNetwork(exitData) {
			const asn = String(exitData?.asn || '').trim();
			const organization = String(exitData?.asOrganization || '').trim();

			if (asn && organization) {
				return 'AS' + asn + ' · ' + organization;
			}

			if (asn) {
				return 'AS' + asn;
			}

			return organization;
		}

		function getExitCountryCode(exitData) {
			const candidates = [
				exitData?.countryCode,
				exitData?.country_code,
				exitData?.countryIsoCode,
				exitData?.country_iso_code,
				exitData?.country
			];

			for (const candidate of candidates) {
				const normalized = String(candidate || '').trim().toLowerCase();
				if (/^[a-z]{2}$/.test(normalized)) {
					return normalized;
				}
			}

			return '';
		}

		function getFlagUrlFromExitIps(exitIps) {
			for (const entry of exitIps) {
				const countryCode = getExitCountryCode(entry.exitData);
				if (countryCode) {
					return 'https://ipdata.co/flags/' + countryCode + '.png';
				}
			}

			return '';
		}

		function updateResultFlag(itemObj, flagUrl) {
			if (!itemObj?.flag) return;

			if (flagUrl) {
				itemObj.el.classList.add('has-flag');
				itemObj.flag.style.backgroundImage = 'url("' + flagUrl + '")';
				return;
			}

			itemObj.el.classList.remove('has-flag');
			itemObj.flag.style.backgroundImage = '';
		}

		function getExitSelectionKey(exitData, fallbackIp) {
			return [
				String(exitData?.ip || fallbackIp || '').trim(),
				String(exitData?.ipType || '').trim().toLowerCase(),
				normalizeColoCode(exitData?.colo),
				String(exitData?.loc || '').trim()
			].join('|');
		}

		function renderExitList(container, exitIps) {
			container.innerHTML = '';

			if (!exitIps.length) {
				const note = document.createElement('span');
				note.className = 'result-detail is-compact';
				note.innerText = '暂无可展示的出口详情';
				container.appendChild(note);
				return;
			}

			const label = document.createElement('span');
			label.className = 'exit-list-label';
			label.innerText = '落地 IP';
			container.appendChild(label);

			exitIps.forEach(function (entry) {
				const button = document.createElement('button');
				button.type = 'button';
				button.className = 'exit-ip-btn';
				button.innerText = entry.ip;
				button.dataset.exitKey = getExitSelectionKey(entry.exitData, entry.ip);
				button.addEventListener('click', function () {
					showDetails(button, entry.exitData);
				});
				container.appendChild(button);
			});
		}

		function addResultItem(ip) {
			hideEmptyState();
			const div = document.createElement('div');
			div.className = 'result-item';
			div.innerHTML =
				'<div class="result-flag-overlay" aria-hidden="true"></div>' +
				'<div class="result-top">' +
					'<div class="result-info">' +
						'<span class="result-label">候选目标</span>' +
						'<span class="result-ip">' + escapeHtml(ip) + '</span>' +
						'<span class="result-detail">已加入检测队列，正在等待返回结果。</span>' +
					'</div>' +
					'<span class="status-badge status-pending">等待中</span>' +
				'</div>' +
				'<div class="result-meta">' +
					buildMetaChip('准备建立检测请求', 'prep') +
				'</div>' +
				'<div class="exit-list"></div>' +
				'<div class="map-container-wrapper"></div>';

			resultsDiv.appendChild(div);

			return {
				el: div,
				flag: div.querySelector('.result-flag-overlay'),
				info: div.querySelector('.result-info'),
				badge: div.querySelector('.status-badge'),
				meta: div.querySelector('.result-meta'),
				exitList: div.querySelector('.exit-list'),
				mapContainer: div.querySelector('.map-container-wrapper')
			};
		}

		async function checkIP(target) {
			const itemObj = addResultItem(target);

			try {
				const response = await fetch('https://api.090227.xyz/check?proxyip=' + encodeURIComponent(target));
				const data = await response.json();
				completedCount++;

				if (data.success) {
					successCount++;
					itemObj.el.className = 'result-item success';
					const latency = formatLatency(data.responseTime);
					itemObj.badge.className = 'status-badge status-success';
					itemObj.badge.innerText = latency;

					const exitIps = [];
					if (data.probe_results?.ipv4?.ok && data.probe_results.ipv4.exit) {
						exitIps.push({ ip: data.probe_results.ipv4.exit.ip, exitData: data.probe_results.ipv4.exit });
					}
					if (data.probe_results?.ipv6?.ok && data.probe_results.ipv6.exit) {
						exitIps.push({ ip: data.probe_results.ipv6.exit.ip, exitData: data.probe_results.ipv6.exit });
					}

					const locations = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitLocation(entry.exitData);
					}), '地区未知');
					const networks = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitNetwork(entry.exitData);
					}), 'ASN / 运营商未知');
					const flagUrl = getFlagUrlFromExitIps(exitIps);

					updateResultFlag(itemObj, flagUrl);

					itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						'<span class="result-ip">' + escapeHtml(data.candidate || target) + '</span>' +
						'<span class="result-detail">代理验证通过，可继续查看出口位置、网络信息和地图分布。</span>';

					const metaParts = [
						buildMetaChip(locations, 'location'),
						buildMetaChip(networks, 'network'),
						buildMetaChip(exitIps.length + '个出口', 'exits')
					];
					itemObj.meta.innerHTML = metaParts.join('');

					renderExitList(itemObj.exitList, exitIps);
				} else {
					itemObj.el.className = 'result-item error';
					updateResultFlag(itemObj, '');
					itemObj.badge.className = 'status-badge status-error';
					itemObj.badge.innerText = '不可用';
					itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						'<span class="result-ip">' + escapeHtml(target) + '</span>' +
						'<span class="result-detail">无法通过该代理访问 Cloudflare，请更换目标后重试。</span>';
					itemObj.meta.innerHTML =
						buildMetaChip('检测未通过', 'error', 'meta-chip-danger') +
						buildMetaChip(data.message || '远端返回失败结果', 'info');
					itemObj.exitList.innerHTML = '';
				}
			} catch (error) {
				completedCount++;
				itemObj.el.className = 'result-item error';
				updateResultFlag(itemObj, '');
				itemObj.badge.className = 'status-badge status-error';
				itemObj.badge.innerText = '失败';
				itemObj.info.innerHTML =
					'<span class="result-label">候选目标</span>' +
					'<span class="result-ip">' + escapeHtml(target) + '</span>' +
					'<span class="result-detail">检测请求执行失败，可能是接口异常或网络中断。</span>';
				itemObj.meta.innerHTML =
					buildMetaChip('请求异常', 'error', 'meta-chip-danger') +
					buildMetaChip('请稍后重试', 'retry');
				itemObj.exitList.innerHTML = '';
			}

			updateProgress();
		}

		async function showDetails(button, exitData) {
			const item = button.closest('.result-item');
			const container = item.querySelector('.map-container-wrapper');
			const isOpen = container.style.display === 'block';
			const nextSelectionKey = button.dataset.exitKey || getExitSelectionKey(exitData);
			const isSameSelection = isOpen && container.dataset.activeExitKey === nextSelectionKey;
			const currentToken = ++mapRenderToken;

			document.querySelectorAll('.map-container-wrapper').forEach(function (panel) {
				if (panel !== container) {
					panel.style.display = 'none';
					panel.dataset.activeExitKey = '';
				}
			});
			document.querySelectorAll('.exit-ip-btn.is-active').forEach(function (activeButton) {
				activeButton.classList.remove('is-active');
			});

			if (isSameSelection) {
				container.style.display = 'none';
				container.dataset.activeExitKey = '';
				return;
			}

			container.dataset.activeExitKey = nextSelectionKey;
			button.classList.add('is-active');
			initMap();
			container.appendChild(globalMap);
			container.style.display = 'block';

			setTimeout(async function () {
				if (currentToken !== mapRenderToken || container.style.display !== 'block') {
					return;
				}

				map.invalidateSize();

				const exitLocation = parseCoordinatePair(exitData?.loc);
				await loadCfLocations();
				if (currentToken !== mapRenderToken || container.style.display !== 'block') {
					return;
				}

				const cfLocation = getCfLocation(exitData?.colo);
				const cfCoordinates = cfLocation ? [cfLocation.lat, cfLocation.lon] : null;
				const hasExitLocation = isValidCoordinatePair(exitLocation);
				const hasCfLocation = isValidCoordinatePair(cfCoordinates);

				clearMapLayers();

				if (hasExitLocation) {
					const exitMarker = L.circleMarker(exitLocation, {
						radius: 8,
						weight: 2,
						color: '#34d399',
						fillColor: '#34d399',
						fillOpacity: 0.3
					}).addTo(map);
					exitMarker.bindPopup(createExitPopup(exitData));
					mapLayers.push(exitMarker);
				}

				if (hasCfLocation) {
					const cfMarker = L.circleMarker(cfCoordinates, {
						radius: 8,
						weight: 2,
						color: '#61dbff',
						fillColor: '#61dbff',
						fillOpacity: 0.28
					}).addTo(map);
					cfMarker.bindPopup(createCfPopup(cfLocation));
					mapLayers.push(cfMarker);
				}

				if (hasExitLocation && hasCfLocation) {
					const transitLine = L.polyline([exitLocation, cfCoordinates], {
						color: '#8be9ff',
						weight: 2,
						opacity: 0.85,
						dashArray: '8 6',
						renderer: mapSvgRenderer
					}).addTo(map);
					mapLayers.push(transitLine);
					applyArrowStyleToPolyline(transitLine);
					map.fitBounds([exitLocation, cfCoordinates], {
						padding: [36, 36],
						maxZoom: 6
					});
					return;
				}

				if (hasExitLocation) {
					map.setView(exitLocation, 6);
					return;
				}

				if (hasCfLocation) {
					map.setView(cfCoordinates, 5);
					return;
				}

				map.setView([20, 0], 2);
			}, 100);
		}

		batchMode.addEventListener('change', function () {
			swapInputMode(batchMode.checked);
		});

		historyBtn.addEventListener('click', function (event) {
			event.stopPropagation();
			const isVisible = historyDropdown.style.display === 'block';
			historyDropdown.style.display = isVisible ? 'none' : 'block';
		});

		document.addEventListener('click', function (event) {
			if (!inputContainer.contains(event.target)) {
				historyDropdown.style.display = 'none';
			}
		});

		if (themeToggle) {
			themeToggle.addEventListener('click', function () {
				const currentTheme = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
				const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
				try {
					localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
				} catch (error) {
					console.warn('Failed to persist theme preference', error);
				}
				applyTheme(nextTheme, 'stored');
			});
		}

		if (systemThemeQuery.addEventListener) {
			systemThemeQuery.addEventListener('change', function (event) {
				if (getStoredTheme()) return;
				applyTheme(event.matches ? 'dark' : 'light', 'system');
			});
		} else if (systemThemeQuery.addListener) {
			systemThemeQuery.addListener(function (event) {
				if (getStoredTheme()) return;
				applyTheme(event.matches ? 'dark' : 'light', 'system');
			});
		}

		checkBtn.addEventListener('click', async function () {
			const value = batchMode.checked ? normalizeBatchInputValue(inputList.value) : stripTargetLabel(inputList.value);
			if (!value) return;

			const lines = batchMode.checked
				? normalizeBatchInputValue(value).split('\\n').map(function (line) { return line.trim(); }).filter(Boolean)
				: [value];

			inputList.value = batchMode.checked ? lines.join('\\n') : value;

			if (!batchMode.checked) {
				saveHistory(value);
			}

			resultsDiv.innerHTML = '';
			progressBar.style.width = '0%';
			progressText.innerText = '正在解析目标...';
			showEmptyState('正在准备检测', '正在解析你输入的目标，请稍候。');

			completedCount = 0;
			successCount = 0;
			totalTargets = 0;
			inputCount = lines.length;

			checkBtn.disabled = true;
			setAppState('resolving');

			try {
				const resolveJobs = [];
				const targetGroups = lines.map(function (line) {
					const directTarget = batchMode.checked ? getDirectIpTarget(line) : '';
					if (directTarget) {
						return [directTarget];
					}

					const group = [];
					resolveJobs.push({ line, group });
					return group;
				});

				for (const job of resolveJobs) {
					try {
						const response = await fetch('/resolve?proxyip=' + encodeURIComponent(job.line));
						const targets = await response.json();
						if (Array.isArray(targets)) {
							job.group.push(...targets);
						}
					} catch (error) {
						console.error('Resolve error for', job.line, error);
					}
				}

				const allResolvedTargets = [];
				pushResolvedTargets(targetGroups, allResolvedTargets);

				if (allResolvedTargets.length > 0) {
					totalTargets = allResolvedTargets.length;
					setAppState('running');
					updateProgress();

					await runWithConcurrency(allResolvedTargets, CHECK_CONCURRENCY, function (target) {
						return checkIP(target);
					});

					const failCount = Math.max(totalTargets - successCount, 0);
					progressText.innerText = '总计 ' + totalTargets + ' · 有效 ' + successCount + ' · 失败 ' + failCount;
					setAppState('done');
				} else {
					progressText.innerText = '未解析到目标';
					showEmptyState('没有可检测的候选目标', '请检查输入格式，或确认域名是否存在 A / AAAA 记录。');
					setAppState('empty');
				}
			} catch (error) {
				console.error(error);
				progressText.innerText = '系统错误';
				showEmptyState('检测流程中断', '请求过程中发生异常，请稍后重试。');
				setAppState('error');
			} finally {
				checkBtn.disabled = false;
			}
		});

		window.onload = function () {
			renderHistory();
			setModeVisuals(false);
			bindInputShortcut();
			renderDashboard();
			loadCfLocations();
			fetchVisitCount();

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

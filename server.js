const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3737;
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
const { version } = require('./package.json');

const AUTH_USERNAME = process.env.AUTH_USERNAME;
const AUTH_PASSWORD = process.env.AUTH_PASSWORD;
const authEnabled = !!(AUTH_USERNAME && AUTH_PASSWORD);

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'nginx-ctl-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 8 * 60 * 60 * 1000 }, // 8h
}));

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!authEnabled) return next();
  if (req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

app.get('/login', (req, res) => {
  if (!authEnabled || req.session.authenticated) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!authEnabled) return res.json({ ok: true });
  if (username === AUTH_USERNAME && password === AUTH_PASSWORD) {
    req.session.authenticated = true;
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/status', (req, res) => {
  res.json({ authEnabled });
});

app.use(express.static(path.join(__dirname, 'public'), {
  index: false, // don't serve index.html automatically
}));

// Protect index.html and all API routes
app.use(requireAuth);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Settings ──────────────────────────────────────────────────────────────────

function loadSettings() {
  if (fs.existsSync(SETTINGS_FILE)) {
    try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch {}
  }
  return { confDir: path.join(__dirname, 'conf.d') };
}

function confDir() {
  return loadSettings().confDir;
}

app.get('/api/version', (req, res) => {
  res.json({ version });
});

app.get('/api/settings', (req, res) => {
  res.json(loadSettings());
});

app.put('/api/settings', (req, res) => {
  try {
    const current = loadSettings();
    const updated = { ...current, ...req.body };
    if (!updated.confDir) return res.status(400).json({ error: 'confDir is required' });
    if (!fs.existsSync(updated.confDir)) return res.status(400).json({ error: 'Directory does not exist' });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(updated, null, 2));
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Parser ────────────────────────────────────────────────────────────────────

function parseConf(content, filename) {
  const site = {
    filename,
    enabled: !filename.endsWith('.disabled') && !filename.endsWith('.deleted'),
    deleted: filename.endsWith('.deleted'),
    name: filename.replace(/\.conf(\.disabled|\.deleted)?$/, ''),
    listen: null,
    serverName: null,
    proxyPass: null,
    sslCertDomain: null,
    swaggerProtection: false,
    type: 'proxy', // proxy | redirect
  };

  const listenMatch = content.match(/listen\s+(\d+(?:\s+ssl)?)/);
  if (listenMatch) site.listen = listenMatch[1].trim();

  const serverNameMatch = content.match(/server_name\s+([^;]+);/);
  if (serverNameMatch) site.serverName = serverNameMatch[1].trim();

  const certMatch = content.match(/ssl_certificate\s+\/etc\/letsencrypt\/live\/([^/]+)\//);
  if (certMatch) site.sslCertDomain = certMatch[1];

  const rootLocationMatch = content.match(/location\s+\/\s*\{([^}]+)\}/s);
  if (rootLocationMatch) {
    const proxyMatch = rootLocationMatch[1].match(/proxy_pass\s+([^;]+);/);
    if (proxyMatch) site.proxyPass = proxyMatch[1].trim();
    if (rootLocationMatch[1].match(/return\s+/)) site.type = 'redirect';
  }

  if (site.type !== 'redirect' && site.proxyPass) site.type = 'proxy';

  if (content.includes('location /v3/api-docs') && content.includes('auth_basic')) {
    site.swaggerProtection = true;
  }

  site.hasForwardingHeaders = content.includes('X-Forwarded-Proto');

  return site;
}

function generateConf(data) {
  const { serverName, proxyPass, sslCertDomain, swaggerProtection, hasForwardingHeaders, listen } = data;
  const certDomain = sslCertDomain || serverName;
  const port = listen || '443 ssl';

  const forwardHeaders = hasForwardingHeaders
    ? `        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Port $server_port;`
    : '';

  const swaggerBlock = swaggerProtection
    ? `
    location /v3/api-docs {
        auth_basic "Swagger Restricted";
        auth_basic_user_file /etc/nginx/auth/.htpasswd;

        proxy_pass ${proxyPass};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
${forwardHeaders ? forwardHeaders + '\n' : ''}    }
`
    : '';

  return `server {
    listen ${port};
    server_name ${serverName};

    ssl_certificate /etc/letsencrypt/live/${certDomain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${certDomain}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
${swaggerBlock}
    location / {
        proxy_pass ${proxyPass};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
${forwardHeaders ? forwardHeaders + '\n' : ''}    }
}
`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getAllFiles() {
  return fs.readdirSync(confDir()).filter(f =>
    f.endsWith('.conf') || f.endsWith('.conf.disabled') || f.endsWith('.conf.deleted')
  );
}

function getActiveFiles() {
  return fs.readdirSync(confDir()).filter(f =>
    f.endsWith('.conf') || f.endsWith('.conf.disabled')
  );
}

function getDeletedFiles() {
  return fs.readdirSync(confDir()).filter(f => f.endsWith('.conf.deleted'));
}

function readSite(filename) {
  const content = fs.readFileSync(path.join(confDir(), filename), 'utf8');
  return parseConf(content, filename);
}

// ── API ───────────────────────────────────────────────────────────────────────

app.get('/api/sites', (req, res) => {
  try {
    res.json(getActiveFiles().map(f => readSite(f)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sites/raw', (req, res) => {
  try {
    const { filename, content } = req.body;
    if (!filename || content === undefined) {
      return res.status(400).json({ error: 'filename and content are required' });
    }
    if (!filename.endsWith('.conf')) {
      return res.status(400).json({ error: 'filename must end with .conf' });
    }
    const filepath = path.join(confDir(), filename);
    if (fs.existsSync(filepath)) {
      return res.status(409).json({ error: 'File already exists' });
    }
    fs.writeFileSync(filepath, content);
    res.status(201).json({ filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/sites/:name/raw', (req, res) => {
  try {
    const filename = getAllFiles().find(f => f.replace(/\.conf(\.disabled|\.deleted)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    const { content } = req.body;
    if (content === undefined) return res.status(400).json({ error: 'content is required' });
    fs.writeFileSync(path.join(confDir(), filename), content);
    res.json({ filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sites/:name/raw', (req, res) => {
  try {
    const filename = getAllFiles().find(f => f.replace(/\.conf(\.disabled|\.deleted)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    const content = fs.readFileSync(path.join(confDir(), filename), 'utf8');
    res.json({ filename, content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sites/:name', (req, res) => {
  try {
    const filename = getActiveFiles().find(f => f.replace(/\.conf(\.disabled)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    res.json(readSite(filename));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sites', (req, res) => {
  try {
    const { name, serverName, proxyPass, sslCertDomain, swaggerProtection, hasForwardingHeaders } = req.body;
    if (!name || !serverName || !proxyPass) {
      return res.status(400).json({ error: 'name, serverName and proxyPass are required' });
    }
    const filename = `${name}.conf`;
    const filepath = path.join(confDir(), filename);
    if (fs.existsSync(filepath) || fs.existsSync(filepath + '.disabled')) {
      return res.status(409).json({ error: 'Site already exists' });
    }
    const content = generateConf({ serverName, proxyPass, sslCertDomain, swaggerProtection, hasForwardingHeaders });
    fs.writeFileSync(filepath, content);
    res.status(201).json(readSite(filename));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/sites/:name', (req, res) => {
  try {
    const filename = getActiveFiles().find(f => f.replace(/\.conf(\.disabled)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    const { serverName, proxyPass, sslCertDomain, swaggerProtection, hasForwardingHeaders } = req.body;
    const content = generateConf({ serverName, proxyPass, sslCertDomain, swaggerProtection, hasForwardingHeaders });
    fs.writeFileSync(path.join(confDir(), filename), content);
    res.json(readSite(filename));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Soft delete: rename to .conf.deleted (or .conf.disabled.deleted)
app.delete('/api/sites/:name', (req, res) => {
  try {
    const filename = getActiveFiles().find(f => f.replace(/\.conf(\.disabled)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    fs.renameSync(path.join(confDir(), filename), path.join(confDir(), filename + '.deleted'));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Toggle enabled/disabled
app.post('/api/sites/:name/toggle', (req, res) => {
  try {
    const filename = getActiveFiles().find(f => f.replace(/\.conf(\.disabled)?$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found' });
    const newFilename = filename.endsWith('.disabled')
      ? filename.replace('.conf.disabled', '.conf')
      : filename + '.disabled';
    fs.renameSync(path.join(confDir(), filename), path.join(confDir(), newFilename));
    res.json(readSite(newFilename));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List deleted sites
app.get('/api/deleted', (req, res) => {
  try {
    res.json(getDeletedFiles().map(f => readSite(f)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Rollback: remove .deleted suffix to restore original state
app.post('/api/deleted/:name/rollback', (req, res) => {
  try {
    const filename = getDeletedFiles().find(f => f.replace(/\.conf(\.disabled)?\.deleted$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found in deleted' });
    const restored = filename.replace('.deleted', '');
    if (fs.existsSync(path.join(confDir(), restored))) {
      return res.status(409).json({ error: 'A site with that name already exists' });
    }
    fs.renameSync(path.join(confDir(), filename), path.join(confDir(), restored));
    res.json(readSite(restored));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Permanent delete
app.delete('/api/deleted/:name', (req, res) => {
  try {
    const filename = getDeletedFiles().find(f => f.replace(/\.conf(\.disabled)?\.deleted$/, '') === req.params.name);
    if (!filename) return res.status(404).json({ error: 'Not found in deleted' });
    fs.unlinkSync(path.join(confDir(), filename));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`nginx-tool running at http://localhost:${PORT}`);
});

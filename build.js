// 把前端 HTML 内联进 worker，输出单文件 dist/index.js
const fs = require('fs');
const path = require('path');
const dir = __dirname;
let worker = fs.readFileSync(path.join(dir, 'src/worker.js'), 'utf8');
let html = fs.readFileSync(path.join(dir, 'src/app.html'), 'utf8');
let agentPy = fs.readFileSync(path.join(dir, 'agent.py'), 'utf8');
let smtpJs = fs.readFileSync(path.join(dir, 'src/smtp.js'), 'utf8');
worker = worker.replace('//__SMTP_JS__', smtpJs);
worker = worker.replace('const APP_HTML = "__APP_HTML__";', 'const APP_HTML = ' + JSON.stringify(html) + ';');
worker = worker.replace('"__AGENT_PY__"', JSON.stringify(agentPy));
fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
fs.writeFileSync(path.join(dir, 'dist/index.js'), worker);
console.log('built dist/index.js', Buffer.byteLength(worker), 'bytes');

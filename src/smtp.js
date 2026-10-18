// SMTP 客户端（基于 cloudflare:sockets，需 Workers 付费版）
// 改编自 https://github.com/Bruol/cloudflare-smtp
const _smtpEncoder = new TextEncoder();
const _smtpDecoder = new TextDecoder();

function _smtpEncodeHeader(value) {
  if (/^[\x00-\x7F]*$/.test(value)) return value;
  const bytes = _smtpEncoder.encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `=?UTF-8?B?${btoa(binary)}?=`;
}
function _smtpToBase64(value) {
  const bytes = _smtpEncoder.encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function _smtpSanitize(v) { return String(v).replace(/[\r\n]+/g, ' ').trim(); }

class _SmtpSession {
  constructor(socket) {
    this.socket = socket;
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
    this.buffer = '';
  }
  async readResponse(expected) {
    while (true) {
      const { value, done } = await this.reader.read();
      if (done) throw new Error('SMTP closed');
      this.buffer += _smtpDecoder.decode(value, { stream: true });
      if (!this.buffer.endsWith('\r\n')) continue;
      const lines = this.buffer.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1];
      const m = last && last.match(/^(\d{3})\s/);
      if (!m) continue;
      const code = Number(m[1]);
      const resp = this.buffer.trimEnd();
      this.buffer = '';
      if (!expected.includes(code)) throw new Error(`SMTP ${code}: ${resp}`);
      return resp;
    }
  }
  async cmd(c, expected) {
    await this.writer.write(_smtpEncoder.encode(`${c}\r\n`));
    return this.readResponse(expected);
  }
  async startTls() {
    this.reader.releaseLock(); this.writer.releaseLock();
    this.socket = this.socket.startTls();
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    this.buffer = '';
  }
  async close() {
    try { await this.cmd('QUIT', [221]); } catch (e) {}
    try { this.reader.releaseLock(); } catch (e) {}
    try { this.writer.releaseLock(); } catch (e) {}
    try { this.socket.close(); } catch (e) {}
  }
}

async function sendSmtpMail(cfg, subject, text) {
  const { connect } = await import('cloudflare:sockets');
  const port = cfg.port || (cfg.secure === 'tls' ? 465 : 587);
  let sockSecure = 'off';
  if (cfg.secure === 'tls' || port === 465) sockSecure = 'on';
  else if (cfg.secure === 'starttls' || port === 587) sockSecure = 'starttls';
  const session = new _SmtpSession(connect({ hostname: cfg.host, port }, { secureTransport: sockSecure }));
  const from = cfg.from.trim();
  const toList = (Array.isArray(cfg.to) ? cfg.to : [cfg.to]).map(s => s.trim()).filter(Boolean);
  try {
    await session.readResponse([220]);
    await session.cmd(`EHLO ${cfg.helo || 'probe.local'}`, [250]);
    if (sockSecure === 'starttls') {
      await session.cmd('STARTTLS', [220]);
      await session.startTls();
      await session.cmd(`EHLO ${cfg.helo || 'probe.local'}`, [250]);
    }
    await session.cmd('AUTH LOGIN', [334]);
    await session.cmd(_smtpToBase64(cfg.username), [334]);
    await session.cmd(_smtpToBase64(cfg.password), [235]);
    await session.cmd(`MAIL FROM:<${from}>`, [250]);
    for (const rcpt of toList) await session.cmd(`RCPT TO:<${rcpt}>`, [250, 251]);
    await session.cmd('DATA', [354]);
    const msgId = `<${crypto.randomUUID()}@${cfg.host}>`;
    const headers = [
      `From: ${from}`, `To: ${toList.join(', ')}`,
      `Subject: ${_smtpEncodeHeader(_smtpSanitize(subject))}`,
      `Date: ${new Date().toUTCString()}`, `Message-ID: ${msgId}`,
      'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: 8bit'
    ];
    const body = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n\./g, '\n..');
    await session.writer.write(_smtpEncoder.encode(`${headers.join('\r\n')}\r\n\r\n${body}\r\n.\r\n`));
    await session.readResponse([250]);
  } finally {
    await session.close();
  }
}

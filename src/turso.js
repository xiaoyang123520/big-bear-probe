// Turso 兼容层：模拟 Cloudflare D1 的 API
// 用法：const db = createTursoDB(TURSO_URL, TURSO_TOKEN);
// 然后 db.prepare(sql).bind(...).all()/first()/run() 和 D1 一样用

function tursoArgs(args) {
  // D1 bind 参数转 Turso 格式
  return args.map(v => {
    if (v === null || v === undefined) return { type: "null" };
    if (typeof v === "number") {
      return Number.isInteger(v) ? { type: "integer", value: String(v) } : { type: "float", value: v };
    }
    return { type: "text", value: String(v) };
  });
}

function rowsToObjects(cols, rows) {
  // Turso 返回 rows 是数组套数组，转成 D1 风格的对象数组
  const names = cols.map(c => c.name);
  return (rows || []).map(r => {
    const obj = {};
    for (let i = 0; i < names.length; i++) {
      const v = r[i];
      if (v && typeof v === "object" && "value" in v) {
        // 按类型转换：integer 转数字，避免字符串 "0" 被当成 truthy
        if (v.type === "integer" && v.value !== null) {
          obj[names[i]] = parseInt(v.value, 10);
        } else if (v.type === "float" && v.value !== null) {
          obj[names[i]] = parseFloat(v.value);
        } else {
          obj[names[i]] = v.value;
        }
      } else {
        obj[names[i]] = v;
      }
    }
    return obj;
  });
}

export function createTursoDB(url, token) {
  // url 格式：https://xxx.turso.io 或 libsql://xxx.turso.io
  const httpUrl = url.replace(/^libsql:\/\//, "https://").replace(/\/$/, "") + "/v2/pipeline";

  async function execute(sql, args) {
    const resp = await fetch(httpUrl, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        requests: [
          { type: "execute", stmt: { sql, args: tursoArgs(args) } },
          { type: "close" },
        ],
      }),
    });
    if (!resp.ok) {
      const t = await resp.text();
      throw new Error(`Turso HTTP ${resp.status}: ${t.slice(0, 200)}`);
    }
    const data = await resp.json();
    const result = data.results?.[0]?.response?.result;
    if (!result) throw new Error("Turso 返回格式异常");
    return result;
  }

  return {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async all() {
              const r = await execute(sql, args);
              return { results: rowsToObjects(r.cols || [], r.rows || []) };
            },
            async first() {
              const r = await execute(sql, args);
              const rows = rowsToObjects(r.cols || [], r.rows || []);
              return rows[0] || null;
            },
            async run() {
              const r = await execute(sql, args);
              return {
                success: true,
                meta: {
                  rows_read: r.rows_read,
                  rows_written: r.rows_written,
                  last_row_id: r.last_insert_rowid ? parseInt(r.last_insert_rowid) : undefined,
                },
              };
            },
          };
        },
        // 不带 bind 参数的直接调用
        async all() {
          const r = await execute(sql, []);
          return { results: rowsToObjects(r.cols || [], r.rows || []) };
        },
        async first() {
          const r = await execute(sql, []);
          const rows = rowsToObjects(r.cols || [], r.rows || []);
          return rows[0] || null;
        },
        async run() {
          const r = await execute(sql, []);
          return { success: true, meta: { rows_read: r.rows_read, rows_written: r.rows_written, last_row_id: r.last_insert_rowid ? parseInt(r.last_insert_rowid) : undefined } };
        },
      };
    },
    // 批量执行（迁移用）
    async batch(statements) {
      const requests = statements.map(s => ({
        type: "execute",
        stmt: typeof s === "string" ? { sql: s } : { sql: s.sql, args: tursoArgs(s.args || []) },
      }));
      requests.push({ type: "close" });
      const resp = await fetch(httpUrl, {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ requests }),
      });
      if (!resp.ok) throw new Error(`Turso batch HTTP ${resp.status}`);
      return await resp.json();
    },
  };
}

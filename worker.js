// ============================================================
//  上海克利工作室 - 官网 + 决案档案库 + 管理员登录
//  Cloudflare Worker 单文件部署
//  环境变量（Settings → Variables and Secrets）：
//    ADMIN_PASSWORD     管理员密码（必需）
//    DINGTALK_WEBHOOK   钉钉 webhook（加入申请必需）
//  Cloudflare Cron Trigger: 0 0 1 1,4,7,10 * (quarterly at 00:00 UTC)
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
    if (url.protocol === "http:" && url.hostname !== "localhost") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    if (url.pathname !== "/" && url.pathname.endsWith("/")) {
      url.pathname = url.pathname.slice(0, -1);
      return Response.redirect(url.toString(), 308);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: securityHeaders(false) });
    }

    // ================= 管理员登录 =================
    if (request.method === "POST" && url.pathname === "/api/login") {
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);
      try {
        const { password, turnstileToken } = await request.json();
        if (!env.ADMIN_PASSWORD) {
          return json({ success: false, message: "服务器未配置管理员密码" }, 500);
        }
        if (!env.TURNSTILE_SECRET) {
          return json({ success: false, message: "服务器未配置 Turnstile 密钥" }, 500);
        }
        if (!await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET, request.headers.get("CF-Connecting-IP"))) {
          return json({ success: false, message: "请完成人机验证" }, 400);
        }
        if (typeof password !== 'string' || !password) {
          return json({ success: false, message: "请输入密码" }, 400);
        }
        if (password === env.ADMIN_PASSWORD) {
          const session = await createSession(env.ADMIN_PASSWORD);
          return json(
            { success: true },
            200,
            {
              "Set-Cookie": `admin_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
            }
          );
        }
        return json({ success: false, message: "密码错误" }, 401);
      } catch (e) {
        return json({ success: false, message: e.message }, 400);
      }
    }

    // ================= 校验登录态 =================
    if (request.method === "GET" && url.pathname === "/api/me") {
      if (!env.ADMIN_PASSWORD) return json({ authed: false });
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      return json({ authed: !!token && await verifySession(token, env.ADMIN_PASSWORD) });
    }

    // ================= 决案 D1 数据 =================
    if (url.pathname === "/api/docs") {
      if (!env.DB) return json({ success: false, message: "未绑定 D1 数据库 DB" }, 500);

      await ensureDocsTable(env.DB);
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);

      if (request.method === "GET") {
        try {
          const result = authed
            ? await env.DB.prepare("SELECT * FROM docs ORDER BY CAST(no AS INTEGER) ASC").all()
            : await env.DB.prepare("SELECT * FROM docs WHERE visibility = '公开' ORDER BY CAST(no AS INTEGER) ASC").all();
          const deleted = await env.DB.prepare("SELECT no FROM deleted_docs").all();
          return json({
            success: true,
            deleted_docs: (deleted.results || []).map(row => row.no),
            docs: (result.results || []).map(row => ({
              no: row.no,
              title: row.title,
              status: row.visibility === "保密" || row.status === "保密"
                ? "保密"
                : row.status === "已发布" ? "公开" : row.status,
              level: row.level,
              visibility: row.visibility,
              desc: row.description,
              sections: parseSections(row.sections_json)
            }))
          });
        } catch (error) {
          return json({ success: false, message: error.message }, 500);
        }
      }

      if (!authed) return json({ success: false, message: "需要管理员登录" }, 401);
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);

      if (request.method === "POST") {
        try {
          const data = await request.json();
          const doc = validateDocData(data);
          if (!doc) return json({ success: false, message: "决案编号、标题或必填字段无效" }, 400);
          await env.DB.prepare(
            "INSERT INTO docs (no, title, status, level, visibility, description, sections_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(doc.no, doc.title, doc.status, doc.level, doc.visibility, doc.desc, JSON.stringify(doc.sections), new Date().toISOString()).run();
          await env.DB.prepare("DELETE FROM deleted_docs WHERE no=?").bind(doc.no).run();
          return json({ success: true, doc });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "PUT") {
        try {
          const data = await request.json();
          const doc = validateDocData(data);
          if (!doc) return json({ success: false, message: "决案编号、标题或必填字段无效" }, 400);
          const updated = await env.DB.prepare(
            "UPDATE docs SET title=?, status=?, level=?, visibility=?, description=?, sections_json=?, updated_at=? WHERE no=?"
          ).bind(doc.title, doc.status, doc.level, doc.visibility, doc.desc, JSON.stringify(doc.sections), new Date().toISOString(), doc.no).run();
          if (!updated.meta.changes) {
            await env.DB.prepare(
              "INSERT INTO docs (no, title, status, level, visibility, description, sections_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(doc.no, doc.title, doc.status, doc.level, doc.visibility, doc.desc, JSON.stringify(doc.sections), new Date().toISOString()).run();
          }
          await env.DB.prepare("DELETE FROM deleted_docs WHERE no=?").bind(doc.no).run();
          return json({ success: true, doc });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "DELETE") {
        try {
          const data = await request.json();
          if (!data || typeof data.no !== "string" || !/^\d{3}$/.test(data.no)) {
            return json({ success: false, message: "决案编号无效" }, 400);
          }
          const result = await env.DB.prepare("DELETE FROM docs WHERE no=?").bind(data.no).run();
          await env.DB.prepare(
            "INSERT OR IGNORE INTO deleted_docs (no, deleted_at) VALUES (?, ?)"
          ).bind(data.no, new Date().toISOString()).run();
          return json({ success: true });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }
    }

    // ================= 人员 D1 数据 =================
    if (url.pathname === "/api/people") {
      if (!env.DB) return json({ success: false, message: "未绑定 D1 数据库 DB" }, 500);
      await ensurePeopleTable(env.DB);
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);

      if (request.method === "GET") {
        try {
          const result = await env.DB.prepare(
            "SELECT p.developer_no, p.name, p.gender, p.department, p.rank, p.joined_at, p.left_at, p.rejoin_type, CASE WHEN ec.developer_no IS NULL THEN 0 ELSE 1 END AS is_candidate FROM people p LEFT JOIN ethics_candidates ec ON ec.developer_no=p.developer_no ORDER BY p.developer_no COLLATE NOCASE ASC"
          ).all();
          return json({ success: true, people: result.results || [] });
        } catch (error) {
          return json({ success: false, message: error.message }, 500);
        }
      }

      if (!authed) return json({ success: false, message: "需要管理员登录" }, 401);
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);

      if (request.method === "POST") {
        try {
          const person = validatePersonData(await request.json());
          if (!person) return json({ success: false, message: "人员信息无效或不完整" }, 400);
          await env.DB.prepare(
            "INSERT INTO people (developer_no, name, gender, department, rank, joined_at, left_at, rejoin_type, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(person.developer_no, person.name, person.gender, person.department, person.rank, person.joined_at, person.left_at, person.rejoin_type, new Date().toISOString()).run();
          return json({ success: true, person });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "PUT") {
        try {
          const person = validatePersonData(await request.json());
          if (!person) return json({ success: false, message: "人员信息无效或不完整" }, 400);
          const result = await env.DB.prepare(
            "UPDATE people SET name=?, gender=?, department=?, rank=?, joined_at=?, left_at=?, rejoin_type=?, updated_at=? WHERE developer_no=?"
          ).bind(person.name, person.gender, person.department, person.rank, person.joined_at, person.left_at, person.rejoin_type, new Date().toISOString(), person.developer_no).run();
          if (!result.meta.changes) return json({ success: false, message: "该开发者编号不存在" }, 404);
          if (person.left_at) {
            await env.DB.prepare("DELETE FROM ethics_candidates WHERE developer_no=?").bind(person.developer_no).run();
          }
          return json({ success: true, person });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "DELETE") {
        try {
          const data = await request.json();
          if (!data || typeof data.developer_no !== "string" || !data.developer_no.trim() || data.developer_no.length > 50) {
            return json({ success: false, message: "开发者编号无效" }, 400);
          }
          const result = await env.DB.prepare("DELETE FROM people WHERE developer_no=?").bind(data.developer_no.trim()).run();
          if (!result.meta.changes) return json({ success: false, message: "该开发者编号不存在" }, 404);
          await env.DB.prepare("DELETE FROM ethics_candidates WHERE developer_no=?").bind(data.developer_no.trim()).run();
          return json({ success: true });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }
    }

    // ================= 伦理道德委员会候选人与抽取 =================
    if (url.pathname === "/api/committee/candidates" && request.method === "PUT") {
      if (!env.DB) return json({ success: false, message: "未绑定 D1 数据库 DB" }, 500);
      await ensurePeopleTable(env.DB);
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);
      if (!authed) return json({ success: false, message: "需要管理员登录" }, 401);
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);
      try {
        const data = await request.json();
        if (!data || typeof data.developer_no !== "string" || typeof data.candidate !== "boolean") {
          return json({ success: false, message: "候选人状态参数无效" }, 400);
        }
        const developerNo = data.developer_no.trim();
        const person = await env.DB.prepare(
          "SELECT developer_no, left_at FROM people WHERE developer_no=?"
        ).bind(developerNo).first();
        if (!person) return json({ success: false, message: "该开发者编号不存在" }, 404);
        if (person.left_at) return json({ success: false, message: "已离职人员不能设为候选人" }, 400);
        if (data.candidate) {
          await env.DB.prepare(
            "INSERT INTO ethics_candidates (developer_no, added_at) VALUES (?, ?) ON CONFLICT(developer_no) DO NOTHING"
          ).bind(developerNo, new Date().toISOString()).run();
        } else {
          await env.DB.prepare("DELETE FROM ethics_candidates WHERE developer_no=?").bind(developerNo).run();
        }
        return json({ success: true, developer_no: developerNo, is_candidate: data.candidate });
      } catch (error) {
        return json({ success: false, message: error.message }, 400);
      }
    }

    if (url.pathname === "/api/committee") {
      if (!env.DB) return json({ success: false, message: "未绑定 D1 数据库 DB" }, 500);
      await ensureCommitteeTables(env.DB);
      if (request.method === "GET") {
        try {
          const quarter = committeeQuarterKey(new Date());
          const term = await env.DB.prepare(
            "SELECT quarter, selected_at, members_json FROM ethics_committee_terms WHERE quarter=?"
          ).bind(quarter).first();
          return json({ success: true, quarter, members: term ? parseCommitteeMembers(term.members_json) : [] });
        } catch (error) {
          return json({ success: false, message: error.message }, 500);
        }
      }

      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);
      if (!authed) return json({ success: false, message: "需要管理员登录" }, 401);
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);
      if (request.method === "POST") {
        try {
          const result = await drawCommittee(env.DB, new Date(), true);
          if (!result.success) return json(result, 400);
          return json(result);
        } catch (error) {
          return json({ success: false, message: error.message }, 500);
        }
      }
    }

    // ================= 分社联系 D1 数据 =================
    if (url.pathname === "/api/branches") {
      if (!env.DB) return json({ success: false, message: "未绑定 D1 数据库 DB" }, 500);
      await ensureBranchesTable(env.DB);
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);

      if (request.method === "GET") {
        try {
          const result = await env.DB.prepare(
            "SELECT id, name, tel, mail, address, person, updated_at FROM branches ORDER BY name COLLATE NOCASE ASC"
          ).all();
          return json({ success: true, branches: result.results || [] });
        } catch (error) {
          return json({ success: false, message: error.message }, 500);
        }
      }

      if (!authed) return json({ success: false, message: "需要管理员登录" }, 401);
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);

      if (request.method === "POST") {
        try {
          const data = await request.json();
          const branch = validateBranchData(data);
          if (!branch) return json({ success: false, message: "分社名称或联系信息无效" }, 400);
          const id = typeof data.id === "string" && data.id.trim() ? data.id.trim() : crypto.randomUUID();
          await env.DB.prepare(
            "INSERT INTO branches (id, name, tel, mail, address, person, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
          ).bind(id, branch.name, branch.tel, branch.mail, branch.address, branch.person, new Date().toISOString()).run();
          return json({ success: true, branch: { id, ...branch } });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "PUT") {
        try {
          const data = await request.json();
          const branch = validateBranchData(data);
          if (!branch || typeof data.id !== "string" || !data.id.trim()) {
            return json({ success: false, message: "分社信息无效" }, 400);
          }
          const id = data.id.trim();
          const result = await env.DB.prepare(
            "UPDATE branches SET name=?, tel=?, mail=?, address=?, person=?, updated_at=? WHERE id=?"
          ).bind(branch.name, branch.tel, branch.mail, branch.address, branch.person, new Date().toISOString(), id).run();
          if (!result.meta.changes) return json({ success: false, message: "该分社不存在" }, 404);
          return json({ success: true, branch: { id, ...branch } });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }

      if (request.method === "DELETE") {
        try {
          const data = await request.json();
          if (!data || typeof data.id !== "string" || !data.id.trim()) {
            return json({ success: false, message: "分社编号无效" }, 400);
          }
          const result = await env.DB.prepare("DELETE FROM branches WHERE id=?").bind(data.id.trim()).run();
          if (!result.meta.changes) return json({ success: false, message: "该分社不存在" }, 404);
          return json({ success: true });
        } catch (error) {
          return json({ success: false, message: error.message }, 400);
        }
      }
    }

    // ================= 管理员登出 =================
    if (request.method === "POST" && url.pathname === "/api/logout") {
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);
      return json(
        { success: true },
        200,
        { "Set-Cookie": "admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }
      );
    }

    // ================= 加入申请 =================
    if (request.method === "POST" && url.pathname === "/api/join") {
      if (!sameOrigin(request, url)) return json({ success: false, message: "请求来源无效" }, 403);
      try {
        const data = await request.json();
        if (!env.TURNSTILE_SECRET) {
          return json({ success: false, message: "服务器未配置 Turnstile 密钥" }, 500);
        }
        if (!await verifyTurnstile(data.turnstileToken, env.TURNSTILE_SECRET, request.headers.get("CF-Connecting-IP"))) {
          return json({ success: false, message: "请完成人机验证" }, 400);
        }
        if (!env.DINGTALK_WEBHOOK) {
          return json({ success: false, message: "未配置申请通知服务" }, 500);
        }
        if (!validJoinData(data)) {
          return json({ success: false, message: "申请信息不完整或格式无效" }, 400);
        }
        const dingPayload = {
          msgtype: "text",
          text: { content: `【新成员申请】\n姓名：${cleanText(data.name)}\n性别：${cleanText(data.gender)}\n年龄：${Number(data.age)}\n兴趣爱好：${cleanText(data.hobbies)}\n特长：${cleanText(data.skills)}\n联系方式：${cleanText(data.contact)}` }
        };
        const dingRes = await fetch(env.DINGTALK_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(dingPayload)
        });
        const dingResult = await dingRes.json();
        if (dingResult.errcode !== 0) throw new Error(dingResult.errmsg || "钉钉返回错误");
        return json({ success: true });
      } catch (err) {
        return json({ success: false, message: err.message }, 500);
      }
    }

    const databaseDetail = /^\/database\/(\d{3})$/.exec(url.pathname);
    if (databaseDetail) {
      if (!env.DB) return errorPageResponse(500, "决案档案暂时无法加载");
      await ensureDocsTable(env.DB);
      const token = getCookie(request.headers.get("Cookie") || "", "admin_session");
      const authed = !!env.ADMIN_PASSWORD && !!token && await verifySession(token, env.ADMIN_PASSWORD);
      const doc = authed
        ? await env.DB.prepare("SELECT no FROM docs WHERE no=?").bind(databaseDetail[1]).first()
        : await env.DB.prepare("SELECT no FROM docs WHERE no=? AND visibility='公开'").bind(databaseDetail[1]).first();
      if (!doc) return errorPageResponse(404, "决案未找到");
    }

    // ================= 前端页面 =================
    const page = routeMeta(url.pathname);
    const isKnownRoute =
      url.pathname === "/" ||
      ["/space", "/history", "/database", "/list", "/contact", "/committee", "/join", "/login"].includes(url.pathname) ||
      /^\/database\/\d{3}$/.test(url.pathname);

    if (!isKnownRoute) {
      return errorPageResponse(404, "页面未找到");
    }

    const htmlContent = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 300 400'%3E%3Cline x1='60' y1='380' x2='130' y2='160' stroke='%23FF0000' stroke-width='24' stroke-linecap='round'/%3E%3Cline x1='140' y1='320' x2='210' y2='100' stroke='%2300FFFF' stroke-width='24' stroke-linecap='round'/%3E%3Cline x1='220' y1='260' x2='290' y2='40' stroke='%230000FF' stroke-width='24' stroke-linecap='round'/%3E%3C/svg%3E">
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
      <title>${page.title}</title>
      <meta name="description" content="${page.description}">
      <link rel="canonical" href="https://developer.kelifoundation.org${canonicalPath(url.pathname)}">
      <meta property="og:type" content="website">
      <meta property="og:site_name" content="上海克利工作室">
      <meta property="og:title" content="${page.title}">
      <meta property="og:description" content="${page.description}">
      <meta property="og:url" content="https://developer.kelifoundation.org${canonicalPath(url.pathname)}">
      <meta name="twitter:card" content="summary">
      <meta name="twitter:title" content="${page.title}">
      <meta name="twitter:description" content="${page.description}">
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", sans-serif; background-color: #0b0d10; color: #eef2f6; line-height: 1.6; overflow-x: hidden; }
        .bg { position: fixed; inset: 0; z-index: -2; background: radial-gradient(circle at 20% 30%, #1a1f2b 0%, #0b0d10 70%); }
        .glow { position: fixed; width: 60vw; height: 60vw; border-radius: 50%; background: radial-gradient(circle, rgba(100, 150, 255, 0.08) 0%, transparent 70%); top: -20vh; right: -10vw; filter: blur(60px); z-index: -1; pointer-events: none; }
        .container { max-width: 1600px; margin: 0 auto; padding: 0 2.5rem; position: relative; z-index: 2; }

        body.theme-light { background-color: #f5f7fb; color: #171a21; }
        body.theme-light .bg { background: radial-gradient(circle at 20% 30%, #ffffff 0%, #edf1f7 70%); }
        body.theme-light .glow { background: radial-gradient(circle, rgba(68, 120, 220, 0.12) 0%, transparent 70%); }
        body.theme-light .navbar { border-bottom-color: rgba(20, 30, 50, 0.09); }
        body.theme-light .logo-main { color: #171a21; }
        body.theme-light .logo-sub { color: #66758d; }
        body.theme-light .nav-links a { color: #596b84; }
        body.theme-light .nav-links a:hover { color: #171a21; }
        body.theme-light .gradient-text { background: linear-gradient(135deg, #171a21 0%, #4e6fc1 80%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        body.theme-light .hero p,
        body.theme-light .history-section p.subtitle,
        body.theme-light .timeline-content p,
        body.theme-light .docs-header p,
        body.theme-light .doc-card p,
        body.theme-light .form-section p.subtitle,
        body.theme-light .join-disclaimer,
        body.theme-light .footer { color: #66758d; }
        body.theme-light .card,
        body.theme-light .timeline-content,
        body.theme-light .stat-box,
        body.theme-light .status-grid,
        body.theme-light .doc-card,
        body.theme-light .doc-modal,
        body.theme-light .code-block { background: rgba(255, 255, 255, 0.86); border-color: rgba(30, 50, 80, 0.11); }
        body.theme-light .card h3,
        body.theme-light .timeline-content h3,
        body.theme-light .history-section h2,
        body.theme-light .docs-header h2,
        body.theme-light .doc-card h3,
        body.theme-light .form-section h2,
        body.theme-light .space-title h2,
        body.theme-light .stat-box .val,
        body.theme-light .status-item p { color: #171a21; }
        body.theme-light .code-block { color: #334155; box-shadow: inset 0 0 20px rgba(30,50,80,.04); }
        body.theme-light .code-title { color: #1e293b; }
        body.theme-light .code-desc { color: #64748b; }
        body.theme-light .form-group input,
        body.theme-light .form-group select,
        body.theme-light .form-group textarea { background: rgba(255,255,255,.9); border-color: rgba(30,50,80,.16); color: #171a21; }
        body.theme-light .form-group label,
        body.theme-light .doc-content { color: #52637a; }
        body.theme-light .footer { border-top-color: rgba(30,50,80,.09); }
        body.theme-light .btn-primary { background: #171a21; color: #fff; }
        body.theme-light .btn-secondary { background: rgba(30,50,80,.08) !important; color: #171a21 !important; }
        
        /* 导航栏 */
        .navbar { display: flex; justify-content: space-between; align-items: center; padding: 2.5rem 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); gap: 1rem; }
        .logo { display: flex; align-items: center; gap: 12px; text-decoration: none; color: inherit; cursor: pointer; }
        .logo-svg { background: #fff; padding: 6px 8px; border-radius: 8px; display: flex; align-items: center; justify-content: center; }
        .logo-svg svg { height: 32px; width: auto; display: block; }
        .logo-main { font-size: 1.25rem; font-weight: 600; color: #fff; display: block; line-height: 1.2; }
        .logo-sub { font-size: 0.7rem; letter-spacing: 0.1em; color: #8b9bb4; text-transform: uppercase; display: block; }
        .nav-links { display: flex; gap: clamp(1.25rem, 2vw, 2.5rem); }
        .nav-links a { text-decoration: none; color: #b1c2d9; font-size: 0.9rem; transition: color 0.3s; cursor: pointer; }
        .nav-links a:hover { color: #fff; }

        /* 管理员图标 */
        .user-icon {
          width: 42px; height: 42px; flex: none;
          display: inline-flex; align-items: center; justify-content: center;
          border-radius: 50%;
          color: #b1c2d9;
          text-decoration: none;
          cursor: pointer;
          transition: background 0.3s, box-shadow 0.4s, filter 0.4s;
          margin-left: auto;
        }
        .user-icon:not(.is-admin) { color: #eef2f6; }
        body.theme-light .user-icon:not(.is-admin) { color: #171a21; }
        .user-icon:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
        body.theme-light .user-icon:hover { background: rgba(30,50,80,.08); color: #171a21; }
        .user-icon svg { width: 22px; height: 22px; display: block; }
        .user-icon .icon-gold { display: none; }
        .user-icon.is-admin {
          background: radial-gradient(circle at 30% 25%, rgba(255, 240, 180, 0.22) 0%, rgba(156, 122, 30, 0.18) 55%, rgba(60, 45, 10, 0.25) 100%);
          box-shadow:
            0 0 14px rgba(240, 224, 160, 0.28),
            inset 0 1px 2px rgba(255, 240, 180, 0.45),
            inset 0 -1px 2px rgba(60, 45, 10, 0.4);
        }
        .user-icon.is-admin .icon-white { display: none; }
        .user-icon.is-admin .icon-gold { display: block; }
        .user-icon.is-admin:hover { filter: brightness(1.15); }

        /* 主题切换与登出确认 */
        .theme-btn {
          width: 42px; height: 42px; flex: none;
          display: inline-flex; align-items: center; justify-content: center;
          border: 0; border-radius: 50%;
          background: transparent; color: #b1c2d9;
          cursor: pointer; transition: background .3s, color .3s;
          margin-left: auto;
        }
        .theme-btn:hover { background: rgba(255,255,255,.08); color: #fff; }
        .theme-btn svg { width: 22px; height: 22px; }
        .theme-btn + .user-icon { margin-left: 0; }
        body.theme-light .theme-btn { color: #596b84; }
        body.theme-light .theme-btn:hover { background: rgba(30,50,80,.08); color: #171a21; }

        .app-modal-backdrop {
          position: fixed; inset: 0; z-index: 2000;
          display: none; align-items: center; justify-content: center;
          padding: 1rem; background: rgba(5,8,12,.58);
          backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
        }
        .app-modal-backdrop.show { display: flex; }
        .app-modal {
          width: min(420px, 100%);
          background: #11151d; border: 1px solid rgba(255,255,255,.1);
          border-radius: 20px; padding: 1.75rem;
          box-shadow: 0 24px 70px rgba(0,0,0,.45);
          text-align: center;
        }
        .app-modal h3 { color: #fff; font-size: 1.35rem; margin-bottom: .6rem; }
        .app-modal p { color: #96a9c4; margin-bottom: 1.25rem; }
        .app-modal-actions { display: flex; gap: .75rem; }
        .app-modal-actions button { width: 100%; margin: 0; }
        .app-modal-actions .app-modal-cancel { background: rgba(255,255,255,.1); color: #fff; }
        body.theme-light .app-modal { background: #fff; border-color: rgba(30,50,80,.12); }
        body.theme-light .app-modal h3 { color: #171a21; }
        body.theme-light .app-modal p { color: #66758d; }
        body.theme-light .app-modal-actions .app-modal-cancel { background: rgba(30,50,80,.08); color: #171a21; }
        
        /* 页面切换 */
        .page { display: none; animation: fadeIn 0.4s ease; }
        .page.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        /* 首页 */
        .hero { text-align: center; padding: 6rem 0 4rem; }
        .hero h1 { font-size: 4rem; font-weight: 600; margin-bottom: 1.5rem; line-height: 1.1; }
        .gradient-text { background: linear-gradient(135deg, #ffffff 0%, #b0c8ff 80%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero p { font-size: 1.2rem; color: #a0b2c9; max-width: 600px; margin: 0 auto 3rem; font-weight: 300; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin: 4rem 0 6rem; }
        .card { background: rgba(20, 25, 35, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 20px; padding: 2.5rem 2rem; transition: 0.3s; cursor: pointer; text-decoration: none; display: block; position: relative; overflow: hidden; }
        .card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: linear-gradient(180deg, rgba(176, 200, 255, 0.03) 0%, transparent 100%); opacity: 0; transition: 0.3s; }
        .card:hover { transform: translateY(-5px); border-color: rgba(140, 180, 255, 0.3); background: rgba(28, 35, 48, 0.7); }
        .card:hover::before { opacity: 1; }
        .card-icon { font-size: 1.5rem; color: #b0c8ff; margin-bottom: 1.2rem; font-weight: 700; font-family: monospace; display: inline-block; padding: 0.5rem; border-radius: 8px; background: rgba(176, 200, 255, 0.1); line-height: 1; }
        .card h3 { color: #fff; margin-bottom: 0.8rem; font-size: 1.25rem; z-index: 1; position: relative; }
        .card p { color: #96a9c4; font-size: 0.95rem; margin-bottom: 1.5rem; z-index: 1; position: relative; }
        .card-link { color: #b0c8ff; font-size: 0.9rem; display: inline-block; transition: 0.3s; font-weight: 500; z-index: 1; position: relative; }
        .card:hover .card-link { color: #fff; transform: translateX(5px); }

        /* 历史时间线 */
        .history-section { padding: 4rem 0 6rem; max-width: 800px; margin: 0 auto; }
        .history-section h2 { font-size: 3rem; margin-bottom: 1rem; text-align: center; color: #fff; }
        .history-section p.subtitle { text-align: center; color: #96a9c4; margin-bottom: 4rem; }
        .timeline { position: relative; padding-left: 2rem; }
        .timeline::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: rgba(176, 200, 255, 0.2); }
        .timeline-item { position: relative; margin-bottom: 3rem; }
        .timeline-item:last-child { margin-bottom: 0; }
        .timeline-dot { position: absolute; left: -2rem; top: 0.5rem; width: 14px; height: 14px; border-radius: 50%; background: #b0c8ff; border: 3px solid #0b0d10; transform: translateX(-50%); box-shadow: 0 0 10px rgba(176, 200, 255, 0.5); z-index: 2; }
        .timeline-date { font-size: 0.85rem; color: #b0c8ff; font-weight: 600; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .timeline-content { background: rgba(20, 25, 35, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 1.5rem 2rem; transition: 0.3s; }
        .timeline-content:hover { border-color: rgba(140, 180, 255, 0.3); background: rgba(28, 35, 48, 0.7); }
        .timeline-content h3 { color: #fff; font-size: 1.2rem; margin-bottom: 0.5rem; }
        .timeline-content p { color: #96a9c4; font-size: 0.95rem; }

        /* Space 档案 */
        .space-section { padding: 4rem 0 6rem; max-width: 900px; margin: 0 auto; }
        .version-container { margin-bottom: 5rem; }
        .version-container:last-child { margin-bottom: 0; }
        .space-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 3rem; border-bottom: 1px solid rgba(255, 255, 255, 0.1); padding-bottom: 2rem; flex-wrap: wrap; gap: 1.5rem; }
        .space-title h2 { font-size: 2.5rem; color: #fff; margin-bottom: 0.5rem; }
        .space-title p { color: #b0c8ff; font-family: monospace; font-size: 1rem; }
        .space-stats { display: flex; gap: 2rem; }
        .stat-box { background: rgba(20, 25, 35, 0.8); padding: 1rem 1.5rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.05); text-align: right; }
        .stat-box .val { font-size: 1.5rem; font-weight: 700; color: #fff; }
        .stat-box .val-small { font-size: 0.9rem; color: #8b9bb4; font-weight: 400; margin-top: 0.2rem; }
        .stat-box .lbl { font-size: 0.8rem; color: #96a9c4; }
        .code-block { background: #0d1117; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; padding: 2rem; font-family: 'Courier New', Courier, monospace; margin-bottom: 2rem; box-shadow: inset 0 0 20px rgba(0,0,0,0.5); }
        .code-line { margin-bottom: 0.8rem; display: flex; flex-direction: column; }
        .code-title { color: #e6edf3; font-weight: bold; font-size: 1.05rem; margin-bottom: 0.3rem; }
        .code-desc { color: #8b949e; font-size: 0.9rem; line-height: 1.6; }
        .code-desc span { color: #79c0ff; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; background: rgba(20, 25, 35, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 2rem; }
        .status-item h4 { color: #96a9c4; font-size: 0.85rem; margin-bottom: 0.3rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .status-item p { color: #fff; font-size: 1.1rem; font-weight: 600; }
        .status-item p.danger { color: #ff7b72; }
        .status-item p.normal { color: #b0c8ff; }
        .status-item p.success { color: #3fb950; }

        /* 决案档案 */
        .docs-section { padding: 4rem 0 6rem; max-width: 1440px; margin: 0 auto; }
        .docs-header { text-align: center; margin-bottom: 4rem; }
        .docs-header h2 { font-size: 3rem; color: #fff; margin-bottom: 1rem; }
        .docs-header p { color: #96a9c4; font-size: 1.1rem; }
        .docs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }
        .doc-card { background: rgba(20, 25, 35, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 2rem; cursor: pointer; transition: 0.3s; display: flex; flex-direction: column; }
        .doc-card:hover { transform: translateY(-5px); border-color: rgba(140, 180, 255, 0.3); background: rgba(28, 35, 48, 0.7); }
        .doc-card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .doc-no { font-size: 0.8rem; font-weight: 700; color: #b0c8ff; background: rgba(176, 200, 255, 0.1); padding: 0.2rem 0.6rem; border-radius: 6px; }
        .doc-tag { font-size: 0.75rem; color: #e3b341; background: rgba(227, 179, 65, 0.1); padding: 0.2rem 0.6rem; border-radius: 6px; }
        .doc-card h3 { color: #fff; font-size: 1.2rem; margin-bottom: 0.8rem; line-height: 1.4; }
        .doc-card p { color: #96a9c4; font-size: 0.9rem; line-height: 1.6; flex: 1; margin-bottom: 1.5rem; }
        .doc-card-foot { display: flex; gap: 0.5rem; flex-wrap: wrap; border-top: 1px dashed rgba(255, 255, 255, 0.1); padding-top: 1rem; align-items: center; }
        .doc-footer-tag { font-size: 0.75rem; color: #8b9bb4; background: rgba(255, 255, 255, 0.05); padding: 0.2rem 0.6rem; border-radius: 4px; }
        .doc-status-draft { color: #e3b341; background: rgba(227,179,65,.1); }
        .doc-status-public { color: #3fb950; background: rgba(63,185,80,.12); }
        .doc-status-private { color: #f87171; background: rgba(248,113,113,.12); }
        .doc-more { margin-left: auto; font-size: 0.85rem; color: #b0c8ff; font-weight: 600; }
        .doc-card-actions { display: flex; align-items: center; gap: 0.55rem; margin-left: auto; }
        .doc-icon-btn { width: 34px; height: 34px; border: 0; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; background: rgba(255,255,255,.08); transition: .2s; }
        .doc-icon-btn svg { width: 17px; height: 17px; display: block; }
        .doc-icon-btn:hover { background: rgba(255,255,255,.16); }
        .doc-edit { color: #fff; }
        .doc-delete { color: #f87171; background: rgba(248,113,113,.1); }
        .doc-delete:hover { background: rgba(248,113,113,.18); }
        body.theme-light .doc-edit { color: #334155; }
        body.theme-light .doc-icon-btn { background: rgba(30,50,80,.08); }
        body.theme-light .doc-icon-btn:hover { background: rgba(30,50,80,.14); }
        body.theme-light .doc-delete { color: #dc2626; background: rgba(220,38,38,.1); }
        .doc-add-card { min-height: 235px; align-items: center; justify-content: center; border-style: dashed; color: #b0c8ff; }
        .doc-add-card .doc-add-icon { font-size: 3.2rem; line-height: 1; font-weight: 300; }
        .doc-modal-backdrop { position: fixed; inset: 0; z-index: 1000; display: none; align-items: center; justify-content: center; padding: 1rem; background: rgba(0,0,0,.72); }
        .doc-modal-backdrop.show { display: flex; }
        .doc-modal { width: min(720px, 100%); max-height: 88vh; overflow-y: auto; background: #11151d; border: 1px solid rgba(255,255,255,.1); border-radius: 20px; padding: 1.5rem; }
        .doc-modal h3 { margin-bottom: 1rem; }
        .doc-modal-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 1rem; }
        .doc-modal-grid .wide { grid-column: 1 / -1; }
        .doc-modal-actions { display: flex; gap: .75rem; justify-content: flex-end; margin-top: 1.25rem; }
        .doc-modal-actions button { width: auto; margin: 0; }
        .doc-modal-actions .btn-secondary { background: rgba(255,255,255,.08); color: #fff; }
        .people-toolbar { display: flex; align-items: center; gap: 1rem; margin: 0 auto 1.25rem; max-width: 1440px; }
        .people-toolbar input { flex: 1; min-width: 0; padding: 1rem 1.2rem; background: rgba(20,25,35,.7); border: 1px solid rgba(255,255,255,.12); border-radius: 12px; color: inherit; font: inherit; }
        .people-toolbar input:focus { outline: none; border-color: #b0c8ff; }
        .people-count { color: #96a9c4; font-size: .9rem; white-space: nowrap; }
        .people-admin-toolbar { display: none; justify-content: flex-end; max-width: 1200px; margin: 0 auto 1rem; }
        body.admin-mode .people-admin-toolbar { display: flex; }
        .people-add-btn { width: auto; margin: 0; }
        .people-table-wrap { overflow-x: auto; border: 1px solid rgba(255,255,255,.08); border-radius: 16px; background: rgba(20,25,35,.45); }
        .people-table { width: 100%; border-collapse: collapse; min-width: 900px; }
        .people-table th, .people-table td { padding: .9rem 1rem; border-bottom: 1px solid rgba(255,255,255,.07); text-align: left; white-space: nowrap; }
        .people-table th { color: #b0c8ff; font-size: .85rem; font-weight: 600; }
        .people-table td { color: #d3dbea; font-size: .92rem; }
        .people-table tbody tr:last-child td { border-bottom: 0; }
        .people-table tbody tr:hover { background: rgba(176,200,255,.05); }
        .people-status-cell { width: 1%; text-align: center; }
        .people-status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; vertical-align: middle; }
        .people-status-dot.active { background: #dbeafe; }
        .people-status-dot.candidate { background: #22c55e; }
        .people-status-dot.left { background: #ef4444; }
        body.theme-light .people-status-dot.active { background: #334155; }
        .people-status-toggle { padding: 0; border: 0; background: transparent; cursor: pointer; }
        .people-status-toggle:focus-visible { outline: 2px solid #b0c8ff; outline-offset: 4px; border-radius: 50%; }
        .people-empty { padding: 2rem; text-align: center; color: #96a9c4; }
        .people-actions { display: flex; gap: .45rem; }
        .people-actions .doc-icon-btn { width: 32px; height: 32px; }
        body.theme-light .people-toolbar input { background: #fff; border-color: rgba(30,50,80,.16); color: #171a21; }
        body.theme-light .people-count,
        body.theme-light .people-empty { color: #66758d; }
        body.theme-light .people-table-wrap { background: rgba(255,255,255,.85); border-color: rgba(30,50,80,.12); }
        body.theme-light .people-table th { color: #4e6fc1; }
        body.theme-light .people-table td { color: #334155; }
        body.theme-light .people-table th,
        body.theme-light .people-table td { border-bottom-color: rgba(30,50,80,.1); }
        body.theme-light .people-table tbody tr:hover { background: rgba(78,111,193,.06); }
        .branch-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }
        .branch-card { background: rgba(20,25,35,.6); border: 1px solid rgba(255,255,255,.05); border-radius: 16px; padding: 1.5rem; }
        .branch-card-top { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; }
        .branch-card h3 { color: #fff; font-size: 1.25rem; }
        .branch-info { display: grid; gap: .65rem; }
        .branch-info-row { display: grid; grid-template-columns: 64px minmax(0,1fr) 34px; align-items: center; gap: .55rem; color: #b1c2d9; }
        .branch-info-label { color: #96a9c4; font-size: .82rem; }
        .branch-info-value { overflow-wrap: anywhere; font-size: .92rem; }
        .copy-btn { width: 34px; height: 34px; border: 0; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; color: #b0c8ff; background: rgba(176,200,255,.1); }
        .copy-btn:hover { background: rgba(176,200,255,.18); }
        .copy-btn svg { width: 16px; height: 16px; }
        .copy-btn.copied { color: #3fb950; }
        body.theme-light .branch-card { background: rgba(255,255,255,.86); border-color: rgba(30,50,80,.12); }
        body.theme-light .branch-card h3 { color: #171a21; }
        body.theme-light .branch-info-label { color: #66758d; }
        body.theme-light .branch-info-row { color: #334155; }
        .committee-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1.5rem; }
        .committee-member { padding: 2rem; text-align: center; border: 1px solid rgba(255,255,255,.08); border-radius: 16px; background: rgba(20,25,35,.6); }
        .committee-member .committee-number { color: #96a9c4; font-size: .85rem; }
        .committee-member h3 { margin: .5rem 0; color: #fff; font-size: 1.4rem; }
        .committee-member p { color: #b1c2d9; }
        .committee-empty { grid-column: 1 / -1; padding: 2rem; text-align: center; color: #96a9c4; }
        .committee-rules { margin-top: 3rem; padding: 2rem; border: 1px solid rgba(255,255,255,.08); border-radius: 16px; background: rgba(20,25,35,.35); }
        .committee-rules h3 { margin-bottom: 1rem; color: #b0c8ff; }
        .committee-rules ul { padding-left: 1.5rem; color: #b1c2d9; line-height: 2; }
        body.theme-light .committee-member { background: rgba(255,255,255,.86); border-color: rgba(30,50,80,.12); }
        body.theme-light .committee-member h3 { color: #171a21; }
        body.theme-light .committee-member p,
        body.theme-light .committee-rules ul { color: #334155; }
        body.theme-light .committee-member .committee-number { color: #66758d; }
        body.theme-light .committee-rules { background: rgba(255,255,255,.65); border-color: rgba(30,50,80,.12); }
        body.theme-light .committee-rules h3 { color: #4e6fc1; }

        .doc-content { color: #b1c2d9; line-height: 1.8; font-size: 0.95rem; }
        .doc-content h3 { color: #79c0ff; font-size: 1.1rem; margin: 1.5rem 0 0.8rem; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .doc-content h3:first-child { margin-top: 0; }
        .doc-content p { margin-bottom: 1rem; }
        .doc-content ol, .doc-content ul { padding-left: 1.5rem; margin-bottom: 1rem; }
        .doc-content li { margin-bottom: 0.5rem; }
        .doc-content li > ul { margin-top: 0.5rem; padding-left: 1.5rem; }
        .doc-content li > ul li { list-style: circle; }
        .doc-note { background: rgba(121, 192, 255, 0.1); border-left: 3px solid #79c0ff; padding: 1rem 1.5rem; border-radius: 0 8px 8px 0; color: #b1c2d9; font-size: 0.9rem; margin: 1rem 0; }

        /* 表单（加入 & 登录） */
        .form-section { padding: 4rem 0; max-width: 480px; margin: 0 auto; }
        .form-section h2 { font-size: 2.5rem; margin-bottom: 1rem; color: #fff; }
        .form-section p.subtitle { color: #96a9c4; margin-bottom: 3rem; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; font-size: 0.9rem; color: #b1c2d9; margin-bottom: 0.5rem; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 1rem; background: rgba(20, 25, 35, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; color: #fff; font-family: inherit; font-size: 1rem; transition: border-color 0.3s; }
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus { outline: none; border-color: #b0c8ff; }
        .form-group textarea { resize: vertical; height: 100px; }
        .password-input-wrap { position: relative; }
        .password-input-wrap input { padding-right: 3.5rem; }
        .password-toggle { position: absolute; top: 50%; right: 0.5rem; transform: translateY(-50%); display: grid; place-items: center; width: 2.5rem; height: 2.5rem; padding: 0; border: 0; border-radius: 8px; background: transparent; color: #b1c2d9; cursor: pointer; }
        .password-toggle:hover { background: rgba(255, 255, 255, 0.08); }
        .password-toggle:focus-visible { outline: 2px solid #b0c8ff; outline-offset: 2px; }
        .password-toggle svg { width: 1.25rem; height: 1.25rem; }
        .password-toggle svg[hidden] { display: none; }
        body.theme-light .password-toggle { color: #52637a; }
        body.theme-light .password-toggle:hover { background: rgba(30, 50, 80, 0.08); }
        .btn-primary { background: #fff; color: #0b0d10; padding: 0.9rem 2.4rem; border-radius: 40px; font-weight: 600; font-size: 1rem; border: none; cursor: pointer; transition: 0.3s; width: 100%; margin-top: 1rem; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(255,255,255,0.2); }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        
        .toast { position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: #4ade80; color: #000; padding: 1rem 2rem; border-radius: 40px; font-weight: 600; opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 999; }
        .toast.error { background: #f87171; }
        .toast.show { opacity: 1; }
        .footer { border-top: 1px solid rgba(255, 255, 255, 0.05); padding: 2rem 0; display: flex; justify-content: space-between; align-items: center; color: #7b8ba3; font-size: 0.85rem; }
        .footer-brand { flex: none; margin-right: 1.5rem; }
        .footer-disclaimer { max-width: 760px; line-height: 1.8; text-align: right; }
        .join-disclaimer { color: #96a9c4; font-size: 0.85rem; line-height: 1.8; margin: 1.5rem 0 0.5rem; }
        .turnstile-box { min-height: 70px; margin: 1rem 0 0.25rem; }

        @media (max-width: 760px) {
          .container { padding: 0 1.25rem; }
          .navbar { flex-wrap: wrap; padding: 1.25rem 0; }
          .logo-main { font-size: 1.05rem; }
          .logo-sub { font-size: 0.58rem; }
          .nav-links { order: 3; width: 100%; gap: 0; justify-content: space-between; border-top: 1px solid rgba(255,255,255,.05); padding-top: .75rem; }
          .nav-links a { font-size: .78rem; }
          .hero { padding: 4rem 0 2rem; }
          .hero h1 { font-size: clamp(2.35rem, 12vw, 3.2rem); }
          .hero p { font-size: 1rem; }
          .features { margin: 2.5rem 0 4rem; }
          .space-header { flex-direction: column; }
          .space-stats { width: 100%; gap: .75rem; }
          .stat-box { flex: 1; text-align: left; padding: 1rem; }
          .docs-grid { grid-template-columns: 1fr; }
          .people-toolbar { align-items: stretch; flex-direction: column; }
          .people-count { text-align: right; }
          .doc-modal-grid { grid-template-columns: 1fr; }
          .doc-modal-grid .wide { grid-column: auto; }
          .history-section h2, .docs-header h2 { font-size: 2.25rem; }
          .footer { flex-direction: column; gap: .5rem; text-align: center; }
          .footer-brand { margin-right: 0; }
          .footer-disclaimer { text-align: center; }
        }
      </style>
    </head>
    <body>
      <div class="bg"></div><div class="glow"></div><div id="toast" class="toast">提交成功</div>
      
      <div class="container">
        <nav class="navbar">
          <a class="logo" href="/" onclick="return navigate(event, '/')">
            <div class="logo-svg">
              <svg viewBox="0 0 300 400" xmlns="http://www.w3.org/2000/svg">
                <line x1="60" y1="380" x2="130" y2="160" stroke="#FF0000" stroke-width="24" stroke-linecap="round" />
                <line x1="140" y1="320" x2="210" y2="100" stroke="#00FFFF" stroke-width="24" stroke-linecap="round" />
                <line x1="220" y1="260" x2="290" y2="40" stroke="#0000FF" stroke-width="24" stroke-linecap="round" />
              </svg>
            </div>
            <div>
              <span class="logo-main">上海克利工作室</span>
              <span class="logo-sub">Shanghai Keli work studio</span>
            </div>
          </a>
          <div class="nav-links">
            <a href="/space" onclick="return navigate(event, '/space')">Space 档案</a>
            <a href="/history" onclick="return navigate(event, '/history')">克利历程</a>
            <a href="/database" onclick="return navigate(event, '/database')">决案档案</a>
            <a href="/list" onclick="return navigate(event, '/list')">人员查询</a>
            <a href="/contact" onclick="return navigate(event, '/contact')">联系我们</a>
            <a href="/committee" onclick="return navigate(event, '/committee')">成员公示</a>
            <a href="/join" onclick="return navigate(event, '/join')">加入我们</a>
          </div>
          <button id="themeBtn" class="theme-btn" type="button" aria-label="切换浅色主题" title="切换主题">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M9 18h6"/>
              <path d="M10 21h4"/>
              <path d="M8.2 14.8A6 6 0 1 1 15.8 14.8c-.9.7-1.3 1.5-1.3 2.2h-5c0-.7-.4-1.5-1.3-2.2Z"/>
              <path d="M12 2V1"/>
              <path d="M4.7 4.7l-.7-.7"/>
              <path d="M19.3 4.7l.7-.7"/>
              <path d="M3 11H1"/>
              <path d="M21 11h2"/>
            </svg>
          </button>
          <a id="userBtn" class="user-icon" href="/login" aria-label="管理员登录">
            <svg class="icon-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
              <circle cx="12" cy="7" r="4"/>
            </svg>
            <svg class="icon-gold" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <defs>
                <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#6b5312"/>
                  <stop offset="25%" stop-color="#9C7A1E"/>
                  <stop offset="50%" stop-color="#f5e6a8"/>
                  <stop offset="75%" stop-color="#9C7A1E"/>
                  <stop offset="100%" stop-color="#6b5312"/>
                </linearGradient>
              </defs>
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" stroke="url(#goldGrad)"/>
              <circle cx="12" cy="7" r="4" stroke="url(#goldGrad)"/>
            </svg>
          </a>
        </nav>

        <!-- 首页 -->
        <div id="home" class="page active">
          <header class="hero">
            <h1><span class="gradient-text">上海克利工作室</span><br>让创意更具价值</h1>
            <p>我们致力于通过专业设计与创新思维，为您提供高品质的视觉与数字体验。联结每一份灵感。</p>
          </header>
          <div class="features">
            <div class="card" onclick="navigate(null, '/space')">
              <div class="card-icon">[ ]</div>
              <h3>Space 历史</h3>
              <p>记录 Space 系列从 1.0 草原到 6 background的完整迭代过程与开发日志。</p>
              <span class="card-link">查阅历史档案 →</span>
            </div>
            <a href="https://ccw.site" target="_blank" rel="noopener noreferrer" class="card">
              <div class="card-icon">&lt;/&gt;</div>
              <h3>Space 系列</h3>
              <p>访问 Space 线上平台，体验我们打造的前沿互联网技术与交互项目。</p>
              <span class="card-link">前往线上平台 →</span>
            </a>
            <div class="card" onclick="navigate(null, '/history')">
              <div class="card-icon">⏣</div>
              <h3>克利历程</h3>
              <p>从回收旧家具到前沿编程，了解上海克利工作室一路走来的成长轨迹。</p>
              <span class="card-link">查看工作室历史 →</span>
            </div>
            <div class="card" onclick="navigate(null, '/database')">
              <div class="card-icon">📄</div>
              <h3>决案档案</h3>
              <p>查阅克利基金会公开发布的档案与基本规则，了解组织的管理与运行结构。</p>
              <span class="card-link">阅读决案 →</span>
            </div>
            <div class="card" onclick="navigate(null, '/list')">
              <div class="card-icon">◎</div>
              <h3>人员查询</h3>
              <p>按姓名查询开发者资料，浏览编号、部门、职级与在社时间。</p>
              <span class="card-link">查询人员 →</span>
            </div>
          </div>
        </div>

        <!-- 决案列表 -->
        <div id="docs" class="page">
          <div class="docs-section">
            <div class="docs-header">
              <h2>决案档案库</h2>
              <p>上海深深漫克利非盈利组织社区基金会公开决案归档。</p>
            </div>
            <div class="docs-grid" id="docsGrid"></div>
          </div>
        </div>

        <!-- 联系我们 -->
        <div id="contact" class="page">
          <div class="docs-section">
            <div class="docs-header">
              <h2>联系我们</h2>
              <p>上海克利工作室各分社联系信息。</p>
            </div>
            <div id="branchesAdminToolbar" class="people-admin-toolbar">
              <button type="button" class="btn-primary people-add-btn" id="branchAddBtn">+ 新增分社</button>
            </div>
            <div class="branch-grid" id="branchesGrid"></div>
          </div>
        </div>

        <div id="committee" class="page">
          <div class="docs-section">
            <div class="docs-header">
              <h2>本季度伦理道德委员会成员</h2>
              <p id="committeeQuarter"></p>
            </div>
            <div id="committeeAdminToolbar" class="people-admin-toolbar">
              <button type="button" class="btn-primary people-add-btn" id="committeeDrawBtn">管理员随机抽取</button>
            </div>
            <div id="committeeMembers" class="committee-grid"></div>
            <div class="committee-rules">
              <h3>伦理道德委员会成员候选人选取规则</h3>
              <ul>
                <li>连续6个月无冻结、举报成立、欠费记录（或新开发者7天）</li>
                <li>是普通开发者</li>
                <li>非上季度伦理委员会成员</li>
                <li>自愿报名或被提名且本人同意</li>
              </ul>
            </div>
          </div>
        </div>

        <div id="committee" class="page">
          <div class="docs-section">
            <div class="docs-header">
              <h2>本季度伦理道德委员会成员</h2>
              <p id="committeeQuarter"></p>
            </div>
            <div id="committeeAdminToolbar" class="people-admin-toolbar">
              <button type="button" class="btn-primary people-add-btn" id="committeeDrawBtn">管理员随机抽取</button>
            </div>
            <div id="committeeMembers" class="committee-grid"></div>
            <div class="committee-rules">
              <h3>伦理道德委员会成员候选人选取规则</h3>
              <ul>
                <li>连续6个月无冻结、举报成立、欠费记录（或新开发者7天）</li>
                <li>是普通开发者</li>
                <li>非上季度伦理委员会成员</li>
                <li>自愿报名或被提名且本人同意</li>
              </ul>
            </div>
          </div>
        </div>

        <div id="branchModalBackdrop" class="doc-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="branchModalTitle">
          <div class="doc-modal">
            <h3 id="branchModalTitle">新增分社</h3>
            <form id="branchForm">
              <div class="doc-modal-grid">
                <div class="form-group wide"><label>分社名称 *</label><input name="name" required maxlength="100000"></div>
                <div class="form-group"><label>Tel</label><input name="tel" maxlength="100000"></div>
                <div class="form-group"><label>Mail</label><input name="mail" maxlength="100000"></div>
                <div class="form-group wide"><label>Address</label><input name="address" maxlength="100000"></div>
                <div class="form-group wide"><label>Person</label><input name="person" maxlength="100000"></div>
              </div>
              <div class="doc-modal-actions">
                <button type="button" class="btn-primary btn-secondary" id="branchModalCancel">取消</button>
                <button type="submit" class="btn-primary" id="branchModalSave">保存</button>
              </div>
            </form>
          </div>
        </div>

        <!-- 人员查询 -->
        <div id="people" class="page">
          <div class="docs-section people-section">
            <div class="docs-header">
              <h2>人员查询</h2>
              <p>可按姓名搜索；不输入时显示全部人员。重名会分别列出。</p>
            </div>
            <div class="people-toolbar">
              <input id="peopleSearch" type="search" maxlength="100000" placeholder="输入姓名搜索" aria-label="按姓名搜索人员">
              <span id="peopleCount" class="people-count"></span>
            </div>
            <div id="peopleAdminToolbar" class="people-admin-toolbar">
              <button type="button" class="btn-primary people-add-btn" id="personAddBtn">+ 新增人员</button>
            </div>
            <div class="people-table-wrap">
              <table class="people-table">
                <thead><tr>
                  <th>状态</th><th>开发者编号</th><th>姓名</th><th>性别</th><th>部门</th><th>职级</th><th>加入时间</th><th>离开时间</th><th>重新加入</th><th id="peopleActionsHeading" hidden>操作</th>
                </tr></thead>
                <tbody id="peopleTableBody"></tbody>
              </table>
              <p id="peopleEmpty" class="people-empty" hidden>没有找到人员</p>
            </div>
          </div>
        </div>

        <div id="personModalBackdrop" class="doc-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="personModalTitle">
          <div class="doc-modal">
            <h3 id="personModalTitle">新增人员</h3>
            <form id="personForm">
              <div class="doc-modal-grid">
                <div class="form-group"><label>开发者编号 *</label><input name="developer_no" required pattern="[0-9]{1,3}" maxlength="3" inputmode="numeric" placeholder="例如：009"></div>
                <div class="form-group"><label>姓名 *</label><input name="name" required maxlength="100000"></div>
                <div class="form-group"><label>性别 *</label><select name="gender" required><option value="男">男</option><option value="女">女</option><option value="其他">其他</option></select></div>
                <div class="form-group"><label>部门 *</label><input name="department" required maxlength="100000"></div>
                <div class="form-group"><label>职级 *</label><input name="rank" required maxlength="100000"></div>
                <div class="form-group"><label>加入时间 *</label><input name="joined_at" type="date" required></div>
                <div class="form-group"><label>离开时间</label><input name="left_at" type="date"></div>
                <div class="form-group"><label>重新加入次数 *</label><select name="rejoin_type" required><option value="一职">一职</option><option value="二职">二职</option><option value="三职">三职</option></select></div>
              </div>
              <div class="doc-modal-actions">
                <button type="button" class="btn-primary btn-secondary" id="personModalCancel">取消</button>
                <button type="submit" class="btn-primary" id="personModalSave">保存</button>
              </div>
            </form>
          </div>
        </div>

        <div id="docModalBackdrop" class="doc-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="docModalTitle">
          <div class="doc-modal">
            <h3 id="docModalTitle">新增决案</h3>
            <form id="docForm">
              <div class="doc-modal-grid">
                <div class="form-group"><label>决案编号 *</label><input name="no" required pattern="[0-9]{1,3}" maxlength="3" inputmode="numeric" placeholder="例如：006"></div>
                <div class="form-group"><label>状态 *</label><select name="status" required><option value="草案">草案</option><option value="公开">公开</option><option value="保密">保密</option></select></div>
                <div class="form-group wide"><label>标题 *</label><input name="title" required maxlength="100000"></div>
                <div class="form-group"><label>影响力 *</label><select name="level" required><option>Root 级影响力</option><option>A 级影响力</option><option>B 级影响力</option><option>C 级影响力</option><option>D 级影响力</option></select></div>
                <div class="form-group wide"><label>简介 *</label><textarea name="desc" required maxlength="100000"></textarea></div>
                <div class="form-group wide"><label>正文（纯文本，每段一行） *</label><textarea name="body" required maxlength="100000" style="height:220px"></textarea></div>
              </div>
              <div class="doc-modal-actions">
                <button type="button" class="btn-primary btn-secondary" id="docModalCancel">取消</button>
                <button type="submit" class="btn-primary" id="docModalSave">保存</button>
              </div>
            </form>
          </div>
        </div>

        <!-- 决案详情 -->
        <div id="docDetail" class="page">
          <div class="docs-section">
            <div class="docs-header" style="text-align: left;">
              <h2 id="detailTitle" style="font-size: 2.5rem;"></h2>
              <p id="detailMeta"></p>
            </div>
            <div id="detailContent" class="doc-content"></div>
            <div style="text-align: center; margin-top: 3rem;">
              <a href="/database" onclick="return navigate(event, '/database')" class="btn-primary" style="display: inline-block; width: auto; text-decoration: none;">返回决案列表</a>
            </div>
          </div>
        </div>

        <!-- Space 档案 -->
        <div id="space" class="page">
          <div class="space-section">
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 1.0</h2><p>// 核心产品线 - 代号：草原</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">711 天</div><div class="val-small">2023.07.30 - 2025.07.10</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">46</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>v1.0.0.0 (2023年7月30日)</span> - <span>v1.0.1.2 (2024年3月1日)</span><br>更新内容：三色方块桌面壁纸、历史版本软件、作者提示、翻译机、退出按钮、四色方块-圆圈 logo。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>v1.0.1.3 (2024年4月20日)</span> - <span>v1.0.3.0 (2024年5月24日)</span><br>更新内容：桌边壁纸更换为蓝色圆球、更换为蓝色圆圈 logo、添加猫咪钢琴、时间显示、退出按钮更新。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(正式版)</div><div class="code-desc"><span>v1.0.3.1 (2024年5月31日)</span> - <span>v1.0.5 (2024年6月7日)</span><br>更新内容：添加画图，logo改为地球-正式logo蓝圈加蓝框叠加，添加仅有八首本地歌曲的音乐软件。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(旗舰最终版)</div><div class="code-desc"><span>v1.1 (2024年6月14日)</span><br>更新内容：调整背景，草地。</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="danger">极低</p></div>
                <div class="status-item"><h4>最初版本</h4><p>1.0.0.0 (2023.07.30)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>1.1 (2024.06.14)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="danger">下架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 2.0</h2><p>// 核心产品线 - 代号：星空</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">442 天</div><div class="val-small">2024.06.28 - 2025.09.12</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">52</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>v2.0.0.0 (1) (2024年6月28日)</span> - <span>v2.0.0.0 (2) (2024年6月29日)</span><br>更新内容：宇宙桌面壁纸、现 SP DOS 1.8 logo。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>v2.0.0 (2024年7月15日)</span> - <span>v2.0.2 (2024年7月30日)</span><br>更新内容：增加新歌、取消开机询问下载。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(正式版)</div><div class="code-desc"><span>v2.0 (2024年)</span><br>更新内容：增加只能搜索固定两条内容的浏览器、调整时间显示位置，更改开机音乐。</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p style="color:#e3b341;">低</p></div>
                <div class="status-item"><h4>最初版本</h4><p>2.0.0.0 (2024.06.28)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>2.0 (2024年)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="danger">下架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 3.0 系统</h2><p>// 核心产品线 - 代号：新的开始</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">415 天</div><div class="val-small">2025.05.09 - 2026.06.28</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">60</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>3.0 build 024 (2025年5月21日)</span> - <span>3.0 build 060 (2025年6月12日)</span><br>更新内容：更换掉 ophg 内核，使用 SP 内核，重新搭建，添加设备软件、版本记录、画图。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>3.0 build 070 (2025年6月14日)</span> - <span>3.0 build 100 (2025年6月18日)</span><br>更新内容：增加终端，添加真正的浏览器（自研 Space 浏览器 1）。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(正式版)</div><div class="code-desc"><span>3.0 build 120 (2025年6月20日)</span><br>更新内容：增加 word 文档、文件管理器、操控按钮、关机、Space 翻译。</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="normal">普通</p></div>
                <div class="status-item"><h4>最初版本</h4><p>3.0 build 024 (2025.05.21)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>3.0 build 120 (2025.06.20)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="danger">下架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 3.1 系统</h2><p>// 核心产品线 - 代号：think</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">919 天</div><div class="val-small">2025.06.27 - 2028.01.01</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">66</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>3.1 build 120 (2025年5月21日)</span><br>更新内容：增加天气软件。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(正式版)</div><div class="code-desc"><span>3.1 build 150 (2025年7月1日)</span><br>更新内容：改变操控按钮外观、提升SP内核的安全防护。</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="normal">普通</p></div>
                <div class="status-item"><h4>最初版本</h4><p>3.1 build 120 (2025.05.21)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>3.1 build 150 (2025.07.01)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="success">上架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 5 系统</h2><p>// 核心产品线 - 跨代巨作</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">1035 天</div><div class="val-small">2025.07.01 - 2028.05.01</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">71</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>5 build 172 (2025年6月16日)</span><br>更新内容：线性动画。<br><span>5 build 175 (2025年6月28日)</span><br>更新内容：添加设备软件。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>5 build 188 (2025年7月3日)</span><br>更新内容：修改 logo、开机音乐、添加 3.1 软件、去除克利商城。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Release 正式版本)</div><div class="code-desc"><span>5 build 200 (2025年10月5日)</span> - <span>5 beta 210 (2025年10月6日)</span><br><span>5 Release 295 (2025年12月6日)</span> (最终版本)</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="normal">普通</p></div>
                <div class="status-item"><h4>最初版本</h4><p>5 build 172 (2025.06.16)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>5 Release 295 (2025.12.06)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="success">上架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space 6 系统</h2><p>// 核心产品线 - 代号：background</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">819 天</div><div class="val-small">2026.02.03 - 2028.05.01</div><div class="lbl">服役时长</div></div>
                  <div class="stat-box"><div class="val">80</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>6 build 300 (2026年2月3日)</span><br>更新内容：更换系统主题<br><span>6 build 304 (2026年2月26日)</span><br>更新内容：将版本记录放置于新增软件设置中</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>5 build 307 (2026年4月5日)</span><br>更新内容：桌面壁纸可更换</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Release 正式版本)</div><div class="code-desc"><span>5 Release 350 (2026年4月6日)</span> (最终版本)</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="normal">高</p></div>
                <div class="status-item"><h4>最初版本</h4><p>6 build 300 (2026.02.03)</p></div>
                <div class="status-item"><h4>最终版本</h4><p>6 Release 350 (2026.05.01)</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="success">上架</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space Future 系统</h2><p>// 核心产品线 - 代号：new world</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">357 天</div><div class="val-small">2025.05.10 - 2026.05.01</div><div class="lbl">测试时长</div></div>
                  <div class="stat-box"><div class="val">40</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>Future build 1 (2025年5月10日)</span><br>更新内容：更换系统主题</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>Future build 5 (2025年7月18日)</span><br>更新内容：更新软件：文件管理、终端、画图、控制面板。增加关机与重启。</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Release 正式版本)</div><div class="code-desc"><span>Future build 10 (2026年5月1日)</span>（最终版本）</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="danger">无</p></div>
                <div class="status-item"><h4>最初版本</h4><p>Future build 1（2025.05.10）</p></div>
                <div class="status-item"><h4>最终版本</h4><p>Future build 10（2026.05.01）</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="danger">下架（项目已重启）</p></div>
              </div>
            </div>
            <div class="version-container">
              <div class="space-header">
                <div class="space-title"><h2>Space ELITE 系统</h2><p>// 核心产品线 - 代号：ELITE</p></div>
                <div class="space-stats">
                  <div class="stat-box"><div class="val">807 天</div><div class="val-small">2026.02.16 - 2028.05.01</div><div class="lbl">测试时长</div></div>
                  <div class="stat-box"><div class="val">78</div><div class="lbl">综合评分</div></div>
                </div>
              </div>
              <div class="code-block">
                <div class="code-line"><div class="code-title">(Alpha 阶段)</div><div class="code-desc"><span>ELITE build 1 (2026年2月16日)</span><br>更新内容：删除冗余代码</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Beta 阶段)</div><div class="code-desc"><span>ELITE build 5 (2026年4月16日)</span><br>更新内容：更换桌面布局</div></div>
                <div class="code-line" style="margin-top:1.5rem;"><div class="code-title">(Release 正式版本)</div><div class="code-desc"><span>ELITE build 10 (2026年7月20日)</span>（最终版本）</div></div>
              </div>
              <div class="status-grid">
                <div class="status-item"><h4>安全程度</h4><p class="normal">安全</p></div>
                <div class="status-item"><h4>最初版本</h4><p>ELITE build 1（2026.02.16）</p></div>
                <div class="status-item"><h4>最终版本</h4><p>ELITE build 10（2026.07.20）</p></div>
                <div class="status-item"><h4>克利DVD市场情况</h4><p class="success">上架</p></div>
              </div>
            </div>
            <div style="text-align: center; margin-top: 3rem;">
               <a href="https://ccw.site" target="_blank" rel="noopener noreferrer" class="btn-primary" style="display: inline-block; width: auto; text-decoration: none;">前往 Space 线上平台</a>
            </div>
          </div>
        </div>

        <!-- 历史时间线 -->
        <div id="history" class="page">
          <div class="history-section">
            <h2>克利历程</h2>
            <p class="subtitle">六年磨砺，不断进化。</p>
            <div class="timeline">
              <div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-date">2020年9月18日</div><div class="timeline-content"><h3>克利室成立</h3><p>成立于上海市静安区，起名为“克利室”，主要工作是回收旧家具。</p></div></div>
              <div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-date">2022年</div><div class="timeline-content"><h3>克利社团诞生</h3><p>组织更名为“克利社团”，并开始转型制作短视频内容。</p></div></div>
              <div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-date">2023年7月30日</div><div class="timeline-content"><h3>踏入编程领域</h3><p>团队再次改行，并于当日正式开始制作 Space 系列项目。</p></div></div>
              <div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-date">2024年</div><div class="timeline-content"><h3>更名为上海静安克利社团</h3><p>进一步明确地域与组织属性，更名为“上海静安克利社团”。</p></div></div>
              <div class="timeline-item"><div class="timeline-dot"></div><div class="timeline-date">2025年10月4日</div><div class="timeline-content"><h3>上海克利工作室</h3><p>正式改名为“上海克利工作室”，以全新的高端数字品牌形象面向大众。</p></div></div>
              <div class="timeline-item"><div class="timeline-dot" style="background: #fff; box-shadow: 0 0 15px #fff;"></div><div class="timeline-date">2026年 至今</div><div class="timeline-content"><h3>持续进化</h3><p>深耕互联网产品研发与设计，探索更多未知的可能性。</p></div></div>
            </div>
          </div>
        </div>

        <!-- 加入我们 -->
        <div id="join" class="page">
          <div class="form-section">
            <h2>加入我们</h2>
            <p class="subtitle">填写以下信息，我们期待与你共同创造。</p>
            <form id="joinForm">
              <div class="form-group"><label>姓名 *</label><input type="text" name="name" required maxlength="100000" placeholder="请输入您的姓名"></div>
              <div class="form-group"><label>性别 *</label>
                <select name="gender" required>
                  <option value="" disabled selected>请选择性别</option>
                  <option value="男">男</option><option value="女">女</option><option value="其他">其他</option>
                </select>
              </div>
              <div class="form-group"><label>年龄 *</label><input type="number" name="age" required maxlength="100000" placeholder="请输入您的年龄" min="1" max="120"></div>
              <div class="form-group"><label>兴趣爱好</label><input type="text" name="hobbies" maxlength="100000" placeholder="例如：摄影、编程、音乐"></div>
              <div class="form-group"><label>特长</label><textarea name="skills" maxlength="100000" placeholder="请描述您的特长或专业技能"></textarea></div>
              <div class="form-group"><label>联系方式（微信 / QQ / 电话号码） *</label><input type="text" name="contact" required maxlength="100000" placeholder="请输入您的联系方式"></div>
              <p class="join-disclaimer">你的个人信息不会被储存，只会发送到社长1号的钉钉机器人私信里，克利基金会有义务保管你的个人信息免遭泄露，法律责任由我们的运营公司承担。</p>
              <div class="turnstile-box cf-turnstile" data-sitekey="0x4AAAAAAGMcQoQ2a13CrMJ_"></div>
              <button type="submit" class="btn-primary" id="submitBtn">提交申请</button>
            </form>
          </div>
        </div>

        <!-- 管理员登录 -->
        <div id="login" class="page">
          <div class="form-section">
            <h2>管理员登录</h2>
            <p class="subtitle">请输入管理员密码以继续。</p>
            <form id="loginForm">
              <div class="form-group">
                <label for="loginPassword">密码 *</label>
                <div class="password-input-wrap">
                  <input id="loginPassword" type="password" name="password" required maxlength="100000" placeholder="请输入密码" autocomplete="current-password">
                  <button type="button" class="password-toggle" id="passwordToggle" aria-label="显示密码" aria-pressed="false" title="显示密码">
                    <svg data-password-icon="show" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" hidden>
                      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                    <svg data-password-icon="hide" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <path d="M3 12c2.4 2.5 5.4 3.8 9 3.8s6.6-1.3 9-3.8"/>
                      <path d="M5.5 13.2l-1.7 1.8"/>
                      <path d="M9.2 14.7l-.7 2.1"/>
                      <path d="M14.8 14.7l.7 2.1"/>
                      <path d="M18.5 13.2l1.7 1.8"/>
                    </svg>
                  </button>
                </div>
              </div>
              <div class="turnstile-box cf-turnstile" data-sitekey="0x4AAAAAAGMcQoQ2a13CrMJ_"></div>
              <button type="submit" class="btn-primary" id="loginBtn">登录</button>
              <div id="loginMsg" style="margin-top: 1rem; text-align: center; font-size: 0.9rem; min-height: 1.4em;"></div>
            </form>
          </div>
        </div>

        <footer class="footer">
          <div class="footer-brand">© 2026 上海克利工作室 · Shanghai Keli work studio</div>
          <div class="footer-disclaimer">本社区是上海深深漫文化传媒有限公司提供资金支持的学生社团，非独立法人，不对外募捐，法律责任由深深漫承担。上海克利工作室是上海深深漫克利非盈利组织社区的品牌名。</div>
        </footer>
      </div>

      <div id="logoutModal" class="app-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="logoutModalTitle">
        <div class="app-modal">
          <h3 id="logoutModalTitle">确定要登出吗？</h3>
          <p>登出后需要重新输入管理员密码。</p>
          <div class="app-modal-actions">
            <button type="button" class="btn-primary app-modal-cancel" id="logoutCancel">取消</button>
            <button type="button" class="btn-primary" id="logoutConfirm">确定登出</button>
          </div>
        </div>
      </div>

      <div id="deleteConfirmModal" class="app-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="deleteConfirmTitle" aria-describedby="deleteConfirmMessage">
        <div class="app-modal">
          <h3 id="deleteConfirmTitle">确认删除？</h3>
          <p id="deleteConfirmMessage"></p>
          <div class="app-modal-actions">
            <button type="button" class="btn-primary app-modal-cancel" id="deleteConfirmCancel">取消</button>
            <button type="button" class="btn-primary" id="deleteConfirmAccept" style="background:#ef4444">确认删除</button>
          </div>
        </div>
      </div>

      <script>
        window.onerror = function(msg, url, line, col, err) {
          var box = document.getElementById('__err__');
          if (!box) {
            box = document.createElement('div');
            box.id = '__err__';
            box.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#b3261e;color:#fff;padding:10px 14px;font-family:monospace;font-size:12px;z-index:99999;white-space:pre-wrap;';
            document.body.insertBefore(box, document.body.firstChild);
          }
          box.textContent = '⚠ JS 错误：' + msg + ' | ' + (url || '') + ':' + line + ':' + col;
        };

        // ================= 决案数据 =================
        var DOCS = [
          { no: '001', title: '“一切的基本规则”', status: '草案', level: 'Root 级影响力', visibility: '公开',
            desc: '社区定位、基金会与伦理道德委员会的构成与职权、表决程序、决案影响力分级与档案库管理。',
            sections: [ { heading: null, blocks: [
              { t:'p', text:'上海深深漫克利非盈利组织社区，即 Shanghai ShenShenMan Keli Organization Community，即克利工作室（Keli 或 KL），全称会在运营公司改变时变动。' },
              { t:'p', text:'最高决策层为：上海深深漫克利非盈利组织社区基金会（Shanghai ShenShenMan Keli Organization Community Foundation），由六名成员组成（工号：1、2、3、8、10、17），负责发表指令、提供资金、组织活动。基金会成员享有提案权、表决权、资金申请权；同时承担决策责任、公开账目义务、接受伦理委员会审核的义务。' },
              { t:'p', text:'资金由资金管理员保管。资金管理员不得同时是基金会成员或伦理委员会成员。资金管理员每季度向伦理委员会提交资金流水，公开给全体社员。大额支出（超过 2500 元）需基金会 + 伦理委员会双签。资金管理员由基金会提名，伦理委员会审核，全体社员大会通过。全体社员大会需 1/2 以上社员出席方为有效；表决需出席人数 2/3 多数通过。大会由基金会召集，每年至少一次。资金管理员变更时，需在基金会 + 伦理委员会 + 全程电子录像或直播共同见证下，当场核对流水、移交账户、签署交接单。交接单存入档案库。' },
              { t:'p', text:'最高审核层为：上海深深漫克利非盈利组织社区伦理道德委员会（Shanghai ShenShenMan Keli Organization Ethics and Morality Committee），由三名连续 6 个月无冻结记录、无举报成立记录、无欠费记录（认定权归伦理委员会，名单每季度更新）的开发者担任（不得是基金会成员或资金管理员），新开发者入社满 3 个月且无违规，可豁免 6 个月限制。每个季度换一次伦理道德委员会成员（随机从符合的名单中抽取，上个季度担任过的不得连任）。伦理道德委员会有权查阅非保密的决策记录和资金流水。伦理道德委员会有权要求基金会书面说明决策理由。伦理道德委员会有权对涉嫌违规的决策发起重新表决。伦理委员会发起重新表决后，若基金会仍以多数通过，该决案生效。但伦理委员会有权将反对意见附在决案档案中，一并公开。' },
              { t:'p', text:'伦理道德委员会成员在担任该职位时权利与责任相当。决案由基金会成员提出并举手表决，基金会表决需至少 4 人出席，赞成票超过出席人数半数方可通过。后交给伦理道德委员会审核，伦理道德委员会举手表决，伦理委员会表决需至少 2 人出席，赞成票超过出席人数半数方可通过。伦理道德委员会无决策权，仅检查基金会的决定。决案有公开和保密，保密状态下仍需伦理委员会审核，但参与审核的伦理道德委员会成员需保密且应限制人数（暂定 1 人）。保密决案审核由伦理委员会内部推选 1 人，该成员不得与决案有利益关系。审核意见需书面记录，密封存入档案库。伦理委员会成员与决案有直接利益关系的，应主动回避或由其他两名成员一致要求其回避。回避后，该决案由剩余成员表决，需全体一致方可通过。' },
              { t:'p', text:'决案影响力由高到低分别是 Root、A、B、C、D，下级决案不得违反上级决案；同级决案冲突时，以时间较晚者为准，或提交伦理委员会仲裁。' },
              { t:'p', text:'档案库由基金会指定一名记录员维护，任期与基金会同步。记录员变更时，需在伦理委员会见证下移交全部档案。所有公开决案存于 Gandi 本地列表（为防止发生服务器损坏导致错误代码覆盖重要数据）+ 本地电脑备份（基金会成员的电脑），保密决案仅存离线加密文件。全体社员有权查阅公开决案。' },
              { t:'note', text:'本决案标注：生效日期与最后更改日期均为「暂未进行表决，仅为草稿」。' }
            ]} ]
          },
          { no: '002', title: '成员招募、除名与退出机制', status: '草案', level: 'Root 级影响力', visibility: '公开',
            desc: '开发者招募流程、除名情形与除名程序、基金会成员及非开发者处理、自行退出与重新加入。',
            sections: [
              { heading: '一、开发者招募', blocks: [ { t:'ol', items:[ '开发者由基金会成员招募，上报社长（工号 1）同意后，交伦理道德委员会审核，通过后加入开发者名单。', '招募标准、考核方式由基金会另行制定，公开给全体社员。' ]} ]},
              { heading: '二、开发者除名', blocks: [ { t:'ol', items:[
                { text:'开发者有下列情形之一，视情节轻重由基金会提出除名：', sub:[ '不遵守决策、不遵守纪律；', '私自复制、窃取高等级授权；', '传播保密决策；', '长期不活跃（连续 6 个月无活动且无请假）；', '其他严重损害社区的行为。' ]},
                { text:'除名程序：', sub:[ '基金会提案；', '伦理委员会 7 日内出具书面审核意见，逾期视为审核通过，但须在下次会议补交说明；', '基金会表决（至少 4 人出席，赞成过半）；', '移除开发者名单；', '销毁授权卡：由基金会 + 伦理委员会共同见证，全程录像，销毁记录存入档案库。' ]},
                '被处理人有权在表决前提交书面申辩，申辩材料存入档案库。未给予申辩机会的，处理决定无效。',
                '被除名 2 次的，终身不得再次加入；经全体社员大会出席人数 2/3 多数同意恢复的除外。恢复后须重新考核，并降为最低权限等级。'
              ]} ]},
              { heading: '三、基金会成员及非开发者处理', blocks: [ { t:'ol', items:[
                '基金会成员或非开发者损害社区、不遵守决策的，由伦理委员会或 1/3 以上社员联名提出，提交全体社员大会讨论。',
                '表决按 001 号规定的全体社员大会程序进行，被处理人回避表决。',
                '处理方式包括：降级、暂停权限、除名。',
                '被处理人有权提交书面申辩，申辩材料存档。未给予申辩机会的处理决定无效。'
              ]} ]},
              { heading: '四、自行退出', blocks: [ { t:'ol', items:[ '自行退出须向基金会书面备案。', '退出后工号冻结、权限卡注销、资金结算完毕。', '退出满 6 个月可申请重新加入，须重新走招募流程。' ]}, { t:'note', text:'生效说明：本决案依据 001 号决案规定的程序表决通过，自签字之日起生效。解释权归伦理道德委员会。修改程序同 001 号决案。' } ]}
            ]
          },
          { no: '003', title: '与深深漫公司关系、非盈利性质和开源性的详细解释', status: '草案', level: 'Root 级影响力', visibility: '公开',
            desc: '社区与深深漫公司的法律关系、非盈利性与开源性边界、业务范围、内部积分与区块链学习、非开发者权限。',
            sections: [
              { heading: '一、总则', blocks: [ { t:'ol', items:[
                '上海深深漫克利非盈利组织社区（以下简称“社区”）是上海深深漫文化传媒有限公司（以下简称“深深漫”）提供资金支持的学生社团，不是独立法人。社区品牌名称仅用于社区内部和日常对外描述，法律主体为深深漫。',
                '社区纪律由克利基金会负责。法律责任由深深漫承担，发票由深深漫签署。社区对外一切法律行为，均须以深深漫名义进行，由深深漫法定代表人签字或授权。社区成员个人对外行为，由个人承担，与深深漫无关。',
                '社区主要业务范围分为社区学习与创作实践、深深漫商业业务两类，具体见第四条。'
              ]} ]},
              { heading: '二、与深深漫公司的关系', blocks: [ { t:'ol', items:[
                '深深漫向社区提供无偿资助或专项经费支持，具体金额和用途由基金会申请、深深漫审批，账目公开。如需借款，由深深漫作为法人主体签署借款协议，明确利息、期限、用途，不得以社区名义口头借款。',
                '深深漫的启动资金仅能在紧急情况下并且深深漫负责人签署后方可动用，详见 004 号决案。本决案不公开启动资金的具体金额，相关金额由深深漫内部掌握。社区成员不得以任何方式对外宣传、猜测或传播具体数额。',
                '社区内部账目由资金管理员管理，受深深漫财务监督。大额支出按 001 号决案执行。社区公共资产须登记，写明保管人和用途。',
                '紧急情况下，克利基金会可以请求深深漫公司进行强制干涉，具体程序、边界和时限按 004 号决案执行，本决案不另设口子。'
              ]} ]},
              { heading: '三、非盈利性和开源性的边界', blocks: [ { t:'ol', items:[
                '社区内部活动不以盈利为目的，收入归深深漫或用于社区经费，账目公开。对外商业项目由深深漫签约收款。',
                '社区原创的 Blend 文件、模型、材质、代码、教程等，按 CC BY-SA 4.0 开源。最终成片和商业项目保留权利，不自动适用 CC BY-SA 4.0。',
                '第三方素材（音乐、声库、字体、贴图、动捕数据等）逐个核查授权，不能授权的不得纳入开源包。开源包须附 CREDITS 文件，列明素材来源和许可证。',
                '贡献者提交贡献，即同意其贡献内容按 CC BY-SA 4.0 发布。社区须保留贡献者名单和署名要求。',
                '开源许可证一经发布不可撤回。发布前须完成第三方素材清理和许可证文件、README、CREDITS 的整理。'
              ]} ]},
              { heading: '四、业务范围', blocks: [ { t:'ol', items:[
                '社区学习与创作实践包括：音乐、短视频、电台、游戏与影视开发学习、软件学习与原型制作、展会活动策划练习、区块链技术学习与研究。',
                '深深漫商业业务包括：对外发行、运营、代制作、网络环境搭建等。上述商业业务一律以深深漫名义签约、收款、开票，由深深漫法定代表人签字或授权。社区成员可在深深漫安排下参与学习实践，不对外独立签约，不独立收款，不以社区名义承接商业业务。',
                '除深深漫商业业务外，社区活动遵守非盈利性和开源性。展会与活动布置、代理制作与搭建等商业安排，以深深漫为法律代表进行。'
              ]} ]},
              { heading: '五、内部积分与区块链学习', blocks: [ { t:'ol', items:[
                '社区可设立内部积分系统，仅用于社区内部奖励和任务结算，由基金会统一记录在社区数据库。',
                '内部积分不与真实货币兑换，不对外交易，不上链，不挖矿，不发行任何形式的代币。',
                '社区可开展区块链技术的学习与研究，包括测试网实验和内部积分系统设计，但不得发行任何形式的代币，不得进行或参与虚拟货币挖矿，不得将社区积分与真实货币或虚拟货币兑换，不涉及真实资金和跨境部署。',
                '深深漫不为任何虚拟货币发行、挖矿或交易行为提供签约、收款、开票或场地支持。'
              ]} ]},
              { heading: '六、非开发者与权限', blocks: [ { t:'ol', items:[
                '一般情况下，非开发者（如资金管理员、顾问、外部协助人员）由深深漫公司提名或选出，基金会备案。',
                '涉及社区权限和数据的非开发者，须经伦理委员会审核，确认无利益冲突后方可授予相应权限。',
                '非开发者不得以社区名义对外签约、收款或承接商业业务。'
              ]} ]},
              { heading: '七、附则', blocks: [ { t:'ol', items:[
                '本决案由基金会提案，伦理委员会审核，全体社员大会按 001 号规定表决通过后生效。',
                '解释权归伦理委员会。修改程序同 001 号决案。',
                '本决案不公开深深漫启动资金的具体金额，社区成员不得对外宣传、猜测或传播具体数额。',
                '本决案与 001 号、002 号、004 号决案冲突时，按 001 号规定的同级冲突规则处理。'
              ]} ]}
            ]
          },
          { no: '004', title: '紧急情况', status: '草案', level: 'Root 级影响力', visibility: '公开',
            desc: '紧急情形的定义、紧急状态的宣布与权限、深深漫强制干涉、终止与补审程序。',
            sections: [
              { heading: '一、目的', blocks: [ { t:'p', text:'为应对社区运营中可能出现的突发风险，明确紧急状态的宣布、处置、补审和终止程序，防止紧急权力被滥用，特制定本决案。' } ]},
              { heading: '二、紧急情形的定义', blocks: [ { t:'p', text:'本决案所称紧急情况，指下列情形之一：' }, { t:'ol', items:[
                '社区账号、云数据、终端系统遭受攻击、泄露、篡改或大规模故障；',
                '社区资金被盗、被骗、账目出现重大异常；',
                '成员严重违规，可能造成数据泄露、资产损失或人身安全风险；',
                '涉及深深漫公司或社区的法律、税务、监管风险，需立即处置；',
                '其他经基金会认定的突发重大风险。'
              ]} ]},
              { heading: '三、紧急状态的宣布', blocks: [ { t:'ol', items:[
                '紧急状态由基金会两名以上成员联名宣布，或由深深漫负责人书面提出。',
                '宣布时须书面说明：紧急事由、影响范围、拟采取的措施、预计持续时间。',
                '宣布后立即通知伦理委员会全体成员，并记录在档案库。',
                '紧急状态最长持续 72 小时。确需延长的，须经基金会至少 4 人出席表决，赞成过半，且每次延长不超过 24 小时。'
              ]} ]},
              { heading: '四、紧急状态下的权限', blocks: [ { t:'ol', items:[
                '紧急状态下，基金会可先行采取必要措施，包括暂停账号、冻结权限、封存数据、暂停资金支出、请求深深漫强制干涉等。',
                '可临时跳过伦理委员会审核，但须在 48 小时内补交书面材料，由伦理委员会追认审核。逾期未补交的，紧急措施自动失效。',
                '紧急状态下的资金支出，须设定上限，由基金会当场记录，至少两人见证，并在 48 小时内向伦理委员会和资金管理员补交凭证。',
                '涉及深深漫启动资金的动用，仅限紧急情况，且须深深漫负责人书面签署，基金会记录备案。具体金额不公开。'
              ]} ]},
              { heading: '五、强制干涉', blocks: [ { t:'ol', items:[
                '紧急情况下，基金会可书面请求深深漫公司进行强制干涉。请求须写明事由、范围、期限和具体措施。',
                '强制干涉由深深漫负责人书面签署后执行，基金会记录全过程。',
                '强制干涉不得超出请求范围，不得用于处理普通纪律争议，不得替代 002 号决策规定的除名和退出程序。',
                '强制干涉结束后，深深漫和基金会须共同出具书面报告，存入档案库。'
              ]} ]},
              { heading: '六、终止与补审', blocks: [ { t:'ol', items:[
                '紧急状态到期自动终止，或由基金会宣布提前终止。',
                '终止后 7 日内，基金会须向伦理委员会提交完整报告，包括事由、措施、支出、影响和后续处理建议。',
                '伦理委员会有权对紧急状态下的措施进行审核，认为不当的，可要求基金会说明、纠正或提交全体社员大会讨论。',
                '滥用紧急状态、超范围强制干涉、虚假宣布紧急情况的，按 002 号决案追究责任。'
              ]} ]},
              { heading: '七、附则', blocks: [ { t:'ol', items:[
                '本决案由基金会提案，伦理委员会审核，全体社员大会按 001 号规定表决通过后生效。因涉及 Root 级影响力，表决前须公示 7 日。',
                '解释权归伦理委员会。修改程序同 001 号决案。',
                '本决案与 001 号、002 号、003 号决案冲突时，按 001 号规定的同级冲突规则处理。',
                '本决案不公开深深漫启动资金的具体金额，社区成员不得对外宣传、猜测或传播具体数额。'
              ]} ]}
            ]
          },
          { no: '005', title: '克利基金会官方网站', status: '草案', level: 'Root 级影响力', visibility: '公开',
            desc: '官方域名与主体、内容审核规则、服务器与数据安全要求、子域名规划、资产登记与变更审批。',
            sections: [
              { heading: '一、域名与主体', blocks: [ { t:'ol', items:[
                '官方网址 kelifoundation.org，注册于 Cloudflare。',
                '网站主体为上海深深漫克利非盈利组织社区，法律主体为上海深深漫文化传媒有限公司。网站首页和页脚须声明：本社区是深深漫提供资金支持的学生社团，非独立法人，不对外募捐，法律责任由深深漫承担。'
              ]} ]},
              { heading: '二、内容审核', blocks: [ { t:'ol', items:[
                '网站内容由克利基金会指定的网站内容负责人审核，伦理委员会备案。',
                '不得包含违法内容、政治敏感内容、侵权内容、泄露隐私内容、未经授权的保密决案。',
                '涉及社区决案、资金、成员信息的，须基金会审核；涉及深深漫商业信息的，须深深漫书面同意。',
                '发现违规内容立即下架，记录存档，按 002 号决案处理。'
              ]} ]},
              { heading: '三、服务器与数据', blocks: [ { t:'ol', items:[
                '网站服务器由深深漫安排，拟放置于 Packsize 香港提供的场地内。该场地为关联方场地，不是社区自有资产。具体地址、场地使用条件、合同主体、管理责任，在《克利社区分社详细表格》中登记，并以深深漫与 Packsize 香港的书面协议为准。',
                '服务器系统管理权限由深深漫指定的管理员持有，社区成员不得单独持有服务器 root 权限。网站内容负责人负责内容审核，不持有服务器 root 权限。',
                '网站须启用 HTTPS、访问日志、定期备份、管理员双因素认证。涉及个人信息存储的，须说明用途、保存期限、访问权限，不得超范围收集。未成年人信息须加强访问控制。',
                '如使用内地 CDN 或内地解析服务，须评估备案和合规要求。香港服务器不自动豁免内地内容合规义务。'
              ]} ]},
              { heading: '四、子域名', blocks: [ { t:'ol', items:[
                'network：网络环境相关学习与实践内容。',
                'points：社区内部积分系统说明，仅用于内部奖励和任务结算，不与真实货币兑换，不对外交易，不上链，不挖矿，不发行任何形式的代币。',
                'developer：开发者公开信息、招募信息、公开决案、项目展示。不得放置密码、完整工号、举报细节、保密决案。'
              ]} ]},
              { heading: '五、资产与变更', blocks: [ { t:'ol', items:[
                '域名和服务器登记为社区资产，写明注册商、账号保管人、到期日、续费价格、服务器位置、管理员、备份方案。',
                '子域名增减、服务器迁移，须基金会提案、伦理委员会审核。'
              ]} ]},
              { heading: '六、附则', blocks: [ { t:'ol', items:[
                '本决案由基金会提案，伦理委员会审核，全体社员大会按 001 号规定表决通过后生效。因涉及 Root 级影响力，表决前须公示 7 日。',
                '解释权归伦理委员会。修改程序同 001 号决案。',
                '与 001、002、003、004 号冲突时，按 001 号同级冲突规则处理。'
              ]} ]}
            ]
          }
        ];

        // ================= 工具函数 =================
        var esc = function(s){ return String(s).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

        function renderList(items, tag) {
          return '<' + tag + '>' + items.map(function(it) {
            if (typeof it === 'string') return '<li>' + esc(it) + '</li>';
            var sub = it.sub ? '<ul>' + it.sub.map(function(s){ return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>' : '';
            return '<li>' + esc(it.text) + sub + '</li>';
          }).join('') + '</' + tag + '>';
        }
        function renderBlock(b) {
          if (b.t === 'p') return '<p>' + esc(b.text) + '</p>';
          if (b.t === 'ol') return renderList(b.items, 'ol');
          if (b.t === 'ul') return renderList(b.items, 'ul');
          if (b.t === 'note') return '<div class="doc-note">' + esc(b.text) + '</div>';
          return '';
        }
        function renderSection(s) {
          var head = s.heading ? '<h3>' + esc(s.heading) + '</h3>' : '';
          return '<section>' + head + s.blocks.map(renderBlock).join('') + '</section>';
        }

        // ================= 渲染决案列表 =================
        var docsGrid = document.getElementById('docsGrid');
        var dbDocs = [];
        var deletedDocs = [];
        var adminMode = false;
        var editingDocNo = null;
        var people = [];
        var peopleLoadError = '';
        var editingPersonNo = null;
        var branches = [];
        var editingBranchId = null;

        var peopleBody = document.getElementById('peopleTableBody');
        var peopleSearch = document.getElementById('peopleSearch');
        var peopleEmpty = document.getElementById('peopleEmpty');
        var peopleCount = document.getElementById('peopleCount');
        var peopleAdminToolbar = document.getElementById('peopleAdminToolbar');
        var peopleActionsHeading = document.getElementById('peopleActionsHeading');
        var editIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 19.5 4 21l1.5-5.5L17 5a2.12 2.12 0 0 1 3 3L8 18.5 5 19.5Z"/><path d="M14.5 7.5l3 3"/></svg>';
        var deleteIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V3h8v3"/><path d="M19 6l-1 15H6L5 6"/><path d="M10 10v7M14 10v7"/></svg>';
        var copyIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>';
        var checkIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l4 4L19 6"/></svg>';

        function sortedPeople(items) {
          return items.slice().sort(function(a, b) {
            return String(a.developer_no).localeCompare(String(b.developer_no), undefined, { numeric: true, sensitivity: 'base' });
          });
        }

        function renderPeople() {
          if (!peopleBody) return;
          var query = peopleSearch.value.trim().toLocaleLowerCase();
          var visiblePeople = sortedPeople(people).filter(function(person) {
            return !query || String(person.name).toLocaleLowerCase().includes(query);
          });
          peopleAdminToolbar.hidden = !adminMode;
          peopleActionsHeading.hidden = !adminMode;
          peopleBody.innerHTML = visiblePeople.map(function(person) {
            var actions = adminMode
              ? '<td><div class="people-actions">' +
                  '<button type="button" class="doc-icon-btn doc-edit" data-person-edit="' + esc(person.developer_no) + '" aria-label="编辑人员 ' + esc(person.developer_no) + '" title="编辑">' + editIcon + '</button>' +
                  '<button type="button" class="doc-icon-btn doc-delete" data-person-delete="' + esc(person.developer_no) + '" aria-label="删除人员 ' + esc(person.developer_no) + '" title="删除">' + deleteIcon + '</button>' +
                '</div></td>'
              : '';
            var hasLeft = person.left_at !== null && person.left_at !== undefined && String(person.left_at).trim() !== '';
            var isCandidate = Number(person.is_candidate) === 1;
            var statusClass = hasLeft ? 'left' : isCandidate ? 'candidate' : 'active';
            var statusLabel = hasLeft ? '已离职' : isCandidate ? '伦理道德委员会成员候选人' : '在职';
            var statusDot = adminMode && !hasLeft
              ? '<button type="button" class="people-status-toggle" data-person-candidate="' + esc(person.developer_no) + '" aria-label="切换' + statusLabel + '" title="' + statusLabel + '"><span class="people-status-dot ' + statusClass + '"></span></button>'
              : '<span class="people-status-dot ' + statusClass + '" title="' + statusLabel + '" aria-label="' + statusLabel + '"></span>';
            return '<tr>' +
              '<td class="people-status-cell">' + statusDot + '</td>' +
              '<td>' + esc(person.developer_no) + '</td>' +
              '<td>' + esc(person.name) + '</td>' +
              '<td>' + esc(person.gender) + '</td>' +
              '<td>' + esc(person.department) + '</td>' +
              '<td>' + esc(person.rank) + '</td>' +
              '<td>' + esc(person.joined_at || '—') + '</td>' +
              '<td>' + esc(person.left_at || '—') + '</td>' +
              '<td>' + esc(person.rejoin_type) + '</td>' +
              actions +
            '</tr>';
          }).join('');
          peopleCount.textContent = '共 ' + visiblePeople.length + ' 人';
          peopleEmpty.hidden = visiblePeople.length > 0;
          peopleEmpty.textContent = visiblePeople.length ? '' : peopleLoadError || (query ? '没有找到匹配的人员' : '暂无人员资料');
        }

        async function loadPeople() {
          try {
            var response = await fetch('/api/people', { credentials: 'same-origin' });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '人员资料加载失败');
            people = Array.isArray(data.people) ? data.people : [];
            peopleLoadError = '';
          } catch (error) {
            people = [];
            peopleLoadError = '人员资料加载失败：' + error.message;
          }
          renderPeople();
        }

        function openPersonModal(person) {
          editingPersonNo = person ? person.developer_no : null;
          var form = document.getElementById('personForm');
          document.getElementById('personModalTitle').textContent = person ? '编辑人员' : '新增人员';
          form.elements.namedItem('developer_no').value = person ? person.developer_no : '';
          form.elements.namedItem('developer_no').disabled = !!person;
          form.elements.namedItem('name').value = person ? person.name : '';
          form.elements.namedItem('gender').value = person ? person.gender : '男';
          form.elements.namedItem('department').value = person ? person.department : '';
          form.elements.namedItem('rank').value = person ? person.rank : '';
          form.elements.namedItem('joined_at').value = person ? person.joined_at : '';
          form.elements.namedItem('left_at').value = person ? person.left_at || '' : '';
          form.elements.namedItem('rejoin_type').value = person ? person.rejoin_type : '一职';
          document.getElementById('personModalBackdrop').classList.add('show');
        }

        function closePersonModal() {
          document.getElementById('personModalBackdrop').classList.remove('show');
          document.getElementById('personForm').elements.namedItem('developer_no').disabled = false;
          editingPersonNo = null;
        }

        peopleSearch.addEventListener('input', renderPeople);
        document.getElementById('personAddBtn').addEventListener('click', function() { openPersonModal(null); });
        peopleBody.addEventListener('click', function(event) {
          var candidateButton = event.target.closest('[data-person-candidate]');
          if (candidateButton) {
            toggleCandidate(candidateButton.dataset.personCandidate);
            return;
          }
          var editButton = event.target.closest('[data-person-edit]');
          if (editButton) {
            openPersonModal(people.find(function(person) { return person.developer_no === editButton.dataset.personEdit; }));
            return;
          }
          var deleteButton = event.target.closest('[data-person-delete]');
          if (deleteButton) deletePerson(deleteButton.dataset.personDelete);
        });

        function joinedDays(joinedAt) {
          var match = /^(\\d{4})-(\\d{2})-(\\d{2})(?:$|T)/.exec(String(joinedAt || ''));
          if (!match) return null;
          var year = Number(match[1]);
          var month = Number(match[2]);
          var day = Number(match[3]);
          var joinedDate = new Date(year, month - 1, day);
          if (joinedDate.getFullYear() !== year || joinedDate.getMonth() !== month - 1 || joinedDate.getDate() !== day) return null;
          var joinedTime = Date.UTC(year, month - 1, day);
          var now = new Date();
          var todayTime = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
          return Math.floor((todayTime - joinedTime) / 86400000);
        }

        async function toggleCandidate(developerNo) {
          var person = people.find(function(item) { return item.developer_no === developerNo; });
          if (!person) return;
          var enable = Number(person.is_candidate) !== 1;
          var daysSinceJoined = joinedDays(person.joined_at);
          if (enable && daysSinceJoined !== null && daysSinceJoined < 7) {
            var confirmed = await showActionConfirmation('入社未满7天，是否继续？', '该开发者入社未满7天，仍可继续设为伦理道德委员会成员候选人。', '确定', '#22c55e');
            if (!confirmed) return;
          }
          try {
            var response = await fetch('/api/committee/candidates', {
              method: 'PUT',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ developer_no: developerNo, candidate: enable })
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '候选人状态更新失败');
            person.is_candidate = enable ? 1 : 0;
            renderPeople();
            toast(enable ? '已设为伦理道德委员会成员候选人' : '已取消候选人状态', false);
          } catch (error) {
            toast(error.message, true);
          }
        }

        async function deletePerson(developerNo) {
          if (!await showDeleteConfirmation('删除人员资料', '确定删除开发者编号 ' + developerNo + ' 的人员资料吗？此操作无法撤销。')) return;
          try {
            var response = await fetch('/api/people', {
              method: 'DELETE',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ developer_no: developerNo })
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '删除失败');
            people = people.filter(function(person) { return person.developer_no !== developerNo; });
            renderPeople();
            toast('人员资料已删除', false);
          } catch (error) {
            toast(error.message, true);
          }
        }

        document.getElementById('personModalCancel').addEventListener('click', closePersonModal);
        var developerNoInput = document.getElementById('personForm').elements.namedItem('developer_no');
        function normalizeDeveloperNo(value) {
          var trimmed = value.trim();
          return /^\d{1,3}$/.test(trimmed) ? trimmed.padStart(3, '0') : trimmed;
        }
        developerNoInput.addEventListener('blur', function() {
          developerNoInput.value = normalizeDeveloperNo(developerNoInput.value);
        });
        document.getElementById('personModalBackdrop').addEventListener('click', function(event) {
          if (event.target === this) closePersonModal();
        });
        document.getElementById('personForm').addEventListener('submit', async function(event) {
          event.preventDefault();
          if (!editingPersonNo) developerNoInput.value = normalizeDeveloperNo(developerNoInput.value);
          var form = event.target;
          var saveButton = document.getElementById('personModalSave');
          var wasEditing = !!editingPersonNo;
          saveButton.disabled = true;
          saveButton.textContent = '保存中...';
          var person = {
            developer_no: editingPersonNo || developerNoInput.value,
            name: form.elements.namedItem('name').value.trim(),
            gender: form.elements.namedItem('gender').value,
            department: form.elements.namedItem('department').value.trim(),
            rank: form.elements.namedItem('rank').value.trim(),
            joined_at: form.elements.namedItem('joined_at').value,
            left_at: form.elements.namedItem('left_at').value,
            rejoin_type: form.elements.namedItem('rejoin_type').value
          };
          try {
            var response = await fetch('/api/people', {
              method: wasEditing ? 'PUT' : 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(person)
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '保存失败');
            var index = people.findIndex(function(item) { return item.developer_no === person.developer_no; });
            if (index >= 0) people[index] = data.person;
            else people.push(data.person);
            closePersonModal();
            renderPeople();
            toast(wasEditing ? '人员资料已更新' : '人员资料已新增', false);
          } catch (error) {
            toast(error.message, true);
          } finally {
            saveButton.disabled = false;
            saveButton.textContent = '保存';
          }
        });
        renderPeople();
        loadPeople();

        var branchesGrid = document.getElementById('branchesGrid');
        var branchesAdminToolbar = document.getElementById('branchesAdminToolbar');

        function renderBranches() {
          branchesAdminToolbar.hidden = !adminMode;
          branchesGrid.innerHTML = branches.map(function(branch) {
            function info(label, value, key) {
              var text = value || '—';
              return '<div class="branch-info-row"><span class="branch-info-label">' + label + '</span>' +
                '<span class="branch-info-value">' + esc(text) + '</span>' +
                '<button type="button" class="copy-btn" data-copy-value="' + esc(text) + '" data-copy-key="' + key + '" aria-label="复制' + label + '" title="复制">' + copyIcon + '</button></div>';
            }
            var actions = adminMode
              ? '<div class="doc-card-actions">' +
                  '<button type="button" class="doc-icon-btn doc-edit" data-branch-edit="' + esc(branch.id) + '" aria-label="编辑分社" title="编辑">' + editIcon + '</button>' +
                  '<button type="button" class="doc-icon-btn doc-delete" data-branch-delete="' + esc(branch.id) + '" aria-label="删除分社" title="删除">' + deleteIcon + '</button>' +
                '</div>'
              : '';
            return '<article class="branch-card">' +
              '<div class="branch-card-top"><h3>' + esc(branch.name) + '</h3>' + actions + '</div>' +
              '<div class="branch-info">' +
                info('Tel', branch.tel, 'tel') +
                info('Mail', branch.mail, 'mail') +
                info('Address', branch.address, 'address') +
                info('Person', branch.person, 'person') +
              '</div></article>';
          }).join('');
        }

        async function loadBranches() {
          try {
            var response = await fetch('/api/branches', { credentials: 'same-origin' });
            var data = await response.json();
            branches = data.success && Array.isArray(data.branches) ? data.branches : [];
          } catch (error) {
            branches = [];
          }
          renderBranches();
        }

        function openBranchModal(branch) {
          editingBranchId = branch ? branch.id : null;
          document.getElementById('branchModalTitle').textContent = branch ? '编辑分社' : '新增分社';
          var form = document.getElementById('branchForm');
          form.elements.namedItem('name').value = branch ? branch.name : '';
          form.elements.namedItem('tel').value = branch ? branch.tel || '' : '';
          form.elements.namedItem('mail').value = branch ? branch.mail || '' : '';
          form.elements.namedItem('address').value = branch ? branch.address || '' : '';
          form.elements.namedItem('person').value = branch ? branch.person || '' : '';
          document.getElementById('branchModalBackdrop').classList.add('show');
        }

        function closeBranchModal() {
          document.getElementById('branchModalBackdrop').classList.remove('show');
          editingBranchId = null;
        }

        async function copyBranchValue(button) {
          var text = button.dataset.copyValue;
          if (text === '—') return;
          try {
            if (navigator.clipboard && window.isSecureContext) {
              await navigator.clipboard.writeText(text);
            } else {
              var textarea = document.createElement('textarea');
              textarea.value = text;
              textarea.style.position = 'fixed';
              textarea.style.opacity = '0';
              document.body.appendChild(textarea);
              textarea.select();
              document.execCommand('copy');
              textarea.remove();
            }
            button.innerHTML = checkIcon;
            button.classList.add('copied');
            setTimeout(function() {
              button.innerHTML = copyIcon;
              button.classList.remove('copied');
            }, 1000);
          } catch (error) {
            toast('复制失败，请手动选择文本', true);
          }
        }

        document.getElementById('branchAddBtn').addEventListener('click', function() { openBranchModal(null); });
        document.getElementById('branchModalCancel').addEventListener('click', closeBranchModal);
        document.getElementById('branchModalBackdrop').addEventListener('click', function(event) {
          if (event.target === this) closeBranchModal();
        });
        branchesGrid.addEventListener('click', function(event) {
          var copyButton = event.target.closest('[data-copy-value]');
          if (copyButton) {
            copyBranchValue(copyButton);
            return;
          }
          var editButton = event.target.closest('[data-branch-edit]');
          if (editButton) {
            openBranchModal(branches.find(function(branch) { return branch.id === editButton.dataset.branchEdit; }));
            return;
          }
          var deleteButton = event.target.closest('[data-branch-delete]');
          if (deleteButton) deleteBranch(deleteButton.dataset.branchDelete);
        });

        async function deleteBranch(id) {
          if (!await showDeleteConfirmation('删除分社', '确定删除该分社吗？此操作无法撤销。')) return;
          try {
            var response = await fetch('/api/branches', {
              method: 'DELETE',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: id })
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '删除失败');
            branches = branches.filter(function(branch) { return branch.id !== id; });
            renderBranches();
            toast('分社已删除', false);
          } catch (error) {
            toast(error.message, true);
          }
        }

        document.getElementById('branchForm').addEventListener('submit', async function(event) {
          event.preventDefault();
          var form = event.target;
          var saveButton = document.getElementById('branchModalSave');
          var wasEditing = !!editingBranchId;
          var branch = {
            id: editingBranchId,
            name: form.elements.namedItem('name').value.trim(),
            tel: form.elements.namedItem('tel').value.trim(),
            mail: form.elements.namedItem('mail').value.trim(),
            address: form.elements.namedItem('address').value.trim(),
            person: form.elements.namedItem('person').value.trim()
          };
          saveButton.disabled = true;
          saveButton.textContent = '保存中...';
          try {
            var response = await fetch('/api/branches', {
              method: wasEditing ? 'PUT' : 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(branch)
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '保存失败');
            var index = branches.findIndex(function(item) { return item.id === data.branch.id; });
            if (index >= 0) branches[index] = data.branch;
            else branches.push(data.branch);
            branches.sort(function(a, b) { return String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }); });
            closeBranchModal();
            renderBranches();
            toast(wasEditing ? '分社已更新' : '分社已新增', false);
          } catch (error) {
            toast(error.message, true);
          } finally {
            saveButton.disabled = false;
            saveButton.textContent = '保存';
          }
        });
        renderBranches();
        loadBranches();

        var committeeData = { quarter: '', members: [] };
        var committeeMembers = document.getElementById('committeeMembers');
        var committeeDrawBtn = document.getElementById('committeeDrawBtn');

        function renderCommittee() {
          document.getElementById('committeeAdminToolbar').hidden = !adminMode;
          var quarter = committeeData.quarter || '';
          var match = /^(\d{4})-Q([1-4])$/.exec(quarter);
          document.getElementById('committeeQuarter').textContent = match
            ? Number(match[1]) + ' 年第 ' + Number(match[2]) + ' 季度'
            : '';
          committeeMembers.innerHTML = committeeData.members.length
            ? committeeData.members.map(function(member, index) {
                return '<article class="committee-member">' +
                  '<div class="committee-number">委员 ' + (index + 1) + ' · ' + esc(member.developer_no) + '</div>' +
                  '<h3>' + esc(member.name) + '</h3>' +
                  '<p>' + esc(member.department || '普通开发者') + '</p>' +
                '</article>';
              }).join('')
            : '<p class="committee-empty">本季度成员尚未抽取，管理员可手动随机抽取。</p>';
        }

        async function loadCommittee() {
          try {
            var response = await fetch('/api/committee', { credentials: 'same-origin' });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '成员公示加载失败');
            committeeData = { quarter: data.quarter, members: Array.isArray(data.members) ? data.members : [] };
          } catch (error) {
            committeeData = { quarter: '', members: [] };
            toast('成员公示加载失败：' + error.message, true);
          }
          renderCommittee();
        }

        committeeDrawBtn.addEventListener('click', async function() {
          committeeDrawBtn.disabled = true;
          committeeDrawBtn.textContent = '抽取中...';
          try {
            var response = await fetch('/api/committee', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: '{}'
            });
            var data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || '随机抽取失败');
            committeeData = { quarter: data.quarter, members: data.members || [] };
            renderCommittee();
            toast('本季度成员已随机抽取并保存', false);
          } catch (error) {
            toast(error.message, true);
          } finally {
            committeeDrawBtn.disabled = false;
            committeeDrawBtn.textContent = '管理员随机抽取';
          }
        });
        renderCommittee();
        loadCommittee();

        function mergedDocs() {
          var map = new Map();
          DOCS.forEach(function(d) {
            if (deletedDocs.indexOf(d.no) === -1) map.set(d.no, d);
          });
          dbDocs.forEach(function(d) { map.set(d.no, d); });
          return Array.from(map.values()).sort(function(a, b) { return a.no.localeCompare(b.no); });
        }

        function renderDocs() {
          var cards = mergedDocs().map(function(d) {
            var statusClass = d.status === '保密' ? 'doc-status-private' : d.status === '公开' || d.status === '已发布' ? 'doc-status-public' : 'doc-status-draft';
            var actions = adminMode
              ? '<div class="doc-card-actions">' +
                  '<button type="button" class="doc-icon-btn doc-edit" data-edit="' + esc(d.no) + '" aria-label="编辑决案 ' + esc(d.no) + '" title="编辑">' + editIcon + '</button>' +
                  '<button type="button" class="doc-icon-btn doc-delete" data-delete="' + esc(d.no) + '" aria-label="删除决案 ' + esc(d.no) + '" title="删除">' + deleteIcon + '</button>' +
                '</div>'
              : '<span class="doc-more">阅读全文 →</span>';
            return '<div class="doc-card" data-no="' + d.no + '">' +
              '<div class="doc-card-top"><span class="doc-no">' + d.no + '</span></div>' +
              '<h3>' + esc(d.title) + '</h3>' +
              '<p>' + esc(d.desc) + '</p>' +
              '<div class="doc-card-foot">' +
                '<span class="doc-footer-tag ' + statusClass + '">' + esc(d.status === '已发布' ? '公开' : d.status) + '</span>' +
                '<span class="doc-footer-tag" style="color:#f87171;background:rgba(248,113,113,.1)">' + esc(d.level) + '</span>' +
                actions +
              '</div>' +
            '</div>';
          }).join('');

          if (adminMode) {
            cards += '<button type="button" class="doc-card doc-add-card" id="docAddCard" aria-label="新增决案"><span class="doc-add-icon">+</span></button>';
          }
          docsGrid.innerHTML = cards;

          var addCard = document.getElementById('docAddCard');
          if (addCard) addCard.addEventListener('click', function() { openDocModal(); });
        }

        docsGrid.addEventListener('click', function(e) {
          var edit = e.target.closest('[data-edit]');
          if (edit) {
            e.stopPropagation();
            openDocModal(mergedDocs().find(function(d) { return d.no === edit.dataset.edit; }));
            return;
          }
          var remove = e.target.closest('[data-delete]');
          if (remove) {
            e.stopPropagation();
            deleteDoc(remove.dataset.delete);
            return;
          }
          var card = e.target.closest('.doc-card');
          if (card && card.dataset.no) navigate(null, '/database/' + card.dataset.no);
        });

        function bodySections(body) {
          return [{ heading: null, blocks: String(body || '').split(/\\r?\\n/).filter(function(line) { return line.trim(); }).map(function(line) {
            return { t: 'p', text: line.trim() };
          }) }];
        }

        function openDocModal(doc) {
          editingDocNo = doc ? doc.no : null;
          document.getElementById('docModalTitle').textContent = doc ? '编辑决案' : '新增决案';
          var form = document.getElementById('docForm');
          form.elements.namedItem('no').value = doc ? doc.no : '';
          form.status.value = doc ? (doc.visibility === '保密' || doc.status === '保密' ? '保密' : doc.status === '已发布' ? '公开' : doc.status) : '草案';
          form.title.value = doc ? doc.title : '';
          form.level.value = doc ? doc.level : 'Root 级影响力';
          form.desc.value = doc ? doc.desc : '';
          form.elements.namedItem('no').disabled = !!doc;
          var paragraphs = [];
          if (doc && doc.sections) doc.sections.forEach(function(section) {
            (section.blocks || []).forEach(function(block) {
              if (block.t === 'p') paragraphs.push(block.text);
            });
          });
          form.body.value = paragraphs.join('\\n');
          document.getElementById('docModalBackdrop').classList.add('show');
        }

        function closeDocModal() {
          document.getElementById('docModalBackdrop').classList.remove('show');
          document.getElementById('docForm').elements.namedItem('no').disabled = false;
          editingDocNo = null;
        }

        async function loadDbDocs() {
          try {
            var response = await fetch('/api/docs', { credentials: 'same-origin' });
            var data = await response.json();
            dbDocs = data.success ? data.docs : [];
            deletedDocs = data.success ? (data.deleted_docs || []) : [];
            renderDocs();
          } catch (error) {
            dbDocs = [];
            deletedDocs = [];
            renderDocs();
          }
        }

        async function deleteDoc(no) {
          if (!await showDeleteConfirmation('删除决案', '确定删除 ' + no + ' 号决案吗？此操作无法撤销。')) return;
          try {
            var response = await fetch('/api/docs', {
              method: 'DELETE',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ no: no })
            });
            var data = await response.json();
            if (!data.success) throw new Error(data.message || '删除失败');
            dbDocs = dbDocs.filter(function(d) { return d.no !== no; });
            if (deletedDocs.indexOf(no) === -1) deletedDocs.push(no);
            renderDocs();
            toast('决案已删除', false);
          } catch (error) {
            toast(error.message, true);
          }
        }

        document.getElementById('docModalCancel').addEventListener('click', closeDocModal);
        var docNoInput = document.getElementById('docForm').elements.namedItem('no');
        function normalizeDocNo(value) {
          var trimmed = value.trim();
          return /^\d{1,3}$/.test(trimmed) ? trimmed.padStart(3, '0') : trimmed;
        }
        docNoInput.addEventListener('blur', function() {
          docNoInput.value = normalizeDocNo(docNoInput.value);
        });
        document.getElementById('docModalBackdrop').addEventListener('click', function(e) {
          if (e.target === this) closeDocModal();
        });
        document.getElementById('docForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          docNoInput.value = normalizeDocNo(docNoInput.value);
          var wasEditing = !!editingDocNo;
          var saveBtn = document.getElementById('docModalSave');
          saveBtn.disabled = true;
          saveBtn.textContent = '保存中...';
          var no = docNoInput.value;
          var doc = {
            no: no,
            title: e.target.title.value.trim(),
            status: e.target.status.value,
            level: e.target.level.value,
            visibility: e.target.status.value === '保密' ? '保密' : '公开',
            desc: e.target.desc.value.trim(),
            sections: bodySections(e.target.body.value)
          };
          try {
            var response = await fetch('/api/docs', {
              method: editingDocNo ? 'PUT' : 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(doc)
            });
            var data = await response.json();
            if (!data.success) throw new Error(data.message || '保存失败');
            var index = dbDocs.findIndex(function(d) { return d.no === no; });
            if (index >= 0) dbDocs[index] = data.doc;
            else dbDocs.push(data.doc);
            deletedDocs = deletedDocs.filter(function(n) { return n !== no; });
            closeDocModal();
            renderDocs();
            toast(wasEditing ? '决案已更新' : '决案已新增', false);
          } catch (error) {
            toast(error.message, true);
          } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = '保存';
          }
        });
        renderDocs();
        loadDbDocs();

        function showDocDetail(d) {
          document.getElementById('detailTitle').textContent = d.no + ' 号决案 · ' + d.title;
          document.getElementById('detailMeta').textContent = d.visibility + ' · ' + d.level + ' · 状态：' + d.status;
          document.getElementById('detailContent').innerHTML = d.sections.map(renderSection).join('');
        }

        // ================= 路由 =================
        function navigate(e, path) {
          if (e && e.preventDefault) e.preventDefault();
          history.pushState(null, '', path);
          renderRoute();
          return false;
        }

        function renderRoute() {
          var rawPath = window.location.pathname;
          var path = rawPath;
          if (rawPath.length > 1 && rawPath.charAt(rawPath.length - 1) === '/') {
            path = rawPath.slice(0, -1);
          }
          if (path === '') path = '/';

          document.querySelectorAll('.page').forEach(function(p){ p.classList.remove('active'); });

          if (path.indexOf('/database/') === 0) {
            var no = path.split('/')[2];
            var d = mergedDocs().find(function(doc){ return doc.no === no; });
            if (d) { showDocDetail(d); document.getElementById('docDetail').classList.add('active'); }
            else {
              window.location.replace('/__not_found__');
              return;
            }
          } else if (path === '/space') { document.getElementById('space').classList.add('active'); }
          else if (path === '/history') { document.getElementById('history').classList.add('active'); }
          else if (path === '/database') { document.getElementById('docs').classList.add('active'); }
          else if (path === '/list') { document.getElementById('people').classList.add('active'); }
          else if (path === '/contact') { document.getElementById('contact').classList.add('active'); }
          else if (path === '/committee') { document.getElementById('committee').classList.add('active'); }
          else if (path === '/join') { document.getElementById('join').classList.add('active'); }
          else if (path === '/login') { document.getElementById('login').classList.add('active'); }
          else { document.getElementById('home').classList.add('active'); }
          var routeTitles = {
            '/': '上海克利工作室 - Shanghai Keli work studio',
            '/space': 'Space 档案 - 上海克利工作室',
            '/history': '克利历程 - 上海克利工作室',
            '/database': '决案档案库 - 上海克利工作室',
            '/list': '人员查询 - 上海克利工作室',
            '/contact': '联系我们 - 上海克利工作室',
            '/committee': '成员公示 - 上海克利工作室',
            '/join': '加入我们 - 上海克利工作室',
            '/login': '管理员登录 - 上海克利工作室'
          };
          document.title = routeTitles[path] || '上海克利工作室 - Shanghai Keli work studio';
          window.scrollTo(0, 0);
        }

        window.addEventListener('popstate', renderRoute);
        renderRoute();

        // ================= 登录状态管理 =================
        var userBtn = document.getElementById('userBtn');
        var themeBtn = document.getElementById('themeBtn');
        var logoutModal = document.getElementById('logoutModal');
        var logoutCancel = document.getElementById('logoutCancel');
        var logoutConfirm = document.getElementById('logoutConfirm');
        var deleteConfirmModal = document.getElementById('deleteConfirmModal');
        var pendingDeleteConfirmation = null;
        var deleteConfirmReturnFocus = null;

        function showActionConfirmation(title, message, acceptText, acceptColor) {
          if (pendingDeleteConfirmation) pendingDeleteConfirmation(false);
          document.getElementById('deleteConfirmTitle').textContent = title;
          document.getElementById('deleteConfirmMessage').textContent = message;
          var acceptButton = document.getElementById('deleteConfirmAccept');
          acceptButton.textContent = acceptText || '确认';
          acceptButton.style.background = acceptColor || '#ef4444';
          deleteConfirmReturnFocus = document.activeElement;
          deleteConfirmModal.classList.add('show');
          document.getElementById('deleteConfirmCancel').focus();
          return new Promise(function(resolve) {
            pendingDeleteConfirmation = function(confirmed) {
              pendingDeleteConfirmation = null;
              deleteConfirmModal.classList.remove('show');
              acceptButton.textContent = '确认删除';
              acceptButton.style.background = '#ef4444';
              resolve(confirmed);
              if (deleteConfirmReturnFocus && typeof deleteConfirmReturnFocus.focus === 'function') {
                deleteConfirmReturnFocus.focus();
              }
            };
          });
        }

        function showDeleteConfirmation(title, message) {
          return showActionConfirmation(title, message, '确认删除', '#ef4444');
        }

        document.getElementById('deleteConfirmCancel').addEventListener('click', function() {
          if (pendingDeleteConfirmation) pendingDeleteConfirmation(false);
        });
        document.getElementById('deleteConfirmAccept').addEventListener('click', function() {
          if (pendingDeleteConfirmation) pendingDeleteConfirmation(true);
        });
        deleteConfirmModal.addEventListener('click', function(event) {
          if (event.target === deleteConfirmModal && pendingDeleteConfirmation) pendingDeleteConfirmation(false);
        });
        window.addEventListener('keydown', function(event) {
          if (event.key === 'Escape' && pendingDeleteConfirmation) pendingDeleteConfirmation(false);
        });

        function getSavedTheme() {
          try { return localStorage.getItem('keliTheme') === 'light' ? 'light' : 'dark'; }
          catch (error) { return 'dark'; }
        }

        function applyTheme(theme) {
          var isLight = theme === 'light';
          document.body.classList.toggle('theme-light', isLight);
          themeBtn.setAttribute('aria-label', isLight ? '切换深色主题' : '切换浅色主题');
          themeBtn.setAttribute('title', isLight ? '切换到深色主题' : '切换到浅色主题');
        }

        applyTheme(getSavedTheme());
        themeBtn.addEventListener('click', function() {
          var nextTheme = document.body.classList.contains('theme-light') ? 'dark' : 'light';
          applyTheme(nextTheme);
          try { localStorage.setItem('keliTheme', nextTheme); } catch (error) {}
        });

        function openLogoutModal() {
          logoutModal.classList.add('show');
          logoutCancel.focus();
        }

        function closeLogoutModal() {
          logoutModal.classList.remove('show');
          userBtn.focus();
        }

        logoutCancel.addEventListener('click', closeLogoutModal);
        logoutModal.addEventListener('click', function(e) {
          if (e.target === logoutModal) closeLogoutModal();
        });
        logoutConfirm.addEventListener('click', function() {
          logoutConfirm.disabled = true;
          logoutConfirm.textContent = '登出中...';
          fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).then(function() {
            closeLogoutModal();
            setAdminUI(false);
            loadDbDocs();
            toast('已登出', false);
          }).catch(function() {
            closeLogoutModal();
            toast('登出失败，请稍后重试', true);
          }).finally(function() {
            logoutConfirm.disabled = false;
            logoutConfirm.textContent = '确定登出';
          });
        });
        window.addEventListener('keydown', function(e) {
          if (e.key === 'Escape' && logoutModal.classList.contains('show')) closeLogoutModal();
        });

        function setAdminUI(isAdmin) {
          adminMode = isAdmin;
          document.body.classList.toggle('admin-mode', isAdmin);
          peopleAdminToolbar.hidden = !isAdmin;
          renderDocs();
          renderPeople();
          renderBranches();
          renderCommittee();
          if (isAdmin) {
            userBtn.classList.add('is-admin');
            userBtn.setAttribute('aria-label', '管理员（点击登出）');
          } else {
            userBtn.classList.remove('is-admin');
            userBtn.setAttribute('aria-label', '管理员登录');
          }
        }

        userBtn.addEventListener('click', function(e) {
          e.preventDefault();
          if (userBtn.classList.contains('is-admin')) {
            openLogoutModal();
          } else {
            try {
              var currentPath = window.location.pathname + window.location.search + window.location.hash;
              sessionStorage.setItem('loginReturnTo', currentPath === '/login' ? '/' : currentPath);
            } catch (storageError) {}
            navigate(null, '/login');
          }
        });

        function getLoginReturnPath() {
          try {
            var returnPath = sessionStorage.getItem('loginReturnTo');
            sessionStorage.removeItem('loginReturnTo');
            if (!returnPath || returnPath.charAt(0) !== '/' || returnPath.indexOf('//') === 0) return '/';
            var target = new URL(returnPath, window.location.origin);
            if (target.origin !== window.location.origin || target.pathname === '/login') return '/';
            return target.pathname + target.search + target.hash;
          } catch (error) {
            return '/';
          }
        }

        async function initAuth() {
          try {
            var res = await fetch('/api/me', {
              credentials: 'same-origin'
            });
            var data = await res.json();
            if (data.authed) {
              setAdminUI(true);
              loadDbDocs();
            } else {
              setAdminUI(false);
              loadDbDocs();
            }
          } catch (e) {
            setAdminUI(false);
          }
        }

        function toast(text, isError) {
          var t = document.getElementById('toast');
          t.textContent = text;
          t.classList.remove('error');
          if (isError) t.classList.add('error');
          t.classList.add('show');
          setTimeout(function(){ t.classList.remove('show'); }, 2000);
        }

        var loginPassword = document.getElementById('loginPassword');
        var passwordToggle = document.getElementById('passwordToggle');
        function setPasswordVisible(visible) {
          loginPassword.type = visible ? 'text' : 'password';
          passwordToggle.setAttribute('aria-pressed', visible ? 'true' : 'false');
          passwordToggle.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
          passwordToggle.title = visible ? '隐藏密码' : '显示密码';
          var openEye = passwordToggle.querySelector('[data-password-icon="show"]');
          var closedEye = passwordToggle.querySelector('[data-password-icon="hide"]');
          openEye.hidden = !visible;
          closedEye.hidden = visible;
          openEye.style.display = visible ? 'block' : 'none';
          closedEye.style.display = visible ? 'none' : 'block';
        }
        passwordToggle.addEventListener('click', function() {
          setPasswordVisible(loginPassword.type === 'password');
        });
        document.getElementById('loginForm').addEventListener('reset', function() {
          setPasswordVisible(false);
        });
        setPasswordVisible(false);

        // 登录表单
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          var btn = document.getElementById('loginBtn');
          var msg = document.getElementById('loginMsg');
          var pwd = e.target.password.value;
          btn.disabled = true;
          btn.innerText = '验证中...';
          msg.textContent = '';
          msg.style.color = '';
          try {
            var res = await fetch('/api/login', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                password: pwd,
                turnstileToken: e.target.querySelector('[name="cf-turnstile-response"]')?.value || ''
              })
            });
            var data = await res.json();
            if (data.success) {
              setAdminUI(true);
              loadDbDocs();
              msg.style.color = '#4ade80';
              msg.textContent = '登录成功，正在跳转...';
              var returnPath = getLoginReturnPath();
              setTimeout(function() {
                e.target.reset();
                msg.textContent = '';
                navigate(null, returnPath);
              }, 800);
            } else {
              msg.style.color = '#f87171';
              msg.textContent = data.message || '登录失败';
              if (window.turnstile) window.turnstile.reset(e.target.querySelector('.cf-turnstile'));
            }
          } catch (err) {
            msg.style.color = '#f87171';
            msg.textContent = '网络错误：' + err.message;
          } finally {
            btn.disabled = false;
            btn.innerText = '登录';
          }
        });

        // ================= 加入表单提交 =================
        document.getElementById('joinForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          var btn = document.getElementById('submitBtn');
          btn.innerText = '提交中...';
          btn.disabled = true;
          var data = Object.fromEntries(new FormData(this).entries());
          data.turnstileToken = this.querySelector('[name="cf-turnstile-response"]')?.value || '';
          try {
            var res = await fetch('/api/join', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
            var result = await res.json();
            if (result.success) {
              toast('提交成功！我们会尽快联系您。', false);
              this.reset();
              setTimeout(function(){ navigate(null, '/'); }, 2000);
            } else {
              throw new Error(result.message || 'Server Error');
            }
          } catch (err) {
            toast('提交失败：' + err.message, true);
            if (window.turnstile) window.turnstile.reset(this.querySelector('.cf-turnstile'));
          } finally {
            btn.innerText = '提交申请';
            btn.disabled = false;
          }
        });

        // 启动登录状态检查
        initAuth();
      </script>
    </body>
    </html>
    `;

    return new Response(htmlContent, {
      headers: htmlHeaders("public, max-age=60, stale-while-revalidate=600", url.pathname)
    });
    } catch (error) {
      console.error("Unhandled Worker request error", error);
      if (url.pathname.startsWith("/api/")) {
        return json({ success: false, message: "服务器暂时无法处理此请求" }, 500);
      }
      return errorPageResponse(500, "服务器暂时无法处理此请求");
    }
  },
  async scheduled(controller, env) {
    if (!env.DB) throw new Error("未绑定 D1 数据库 DB，季度成员抽取无法执行");
    const result = await drawCommittee(env.DB, new Date(controller.scheduledTime), false);
    if (!result.success) throw new Error(result.message);
  }
};

function errorPageResponse(status, message) {
  const safeMessage = String(message).replace(/[&<>"]/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;"
  })[character]);
  return new Response(
    `<!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>${status} · ${safeMessage}</title>
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 300 400'%3E%3Cline x1='60' y1='380' x2='130' y2='160' stroke='%23FF0000' stroke-width='24' stroke-linecap='round'/%3E%3Cline x1='140' y1='320' x2='210' y2='100' stroke='%2300FFFF' stroke-width='24' stroke-linecap='round'/%3E%3Cline x1='220' y1='260' x2='290' y2='40' stroke='%230000FF' stroke-width='24' stroke-linecap='round'/%3E%3C/svg%3E">
      <style>
        * { box-sizing: border-box; }
        :root { color-scheme: dark; }
        body {
          min-height: 100vh; margin: 0;
          display: grid; place-items: center;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", sans-serif;
          background: radial-gradient(circle at 20% 30%, #1a1f2b 0%, #0b0d10 70%);
          color: #eef2f6; text-align: center;
        }
        body.light { color-scheme: light; background: radial-gradient(circle at 20% 30%, #ffffff 0%, #edf1f7 70%); color: #171a21; }
        main { width: min(680px, calc(100% - 40px)); padding: 3rem 1.5rem; }
        h1 { margin: 0; font-size: clamp(7rem, 28vw, 12rem); line-height: .82; font-weight: 900; letter-spacing: -.08em; }
        p { margin: 2.25rem 0 2rem; font-size: clamp(1.35rem, 5vw, 2rem); font-weight: 700; line-height: 1.5; }
        a {
          display: inline-block; min-width: 180px;
          padding: .9rem 2rem; border-radius: 999px;
          background: #fff; color: #0b0d10;
          font-size: 1.05rem; font-weight: 800;
          text-decoration: none;
          box-shadow: 0 14px 35px rgba(0,0,0,.18);
        }
        body.light a { background: #171a21; color: #fff; }
        a:focus-visible { outline: 3px solid #79c0ff; outline-offset: 5px; }
      </style>
    </head>
    <body>
      <main>
        <h1>${status}</h1>
        <p>${safeMessage}</p>
        <a href="/">返回首页</a>
      </main>
      <script>
        try { if (localStorage.getItem("keliTheme") === "light") document.body.classList.add("light"); } catch (_) {}
      </script>
    </body>
    </html>`,
    {
      status,
      headers: htmlHeaders("no-store")
    }
  );
}

// ================= 安全与工具函数 =================
async function hmacSha256(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function createSession(secret) {
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  const nonce = crypto.randomUUID();
  const payload = `${expiresAt}.${nonce}`;
  const signature = await hmacSha256(secret, payload);
  return `${payload}.${signature}`;
}

async function verifySession(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  const signature = parts[2];
  const expiresAt = Number(parts[0]);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;
  const expected = await hmacSha256(secret, payload);
  if (signature.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < signature.length; i++) mismatch |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  return mismatch === 0;
}

function getCookie(cookieHeader, name) {
  for (const part of cookieHeader.split(";")) {
    const pair = part.trim();
    const index = pair.indexOf("=");
    if (index > 0 && pair.slice(0, index) === name) return pair.slice(index + 1);
  }
  return "";
}

function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return origin === url.origin;
}

function cleanText(value) {
  if (value === undefined || value === null || String(value).trim() === "") return "未填写";
  return String(value).replace(/[^\S\r\n]+/g, " ").trim().slice(0, 100000);
}

async function verifyTurnstile(token, secret, remoteIp) {
  if (typeof token !== "string" || token.length < 20) return false;
  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);
  if (remoteIp) form.append("remoteip", remoteIp);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form
    });
    if (!response.ok) return false;
    const result = await response.json();
    return result.success === true;
  } catch (_) {
    return false;
  }
}

function validJoinData(data) {
  if (!data || typeof data !== "object") return false;
  if (typeof data.name !== "string" || data.name.trim().length < 1 || data.name.length > 100000) return false;
  if (!["男", "女", "其他"].includes(data.gender)) return false;
  const age = Number(data.age);
  if (!Number.isInteger(age) || age < 1 || age > 120) return false;
  if (typeof data.contact !== "string" || data.contact.trim().length < 3 || data.contact.length > 100000) return false;
  if (typeof data.hobbies === "string" && data.hobbies.length > 100000) return false;
  if (typeof data.skills === "string" && data.skills.length > 100000) return false;
  return true;
}

async function ensureDocsTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS docs (
      no TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      level TEXT NOT NULL,
      visibility TEXT NOT NULL,
      description TEXT NOT NULL,
      sections_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS deleted_docs (
      no TEXT PRIMARY KEY,
      deleted_at TEXT NOT NULL
    )
  `).run();
}

async function ensureBranchesTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS branches (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      tel TEXT,
      mail TEXT,
      address TEXT,
      person TEXT,
      updated_at TEXT NOT NULL
    )
  `).run();
}

function validateBranchData(data) {
  if (!data || typeof data !== "object") return null;
  if (typeof data.name !== "string" || !data.name.trim() || data.name.length > 100000) return null;
  for (const key of ["tel", "mail", "address", "person"]) {
    if (data[key] !== undefined && data[key] !== null && (typeof data[key] !== "string" || data[key].length > 100000)) return null;
  }
  return {
    name: data.name.trim(),
    tel: typeof data.tel === "string" ? data.tel.trim() : "",
    mail: typeof data.mail === "string" ? data.mail.trim() : "",
    address: typeof data.address === "string" ? data.address.trim() : "",
    person: typeof data.person === "string" ? data.person.trim() : ""
  };
}

async function ensurePeopleTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS people (
      developer_no TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      gender TEXT NOT NULL,
      department TEXT NOT NULL,
      rank TEXT NOT NULL,
      joined_at TEXT NOT NULL,
      left_at TEXT,
      rejoin_type TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS ethics_candidates (
      developer_no TEXT PRIMARY KEY,
      added_at TEXT NOT NULL
    )
  `).run();
}

async function ensureCommitteeTables(db) {
  await ensurePeopleTable(db);
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS ethics_committee_terms (
      quarter TEXT PRIMARY KEY,
      selected_at TEXT NOT NULL,
      members_json TEXT NOT NULL
    )
  `).run();
}

function committeeQuarterKey(date) {
  return date.getUTCFullYear() + "-Q" + (Math.floor(date.getUTCMonth() / 3) + 1);
}

function previousCommitteeQuarterKey(date) {
  const quarterStartMonth = Math.floor(date.getUTCMonth() / 3) * 3;
  return committeeQuarterKey(new Date(Date.UTC(date.getUTCFullYear(), quarterStartMonth - 3, 1)));
}

function parseCommitteeMembers(value) {
  try {
    const members = JSON.parse(value);
    return Array.isArray(members) ? members : [];
  } catch (error) {
    return [];
  }
}

async function drawCommittee(db, date, force) {
  await ensureCommitteeTables(db);
  const quarter = committeeQuarterKey(date);
  const existing = await db.prepare(
    "SELECT quarter, selected_at, members_json FROM ethics_committee_terms WHERE quarter=?"
  ).bind(quarter).first();
  if (existing && !force) {
    return { success: true, quarter, members: parseCommitteeMembers(existing.members_json), selected_at: existing.selected_at };
  }

  const previous = await db.prepare(
    "SELECT members_json FROM ethics_committee_terms WHERE quarter=?"
  ).bind(previousCommitteeQuarterKey(date)).first();
  const previousIds = new Set(previous ? parseCommitteeMembers(previous.members_json).map(member => member.developer_no) : []);
  const candidateResult = await db.prepare(
    "SELECT p.developer_no, p.name, p.department FROM people p INNER JOIN ethics_candidates ec ON ec.developer_no=p.developer_no WHERE p.left_at IS NULL OR p.left_at=''"
  ).all();
  const eligible = (candidateResult.results || []).filter(person => !previousIds.has(person.developer_no));
  if (eligible.length < 3) {
    return {
      success: false,
      quarter,
      message: "排除上季度成员后，符合条件的候选人不足 3 人；当前可抽取 " + eligible.length + " 人。"
    };
  }

  const pool = eligible.slice();
  for (let i = pool.length - 1; i > 0; i--) {
    const random = new Uint32Array(1);
    crypto.getRandomValues(random);
    const j = Math.floor(random[0] / 4294967296 * (i + 1));
    const temp = pool[i];
    pool[i] = pool[j];
    pool[j] = temp;
  }
  const members = pool.slice(0, 3).map(person => ({
    developer_no: person.developer_no,
    name: person.name,
    department: person.department
  }));
  const selectedAt = new Date().toISOString();
  await db.prepare(
    "INSERT INTO ethics_committee_terms (quarter, selected_at, members_json) VALUES (?, ?, ?) ON CONFLICT(quarter) DO UPDATE SET selected_at=excluded.selected_at, members_json=excluded.members_json"
  ).bind(quarter, selectedAt, JSON.stringify(members)).run();
  return { success: true, quarter, members, selected_at: selectedAt };
}

function isValidDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00Z");
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validatePersonData(data) {
  if (!data || typeof data !== "object") return null;
  const developerNo = typeof data.developer_no === "string" ? data.developer_no.trim() : "";
  if (!developerNo || developerNo.length > 50) return null;
  if (typeof data.name !== "string" || !data.name.trim() || data.name.length > 100000) return null;
  if (!["男", "女", "其他"].includes(data.gender)) return null;
  if (typeof data.department !== "string" || !data.department.trim() || data.department.length > 100000) return null;
  if (typeof data.rank !== "string" || !data.rank.trim() || data.rank.length > 100000) return null;
  if (!isValidDate(data.joined_at)) return null;
  if (data.left_at !== "" && data.left_at !== null && data.left_at !== undefined && !isValidDate(data.left_at)) return null;
  if (data.left_at && data.left_at < data.joined_at) return null;
  if (!["一职", "二职", "三职"].includes(data.rejoin_type)) return null;
  return {
    developer_no: developerNo,
    name: data.name.trim(),
    gender: data.gender,
    department: data.department.trim(),
    rank: data.rank.trim(),
    joined_at: data.joined_at,
    left_at: data.left_at || null,
    rejoin_type: data.rejoin_type
  };
}

function parseSections(value) {
  try {
    const sections = JSON.parse(value);
    return Array.isArray(sections) ? sections : [{ heading: null, blocks: [] }];
  } catch (_) {
    return [{ heading: null, blocks: [] }];
  }
}

function validateDocData(data) {
  if (!data || typeof data !== "object") return null;
  if (typeof data.no !== "string" || !/^\d{3}$/.test(data.no)) return null;
  if (typeof data.title !== "string" || data.title.trim().length < 1 || data.title.length > 100000) return null;
  if (typeof data.desc !== "string" || data.desc.trim().length < 1 || data.desc.length > 100000) return null;
  if (!["草案", "公开", "保密"].includes(data.status)) return null;
  if (!/^(Root|[A-D]) 级影响力$/.test(data.level)) return null;
  const sections = Array.isArray(data.sections) ? data.sections : null;
  if (!sections) return null;
  return {
    no: data.no,
    title: data.title.trim(),
    status: data.status,
    level: data.level,
    visibility: data.status === "保密" ? "保密" : "公开",
    desc: data.desc.trim(),
    sections
  };
}

function securityHeaders(cacheControl) {
  const headers = {
    "Cache-Control": cacheControl || "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; font-src 'self'; img-src 'self' data:; connect-src 'self' https://cloudflareinsights.com https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  };
  return headers;
}

function htmlHeaders(cacheControl, path) {
  return {
    "Content-Type": "text/html;charset=UTF-8",
    ...securityHeaders(cacheControl),
    ...(path ? { "X-Worker-Path": path } : {})
  };
}

function canonicalPath(path) {
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

function routeMeta(path) {
  const routes = {
    "/": {
      title: "上海克利工作室 - Shanghai Keli work studio",
      description: "上海克利工作室官方网站，展示创意设计、数字体验、Space 产品档案与公开决案。"
    },
    "/space": {
      title: "Space 档案 - 上海克利工作室",
      description: "查阅 Space 系列从 1.0 到 6 的版本演进、开发日志与市场状态。"
    },
    "/history": {
      title: "克利历程 - 上海克利工作室",
      description: "了解上海克利工作室从成立、社团转型到数字产品研发的成长历程。"
    },
    "/database": {
      title: "决案档案库 - 上海克利工作室",
      description: "查阅上海克利基金会公开决案、组织规则和档案记录。"
    },
    "/list": {
      title: "人员查询 - 上海克利工作室",
      description: "按姓名查找上海克利工作室开发者资料，包括部门、职级与在社时间。"
    },
    "/contact": {
      title: "联系我们 - 上海克利工作室",
      description: "查看上海克利工作室各分社的电话、邮箱、地址与联系人。"
    },
    "/committee": {
      title: "成员公示 - 上海克利工作室",
      description: "查看本季度伦理道德委员会成员名单及候选人选取规则。"
    },
    "/join": {
      title: "加入我们 - 上海克利工作室",
      description: "提交加入上海克利工作室的申请，共同创造创意与数字产品。"
    },
    "/login": {
      title: "管理员登录 - 上海克利工作室",
      description: "上海克利工作室管理员登录入口。"
    }
  };
  return routes[canonicalPath(path)] || routes["/"];
}

function json(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      ...securityHeaders("no-store"),
      ...(extraHeaders || {})
    }
  });
}
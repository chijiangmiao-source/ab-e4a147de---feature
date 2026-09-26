"use strict";

const $ = (id) => document.getElementById(id);
const short = (h, n = 14) => (h.length > n * 2 ? h.slice(0, n) + "…" + h.slice(-6) : h);

// ---------------- health ------------------------------------------------- //
async function refreshHealth() {
  try {
    const r = await fetch("/healthz", { cache: "no-store" });
    const j = await r.json();
    if (r.ok && j.status === "ok") {
      $("health-dot").className = "dot dot-ok";
      $("health-text").textContent = `服务正常 · 空树根 ${short(j.empty_root, 8)}`;
    } else {
      throw new Error("bad status");
    }
  } catch {
    $("health-dot").className = "dot dot-bad";
    $("health-text").textContent = "服务不可达";
  }
}
setInterval(refreshHealth, 10000);

// ---------------- form helpers ------------------------------------------- //
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function collectPayload() {
  const leaves = JSON.parse($("leaves").value || "[]");
  const siblings = JSON.parse($("siblings").value || "[]");
  return {
    old_root: $("old-root").value.trim(),
    new_root: $("new-root").value.trim(),
    leaves,
    shared_siblings: siblings,
  };
}

function fillForm(p) {
  $("old-root").value = p.old_root ?? "";
  $("new-root").value = p.new_root ?? "";
  $("leaves").value = JSON.stringify(p.leaves ?? [], null, 2);
  $("siblings").value = JSON.stringify(p.shared_siblings ?? [], null, 2);
}

function showFormError(msg) {
  const el = $("form-error");
  el.textContent = msg;
  el.hidden = false;
}
function clearFormError() { $("form-error").hidden = true; }

// ---------------- result rendering ---------------------------------------- //
let lastVerificationId = null;

function resetResult() {
  // Critical: a prior verdict must never masquerade as the current one.
  lastVerificationId = null;
  $("result-empty").hidden = false;
  $("result-body").hidden = true;
  $("result-body").innerHTML = "";
}

function sourcePill(src) {
  return `<span class="pill pill-${esc(src)}">${esc(src)}</span>`;
}

function renderSuccess(d) {
  if (d.verification_id === lastVerificationId) return; // stale guard
  lastVerificationId = d.verification_id;

  const mergeRows = d.merges.map((m) => `
    <tr>
      <td>${m.level}</td>
      <td><code>${esc(m.parent_prefix.slice(0, 20))}${m.parent_prefix.length > 20 ? "…" : ""}</code></td>
      <td class="hash" title="${esc(m.old_left)}">${esc(short(m.old_left, 10))}</td>
      <td class="hash" title="${esc(m.old_right)}">${esc(short(m.old_right, 10))}</td>
      <td class="hash" title="${esc(m.new_left)}">${esc(short(m.new_left, 10))}</td>
      <td class="hash" title="${esc(m.new_right)}">${esc(short(m.new_right, 10))}</td>
      <td class="hash" title="${esc(m.old_parent)}"><b>${esc(short(m.old_parent, 10))}</b></td>
      <td class="hash" title="${esc(m.new_parent)}"><b>${esc(short(m.new_parent, 10))}</b></td>
      <td>${sourcePill(m.left_source)} ${sourcePill(m.right_source)}</td>
      <td>[${m.changed_sides.join(",")}]</td>
    </tr>`).join("");

  const leafRows = d.leaves.map((l) => `
    <tr>
      <td class="hash" title="${esc(l.key)}">${esc(short(l.key, 12))}</td>
      <td class="hash" title="${esc(l.old_leaf_digest)}">${esc(short(l.old_leaf_digest, 10))}</td>
      <td class="hash" title="${esc(l.old_leaf_hash)}">${esc(short(l.old_leaf_hash, 10))}</td>
      <td class="hash" title="${esc(l.new_leaf_digest)}">${esc(short(l.new_leaf_digest, 10))}</td>
      <td class="hash" title="${esc(l.new_leaf_hash)}">${esc(short(l.new_leaf_hash, 10))}</td>
    </tr>`).join("");

  const sibRows = d.shared_siblings.length
    ? d.shared_siblings.map((s) => `
      <tr>
        <td>${s.depth}</td>
        <td class="hash" title="${esc(s.prefix)}">${esc(short(s.prefix, 16))}</td>
        <td class="hash" title="${esc(s.digest)}">${esc(short(s.digest, 12))}</td>
        <td>${s.is_default_empty ? "是（不应出现）" : "否"}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" style="color:var(--muted)">无共享兄弟证明（所有兄弟子树均为默认空树）</td></tr>`;

  const defaults = d.defaults_used.length
    ? `<details class="trace"><summary>本次代入的默认空子树（${d.defaults_used.length} 处，去重见阶梯）</summary>
       <div class="trace-body"><div class="scrollx"><table>
         <tr><th>level</th><th>prefix</th><th>默认摘要 DEFAULT[${256}−level]</th></tr>
         ${d.defaults_used.map((x) => `<tr><td>${x.level}</td>
           <td class="hash">${esc(short(x.prefix, 18))}</td>
           <td class="hash" title="${esc(x.digest)}">${esc(short(x.digest, 12))}</td></tr>`).join("")}
       </table></div></div></details>`
    : "";

  $("result-body").innerHTML = `
    <div class="verdict ok">
      <div style="font-size:26px">✓</div>
      <div>
        <div class="big">通过：新根仅由获准键的旧值替换为新值产生</div>
        <p>旧树与新树已由同一份叶/兄弟骨架自底向上分别重建，两个复算根均与提交根一致。</p>
        <p class="sub">verification_id = <code>${esc(d.verification_id)}</code> ·
          变更键 ${d.changed_keys.length} 个 ·
          合并层级 ${d.merges.length} 行 · 无状态结论，刷新或重提即失效</p>
      </div>
    </div>

    <div class="roots">
      <div class="rootbox">
        <h3>旧树（双根之一）</h3>
        <div class="root-line"><span class="lab">提交 old_root</span>${esc(short(d.old_root, 20))}</div>
        <div class="root-line"><span class="lab">复算根</span>${esc(short(d.recomputed_old_root, 20))}<span class="match">✓ 相等</span></div>
      </div>
      <div class="rootbox">
        <h3>新树（双根之二）</h3>
        <div class="root-line"><span class="lab">提交 new_root</span>${esc(short(d.new_root, 20))}</div>
        <div class="root-line"><span class="lab">复算根</span>${esc(short(d.recomputed_new_root, 20))}<span class="match">✓ 相等</span></div>
      </div>
    </div>

    <h3 class="section">叶节点固定编码 SHA-256(00 ‖ 叶摘要)</h3>
    <div class="scrollx"><table>
      <thead><tr><th>key</th><th>old 叶摘要</th><th>old 叶节点</th><th>new 叶摘要</th><th>new 叶节点</th></tr></thead>
      <tbody>${leafRows}</tbody>
    </table></div>

    <h3 class="section">共享兄弟节点证明</h3>
    <div class="scrollx"><table>
      <thead><tr><th>depth</th><th>prefix</th><th>digest（旧/新共用，因子树未变）</th><th>默认空树?</th></tr></thead>
      <tbody>${sibRows}</tbody>
    </table></div>

    <h3 class="section">每层合并轨迹（自底向上 level 255 → 0；内部节点 SHA-256(01 ‖ L ‖ R)）</h3>
    <div class="scrollx"><table>
      <thead><tr>
        <th>level</th><th>父前缀</th>
        <th>旧左</th><th>旧右</th><th>新左</th><th>新右</th>
        <th>旧父</th><th>新父</th><th>左右来源</th><th>变更侧</th>
      </tr></thead>
      <tbody>${mergeRows}</tbody>
    </table></div>

    ${defaults}

    <details class="trace">
      <summary>默认空子树阶梯 DEFAULT[h]（h = 256−level，共 257 项）</summary>
      <div class="trace-body"><div class="scrollx"><table>
        <thead><tr><th>height h</th><th>level</th><th>digest</th></tr></thead>
        <tbody>${d.default_ladder.map((x) =>
          `<tr><td>${x.height}</td><td>${x.level}</td>
           <td class="hash" title="${esc(x.digest)}">${esc(short(x.digest, 12))}</td></tr>`).join("")}
        </tbody>
      </table></div></div>
    </details>`;
  $("result-empty").hidden = true;
  $("result-body").hidden = false;
}

function renderFailure(d) {
  if (d.verification_id === lastVerificationId) return;
  lastVerificationId = d.verification_id;
  const e = d.error || {};
  $("result-body").innerHTML = `
    <div class="verdict bad">
      <div style="font-size:26px">✗</div>
      <div>
        <div class="big">拒绝：${esc(e.code || "rejected")}${e.level != null ? ` · level ${e.level}` : ""}</div>
        <p>${esc(e.message || "证明未通过双树重建核验")}</p>
        <p class="sub">verification_id = <code>${esc(d.verification_id)}</code> ·
          本次提交未获通过；此前任何通过结论均不适用于本次提交</p>
      </div>
    </div>`;
  $("result-empty").hidden = true;
  $("result-body").hidden = false;
}

// ---------------- events -------------------------------------------------- //
$("parse-all").addEventListener("click", () => {
  clearFormError();
  try {
    const p = JSON.parse($("paste-all").value);
    fillForm(p);
  } catch (err) {
    showFormError("完整 JSON 解析失败：" + err.message);
  }
});

$("demo-btn").addEventListener("click", async () => {
  clearFormError();
  try {
    const r = await fetch("/api/demo", { method: "POST" });
    const d = await r.json();
    if (!d.ok) throw new Error("demo endpoint failed");
    fillForm(d.payload);
  } catch (err) {
    showFormError("载入示例失败：" + err.message);
  }
});

$("clear-btn").addEventListener("click", () => {
  $("verify-form").reset();
  clearFormError();
  resetResult();
});

$("verify-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearFormError();
  resetResult();                       // never let an old verdict linger
  $("result-empty").textContent = "正在进行双树重建核验…";
  const btn = $("submit-btn");
  btn.disabled = true;
  try {
    let payload;
    try {
      payload = collectPayload();
    } catch (err) {
      throw new Error("叶/兄弟 JSON 数组解析失败：" + err.message);
    }
    const r = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (d.ok) renderSuccess(d); else renderFailure(d);
  } catch (err) {
    showFormError("提交失败（未获得 API 结论）：" + err.message);
    $("result-empty").textContent = "本次提交因网络或解析错误未产生结论。";
  } finally {
    btn.disabled = false;
  }
});

refreshHealth();

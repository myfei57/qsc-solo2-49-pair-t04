const LAMP_SOURCES = [
  ["对中确认", (s) => s.aligned],
  ["张力已落盘", (s) => s.tension && s.tension.allowed],
  ["酸泵运行", (s) => s.pump && s.pump.running],
  ["喷淋开启", (s) => s.pickle && s.pickle.rinsing],
  ["排风建立", (s) => s.exit && s.exit.exhaust],
  ["烘干升温", (s) => s.dry && s.dry.heating],
  ["焊接联锁释放", (s) => s.weld && s.weld.interlock],
  ["带尾已冲净", (s) => s.strip && !s.strip.tailDirty],
];

function fmt(value, digits) {
  if (value === null || value === undefined) {
    return "-";
  }
  if (typeof value === "number") {
    return value.toFixed(digits === undefined ? 1 : digits);
  }
  return String(value);
}

async function loadJSON(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!data.ok) {
    const detail = data.detail && data.detail.detail ? data.detail.detail : data.error;
    throw new Error(detail || "request failed");
  }
  return data;
}

function post(path, params) {
  const query = params ? "?" + new URLSearchParams(params).toString() : "";
  return loadJSON(path + query, { method: "POST", headers: { Accept: "application/json" } });
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = value;
  }
}

function renderState(state) {
  const badge = document.getElementById("phase");
  badge.textContent = state.phase || "idle";
  badge.className = "badge " + (state.phase === "fault" ? "fault" : "running");
  setText("coil", state.coil || "-");
  setText("head", fmt(state.head, 1));
  setText("aligned", state.aligned ? "已确认" : "未确认");
  setText("track", fmt(state.strip ? state.strip.track : 0, 1));
  setText("tension", fmt(state.tension ? state.tension.setpoint : 0, 1));
  setText("effective", fmt(state.tension ? state.tension.effective : 0, 1));
  setText("concentration", fmt(state.pickle ? state.pickle.concentration : 0, 2));
  setText("level", fmt(state.pickle ? state.pickle.level : 0, 2));
  setText("rinsing", state.pickle && state.pickle.rinsing ? "开" : "关");
  setText("pump", state.pump && state.pump.running ? "运行" : "停");
  setText("dry", state.dry && state.dry.heating ? "升温" : "停");
  setText("tail", state.strip && state.strip.tailDirty ? "脏" : "净");
  setText("speed", fmt(state.strip ? state.strip.speed : 0, 2));
  setText("travel", fmt(state.strip ? state.strip.travel : 0, 1));

  const lamps = document.getElementById("lamps");
  lamps.innerHTML = "";
  LAMP_SOURCES.forEach(function (entry) {
    const li = document.createElement("li");
    const on = Boolean(entry[1](state));
    li.className = "lamp " + (on ? "on" : "off");
    li.textContent = entry[0];
    lamps.appendChild(li);
  });

  const alarms = document.getElementById("alarmList");
  alarms.innerHTML = "";
  const active = state.alarms || [];
  if (!active.length) {
    const li = document.createElement("li");
    li.className = "clear";
    li.textContent = "无活动告警";
    alarms.appendChild(li);
  } else {
    active.forEach(function (id) {
      const li = document.createElement("li");
      li.textContent = id;
      alarms.appendChild(li);
    });
  }
}

function renderEvents(events) {
  const list = document.getElementById("auditList");
  list.innerHTML = "";
  if (!events.length) {
    const li = document.createElement("li");
    li.textContent = "没有符合条件的记录";
    list.appendChild(li);
    return;
  }
  events.slice().reverse().forEach(function (event) {
    const li = document.createElement("li");
    const when = event.at ? new Date(event.at).toLocaleString() : "";
    li.textContent = when + " [" + event.kind + "] " + (event.message || "");
    list.appendChild(li);
  });
}

function renderSummary(summary) {
  const list = document.getElementById("summary");
  list.innerHTML = "";
  Object.keys(summary).sort().forEach(function (kind) {
    const li = document.createElement("li");
    li.textContent = kind + " x " + summary[kind];
    list.appendChild(li);
  });
}

function renderLedger(exports) {
  const list = document.getElementById("exportLedger");
  list.innerHTML = "";
  if (!exports.length) {
    const li = document.createElement("li");
    li.className = "clear";
    li.textContent = "暂无导出记录";
    list.appendChild(li);
    return;
  }
  exports.slice().reverse().forEach(function (receipt) {
    const li = document.createElement("li");
    const criteria = receipt.criteria || {};
    const kinds = criteria.kinds && criteria.kinds.length ? criteria.kinds.join(",") : "全部类别";
    const span = [criteria.start || "起点", criteria.end || "至今"].join(" ~ ");
    li.textContent = receipt.exportedAt.replace("T", " ").slice(0, 19)
      + " ｜ " + kinds + " ｜ " + span
      + " ｜ " + receipt.eventCount + " 条 ｜ " + receipt.sha256.slice(0, 16);
    li.title = receipt.sha256;
    list.appendChild(li);
  });
}

function renderSequence(sequence) {
  const list = document.getElementById("sequenceList");
  list.innerHTML = "";
  if (!sequence) {
    return;
  }
  const head = document.createElement("li");
  head.textContent = "流程 " + (sequence.label || "-");
  list.appendChild(head);
  (sequence.steps || []).forEach(function (step) {
    const li = document.createElement("li");
    li.className = step.ok ? "step-ok" : "step-bad";
    li.textContent = (step.ok ? "通过 " : "失败 ") + step.name + (step.detail ? " :: " + step.detail : "");
    list.appendChild(li);
  });
}

async function refresh() {
  try {
    const data = await loadJSON("/api/state");
    renderState(data.state || {});
    renderSequence(data.state ? data.state.sequence : null);
    const summary = await loadJSON("/api/audit/summary");
    renderSummary(summary.summary || {});
    const ledger = await loadJSON("/api/audit/exports");
    renderLedger(ledger.exports || []);
  } catch (error) {
    console.error(error);
  }
}

function auditParams(form) {
  const params = new URLSearchParams();
  form.querySelectorAll("input[data-kind]:checked").forEach(function (box) {
    params.append("kind", box.dataset.kind);
  });
  if (form.start.value) {
    params.set("start", new Date(form.start.value).toISOString());
  }
  if (form.end.value) {
    params.set("end", new Date(form.end.value).toISOString());
  }
  const limit = parseInt(form.limit.value, 10);
  if (Number.isFinite(limit) && limit > 0) {
    params.set("limit", limit);
  }
  return params;
}

async function runAuditSearch(form) {
  const data = await loadJSON("/api/audit?" + auditParams(form).toString());
  renderEvents(data.events || []);
  const meta = document.getElementById("auditMeta");
  meta.textContent = "命中 " + data.count + " 条（按时间正序返回，页面倒序展示）";
}

async function exportArchive(form) {
  const response = await fetch("/api/audit/export?" + auditParams(form).toString());
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "导出失败");
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = match ? match[1] : "audit-export.zip";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

const OP_CALLS = {
  "weld-confirm": () => post("/api/weld/confirm"),
  "weld-alarm": () => post("/api/weld/alarm"),
  "weld-clear": () => post("/api/weld/clear"),
  "weld-release": () => post("/api/weld/release"),
  "dry-heat": () => post("/api/dry/heat"),
  "dry-reheat": () => post("/api/dry/reheat"),
  "entry-correct": () => post("/api/entry/correct"),
  "stop": () => post("/api/stop"),
  "strip-sag": async () => {
    const data = await loadJSON("/api/strip/sag");
    window.alert("垂度 " + fmt(data.sag, 2) + " mm");
  },
};

const FORM_CALLS = {
  "weld-power": (form) => post("/api/weld/power", readForm(form)),
  "weld-splice": (form) => post("/api/weld/splice", readForm(form)),
  "tension-ramp": (form) => post("/api/tension/ramp", readForm(form)),
  "tension-calibrate": (form) => post("/api/tension/calibrate", readForm(form)),
  "pump-start": (form) => post("/api/pump/start", readForm(form)),
  "pump-replenish": (form) => post("/api/pump/replenish", readForm(form)),
  "pickle-calibrate": (form) => post("/api/pickle/calibrate", readForm(form)),
  "dry-dew": (form) => post("/api/dry/dew", readForm(form)),
  "dry-heat-target": (form) => post("/api/dry/heat-target", readForm(form)),
  "strip-advance": (form) => post("/api/strip/advance", readForm(form)),
  "strip-speed": (form) => post("/api/strip/speed", readForm(form)),
  "entry-offset": (form) => post("/api/entry/offset", readForm(form)),
  "entry-sample": (form) => post("/api/entry/sample", readForm(form)),
  "shear-offset": (form) => post("/api/exit/shear-offset", readForm(form)),
  "exit-weight": (form) => post("/api/exit/weight", readForm(form)),
  "cycle": (form) => post("/api/cycle", readForm(form)),
};

function readForm(form) {
  const data = {};
  new FormData(form).forEach(function (value, key) {
    data[key] = value;
  });
  return data;
}

const auditForm = document.getElementById("auditFilter");

auditForm.addEventListener("submit", async function (event) {
  event.preventDefault();
  const meta = document.getElementById("auditMeta");
  meta.textContent = "查询中…";
  try {
    await runAuditSearch(auditForm);
  } catch (error) {
    meta.textContent = "";
    window.alert(error.message);
  }
});

document.getElementById("auditExportBtn").addEventListener("click", async function () {
  const meta = document.getElementById("auditMeta");
  meta.textContent = "正在生成签名归档包…";
  try {
    await exportArchive(auditForm);
    meta.textContent = "归档包已导出（内含 SHA-256 清单与 HMAC 签名，记录不可篡改）";
    await refresh();
  } catch (error) {
    meta.textContent = "";
    window.alert(error.message);
  }
});

document.getElementById("archiveVerify").addEventListener("submit", async function (event) {
  event.preventDefault();
  const output = document.getElementById("verifyResult");
  const fileInput = this.archive;
  if (!fileInput.files.length) {
    return;
  }
  output.textContent = "校验中…";
  const body = new FormData();
  body.append("archive", fileInput.files[0]);
  try {
    const response = await fetch("/api/audit/verify", { method: "POST", body: body });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      output.textContent = "校验失败：" + (data.error || "归档包已被改动或密钥不符");
      return;
    }
    const manifest = data.manifest;
    output.textContent =
      "校验通过 ✓\n" +
      "生成时间: " + manifest.createdAt + "\n" +
      "记录条数: " + manifest.eventCount + "\n" +
      "查询类别: " + ((manifest.criteria.kinds || ["全部"]).join(", ")) + "\n" +
      "时间范围: " + (manifest.criteria.start || "起点") + " ~ " + (manifest.criteria.end || "至今") + "\n" +
      "events 哈希: " + manifest.eventsSha256 + "\n" +
      "校验时间: " + data.verifiedAt;
  } catch (error) {
    output.textContent = "校验失败：" + error.message;
  }
});

document.querySelectorAll("button[data-op]").forEach(function (button) {
  button.addEventListener("click", async function () {
    const call = OP_CALLS[button.dataset.op];
    if (!call) {
      return;
    }
    try {
      await call();
      await refresh();
    } catch (error) {
      window.alert(error.message);
    }
  });
});

document.querySelectorAll("form[data-form]").forEach(function (form) {
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    const call = FORM_CALLS[form.dataset.form];
    if (!call) {
      return;
    }
    try {
      await call(form);
      await refresh();
    } catch (error) {
      window.alert(error.message);
    }
  });
});

document.querySelectorAll("button.tab").forEach(function (button) {
  button.addEventListener("click", function () {
    document.querySelectorAll(".tabpage").forEach(function (page) {
      page.classList.add("hidden");
    });
    const target = document.getElementById("tab-" + button.dataset.tab);
    if (target) {
      target.classList.remove("hidden");
    }
  });
});

refresh();
setInterval(refresh, 3000);
runAuditSearch(auditForm).catch(function (error) {
  console.error(error);
});

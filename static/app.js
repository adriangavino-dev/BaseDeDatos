"use strict";

const $ = (sel) => document.querySelector(sel);
const sqlBox = $("#sql");
const runBtn = $("#run-btn");
const clearBtn = $("#clear-btn");
const resultArea = $("#result-area");
const resultMeta = $("#result-meta");

// --------------------------------------------------------------------------
// Panel lateral: esquema de tablas
// --------------------------------------------------------------------------
function buildSchema() {
  const list = $("#table-list");
  const schema = window.SCHEMA || {};
  Object.keys(schema).forEach((tableName) => {
    const li = document.createElement("li");

    const name = document.createElement("span");
    name.className = "table-name";
    name.textContent = tableName;

    const cols = document.createElement("div");
    cols.className = "cols";
    schema[tableName].forEach((c, i) => {
      const chip = document.createElement("span");
      chip.className = "col-chip";
      chip.textContent = c;
      chip.addEventListener("click", (e) => {
        e.stopPropagation();
        insertAtCursor(c);
      });
      cols.appendChild(chip);
      if (i < schema[tableName].length - 1) {
        cols.appendChild(document.createTextNode(", "));
      }
    });

    name.addEventListener("click", () => {
      cols.classList.toggle("open");
      name.classList.toggle("expanded");
    });
    name.addEventListener("dblclick", () => insertAtCursor(tableName));

    li.appendChild(name);
    li.appendChild(cols);
    list.appendChild(li);
  });
}

function insertAtCursor(text) {
  const start = sqlBox.selectionStart;
  const end = sqlBox.selectionEnd;
  sqlBox.value = sqlBox.value.slice(0, start) + text + sqlBox.value.slice(end);
  sqlBox.selectionStart = sqlBox.selectionEnd = start + text.length;
  sqlBox.focus();
}

// --------------------------------------------------------------------------
// Vista: tabla vs JSON
// --------------------------------------------------------------------------
let lastData = null;
let viewMode = "table";

function setViewMode(mode) {
  viewMode = mode;
  const btnTable = $("#btn-view-table");
  const btnJson = $("#btn-view-json");
  if (btnTable) btnTable.classList.toggle("active", mode === "table");
  if (btnJson) btnJson.classList.toggle("active", mode === "json");
  if (lastData) renderResult(lastData, true);
}

function buildViewToggle() {
  const wrap = document.createElement("span");
  wrap.className = "view-toggle";

  const btnTable = document.createElement("button");
  btnTable.id = "btn-view-table";
  btnTable.textContent = "Tabla";
  btnTable.className = viewMode === "table" ? "active" : "";
  btnTable.addEventListener("click", () => setViewMode("table"));

  const btnJson = document.createElement("button");
  btnJson.id = "btn-view-json";
  btnJson.textContent = "JSON";
  btnJson.className = viewMode === "json" ? "active" : "";
  btnJson.addEventListener("click", () => setViewMode("json"));

  wrap.appendChild(btnTable);
  wrap.appendChild(btnJson);
  return wrap;
}

// --------------------------------------------------------------------------
// Ejecutar consulta
// --------------------------------------------------------------------------
async function runQuery() {
  const sql = sqlBox.value.trim();
  if (!sql) {
    showError("Escribe una consulta primero.");
    return;
  }

  runBtn.disabled = true;
  resultMeta.innerHTML = '<span class="hint" style="margin:0">Ejecutando&hellip;</span>';
  resultArea.innerHTML = '<p class="placeholder"><span class="big">⏳</span>Ejecutando consulta&hellip;</p>';

  try {
    const resp = await fetch("/api/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sql }),
    });
    const data = await resp.json();

    if (data.error) {
      showError(data.error);
    } else {
      lastData = data;
      renderResult(data);
    }
  } catch (err) {
    showError("No se pudo contactar al servidor: " + err.message);
  } finally {
    runBtn.disabled = false;
  }
}

function showError(msg) {
  resultMeta.innerHTML = '<span class="err-msg">⚠️ ' + escapeHtml(msg) + "</span>";
  resultArea.innerHTML = '<p class="placeholder"><span class="big">🚫</span>Consulta rechazada.</p>';
}

function renderResult(data, skipMeta) {
  if (!skipMeta) {
    const parts = [
      '<span class="chip ok">✓ ' + data.rowcount + " fila(s)</span>",
      '<span class="chip time">⏱ ' + data.elapsed_ms + " ms</span>",
    ];
    if (data.truncated) {
      parts.push('<span class="chip warn">resultado recortado (límite de filas)</span>');
    }
    resultMeta.innerHTML = parts.join(" ");
    resultMeta.appendChild(buildViewToggle());
  }

  if (data.rowcount === 0) {
    resultArea.innerHTML = '<p class="placeholder"><span class="big">∅</span>La consulta no devolvió filas.</p>';
    return;
  }

  // EXPLAIN -> una sola columna "QUERY PLAN": mostrar como texto plano.
  if (data.columns.length === 1 && /query plan/i.test(data.columns[0])) {
    const text = data.rows.map((r) => r[0]).join("\n");
    const pre = document.createElement("pre");
    pre.className = "explain";
    pre.textContent = text;
    resultArea.innerHTML = "";
    resultArea.appendChild(pre);
    return;
  }

  if (viewMode === "json") {
    renderJson(data.columns, data.rows);
  } else {
    renderTable(data.columns, data.rows);
  }
}

function renderJson(columns, rows) {
  const objects = rows.map((row) => {
    const obj = {};
    columns.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
  const pre = document.createElement("pre");
  pre.className = "json-view";
  pre.textContent = JSON.stringify(objects, null, 2);
  resultArea.innerHTML = "";
  resultArea.appendChild(pre);
}

function renderTable(columns, rows) {
  const table = document.createElement("table");
  table.className = "result";

  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  htr.appendChild(th("#", "rownum"));
  columns.forEach((c) => htr.appendChild(th(c)));
  thead.appendChild(htr);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((row, idx) => {
    const tr = document.createElement("tr");
    tr.appendChild(td(String(idx + 1), "rownum"));
    row.forEach((val) => {
      if (val === null) {
        tr.appendChild(td("NULL", "null"));
      } else {
        tr.appendChild(td(String(val)));
      }
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  resultArea.innerHTML = "";
  resultArea.appendChild(table);
}

function th(text, cls) {
  const el = document.createElement("th");
  el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
function td(text, cls) {
  const el = document.createElement("td");
  el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// --------------------------------------------------------------------------
// Estado de la conexión
// --------------------------------------------------------------------------
async function checkHealth() {
  const el = $("#db-status");
  try {
    const resp = await fetch("/api/health");
    const data = await resp.json();
    if (data.ok) {
      el.textContent = "Conectado a " + data.database;
      el.className = "status ok";
    } else {
      el.textContent = "Sin conexión a la BD";
      el.className = "status err";
      el.title = data.error || "";
    }
  } catch (e) {
    el.textContent = "Servidor no responde";
    el.className = "status err";
  }
}

// --------------------------------------------------------------------------
// Eventos
// --------------------------------------------------------------------------
runBtn.addEventListener("click", runQuery);
clearBtn.addEventListener("click", () => {
  sqlBox.value = "";
  lastData = null;
  viewMode = "table";
  resultMeta.innerHTML = '<span class="hint" style="margin:0">Ejecuta una consulta para ver los resultados.</span>';
  resultArea.innerHTML = '<p class="placeholder"><span class="big">🗒️</span>Los resultados aparecerán aquí.</p>';
  sqlBox.focus();
});
sqlBox.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    runQuery();
  }
});

buildSchema();
checkHealth();

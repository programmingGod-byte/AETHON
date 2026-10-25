"use strict";

const list = document.getElementById("notes");
const form = document.getElementById("note-form");
const input = document.getElementById("note-text");
const statusEl = document.getElementById("status");

async function api(path, opts) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function render(notes) {
  list.replaceChildren();
  for (const n of notes) {
    const li = document.createElement("li");
    const text = document.createElement("span");
    text.textContent = n.text; // textContent, never innerHTML: no XSS
    const del = document.createElement("button");
    del.textContent = "Delete";
    del.onclick = async () => {
      await api(`/api/notes/${n.id}`, { method: "DELETE" });
      load();
    };
    li.append(text, del);
    list.append(li);
  }
}

async function load() {
  try {
    const { notes } = await api("/api/notes");
    render(notes);
  } catch (e) {
    statusEl.textContent = `Error: ${e.message}`;
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  try {
    await api("/api/notes", { method: "POST", body: JSON.stringify({ text }) });
    input.value = "";
    load();
  } catch (err) {
    statusEl.textContent = `Error: ${err.message}`;
  }
});

api("/api/health")
  .then((h) => { statusEl.textContent = `Backend OK (uptime ${h.uptime_s}s)`; statusEl.classList.add("ok"); })
  .catch(() => { statusEl.textContent = "Backend unreachable"; });
load();

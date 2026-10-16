/**
 * Interfaz web de TaskGuard.
 *
 * Flujo: login/registro -> verificación OTP -> panel de tareas.
 *
 * Seguridad en el cliente:
 *  - El token JWT se guarda en sessionStorage: se borra al cerrar la pestaña.
 *  - Todo texto que viene del usuario se inserta con textContent (nunca
 *    innerHTML), así un título como "<script>" se muestra como texto (evita XSS).
 *  - Si la API responde 401, se cierra la sesión local y se vuelve al login.
 *  - El token se renueva automáticamente antes de expirar (/auth/refresh).
 */
"use strict";

const TOKEN_KEY = "taskguard.token";
const TOKEN_EXP_KEY = "taskguard.tokenExp";

const state = {
  pendingEmail: null, // correo que está verificando el OTP
  otpTimer: null,
  refreshTimer: null,
  user: null,
  editingTaskId: null,
  searchDebounce: null,
};

const $ = (selector) => document.querySelector(selector);

// ---------------------------------------------------------------- utilidades

/** Muestra una notificación temporal. */
function toast(message, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), 4500);
}

/** Muestra solo la vista indicada (auth, otp o app). */
function showView(name) {
  for (const view of ["auth", "otp", "app"]) {
    $(`#view-${view}`).hidden = view !== name;
  }
}

/** Convierte "2026-10-16" en fecha local sin problemas de zona horaria. */
function parseDate(isoDate) {
  const [y, m, d] = isoDate.split("-").map(Number);
  return new Date(y, m - 1, d);
}

function todayStart() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

function formatDate(isoDate) {
  return parseDate(isoDate).toLocaleDateString("es", { day: "numeric", month: "short", year: "numeric" });
}

/** Deshabilita el botón de envío mientras se procesa un formulario. */
async function withSubmitLock(form, action) {
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await action();
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------- token

function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

function saveToken({ access_token, expires_in }) {
  sessionStorage.setItem(TOKEN_KEY, access_token);
  sessionStorage.setItem(TOKEN_EXP_KEY, String(Date.now() + expires_in * 1000));
  scheduleRefresh();
}

function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_EXP_KEY);
  clearTimeout(state.refreshTimer);
}

/** Programa la renovación del token cuando le quede ~20 % de vida. */
function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  const expiresAt = Number(sessionStorage.getItem(TOKEN_EXP_KEY));
  if (!expiresAt) return;
  const remaining = expiresAt - Date.now();
  const delay = Math.max(remaining * 0.8, 5000);
  state.refreshTimer = setTimeout(refreshToken, delay);
}

async function refreshToken() {
  try {
    const data = await api("/auth/refresh", { method: "POST" });
    saveToken(data);
  } catch {
    // Si falla, api() ya gestionó el 401 y devolvió al login.
  }
}

// ---------------------------------------------------------------- API

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** Convierte la respuesta de error de la API en un mensaje legible. */
function errorMessage(status, body) {
  if (status === 429) return "Demasiados intentos. Espera un momento e inténtalo de nuevo.";
  if (body && Array.isArray(body.errors) && body.errors.length) {
    return body.errors.map((e) => (e.field ? `${e.field}: ${e.message}` : e.message)).join(" · ");
  }
  if (body && typeof body.detail === "string") return body.detail;
  return "Ocurrió un error inesperado.";
}

/**
 * Llama a la API con JSON y el token (si existe).
 * Lanza ApiError si la respuesta no es correcta.
 */
async function api(path, { method = "GET", body, auth = true } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (auth && token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  } catch {
    throw new ApiError(0, "No se pudo conectar con el servidor.");
  }

  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401 && auth) {
      // Token expirado, revocado o inválido: se cierra la sesión local.
      endSession("Tu sesión expiró. Inicia sesión de nuevo.");
    }
    throw new ApiError(response.status, errorMessage(response.status, data));
  }
  return data;
}

// ---------------------------------------------------------------- autenticación

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((el) => el.classList.toggle("active", el.dataset.tab === tab));
  $("#form-login").hidden = tab !== "login";
  $("#form-register").hidden = tab !== "register";
}

async function handleRegister(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  await withSubmitLock(form, async () => {
    try {
      // El registro envía un OTP: verificarlo confirma el correo e inicia sesión.
      const data = await api("/auth/register", { method: "POST", body: values, auth: false });
      toast("Cuenta creada. Revisa tu correo para verificarla.", "success");
      form.reset();
      startOtpStep(values.email, data.email, data.otp_expires_in);
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  await withSubmitLock(form, async () => {
    try {
      const data = await api("/auth/login", { method: "POST", body: values, auth: false });
      form.password.value = "";
      startOtpStep(values.email, data.email, data.otp_expires_in);
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

/** Muestra la pantalla del OTP con la cuenta atrás de validez. */
function startOtpStep(email, maskedEmail, expiresIn) {
  state.pendingEmail = email;
  $("#otp-email").textContent = maskedEmail;
  $("#form-otp").reset();
  showView("otp");
  $("#form-otp").code.focus();
  startOtpCountdown(expiresIn);
}

function startOtpCountdown(seconds) {
  clearInterval(state.otpTimer);
  const end = Date.now() + seconds * 1000;
  const render = () => {
    const left = Math.max(0, Math.round((end - Date.now()) / 1000));
    const mm = String(Math.floor(left / 60)).padStart(2, "0");
    const ss = String(left % 60).padStart(2, "0");
    $("#otp-timer").textContent = left > 0 ? `${mm}:${ss}` : "expirado — pide uno nuevo";
    if (left === 0) clearInterval(state.otpTimer);
  };
  render();
  state.otpTimer = setInterval(render, 1000);
}

async function handleVerifyOtp(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const code = form.code.value.trim();
  if (!/^\d{6}$/.test(code)) {
    toast("El código debe tener 6 dígitos.", "error");
    return;
  }
  await withSubmitLock(form, async () => {
    try {
      const data = await api("/auth/verify-otp", {
        method: "POST",
        body: { email: state.pendingEmail, code },
        auth: false,
      });
      clearInterval(state.otpTimer);
      saveToken(data);
      state.pendingEmail = null;
      await enterApp();
      toast("Sesión iniciada correctamente.", "success");
    } catch (err) {
      toast(err.message, "error");
      form.code.select();
    }
  });
}

async function handleResendOtp(event) {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const data = await api("/auth/resend-otp", { method: "POST", body: { email: state.pendingEmail }, auth: false });
    toast(data.message, "success");
    startOtpCountdown(15 * 60);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    // Pequeña espera antes de permitir otro reenvío.
    setTimeout(() => { button.disabled = false; }, 30000);
  }
}

/** Cierra la sesión local (sin llamar a la API) y vuelve al login. */
function endSession(message) {
  clearToken();
  state.user = null;
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  showView("auth");
  switchTab("login");
  if (message) toast(message, "error");
}

async function handleLogout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    // Aunque falle (p. ej. token ya expirado), se limpia la sesión local.
  }
  endSession();
  toast("Sesión cerrada.", "success");
}

// ---------------------------------------------------------------- panel

async function enterApp() {
  state.user = await api("/users/profile");
  $("#user-name").textContent = state.user.full_name;
  showView("app");
  await loadTasks();
}

/** Construye la URL de /tasks con los filtros seleccionados. */
function tasksQuery() {
  const params = new URLSearchParams();
  const status = $("#filter-status").value;
  const priority = $("#filter-priority").value;
  const search = $("#filter-search").value.trim();
  if (status) params.set("completed", status);
  if (priority) params.set("priority", priority);
  if (search) params.set("search", search);
  const query = params.toString();
  return query ? `/tasks?${query}` : "/tasks";
}

async function loadTasks() {
  try {
    const [tasks, summary] = await Promise.all([api(tasksQuery()), api("/tasks/summary")]);
    renderSummary(summary);
    renderTasks(tasks);
  } catch (err) {
    if (err.status !== 401) toast(err.message, "error");
  }
}

function renderSummary(summary) {
  $("#stat-total").textContent = summary.total;
  $("#stat-pending").textContent = summary.pending;
  $("#stat-completed").textContent = summary.completed;
  $("#stat-overdue").textContent = summary.overdue;
}

/** Pinta la lista de tareas creando los elementos con textContent (sin innerHTML). */
function renderTasks(tasks) {
  const list = $("#task-list");
  list.replaceChildren(...tasks.map(renderTask));
  $("#task-empty").hidden = tasks.length > 0;
}

function renderTask(task) {
  const item = document.createElement("li");
  item.className = `task${task.completed ? " done" : ""}`;

  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = task.completed;
  checkbox.setAttribute("aria-label", "Marcar como completada");
  checkbox.addEventListener("change", () => toggleTask(task, checkbox));

  const body = document.createElement("div");
  const title = document.createElement("div");
  title.className = "task-title";
  title.textContent = task.title;
  body.append(title);

  if (task.description) {
    const desc = document.createElement("p");
    desc.className = "task-desc";
    desc.textContent = task.description;
    body.append(desc);
  }

  const meta = document.createElement("div");
  meta.className = "task-meta";
  const priority = document.createElement("span");
  priority.className = `badge ${task.priority}`;
  priority.textContent = `Prioridad ${task.priority}`;
  meta.append(priority);
  if (task.due_date) {
    const due = document.createElement("span");
    const overdue = !task.completed && parseDate(task.due_date) < todayStart();
    due.className = `badge${overdue ? " overdue" : ""}`;
    due.textContent = `${overdue ? "Venció" : "Vence"} ${formatDate(task.due_date)}`;
    meta.append(due);
  }
  body.append(meta);

  const actions = document.createElement("div");
  actions.className = "task-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "btn icon";
  edit.textContent = "Editar";
  edit.addEventListener("click", () => openEditDialog(task));
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn icon danger";
  remove.textContent = "Eliminar";
  remove.addEventListener("click", () => deleteTask(task));
  actions.append(edit, remove);

  item.append(checkbox, body, actions);
  return item;
}

/** Lee el formulario de tarea y lo convierte al formato de la API. */
function taskPayload(form) {
  return {
    title: form.title.value.trim(),
    description: form.description.value.trim(),
    priority: form.priority.value,
    due_date: form.due_date.value || null,
  };
}

async function handleCreateTask(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = taskPayload(form);
  if (!payload.title) {
    toast("Escribe un título para la tarea.", "error");
    form.title.focus();
    return;
  }
  await withSubmitLock(form, async () => {
    try {
      await api("/tasks", { method: "POST", body: payload });
      form.reset();
      form.priority.value = "media";
      await loadTasks();
      toast("Tarea añadida.", "success");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "error");
    }
  });
}

async function toggleTask(task, checkbox) {
  checkbox.disabled = true;
  try {
    await api(`/tasks/${task.id}`, { method: "PUT", body: { completed: checkbox.checked } });
    await loadTasks();
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    if (err.status !== 401) toast(err.message, "error");
  } finally {
    checkbox.disabled = false;
  }
}

async function deleteTask(task) {
  if (!confirm(`¿Eliminar la tarea "${task.title}"?`)) return;
  try {
    await api(`/tasks/${task.id}`, { method: "DELETE" });
    await loadTasks();
    toast("Tarea eliminada.", "success");
  } catch (err) {
    if (err.status !== 401) toast(err.message, "error");
  }
}

function openEditDialog(task) {
  const form = $("#form-edit-task");
  state.editingTaskId = task.id;
  form.title.value = task.title;
  form.description.value = task.description;
  form.priority.value = task.priority;
  form.due_date.value = task.due_date || "";
  $("#dialog-task").showModal();
  form.title.focus();
}

async function handleEditTask(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = taskPayload(form);
  if (!payload.title) {
    toast("El título no puede estar vacío.", "error");
    return;
  }
  await withSubmitLock(form, async () => {
    try {
      await api(`/tasks/${state.editingTaskId}`, { method: "PUT", body: payload });
      $("#dialog-task").close();
      await loadTasks();
      toast("Tarea actualizada.", "success");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "error");
    }
  });
}

// ---------------------------------------------------------------- perfil

function openProfileDialog() {
  const form = $("#form-profile");
  form.reset();
  form.full_name.value = state.user.full_name;
  $("#profile-email").textContent = state.user.email;
  $("#dialog-profile").showModal();
}

async function handleProfile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {};
  const name = form.full_name.value.trim();
  if (name && name !== state.user.full_name) payload.full_name = name;
  if (form.new_password.value) {
    payload.new_password = form.new_password.value;
    payload.current_password = form.current_password.value;
  }
  if (!Object.keys(payload).length) {
    $("#dialog-profile").close();
    return;
  }
  await withSubmitLock(form, async () => {
    try {
      state.user = await api("/users/profile", { method: "PUT", body: payload });
      $("#user-name").textContent = state.user.full_name;
      $("#dialog-profile").close();
      toast("Perfil actualizado.", "success");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "error");
    }
  });
}

// ---------------------------------------------------------------- inicio

function bindEvents() {
  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));
  $("#form-login").addEventListener("submit", handleLogin);
  $("#form-register").addEventListener("submit", handleRegister);
  $("#form-otp").addEventListener("submit", handleVerifyOtp);
  $("#btn-otp-resend").addEventListener("click", handleResendOtp);
  $("#btn-otp-back").addEventListener("click", () => {
    clearInterval(state.otpTimer);
    showView("auth");
  });
  $("#form-otp").code.addEventListener("input", (e) => {
    e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);
  });

  $("#btn-logout").addEventListener("click", handleLogout);
  $("#btn-profile").addEventListener("click", openProfileDialog);
  $("#form-task").addEventListener("submit", handleCreateTask);
  $("#form-edit-task").addEventListener("submit", handleEditTask);
  $("#form-profile").addEventListener("submit", handleProfile);
  document.querySelectorAll("[data-close]").forEach((btn) =>
    btn.addEventListener("click", () => btn.closest("dialog").close()),
  );

  $("#filter-status").addEventListener("change", loadTasks);
  $("#filter-priority").addEventListener("change", loadTasks);
  $("#filter-search").addEventListener("input", () => {
    clearTimeout(state.searchDebounce);
    state.searchDebounce = setTimeout(loadTasks, 300);
  });
}

async function init() {
  bindEvents();
  if (getToken()) {
    // Hay una sesión en esta pestaña: se comprueba que siga siendo válida.
    try {
      scheduleRefresh();
      await enterApp();
      return;
    } catch {
      clearToken();
    }
  }
  showView("auth");
}

init();

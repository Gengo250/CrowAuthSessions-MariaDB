#include "todo.hpp"

#include <mysql/mysql.h>

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <type_traits>

// ---------------- Random SID ----------------
static std::string random_hex(std::size_t bytes) {
  std::random_device rd;
  std::uniform_int_distribution<int> dist(0, 255);

  std::ostringstream oss;
  oss << std::hex;
  for (std::size_t i = 0; i < bytes; i++) {
    int v = dist(rd);
    oss.width(2);
    oss.fill('0');
    oss << v;
  }
  return oss.str();
}

// ---------------- Db (thread-local connection) ----------------
static std::mutex g_cfg_mtx;
static DbConfig g_cfg;
static std::atomic<bool> g_db_ready{false};

struct ThreadConn {
  MYSQL* conn = nullptr;
  bool thread_inited = false;
  bool connected = false;

  ~ThreadConn() {
    if (conn) mysql_close(conn);
    if (thread_inited) mysql_thread_end();
  }
};

static thread_local ThreadConn tl;

void Db::init(DbConfig cfg) {
  std::lock_guard<std::mutex> lk(g_cfg_mtx);
  g_cfg = std::move(cfg);
  g_db_ready.store(true, std::memory_order_release);

  mysql_library_init(0, nullptr, nullptr);
}

bool Db::is_ready() {
  return g_db_ready.load(std::memory_order_acquire);
}

DbConfig Db::config() {
  std::lock_guard<std::mutex> lk(g_cfg_mtx);
  return g_cfg;
}

void Db::ensure_thread_conn() {
  if (!is_ready()) return;
  if (tl.connected && tl.conn) return;

  if (!tl.thread_inited) {
    mysql_thread_init();
    tl.thread_inited = true;
  }

  DbConfig cfg = config();

  tl.conn = mysql_init(nullptr);
  if (!tl.conn) return;

  // Reconnect (best-effort)
  {
    bool reconnect = true;
    mysql_options(tl.conn, MYSQL_OPT_RECONNECT, &reconnect);
  }

  if (!mysql_real_connect(
          tl.conn,
          cfg.host.c_str(),
          cfg.user.c_str(),
          cfg.pass.c_str(),
          cfg.db.c_str(),
          static_cast<unsigned int>(cfg.port),
          nullptr,
          0)) {
    mysql_close(tl.conn);
    tl.conn = nullptr;
    tl.connected = false;
    return;
  }

  mysql_set_character_set(tl.conn, "utf8mb4");
  tl.connected = true;
}

void* Db::raw_conn() {
  ensure_thread_conn();
  return tl.conn;
}

// ---------------- AuthService (MySQL-backed) ----------------

static bool stmt_exec(MYSQL_STMT* stmt) {
  if (!stmt) return false;
  return mysql_stmt_execute(stmt) == 0;
}

static void maybe_cleanup_expired_sessions(MYSQL* conn) {
  // Limpeza leve: 1% das vezes pra não ficar caro.
  static thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_int_distribution<int> dist(1, 100);
  if (dist(rng) != 1) return;

  mysql_query(conn, "DELETE FROM sessions WHERE expires_at <= NOW()");
}

AuthService::AuthService(std::chrono::seconds ttl) : ttl_(ttl) {}

std::optional<uint64_t> AuthService::authenticate(const std::string& username, const std::string& password) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return std::nullopt;

  using is_null_t = std::remove_pointer_t<decltype(MYSQL_BIND{}.is_null)>;

  // MVP: password_hash guarda senha em texto (depois trocamos por hash).
  const char* sql = "SELECT id, password_hash FROM users WHERE username = ? LIMIT 1";
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return std::nullopt;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  MYSQL_BIND bind_param[1]{};
  bind_param[0].buffer_type = MYSQL_TYPE_STRING;
  bind_param[0].buffer = (void*)username.c_str();
  bind_param[0].buffer_length = static_cast<unsigned long>(username.size());

  if (mysql_stmt_bind_param(stmt, bind_param) != 0 || !stmt_exec(stmt)) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  uint64_t id = 0;
  char pwbuf[256]{};
  unsigned long pwlen = 0;
  is_null_t is_null_id = 0;
  is_null_t is_null_pw = 0;

  MYSQL_BIND bind_out[2]{};
  bind_out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  bind_out[0].buffer = &id;
  bind_out[0].is_null = &is_null_id;

  bind_out[1].buffer_type = MYSQL_TYPE_STRING;
  bind_out[1].buffer = pwbuf;
  bind_out[1].buffer_length = sizeof(pwbuf);
  bind_out[1].length = &pwlen;
  bind_out[1].is_null = &is_null_pw;

  if (mysql_stmt_bind_result(stmt, bind_out) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  if (mysql_stmt_store_result(stmt) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  int fetch_rc = mysql_stmt_fetch(stmt);
  mysql_stmt_free_result(stmt);
  mysql_stmt_close(stmt);

  if (fetch_rc != 0 || is_null_id || is_null_pw) return std::nullopt;

  std::string stored(pwbuf, pwlen);
  if (stored != password) return std::nullopt;

  return id;
}

std::optional<uint64_t> AuthService::register_user(const std::string& username,
                                                   const std::string& password,
                                                   std::string* out_error) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) {
    if (out_error) *out_error = "Banco indisponível.";
    return std::nullopt;
  }

  const char* sql = "INSERT INTO users (username, password_hash, last_login) VALUES (?, ?, NOW())";
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) {
    if (out_error) *out_error = "Erro interno (stmt).";
    return std::nullopt;
  }

  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    if (out_error) *out_error = "Erro interno (prepare).";
    return std::nullopt;
  }

  MYSQL_BIND p[2]{};
  p[0].buffer_type = MYSQL_TYPE_STRING;
  p[0].buffer = (void*)username.c_str();
  p[0].buffer_length = static_cast<unsigned long>(username.size());

  p[1].buffer_type = MYSQL_TYPE_STRING;
  p[1].buffer = (void*)password.c_str();
  p[1].buffer_length = static_cast<unsigned long>(password.size());

  if (mysql_stmt_bind_param(stmt, p) != 0 || mysql_stmt_execute(stmt) != 0) {
    unsigned int err = mysql_stmt_errno(stmt);
    mysql_stmt_close(stmt);

    if (err == 1062) { // duplicate key
      if (out_error) *out_error = "Este usuário já existe.";
    } else {
      if (out_error) *out_error = "Erro ao cadastrar usuário.";
    }
    return std::nullopt;
  }

  uint64_t new_id = (uint64_t)mysql_stmt_insert_id(stmt);
  mysql_stmt_close(stmt);
  return new_id;
}

void AuthService::touch_last_login(uint64_t user_id) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return;

  const char* sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return;
  }

  MYSQL_BIND p[1]{};
  p[0].buffer_type = MYSQL_TYPE_LONGLONG;
  p[0].buffer = &user_id;

  mysql_stmt_bind_param(stmt, p);
  mysql_stmt_execute(stmt);
  mysql_stmt_close(stmt);
}

std::optional<std::string> AuthService::create_session(uint64_t user_id) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return std::nullopt;

  maybe_cleanup_expired_sessions(conn);

  const std::string sid = random_hex(32);
  const unsigned int ttl_seconds = static_cast<unsigned int>(ttl_.count());

  const char* sql = "INSERT INTO sessions (sid, user_id, expires_at) "
                    "VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))";
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return std::nullopt;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  MYSQL_BIND p[3]{};
  p[0].buffer_type = MYSQL_TYPE_STRING;
  p[0].buffer = (void*)sid.c_str();
  p[0].buffer_length = static_cast<unsigned long>(sid.size());

  p[1].buffer_type = MYSQL_TYPE_LONGLONG;
  p[1].buffer = &user_id;

  p[2].buffer_type = MYSQL_TYPE_LONG;
  p[2].buffer = (void*)&ttl_seconds;

  if (mysql_stmt_bind_param(stmt, p) != 0 || !stmt_exec(stmt)) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  mysql_stmt_close(stmt);
  return sid;
}

std::optional<AuthService::SessionUser> AuthService::session_user_from_sid(const std::string& sid) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return std::nullopt;

  using is_null_t = std::remove_pointer_t<decltype(MYSQL_BIND{}.is_null)>;

  maybe_cleanup_expired_sessions(conn);

  const char* sql =
      "SELECT u.id, u.username "
      "FROM sessions s "
      "JOIN users u ON u.id = s.user_id "
      "WHERE s.sid = ? AND s.expires_at > NOW() "
      "LIMIT 1";

  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return std::nullopt;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  MYSQL_BIND p[1]{};
  p[0].buffer_type = MYSQL_TYPE_STRING;
  p[0].buffer = (void*)sid.c_str();
  p[0].buffer_length = static_cast<unsigned long>(sid.size());

  if (mysql_stmt_bind_param(stmt, p) != 0 || !stmt_exec(stmt)) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  uint64_t uid = 0;
  char userbuf[128]{};
  unsigned long userlen = 0;
  is_null_t is_null_uid = 0;
  is_null_t is_null_user = 0;

  MYSQL_BIND out[2]{};
  out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out[0].buffer = &uid;
  out[0].is_null = &is_null_uid;

  out[1].buffer_type = MYSQL_TYPE_STRING;
  out[1].buffer = userbuf;
  out[1].buffer_length = sizeof(userbuf);
  out[1].length = &userlen;
  out[1].is_null = &is_null_user;

  if (mysql_stmt_bind_result(stmt, out) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  if (mysql_stmt_store_result(stmt) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  int fetch_rc = mysql_stmt_fetch(stmt);
  mysql_stmt_free_result(stmt);
  mysql_stmt_close(stmt);

  if (fetch_rc != 0 || is_null_uid || is_null_user) return std::nullopt;

  // Sliding expiration: renova TTL
  const unsigned int ttl_seconds = static_cast<unsigned int>(ttl_.count());
  const char* up =
      "UPDATE sessions SET expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND) "
      "WHERE sid = ?";

  MYSQL_STMT* upstmt = mysql_stmt_init(conn);
  if (upstmt && mysql_stmt_prepare(upstmt, up, static_cast<unsigned long>(std::strlen(up))) == 0) {
    MYSQL_BIND upb[2]{};
    upb[0].buffer_type = MYSQL_TYPE_LONG;
    upb[0].buffer = (void*)&ttl_seconds;

    upb[1].buffer_type = MYSQL_TYPE_STRING;
    upb[1].buffer = (void*)sid.c_str();
    upb[1].buffer_length = static_cast<unsigned long>(sid.size());

    mysql_stmt_bind_param(upstmt, upb);
    mysql_stmt_execute(upstmt);
    mysql_stmt_close(upstmt);
  } else if (upstmt) {
    mysql_stmt_close(upstmt);
  }

  return SessionUser{uid, std::string(userbuf, userlen)};
}

std::optional<AuthService::UserProfile> AuthService::profile_by_user_id(uint64_t user_id) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return std::nullopt;

  using is_null_t = std::remove_pointer_t<decltype(MYSQL_BIND{}.is_null)>;

  const char* sql =
      "SELECT username, "
      "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at, "
      "DATE_FORMAT(last_login, '%Y-%m-%d %H:%i:%s') AS last_login "
      "FROM users WHERE id = ? LIMIT 1";

  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return std::nullopt;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  MYSQL_BIND p[1]{};
  p[0].buffer_type = MYSQL_TYPE_LONGLONG;
  p[0].buffer = &user_id;

  if (mysql_stmt_bind_param(stmt, p) != 0 || !stmt_exec(stmt)) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  char ubuf[128]{};
  unsigned long ulen = 0;
  is_null_t is_null_u = 0;

  char cbuf[32]{};
  unsigned long clen = 0;
  is_null_t is_null_c = 0;

  char lbuf[32]{};
  unsigned long llen = 0;
  is_null_t is_null_l = 0;

  MYSQL_BIND out[3]{};
  out[0].buffer_type = MYSQL_TYPE_STRING;
  out[0].buffer = ubuf;
  out[0].buffer_length = sizeof(ubuf);
  out[0].length = &ulen;
  out[0].is_null = &is_null_u;

  out[1].buffer_type = MYSQL_TYPE_STRING;
  out[1].buffer = cbuf;
  out[1].buffer_length = sizeof(cbuf);
  out[1].length = &clen;
  out[1].is_null = &is_null_c;

  out[2].buffer_type = MYSQL_TYPE_STRING;
  out[2].buffer = lbuf;
  out[2].buffer_length = sizeof(lbuf);
  out[2].length = &llen;
  out[2].is_null = &is_null_l;

  if (mysql_stmt_bind_result(stmt, out) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  if (mysql_stmt_store_result(stmt) != 0) {
    mysql_stmt_close(stmt);
    return std::nullopt;
  }

  int fetch_rc = mysql_stmt_fetch(stmt);
  mysql_stmt_free_result(stmt);
  mysql_stmt_close(stmt);

  if (fetch_rc != 0 || is_null_u || is_null_c) return std::nullopt;

  UserProfile prof;
  prof.username = std::string(ubuf, ulen);
  prof.created_at = std::string(cbuf, clen);
  if (!is_null_l) prof.last_login = std::string(lbuf, llen);
  return prof;
}

void AuthService::logout(const std::string& sid) {
  auto* conn = static_cast<MYSQL*>(Db::raw_conn());
  if (!conn) return;

  const char* sql = "DELETE FROM sessions WHERE sid = ?";
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) return;
  if (mysql_stmt_prepare(stmt, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
    mysql_stmt_close(stmt);
    return;
  }

  MYSQL_BIND p[1]{};
  p[0].buffer_type = MYSQL_TYPE_STRING;
  p[0].buffer = (void*)sid.c_str();
  p[0].buffer_length = static_cast<unsigned long>(sid.size());

  mysql_stmt_bind_param(stmt, p);
  mysql_stmt_execute(stmt);
  mysql_stmt_close(stmt);
}

// ---------------- TodoApp ----------------

TodoApp::TodoApp(int port) : port_(port), app_(), auth_(std::chrono::hours(12)) {
  Db::init(load_db_config_from_env());
  crow::mustache::set_base("templates");
  register_routes();
}

void TodoApp::register_routes() {
  CROW_ROUTE(app_, "/")([this](const crow::request& req) { return this->handle_root(req); });

  CROW_ROUTE(app_, "/login").methods(crow::HTTPMethod::GET)([this] { return this->handle_login_get(); });
  CROW_ROUTE(app_, "/login").methods(crow::HTTPMethod::POST)([this](const crow::request& req) { return this->handle_login_post(req); });

  // Compat caminho antigo
  CROW_ROUTE(app_, "/app_web_crow_mysql/login").methods(crow::HTTPMethod::GET)([this] { return this->handle_login_get(); });
  CROW_ROUTE(app_, "/app_web_crow_mysql/login").methods(crow::HTTPMethod::POST)([this](const crow::request& req) { return this->handle_login_post(req); });

  CROW_ROUTE(app_, "/register").methods(crow::HTTPMethod::GET)([this] { return this->handle_register_get(); });
  CROW_ROUTE(app_, "/register").methods(crow::HTTPMethod::POST)([this](const crow::request& req) { return this->handle_register_post(req); });

  CROW_ROUTE(app_, "/dashboard")([this](const crow::request& req) { return this->handle_dashboard_get(req); });

  CROW_ROUTE(app_, "/profile")([this](const crow::request& req) { return this->handle_profile_get(req); });

  CROW_ROUTE(app_, "/logout")([this](const crow::request& req) { return this->handle_logout_get(req); });

  CROW_ROUTE(app_, "/assets/<path>")([this](const crow::request& req, std::string relpath) {
    return this->handle_assets_get(req, std::move(relpath));
  });
}

void TodoApp::run() {
  app_.port(static_cast<uint16_t>(port_)).multithreaded().run();
}

// ---------- Validation ----------
bool TodoApp::is_username_valid(const std::string& u) {
  if (u.size() < 3 || u.size() > 32) return false;
  for (unsigned char ch : u) {
    if (!(std::isalnum(ch) || ch == '_' || ch == '.')) return false;
  }
  return true;
}

// ---------- Handlers ----------
crow::response TodoApp::handle_root(const crow::request& req) {
  auto sid = cookie_get(req, "sid");
  if (sid) {
    auto su = auth_.session_user_from_sid(*sid);
    if (su) return redirect_to("/dashboard");
  }
  return redirect_to("/login");
}

crow::response TodoApp::handle_login_get() {
  crow::mustache::context ctx;
  ctx["title"] = "Login";
  crow::response res(crow::mustache::load("login.html").render(ctx));
  res.set_header("Content-Type", "text/html; charset=utf-8");
  return res;
}

crow::response TodoApp::handle_login_post(const crow::request& req) {
  auto mid = form_get_urlencoded(req, "mid");
  auto mpass = form_get_urlencoded(req, "mpass");

  if (!mid || !mpass) {
    crow::mustache::context ctx;
    ctx["title"] = "Login";
    ctx["error"] = "Preencha usuário e senha.";
    crow::response res(crow::mustache::load("login.html").render(ctx));
    res.code = 400;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  auto user_id = auth_.authenticate(*mid, *mpass);
  if (!user_id) {
    crow::mustache::context ctx;
    ctx["title"] = "Login";
    ctx["error"] = "Login inválido.";
    crow::response res(crow::mustache::load("login.html").render(ctx));
    res.code = 401;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  auth_.touch_last_login(*user_id);

  auto sid = auth_.create_session(*user_id);
  if (!sid) {
    crow::response res("Erro ao criar sessão no banco.");
    res.code = 500;
    return res;
  }

  auto res = redirect_to("/dashboard");
  set_cookie_sid(res, *sid, 12 * 60 * 60);
  return res;
}

crow::response TodoApp::handle_register_get() {
  crow::mustache::context ctx;
  ctx["title"] = "Cadastro";
  crow::response res(crow::mustache::load("register.html").render(ctx));
  res.set_header("Content-Type", "text/html; charset=utf-8");
  return res;
}

crow::response TodoApp::handle_register_post(const crow::request& req) {
  auto u = form_get_urlencoded(req, "username");
  auto p = form_get_urlencoded(req, "password");
  auto pc = form_get_urlencoded(req, "password_confirm");

  crow::mustache::context ctx;
  ctx["title"] = "Cadastro";

  if (!u || !p || !pc) {
    ctx["error"] = "Preencha todos os campos.";
    crow::response res(crow::mustache::load("register.html").render(ctx));
    res.code = 400;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  if (!is_username_valid(*u)) {
    ctx["error"] = "Usuário inválido: 3-32 chars, letras/números e _ .";
    crow::response res(crow::mustache::load("register.html").render(ctx));
    res.code = 400;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  if (p->size() < 6) {
    ctx["error"] = "Senha muito curta (mínimo 6).";
    crow::response res(crow::mustache::load("register.html").render(ctx));
    res.code = 400;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  if (*p != *pc) {
    ctx["error"] = "As senhas não conferem.";
    crow::response res(crow::mustache::load("register.html").render(ctx));
    res.code = 400;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  std::string reg_err;
  auto user_id = auth_.register_user(*u, *p, &reg_err);
  if (!user_id) {
    ctx["error"] = reg_err.empty() ? "Falha ao cadastrar." : reg_err;
    crow::response res(crow::mustache::load("register.html").render(ctx));
    res.code = 409; // conflito (username já existe)
    res.set_header("Content-Type", "text/html; charset=utf-8");
    return res;
  }

  // Auto-login após cadastro
  auto sid = auth_.create_session(*user_id);
  if (!sid) {
    crow::response res("Usuário criado, mas falha ao criar sessão.");
    res.code = 500;
    return res;
  }

  auto res = redirect_to("/dashboard");
  set_cookie_sid(res, *sid, 12 * 60 * 60);
  return res;
}

crow::response TodoApp::handle_dashboard_get(const crow::request& req) {
  auto sid = cookie_get(req, "sid");
  if (!sid) return redirect_to("/login");

  auto su = auth_.session_user_from_sid(*sid);
  if (!su) return redirect_to("/login");

  crow::mustache::context ctx;
  ctx["title"] = "Dashboard";
  ctx["user"] = su->username;

  crow::response res(crow::mustache::load("dashboard.html").render(ctx));
  res.set_header("Content-Type", "text/html; charset=utf-8");
  return res;
}

crow::response TodoApp::handle_profile_get(const crow::request& req) {
  auto sid = cookie_get(req, "sid");
  if (!sid) return redirect_to("/login");

  auto su = auth_.session_user_from_sid(*sid);
  if (!su) return redirect_to("/login");

  auto prof = auth_.profile_by_user_id(su->user_id);
  if (!prof) return redirect_to("/dashboard");

  crow::mustache::context ctx;
  ctx["title"] = "Perfil";
  ctx["username"] = prof->username;
  ctx["created_at"] = prof->created_at;
  ctx["last_login"] = prof->last_login.value_or("Nunca");

  crow::response res(crow::mustache::load("profile.html").render(ctx));
  res.set_header("Content-Type", "text/html; charset=utf-8");
  return res;
}

crow::response TodoApp::handle_logout_get(const crow::request& req) {
  auto sid = cookie_get(req, "sid");
  if (sid) auth_.logout(*sid);

  auto res = redirect_to("/login");
  clear_cookie_sid(res);
  return res;
}

crow::response TodoApp::handle_assets_get(const crow::request&, std::string relpath) {
  if (relpath.find("..") != std::string::npos || (!relpath.empty() && relpath[0] == '/')) {
    return crow::response(400);
  }

  const std::string full = "static/" + relpath;
  std::string content = read_file(full);
  if (content.empty()) return crow::response(404);

  crow::response res;
  res.code = 200;
  res.set_header("Content-Type", mime_from_path(full));
  res.body = std::move(content);
  return res;
}

// ---------- Helpers HTTP ----------
std::optional<std::string> TodoApp::cookie_get(const crow::request& req, const std::string& name) {
  const std::string cookie = req.get_header_value("Cookie");
  if (cookie.empty()) return std::nullopt;

  const std::string needle = name + "=";
  std::size_t pos = 0;

  while (pos < cookie.size()) {
    while (pos < cookie.size() && (cookie[pos] == ' ' || cookie[pos] == ';')) pos++;

    if (cookie.compare(pos, needle.size(), needle) == 0) {
      pos += needle.size();
      std::size_t end = cookie.find(';', pos);
      std::string val = cookie.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
      return val;
    }

    std::size_t next = cookie.find(';', pos);
    if (next == std::string::npos) break;
    pos = next + 1;
  }
  return std::nullopt;
}

void TodoApp::set_cookie_sid(crow::response& res, const std::string& sid, int max_age_seconds) {
  // Produção (HTTPS): acrescente "; Secure"
  std::ostringstream oss;
  oss << "sid=" << sid
      << "; Path=/"
      << "; Max-Age=" << max_age_seconds
      << "; HttpOnly"
      << "; SameSite=Lax";
  res.add_header("Set-Cookie", oss.str());
}

void TodoApp::clear_cookie_sid(crow::response& res) {
  res.add_header("Set-Cookie", "sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
}

crow::response TodoApp::redirect_to(const std::string& where) {
  crow::response res;
  res.code = 302;
  res.set_header("Location", where);
  return res;
}

std::optional<std::string> TodoApp::form_get_urlencoded(const crow::request& req, const std::string& key) {
  const std::string body_qs = "?" + req.body;
  crow::query_string qs(body_qs);
  if (const char* v = qs.get(key); v) return std::string(v);
  return std::nullopt;
}

// ---------- Static ----------
std::string TodoApp::read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::string TodoApp::mime_from_path(const std::string& p) {
  auto dot = p.find_last_of('.');
  std::string ext = (dot == std::string::npos) ? "" : p.substr(dot + 1);
  if (ext == "html") return "text/html; charset=utf-8";
  if (ext == "css")  return "text/css; charset=utf-8";
  if (ext == "js")   return "application/javascript; charset=utf-8";
  if (ext == "png")  return "image/png";
  if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
  if (ext == "svg")  return "image/svg+xml";
  return "application/octet-stream";
}

// ---------- Config ----------
static std::string env_or(const char* key, std::string def) {
  if (const char* v = std::getenv(key); v && *v) return std::string(v);
  return def;
}

DbConfig TodoApp::load_db_config_from_env() {
  DbConfig cfg;
  cfg.host = env_or("CROW_DB_HOST", cfg.host);
  cfg.user = env_or("CROW_DB_USER", cfg.user);
  cfg.pass = env_or("CROW_DB_PASS", cfg.pass);
  cfg.db   = env_or("CROW_DB_NAME", cfg.db);

  if (const char* p = std::getenv("CROW_DB_PORT"); p && *p) {
    try { cfg.port = static_cast<uint16_t>(std::stoi(p)); } catch (...) {}
  }
  return cfg;
}

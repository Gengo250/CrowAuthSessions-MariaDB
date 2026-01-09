#pragma once
#include <crow.h>
#include <crow/mustache.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

struct DbConfig {
  std::string host = "127.0.0.1";
  uint16_t port = 3306;
  std::string user = "crow";
  std::string pass = "";
  std::string db   = "crow_app";
};

// Banco por thread (evita concorrência em uma única conexão).
class Db {
public:
  static void init(DbConfig cfg);
  static bool is_ready();
  static DbConfig config();

  // Retorna conexão do thread atual (lazy). Pode retornar nullptr se falhar.
  static void* raw_conn(); // MYSQL*

private:
  static void ensure_thread_conn();
};

class AuthService {
public:
  struct SessionUser {
    uint64_t user_id{};
    std::string username;
  };

  struct UserProfile {
    std::string username;
    std::string created_at;
    std::optional<std::string> last_login;
  };

  explicit AuthService(std::chrono::seconds ttl = std::chrono::hours(12));

  // Retorna user_id se credenciais ok
  std::optional<uint64_t> authenticate(const std::string& username, const std::string& password);

  // Cria usuário e retorna id; retorna nullopt se username já existe ou erro.
  std::optional<uint64_t> register_user(const std::string& username, const std::string& password, std::string* out_error);

  // Atualiza last_login = NOW()
  void touch_last_login(uint64_t user_id);

  // Cria sessão e retorna SID
  std::optional<std::string> create_session(uint64_t user_id);

  // Valida SID -> (user_id, username) e renova expiração
  std::optional<SessionUser> session_user_from_sid(const std::string& sid);

  // Busca perfil por user_id
  std::optional<UserProfile> profile_by_user_id(uint64_t user_id);

  // Encerra sessão
  void logout(const std::string& sid);

private:
  std::chrono::seconds ttl_;
};

class TodoApp {
public:
  explicit TodoApp(int port = 18080);
  void run();

private:
  // Rotas
  crow::response handle_root(const crow::request& req);

  crow::response handle_login_get();
  crow::response handle_login_post(const crow::request& req);

  crow::response handle_register_get();
  crow::response handle_register_post(const crow::request& req);

  crow::response handle_dashboard_get(const crow::request& req);
  crow::response handle_profile_get(const crow::request& req);

  crow::response handle_logout_get(const crow::request& req);

  crow::response handle_assets_get(const crow::request& req, std::string relpath);

  void register_routes();

  // Helpers HTTP
  static std::optional<std::string> cookie_get(const crow::request& req, const std::string& name);
  static void set_cookie_sid(crow::response& res, const std::string& sid, int max_age_seconds);
  static void clear_cookie_sid(crow::response& res);
  static crow::response redirect_to(const std::string& where);

  static std::optional<std::string> form_get_urlencoded(const crow::request& req, const std::string& key);

  // Static
  static std::string read_file(const std::string& path);
  static std::string mime_from_path(const std::string& path);

  // Config
  static DbConfig load_db_config_from_env();

  // Validation
  static bool is_username_valid(const std::string& u);

private:
  int port_;
  crow::SimpleApp app_;
  AuthService auth_;
};

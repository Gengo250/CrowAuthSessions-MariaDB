#include "todo.hpp"

int main() {
  // Config via env:
  //   export CROW_DB_HOST=127.0.0.1
  //   export CROW_DB_PORT=3306
  //   export CROW_DB_USER=crow
  //   export CROW_DB_PASS='SUA_SENHA'
  //   export CROW_DB_NAME=crow_app
  TodoApp app(18080);
  app.run();
  return 0;
}

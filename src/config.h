#ifndef CONFIG_H
#define CONFIG_H

#include "../lib/cpptoml.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

class IRCConfig
{
public:
    struct Server
    {
        std::string host; // Хост IRC сервера
        int port; // Порт IRC сервера
        std::string password; // Пароль к IRC серверу
    };

    struct Client
    {
        std::string username; // Имя пользователя
        std::string nickname; // Основной ник
        std::string alt_nick; // Альтернативный ник
        std::string realname; // RealName
        std::string nickserv_password;       // Пароль для NickServ
        std::vector<std::string> channels;  // Каналы
        std::vector<std::string> admins;    // Админы
        std::string run_at_connect;         // Команды после подключения
        std::string dcc_version;            // Версия для CTCP VERSION
        bool auto_connect;                  // Автозапуск
        char command_symbol;                // Символ команды бота
    };

    struct Feature
    {
        std::string ip_info_token;  // Токен для ipinfo.io
        std::string log_file;       // Имя файла лога в директории ./log
        bool hide_pingpong;         // Скрывать PING-PONG
        bool output_tty;          // Выводить подробную информацию о событиях
        bool output_raw;            // Выводить RAW данные
        bool debug_mode;            // Режим отладки
        bool is_configured = false; // Флаг, указывающий, что конфигурация была отредактирована
    };

    explicit IRCConfig(const std::string &filename);

    const Server &get_server() const { return server_; }
    const Client &get_client() const { return client_; }
    const Feature &get_feature() const { return feature_; }

    void createConfig(const std::string &filename) const;
    void printConfig() const;

private:
    Server server_;
    Client client_;
    Feature feature_;
    std::string runtime_file_; // Имя файла runtime
    std::vector<std::string> split(const std::string &str, char delimiter = ',');
};
#endif // CONFIG_H
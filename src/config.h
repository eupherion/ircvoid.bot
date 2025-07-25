#pragma once

#include "cpptoml.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

class IRCConfig
{
public:
    struct Server
    {
        std::string host;
        int port;
        std::string password;
    };

    struct Client
    {
        std::string username;
        std::string nickname; // Основной ник
        std::string realname; // RealName
        std::string nickserv_password;
        std::vector<std::string> channels;  // Каналы
        std::vector<std::string> admins;    // Админы
        std::vector<std::string> alt_nicks; // Альтернативные ники
        std::string run_at_connect;         // Команды после подключения
        std::string dcc_version;            // Версия для CTCP VERSION
        bool auto_connect;                  // Автозапуск
        char command_symbol;                // Символ команды бота
    };

    struct Feature
    {
        std::string ip_info_token; // Токен для ipinfo.io
        bool debug_mode; // Режим отладки
        std::string log_file; // Имя файла лога в директории ./log
    };

    explicit IRCConfig(const std::string &filename);

    const Server &get_server() const { return server_; }
    const Client &get_client() const { return client_; }
    const Feature &get_feature() const { return feature_; }

    void saveRuntimeConfig() const;
    bool validate() const;
    void print() const;

private:
    Server server_;
    Client client_;
    Feature feature_;
    std::string runtime_file_; // Имя файла runtime
    std::vector<std::string> split(const std::string &str, char delimiter = ',');
};
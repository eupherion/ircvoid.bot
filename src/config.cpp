#include "config.h"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <boost/algorithm/string.hpp>

// Разделение строки на вектор по разделителю
std::vector<std::string> IRCConfig::split(const std::string &str, char delimiter)
{
    std::vector<std::string> tokens;

    // Разделяем по символу-разделителю
    boost::algorithm::split(
        tokens, str,
        [delimiter](char c)
        { return c == delimiter; },
        boost::algorithm::token_compress_off);

    // Очищаем каждую подстроку от пробелов и табуляций
    for (std::string &token : tokens)
    {
        boost::algorithm::trim(token);
    }

    // Удаляем пустые строки
    tokens.erase(
        std::remove_if(tokens.begin(), tokens.end(),
                       [](const std::string &s)
                       { return s.empty(); }),
        tokens.end());

    return tokens;
}

IRCConfig::IRCConfig(const std::string &filename)
{
    const std::string runtime_file = "bot.run";

    try
    {
        // Шаг 1: Создаём bot.run, если его нет
        if (!std::filesystem::exists(runtime_file))
        {
            if (!std::filesystem::exists(filename))
            {
                throw std::runtime_error("Source config file not found: " + filename);
            }
            std::filesystem::copy_file(filename, runtime_file);
            std::cout << "[i] Created runtime config: " << runtime_file << std::endl;
        }

        // Шаг 2: Парсим из bot.run
        auto table = cpptoml::parse_file(runtime_file);

        // [ircServer]
        auto ircServer = table->get_table("ircServer");
        server_.host = *ircServer->get_as<std::string>("ircServerHost");
        server_.port = *ircServer->get_as<int>("ircServerPort");
        server_.password = *ircServer->get_as<std::string>("ircServerPass");

        // [ircClient]
        auto ircClient = table->get_table("ircClient");
        client_.username = *ircClient->get_as<std::string>("ircBotUser");
        client_.nickname = *ircClient->get_as<std::string>("ircBotNick");
        client_.realname = *ircClient->get_as<std::string>("ircBotRnam");
        client_.nickserv_password = *ircClient->get_as<std::string>("ircBotNspw");

        // Получаем список каналов
        std::string channels_str = *ircClient->get_as<std::string>("ircBotChan");
        client_.channels = split(channels_str, ',');

        // Получаем список админов
        std::string admins_str = *ircClient->get_as<std::string>("ircBotAdmi");
        client_.admins = split(admins_str, ',');

        // Получаем список альтернативных никнеймов
        if (auto alt_nicks = ircClient->get_array_of<std::string>("ircBotNalt"))
        {
            client_.alt_nicks = *alt_nicks;
        }
        else
        {
            client_.alt_nicks.push_back(client_.nickname + "_");
        }

        client_.run_at_connect = *ircClient->get_as<std::string>("ircBotRcon");
        client_.dcc_version = *ircClient->get_as<std::string>("ircBotDccv");
        client_.auto_connect = *ircClient->get_as<bool>("ircBotAcon");

        // Командный символ
        std::string csym_str = *ircClient->get_as<std::string>("ircBotCsym");
        if (!csym_str.empty())
        {
            client_.command_symbol = csym_str[0];
        }
        else
        {
            client_.command_symbol = '.';
        }

        // [botComset]
        auto botComset = table->get_table("botComset");
        feature_.ip_info_token = *botComset->get_as<std::string>("ipInfToken");
        feature_.debug_mode = *botComset->get_as<bool>("debugMode");
        feature_.log_file = *botComset->get_as<std::string>("logFileName");
    }
    catch (const cpptoml::parse_exception &e)
    {
        std::cerr << "TOML parsing error: " << e.what() << "\n";
        throw;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing TOML: " << e.what() << "\n";
        throw;
    }
}

bool IRCConfig::validate() const // Проверка на корректность
{/* Проверка runtime */
    return true;
}

void IRCConfig::saveRuntimeConfig() const
{
    try
    {
        // Парсим текущий bot.run
        auto table = cpptoml::parse_file("bot.run");

        auto ircClient = table->get_table("ircClient");

        // Формируем строку каналов: "chan1, chan2, chan3"
        std::ostringstream oss;
        for (size_t i = 0; i < client_.channels.size(); ++i)
        {
            if (i > 0)
                oss << ", ";
            oss << client_.channels[i];
        }
        std::string channels_str = oss.str();

        // Устанавливаем новое значение
        ircClient->insert("ircBotChan", channels_str);

        // Перезаписываем файл
        std::ofstream out("bot.run");
        out << *table;
        out.close();

        std::cout << "[i] Runtime config saved: bot.run" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[ERR] Failed to save runtime config: " << e.what() << std::endl;
    }
}

void IRCConfig::print() const
{
    std::cout << "[IRC Server Configuration]\n";
    std::cout << "Host: " << server_.host << "\n";
    std::cout << "Port: " << server_.port << "\n";
    std::cout << "Password: " << (server_.password.empty() ? "(none)" : "*hidden*") << "\n\n";

    std::cout << "[IRC Client Configuration]\n";
    std::cout << "Username: " << client_.username << "\n";
    std::cout << "Main Nick: " << client_.nickname << "\n";
    std::cout << "RealName: " << client_.realname << "\n";
    std::cout << "NickServ Password: " << (client_.nickserv_password.empty() ? "(none)" : "*hidden*") << "\n";

    std::cout << "Channels: ";
    for (const auto &ch : client_.channels)
        std::cout << ch << " ";
    std::cout << "\n";

    std::cout << "Admins: ";
    for (const auto &adm : client_.admins)
        std::cout << adm << " ";
    std::cout << "\n";

    std::cout << "Auto Connect: " << (client_.auto_connect ? "true" : "false") << "\n";
    std::cout << "Command Symbol: '" << client_.command_symbol << "'\n";
    std::cout << "CTCP Version: " << client_.dcc_version << "\n";
    std::cout << "Run on connect: " << client_.run_at_connect << "\n\n";

    std::cout << "[Bot Features]\n";
    std::cout << "IP Info Token: " << feature_.ip_info_token << "\n";
    std::cout << "Debug Mode: " << (feature_.debug_mode ? "true" : "false") << "\n";
    std::cout << "Log File: " << feature_.log_file << "\n\n";
}
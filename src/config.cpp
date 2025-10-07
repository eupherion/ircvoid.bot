#include "config.h"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <iostream>

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

void IRCConfig::createConfig(const std::string &filename) const
{
    std::string config_content = R"(# Пример конфигурационного файла для IRC-бота

[ircServer]	# Параметры IRC сервера
ircServerHost = "irc.rizon.net"   # Адрес сервера IRC
ircServerPort = 7000              # Порт сервера IRC
ircServerPass = ""                # Пароль сервера (ZNC и сервера с паролем)

[ircClient] # Параметры IRC клиента
ircBotUser = "cbot"               # Имя пользователя бота
ircBotNick = "CxxBot"             # Основной ник бота
ircBotNalt = "CxxBot_, CBot1"     # Альтернативные ники
ircBotRnam = "IP info Bot"        # Реальное имя (RealName)
ircBotNspw = ""                   # Пароль NickServ (двойные кавычки обязательны, пустое если авторизация не нужна)
ircBotChan = "#test, #ircx"       # Каналы, к которым присоединяется бот при подключении
ircBotAdmi = "const, aesh"        # Ники администраторов бота
ircBotAcon = false                # Подключаться ли при старте (только для  работы в foreground, иначе игнорируется)
ircBotCsym = "."                  # Символ команды бота
ircBotRcon = ""                   # Сообщения серверу при соединении 
ircBotDccv = "C++ IRC bot"        # CTCP DCC VERSION

[botComset] # Параметры дополнительных функций бота
ipInfoToken = ""               # Токен сервиса ipinfo.io
logFileName = "mybot.irc.log"  # Имя лог-файла бота
hidePingPong = true            # Скрывать PING? PONG! сервера (в т.ч. из логов)
outputVerbose = true           # RAW вывод на консоль (только при работе в foreground)
outputDebug = false            # Флаг отладочного режима (только при работе в foreground)
botConfigured = false          # Флаг, что дефолтная конфигурация отредактирована, иначе не запустится
)";
    std::string edit_note = R"(Sample config file created. Edit config.toml and run the bot again.)";

    std::ofstream file(filename);
    if (file.is_open())
    {
        file << config_content;
        file.close();
        std::cout << "[ i ] " << edit_note << std::endl;
    }
    else
    {
        std::cerr << "[ERR] Failed to create default config file: " << filename << std::endl;
    }
}

IRCConfig::IRCConfig(const std::string &filename)
{
    bool source_exists = std::filesystem::exists(filename); // Проверяем наличие файла

    if (!source_exists)
    {
        std::string samplename = "config.toml";
        std::cout << "[ i ] No config file found. Creating sample: " << samplename << std::endl;
        createConfig(samplename); // Создаём пример файла
        if (!std::filesystem::exists(samplename))
        {
            // На всякий случай, если createConfig не сработал
            throw std::runtime_error("Failed to create default config file: " + samplename);
        }
    }

    try
    {
        if (!std::filesystem::exists(filename)) // Проверка на всякий случай
        {
            throw std::runtime_error("Source config file not found: " + filename);
        }

        // Шаг 2: Парсим из filename
        auto table = cpptoml::parse_file(filename);

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
        feature_.ip_info_token = *botComset->get_as<std::string>("ipInfoToken");
        feature_.log_file = *botComset->get_as<std::string>("logFileName");
        feature_.hide_pingpong = *botComset->get_as<bool>("hidePingPong");
        feature_.verbose_mode = *botComset->get_as<bool>("outputVerbose");
        feature_.debug_mode = *botComset->get_as<bool>("outputDebug");
        feature_.is_configured = *botComset->get_as<bool>("botConfigured");
    }
    catch (const cpptoml::parse_exception &e)
    {
        std::cerr << "[ERR] Error parsing TOML: " << e.what() << "\n";
        throw;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[ERR] Error parsing file: " << e.what() << "\n";
        throw;
    }
}

void IRCConfig::printConfig() const
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
    std::cout << "Log File: " << feature_.log_file << "\n";
    std::cout << "Ping-Pong Hiding: " << (feature_.hide_pingpong ? "true" : "false") << "\n";
    std::cout << "Output Mode: " << (feature_.verbose_mode ? "Verbose" : "Normal") << "\n";
    std::cout << "Debug Mode: " << (feature_.debug_mode ? "Enabled" : "Disabled") << "\n";
    std::cout << "Bot Configured: " << (feature_.is_configured ? "true" : "false") << "\n\n";
    std::cout << "\n";
}
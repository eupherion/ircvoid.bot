#include "config.h"
#include "ipinfo.h"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <chrono> // Для std::chrono::milliseconds
#include <filesystem>
#include <iostream>
#include <regex> // Для std::regex и std::regex_match
#include <string>
#include <thread> // Для std::this_thread::sleep_for
#include <unordered_set> // Для std::unordered_set
#include <vector>

using boost::asio::ip::tcp;

class IRCBot
{
public:

    bool rusnetAuth = false;

    struct IRCUser
    {
        std::string nick;
        std::string user;
        std::string host;
        std::string realname;

        // Конструктор для создания пользователя по нику (например, из JOIN)
        IRCUser(const std::string &n, const std::string &u = "", const std::string &h = "", const std::string &r = "")
            : nick(n), user(u), host(h), realname(r) {}

        // Оператор сравнения для поиска
        bool operator==(const IRCUser &other) const
        {
            return nick == other.nick;
        }
    };

    struct IRCChan
    {
        std::string name;
        std::string topic;
        std::vector<IRCUser> users;
        bool isJoined = false;

        // Конструктор
        IRCChan(const std::string &n, const std::string &t = "")
            : name(n), topic(t), users(), isJoined(false) {}
    };

    std::vector<IRCChan> channels; // Вектор структур каналов

    IRCBot(boost::asio::io_context &io_context, const IRCConfig &config)
        : socket_(io_context), config_(config) {}

    void start(void)
    {
        const auto &server = config_.get_server();
        tcp::resolver resolver(socket_.get_executor());
        auto endpoints = resolver.resolve(server.host, std::to_string(server.port));
        boost::asio::async_connect(socket_, endpoints,
                                   boost::bind(&IRCBot::handleConnect, this, boost::placeholders::_1 /* , client.nickname, server.password */));
    }

    bool isAdmin(const std::string &nick)
    {
        const auto config = config_.get_client();
        for (const auto &admin : config.admins)
        {
            if (std::equal(admin.begin(), admin.end(),
                           nick.begin(), nick.end(),
                           [](char a, char b)
                           {
                               return std::tolower(static_cast<unsigned char>(a)) ==
                                std::tolower(static_cast<unsigned char>(b));
                           }))
            {
                return true;
            }
        }
        return false;
    }

    void logWrite(const std::string &message)
    {
        auto feature = config_.get_feature();
        const std::string logDir = "./log";
        const std::string logFilePath = logDir + "/" + feature.log_file;

        try
        {
            // Создание директории, если её нет
            if (!std::filesystem::exists(logDir))
            {
                std::filesystem::create_directory(logDir);
            }

            // Проверяем размер файла
            std::ifstream checkFile(logFilePath, std::ios::binary | std::ios::ate);
            if (checkFile.is_open())
            {
                std::streamsize size = checkFile.tellg();
                checkFile.close();

                const std::streamsize max_size = 50 * 1024; // 50 КБ
                if (size >= max_size)
                {
                    // Формируем временную метку для имени
                    auto now = std::chrono::system_clock::now();
                    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
                    std::tm tm = *std::localtime(&now_c);

                    std::ostringstream timestamp;
                    timestamp << std::put_time(&tm, "%Y-%m-%d-%H%M%S"); // 2025-04-05-123456
                    std::string newFileName = logDir + "/" + timestamp.str() + "." + feature.log_file;

                    // Переименовываем старый лог-файл
                    std::filesystem::rename(logFilePath, newFileName);
                }
            }

            // Добавляем временную метку к сообщению
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm tm = *std::localtime(&now_c);

            std::ostringstream time_stream;
            time_stream << std::put_time(&tm, "[%Y-%m-%d %H:%M:%S] ");
            std::string tstamp_message = time_stream.str() + message;

            // Открываем файл для добавления
            std::ofstream log_file(logFilePath, std::ios_base::app);
            if (log_file.is_open())
            {
                log_file << tstamp_message << std::endl;
                log_file.close();

                if (log_file.fail())
                {
                    std::cerr << "[ERR] Failed to write to log file." << std::endl;
                }
            }
            else
            {
                std::cerr << "[ERR] Could not open log file for writing." << std::endl;
            }
        }
        catch (const std::exception &ex)
        {
            std::cerr << "[ERR] Exception in logWrite(): " << ex.what() << std::endl;
        }
        std::cout << message << std::endl;
    }

    void shutdown(void)
    {
        config_.saveRuntimeConfig();
        logWrite("[i] Saving runtime config...");
        sendToServer("QUIT :Shutting down\r\n");
        logWrite("[i] QUIT Command sent to server");

        if (socket_.is_open())
        {
            boost::system::error_code ec;
            socket_.shutdown(tcp::socket::shutdown_both, ec); // Завершение работы с сокетом
            socket_.close(ec);
            logWrite("[i] Bot shutdown complete.\n");
        }

        exit(0); // Принудительный выход из программы
        //io_context_.stop();
    }

    void sendToServer(const std::string &message)
    {
        if (socket_.is_open())
        {
            boost::asio::async_write(socket_, boost::asio::buffer(message),
                                     boost::bind(&IRCBot::handleWrite, this, boost::placeholders::_1));
        }
    }

private:
    tcp::socket socket_;
    std::string incomingBuffer_; // Хранит неполную строку до следующего вызова handleRead()
    enum
    {
        max_length = 4096
    };
    char data_[max_length];
    const IRCConfig &config_; // Теперь конфиг хранится внутри бота
    // Вложенные классы
    class IRCPrefix
    {
    public:
        std::string nick;
        std::string ident;
        std::string host;

        IRCPrefix() = default;

        // Конструктор из строки вида "nick!ident@host"
        IRCPrefix(const std::string &prefixStr)
        {
            parseIrcPrefix(prefixStr);
        }

        void parseIrcPrefix(const std::string &prefixStr)
        {
            std::string::size_type pos1 = prefixStr.find('!');
            std::string::size_type pos2 = prefixStr.find('@');

            if (pos1 != std::string::npos && pos2 != std::string::npos && pos1 < pos2)
            {
                nick = prefixStr.substr(0, pos1);
                ident = prefixStr.substr(pos1 + 1, pos2 - pos1 - 1);
                host = prefixStr.substr(pos2 + 1);
            }
            else
            {
                nick = prefixStr; // Если нет ! или @
            }
        }
    };

    class IRCMessage
    {
    public:
        IRCPrefix prefix;
        std::string command;
        std::vector<std::string> params;
        std::string trailing;

        IRCMessage() = default;

        explicit IRCMessage(const std::string &rawMsg)
        {
            parseIrcMessage(rawMsg);
        }

        void parseIrcMessage(const std::string &rawMsg)
        {
            std::string msg = rawMsg;
            // std::cout << "[Parsing RAW] " << msg << std::endl;
            boost::trim(msg);
            if (msg.empty())
                return;

            params.clear();
            trailing.clear();

            std::istringstream iss(msg);
            std::string line;
            while (std::getline(iss, line))
            {
                boost::trim(line);
                if (line.empty())
                    continue;

                size_t idx = 0;

                // Парсим префикс (начинается с ':')
                if (line[0] == ':')
                {
                    size_t spacePos = line.find(' ');
                    if (spacePos != std::string::npos)
                    {
                        std::string prefixStr = line.substr(1, spacePos - 1);
                        prefix = IRCPrefix(prefixStr); // Заполняем prefix
                        idx = spacePos + 1;
                    }
                }

                // Парсим команду
                size_t nextSpace = line.find(' ', idx);
                if (nextSpace != std::string::npos)
                {
                    command = line.substr(idx, nextSpace - idx);
                    idx = nextSpace + 1;
                }
                else
                {
                    command = line.substr(idx);
                    break;
                }

                // Парсим параметры
                bool trailingFound = false;
                while (idx < line.size())
                {
                    if (line[idx] == ':')
                    {
                        ++idx;
                        trailing = line.substr(idx);
                        trailingFound = true;
                        break;
                    }

                    nextSpace = line.find(' ', idx);
                    if (nextSpace == std::string::npos)
                    {
                        params.push_back(line.substr(idx));
                        break;
                    }

                    params.push_back(line.substr(idx, nextSpace - idx));
                    idx = nextSpace + 1;
                }

                if (!trailingFound && !trailing.empty())
                {
                    trailing.clear();
                }
            }
        }
    };

    IRCMessage ircmsg;

    void handleConnect(const boost::system::error_code &error)
    {
        const auto &server = config_.get_server();
        const auto &client = config_.get_client();
        if (!error)
        {
            std::string logentry = "[+] Connected to " + server.host + ":" + std::to_string(server.port);
            logWrite(logentry);
            std::string message("");
            if (!server.password.empty())
            {
                message += "PASS " + server.password + "\r\n";
            }
            message += "NICK " + client.nickname + "\r\n";
            message += "USER " + client.username + " 0 * :" + client.realname + "\r\n";

            boost::asio::async_write(socket_, boost::asio::buffer(message),
                                     boost::bind(&IRCBot::handleWrite, this, boost::placeholders::_1));
        }
        else
        {
            std::cerr << "[!] Connection failed: " << error.message() << std::endl;
        }
    }

    void handleWrite(const boost::system::error_code &error)
    {
        if (!error)
        {
            startRead(); // Начинаем читать ответ от сервера
        }
        else
        {
            std::cerr << "[!] Write failed: " << error.message() << std::endl;
        }
    }

    void startRead()
    {
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
                                boost::bind(&IRCBot::handleRead, this, boost::placeholders::_1, boost::placeholders::_2));
    }

    void handleRead(const boost::system::error_code &error, size_t bytes_transferred)
    {
        if (!error && bytes_transferred > 0)
        {
            std::string response(data_, bytes_transferred);
            incomingBuffer_ += response; // Добавляем в буфер
            size_t pos = 0;
            while ((pos = incomingBuffer_.find("\r\n")) != std::string::npos) {
                std::string line = incomingBuffer_.substr(0, pos);
                incomingBuffer_.erase(0, pos + 2); // Удаляем обработанную строку
                std::cout << "[RAW] " << line << std::endl;
                if (!line.empty()) {
                    parseServerMessage(line);
                }
            }
            startRead(); // Продолжаем читать
        }
        else
        {
            std::cerr << "[!] Read failed: " << error.message() << std::endl;
        }
    }

    void parseServerMessage(const std::string &line)
    {
        auto &client = config_.get_client();
        auto &feature = config_.get_feature();
        ircmsg.parseIrcMessage(line);

        // Теперь весь парсинг происходит через IRCMessage
        // Можно использовать ircmsg.command, ircmsg.params, ircmsg.trailing и т.д.
        std::string replydest = "";

        if (ircmsg.params[0].find("#") != std::string::npos)
        {
            replydest = ircmsg.params[0];
        }
        else
        {
            replydest = ircmsg.prefix.nick;
        }

        // Пример: обработка PING
        if (ircmsg.command == "PING")
        {
            std::string pong = "PONG :" + ircmsg.trailing + "\r\n";
            sendToServer(pong);
        }

        else if (!ircmsg.trailing.empty() && ircmsg.trailing.front() == '\x01' && ircmsg.trailing.back() == '\x01')
        {
            std::string ctcpCommand = ircmsg.trailing.substr(1, ircmsg.trailing.size() - 2);
            logWrite("[+] Got CTCP: " + ctcpCommand + " from " + ircmsg.prefix.nick);

            if (ctcpCommand.find("VERSION") != std::string::npos)
            {
                if (replydest.empty())
                {
                    std::cout << "[DEBUG] Target is empty\n";
                    return; // Пропускаем, если target пуст
                }
                else
                {
                    sendToServer("NOTICE " + replydest + " :\x01VERSION " + client.dcc_version + "\x01\r\n");
                    logWrite("[+] Sent CTCP [VERSION " + client.dcc_version + "] to " + replydest);
                }
            }

            if (ctcpCommand.find("PING") != std::string::npos)
            {
                if (replydest.empty())
                {
                    std::cout << "[DEBUG] Reply destination is empty\n";
                    return; // Пропускаем, если reply destination пуст
                }
                else
                {
                    sendToServer("NOTICE " + replydest + " :\x01PING " + ircmsg.trailing.substr(6) + "\x01\r\n");
                    logWrite("[+] Sent CTCP PING to " + replydest);
                }
            }

            if (ctcpCommand.find("TIME") != std::string::npos)
            {
                if (replydest.empty())
                {
                    std::cout << "[DEBUG] Reply destination is empty\n";
                    return; // Пропускаем, если reply destination пуст
                }
                else
                {
                    // Получаем текущее время
                    auto now = std::chrono::system_clock::now();
                    auto timestamp = std::chrono::system_clock::to_time_t(now);

                    sendToServer("NOTICE " + replydest + " :\x01TIME " + std::to_string(timestamp) + "\x01\r\n");
                    logWrite("[+] Sent CTCP TIME: " + std::to_string(timestamp) + " to " + ircmsg.prefix.nick);
                }
            }
        }

        else if (ircmsg.command == "020" && ircmsg.trailing.find("RusNet") != std::string::npos)
        {
            logWrite("[+] " + ircmsg.trailing);
            logWrite("[+] RusNet Server detected");

            std::string setmode = "MODE " + client.nickname + " +ix\r\n";
            sendToServer(setmode);
            logWrite("[+] " + setmode);
            rusnetAuth = true;
        }

        else if (ircmsg.command == "376" || ircmsg.command == "422")
        {
            logWrite("[+] End of MOTD command received");
            if (!client.nickserv_password.empty())
            {
                std::string ns_auth = "";
                if (rusnetAuth)
                {
                    std::cout << "[i] RusNet NickServ reply formed\n";
                    ns_auth = "NICKSERV IDENTIFY " + client.nickserv_password + "\r\n";
                }
                else
                {
                    std::cout << "[i] Normal NickServ reply formed\n";
                    ns_auth = "PRIVMSG NickServ :IDENTIFY " + client.nickserv_password + "\r\n";
                }
                sendToServer(ns_auth);
                std::string logentry = "[+] Sent NICKSERV AUTH";
                if (rusnetAuth) {logentry += " (RusNet)";}
                logWrite(logentry);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            for (size_t i = 0; i < client.channels.size(); i++)
            {
                logWrite("[i] Joining channel " + client.channels[i]);
                sendToServer("JOIN " + client.channels[i] + "\r\n");
                sendToServer("WHO " + client.channels[i] + "\r\n");
                //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }

        else if (ircmsg.command == "352") // [RPL_WHOREPLY] :server 352 Alice #chat bob bhost irc.example.org Bobby H :0 Bob Smith
        {
            if (ircmsg.params.size() >= 4)
            {
                std::string userchan = ircmsg.params[1];
                std::string username = ircmsg.params[2];
                std::string userhost = ircmsg.params[3];
                std::string usernick = ircmsg.params[5];
                std::string realname = ircmsg.trailing.substr(ircmsg.trailing.find(' ') + 1);

                // Создаём пользователя
                IRCUser user(usernick, username, userhost, realname);

                // Находим канал и добавляем пользователя
                for (auto &chan : channels)
                {
                    if (chan.name == userchan)
                    {
                        // Проверяем дубликат
                        auto it = std::find_if(chan.users.begin(), chan.users.end(),
                                               [&user](const IRCUser &u)
                                               { return u.nick == user.nick; });

                        if (it == chan.users.end())
                        {
                            // Пользователя нет — добавляем
                            chan.users.push_back(user);
                            if (feature.debug_mode)
                            {
                                std::cout << "[+] User " << user.nick << '!' << user.user << '@' << user.host
                                          << " (" << user.realname << ") added to channel " << userchan << std::endl;
                            }
                        }
                        else
                        {
                            // Пользователь уже есть — обновляем данные
                            it->user = user.user;
                            it->host = user.host;
                            it->realname = user.realname;
                            if (feature.debug_mode)
                            {
                                std::cout << "[i] Updated user " << user.nick << '!' << user.user << '@' << user.host
                                          << " (" << user.realname << ") in channel " << userchan << std::endl;
                            }
                        }
                    }
                }
            }
        }

        else if (ircmsg.command == "353") // [RPL_NAMREPLY] :server 353 yournick = #channel :nick1 nick2 ...
        {
            if (ircmsg.params[0] == client.nickname && ircmsg.params[2].find('#') != std::string::npos)
            {
                auto nicklist = splitStringBySpaces(ircmsg.trailing);
                std::string channelName = ircmsg.params[2];

                bool found = false;
                for (auto &chan : channels)
                {
                    if (chan.name == channelName)
                    {
                        found = true;
                        auto &existingUsers = chan.users;

                        // Используем set для уникальности по нику
                        std::unordered_set<std::string> userSet;
                        for (const auto &u : existingUsers)
                        {
                            userSet.insert(u.nick);
                        }

                        for (const auto &nick : nicklist)
                        {
                            if (userSet.find(nick) == userSet.end())
                            {
                                existingUsers.emplace_back(nick); // Добавляем с минимальными данными
                                userSet.insert(nick);
                            }
                        }

                        std::cout << "[+] Updated user list for " << channelName
                                  << " (" << existingUsers.size() << " users)" << std::endl;
                        break;
                    }
                }

                if (!found)
                {
                    // Создаём новый канал
                    std::vector<IRCUser> users;
                    for (const auto &nick : nicklist)
                    {
                        users.emplace_back(nick);
                    }
                    channels.emplace_back(channelName, "");
                    auto &newChan = channels.back();
                    newChan.users = std::move(users);
                    logWrite("[+] Channel " + channelName + " added to channels vector");
                }
            }
        }

        else if (ircmsg.command == "366") // [RPL_ENDOFNAMES] :server 366 yournick #channel :End of /NAMES list.
        {
            if (ircmsg.params.size() >= 2)
            {
                std::string channelName = ircmsg.params[1];

                for (auto &channel : channels)
                {
                    if (channel.name == channelName)
                    {
                        // Список пользователей завершён — считаем, что бот "присоединён"
                        channel.isJoined = true;
                        std::cout << "[+] Channel " << channelName
                                  << " names saved. There are " << channel.users.size() << " users." << std::endl;
                        break;
                    }
                }
            }
        }

        else if (ircmsg.command == "JOIN") // [JOIN] :nick!user@host JOIN :#channel // Пользователь присоединяется к каналу
        {
            std::string chanjoined = extractChan(ircmsg.trailing);
            std::string nick = ircmsg.prefix.nick;
            std::string user = ircmsg.prefix.ident;
            std::string host = ircmsg.prefix.host;

            for (auto &chan : channels)
            {
                if (chan.name == chanjoined)
                {
                    auto &users = chan.users;
                    auto it = std::find_if(users.begin(), users.end(),
                                           [&nick](const IRCUser &u)
                                           { return u.nick == nick; });

                    if (it == users.end())
                    {
                        // Добавляем пользователя с известными данными
                        users.emplace_back(nick, user, host, ""); // realname = ""
                        logWrite("[+] User " + nick + " joined channel " + chanjoined);
                    }
                    else
                    {
                        // Обновляем данные, если изменились
                        if (it->user != user || it->host != host)
                        {
                            it->user = user;
                            it->host = host;
                            logWrite("[i] Updated host/user for " + nick);
                        }
                    }
                    updateChanNames(chanjoined);
                    break;
                }
            }
        }

        else if (ircmsg.command == "PART") // [PART] :nick!user@host PART #channel:reason // Пользователь покидает канал
        {
            std::string chanleft = ircmsg.params[0];
            std::string nick = ircmsg.prefix.nick;

            if (nick == client.nickname)
            {
                // Бот покидает канал
                auto &chans = channels;
                auto it = std::find_if(chans.begin(), chans.end(),
                                       [&chanleft](const IRCChan &c)
                                       { return c.name == chanleft; });
                if (it != chans.end())
                {
                    chans.erase(it);
                }
                logWrite("[-] Channel " + chanleft + " left and removed from internal lists");
            }
            else
            {
                // Другой пользователь покинул
                for (auto &chan : channels)
                {
                    if (chan.name == chanleft)
                    {
                        auto &users = chan.users;
                        auto it = std::find_if(users.begin(), users.end(),
                                               [&nick](const IRCUser &u)
                                               { return u.nick == nick; });
                        if (it != users.end())
                        {
                            users.erase(it);
                            logWrite("[-] User " + nick + " left channel " + chanleft);
                        }
                        updateChanNames(chanleft);
                        break;
                    }
                }
            }
        }

        else if (ircmsg.command == "QUIT") // [QUIT] :nick!user@host QUIT :reason // Пользователь выходит
        {
            std::string nick = ircmsg.prefix.nick;

            for (auto &chan : channels)
            {
                auto &users = chan.users;
                auto it = std::find_if(users.begin(), users.end(),
                                       [&nick](const IRCUser &u)
                                       { return u.nick == nick; });
                if (it != users.end())
                {
                    users.erase(it);
                    logWrite("[-] User " + nick + " quit from all channels");
                }
            }
        }

        else if (ircmsg.command == "KICK") // [KICK] :nick!user@host KICK #channel kickednick :reason // Пользователь кикнут
        {
            std::string channel = ircmsg.params[0];
            std::string kicked = ircmsg.params[1];

            for (auto &chan : channels)
            {
                if (chan.name == channel)
                {
                    auto &users = chan.users;
                    auto it = std::find_if(users.begin(), users.end(),
                                           [&kicked](const IRCUser &u)
                                           { return u.nick == kicked; });
                    if (it != users.end())
                    {
                        users.erase(it);
                        logWrite("[-] User " + kicked + " was kicked from " + channel);
                    }
                    updateChanNames(channel);
                    break;
                }
            }
        }

        else if (ircmsg.command == "NICK") // [NICK] :nick!user@host NICK :newnick // Пользователь меняет ник
        {
            std::string oldnick = ircmsg.prefix.nick;
            std::string newnick = ircmsg.trailing;
            for (auto &chan : channels)
            {
                for (auto &user : chan.users)
                {
                    if (user.nick == oldnick)
                    {
                        user.nick = newnick;
                        logWrite("[i] Nick changed from " + oldnick + " to " + newnick);
                        updateChanNames(chan.name);
                        break;
                    }
                }
            }
        }

        else if (ircmsg.command == "PRIVMSG") // [PRIVMSG] :nick!user@host PRIVMSG #channel :message // Пользователь пишет в канал
        {
            std::string msgtext = boost::algorithm::trim_copy(ircmsg.trailing);
            std::string command = "";
            std::vector<std::string> cmdargs = {};
            if (!msgtext.empty() && msgtext[0] == client.command_symbol)
            {
                // Разбиваем строку на слова
                std::vector<std::string> parts = splitStringBySpaces(msgtext.substr(1)); // без символа команды

                if (!parts.empty())
                {
                    command = parts[0]; // первая часть - команда
                    if (parts.size() > 1)
                    {
                        for (size_t i = 1; i < parts.size(); ++i)
                        {
                            cmdargs.push_back(parts[i]);
                        }
                    }
                }
            }

            if (feature.debug_mode)
            {
                std::cout << "[DEBUG]: ircmsg.prefix: " << ircmsg.prefix.nick << "!" << ircmsg.prefix.ident << "@" << ircmsg.prefix.host << std::endl;
                std::cout << "[DEBUG]: ircmsg.command: " << ircmsg.command << std::endl;
                for (size_t i = 0; i < ircmsg.params.size(); ++i)
                {
                    std::cout << "[DEBUG]: ircmsg.param[" << i << "]: " << ircmsg.params[i] << std::endl;
                }
                if (!ircmsg.trailing.empty())
                {
                    std::cout << "[DEBUG]: ircmsg.trailing: " << ircmsg.trailing << std::endl;
                }
                if (!command.empty())
                {
                    if (!cmdargs.empty())
                    {
                        std::cout << "[DEBUG]: command: [" << command << ']' << std::endl;
                        std::cout << "[DEBUG]: cmdargs: ";
                        for (const auto &arg : cmdargs)
                        {
                            if (!arg.empty())
                            {
                                std::cout << '[' << arg << ']';
                            }
                        }
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cout << "[DEBUG]: command: [" << command << "] (no args)" << std::endl;
                    }
                }
            }
            std::cout << "[MESSAGE] From " << ircmsg.prefix.nick
                      << " to " << ircmsg.params[0]
                      << ": " << msgtext << std::endl;

            if (command == "chan")
            {
                if (isAdmin(ircmsg.prefix.nick))
                {
                    std::cout << "[i] Admin " << ircmsg.prefix.nick << " command received\n";
                    std::string currentchans = "";
                    for (auto &chan : channels)
                    {
                        currentchans += chan.name + " [" + std::to_string(chan.users.size()) + "] ";
                    }
                    if (!currentchans.empty())
                    {
                        sendToServer("PRIVMSG " + replydest + " :Joined channels: " + currentchans + "\r\n");
                    }
                }
            }

            else if (command == "quit")
            {
                if (client.admins.empty())
                {
                    std::cout << "[ERR] Admins list is empty\n";
                    return; // Пропускаем, если admins пуст
                }
                else
                {
                    std::string reason = "";
                    if (!cmdargs.empty())
                    {
                        for(const auto &arg : cmdargs)
                        {
                            if (!arg.empty())
                            {
                                reason += arg + " ";
                            }
                        }
                    }
                    if (isAdmin(ircmsg.prefix.nick))
                    {
                        std::cout << "[i] Admin " << ircmsg.prefix.nick << " quit command received\n";
                        std::string reply = "";
                        std::string action = "PRIVMSG " + replydest + " :\x01" + "ACTION Going down...\x01\r\n";
                        sendToServer(action);
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));

                        if (!reason.empty())
                        {
                            reply = "PRIVMSG " + replydest + " :Goodbye, " + ircmsg.prefix.nick + "! " + reason + "\r\n";
                        }
                        else
                        {
                            reply = "PRIVMSG " + replydest + " :Goodbye, " + ircmsg.prefix.nick + "!\r\n";
                        }

                        sendToServer(reply);
                        logWrite("[i] Shutdown message sent to " + replydest);
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        logWrite("[!] Shutting down...");
                        shutdown();
                    }
                }
            }

            else if (command == "join")
            {
                if (isAdmin(ircmsg.prefix.nick))
                {
                    std::string chanjoin = "";
                    if (!cmdargs.empty())
                    {
                        chanjoin = extractChan(cmdargs[0]);
                        if (!chanjoin.empty())
                        {
                            sendToServer("JOIN " + chanjoin + "\r\n");
                            sendToServer("PRIVMSG " + replydest + " :\x01" + "ACTION joins " + chanjoin + "\x01\r\n");
                            sendToServer("WHO " + chanjoin + "\r\n");
                            logWrite("[i] Joining channel " + chanjoin + " by " + ircmsg.prefix.nick);
                        }
                    }
                    else
                    {
                        sendToServer("NOTICE " + ircmsg.prefix.nick + " :No channel specified.\r\n");
                        sendToServer("PRIVMSG " + replydest + " : Usage: .join #channel\r\n");
                    }
                }
                else
                {
                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :You are not an admin!\r\n");
                }
            }

            else if (command == "part")
            {
                if (isAdmin(ircmsg.prefix.nick))
                {
                    std::string chanpart = "";
                    if (!cmdargs.empty())
                    {
                        chanpart = extractChan(cmdargs[0]);
                        if (chanpart.empty())
                        {
                            sendToServer("NOTICE " + ircmsg.prefix.nick + " :Invalid channel name.\r\n");
                            return;
                        }
                    }
                    else
                    {
                        // Если аргумента нет, покидаем текущий канал
                        if (ircmsg.params[0].find('#') != std::string::npos)
                        {
                            chanpart = ircmsg.params[0];
                        }
                        else
                        {
                            sendToServer("NOTICE " + ircmsg.prefix.nick + " :No channel specified.\r\n");
                            return;
                        }
                    }

                    // 1. Отправляем команды
                    sendToServer("PRIVMSG " + replydest + " :\x01" + "ACTION parts " + chanpart + "\x01\r\n");
                    sendToServer("PART " + chanpart + "\r\n");
                    logWrite("[i] Parting channel " + chanpart + " by " + ircmsg.prefix.nick);

                    // 2. Удаляем канал из вектора channels
                    auto &chans = channels;
                    auto it = std::find_if(chans.begin(), chans.end(),
                                           [&chanpart](const IRCChan &c)
                                           {
                                               return c.name == chanpart;
                                           });

                    if (it != chans.end())
                    {
                        chans.erase(it);
                        logWrite("[-] Removed channel " + chanpart + " from internal list.");
                    }
                }
                else
                {
                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :You are not an admin!\r\n");
                }
            }

            else if (command == "names")
            {
                if (isAdmin(ircmsg.prefix.nick))
                {
                    if (!cmdargs.empty())
                    {
                        for (const auto &arg : cmdargs)
                        {
                            if (!arg.empty())
                            {
                                std::string chanupdate = extractChan(arg);
                                if (!chanupdate.empty())
                                {
                                    updateChanNames(chanupdate);
                                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                }
                                else
                                {
                                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :Invalid channel name:" + arg + "\r\n");
                                }
                            }
                        }
                    }
                    else
                    {
                        for (const auto &chan : channels)
                        {
                            updateChanNames(chan.name);
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }
                    }
                }
                else
                {
                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :You are not an admin!\r\n");
                }
            }

            else if (command == "loc") // :yournick!~yourhost@yourip PRIVMSG #channel :.loc host
            {
                logWrite("[i] Command " + command + " received by " + ircmsg.prefix.nick + " :" + msgtext);
                std::string loc_reply;
                bool found = false;
                if (!cmdargs.empty())
                {
                    for (const auto &chan : channels)
                    {
                        for (const auto &user : chan.users)
                        {
                            if (user.nick == cmdargs[0])
                            {
                                found = true;
                                if (user.host.find("in-addr") == std::string::npos)
                                {
                                    std::vector<std::string> user_ip = getIpAddr(user.host);
                                    if (!user_ip.empty())
                                    {
                                        std::cout << "[DEBUG] user_ip: " << user_ip[0] << std::endl;
                                        std::string ip_info = getIpInfo(user_ip[0], feature.ip_info_token);
                                        if (!ip_info.empty())
                                        {
                                            loc_reply = "PRIVMSG " + replydest + " :\x01" + "ACTION " + user.nick + " is " + ip_info + "\x01\r\n";
                                            std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                                        }
                                        else
                                        {
                                            loc_reply = "PRIVMSG " + replydest + " :\x01" + "ACTION " + user.nick + ": no info for user ip " + user_ip[0] + "\r\n";
                                            std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                                        }
                                    }
                                    else
                                    {
                                        loc_reply = "PRIVMSG " + replydest + " :\x01" + "ACTION " + user.nick + ": no ip got for " + user.host + " at " + chan.name + "\r\n";
                                        std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                                    }
                                }
                                else
                                {
                                    loc_reply = "PRIVMSG " + replydest + " :\x01" + "ACTION " + user.nick + ": host " + user.host + " is hidden\r\n";
                                    std::cout << "[i] Hidden host: " << user.host << std::endl;
                                    std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                                }
                                //logWrite("[i] Sent location command to " + replydest);
                                break;
                            }
                        }
                        if (found)
                        {
                            if (!loc_reply.empty())
                            {
                                sendToServer(loc_reply);
                                logWrite("[i] Sent location reply to " + replydest + ": " + loc_reply);
                            }
                            break;
                        }
                    }
                }
                else
                {
                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :Usage: " + client.command_symbol + "loc <nick>\r\n");
                }
            }

            else if (command == "ip")
            {
                if (!cmdargs.empty())
                {
                    std::vector<std::string> ipvect = getIpAddr(cmdargs[0]);
                    if (ipvect.size() == 1)
                    {
                        std::string botReply = getIpInfo(ipvect[0], feature.ip_info_token);
                        sendToServer("PRIVMSG " + replydest + " :" + botReply + "\r\n");
                        logWrite("[i] Bot reply: " + botReply);
                    }
                    else if (ipvect.size() > 1)
                    {
                        std::string replyHeader = "IPs for " + cmdargs[0] + ": ";
                        std::vector<std::string> replyBody;
                        replyBody.push_back(replyHeader);
                        for (size_t i = 0; i < ipvect.size(); i++)
                        {
                            replyBody.push_back(ipvect[i]);
                        }
                        std::vector<std::string> packedIpAddr = pack_strings(replyBody, 496);
                        for (size_t i = 0; i < packedIpAddr.size(); i++)
                        {
                            sendToServer("PRIVMSG " + replydest + " :" + packedIpAddr[i] + "\r\n");
                            logWrite("[i] Sent packed IPs to " + replydest);
                        }
                    }
                }                  
            }

            else if (command == "help")
            {
                if (cmdargs.empty())
                {
                    sendToServer("NOTICE " + ircmsg.prefix.nick + " :Available commands: " + client.command_symbol + "help, " + client.command_symbol + "loc, " + client.command_symbol + "ip\r\n");
                }
                else if (cmdargs[0] == "loc")
                {
                    if (cmdargs.size() == 1)
                    {
                        sendToServer("NOTICE " + ircmsg.prefix.nick + " :Usage: " + client.command_symbol + "loc <nick>\r\n");
                    }
                }
                else if (cmdargs[0] == "ip")
                {
                    if (cmdargs.size() == 1)
                    {
                        sendToServer("NOTICE " + ircmsg.prefix.nick + " :Usage: " + client.command_symbol + "ip <host>\r\n");
                    }
                }
            }
        }
        // Можно добавлять другие команды...
    }

    void updateChanNames(const std::string &chname)
    {
        // Проверяем, существует ли канал в векторе channels
        auto it = std::find_if(channels.begin(), channels.end(),
                               [&chname](const IRCChan &c)
                               { return c.name == chname; });

        if (it == channels.end())
        {
            sendToServer("NOTICE " + ircmsg.prefix.nick + " :Channel " + chname + " not found\r\n");
            logWrite("[-] Cannot update names: channel " + chname + " not found in internal list");
            return;
        }

        // Очищаем список пользователей и сбрасываем флаг
        it->users.clear();
        it->isJoined = false; // Будет снова установлен при 366

        sendToServer("NAMES " + chname + "\r\n"); // Запрашиваем имена канала
        logWrite("[i] Sent NAMES request for " + chname);
    }
};

// Функция разбивает строку на части по одному или нескольким пробелам
std::vector<std::string> splitStringBySpaces(const std::string &input)
{
    std::vector<std::string> result;
    std::istringstream stream(input);
    std::string word;

    // Извлекаем слова, пока не достигнем конца строки
    while (stream >> word)
    {
        result.push_back(word);
    }

    return result;
}

// Функция объединяет строки из вектора в "пакеты", не превышающие заданного размера
std::vector<std::string> pack_strings(const std::vector<std::string> &input, size_t max_length)
{
    std::vector<std::string> result;
    std::string current_packet;

    for (const auto &str : input)
    {
        // Проверяем, помещается ли текущая строка в текущий пакет
        if (current_packet.empty())
        {
            // Если пакет пуст, просто добавляем строку
            current_packet = str;
        }
        else if (current_packet.size() + 1 + str.size() <= max_length)
        {
            // Добавляем пробел и строку (или любой разделитель между строками)
            current_packet += ' ' + str;
        }
        else
        {
            // Не помещается — сохраняем текущий пакет и начинаем новый
            result.push_back(current_packet);
            current_packet = str;
        }
    }

    // Добавляем оставшийся пакет
    if (!current_packet.empty())
        result.push_back(current_packet);

    return result;
}

// Функция извлекает канал, если он начинается с '#' и содержит допустимые символы
std::string extractChan(const std::string& msgtext)
{
    std::string trimmed = boost::algorithm::trim_copy(msgtext);

    // Проверяем, что строка начинается с '#' и содержит допустимые символы
    std::regex channelRegex("^#([a-zA-Z0-9_\\-\\[\\]\\{\\}<>]+)$");
    std::smatch match;

    if (std::regex_match(trimmed, match, channelRegex)) {
        return match[0].str(); // валидный канал
    }
    return ""; // невалидный формат канала
}


int main(int argc, char *argv[])
{
    try
    {
        std::string config_path = "config.toml"; // Значение по умолчанию
        if (argc > 1)
        {
            config_path = argv[1];
        }

        IRCConfig config(config_path);
        const auto &client = config.get_client();
        if (!client.auto_connect) 
        {
            std::cout << "Bot is not connected to IRC server automatically. Please connect manually.\n";
            config.print();
            std::cout << "Connect to IRC now? [Y/n]\n";
            std::string input;
            std::getline(std::cin, input);
            if (input.empty() || input[0] == 'y' || input[0] == 'Y')
            {
                std::cout << "Starting IRC client\n";
            }
            else
            {
                std::cout << "Program will close\n";
                return 0;
            }
        }
        boost::asio::io_context io;
        IRCBot bot(io, config);
        bot.start();
        io.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
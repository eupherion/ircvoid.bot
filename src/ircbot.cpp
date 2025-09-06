#include "ircbot.h"
#include "config.h"
#include "ipinfo.h"

#include <iostream>

// Конструктор IRCUser
IRCBot::IRCUser::IRCUser(const std::string &n, const std::string &u, const std::string &h, const std::string &r)
    : nick(n), user(u), host(h), realname(r) {}

// Конструктор IRCChan
IRCBot::IRCChan::IRCChan(const std::string &n, const std::string &t)
    : name(n), topic(t), users(), isJoined(false) {}

// Конструктор IRCPrefix
IRCBot::IRCPrefix::IRCPrefix(const std::string &prefixStr)
{
    parseIrcPrefix(prefixStr);
}

// Конструктор IRCBot
IRCBot::IRCBot(boost::asio::io_context &io_context, const IRCConfig &config)
    : socket_(io_context), config_(config)
{
    // Инициализация других членов класса, если нужно
}

void IRCBot::handleConnect(const boost::system::error_code &error)
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

void IRCBot::handleWrite(const boost::system::error_code &error)
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

void IRCBot::startRead()
{
    socket_.async_read_some(boost::asio::buffer(data_, max_length),
                            boost::bind(&IRCBot::handleRead, this, boost::placeholders::_1, boost::placeholders::_2));
}

void IRCBot::handleRead(const boost::system::error_code &error, size_t bytes_transferred)
{
    if (!error && bytes_transferred > 0)
    {
        std::string response(data_, bytes_transferred);
        incomingBuffer_ += response; // Добавляем в буфер
        size_t pos = 0;
        while ((pos = incomingBuffer_.find("\r\n")) != std::string::npos)
        {
            std::string line = incomingBuffer_.substr(0, pos);
            incomingBuffer_.erase(0, pos + 2); // Удаляем обработанную строку
            std::cout << "[RAW] " << line << std::endl;
            if (!line.empty())
            {
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

void IRCBot::start(void)
{
    const auto &server = config_.get_server();
    tcp::resolver resolver(socket_.get_executor());
    auto endpoints = resolver.resolve(server.host, std::to_string(server.port));
    boost::asio::async_connect(socket_, endpoints,
                               boost::bind(&IRCBot::handleConnect, this, boost::placeholders::_1 /* , client.nickname, server.password */));
}

void IRCBot::sendToServer(const std::string &message)
{
    if (socket_.is_open())
    {
        boost::asio::async_write(socket_, boost::asio::buffer(message),
                                 boost::bind(&IRCBot::handleWrite, this, boost::placeholders::_1));
    }
}

bool IRCBot::isAdmin(const std::string &nick)
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

void IRCBot::logWrite(const std::string &message)
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

void IRCBot::shutdown(const std::string &reason)
{
    config_.saveRuntimeConfig();
    logWrite("[i] Saving runtime config...");
    if (!reason.empty())
    {
        sendToServer("QUIT :" + reason + "\r\n");
        logWrite("[i] QUIT Command sent to server, reason: " + reason);
    }
    else
    {
        sendToServer("QUIT :Shutting down\r\n");
        logWrite("[i] QUIT Command sent to server");
    }
    
    if (socket_.is_open())
    {
        boost::system::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_both, ec); // Завершение работы с сокетом
        socket_.close(ec);
        logWrite("[i] Bot shutdown complete.\n");
    }

    exit(0); // Принудительный выход из программы
    // io_context_.stop();
}

void IRCBot::IRCPrefix::parseIrcPrefix(const std::string &prefixStr)
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

void IRCBot::IRCMessage::parseIrcMessage(const std::string &rawMsg)
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

void IRCBot::updateChanNames(const IRCMessage &msg, const std::string &chname)
{
    // Проверяем, существует ли канал в векторе channels
    auto it = std::find_if(channels.begin(), channels.end(),
                           [&chname](const IRCChan &c)
                           { return c.name == chname; });

    if (it == channels.end())
    {
        sendToServer("NOTICE " + msg.prefix.nick + " :Channel " + chname + " not joined\r\n");
        logWrite("[-] Channel " + chname + " not joined");
        return;
    }
    else
    {
        // Очищаем список пользователей и сбрасываем флаг
        it->users.clear();
        it->isJoined = false; // Будет снова установлен при 366

        sendToServer("NAMES " + chname + "\r\n"); // Запрашиваем имена канала
        logWrite("[i] Sent NAMES request for " + chname);
    }
}

void IRCBot::handleNamesReply(const IRCMessage &msg) // 353 RPL_NAMREPLY
{
    auto client = config_.get_client();
    if (msg.params[0] == client.nickname && msg.params[2].find('#') != std::string::npos)
    {
        auto nicklist = splitStringBySpaces(msg.trailing);
        std::string channelName = msg.params[2];

        bool found = false;
        for (auto &chan : channels)
        {
            if (chan.name == channelName)
            {
                found = true;
                auto &existingUsers = chan.users;

                // --- Цикл проверки уникальности ---
                // Создаем set с существующими никами для быстрой проверки на дубликаты
                std::unordered_set<std::string> userSet;
                for (const auto &u : existingUsers)
                {
                    userSet.insert(u.nick);
                }

                // --- Цикл добавления ников ---
                // Проходим по всем никам из NAMES reply
                for (const auto &nick_with_prefix : nicklist)
                {
                    // Удаляем префикс роли (@, +, %, и т.д.) из ника
                    std::string clean_nick = stripNickPrefix(nick_with_prefix);

                    // Проверяем, есть ли уже такой ник в канале
                    if (userSet.find(clean_nick) == userSet.end())
                    {
                        // Если нет - добавляем пользователя с очищенным ником
                        existingUsers.emplace_back(clean_nick); // Добавляем с минимальными данными
                        userSet.insert(clean_nick);             // Добавляем в set для последующих проверок
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
            for (const auto &nick_with_prefix : nicklist)
            {
                // Удаляем префикс роли при создании нового канала тоже
                std::string clean_nick = stripNickPrefix(nick_with_prefix);
                users.emplace_back(clean_nick);
            }
            channels.emplace_back(channelName, "");
            auto &newChan = channels.back();
            newChan.users = std::move(users);
            logWrite("[+] Channel " + newChan.name + " (" + std::to_string(newChan.users.size()) + " users) added to internal list");
        }
    }
}

void IRCBot::handleEndOfNames(const IRCMessage &msg)
{
    std::string channelName = msg.params[1];

    for (auto &channel : channels)
    {
        if (channel.name == channelName)
        {
            // Список пользователей завершён — считаем, что бот "присоединён"
            channel.isJoined = true;
            std::cout << "[+] Channel " << channelName
                      << " names saved. There are " << channel.users.size() << " users." << std::endl;
            logWrite("[+] Channel " + channelName + " joined, channel names saved. ");
            sendToServer("WHO " + channelName + "\r\n");
            logWrite("[+] Sent WHO " + channelName + " to server. ");
            break;
        }
    }
}

void IRCBot::handleWhoReply(const IRCMessage &msg) // :server 352 <client> <channel> <username> <hostname> <servername> <nick> <flags> :<hopcount> <realname>
{
    auto feature = config_.get_feature();
    std::string userchan = msg.params[1];
    std::string username = msg.params[2];
    std::string userhost = msg.params[3];
    std::string usernick = msg.params[5];
    std::string realname = msg.trailing.substr(msg.trailing.find(' ') + 1);

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
                              << " (" << user.realname << ") saved to internal list of channel " << userchan << std::endl;
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
                              << " (" << user.realname << ") in internal list of channel " << userchan << std::endl;
                }
            }
        }
    }
}

bool IRCBot::detectRusNet(const IRCMessage &msg)
{
    auto &client = config_.get_client();
    logWrite("[+] " + msg.trailing);
    logWrite("[+] RusNet Server detected");
    std::string setmode = "MODE " + client.nickname + " +ix\r\n";
    sendToServer(setmode);
    logWrite("[+] " + setmode.substr(0, setmode.length() - 2));
    return true;
}

void IRCBot::authNickServ(bool rusnet)
{
    auto &client = config_.get_client();
    std::string ns_auth;
    if (rusnet)
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
    if (rusnet)
    {
        logentry += " (RusNet)";
    }
    logWrite(logentry);
}

void IRCBot::joinConfigChans(const std::vector<std::string> &chans)
{
    for (size_t i = 0; i < chans.size(); i++)
    {
        logWrite("[i] Joining channel " + chans[i]);
        sendToServer("JOIN " + chans[i] + "\r\n");
    }
}

void IRCBot::handleServerPing(const IRCMessage &msg)
{
    std::string pong = "PONG :" + msg.trailing + "\r\n";
    sendToServer(pong);
    std::cout << "[>>>] " + pong.substr(0, pong.length() - 2) + '\n';
}

void IRCBot::handleCtcpReply(const IRCMessage &msg)
{
    auto &client = config_.get_client();
    std::string ctcp = msg.trailing.substr(1, msg.trailing.size() - 2);
    logWrite("[+] Got CTCP: " + ctcp + " from " + msg.prefix.nick);
    if (ctcp.find("VERSION") != std::string::npos) // CTCP VERSION
    {
        if (!msg.prefix.nick.empty())
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :\x01VERSION " + client.dcc_version + "\x01\r\n");
            logWrite("[+] Sent CTCP [VERSION " + client.dcc_version + "] to " + msg.prefix.nick);
        }
    }

    else if (ctcp.find("PING") != std::string::npos) // CTCP PING
    {
        if (!msg.prefix.nick.empty())
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :\x01PING " + msg.trailing.substr(6) + "\x01\r\n");
            logWrite("[+] Sent CTCP PING to " + msg.prefix.nick);
        }
    }

    else if (ctcp.find("TIME") != std::string::npos) // CTCP TIME
    {
        if (!msg.prefix.nick.empty())
        {
            // Получаем текущее время
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            std::tm tm = *std::localtime(&t);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
            std::string time_str = oss.str();

            sendToServer("NOTICE " + msg.prefix.nick + " :\x01TIME " + time_str + "\x01\r\n");
            logWrite("[+] Sent CTCP TIME: " + time_str + " to " + msg.prefix.nick);
        }
    }

    else if (ctcp.find("CLIENTINFO") != std::string::npos) // CTCP CLIENTINFO
    {
        if (!msg.prefix.nick.empty())
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :\x01" + "CLIENTINFO VERSION PING TIME CLIENTINFO\x01\r\n");
            logWrite("[+] Sent CTCP CLIENTINFO to " + msg.prefix.nick);
        }
    }
}

void IRCBot::handleUserJoin(const IRCMessage &msg)
{
    std::string chanjoined = extractChan(msg.trailing);
    std::string nick = msg.prefix.nick;
    std::string user = msg.prefix.ident;
    std::string host = msg.prefix.host;

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
            updateChanNames(ircmsg, chanjoined);
            break;
        }
    }
}

void IRCBot::handleUserPart(const IRCMessage &msg)
{
    auto client = config_.get_client();
    std::string chanleft = msg.params[0];
    std::string nick = msg.prefix.nick;

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
                updateChanNames(ircmsg, chanleft);
                break;
            }
        }
    }
}

void IRCBot::handleUserQuit(const IRCMessage &msg)
{
    std::string nick = msg.prefix.nick;

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

void IRCBot::handleUserKick(const IRCMessage &msg)
{
    std::string channel = msg.params[0];
    std::string kicked = msg.params[1];

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
            updateChanNames(msg, channel);
            break;
        }
    }
}

void IRCBot::handleNickChange(const IRCMessage &msg)
{
    std::string oldnick = msg.prefix.nick;
    std::string newnick = msg.trailing;
    for (auto &chan : channels)
    {
        for (auto &user : chan.users)
        {
            if (user.nick == oldnick)
            {
                user.nick = newnick;
                logWrite("[i] Nick changed from " + oldnick + " to " + newnick);
                updateChanNames(msg, chan.name);
                break;
            }
        }
    }
}

void IRCBot::handleCommandIp(const IRCMessage &msg)
{
    auto &client = config_.get_client();
    auto &feature = config_.get_feature();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
    logWrite("[i] Bot Command " + cmdline[0] + " received by " + msg.prefix.nick + " :" + msg.trailing);

    if (!cmdargs.empty())
    {
        std::vector<std::string> ipvect = getIpAddr(cmdargs[0]);
        if (!ipvect.empty())
        {
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
        else
        {
            sendToServer("PRIVMSG " + replydest + " :No IP addresses found for " + cmdargs[0] + "\r\n");
            logWrite("[i] No IP addresses found for " + cmdargs[0]);
        }
    }
    else
    {
        sendToServer("NOTICE " + msg.prefix.nick + " :Usage: " + client.command_symbol + "ip <host>\r\n");
    }
}

void IRCBot::handleCommandLoc(const IRCMessage &msg)
{
    auto &client = config_.get_client();
    auto &feature = config_.get_feature();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string loc_reply = "";
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
    logWrite("[i] Bot Command " + cmdline[0] + " received by " + msg.prefix.nick + " :" + msg.trailing);

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
                                loc_reply = "PRIVMSG " + replydest + " :" + user.nick + " is " + ip_info + "\r\n";
                                std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                            }
                            else
                            {
                                loc_reply = "PRIVMSG " + replydest + " :" + user.nick + ": no info for user ip " + user_ip[0] + "\r\n";
                                std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                            }
                        }
                        else
                        {
                            loc_reply = "PRIVMSG " + replydest + " :" + user.nick + ": no ip got for " + user.host + " at " + chan.name + "\r\n";
                            std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                        }
                    }
                    else
                    {
                        loc_reply = "PRIVMSG " + replydest + " :" + user.nick + ": host " + user.host + " is hidden\r\n";
                        std::cout << "[i] Hidden host: " << user.host << std::endl;
                        std::cout << "[DEBUG] loc_reply: " << loc_reply << std::endl;
                    }
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
        if (!found)
        {
            std::cout << "[DEBUG] No user found in channels, sending [WHO]" << std::endl;
            sendToServer("PRIVMSG " + replydest + " :User " + cmdargs[0] + " not found in my channels\r\n");
            sendToServer("PRIVMSG " + replydest + " :Trying to use WHO " + cmdargs[0] + " command\r\n");
            logWrite("[i] User " + cmdargs[0] + " not found in joined channels");
            sendToServer("WHO " + cmdargs[0] + "\r\n");
        }
    }
    else
    {
        sendToServer("NOTICE " + msg.prefix.nick + " :Usage: " + client.command_symbol + "loc <nick>\r\n");
    }
}

void IRCBot::handleCommandChan(const IRCMessage &msg)
{
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    if (isAdmin(msg.prefix.nick))
    {
        std::cout << "[i] Admin " << msg.prefix.nick << " command received\n";
        std::string currentchans = "";
        for (auto &chan : channels)
        {
            currentchans += chan.name + " [" + std::to_string(chan.users.size()) + "] ";
            std::cout << "chan:" << chan.name << '\n';
            for (auto cu : chan.users)
            {
                std::cout << "user:" << cu.nick << '\n';
            }
        }
        if (!currentchans.empty())
        {
            sendToServer("PRIVMSG " + replydest + " :Joined channels: " + currentchans + "\r\n");
        }
    }
    else
    {
        if (!isAdmin(msg.prefix.nick))
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :You are not an admin\r\n");
        }
    }
}

void IRCBot::handleCommandQuit(const IRCMessage &msg)
{
    auto &client = config_.get_client();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
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
            for (const auto &arg : cmdargs)
            {
                if (!arg.empty())
                {
                    reason += arg + " ";
                }
            }
        }
        if (isAdmin(msg.prefix.nick))
        {
            std::cout << "[i] Admin " << msg.prefix.nick << " quit command received\n";
            std::string reply = "";
            sendToServer("PRIVMSG " + replydest + " :\x01" + "ACTION Going down...\x01\r\n");
            // std::this_thread::sleep_for(std::chrono::milliseconds(100));

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
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logWrite("[!] Shutting down...");
            shutdown(reason);
        }
    }
}

void IRCBot::handleCommandJoin(const IRCMessage &msg)
{
    //auto &client = config_.get_client();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
    if (isAdmin(msg.prefix.nick))
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
                logWrite("[i] Joining channel " + chanjoin + " by " + msg.prefix.nick);
            }
        }
        else
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :No channel specified.\r\n");
            sendToServer("PRIVMSG " + replydest + " : Usage: .join #channel\r\n");
        }
    }
    else
    {
        sendToServer("NOTICE " + msg.prefix.nick + " :You are not an admin!\r\n");
    }
}

void IRCBot::handleCommandPart(const IRCMessage &msg)
{
    //auto &client = config_.get_client();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
    if (isAdmin(msg.prefix.nick))
    {
        std::string chanpart = "";
        if (!cmdargs.empty())
        {
            chanpart = extractChan(cmdargs[0]);
            if (chanpart.empty())
            {
                sendToServer("NOTICE " + msg.prefix.nick + " :Invalid channel name.\r\n");
                return;
            }
        }
        else
        {
            // Если аргумента нет, покидаем текущий канал
            if (msg.params[0].find('#') != std::string::npos)
            {
                chanpart = msg.params[0];
            }
            else
            {
                sendToServer("NOTICE " + msg.prefix.nick + " :No channel specified.\r\n");
                return;
            }
        }

        // 1. Отправляем команды
        sendToServer("PRIVMSG " + replydest + " :\x01" + "ACTION parts " + chanpart + "\x01\r\n");
        sendToServer("PART " + chanpart + "\r\n");
        logWrite("[i] Parting channel " + chanpart + " by " + msg.prefix.nick);

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
        sendToServer("NOTICE " + msg.prefix.nick + " :You are not an admin!\r\n");
    }
}

void IRCBot::handleCommandNames(const IRCMessage &msg)
{
    //auto &client = config_.get_client();
    std::string replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::vector<std::string> cmdline = splitStringBySpaces(msgtext);
    std::vector<std::string> cmdargs;
    if (cmdline.size() > 1)
    {
        for (size_t i = 1; i < cmdline.size(); i++)
        {
            cmdargs.push_back(cmdline[i]);
        }
    }
    if (isAdmin(msg.prefix.nick))
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
                        for (const auto &chan : channels)
                        {
                            if (chan.name == chanupdate)
                            {
                                updateChanNames(msg, chanupdate);
                                sendToServer("NOTICE " + msg.prefix.nick + " :Channel " + chanupdate + " NAMES updated\r\n");
                                // std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                return;
                            }
                        }
                        sendToServer("NOTICE " + msg.prefix.nick + " :Channel " + chanupdate + " not found in internal list\r\n");
                        logWrite("[-] Cannot update names: channel " + chanupdate + " not found in internal list");
                    }
                    else
                    {
                        sendToServer("NOTICE " + msg.prefix.nick + " :Invalid channel name:" + arg + "\r\n");
                    }
                }
            }
        }
        else
        {
            for (const auto &chan : channels)
            {
                updateChanNames(msg, chan.name);
                sendToServer("NOTICE " + msg.prefix.nick + " :Channel " + chan.name + " NAMES updated\r\n");
                // std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }
    else
    {
        sendToServer("NOTICE " + msg.prefix.nick + " :You are not an admin!\r\n");
    }
}

void IRCBot::handlePrivMsg(const IRCMessage &msg)
{
    const auto &client = config_.get_client();
    const auto &feature = config_.get_feature();
    std::string replydest;
    std::string msgtext = boost::algorithm::trim_copy(msg.trailing);
    std::string command = ""; // команда боту
    std::vector<std::string> cmdargs = {}; // аргументы команды
    replydest = (msg.params[0].find("#") != std::string::npos) ? msg.params[0] : msg.prefix.nick;
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
        std::cout << "[DEBUG]: ircmsg.prefix: " << msg.prefix.nick << "!" << msg.prefix.ident << "@" << msg.prefix.host << std::endl;
        std::cout << "[DEBUG]: ircmsg.command: " << msg.command << std::endl;
        for (size_t i = 0; i < msg.params.size(); ++i)
        {
            std::cout << "[DEBUG]: ircmsg.param[" << i << "]: " << msg.params[i] << std::endl;
        }
        if (!msg.trailing.empty())
        {
            std::cout << "[DEBUG]: ircmsg.trailing: " << msg.trailing << std::endl;
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
    std::cout << "[MESSAGE] From " << msg.prefix.nick
              << " to " << msg.params[0]
              << ": " << msgtext << std::endl;

    if (command == "chan")
    {
        handleCommandChan(msg); // Показывает список каналов
    }

    else if (command == "quit")
    {
        handleCommandQuit(msg); // Выход из бота
    }

    else if (command == "join")
    {
        handleCommandJoin(msg); // Подключается к каналу
    }

    else if (command == "part")
    {
        handleCommandPart(msg); // Покидает канал
    }

    else if (command == "names")
    {
        handleCommandNames(msg); // Показывает список участников канала
    }

    else if (command == "loc") // :yournick!~yourhost@yourip PRIVMSG #channel :.loc <nick>
    {
        handleCommandLoc(msg);
    }

    else if (command == "ip")
    {
        handleCommandIp(msg);
    }

    else if (command == "help")
    {
        if (cmdargs.empty())
        {
            sendToServer("NOTICE " + msg.prefix.nick + " :Available commands: " + client.command_symbol + "help, " + client.command_symbol + "loc, " + client.command_symbol + "ip\r\n");
        }
        else if (cmdargs[0] == "loc")
        {
            if (cmdargs.size() == 1)
            {
                sendToServer("NOTICE " + msg.prefix.nick + " :Usage: " + client.command_symbol + "loc <nick>\r\n");
            }
        }
        else if (cmdargs[0] == "ip")
        {
            if (cmdargs.size() == 1)
            {
                sendToServer("NOTICE " + msg.prefix.nick + " :Usage: " + client.command_symbol + "ip <host>\r\n");
            }
        }
    }
}

void IRCBot::parseServerMessage(const std::string &line)
{
    auto &client = config_.get_client();
    ircmsg.parseIrcMessage(line);

    // Теперь весь парсинг происходит через IRCMessage
    // Можно использовать ircmsg.command, ircmsg.params, ircmsg.trailing и т.д.
    std::string replydest = "";

    // Пример: обработка PING
    if (ircmsg.command == "PING")
    {
        handleServerPing(ircmsg);
    }

    else if (!ircmsg.trailing.empty() && ircmsg.trailing.front() == '\x01' && ircmsg.trailing.back() == '\x01') // CTCP
    {
        handleCtcpReply(ircmsg);
    }

    else if (ircmsg.command == "020" && ircmsg.trailing.find("RusNet") != std::string::npos)
    {
        rusnetAuth = detectRusNet(ircmsg);
    }

    else if (ircmsg.command == "376" || ircmsg.command == "422")
    {
        logWrite("[+] End of MOTD command received");
        if (!client.nickserv_password.empty())
        {
            authNickServ(rusnetAuth);
        }
        joinConfigChans(client.channels);
    }

    else if (ircmsg.command == "352") // [RPL_WHOREPLY] :server 352 YourNick #channel bob bob@host.org ircd.example.org Bobby H :0 Bob Smith
    {
        if (!ircmsg.params.empty())
        {
            handleWhoReply(ircmsg);
        }
    }

    else if (ircmsg.command == "353") // [RPL_NAMREPLY] :server 353 yournick = #channel :nick1 nick2 ...
    {
        if (!ircmsg.params.empty())
        {
            handleNamesReply(ircmsg);
        }
    }

    else if (ircmsg.command == "366") // [RPL_ENDOFNAMES] :server 366 yournick #channel :End of /NAMES list.
    {
        if (!ircmsg.params.empty())
        {
            handleEndOfNames(ircmsg);
        }
    }

    else if (ircmsg.command == "JOIN") // [JOIN] :nick!user@host JOIN :#channel // Пользователь присоединяется к каналу
    {
        handleUserJoin(ircmsg);
    }

    else if (ircmsg.command == "PART") // [PART] :nick!user@host PART #channel:reason // Пользователь покидает канал
    {
        handleUserPart(ircmsg);
    }

    else if (ircmsg.command == "QUIT") // [QUIT] :nick!user@host QUIT :reason // Пользователь выходит
    {
        handleUserQuit(ircmsg);
    }

    else if (ircmsg.command == "KICK") // [KICK] :nick!user@host KICK #channel kickednick :reason // Пользователь кикнут
    {
        handleUserKick(ircmsg);
    }

    else if (ircmsg.command == "NICK") // [NICK] :nick!user@host NICK :newnick // Пользователь меняет ник
    {
        handleNickChange(ircmsg);
    }

    else if (ircmsg.command == "PRIVMSG") // [PRIVMSG] :nick!user@host PRIVMSG #channel :message // Пользователь пишет в канал
    {
        handlePrivMsg(ircmsg);
    }
    // Можно добавлять другие команды...
}

std::vector<std::string> IRCBot::splitStringBySpaces(const std::string &input)
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

std::vector<std::string> IRCBot::pack_strings(const std::vector<std::string> &input, size_t max_length)
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

std::string IRCBot::extractChan(const std::string &msgtext)
{
    std::string trimmed = boost::algorithm::trim_copy(msgtext);

    // Проверяем, что строка начинается с '#' и содержит допустимые символы
    std::regex channelRegex("^#([a-zA-Z0-9_\\-\\[\\]\\{\\}<>]+)$");
    std::smatch match;

    if (std::regex_match(trimmed, match, channelRegex))
    {
        return match[0].str(); // валидный канал
    }
    return ""; // невалидный формат канала
}

std::string IRCBot::stripNickPrefix(const std::string &nick_with_prefix)
{
    if (nick_with_prefix.empty())
        return nick_with_prefix;

    // Определим возможные префиксы (в порядке убывания приоритета, хотя не важно)
    const std::string prefixes = "~&@%+";

    // Проверяем, начинается ли ник с одного из префиксов
    if (prefixes.find(nick_with_prefix[0]) != std::string::npos)
    {
        // Возвращаем ник без первого символа
        return nick_with_prefix.substr(1);
    }
    // Если префикса нет, возвращаем как есть
    return nick_with_prefix;
}
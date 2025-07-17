#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <thread>   // Для std::this_thread::sleep_for
#include <chrono>  // Для std::chrono::milliseconds
#include "config.h"
#include "ipinfo.h"

using boost::asio::ip::tcp;

class IRCBot
{
public:
    IRCBot(boost::asio::io_context &io_context, const IRCConfig &config)
        : socket_(io_context), config_(config) {}
    bool rusnetAuth = false;
    void start(void)
    {
        const auto &server = config_.get_server();
        // const auto &client = config_.get_client();

        tcp::resolver resolver(socket_.get_executor());
        auto endpoints = resolver.resolve(server.host, std::to_string(server.port));

        boost::asio::async_connect(socket_, endpoints,
                                   boost::bind(&IRCBot::handleConnect, this, boost::placeholders::_1 /* , client.nickname, server.password */));
    }

    void shutdown(void)
    {
        std::cout << "[i] Shutting down bot..." << std::endl;
        sendToServer("QUIT :Shutting down\r\n");

        if (socket_.is_open())
        {
            boost::system::error_code ec;
            socket_.shutdown(tcp::socket::shutdown_both, ec); // Завершение работы с сокетом
            socket_.close(ec);
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
            parse(prefixStr);
        }

        void parse(const std::string &prefixStr)
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
            parse(rawMsg);
        }

        void parse(const std::string &rawMsg)
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
            std::cout << "[+] Connected to server!" << std::endl;
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
        const auto &client = config_.get_client();
        const auto &feature = config_.get_feature();
        ircmsg.parse(line);

        // Теперь весь парсинг происходит через IRCMessage
        // Можно использовать ircmsg.command, ircmsg.params, ircmsg.trailing и т.д.

        // Пример: обработка PING
        if (ircmsg.command == "PING")
        {
            std::string pong = "PONG :" + ircmsg.trailing + "\r\n";
            sendToServer(pong);
        }

        if (!ircmsg.trailing.empty() && ircmsg.trailing.front() == '\x01' && ircmsg.trailing.back() == '\x01')
        {
            std::string ctcpCommand = ircmsg.trailing.substr(1, ircmsg.trailing.size() - 2);
            std::string target = "";
            if (ircmsg.params[0].find("#") != std::string::npos)
            {
                target = ircmsg.params[0];
            }
            else
            {
                target = ircmsg.prefix.nick;
            }

            if (ctcpCommand.find("VERSION") != std::string::npos)
            {
                if (target.empty())
                {
                    std::cout << "[DEBUG] Target is empty\n";
                    return; // Пропускаем, если target пуст
                }
                else
                {
                    std::string ctcpReply = "NOTICE " + target + " :\x01VERSION " + client.dcc_version + "\x01\r\n";
                    sendToServer(ctcpReply);
                    std::cout << "[+] Sent CTCP VERSION to " << target << '\n';
                }
            }

            if (ctcpCommand.find("PING") != std::string::npos)
            {
                if (target.empty())
                {
                    std::cout << "[DEBUG] Target is empty\n";
                    return; // Пропускаем, если target пуст
                }
                else
                {
                    std::string ctcpReply = "NOTICE " + target + " :\x01PING " + ircmsg.trailing.substr(6) + "\x01\r\n";
                    sendToServer(ctcpReply);
                    std::cout << "[+] Sent CTCP PING to " << target << '\n';
                }
            }
        }

        if (ircmsg.command == "020" && ircmsg.trailing.find("RusNet") != std::string::npos)
        {
            std::cout << "[+] " << ircmsg.trailing << '\n';
            std::cout << "[+] RusNet Server detected\n";
            rusnetAuth = true;
        }

        if (ircmsg.command == "376" || ircmsg.command == "422")
        {
            std::cout << "[+] End of MOTD command received\n";
            if (!client.nickserv_password.empty())
            {
                std::string ns_auth = "";
                if (rusnetAuth)
                {
                    std::cout << "[i] RusNet NickServ reply generated\n";
                    ns_auth = "NICKSERV IDENTIFY " + client.nickserv_password + "\r\n";
                }
                else
                {
                    std::cout << "[i] Normal NickServ reply formed\n";
                    ns_auth = "PRIVMSG NickServ :IDENTIFY " + client.nickserv_password + "\r\n";
                }
                sendToServer(ns_auth);
                std::cout << "[+] Sent NICKSERV AUTH\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }

            for (size_t i = 0; i < client.channels.size(); i++)
            {
                std::string joinMessage = "JOIN " + client.channels[i] + "\r\n";
                std::cout << "[+] Joining channel " << client.channels[i] << '\n';
                sendToServer(joinMessage);
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }

        if (ircmsg.command == "353")
        {
            if (ircmsg.params[1] == client.nickname)
            {
                std::cout << "[+] Channel " << ircmsg.params[2] << " joined\n";
            }
        }

        // Пример реакции на PRIVMSG
        if (ircmsg.command == "PRIVMSG")
        {
            std::string channel = ircmsg.params[0];
            std::string msgtext = ircmsg.trailing;
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
            }
            std::cout << "[MESSAGE] From " << ircmsg.prefix.nick
                      << " on " << channel
                      << ": " << msgtext << std::endl;

            // Пример реакции на "hello bot"
            if (msgtext == ".hi")
            {
                std::string target("");
                if (ircmsg.params[0].find("#") != std::string::npos)
                {
                    target = ircmsg.params[0];
                }
                else
                {
                    target = ircmsg.prefix.nick;
                }
                if (target.empty()) {
                    std::cout << "[ERR] Target is empty\n";
                    return; // Пропускаем, если target пуст
                }
                for (size_t i = 0; i < client.admins.size(); i++)
                {
                    if (client.admins[i] == ircmsg.prefix.nick)
                    {
                        std::cout << "[i] Admin " << ircmsg.prefix.nick << " command received\n";
                        std::string reply = "PRIVMSG " + target + " :Hello, " + ircmsg.prefix.nick + "! I'm your bot.\r\n";
                        sendToServer(reply);
                        break;
                    }
                }
            }

            if (msgtext.size() >= 4 && msgtext.substr(0, 4) == ".bye")
            {
                if (client.admins.empty())
                {
                    std::cout << "[ERR] Admins list is empty\n";
                    return; // Пропускаем, если admins пуст
                }
                else
                {
                    std::string target("");
                    std::string reason = "";
                    if (msgtext.size() > 4)
                    {
                        reason = msgtext.substr(5);
                    }
                    for (size_t i = 0; i < client.admins.size(); i++)
                    {
                        if (client.admins[i] == ircmsg.prefix.nick)
                        {
                            if (ircmsg.params[0].find("#") != std::string::npos)
                            {
                                target = ircmsg.params[0];
                            }
                            else
                            {
                                target = ircmsg.prefix.nick;
                            }
                            std::cout << "[i] Admin " << ircmsg.prefix.nick << " is in admins list\n";
                            std::string reply = "";
                            std::string action = "PRIVMSG " + target + " :\x01" + "ACTION Going down...\x01\r\n";
                            sendToServer(action);
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            if (!reason.empty())
                            {
                                reply = "PRIVMSG " + target + " :Goodbye, " + ircmsg.prefix.nick + "! " + reason + "\r\n";
                            }
                            else
                            {
                                reply = "PRIVMSG " + target + " :Goodbye, " + ircmsg.prefix.nick + "!\r\n";
                            }

                            sendToServer(reply);
                            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                            shutdown();
                            break;
                        }
                    }
                }
            }

            if (msgtext.substr(0, 4) == ".ip ")
            {
                std::cout << "[i] Command .ip received by " << ircmsg.prefix.nick << ":" << msgtext << '\n';
                std::vector<std::string> parts = splitStringBySpaces(msgtext.substr(4));
                std::string target("");
                if (ircmsg.params[0].find("#") != std::string::npos)
                {
                    target = ircmsg.params[0];
                }
                else
                {
                    target = ircmsg.prefix.nick;
                }
                if (target.empty())
                {
                    std::cout << "[ERR] Target is empty\n";
                    return; // Пропускаем, если target пуст
                }
                if (feature.debug_mode)
                {
                    for (size_t i = 0; i < parts.size(); i++)
                    {
                        std::cout << "[DEBUG] Command part " << i << ": " << parts[i] << '\n';
                    }
                }


                if (parts.size() == 1)
                {
                    if (parts[0] == "help")
                    {
                        std::string helpMessage = "Usage: .ip <ip> || <host> [key]\n";
                        sendToServer("NOTICE " + ircmsg.prefix.nick + " :" + helpMessage + "\r\n");
                        std::cout << "[i] Help message sent to " << ircmsg.prefix.nick << '\n';
                    }
                    else
                    {
                        std::string hostName = parts[0];
                        std::vector<std::string> infoVect = getIpAddr(hostName);
                        if (infoVect.size() == 1)
                        {
                            std::string botReply = getIpInfo(infoVect[0], feature.ip_info_token);
                            std::cout << "Bot reply: " << botReply << '\n';
                            sendToServer("PRIVMSG " + target + " :" + botReply + "\r\n");
                        }
                        else if (infoVect.size() > 1)
                        {
                            std::string replyHeader = "IPs for " + hostName + ": ";
                            std::vector<std::string> replyBody;
                            replyBody.push_back(replyHeader);
                            for (size_t i = 0; i < infoVect.size(); i++)
                            {
                                replyBody.push_back(infoVect[i]);
                            }
                            std::vector<std::string> packedIpAddr = pack_strings(replyBody, 496);
                            for (size_t i = 0; i < packedIpAddr.size(); i++)
                            {
                                sendToServer("PRIVMSG " + target + " :" + packedIpAddr[i] + "\r\n");
                            }
                        }
                    }
                }
            }
        }
        // Можно добавлять другие команды...
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
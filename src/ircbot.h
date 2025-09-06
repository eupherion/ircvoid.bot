// ircbot.h
#ifndef IRCBOT_H
#define IRCBOT_H

#include "config.h" // Предполагается, что IRCConfig определён там
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <chrono>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using boost::asio::ip::tcp;

class IRCBot
{
public:
    // --- Вложенные структуры ---
    struct IRCUser
    {
        std::string nick;
        std::string user;
        std::string host;
        std::string realname;

        IRCUser(const std::string &n, const std::string &u = "", const std::string &h = "", const std::string &r = "");
        bool operator==(const IRCUser &other) const;
    };

    struct IRCChan
    {
        std::string name;
        std::string topic;
        std::vector<IRCUser> users;
        bool isJoined = false;

        IRCChan(const std::string &n, const std::string &t = "");
    };

    // --- Конструктор ---
    IRCBot(boost::asio::io_context &io_context, const IRCConfig &config);

    // --- Публичные методы ---
    void start();
    void shutdown(const std::string &reason);

    // Команды бота


private:
    // --- Сокет и буфер ---
    tcp::socket socket_;
    std::string incomingBuffer_;
    enum
    {
        max_length = 4096
    };
    char data_[max_length];

    // --- Конфигурация ---
    const IRCConfig &config_;

    // --- Вложенные классы для парсинга ---
    class IRCPrefix
    {
    public:
        std::string nick;
        std::string ident;
        std::string host;

        IRCPrefix() = default;
        IRCPrefix(const std::string &prefixStr);
        void parseIrcPrefix(const std::string &prefixStr);
    };

    class IRCMessage
    {
    public:
        IRCPrefix prefix;
        std::string command;
        std::vector<std::string> params;
        std::string trailing;

        IRCMessage() = default;
        explicit IRCMessage(const std::string &rawMsg);
        void parseIrcMessage(const std::string &rawMsg);
    };

    // --- Внутренние данные ---
    IRCMessage ircmsg;
    std::vector<IRCChan> channels;
    bool rusnetAuth = false;

    // --- Вспомогательные методы ---
    void handleConnect(const boost::system::error_code &error);
    void handleWrite(const boost::system::error_code &error);
    void startRead();
    void handleRead(const boost::system::error_code &error, size_t bytes_transferred);
    void parseServerMessage(const std::string &line);

    // --- Обработчики команд и событий ---
    bool detectRusNet(const IRCMessage &msg);
    void authNickServ(bool rusnet);
    void joinConfigChans(const std::vector<std::string> &chans);
    void handleServerPing(const IRCMessage &msg);
    void handleCtcpReply(const IRCMessage &msg);
    void updateChanNames(const IRCMessage &msg, const std::string &chame);
    void handleNamesReply(const IRCMessage &msg);
    void handleEndOfNames(const IRCMessage &msg);
    void handleWhoReply(const IRCMessage &msg);

    void handleUserJoin(const IRCMessage &msg);
    void handleUserPart(const IRCMessage &msg);
    void handleUserQuit(const IRCMessage &msg);
    void handleUserKick(const IRCMessage &msg);
    void handleNickChange(const IRCMessage &msg);
    void handlePrivMsg(const IRCMessage &msg);

    // // --- Команды бота ---
    void handleCommandIp(const IRCMessage &msg);
    void handleCommandLoc(const IRCMessage &msg);
    void handleCommandChan(const IRCMessage &msg);
    void handleCommandJoin(const IRCMessage &msg);
    void handleCommandPart(const IRCMessage &msg);
    void handleCommandQuit(const IRCMessage &msg);
    void handleCommandNames(const IRCMessage &msg);

    // --- Утилиты ---
    bool isAdmin(const std::string &nick);
    void sendToServer(const std::string &message);
    void logWrite(const std::string &message);
    std::string extractChan(const std::string &input);
    std::string stripNickPrefix(const std::string &nick_with_prefix);
    std::vector<std::string> splitStringBySpaces(const std::string &str);
    std::vector<std::string> pack_strings(const std::vector<std::string> &input, size_t max_length);
};

#endif // IRCBOT_H
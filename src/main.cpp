#include "config.h"
#include "ipinfo.h"
#include "ircbot.h"

#include <iostream>

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
        const auto &feature = config.get_feature();
        if (!feature.is_configured)
        {
            std::cout << "[!] Bot is not configured. Please configure it first by editing config.toml.\n";
            return 0;
        }
        if (!client.auto_connect)
        {
            std::cout << "Bot is not connected to IRC server automatically. Please connect manually.\n";
            config.printConfig();
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
#include "config.h" // Используем IRCConfig
#include "ipinfo.h" // Используем getIpInfo
#include "ircbot.h" // Используем IRCBot

#include <cerrno>       // errno
#include <cstdlib>      // exit, _exit
#include <cstring>      // strerror
#include <fstream>      // std::ifstream
#include <iostream>     // std::cerr
#include <limits.h>     // PATH_MAX
#include <signal.h>     // 
#include <sys/stat.h>   // umask
#include <sys/types.h>  // pid_t
#include <unistd.h>     // fork, setsid, chdir, dup2, ...

std::string g_pid_file_path; // Глобально храним путь к .pid-файлу

void write_pid_file(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "[!] Cannot create PID file: " << path << std::endl;
        _exit(1);
    }
    file << getpid() << std::endl;
}

void remove_pid_file_at_exit() {
    if (!g_pid_file_path.empty()) {
        unlink(g_pid_file_path.c_str());
    }
}

void remove_pid_file(const std::string& path) {
    unlink(path.c_str());
}

void signal_handler([[maybe_unused]]int sig) {
    // Важно: использовать только async-signal-safe функции
    // exit() безопасна, но не cout/cerr
    exit(EXIT_SUCCESS);
}

void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Перезапуск системных вызовов при прерывании

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

// --- Функция демонизации ---
void daemonize(const std::string& pid_path)
{
    g_pid_file_path = pid_path; // Сохраняем путь глобально

    char original_cwd[PATH_MAX];
    if (getcwd(original_cwd, sizeof(original_cwd)) == NULL)
    {
        std::cerr << "[!] getcwd() failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    pid_t pid = fork();

    if (pid < 0)
    {
        std::cerr << "[!] fork() failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    if (pid > 0)
    {
        exit(0);
    }

    // Дочерний процесс:
    write_pid_file(pid_path);
    std::atexit(remove_pid_file_at_exit); // Регистрируем cleanup

    if (setsid() < 0)
    {
        std::cerr << "[!] setsid() failed: " << strerror(errno) << std::endl;
        _exit(1);
    }

    umask(0);

    if (chdir(original_cwd) < 0)
    {
        std::cerr << "[!] chdir(original_cwd) failed: " << strerror(errno) << std::endl;
        _exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd_in = open("/dev/null", O_RDONLY);
    int fd_out = open("/dev/null", O_WRONLY);
    int fd_err = open("/dev/null", O_WRONLY);

    if (fd_in != STDIN_FILENO || fd_out != STDOUT_FILENO || fd_err != STDERR_FILENO)
    {
        std::cerr << "[!] Unexpected file descriptors after daemonization!" << std::endl;
        _exit(1);
    }

    setup_signal_handlers(); // Устанавливаем обработчики сигналов
}

int main(int argc, char *argv[])
{
    std::string pid_file_path = "./bot.pid"; // Можно задать через аргумент
    try
    {
        std::string config_path = "config.toml"; // Значение по умолчанию
        bool should_daemonize = true; // Проверка аргумента командной строки

        for (int i = 1; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--fg")
            {
                should_daemonize = false;
            }

            if (std::string(argv[i]).size() > 5 && std::string(argv[i]).rfind(".toml") == std::string(argv[i]).size() - 5)
            {
                if (std::ifstream(argv[i]).good())
                {
                    config_path = argv[i];
                }
                else
                {
                    std::cout << "[ ! ] Config file not found: " << argv[i] << std::endl;
                    return 1;
                }
            }
        }

        if (should_daemonize)
        {
            IRCConfig config(config_path);
            const auto &feature = config.get_feature();
            if (!feature.is_configured)
            {
                std::cout << "[ ! ] Bot is not configured. Please configure it first by editing config.toml.\n";
                std::cout << "[ ! ] Parameter botConfigured should be set to true in config.toml\n";
                std::cout << "[ ! ] If you want to run bot in foreground, use --fg argument.\n";
                return 0;
            }
            std::cout << "Using config: " << config_path << std::endl;
            std::cout << "Starting bot in daemon mode...\n";
            daemonize(pid_file_path);
            // После демонизации вывод в std::cout/std::cerr не будет работать,
            // так как они перенаправлены в /dev/null. Используется логирование в файл.
        }
        else
        {
            // Если не в режиме демона, спрашиваем у пользователя
            IRCConfig config(config_path);
            const auto &client = config.get_client();
            const auto &feature = config.get_feature();
            if (!feature.is_configured)
            {
                std::cout << "[ ! ] Bot is not configured. Please configure it first by editing config.toml.\n";
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
        }

        // Теперь создаём io_context и запускаем бота
        boost::asio::io_context io;
        IRCConfig config(config_path); // Нужно снова загрузить конфиг, если демонизация происходила
        IRCBot bot(io, config);
        bot.start();
        io.run();
    }
    catch (const std::exception &e)
    {
        // Если демонизирован, вывод в stderr не увидеть
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
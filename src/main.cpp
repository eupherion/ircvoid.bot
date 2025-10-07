#include "config.h" // Используем IRCConfig
#include "ipinfo.h" // Используем getIpInfo
#include "ircbot.h" // Используем IRCBot

#include <cerrno>       // errno
#include <cstdlib>      // exit, _exit
#include <cstring>      // strerror
#include <fstream>      // std::ifstream
#include <iostream>     // std::cerr
#include <limits.h>     // PATH_MAX
#include <sys/stat.h>   // umask
#include <sys/types.h>  // pid_t
#include <unistd.h>     // fork, setsid, chdir, dup2, ...

// --- Функция демонизации ---
void daemonize()
{
    // 0. Сохраняем текущую рабочую директорию (не обязательно, но надёжно)
    char original_cwd[PATH_MAX];
    if (getcwd(original_cwd, sizeof(original_cwd)) == NULL)
    {
        std::cerr << "[!] getcwd() failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    pid_t pid = fork(); // Создаём дочерний процесс

    if (pid < 0)
    {
        std::cerr << "[!] fork() failed: " << strerror(errno) << std::endl;
        exit(1);
    }

    if (pid > 0)
    {
        // Родительский процесс: завершаемся
        exit(0);
    }

    // Дочерний процесс:
    // 1. Создаём новую сессию (становимся лидером группы и теряем управляющий терминал)
    if (setsid() < 0)
    {
        std::cerr << "[!] setsid() failed: " << strerror(errno) << std::endl;
        _exit(1); // Используем _exit, т.к. std::atexit не нужен в дочке
    }

    // 2. Изменяем umask
    umask(0);

    // 3. Восстанавливаем оригинальную рабочую директорию
    if (chdir(original_cwd) < 0)
    {
        std::cerr << "[!] chdir(original_cwd) failed: " << strerror(errno) << std::endl;
        _exit(1);
    }

    // 4. Закрываем и перенаправляем стандартные файловые дескрипторы
    // Закрываем старые
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Открываем /dev/null для stdin, stdout, stderr
    // Это предотвратит ошибки ввода-вывода в будущем
    int fd_in = open("/dev/null", O_RDONLY);
    int fd_out = open("/dev/null", O_WRONLY);
    int fd_err = open("/dev/null", O_WRONLY);

    if (fd_in != STDIN_FILENO || fd_out != STDOUT_FILENO || fd_err != STDERR_FILENO)
    {
        std::cerr << "[!] Unexpected file descriptors after daemonization!" << std::endl;
        _exit(1);
    }

    // Теперь процесс стал демоном.
    // Все файловые дескрипторы перенаправлены.
    // Он не связан с терминалом.
    // Его PID изменился (если был лидером сессии).
    // Его родитель - init (PID 1).
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
        
        bool should_daemonize = true; // Проверка аргумента командной строки
        for (int i = 1; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--fg")
            {
                should_daemonize = false;
                break;
            }
        }

        if (should_daemonize)
        {
            std::cout << "Using config: " << config_path << std::endl;
            std::cout << "Starting bot in daemon mode...\n";
            daemonize();
            // После демонизации вывод в std::cout/std::cerr не будет работать,
            // так как они перенаправлены в /dev/null. Используйте логирование в файл.
        }
        else
        {
            // Если не в режиме демона, спрашиваем у пользователя
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
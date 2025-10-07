#include <cstring>
#include <iostream>
#include <netdb.h>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <curl/curl.h>

#include "../lib/cppjson.h"
#include "ipinfo.h"

// Функция обратного вызова для записи данных из ответа сервера
size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    size_t totalSize = size * nmemb;
    userp->append((char *)contents, totalSize);
    return totalSize;
}

// Компаратор: IPv4 перед IPv6
bool customIpSort(const std::string &a, const std::string &b)
{
    bool aIsIPv4 = a.find(':') == std::string::npos;
    bool bIsIPv4 = b.find(':') == std::string::npos;

    if (aIsIPv4 && !bIsIPv4)
        return true; // IPv4 раньше
    if (!aIsIPv4 && bIsIPv4)
        return false;
    return a < b; // Обычная сортировка внутри типа
}

// Принимает строку с ip адресом, возвращает ответ с ipinfo.io
std::string getIpInfo(std::string /* string with ip */ ipAddrStr, std::string ipinfo_token)
{

    CURL *curl;
    CURLcode res;

    std::string ipInfoStr;
    std::string ipReplStr;
    std::string readbuffer;
    std::string requeststr;

    curl = curl_easy_init();
    if (curl)
    {
        if (!ipAddrStr.empty())
        {
            requeststr = "http://ipinfo.io/" + ipAddrStr + "?token=" + ipinfo_token;
            curl_easy_setopt(curl, CURLOPT_URL, requeststr.c_str());
            // Установка функции обратного вызова для записи данных
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

            // Передача указателя на строку, куда будут записываться данные
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readbuffer);

            // Выполнение запроса
            res = curl_easy_perform(curl);

            // Проверка результата выполнения запроса
            if (res != CURLE_OK)
            {
                std::string curl_err(curl_easy_strerror(res));
                ipInfoStr = "curl_easy_perform() failed: " + curl_err + '\n';
            }
            else
            {
                ipInfoStr = readbuffer; // Возврат строки с ipinfo.io
                // std::cout << "IP info string:\n" << ipInfoStr << '\n';
                nlohmann::json jsonData = nlohmann::json::parse(ipInfoStr);

                if (!jsonData["ip"].is_null())
                {
                    ipReplStr += jsonData["ip"].get<std::string>() + ' ';
                }

                if (!jsonData["hostname"].is_null())
                {
                    ipReplStr += jsonData["hostname"].get<std::string>() + ' ';
                }

                if (!jsonData["city"].is_null())
                {
                    ipReplStr += jsonData["city"].get<std::string>() + ' ';
                }

                if (!jsonData["region"].is_null())
                {
                    ipReplStr += jsonData["region"].get<std::string>() + ' ';
                }

                if (!jsonData["country"].is_null())
                {
                    ipReplStr += jsonData["country"].get<std::string>() + ' ';
                }

                // if (!jsonData["loc"].is_null())
                // {
                //     ipReplStr += jsonData["loc"].get<std::string>() + ' ';
                // }

                if (!jsonData["org"].is_null())
                {
                    ipReplStr += jsonData["org"].get<std::string>() + ' ';
                }

                // if (!jsonData["postal"].is_null())
                // {
                //     ipReplStr += jsonData["postal"].get<std::string>() + ' ';
                // }

                // if (!jsonData["timezone"].is_null())
                // {
                //     ipReplStr += jsonData["timezone"].get<std::string>();
                // }
            }
            // Освобождение ресурсов
            curl_easy_cleanup(curl);
        }
    }
    else
    {
        std::cerr << "Failed to initialize libcurl." << std::endl;
    }
    return ipReplStr; // Возврат строки с ipinfo.io или пустой строки при ошибке
}

// Принимает строку с хостнеймом, возвращает вектор строк с ip адресом
std::vector<std::string> getIpAddr(const std::string &hostname)
{
    std::vector<std::string> ipAddrSet;
    struct addrinfo hints = {};
    struct addrinfo *res = nullptr;

    // Настройка параметров для getaddrinfo
    hints.ai_family = AF_UNSPEC;     // IPv4 или IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0)
    {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return ipAddrSet; // возвращаем пустой вектор при ошибке
    }

    // Перебор всех адресов, соответствующих имени хоста
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next)
    {
        void *addr;

        // Определение типа адреса (IPv4 или IPv6)
        if (p->ai_family == AF_INET)
        { // IPv4
            struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            addr = &(ipv4->sin_addr);
        }
        else if (p->ai_family == AF_INET6)
        { // IPv6
            struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            addr = &(ipv6->sin6_addr);
        }
        else
        {
            continue; // Пропускаем неизвестные типы адресов
        }

        // Преобразование адреса в строку
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        ipAddrSet.push_back(std::string(ipstr));
    }

    freeaddrinfo(res); // Освобождение памяти
    std::sort(ipAddrSet.begin(), ipAddrSet.end(), customIpSort);
    return ipAddrSet;
}
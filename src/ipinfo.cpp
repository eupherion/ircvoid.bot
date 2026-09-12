
#include <iostream>
#include <cctype>
#include <string>
#include <vector>
#include <netdb.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <maxminddb.h>

#include "ipinfo.h"

#include "ipinfo.h"

bool validHostOrIp(const std::string &s) {
    if (s.empty()) return false;
    
    // Специфичный host-cloaking для RusNet
    if (s.ends_with(".in-addr") || s.ends_with(".in-addr.arpa")) {
        return false;
    }

    // Проверяем, является ли это валидным IP (v4 или v6)
    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, s.c_str(), &ipv4) == 1 || 
        inet_pton(AF_INET6, s.c_str(), &ipv6) == 1) {
        return true;
    }

    // Проверка на доменное имя
    if (s.find('.') == std::string::npos) return false;

    // Разрешаем буквы, цифры, точку, дефис, подчеркивание (аналог regex ^[A-Za-z0-9._-]+$)
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') {
            return false;
        }
    }
    return true;
}

// Функция резолва хоста в один "основной" IP-адрес
std::string resolveToIp(const std::string &hostname) {
    if (hostname.empty()) return "";

    // Фильтрация PTR записей (.in-addr) с помощью C++20 ends_with
    if (hostname.ends_with(".in-addr") || hostname.ends_with(".in-addr.arpa")) {
        return ""; 
    }

    struct addrinfo hints = {};
    struct addrinfo *res = nullptr;

    hints.ai_family = AF_UNSPEC;     // IPv4 или IPv6
    hints.ai_socktype = SOCK_STREAM;

    // getaddrinfo универсален: он работает и с доменами, и с уже готовыми IP-адресами
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        return ""; 
    }

    std::string first_ipv4;
    std::string first_ipv6;

    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        
        if (p->ai_family == AF_INET && first_ipv4.empty()) {
            struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
            first_ipv4 = ipstr;
        } else if (p->ai_family == AF_INET6 && first_ipv6.empty()) {
            struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipstr, sizeof(ipstr));
            first_ipv6 = ipstr;
        }
        
        // Если нашли оба типа, можно прерывать цикл
        if (!first_ipv4.empty() && !first_ipv6.empty()) break;
    }
    freeaddrinfo(res);

    // Приоритет отдаем IPv4, так как он исторически имеет лучшее покрытие в GeoIP базах
    if (!first_ipv4.empty()) return first_ipv4;
    if (!first_ipv6.empty()) return first_ipv6;
    
    return "";
}

GeoInfo get_ip_info(const std::string &host_or_ip, const std::string &db_path = "./qdb/GeoLite2-City.mmdb") {
    GeoInfo info;

    if (!validHostOrIp(host_or_ip)) {
        return info; // Не похоже на хост
    }

    std::string ip = resolveToIp(host_or_ip);
    if (ip.empty()) {
        return info; // Ошибка резолва или .in-addr
    }

    MMDB_s mmdb;
    int status = MMDB_open(db_path.c_str(), MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        return info; // База не найдена
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        MMDB_close(&mmdb);
        return info; // IP не найден в базе
    }

    MMDB_entry_data_s entry_data;

    // City
    status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        info.city = std::string(entry_data.utf8_string, entry_data.data_size);
    }

    // Region (subdivisions)
    // В MaxMind C API доступ к элементу массива осуществляется по строковому индексу ("0")
    status = MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0", "names", "en", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        info.region = std::string(entry_data.utf8_string, entry_data.data_size);
    }

    // Country
    status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        info.country = std::string(entry_data.utf8_string, entry_data.data_size);
    }

    // Country ISO
    status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        info.country_iso = std::string(entry_data.utf8_string, entry_data.data_size);
    }

    info.valid = true;
    MMDB_close(&mmdb);
    return info;
}

std::string getGeoIp(const std::string &hostStr) {
    GeoInfo info = get_ip_info(hostStr);
    std::string geoIpInfo;
    if (info.valid) {
        geoIpInfo += info.city + ' ';
        geoIpInfo += info.region + ' ';
        geoIpInfo += info.country + ' ';
    }
    return geoIpInfo;
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
    return ipAddrSet;
}
// ipinfo.h
#pragma once

#include <string>
#include <vector>

/**
 * @brief Получает информацию об IP-адресе через сервис ipinfo.io
 *
 * @param ipAddrStr Строка с IP-адресом. Если пустая — используется локальный хост.
 * @param ipinfo_token Токен для доступа к API ipinfo.io
 * @return std::string Информация о IP в виде строки
 */
std::string getIpInfo(std::string /* string with ip */ ipAddrStr, std::string ipinfo_token);

/**
 * @brief Получает список IP-адресов для указанного имени хоста
 *
 * @param hostname Имя хоста для поиска IP-адресов
 * @return std::vector<std::string> Вектор строк с IPv4/IPv6 адресами
 */
std::vector<std::string> getIpAddr(const std::string &hostname);

/**
 * @brief Компаратор для сортировки: IPv4 перед IPv6
 *
 * @param a Первый IP-адрес
 * @param b Второй IP-адрес
 * @return true Если a должен быть до b
 */
bool customIpSort(const std::string &a, const std::string &b);

std::vector<std::string> splitStringBySpaces(const std::string &input);
std::vector<std::string> pack_strings(const std::vector<std::string> &input, size_t max_length);
std::string extractChan(const std::string& msgtext);
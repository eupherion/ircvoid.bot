// ipinfo.h
#ifndef IPINFO_H
#define IPINFO_H

#include <string>
#include <vector>

/**
 * @brief Структура для хранения географической информации об IP-адресе
 */
struct GeoInfo {
    std::string city;       ///< Название города (на английском)
    std::string region;     ///< Название региона/области (на английском)
    std::string country;    ///< Название страны (на английском)
    std::string country_iso;///< Двухбуквенный ISO-код страны (например, "RU", "US")
    bool valid = false;     ///< Флаг успешного получения данных из базы
};

/**
 * @brief Проверяет, является ли строка валидным IP-адресом (IPv4/IPv6) или допустимым доменным именем
 *
 * @param s Строка для проверки
 * @return true Если строка соответствует формату IP-адреса или доменного имени (буквы, цифры, '.', '-', '_')
 * @return false Если строка пуста, содержит недопустимые символы или является обратной PTR-записью (.in-addr)
 */
bool validHostOrIp(const std::string &s);

/**
 * @brief Выполняет резолв имени хоста или IP-адреса в один "основной" строковый IP-адрес
 *
 * @param hostname Имя хоста или IP-адрес для резолва
 * @return std::string Строка с найденным IP-адресом (приоритет отдается IPv4) или пустая строка в случае ошибки резолва
 */
std::string resolveToIp(const std::string &hostname);

/**
 * @brief Получает детальную географическую информацию по хосту или IP-адресу из локальной базы MaxMind
 *
 * @param host_or_ip Имя хоста или IP-адрес для поиска
 * @param db_path Путь к файлу базы данных MaxMind (например, "./qdb/GeoLite2-City.mmdb")
 * @return GeoInfo Структура с заполненными данными (город, регион, страна, ISO-код) или с valid = false при ошибке валидации, резолва или чтения базы
 */
GeoInfo get_ip_info(const std::string &host_or_ip, const std::string &db_path);

/**
 * @brief Возвращает краткую, человекочитаемую строку с географической привязкой хоста
 *
 * @param host Имя хоста или IP-адрес для поиска
 * @return std::string Форматированная строка вида "Город Регион Страна " или пустая строка, если данные не найдены или хост невалиден
 */
std::string getGeoIp(const std::string &host);

/**
 * @brief Получает список всех IP-адресов, связанных с указанным именем хоста
 *
 * @param hostname Имя хоста для поиска IP-адресов
 * @return std::vector<std::string> Вектор строк с найденными IPv4 и/или IPv6 адресами (пустой вектор при ошибке)
 */
std::vector<std::string> getIpAddr(const std::string &hostname);

#endif // IPINFO_H
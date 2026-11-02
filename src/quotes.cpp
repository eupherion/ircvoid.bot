#include "quotes.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>

namespace {

std::string trim_copy(const std::string& value) {
    const std::string whitespace = " \t\n\r\f\v";
    const std::size_t first = value.find_first_not_of(whitespace);
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}

bool is_ascii_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

std::size_t utf8_codepoint_count(std::string_view value) {
    std::size_t count = 0;
    for (unsigned char c : value) {
        if ((c & 0xC0) != 0x80) {
            ++count;
        }
    }
    return count;
}

bool next_utf8_codepoint(std::string_view value, std::size_t& pos, std::uint32_t& cp) {
    if (pos >= value.size()) {
        return false;
    }

    const unsigned char c = static_cast<unsigned char>(value[pos]);
    if (c < 0x80) {
        cp = c;
        ++pos;
        return true;
    }

    int length = 0;
    std::uint32_t codepoint = 0;
    if ((c & 0xE0) == 0xC0) {
        length = 2;
        codepoint = c & 0x1F;
        if (c < 0xC2) {
            return false;
        }
    } else if ((c & 0xF0) == 0xE0) {
        length = 3;
        codepoint = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
        length = 4;
        codepoint = c & 0x07;
    } else {
        return false;
    }

    if (pos + static_cast<std::size_t>(length) > value.size()) {
        return false;
    }

    for (int i = 1; i < length; ++i) {
        const unsigned char continuation = static_cast<unsigned char>(value[pos + i]);
        if ((continuation & 0xC0) != 0x80) {
            return false;
        }
        codepoint = (codepoint << 6) | (continuation & 0x3F);
    }

    if ((length == 2 && codepoint < 0x80) ||
        (length == 3 && (codepoint < 0x800 || (codepoint >= 0xD800 && codepoint <= 0xDFFF))) ||
        (length == 4 && (codepoint < 0x10000 || codepoint > 0x10FFFF))) {
        return false;
    }

    cp = codepoint;
    pos += static_cast<std::size_t>(length);
    return true;
}

bool is_latin_or_cyrillic_letter(std::uint32_t cp) {
    return (cp >= 0x41 && cp <= 0x5A) ||  // A-Z
           (cp >= 0x61 && cp <= 0x7A) ||  // a-z
           (cp >= 0x410 && cp <= 0x44F) || // а-я, А-Я
           cp == 0x401 || cp == 0x451;     // Ё, ё
}

bool contains_latin_or_cyrillic_letter(std::string_view value) {
    std::size_t pos = 0;
    std::uint32_t cp = 0;
    while (next_utf8_codepoint(value, pos, cp)) {
        if (is_latin_or_cyrillic_letter(cp)) {
            return true;
        }
    }
    return false;
}

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string lowercase_latin_and_cyrillic(std::string_view value) {
    std::string result;
    result.reserve(value.size());

    std::size_t pos = 0;
    std::uint32_t cp = 0;
    while (next_utf8_codepoint(value, pos, cp)) {
        if (cp >= 0x41 && cp <= 0x5A) {
            cp += 0x20;
        } else if (cp >= 0x410 && cp <= 0x42F) {
            cp += 0x20;
        } else if (cp == 0x401) {
            cp = 0x451;
        }
        append_utf8(result, cp);
    }

    return result;
}

bool is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

bool is_valid_date(int year, int month, int day) {
    static constexpr int kDaysInMonth[] = {31, 28, 31, 30, 31, 30,
                                           31, 31, 30, 31, 30, 31};
    if (year < 1 || month < 1 || month > 12 || day < 1) {
        return false;
    }
    int days_in_month = kDaysInMonth[month - 1];
    if (month == 2 && is_leap_year(year)) {
        days_in_month = 29;
    }
    return day <= days_in_month;
}

// days_from_civil: алгоритм Говарда Хиннанта для григорианского календаря.
std::int64_t days_from_civil(int year, unsigned month, unsigned day) {
    std::int64_t y = year;
    const unsigned m = month;
    const unsigned d = day;
    y -= m <= 2;

    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned shifted_month = m > 2 ? m - 3 : m + 9;
    const unsigned doy = (153 * shifted_month + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

std::optional<std::chrono::system_clock::time_point>
parse_datetime_utc(const std::string& input) {
    static const std::regex pattern(
        R"(^\s*([0-9]{4})-([0-9]{2})-([0-9]{2})"
        R"((?:[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?)?)"
        R"((?:\s*(Z|[+-][0-9]{2}:?[0-9]{2}))?\s*$)");

    std::smatch match;
    if (!std::regex_match(input, match, pattern)) {
        return std::nullopt;
    }

    const int year = std::stoi(match[1].str());
    const int month = std::stoi(match[2].str());
    const int day = std::stoi(match[3].str());
    const int hour = match[4].matched ? std::stoi(match[4].str()) : 0;
    const int minute = match[5].matched ? std::stoi(match[5].str()) : 0;
    const int second = match[6].matched ? std::stoi(match[6].str()) : 0;

    if (!is_valid_date(year, month, day) || hour > 23 || minute > 59 || second > 60) {
        return std::nullopt;
    }

    long long offset_minutes = 0;
    if (match[8].matched && match[8].str() != "Z") {
        const std::string zone = match[8].str();
        const int sign = zone.front() == '-' ? -1 : 1;
        const int zone_hour = std::stoi(zone.substr(1, 2));
        const int zone_minute = std::stoi(zone.substr(zone.size() - 2));
        if (zone_hour > 23 || zone_minute > 59) {
            return std::nullopt;
        }
        offset_minutes = sign * (static_cast<long long>(zone_hour) * 60 + zone_minute);
    }

    const std::int64_t days = days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
    long long total_seconds = days * 86400LL + hour * 3600LL + minute * 60LL + second;

    std::chrono::system_clock::time_point result(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::seconds(total_seconds)));

    if (match[7].matched) {
        const std::string fraction = match[7].str();
        long long nanoseconds = 0;
        for (char c : fraction) {
            nanoseconds = nanoseconds * 10 + (c - '0');
        }
        for (std::size_t i = fraction.size(); i < 9; ++i) {
            nanoseconds *= 10;
        }
        result += std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::nanoseconds(nanoseconds));
    }

    // ISO-строка без часового пояса считается UTC — как в исходном Python-коде.
    result -= std::chrono::minutes(offset_minutes);
    return result;
}

long long quote_id(const nlohmann::json& quote) {
    if (!quote.is_object() || !quote.contains("id")) {
        return 0;
    }

    const nlohmann::json& id = quote.at("id");
    if (id.is_number_unsigned()) {
        return static_cast<long long>(id.get<unsigned long long>());
    }
    if (id.is_number_integer()) {
        return id.get<long long>();
    }
    return 0;
}

std::string current_local_datetime() {
    const std::time_t now = std::time(nullptr);
    std::tm local_time{};

#ifdef _WIN32
    localtime_s(&local_time, &now);
#else
    localtime_r(&now, &local_time);
#endif

    std::ostringstream out;
    out << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

void set_tar_string(char* field, std::size_t field_size, const std::string& value) {
    std::snprintf(field, field_size, "%s", value.c_str());
}

void set_tar_octal(char* field, std::size_t field_size, unsigned long long value) {
    std::snprintf(field, field_size, "%0*o", static_cast<int>(field_size - 1), value);
    field[field_size - 1] = '\0';
}

void append_tar_header(std::string& out, const std::string& filename,
                       std::uintmax_t file_size, std::time_t modification_time) {
    std::array<char, 512> header{};
    constexpr std::size_t kNameOffset = 0;
    constexpr std::size_t kModeOffset = 100;
    constexpr std::size_t kUidOffset = 108;
    constexpr std::size_t kGidOffset = 116;
    constexpr std::size_t kSizeOffset = 124;
    constexpr std::size_t kMtimeOffset = 136;
    constexpr std::size_t kChecksumOffset = 148;
    constexpr std::size_t kTypeflagOffset = 156;
    constexpr std::size_t kMagicOffset = 257;
    constexpr std::size_t kVersionOffset = 263;

    set_tar_string(header.data() + kNameOffset, 100, filename);
    set_tar_octal(header.data() + kModeOffset, 8, 0644ULL);
    set_tar_octal(header.data() + kUidOffset, 8, 0ULL);
    set_tar_octal(header.data() + kGidOffset, 8, 0ULL);
    set_tar_octal(header.data() + kSizeOffset, 12, static_cast<unsigned long long>(file_size));
    set_tar_octal(header.data() + kMtimeOffset, 12, static_cast<unsigned long long>(modification_time));

    std::fill_n(header.data() + kChecksumOffset, 8, ' ');
    header[kTypeflagOffset] = '0';
    set_tar_string(header.data() + kMagicOffset, 6, "ustar");
    header[kVersionOffset] = '0';
    header[kVersionOffset + 1] = '0';

    unsigned int checksum = 0;
    for (unsigned char c : header) {
        checksum += c;
    }
    std::snprintf(header.data() + kChecksumOffset, 8, "%06o", checksum);
    header[kChecksumOffset + 6] = '\0';
    header[kChecksumOffset + 7] = ' ';

    out.append(header.data(), header.size());
}

std::string make_tar_archive(const std::filesystem::path& file_path, const std::string& archive_name) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Не удалось открыть файл для архивации: " + file_path.string());
    }

    std::string data{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}}; // используем фигурные скобки {}
    
    std::string tar_data;
    tar_data.reserve(data.size() + 2048); 
    
    append_tar_header(tar_data, archive_name, data.size(), std::time(nullptr)); 
    
    tar_data.append(data); 

    const std::size_t padding = (512 - (data.size() % 512)) % 512; 
    
    tar_data.append(padding, '\0');
    tar_data.append(1024, '\0');

    return tar_data;
}

std::string gzip_compress(const std::string& data) {
    namespace io = boost::iostreams;

    std::string compressed;
    io::filtering_ostream out;
    out.push(io::gzip_compressor(io::gzip_params(io::gzip::default_compression)));
    out.push(io::back_inserter(compressed));
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.reset();
    return compressed;
}

} // namespace

Quotes::Quotes(std::string quotes_fpath)
    : quotes_fpath_(std::move(quotes_fpath)), quotes_array_(nlohmann::json::array()) {
    load_quotes();
}

void Quotes::load_quotes() {
    quotes_array_ = nlohmann::json::array();

    std::ifstream in(quotes_fpath_, std::ios::binary);
    if (!in) {
        std::cerr << "Файл " << quotes_fpath_ << " не найден. Создан пустой список цитат.\n";
        return;
    }

    try {
        nlohmann::json parsed;
        in >> parsed;
        if (parsed.is_array()) {
            quotes_array_ = std::move(parsed);
        } else {
            std::cerr << "Файл " << quotes_fpath_
                      << " должен содержать JSON-массив. Используется пустой список цитат.\n";
        }
    } catch (const nlohmann::json::exception&) {
        std::cerr << "Файл " << quotes_fpath_
                  << " содержит некорректный JSON. Используется пустой список цитат.\n";
    }
}

void Quotes::save_quotes() const {
    std::ofstream out(quotes_fpath_, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Не удалось открыть файл для записи: " + quotes_fpath_);
    }
    out << quotes_array_.dump(2) << '\n';
    if (!out) {
        throw std::runtime_error("Не удалось сохранить файл цитат: " + quotes_fpath_);
    }
}

bool Quotes::is_valid_text_token(const std::string& token) const {
    const std::size_t length = utf8_codepoint_count(token);
    if (length < 3 || length > 64) {
        return false;
    }
    if (trim_copy(token).empty()) {
        return false;
    }
    return contains_latin_or_cyrillic_letter(token);
}

bool Quotes::is_valid_id_token(int token) const {
    return token >= 1 && token <= 99999;
}

bool Quotes::is_valid_id_token(const std::string& token) const {
    if (token.empty() || token.size() > 5 ||
        !std::all_of(token.begin(), token.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return false;
    }

    try {
        return is_valid_id_token(std::stoi(token));
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<nlohmann::json> Quotes::search_by_token(int token) const {
    std::vector<nlohmann::json> result;
    if (!is_valid_id_token(token)) {
        return result;
    }

    for (const nlohmann::json& quote : quotes_array_) {
        if (quote_id(quote) == token) {
            result.push_back(quote);
        }
    }
    return result;
}

std::vector<nlohmann::json> Quotes::search_by_token(const std::string& token) const {
    std::vector<nlohmann::json> result;

    if (is_valid_id_token(token)) {
        const int target_id = std::stoi(token);
        for (const nlohmann::json& quote : quotes_array_) {
            if (quote_id(quote) == target_id) {
                result.push_back(quote);
            }
        }
        return result;
    }

    if (!is_valid_text_token(token)) {
        return result;
    }

    const std::string token_lower = lowercase_latin_and_cyrillic(token);
    for (const nlohmann::json& quote : quotes_array_) {
        if (!quote.is_object() || !quote.contains("text") || !quote.at("text").is_string()) {
            continue;
        }

        const std::string text_lower =
            lowercase_latin_and_cyrillic(quote.at("text").get<std::string>());
        if (text_lower.find(token_lower) != std::string::npos) {
            result.push_back(quote);
        }
    }
    return result;
}

std::optional<std::chrono::system_clock::time_point>
Quotes::parse_quote_date(const nlohmann::json& entry) const {
    if (!entry.is_object() || !entry.contains("date-posted") ||
        entry.at("date-posted").is_null() || !entry.at("date-posted").is_string()) {
        return std::nullopt;
    }
    return parse_datetime_utc(entry.at("date-posted").get<std::string>());
}

std::optional<nlohmann::json> Quotes::get_latest_quote() const {
    if (quotes_array_.empty()) {
        return std::nullopt;
    }

    const auto date_key = [this](const nlohmann::json& entry) {
        return parse_quote_date(entry).value_or(std::chrono::system_clock::time_point::min());
    };

    const auto latest = std::max_element(quotes_array_.begin(), quotes_array_.end(),
                                         [&](const nlohmann::json& lhs, const nlohmann::json& rhs) {
                                             return date_key(lhs) < date_key(rhs);
                                         });
    return *latest;
}

std::optional<nlohmann::json> Quotes::get_earliest_quote() const {
    if (quotes_array_.empty()) {
        return std::nullopt;
    }

    const auto date_key = [this](const nlohmann::json& entry) {
        return parse_quote_date(entry).value_or(std::chrono::system_clock::time_point::max());
    };

    const auto earliest = std::min_element(quotes_array_.begin(), quotes_array_.end(),
                                           [&](const nlohmann::json& lhs, const nlohmann::json& rhs) {
                                               return date_key(lhs) < date_key(rhs);
                                           });
    return *earliest;
}

std::optional<nlohmann::json> Quotes::get_random_quote() const {
    if (quotes_array_.empty()) {
        return std::nullopt;
    }

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<std::size_t> distribution(0, quotes_array_.size() - 1);
    return quotes_array_[distribution(generator)];
}

nlohmann::json Quotes::add_quote(const std::string& posted_by, const std::string& text) {
    long long next_id = 1;
    for (const nlohmann::json& quote : quotes_array_) {
        next_id = std::max(next_id, quote_id(quote) + 1);
    }

    nlohmann::json new_entry = {
        {"date-posted", current_local_datetime()},
        {"id", next_id},
        {"posted-by", posted_by},
        {"text", text}
    };

    quotes_array_.push_back(new_entry);
    save_quotes();
    return new_entry;
}

bool Quotes::delete_quote(int quote_id_to_delete) {
    for (auto it = quotes_array_.begin(); it != quotes_array_.end(); ++it) {
        if (quote_id(*it) == quote_id_to_delete) {
            quotes_array_.erase(it);
            save_quotes();
            return true;
        }
    }
    return false;
}

std::string Quotes::backup_quotes() const {
    namespace fs = std::filesystem;

    const fs::path source_path(quotes_fpath_);
    if (!fs::exists(source_path)) {
        throw std::runtime_error("Файл для резервного копирования не найден: " + quotes_fpath_);
    }

    const fs::path directory = source_path.parent_path().empty() ? fs::path(".") : source_path.parent_path();
    const std::string base_name = source_path.stem().string();
    const std::string extension = source_path.extension().string();

    const std::string timestamp = current_local_datetime();
    std::string timestamp_compact;
    timestamp_compact.reserve(timestamp.size());
    for (char c : timestamp) {
        if (std::isdigit(static_cast<unsigned char>(c)) != 0) {
            timestamp_compact.push_back(c);
        }
    }

    const fs::path backup_path = directory / (base_name + "_bkp_" + timestamp_compact + extension);
    fs::copy_file(source_path, backup_path, fs::copy_options::overwrite_existing);

    const std::string tar_data = make_tar_archive(backup_path, backup_path.filename().string());
    const std::string compressed_data = gzip_compress(tar_data);

    const std::string archive_path = backup_path.string() + ".tar.gz";
    std::ofstream archive_out(archive_path, std::ios::binary | std::ios::trunc);
    if (!archive_out) {
        throw std::runtime_error("Не удалось создать архив резервной копии: " + archive_path);
    }
    archive_out.write(compressed_data.data(), static_cast<std::streamsize>(compressed_data.size()));
    if (!archive_out) {
        throw std::runtime_error("Не удалось записать архив резервной копии: " + archive_path);
    }

    fs::remove(backup_path);
    std::cout << "[BACKUP] Created backup: " << archive_path << '\n';
    return archive_path;
}

std::string Quotes::getStringField(const nlohmann::json& quote,
                                   const char* field_name) {
    if (quote.is_object() &&
        quote.contains(field_name) &&
        quote.at(field_name).is_string()) {
        return quote.at(field_name).get<std::string>();
    }
    return {};
}

std::string Quotes::getQuoteDate(const nlohmann::json& quote) {
    return getStringField(quote, "date-posted");
}

std::string Quotes::getQuoteId(const nlohmann::json& quote) {
    if (!quote.is_object() || !quote.contains("id")) {
        return {};
    }

    const nlohmann::json& id = quote.at("id");
    if (id.is_number_unsigned()) {
        return std::to_string(id.get<unsigned long long>());
    }
    if (id.is_number_integer()) {
        return std::to_string(id.get<long long>());
    }
    return {};
}

std::string Quotes::getQuotePostedBy(const nlohmann::json& quote) {
    return getStringField(quote, "posted-by");
}

std::string Quotes::getQuoteText(const nlohmann::json& quote) {
    return getStringField(quote, "text");
}

#ifndef QUOTES_HPP
#define QUOTES_HPP

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "../lib/cppjson.h"

class Quotes {
public:
    explicit Quotes(std::string quotes_fpath = "./qdb/mq.json");

    void load_quotes();
    void save_quotes() const;

    std::vector<nlohmann::json> search_by_token(int token) const;
    std::vector<nlohmann::json> search_by_token(const std::string& token) const;

    std::optional<nlohmann::json> get_latest_quote() const;
    std::optional<nlohmann::json> get_earliest_quote() const;
    std::optional<nlohmann::json> get_random_quote() const;

    nlohmann::json add_quote(const std::string& posted_by, const std::string& text);
    bool delete_quote(int quote_id);
    std::string backup_quotes() const;
    static std::string getQuoteDate(const nlohmann::json& quote);
    static std::string getQuoteId(const nlohmann::json& quote);
    static std::string getQuotePostedBy(const nlohmann::json& quote);
    static std::string getQuoteText(const nlohmann::json& quote);

private:
    static std::string getStringField(const nlohmann::json& quote,
                                      const char* field_name);
    std::string quotes_fpath_;
    nlohmann::json quotes_array_;

    bool is_valid_text_token(const std::string& token) const;
    bool is_valid_id_token(int token) const;
    bool is_valid_id_token(const std::string& token) const;

    std::optional<std::chrono::system_clock::time_point>
    parse_quote_date(const nlohmann::json& entry) const;
};

#endif // QUOTES_HPP

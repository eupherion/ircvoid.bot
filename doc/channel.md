#### Channel structure
```cpp
struct IRCChan {
    std::string name;
    std::string topic;
    bool joined;
    int usercount;
    std::vector<std::vector<std::string>> userlist;
}
```
# `ircvoid.bot` — C++ IRC Bot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **IRC-бот на C++ с поддержкой IP-геолокации, командной системы и расширенной конфигурации.**

---

## 1) Краткое описание

`ircvoid.bot` — это асинхронный IRC-бот, написанный на **C++** с использованием библиотеки **Boost.Asio**. Он предназначен для работы в IRC-сетях и предоставляет следующие возможности:

- Подключение к IRC-серверу (по TLS пока нет).
- Обработка команд от администраторов.
- Получение геолокации IP-адресов и доменов из бызы .mmdb.
- Логирование событий в файл.
- Поддержка CTCP-запросов (`VERSION`, `PING`, `TIME`).
- Управление каналами через команды `.join`, `.part`.

Бот использует **header-only** библиотеки `cpptoml.h` и `cppjson.h` для парсинга TOML-конфигов и JSON-ответов от API.

---

## 2) Установка

### Требования

Для сборки бота вам понадобятся:

- **C++17** или новее
- `g++` или `clang++`
- `Boost.Asio`, `Boost.System`, `Boost.Filesystem`
- `libmaxminddb-dev` - запросов к mmdb ( maxminddb.h )
- `make` (для сборки через Makefile)

### Установка зависимостей (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install build-essential libboost-all-dev libmaxminddb-dev clang
```

### Сборка

```bash
git clone https://github.com/eupherion/ircvoid.bot.git  
cd ircvoid.bot
make
```


#### Очистка

```bash
make clean
```

Удаляет объектные файлы и исполняемый файл.

---

## 3) Конфигурационный файл

Бот использует конфигурационный файл в формате **TOML**. По умолчанию — `conf.toml` в том же каталоге, где находится исполняемый файл бота.

### Пример `conf.toml`

```toml
# Пример конфигурационного файла для IRC-бота

[ircServer]	# Параметры IRC сервера
ircServerHost = "irc.rizon.net"   # Адрес сервера IRC
ircServerPort = 7000              # Порт сервера IRC
ircServerPass = ""                # Пароль сервера (ZNC и сервера с паролем)

[ircClient] # Параметры IRC клиента
ircBotUser = "cbot"               # Имя пользователя бота
ircBotNick = "CxxBot"             # Основной ник бота
ircBotNalt = "CxxBot_, CBot1"     # Альтернативный ник
ircBotRnam = "IP info Bot"        # Реальное имя (RealName)
ircBotNspw = ""                   # Пароль NickServ (двойные кавычки обязательны, пустое если авторизация не нужна)
ircBotChan = "#test, #ircx"       # Каналы, к которым присоединяется бот при подключении
ircBotAdmi = "const, aesh"        # Ники администраторов бота
ircBotAcon = false                # Подключаться ли при старте (только для  работы в foreground)
ircBotCsym = "."                  # Символ команды бота
ircBotRcon = ""                   # Сообщения серверу при соединении 
ircBotDccv = "C++ IRC bot"        # CTCP DCC VERSION

[botComset] # Параметры дополнительных функций бота
geoMMdbPath = "./qdb/GeoLite2-City.mmdb" # Относительный пусть (по отн. к исполняемому файлу бота) к базе MMDB
logFileName = "mybot.irc.log"  # Имя лог-файла бота в директории ./log/ (по отн. к исполняемому файлу бота)
hidePingPong = true            # Скрывать PING? PONG! сервера (в т.ч. из логов)
outputConsole = true           # Вывод внутренних событий бота на консоль (только при работе в foreground)
outputRawData = true           # Вывод RAW траффика от IRC сервера на консоль (только при работе в foreground)
outputDebug = false            # Флаг отладочного режима (только при работе в foreground)
botConfigured = false          # Флаг, что дефолтная конфигурация отредактирована, иначе не запустится
```

> ⚠️ Все поля обязательны.

> ⚠️ При отсутствии `conf.toml` и запуске без аргументов бот создаст дефолтный `conf.toml`.


---

## 4) Запуск

### Режим работы по умолчанию (демон)

По умолчанию, после запуска бот **продолжает работу в фоне** как **демон**, отвязываясь от терминала.

```bash
./bot
```

После этого вы можете закрыть терминал, а бот продолжит свою работу.

### Запуск на переднем плане

Для запуска бота на переднем плане (foreground) используйте ключ `--fg`:

```bash
./bot --fg
# или с указанием конфига
./bot myconfig.toml --fg
```

### Запуск с указанием конфигурации

```bash
./bot myconfig.toml
```

---

## 5) Реализованные команды

Бот реагирует на команды, начинающиеся с символа, указанного в `ircBotCsym` (по умолчанию `.`).

| Команда | Описание |
|--------|--------|
| `.loc <nick>` | Выдаст информацию о хосте пользователя с ником `<nick>` (если хост виден) |
| `.nick <newnick>` | Меняет никнейм бота |
| `.join #channel` | Присоединяется к указанному каналу (только для админов) |
| `.part #channel` | Покидает канал и удаляет его из внутреннего списка (только для админов) |
| `.quit [причина]` | Отключает бота от сервера (только для админов) |

### Примеры

```irc

<admin> .ip 8.8.8.8
<bot> IP: 8.8.8.8 | Host: google-public-dns-a.google.com | Loc: Mountain View, CA, US | Org: Google LLC

<admin> .join #newchat
<bot> *CxxBot parts #newchat*  
      *CxxBot has joined #newchat*

<admin> .quit Maintenance
<bot> *CxxBot has quit (Maintenance)*
```

---

## 6) Лицензия

MIT License — см. файл `LICENSE`.

---

## 7) Автор

**eupherion**  
GitHub: [@eupherion](https://github.com/eupherion)


```

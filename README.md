# `ircvoid.bot` — C++ IRC Bot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **IRC-бот на C++ с поддержкой IP-геолокации, командной системы и расширенной конфигурации.**

---

## 1) Краткое описание

`ircvoid.bot` — это асинхронный IRC-бот, написанный на **C++** с использованием библиотеки **Boost.Asio**. Он предназначен для работы в IRC-сетях и предоставляет следующие возможности:

- Подключение к IRC-серверу по TLS (пока нет).
- Обработка команд от администраторов.
- Получение геолокации IP-адресов и доменов через сервис [ipinfo.io](https://ipinfo.io/).
- Поддержка динамической конфигурации с рантайм-файлами.
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
- `libcurl` (для HTTP-запросов к `ipinfo.io`)
- `make` (для сборки через Makefile)

### Установка зависимостей (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install build-essential libboost-all-dev libcurl4-openssl-dev clang
```

### Сборка

Проект поставляется с `Makefile`, что упрощает сборку.

#### Вариант 1: Сборка через `make` (рекомендуется)

```bash
git clone https://github.com/eupherion/ircvoid.bot.git
cd ircvoid.bot
make
```

Бот будет собран с `clang++` (по умолчанию в `Makefile`). Выходной файл — `bot`.

#### Вариант 2: Сборка вручную

Для сборки вручную используйте:

```bash
# Сборка с помощью clang++
clang++ -std=c++17 -O2 src/main.cpp src/config.cpp src/ipinfo.cpp src/ircbot.cpp \
        -o bot \
        -lboost_system -lboost_filesystem -lboost_thread -lpthread -lcurl

# Или с g++
g++ -std=c++17 -O2 src/main.cpp src/config.cpp src/ipinfo.cpp src/ircbot.cpp \
    -o bot \
    -lboost_system -lboost_filesystem -lboost_thread -lpthread -lcurl
```

> 🔧 **Примечание:** В `Makefile` используется `clang++`. Чтобы переключиться на `g++`, раскомментируйте строку `CC=g++ -std=c++17` и закомментируйте `CC=clang++ -std=c++17`.

#### Очистка

```bash
make clean
```

Удаляет объектные файлы и исполняемый файл.

---

## 3) Конфигурационный файл

Бот использует конфигурационный файл в формате **TOML**. По умолчанию — `config.toml`.

### Пример `config.toml`

```toml
# Конфигурационный файл для IRC-клиента

[ircServer]	# Параметры IRC сервера
ircServerHost = "irc.rizon.net"   # Адрес сервера IRC
ircServerPort = 7000              # Порт сервера IRC
ircServerPass = ""                # Пароль сервера (ZNC и сервера с паролем)

[ircClient] # Параметры IRC клиента
ircBotUser = "cbot"               # Имя пользователя бота
ircBotNick = "CxxBot"             # Основной ник бота
ircBotNalt = "CxxBot_, CBot1"     # Альтернативные ники (через запятую)
ircBotRnam = "IP info Bot"        # Реальное имя (RealName)
ircBotNspw = ""                   # Пароль NickServ (двойные кавычки обязательны, пустое если авторизация не нужна)
ircBotChan = "#test, #ircx"       # Каналы, к которым присоединяется бот при подключении
ircBotAdmi = "vast, nikky"        # Ники администраторов бота (через запятую)
ircBotAcon = false                # Флаг автозапуска (true/false) - подключаться ли при старте
ircBotCsym = "."                  # Символ команды бота
ircBotRcon = ""                   # Сообщения серверу при соединении 
ircBotDccv = "C++ IRC bot"        # CTCP DCC VERSION

[botComset] # Параметры дополнительных функций бота
ipInfToken = "xxxxxxxxxxxxxx"	    # Токен сервиса ipinfo.io (получить на https://ipinfo.io/)
debugMode = false                 # Флаг отладочного режима (verbose mode)
logFileName = "ircbot.log"        # Имя лог-файла бота в директории ./log
```

> ⚠️ Все поля обязательны.  
> 🔐 Поле `ipInfToken` необходимо для получения данных от `ipinfo.io`. Получите его бесплатно на [https://ipinfo.io/](https://ipinfo.io/).

---

## 4) Запуск

### Базовый запуск

```bash
./bot
```

Бот попытается загрузить конфиг из `config.toml` в текущей директории.

### Запуск с указанием конфигурации

```bash
./bot myconfig.toml
```

---

### Особенности запуска

- При первом запуске бот создаёт:
  - Директорию `./log/` для логов.
  - Файл `config.run` (или `<имя_конфига>.run`) — **рантайм-копию конфигурации**.
- При последующих запусках бот **сначала пытается загрузить `.run`-файл**.
  - Если он существует — используется он.
  - Если удалён — создаётся заново из исходного `.toml`.
- Это позволяет модифицировать конфигурацию в рантайме (например, добавлять каналы) и сохранять её между перезапусками.

---

## 5) Реализованные команды

Бот реагирует на команды, начинающиеся с символа, указанного в `ircBotCsym` (по умолчанию `.`).

| Команда | Описание |
|--------|--------|
| `.hi` | Приветствие от бота |
| `.ip <ip или домен>` | Получает информацию о IP/домене через `ipinfo.io` |
| `.loc <ip>` | Синоним `.ip` |
| `.join #channel` | Присоединяется к указанному каналу (только для админов) |
| `.part #channel` | Покидает канал и удаляет его из внутреннего списка (только для админов) |
| `.quit [причина]` | Отключает бота от сервера (только для админов) |

### Примеры

```irc
<user> .hi
<bot> Hello, user! I'm your bot.

<admin> .ip 8.8.8.8
<bot> IP: 8.8.8.8 | Host: google-public-dns-a.google.com | Loc: Mountain View, CA, US | Org: Google LLC

<admin> .join #newchat
<bot> *CxxBot parts #newchat*  
      *CxxBot has joined #newchat*

<admin> .quit Maintenance
<bot> *CxxBot has quit (Maintenance)*
```

---

## 6) Расширение функционала

Вы можете легко расширить бота:

- Добавить новые команды в `parseServerMessage()`.
- Реализовать `.whois`, `.mode`, `.kick`.
- Добавить поддержку DCC-передач.
- Интегрировать с базой данных.

---

## 7) Лицензия

MIT License — см. файл `LICENSE`.

---

## 8) Автор

**eupherion**  
GitHub: [@eupherion](https://github.com/eupherion)

---

> 🚀 Бот готов к использованию в реальных IRC-сетях.  
> Поддерживает современный C++, асинхронную работу и масштабируемую архитектуру.

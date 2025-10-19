CC=g++ -std=c++17
#CC=clang++ -std=c++17

# Добавляем -Wextra и -g
#CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread
#CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
#CFLAGS   = -c -Wall -Wextra -g -pthread
#CFLAGS   = -c -Wall -Wextra -pthread
CFLAGS   = -c -Wall -Wextra -O2 -pthread
LDFLAGS  = -lpthread -lcurl

SOURCE_DIR = src
OBJECT_DIR = obj
BUILD_DIR  = $(CURDIR)
EXECUTABLE = $(BUILD_DIR)/bot

# Список всех .cpp файлов
SOURCES = $(wildcard $(SOURCE_DIR)/*.cpp)

# Замена .cpp на .o и пути src/ на obj/
OBJECTS = $(SOURCES:$(SOURCE_DIR)/%.cpp=$(OBJECT_DIR)/%.o)

# Цель по умолчанию
all: $(EXECUTABLE)

# Сборка исполняемого файла
$(EXECUTABLE): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $^ $(LDFLAGS)

# Компиляция .cpp -> .o
$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CC) $(CXXFLAGS) -c $< -o $@

# Очистка
clean:
	rm -rf $(OBJECT_DIR) $(EXECUTABLE)

# Файлы, не связанные с файлами на диске
.PHONY: all clean

# Компилятор C++ (используем CXX, а не CC)
CXX = g++

# Флаги компиляции (стандарт, предупреждения, оптимизация, поддержка потоков)
CXXFLAGS = -std=c++20 -Wall -Wextra -O2 -pthread

# Флаги линковщика (пути поиска библиотек, если нужны. Пока пусто)
LDFLAGS = 

# Библиотеки для линковки
LDLIBS = -lcurl -lmaxminddb

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

# Сборка исполняемого файла (используем CXX и LDLIBS)
$(EXECUTABLE): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Компиляция .cpp -> .o (используем CXX и CXXFLAGS)
$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Очистка
clean:
	rm -rf $(OBJECT_DIR) $(EXECUTABLE)

# Файлы, не связанные с файлами на диске
.PHONY: all clean
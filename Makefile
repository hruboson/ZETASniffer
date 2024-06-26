# Compiler
CXX = g++

# Compiler flags
CFLAGS = -std=c++20 -Wall -Wextra -pedantic -lpcap

# Source files
SRCDIR = .
SRCS := $(filter-out $(SRCDIR)/main.cpp, $(wildcard $(SRCDIR)/*.cpp))
OBJS := $(SRCS:.cpp=.o)

# Include directories
INCDIR = .

# Executable name
TARGET = ipk-sniffer

# Build directory
BUILDDIR = .

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) -I$(INCDIR) $^ main.cpp -o ./$@

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp $(INCDIR)/%.hpp
	$(CXX) $(CFLAGS) -I$(INCDIR) -c $< -o $@

.PHONY: clean
.PHONY: run

clean:
	rm -rf $(OBJS) $(TARGET)

run:
	./$(TARGET) -i


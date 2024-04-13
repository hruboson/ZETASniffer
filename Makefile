# Compiler
CXX = g++

# Compiler flags
CFLAGS = -std=c++20 -Wall -Wextra -pedantic

# Source files
SRCDIR = .
SRCS := $(filter-out $(SRCDIR)/main.cpp, $(wildcard $(SRCDIR)/*.cpp))
OBJS := $(SRCS:.cpp=.o)

# Include directories
INCDIR = .

# Executable name
TARGET = ipk-sniffer.out

# Build directory
BUILDDIR = .

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) -I$(INCDIR) $^ main.cpp -o ./$@

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp $(INCDIR)/%.hpp
	$(CXX) $(CFLAGS) -I$(INCDIR) -c $< -o $@

.PHONY: clean

clean:
	rm -rf $(OBJS) $(TARGET)


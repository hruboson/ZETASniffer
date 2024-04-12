# Compiler
CC = g++

# Compiler flags
CFLAGS = -std=c++20 -Wall -Wextra -pedantic

# Source files
SRCDIR = ./
SRCS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(SRCS:.cpp=.o)

# Include directories
INCDIR = include

# Executable name
TARGET = ipk-sniffer 

# Build directory
BUILDDIR = ./

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o ./$@

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

.PHONY: clean

clean:
	rm -rf $(BUILDDIR)

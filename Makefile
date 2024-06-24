# Compiler and linker configurations
CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -pedantic -std=c++20
LDFLAGS =

# Define all cpp files as sources
SOURCES = main.cpp message.cpp MessageBuilder.cpp validation_functions.cpp
# Define all object files based on sources
OBJECTS = $(SOURCES:.cpp=.o)
# Define the executable file name
EXECUTABLE = ipk24chat-client

# The first target is the one that is executed when you run make without args
all: $(SOURCES) $(EXECUTABLE)

# This will link the executable
$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

# This will compile the source files into object files
.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up the compilation
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
OUT   = bin/main
SRC   = $(wildcard src/*.cpp)
MAIN  = main.cpp
OBJ   = $(SRC:src/%.cpp=obj/%.o) obj/main.o
CXX   = g++
CXXFLAGS = -g -O3 -I./src -std=c++17
LDFLAGS  = -lcurl
HEAD  = $(wildcard src/*.h)

$(OUT): $(OBJ)
	mkdir -p bin
	$(CXX) $(CXXFLAGS) $(OBJ) -o $@ $(LDFLAGS)

obj/%.o: src/%.cpp
	mkdir -p obj
	$(CXX) $(CXXFLAGS) -c $< -o $@

obj/main.o: $(MAIN)
	mkdir -p obj
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf bin obj

.PHONY: run
run: $(OUT)
	./$(OUT)

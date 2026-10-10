CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra
LDFLAGS = -lpcap

TARGET = asta-sec
SRCS = asta-sec.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) sniffer

# Give execution capabilities to run without sudo on Linux
cap: $(TARGET)
	sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all clean cap run

CXX = g++
LDFLAGS = -lnetfilter_queue

TARGET = 1m-block
SRCS = 1m-block.c

all: $(TARGET)

1m-block: $(SRCS)
	$(CXX) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
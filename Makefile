
OBJS := p2pMessenger.o 
CC := g++
CFLAGS := -Wall  #-Wall -Werror
#CFLAGS += -g #debug flag
LINKFLAGS := -lncurses -lpanel -g


all: p2pMessenger
p2pMessenger: $(OBJS)
	$(CC) $(OBJS) -o p2pMessenger $(LINKFLAGS)

deps := $(patsubst %.o,%.d,$(OBJS))

-include $(deps)
DEPFLAGS = -MMD -MF $(@:.o=.d)
%.o: %.c
	$(CC) $(CFLAGS) -g -c -o $@ $< $(DEPFLAGS)
	
clean:    
	rm -f $(LIB) $(OBJS) *.d

## TODO: Phase 1.1

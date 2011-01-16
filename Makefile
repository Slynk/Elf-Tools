TOOLS	=	testelf extract_elf
COMMON	=	common.o aes.o sha1.o
DEPS	=	Makefile elf32.h elf64.h common.h self.h aes.h sha1.h elf_common.h

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS =	-lz

OBJS	= $(COMMON) $(addsuffix .o, $(TOOLS))

all: $(TOOLS)

$(TOOLS): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON) $(LDFLAGS)

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS)

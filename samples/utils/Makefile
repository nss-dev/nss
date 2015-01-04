include ../common.mk

all: libutils.a
	echo "all done"

libutils.a: util.c
	gcc -Werror -Wfatal-errors -g -c $^ -o util.o \
	$(INCLUDES) $(LIBS)
	ar -cvq libutils.a util.o

clean:
	rm -f libutils.a util.o
	echo "all done"


# get some random seed in a file
# enables testing directly
# without user interaction.
noise:
	echo "Saving random seed..."
	touch noise
	dd if=/dev/urandom of=random-seed count=1 bs=4096	

	

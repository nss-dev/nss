# In some platforms we can't count on pkg-config, on those case
# invoke make with
# export LD_LIBARY_PATH=path_to_nss_shared_libraries; make DONT_USE_PKG_CONFIG=1 all
ifdef DONT_USE_PKG_CONFIG
# Change this to where you have the nspr/nss headers
INCLUDES = -I/usr/include/nspr4 -I/usr/include/nss3
LIBS = -lnspr4 -lc -lnss3 -lnssutil3 -lsmime3 -lplc4
else
INCLUDES = `pkg-config --cflags nss`
LIBS = `pkg-config --libs nss`
endif

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

	

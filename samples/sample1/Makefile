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

all: sample1

clean:
	rm -f ./sample1 ./sample1.c.md* ./sample1.c.sha*

sample1: sample1.c
	gcc -g $^ -o $@ \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

test: test-md2 test-md5 test-sha1 test-sha256 test-sha384 test-sha512

test-md2: sample1
	./sample1 -t MD2 < sample1.c > sample1.c.md2

test-md5: sample1
	./sample1 -t MD5 < sample1.c > sample1.c.md5
	
test-sha1: sample1
	./sample1 -t SHA1 < sample1.c > sample1.c.sha1
	
test-sha256: sample1
	./sample1 -t SHA256 < sample1.c > sample1.c.sha256

test-sha384: sample1
	./sample1 -t SHA384 < sample1.c > sample1.c.sha384

test-sha512: sample1
	./sample1 -t SHA512 < sample1.c > sample1.c.sha512



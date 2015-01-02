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

all: sample5

clean: remove-sample5 remove-nssdb remove-temp-files

sample5: ../utils/util.c sample5.c
	gcc -g $^ -o $@ -I../utils \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

test: genwrapkey encrypt decrypt

genwrapkey: sample5 nssdb
	./sample5 -c G -d sql:./nssdb -s "CN=John Smith, O=Netscape, L=Mountain View, ST=California, C=US" -r "my.req" -a ""

encrypt: sample5 nssdb
	./sample5 -c E -d sql:./nssdb -r "my.req" -i x -a ""

decrypt: sample5 nssdb
	./sample5 -c D -d sql:./nssdb -i x -o y -a ""


nssdb: make-nssdb

make-nssdb:
	if [ -d ./nssdb ]; \
	then \
		echo "nssdb already exists"; \
	else \
		mkdir nssdb &&\
		certutil -N -d sql:./nssdb &&\
		certutil -L -d sql:./nssdb &&\
		echo "created nssdb" ;\
	fi

remove-sample5:
	rm -f sample5

remove-nssdb:
	rm -fr nssdb

remove-temp-files:
	rm -fr my.req sample5.enc sample5.header y noise random-seed

# get some random seed in a file
noise:
	echo "Saving random seed..."
	touch noise
	dd if=/dev/urandom of=random-seed count=1 bs=4096	

	

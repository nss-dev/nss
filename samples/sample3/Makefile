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

all: sample3

clean: remove-sample3 remove-nssdb remove-noise remove-intermediates

sample3: ../utils/util.c sample3.c
	gcc -g $^ -o $@ -I../utils \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

test: encrypt decrypt
			
encrypt: sample3 nssdb
	./sample3 -c a -d sql:./nssdb -z noise -i x -o y

decrypt: sample3 nssdb
	./sample3 -c b -d sql:./nssdb -z noise -i x -o y


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

remove-sample3:
	rm -f sample3

remove-nssdb:
	rm -fr nssdb

remove-noise:
	rm -f noise random-seed

remove-intermediates:
	rm -f x.enc x.header y

# get some random seed in a file
noise:
	echo "Saving random seed..."
	touch noise
	dd if=/dev/urandom of=random-seed count=1 bs=4096	

	

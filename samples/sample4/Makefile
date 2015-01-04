# In some platforms we can't count on pkg-config, due to nss and nspr not being
# installed in the system, on those cases invoke make with
# export LD_LIBARY_PATH=$PATH_TO_NSS_SHARED_LIBS \
# export PATH=$PATH:${LD_LIBARY_PATH}/../bin \
# make DONT_USE_PKG_CONFIG=1 all

ifdef DONT_USE_PKG_CONFIG
# Change this to where you have the nspr/nss headers
INCLUDES = -I/usr/include/nspr4 -I/usr/include/nss3
# For example:
#NSPR_INC_DIR = /home/emaldona/work4nss/upstream/checkout-samples-branch/dist/Linux3.17_x86_64_glibc_PTH_64_DBG.OBJ/include
#NSS_INC_DIR = home/emaldona/work4nss/upstream/checkout-samples-branch/dist/includes/nss
#INCLUDES = -I${NSPR_INC_DIR} -I${NSS_INC_DIR}
LIBS = -lnspr4 -lc -lnss3 -lnssutil3 -lsmime3 -lplc4 -L${LD_LIBRARY_PATH}
else
INCLUDES = `pkg-config --cflags nss`
LIBS = `pkg-config --libs nss`
endif

all: sample4

clean: remove-sample4 remove-nssdb remove-noise remove-intermediates

sample4: ../utils/util.c sample4.c
	gcc -g $^ -o $@ -I../utils \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

test: genwrapkey encrypt decrypt
			
genwrapkey: sample4 nssdb
	./sample4 -c a -d sql:./nssdb -z noise -k qwer

encrypt: sample4 nssdb
	./sample4 -c b -d sql:./nssdb -z noise -k qwer -i x -o y

decrypt: sample4 nssdb
	./sample4 -c c -d sql:./nssdb -z noise -i x -o y


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

remove-sample4:
	rm -f sample4

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

	

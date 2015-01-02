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

all: sample2

clean: remove-sample2 remove-nssdb

sample2: util.c sample2.c
	gcc -g $^ -o $@ \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

test: sample2
	if [ -d ./nssdb ]; \
	then \
		echo "nssdb already exists"; \
	else \
		mkdir nssdb &&\
		./sample2 -d sql:./nssdb &&\
		echo "created nssdb" ;\
	fi

remove-sample2:
	rm -fr sample2

remove-nssdb:
	rm -fr nssdb

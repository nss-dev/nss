# In some platforms we can't count on pkg-config, due to nss and nspr not being
# installed in the system, on those cases invoke make with
# export LD_LIBARY_PATH=$PATH_TO_NSS_SHARED_LIBS \
# export PATH=$PATH:${LD_LIBARY_PATH}/../bin \
# make DONT_USE_PKG_CONFIG=1 all

ifdef DONT_USE_PKG_CONFIG
# Change this to where you have the nspr/nss headers
INCLUDES = -I$(NSPR_INC_DIR) -I$(NSS_INC_DIR)
LIBS = -lnspr4 -lc -lnss3 -lnssutil3 -lsmime3 -lplc4 -L${LD_LIBRARY_PATH}
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

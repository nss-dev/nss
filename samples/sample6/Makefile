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

all: sample6

clean: remove-sample6 remove-alice remove-bob remove-temp-files

sample6: ../utils/util.c sample6.c
	gcc -Werror -Wfatal-errors -g $^ -o $@ -I../utils \
	$(INCLUDES) $(LIBS)
	chmod 755 $@

# setup nss db
make-nssdb-for-both-alice-and-bob: make-alice-nssdb make-bob-nssdb
	echo "Created nssdb for Alice and Bob"

make-alice-nssdb:
	if [ -d ./alice ]; \
	then \
		echo "alice already exists"; \
	else \
		mkdir alice &&\
		echo "created alice" ;\
	fi
	if [ -d ./alice/nssdb ]; \
	then \
		echo "nssdb already exists for alice"; \
	else \
		mkdir -p ./alice/nssdb &&\
		certutil -N -d sql:./alice/nssdb &&\
		certutil -L -d sql:./alice/nssdb &&\
		echo "created nssdb for alice" ;\
	fi

make-bob-nssdb:
	if [ -d ./bob ]; \
	then \
		echo "bob already exists"; \
	else \
		mkdir bob &&\
		echo "created bob" ;\
	fi
	if [ -d ./bob/nssdb ]; \
	then \
		echo "nssdb already exists for bob"; \
	else \
		mkdir -p ./bob/nssdb &&\
		certutil -N -d sql:./bob/nssdb &&\
		certutil -L -d sql:./bob/nssdb &&\
		echo "created nssdb for bob" ;\
	fi

#Clean up
remove-alice:
	rm -fr sample6 ./alice
	echo "cleaned all files under alice"

remove-bob:
	rm -fr sample6 ./bob
	echo "cleaned all files under bob"

remove-sample6:
	rm -f sample6

remove-temp-files:
	rm -fr sample6.header noise random-seed

# Demo for Alice
test: setup-alice-demo show-alice-demo-with-signature-verification

construct-msg-for-alice-as-bob: 
	echo "Construct message for Alice as Bob"
	cp ./x ./bob/bob-msg

setup-alice-demo: sample6 make-nssdb-for-both-alice-and-bob construct-msg-for-alice-as-bob
	echo "Setup completed for Alice"

show-alice-demo: make-csr-as-alice add-alicecert-as-alice encrypt-msg-for-alice-as-bob decrypt-bobs-msg-as-alice
	echo "Demo completed for Alice"

show-alice-demo-with-signature-verification: show-alice-demo sign-msg-as-bob verify-msg-as-alice
	echo "Demo with signature verification completed for Alice"

make-csr-as-alice:
	echo "Generating certificate request for alice"
	./sample6 -G -d sql:./alice/nssdb -z noise -s "CN=Alice, O=Netscape, L=Mountain View, ST=California, C=US" -r ./alice/alice.req -a ""

add-alicecert-as-alice:
	echo "Adding Alice's certificate to Alice's DB"
	./sample6 -A -d sql:./alice/nssdb -n alice -x "" -t "u,u,u" -m 1234 -r ./alice/alice.req -c ./alice/alice.cert -a ""

add-alicecert-as-bob:
	echo "Adding Alice's certificate to Bob's DB"
	./sample6 -A -d sql:./bob/nssdb -n alice -t "u,u,u" -c ./alice/alice.cert -a ""

save-alicecert-to-header:
	echo "Saving Alice's certificate to header"
	./sample6 -H -d sql:./bob/nssdb -n alice -b ./alice/bob-msg.header -a ""

encrypt-msg-for-alice-as-bob: add-alicecert-as-bob save-alicecert-to-header
	echo "As Bob, generate encrypted message for Alice"
	./sample6 -E -d sql:./bob/nssdb -n alice -b ./alice/bob-msg.header -i ./bob/bob-msg -e ./alice/bob-msg-encrypted -a ""

sign-msg-as-bob: make-csr-as-bob add-bobcert-as-bob
	echo "As Bob, signs the message for Alice"
	./sample6 -S -d sql:./bob/nssdb -n bob -b ./alice/bob-msg.header -i ./bob/bob-msg -a ""

verify-msg-as-alice:
	echo "As Alice, verifies Bob's signature"
	./sample6 -V -d sql:./bob/nssdb -b ./alice/bob-msg.header -i ./bob/bob-msg -a ""

decrypt-bobs-msg-as-alice:
	echo "As Alice, decrypt Bob's message"
	./sample6 -D -d sql:./alice/nssdb -b ./alice/bob-msg.header -e ./alice/bob-msg-encrypted -o ./alice/bob-msg-decrypted -a ""

construct-msg-for-bob-as-alice: 
	echo "Construct message for Bob as Alice"
	cp ./x ./alice/alice-msg

setup-bob-demo: sample6 make-nssdb-for-both-alice-and-bob construct-msg-for-bob-as-alice
	echo "Setup completed for Bob"

# Demo for Bob
show-bob-demo: make-csr-as-bob add-bobcert-as-bob encrypt-msg-for-bob-as-alice decrypt-alices-msg-as-bob
	echo "Demo completed for Demo"


make-csr-as-bob:
	echo "Generating certificate request for Bob"
	./sample6 -G -d sql:./bob/nssdb -z noise -s "CN=Bob, O=Netscape, L=Mountain View, ST=California, C=US" -r ./bob/bob.req -a ""

add-bobcert-as-bob:
	echo "Adding Bob's certificate to Bob's DB"
	./sample6 -A -d sql:./bob/nssdb -n bob -x "" -t "u,u,u" -m 2345 -r ./bob/bob.req -c ./bob/bob.cert -a ""

add-bobcert-as-alice:
	echo "Adding Bob's certificate to Alice's DB"
	./sample6 -A -d sql:./alice/nssdb -n bob -t "u,u,u" -c ./bob/bob.cert -a ""

save-bobcert-to-header:
	echo "Saving Bob's certificate to header"
	./sample6 -H -d sql:./alice/nssdb -n bob -b ./bob/alice-msg.header -a ""

encrypt-msg-for-bob-as-alice: add-bobcert-as-alice save-bobcert-to-header
	echo "As Alice, generate encrypted message for Bob"
	./sample6 -E -d sql:./alice/nssdb -n bob -b ./bob/alice-msg.header -i ./alice/alice-msg -e ./bob/alice-msg-encrypted -a ""

decrypt-alices-msg-as-bob:
	echo "As Bob, decrypt Alice's message"
	./sample6 -D -d sql:./bob/nssdb -b ./bob/alice-msg.header -e ./bob/alice-msg-encrypted -o ./bob/alice-msg-decrypted -a ""

# get some random seed in a file
noise:
	echo "Saving random seed..."
	touch noise
	dd if=/dev/urandom of=random-seed count=1 bs=4096	

	

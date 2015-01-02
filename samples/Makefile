SAMPLES = sample1 sample2 sample3 sample4 sample5 sample6

all:
	for d in $(SAMPLES); \
	do \
		(cd $$d; make all); \
	done

clean:
	for d in $(SAMPLES); \
	do \
		(cd $$d; make clean); \
	done


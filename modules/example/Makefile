
all: build

build:
	python setup.py build

install:
	python setup.py install

clean: calc_clean
	rm -rf build
	rm -rf dist

%.o: %.c
	$(CC) -o $@ -c $^

calc_test: main.o calc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

calc_clean:
	rm -rf *.o calc_test

test:
	echo "nothing to do!"

.PHONY: clean
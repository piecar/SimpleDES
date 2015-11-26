all:	 mycipher

mycipher: mycipher.c
	gcc -Wall $< -o $@

clean:
	rm -f mycipher *.o *~ core


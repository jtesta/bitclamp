all: clean archive

clean:
	rm -f *~ *.bz2

archive:
	tar -cf bitclamp_`date +%Y-%m-%d_%H-%M`.tar *.py *.txt Makefile && bzip2 -9 *.tar

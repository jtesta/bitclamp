all: clean archive

clean:
	rm -rf *~ *.bz2 *.pyc *.state __pycache__

archive:
	tar -cf bitclamp_`date +%Y-%m-%d_%H-%M`.tar *.py *.txt Makefile && bzip2 -9 *.tar

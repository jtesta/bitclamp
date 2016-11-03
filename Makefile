.PHONY:	initdev wipedev alltests coretests clean

all: clean archive

TLD=$(shell pwd)

# Install the developer environment, if it isn't already.
initdev:
	@cd unittests && /bin/bash ./install.sh $(TLD)

# Wipe the developer environment.
wipedev:
	@cd unittests && /bin/bash ./wipe_unittest_environment.sh

# Run all the unit tests.
alltests:	initdev
	@python3 unittests/unittests.py $(TLD) all

coretests:	initdev
	@python3 unittests/unittests.py $(TLD) core

clean:
	rm -rf *~ *.bz2 *.pyc *.state __pycache__ unittests/__pycache__

archive:	clean
	tar -cf bitclamp_`date +%Y-%m-%d_%H-%M`.tar *.py *.txt Makefile unittests/*.sh unittests/*.py unittests/*.txt && bzip2 -9 *.tar

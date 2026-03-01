all:
	coq_makefile -f _CoqProject -o Makefile.coq
	$(MAKE) -f Makefile.coq

clean:
	if [ -f Makefile.coq ]; then $(MAKE) -f Makefile.coq clean; fi
	rm -f Makefile.coq Makefile.coq.conf

.PHONY: all clean

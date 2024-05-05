AUTOMAKE_OPTIONS = no-dependencies 
TAGS=ctags
TFLAGS=-dt

SUBDIRS=@BUILD_SUBDIRS@

tags:
	${TAGS} ${TFLAGS} */*.[chly]
MKDEP = @MKDEP@

depend: $(SOURCES) $(HEADERS)
	@for i in $(BUILD_SUBDIRS); do 			\
		cd $$i ;  $(MAKE) depend; cd .. ; 	\
	done

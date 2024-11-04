SHELL         ::= /bin/bash -o pipefail

all: # default target

CC		 ?= clang
CFLAGS		::= -static -lpthread $(CFLAGS)
INCLUDES	::= -I.
DEFS		::= -DGIT_COMMIT='0.1'
PKG_CFLAGS	::= -Wall $(shell pkg-config --static --cflags squashfuse)
OPTIMIZE	::= -Os -flto
LDFLAGS		::= -pthread
SQUASHLIBS	::= squashfs squashfuse squashfuse_ll fuse fuseprivate
UNZLIBS		::= zstd lz4 z lzo2 lzma
LIBS		::= -ldl $(SQUASHLIBS:%=-l:lib%.a)
TARGETS		::=

# == runtime.c ==
runtime.o: src/runtime.c $(wildcard src/*.c src/*.h)
	$(CC) $(INCLUDES) $(DEFS) $(OPTIMIZE) $(PKG_CFLAGS) $(CFLAGS) -c $< -o $@

# == runtime-fuse2-all ==
runtime-fuse2-all: runtime.o
	$(CC) $(OPTIMIZE) $(PKG_CFLAGS) $(CFLAGS) $(LDFLAGS) \
		$< -o $@ $(LIBS) $(UNZLIBS:%=-l:lib%.a)
	strip -s -R .comment --strip-unneeded $@
	# echo -ne 'AI\x02' | dd of="$@" bs=1 count=3 seek=8 conv=notrunc
TARGETS += runtime-fuse2-all

# == runtime-fuse2-zstd ==
runtime-fuse2-zstd: runtime.o src/mocklibs.c
	$(CC) $(OPTIMIZE) $(PKG_CFLAGS) $(CFLAGS) $(LDFLAGS) \
		src/mocklibs.c -DWITH_ZSTD \
		$< -o $@ $(LIBS) $(UNZLIBS:%=-l:lib%.a) \
		$(LIBS) -l:libzstd.a
	strip -s -R .comment --strip-unneeded $@
	# echo -ne 'AI\x02' | dd of="$@" bs=1 count=3 seek=8 conv=notrunc
TARGETS += runtime-fuse2-zstd

# == runtime-fuse2-lz4 ==
runtime-fuse2-lz4: runtime.o src/mocklibs.c
	$(CC) $(OPTIMIZE) $(PKG_CFLAGS) $(CFLAGS) $(LDFLAGS) \
		src/mocklibs.c -DWITH_LZ4 \
		$< -o $@ $(LIBS) $(UNZLIBS:%=-l:lib%.a) \
		$(LIBS) -l:libzstd.a
	strip -s -R .comment --strip-unneeded $@
	# echo -ne 'AI\x02' | dd of="$@" bs=1 count=3 seek=8 conv=notrunc
TARGETS += runtime-fuse2-lz4

# == clean ==
clean:
	rm -f *.o runtime-fuse2-all runtime-fuse2-zstd runtime-fuse2-lz4

# == all ==
all: $(TARGETS)

#
WARNS = 6
NOMAN =
PROG = drm_test
CPPFLAGS += -I/usr/X11R7/include -I/usr/X11R7/include/libdrm
LDFLAGS += -Wl,-R/usr/X11R7/lib -L/usr/X11R7/lib
LDADD += -ldrm


.include <bsd.prog.mk>

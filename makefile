###########################################################################
#
#	Filename:			makefile
#
#	Description:		Basic example application makefile from
#						Chapter 12: An Example Application Using eCos.
#						This makefile is based on the example makefile
#						from the eCos source code repository.
#
#						Embedded Software Development With eCos
#						by Anthony Massa
#
#						Copyright (c) 2002, 2003 by Anthony Massa.
#						This software is placed into the public domain
#						and may be used for any purpose.  No warranty
#						is either expressed or implied by its
#						publication or distribution.
#
###########################################################################

## eCos library installation directory
PKG_INSTALL_DIR = /home/kos/Desktop/untitled_install


## This sets the compiler to i386 PC.
XCC = gcc

##
## Build flag descriptions.
##
## Compiler flags
##
##   -g						: Produce debugging information.
##   -Wall					: Enable all preprocessor warnings.
##   -I						: Add directory to head of list to be searched for header files.
##   -ffunction-sections	: Place each function into its own section.
##   -fdata-sections		: Discard unused virtual functions.
##
## Linker flags
##
##   -nostartfiles			: Do not use the standard system startup files when linking.
##							  The standard system libraries are used normally, unless
##							  -nostdlib or -nodefaultlibs is used.
##   -L						: Add DIRECTORY to library search path.
##   -Wl					: Pass comma-separated <options> on to the linker.
##   --gc-sections			: Remove unused sections (on some targets).
##   -Map					: Write a map file.
##   -T						: Read linker script.
##   -nostdlib				: Do not use the standard system startup files or
##							  libraries when linking. No startup files and only
##							  the libraries you specify will be passed to the linker.
##

## Build flags.
CFLAGS	= -gstabs+ -O0 -Wall -I$(PKG_INSTALL_DIR)/include -ffunction-sections -fdata-sections -D__ECOS -D_KERNEL
LDFLAGS	= -gstabs+ -nostartfiles -L$(PKG_INSTALL_DIR)/lib -Wl,--gc-sections -Wl,--Map -Wl,bridge.map
LIBS	= -Ttarget.ld -nostdlib
LD		= $(XCC)

SOURCES=bridge.c ip_fw.c ip_fw_sockopt.c ip_fw_table.c ipfw2.c ether_aton.c strsep.c alias.c ip_fw_nat.c ip_divert.c
OBJECTS=$(SOURCES:.c=.o)

## Build rules.
all: 	bridge

.c.o:
	$(XCC) $(CFLAGS) $< -c -o $@

bridge: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-rm -f bridge $(OBJECTS) bridge.map


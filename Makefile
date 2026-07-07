.PHONY: all libcryptoauth libateccssl libpkcs11 dist install clean

ifdef DEB_HOST_GNU_TYPE
CROSS_COMPILE=$(DEB_HOST_GNU_TYPE)-
endif

ifdef CROSS_COMPILE
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)gcc
AR:=$(CROSS_COMPILE)ar
endif

OPTIONS := ATCAPRINTF ATCA_HAL_I2C ENGINE_DYNAMIC_SUPPORT USE_ECCX08 ATCA_OPENSSL_ENGINE_STATIC_CONFIG

# SYSTEM_INCLUDES := /usr/include

# Check platform
ifeq ($(OS),Windows_NT)
# Special check for simulated windows environments
uname_S := $(shell cmd /C 'uname -s' 2>nul)
ifeq ($(uname_S),)
# Straight-up windows detected
uname_S := Windows
endif
else
uname_S := $(shell uname -s 2>/dev/null)
endif

# Define helpful macros for interacting with the specific environment
BACK2SLASH = $(subst \,/,$(1))
SLASH2BACK = $(subst /,\,$(1))

ifeq ($(uname_S),Windows)
# Windows commands
FIND = $(shell dir $(call SLASH2BACK,$(1)\$(2)) /W /B /S)
MKDIR = $(shell mkdir $(call SLASH2BACK,$(1)))
else
# Assume *nix like commands
FIND = $(shell find $(abspath $(1)) -name $(2))
MKDIR = $(shell mkdir -p $(1) 2>/dev/null)
endif

# If the target wasn't specified assume the target is the build machine
ifeq ($(TARGET_ARCH),)
ifeq ($(OS),Windows_NT)
TARGET_ARCH = Windows
endif
endif

CFLAGS := 

ifeq ($(uname_S),Linux)
CFLAGS += -g -O2 -Wall -fPIC $(addprefix -D,$(OPTIONS))
TARGET_ARCH := Linux
endif
#    ifeq ($(uname_S),Darwin)
#        CCFLAGS += -D OSX
#    endif
#    UNAME_P := $(shell uname -p)
#    ifeq ($(UNAME_P),x86_64)
#        CCFLAGS += -D AMD64
#    endif
#    ifneq ($(filter %86,$(UNAME_P)),)
#        CCFLAGS += -D IA32
#    endif
#    ifneq ($(filter arm%,$(UNAME_P)),)
#        CCFLAGS += -D ARM
#    endif

OUTDIR := $(abspath .$(CROSS_COMPILE)build)

DEPFLAGS = -MT $@ -MMD -MP -MF $(OUTDIR)/$*.d
ARFLAGS = rcs

CRYPTOAUTHLIB_DIR=./cryptoauthlib
LIBATECCSSL_DIR=./ateccssl

LIBATECCSSL_SOURCES :=  eccx08_cmd_defns.c \
						eccx08_ecdsa_sign.c \
						eccx08_eckey_meth.c \
						eccx08_engine.c \
						eccx08_err.c \
						eccx08_platform.c \
						eccx08_auth.c

ifneq (,$(findstring ATCA_OPENSSL_ENGINE_ENABLE_CERTS, $(OPTIONS)))
LIBATECCSSL_SOURCES += eccx08_cert.c
ifneq (,$(findstring ATCA_OPENSSL_ENGINE_STATIC_CONFIG, $(OPTIONS)))
LIBATECCSSL_SOURCES +=  cert_def_1_signer.c \
						cert_def_2_device.c \
						cert_def_3_device_csr.c
endif
endif

ifneq (,$(findstring ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS, $(OPTIONS)))
LIBATECCSSL_SOURCES += eccx08_cipher.c
endif

ifneq (,$(findstring ATCA_OPENSSL_ENGINE_REGISTER_ECDH, $(OPTIONS)))
LIBATECCSSL_SOURCES += eccx08_ecdh.c
endif

ifneq (,$(findstring ATCA_OPENSSL_ENGINE_ENABLE_SHA256, $(OPTIONS)))
LIBATECCSSL_SOURCES += eccx08_sha256.c
endif

ifneq (,$(findstring ATCA_OPENSSL_ENGINE_ENABLE_RAND, $(OPTIONS)))
LIBATECCSSL_SOURCES += eccx08_rand.c
endif

LIBATECCSSL_SOURCES := $(addprefix $(LIBATECCSSL_DIR)/, $(LIBATECCSSL_SOURCES))

# Wildcard all the sources and headers
SOURCES := $(call FIND,$(CRYPTOAUTHLIB_DIR)/lib,*.c)
SOURCES += $(LIBATECCSSL_SOURCES)
INCLUDE := $(dir $(call FIND, $(CRYPTOAUTHLIB_DIR)/lib, *.h))
INCLUDE += $(dir $(call FIND, $(LIBATECCSSL_DIR), *.h))
INCLUDE := $(sort $(INCLUDE))



# Gather OpenSSL Engine objects
LIBATECCSSL_OBJECTS := $(filter $(abspath $(LIBATECCSSL_DIR))/%, $(SOURCES))
LIBATECCSSL_OBJECTS := $(addprefix $(OUTDIR)/,$(notdir $(LIBATECCSSL_OBJECTS:.c=.o)))

# Gather PKCS11 Objects
LIBPKCS11_OBJECTS := $(filter $(abspath $(LIBATECCSSL_DIR)/lib/pkcs11)/%, $(SOURCES))
LIBPKCS11_OBJECTS := $(addprefix $(OUTDIR)/,$(notdir $(LIBPKCS11_OBJECTS:.c=.o)))

# Gather libcryptoauth objects
LIBCRYPTOAUTH_OBJECTS := $(filter-out $(abspath $(CRYPTOAUTHLIB_DIR)/lib/hal)/%, $(SOURCES))
LIBCRYPTOAUTH_OBJECTS := $(filter-out $(abspath $(CRYPTOAUTHLIB_DIR)/lib/pkcs11)/%, $(LIBCRYPTOAUTH_OBJECTS))
LIBCRYPTOAUTH_OBJECTS := $(filter-out $(abspath $(LIBATECCSSL_DIR))/%, $(LIBCRYPTOAUTH_OBJECTS))
LIBCRYPTOAUTH_OBJECTS += atca_hal.c

HAL_OBJECTS:=

ifeq ($(TARGET_ARCH),Windows)
# Only kit protocol hals are available on windows
HAL_OBJECTS += hal_win_kit_cdc.c hal_win_timer.c hal_win_os.c kit_protocol.c
endif

ifeq ($(TARGET_ARCH),Linux)
# General Linux Support
HAL_OBJECTS += hal_linux_timer.c hal_linux_os.c

ifeq ($(TARGET_HAL),I2C)
# Native I2C hardware/driver
HAL_OBJECTS += hal_linux_i2c_userspace.c
else
# Assume Kit Protocol
HAL_OBJECTS += hal_linux_kit_cdc.c kit_protocol.c
endif
endif

LIBCRYPTOAUTH_OBJECTS += $(addprefix $(CRYPTOAUTHLIB_DIR)/lib/hal/, $(HAL_OBJECTS))

TEST_SOURCES := $(call FIND,$(CRYPTOAUTHLIB_DIR)/test,*.c)
#TEST_INCLUDE := $(sort $(dir $(call FIND, $(CRYPTOAUTHLIB_DIR)/test, *.h)))
TEST_INCLUDE := $(abspath .)
TEST_OBJECTS := $(addprefix $(OUTDIR)/,$(notdir $(TEST_SOURCES:.c=.o)))

LIBCRYPTOAUTH_OBJECTS := $(addprefix $(OUTDIR)/,$(notdir $(LIBCRYPTOAUTH_OBJECTS:.c=.o)))

CFLAGS += $(addprefix -I, $(INCLUDE) $(TEST_INCLUDE) $(SYSTEM_INCLUDES))

# Regardless of platform set the vpath correctly
vpath %.c $(call BACK2SLASH,$(sort $(dir $(SOURCES) $(TEST_SOURCES))))

$(OUTDIR):
	$(call MKDIR, $(OUTDIR))

$(OUTDIR)/%.o : %.c $(OUTDIR)/%.d | $(OUTDIR)
	@echo " [CC] $<"
	@$(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

$(OUTDIR)/%.d: ;
.PRECIOUS: $(OUTDIR)/%.d

$(OUTDIR)/libcryptoauth.a: $(LIBCRYPTOAUTH_OBJECTS) | $(OUTDIR)
	@echo " [AR] $@"
	@$(AR) $(ARFLAGS) $@ $(LIBCRYPTOAUTH_OBJECTS)

$(OUTDIR)/libateccssl.so: $(LIBATECCSSL_OBJECTS) $(LIBCRYPTOAUTH_OBJECTS) | $(OUTDIR)
	@echo " [LD] $@"
	@$(CC) -shared $(LIBATECCSSL_OBJECTS) $(LIBCRYPTOAUTH_OBJECTS) -o $@ -lcrypto -lrt

$(OUTDIR)/test: $(OUTDIR)/libateccssl.so $(TEST_OBJECTS) | $(OUTDIR)
	@echo " [CC TEST] $@"
	@$(CC) -o $@ $(TEST_OBJECTS) -L$(OUTDIR) -lateccssl -lcrypto -lssl
	
install: $(OUTDIR)/libateccssl.so
	mkdir -p $(DESTDIR)/usr/lib/$(DEB_HOST_GNU_TYPE)/engines-3/
	install -m 0644 $(OUTDIR)/libateccssl.so $(DESTDIR)/usr/lib/$(DEB_HOST_GNU_TYPE)/engines-3/ateccx08.so

include $(wildcard $(patsubst %,$(OUTDIR)/%.d,$(basename $(SOURCES))))

libpkcs11: $(LIBPKCS11_OBJECTS) | $(OUTDIR)

libateccssl: $(OUTDIR)/libateccssl.so | $(OUTDIR)

libcryptoauth: $(OUTDIR)/libcryptoauth.a | $(OUTDIR)

all: $(LIBCRYPTOAUTH_OBJECTS) $(LIBATECCSSL_OBJECTS) $(LIBPKCS11_OBJECTS) | $(OUTDIR)

test: $(OUTDIR)/test | $(OUTDIR)
	env LD_LIBRARY_PATH=$(OUTDIR) $(OUTDIR)/test

clean:
	rm -rf .*build

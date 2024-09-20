#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2022 Zondax GmbH
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines
# Set the default value for PRODUCTION_BUILD to 0 if not already defined
PRODUCTION_BUILD ?= 1

$(info ************ TARGET_NAME  = [$(TARGET_NAME)])

# Display whether this is a production build or for internal use
ifeq ($(PRODUCTION_BUILD), 1)
    $(info ************ PRODUCTION_BUILD  = [PRODUCTION BUILD])
else
    $(info ************ PRODUCTION_BUILD  = [INTERNAL USE])
endif

# Add the PRODUCTION_BUILD definition to the compiler flags
DEFINES += PRODUCTION_BUILD=$(PRODUCTION_BUILD)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=ICP
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN),ICP)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "InternetComputer"
APPPATH = "44'/223'"

else ifeq ($(COIN),ICP_INVALID)
else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS) --path $(APPPATH)

APP_STACK_MIN_SIZE := 2050
include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices
RUST_TARGET := thumbv6m-none-eabi

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

# Enable bls signature verification for all targets except TARGET_NANOS and TARGET_NANOX
ifneq ($(TARGET_NAME),TARGET_NANOS)
ifneq ($(TARGET_NAME),TARGET_NANOX)
BLS_SIGNATURE = 1
DEFINES += BLS_SIGNATURE=$(BLS_SIGNATURE)
endif
endif

RUST_TARGET_NAME := $(TARGET_NAME)

NBGL_TARGETS := TARGET_STAX TARGET_FLEX
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME), $(NBGL_TARGETS)))
RUST_TARGET_NAME := TARGET_STAX
endif

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform
CFLAGS += -Wvla  -Wno-implicit-fallthrough
CFLAGS += -I$(MY_DIR)/../deps/tinycbor/src
APP_SOURCE_PATH += $(MY_DIR)/../deps/tinycbor-ledger
LDFLAGS  += -z muldefs

ifdef BLS_SIGNATURE
LDLIBS   += -Lrust/target/$(RUST_TARGET)/release -lrslib
endif

APP_SOURCE_PATH += $(MY_DIR)/rust/include

CFLAGS += -I$(MY_DIR)/../deps/nanopb/
APP_SOURCE_PATH += $(MY_DIR)/../deps/nanopb_tiny/


# Check if BLS_SIGNATURE is set
ifdef BLS_SIGNATURE

APP_CUSTOM_LINK_DEPENDENCIES = rust

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" TARGET_NAME=$(RUST_TARGET_NAME) cargo build --target $(RUST_TARGET) --release

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

.PHONY: rust_tests
rust_tests:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo test
else
# Empty rules when BLS_SIGNATURE is not set
.PHONY: rust
rust:
	@echo "Skipping Rust build (BLS_SIGNATURE not set)"

.PHONY: rust_clean
rust_clean:
	@echo "Skipping Rust clean (BLS_SIGNATURE not set)"

.PHONY: rust_tests
rust_tests:
	@echo "Skipping Rust tests (BLS_SIGNATURE not set)"

endif

ifdef BLS_SIGNATURE
clean: rust_clean
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: listvariants
listvariants:
	@echo VARIANTS COIN ICP

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version

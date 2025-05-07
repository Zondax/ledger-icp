#*******************************************************************************
#*   (c) 2019 Zondax AG
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

# We use BOLOS_SDK to determine the development environment that is being used
# BOLOS_SDK IS  DEFINED	 	We use the plain Makefile for Ledger
# BOLOS_SDK NOT DEFINED		We use a containerized build approach

# TESTS_JS_PACKAGE = "@zondax/ledger-icp"
# TESTS_JS_DIR = $(CURDIR)/../ledger-icp-js

ifeq ($(BOLOS_SDK),)

ZXLIB_COMPILE_STAX ?= 1
PRODUCTION_BUILD ?= 1
include $(CURDIR)/deps/ledger-zxlib/dockerized_build.mk

proto:
	cd $(CURDIR)/app/src/protobuf && $(CURDIR)/deps/nanopb/generator/protoc ./base_types.proto ./types.proto ./governance.proto ./dfinity.proto --nanopb_out=.

else
default:
	$(MAKE) -C app
%:
	$(info "Calling app Makefile for target $@")
	COIN=$(COIN) $(MAKE) -C app $@
endif

test_all:
	make zemu_install
	PRODUCTION_BUILD=1 make
	make zemu_test

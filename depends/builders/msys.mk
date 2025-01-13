# MSYS-specific tools and configurations
build_os = msys
build_CC = x86_64-w64-mingw32-gcc
build_CXX = x86_64-w64-mingw32-g++
build_AR = x86_64-w64-mingw32-ar
build_RANLIB = x86_64-w64-mingw32-ranlib
build_STRIP = x86_64-w64-mingw32-strip
build_NM = x86_64-w64-mingw32-nm
build_SHA256SUM = sha256sum
build_DOWNLOAD = curl -f --retry 5 --retry-delay 3 -o
build_CFLAGS =
build_CXXFLAGS =
build_LDFLAGS =

# Use default tools where applicable
default_build_CC = gcc
default_build_CXX = g++
default_build_AR = ar
default_build_RANLIB = ranlib
default_build_STRIP = strip
default_build_NM = nm
default_build_SHA256SUM = sha256sum
default_build_DOWNLOAD = curl -f --retry 5 --retry-delay 3 -o

# Apply default values if not set
define add_build_tool_func
build_$(build_os)_$1 ?= $$(default_build_$1)
build_$(build_arch)_$(build_os)_$1 ?= $$(build_$(build_os)_$1)
build_$1=$$(build_$(build_arch)_$(build_os)_$1)
endef

$(foreach var,CC CXX AR RANLIB NM STRIP SHA256SUM DOWNLOAD,$(eval $(call add_build_tool_func,$(var))))

define add_build_flags_func
build_$(build_arch)_$(build_os)_$1 += $(build_$(build_os)_$1)
build_$1=$$(build_$(build_arch)_$(build_os)_$1)
endef

$(foreach flags,CFLAGS CXXFLAGS LDFLAGS,$(eval $(call add_build_flags_func,$(flags))))

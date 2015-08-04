Name: libcom-core
Summary: Library for the light-weight IPC
Version: 1.0.2
Release: 1
Group: Base/IPC
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: 	%{name}.manifest
BuildRequires: cmake, gettext-tools, coreutils
BuildRequires: libattr-devel
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(libsystemd-daemon)

%description
Light-weight IPC supporting library for Tizen

%package devel
Summary: Files for using API for light-weight IPC
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Light-weight IPC supporting library for Tizen (dev)

%prep
%setup -q
cp %{SOURCE1001} .

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="${CFLAGS} -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="${CXXFLAGS} -DTIZEN_ENGINEER_MODE"
export FFLAGS="${FFLAGS} -DTIZEN_ENGINEER_MODE"
%endif

%cmake .
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/%{_datarootdir}/license

%post -n libcom-core -p /sbin/ldconfig

%postun -n libcom-core -p /sbin/ldconfig

%files -n libcom-core
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so*
%{_datarootdir}/license/*

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/com-core/com-core.h
%{_includedir}/com-core/packet.h
%{_includedir}/com-core/com-core_packet.h
%{_includedir}/com-core/com-core_thread.h
%{_includedir}/com-core/secure_socket.h
%{_libdir}/pkgconfig/*.pc

# End of a file

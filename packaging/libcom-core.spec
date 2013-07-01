Name: libcom-core
Summary: Library for the light-weight IPC 
Version: 0.3.14
Release: 1
Group: HomeTF/Framework
License: Apache License
Source0: %{name}-%{version}.tar.gz
Source1001: 	libcom-core.manifest
BuildRequires: cmake, gettext-tools, coreutils
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(glib-2.0)

%description
Light-weight IPC supporting library

%package devel
Summary: Files for using API for light-weight IPC.
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Light-weight IPC supporting library (dev)

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/%{_datarootdir}/license

%post

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
Name: libcom-core
Summary: Library for the light-weight IPC 
Version: 0.3.5
Release: 1
Group: main/util
License: Flora License
Source0: %{name}-%{version}.tar.gz
BuildRequires: cmake, gettext-tools
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

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license

%post

%files -n libcom-core
%manifest libcom-core.manifest
%defattr(-,root,root,-)
/usr/lib/*.so*
/usr/share/license/*

%files devel
%defattr(-,root,root,-)
/usr/include/com-core/com-core.h
/usr/include/com-core/packet.h
/usr/include/com-core/com-core_packet.h
/usr/include/com-core/com-core_thread.h
/usr/include/com-core/secure_socket.h
/usr/lib/pkgconfig/*.pc

Name: libconnector
Summary: Library for the light-weight IPC 
Version: 0.0.1
Release: 1
Group: main/util
License: Samsung Proprietary License
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
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

%build
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%post

%files
%defattr(-,root,root,-)
/usr/lib/*.so*

%files devel
%defattr(-,root,root,-)
/usr/include/connector/connector.h
/usr/include/connector/packet.h
/usr/include/connector/connector_packet.h
/usr/include/connector/secom_socket.h
/usr/lib/pkgconfig/*.pc

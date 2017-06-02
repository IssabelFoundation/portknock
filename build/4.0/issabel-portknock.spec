%define modname portknock

Summary: Single-packet port-knocking utility for Issabel
Name:    issabel-%{modname}
Group: Applications/System
Version: 4.0.0
Release: 1
License: GPL
Source0: %{modname}_%{version}-%{release}.tgz
BuildRequires: libpcap-devel
Packager: Issabel Foundation
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Obsoletes: elastix-portknock

%description
This is a simple program to implement a single-packet authentication system for
Issabel on selected network interfaces. This program only verifies that the 
payload is a well-formed port knocking packet. The actual decryption is 
delegated to the helper program specified in the command line.

%prep
%setup -n %{name}_%{version}-%{release}

%build
%__make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sbindir}/
cp udp-portknock $RPM_BUILD_ROOT%{_sbindir}/

%files
%defattr(755,root,root)
%{_sbindir}/udp-portknock

%changelog

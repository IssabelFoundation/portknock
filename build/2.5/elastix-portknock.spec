Summary: Single-packet port-knocking utility for Elastix
Name: elastix-portknock
Group: Applications/System
Version: 0.0.1
Release: 0
License: GPL
Source: %{name}-%{version}.tar.bz2
BuildRequires: libpcap-devel
Packager: Palosanto Solutions
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
This is a simple program to implement a single-packet authentication system for
Elastix on selected network interfaces. This program only verifies that the
payload is a well-formed port knocking packet. The actual decryption is
delegated to the helper program specified in the command line.

%prep
%setup

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
* Wed Jun 20 2012 Alex Villacis Lasso <a_villacis@palosanto.com> 0.0.1-0
- Initial version

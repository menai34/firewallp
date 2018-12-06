%define name firewallp
%define use_systemd (0%{?fedora} && 0%{?fedora} >= 18) || (0%{?rhel} && 0%{?rhel} >= 7) || (0%{?suse_version} && 0%{?suse_version} >=1210)

Name:      %{name}
Version:   1
Release:   1
Url:       https://bitbucket.sperasoft.com/projects/IT/repos/firewallp/browse
Summary:   Frontend for Iptables and IPSet tools
License:   GPLv3+
Group:     Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Source0:    %{name}-%{version}.tar.gz
Source10:    dnat.yml
Source11:    firewallp.yml
Source12:    forward.yml
Source13:    input.yml
Source14:    objects.yml
Source15:    output.yml
Source16:    policy.yml
Source17:    service.yml
Source18:    snat.yml
Source19:    mangle_forward.yml
Source20:    mangle_input.yml
Source21:    mangle_output.yml
Source22:    mangle_postrouting.yml
Source23:    mangle_prerouting.yml
Source40:    firewallp
Source41:    firewallp.service

BuildArch: noarch

# RHEL <=5
%if 0%{?rhel} && 0%{?rhel} <= 5
BuildRequires: python26-devel
BuildRequires: python26-setuptools
Requires: ipset
Requires: iptables-services
Requires: python26-PyYAML
Requires: python26-lxml
Requires: python26-jinja2
Requires: python26-setuptools
%endif

# RHEL > 5
%if 0%{?rhel} && 0%{?rhel} > 5
BuildRequires: python2-devel
BuildRequires: python-setuptools
Requires: ipset
Requires: iptables-services
Requires: PyYAML
Requires: python-lxml
Requires: python-jinja2
Requires: python-setuptools
%endif

%description

FirewallP frontend solution for Iptables and IPSet tools

%prep
%setup -q

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --skip-build --root=%{buildroot}

mkdir -p %{buildroot}%{_sysconfdir}/firewallp/
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_usr}/lib/systemd/system/
cp %{SOURCE10} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE11} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE12} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE13} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE14} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE15} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE16} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE17} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE18} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE19} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE20} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE21} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE22} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE23} %{buildroot}%{_sysconfdir}/firewallp/
cp %{SOURCE40} %{buildroot}%{_bindir}
cp %{SOURCE41} %{buildroot}%{_usr}/lib/systemd/system/

%clean
rm -rf %{buildroot}

%pre

%post

%postun
%if %use_systemd
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 ||:
%endif

%files
%defattr(-,root,root)
%{python_sitelib}/firewallp*
%{_bindir}/firewallp
%config(noreplace) %{_sysconfdir}/firewallp
%config %{_usr}/lib/systemd/system/firewallp.service

%changelog

* Fri Apr 27 2018 FirewallP <stream.it@sperasoft.com> - 0.0.1a4
- Version 0.0.1a4

* Wed Jan 31 2018 FirewallP <stream.it@sperasoft.com> - 0.0.1a3
- Version 0.0.1a3

* Wed Nov 29 2017 FirewallP <stream.it@sperasoft.com> - 0.0.1a2
- Version 0.0.1a2
%global __requires_exclude pkg-config
%global pkgdir %{_prefix}/lib/systemd
%global system_unit_dir %{pkgdir}/system
%global user_unit_dir %{pkgdir}/user
%global _docdir_fmt %{name}
%global _systemddir /usr/lib/systemd

%ifarch aarch64
%global efi_arch aa64
%endif

%ifarch x86_64
%global efi_arch x64
%endif

%ifarch %{ix86} x86_64 aarch64
%global have_gnu_efi 1
%endif

Name:           systemd
Url:            https://www.freedesktop.org/wiki/Software/systemd
Version:        249
Release:        3
License:        MIT and LGPLv2+ and GPLv2+
Summary:        System and Service Manager


Source0:        https://github.com/systemd/systemd/archive/v%{version}/%{name}-%{version}.tar.gz
Source3:        purge-nobody-user
Source4:        yum-protect-systemd.conf
Source5:        inittab
Source6:        sysctl.conf.README
Source7:        systemd-journal-remote.xml
Source8:        systemd-journal-gatewayd.xml
Source10:       systemd-udev-trigger-no-reload.conf
Source11:       20-grubby.install
Source12:       systemd-user
Source13:       rc.local

Source100:  	udev-40-openEuler.rules
Source101:  	udev-55-persistent-net-generator.rules
Source102:  	udev-56-net-sriov-names.rules
Source103:  	udev-61-openeuler-persistent-storage.rules
Source104:  	net-set-sriov-names
Source105:  	rule_generator.functions
Source106:  	write_net_rules
Source107:  	detect_virt

Patch0001:      0001-update-rtc-with-system-clock-when-shutdown.patch
Patch0002:      0002-udev-add-actions-while-rename-netif-failed.patch
Patch0003:      0003-fix-two-VF-virtual-machines-have-same-mac-address.patch
Patch0004:      0004-logind-set-RemoveIPC-to-false-by-default.patch
Patch0005:      0005-rules-add-rule-for-naming-Dell-iDRAC-USB-Virtual-NIC.patch
Patch0006:      0006-unit-don-t-add-Requires-for-tmp.mount.patch
Patch0007:      0007-rules-add-elevator-kernel-command-line-parameter.patch
Patch0008:      0008-rules-add-the-rule-that-adds-elevator-kernel-command.patch
Patch0009:      0009-units-add-Install-section-to-tmp.mount.patch
Patch0010:      0010-Make-systemd-udevd.service-start-after-systemd-remou.patch
Patch0011:      0011-udev-virsh-shutdown-vm.patch
Patch0012:      0012-sd-bus-properly-initialize-containers.patch
Patch0013:      0013-Revert-core-one-step-back-again-for-nspawn-we-actual.patch
Patch0014:      0014-journal-don-t-enable-systemd-journald-audit.socket-b.patch
Patch0015:      0015-systemd-change-time-log-level.patch
Patch0016:      0016-fix-capsh-drop-but-ping-success.patch
Patch0017:      0017-resolved-create-etc-resolv.conf-symlink-at-runtime.patch
%ifarch riscv64
Patch0018:      0018-extend_timeout_for_riscv.patch
%endif

BuildRequires:  gcc, gcc-c++
BuildRequires:  libcap-devel, libmount-devel, pam-devel, libselinux-devel
BuildRequires:  audit-libs-devel, cryptsetup-devel, dbus-devel, libacl-devel
BuildRequires:  gobject-introspection-devel, libblkid-devel, xz-devel, xz
BuildRequires:  lz4-devel, lz4, bzip2-devel, libidn2-devel, libcurl-devel
BuildRequires:  kmod-devel, elfutils-devel, libgcrypt-devel, libgpg-error-devel
BuildRequires:  gnutls-devel, qrencode-devel, libmicrohttpd-devel, libxkbcommon-devel
BuildRequires:  iptables-devel, docbook-style-xsl, pkgconfig, libxslt, gperf
BuildRequires:  gawk, tree, hostname, git, meson >= 0.43, gettext, dbus >= 1.9.18
BuildRequires:  python3-devel, python3-lxml, firewalld-filesystem, libseccomp-devel
BuildRequires:  python3-jinja2
%if 0%{?have_gnu_efi}
BuildRequires:  gnu-efi gnu-efi-devel
%endif

%ifarch %{valgrind_arches}
BuildRequires:  valgrind-devel
%endif
BuildRequires:  util-linux
BuildRequires:  chrpath

Requires:       %{name}-libs = %{version}-%{release}
Requires(post): coreutils
Requires(post): sed
Requires(post): acl
Requires(post): grep
Requires(post): openssl-libs
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd
Recommends:     diffutils
Recommends:     libxkbcommon%{?_isa}
Provides:       /bin/systemctl
Provides:       /sbin/shutdown
Provides:       syslog
Provides:       systemd-units = %{version}-%{release}
Obsoletes:      system-setup-keyboard < 0.9
Provides:       system-setup-keyboard = 0.9
Obsoletes:      systemd-sysv < 206
Obsoletes:      %{name} < 229-5
Provides:       systemd-sysv = 206
Conflicts:      initscripts < 9.56.1
Recommends:     %{name}-help

Provides:       %{name}-rpm-config
Obsoletes:      %{name}-rpm-config < 243

%description
systemd is a system and service manager that runs as PID 1 and starts
the rest of the system. 

%package devel
Summary:        Development headers for systemd
License:        LGPLv2+ and MIT
Requires:       %{name}-libs = %{version}-%{release}
Requires:       %{name}-pam = %{version}-%{release}
Provides:       libudev-devel = %{version}
Provides:       libudev-devel%{_isa} = %{version}
Obsoletes:      libudev-devel < 183

%description devel
Development headers and auxiliary files for developing applications linking
to libudev or libsystemd.

%package libs
Summary:        systemd libraries
License:        LGPLv2+ and MIT
Obsoletes:      libudev < 183
Obsoletes:      systemd < 185-4
Conflicts:      systemd < 185-4
Obsoletes:      systemd-compat-libs < 230
Obsoletes:      nss-myhostname < 0.4
Provides:       nss-myhostname = 0.4
Provides:       nss-myhostname%{_isa} = 0.4
Requires(post): coreutils
Requires(post): sed
Requires(post): grep
Requires(post): /usr/bin/getent

%description libs
Libraries for systemd and udev.

%package udev
Summary: Rule-based device node and kernel event manager
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd
Requires(post): grep
Requires:       kmod >= 18-4
# obsolete parent package so that dnf will install new subpackage on upgrade (#1260394)
Obsoletes:      %{name} < 229-5
Provides:       udev = %{version}
Provides:       udev%{_isa} = %{version}
Obsoletes:      udev < 183
# https://bugzilla.redhat.com/show_bug.cgi?id=1377733#c9
Recommends:     systemd-bootchart
# https://bugzilla.redhat.com/show_bug.cgi?id=1408878
Recommends:     kbd
License:        LGPLv2+

%description udev
This package contains systemd-udev and the rules and hardware database
needed to manage device nodes. This package is necessary on physical
machines and in virtual machines, but not in containers.

%package container
Summary: Tools for containers and VMs
Requires:       %{name}%{?_isa} = %{version}-%{release}
Obsoletes:      %{name} < 229-5
License:        LGPLv2+

%description container
Systemd tools to spawn and manage containers and virtual machines.

This package contains systemd-nspawn, machinectl, systemd-machined,
and systemd-importd.

%package journal-remote
# Name is the same as in Debian
Summary:        Tools to send journal events over the network
Requires:       %{name}%{?_isa} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires:       firewalld
Provides:       %{name}-journal-gateway = %{version}-%{release}
Provides:       %{name}-journal-gateway%{_isa} = %{version}-%{release}
Obsoletes:      %{name}-journal-gateway < 227-7

%description journal-remote
Programs to forward journal entries over the network, using encrypted HTTP,
and to write journal files from serialized journal contents.

%package udev-compat
Summary:       Udev rules compatibility with NetworkManager
Requires:       %{name} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description udev-compat
systemd-udev-compat is a set of udev rules which conflict with NetworkManager.
If users choose to use the network-scripts to manager the network, the package can be used
to do somethings when down or up nics or disk.

%package oomd
Summary:       Systemd oomd feature
Requires:       %{name} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description oomd
Systemd-oomd.service, systemd-oomd - A userspace out-of-memory (OOM) killer

%package resolved
Summary:        Network Name Resolution manager
License:        LGPLv2+
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires(post): systemd
Requires(preun):systemd
Requires(postun):systemd
Requires(pre):  /usr/bin/getent

%description resolved
systemd-resolve is a system service that provides network name resolution to
local applications. It implements a caching and validating DNS/DNSSEC stub
resolver, as well as an LLMNR and MulticastDNS resolver and responder.

%package nspawn
Summary:        Spawn a command or OS in a light-weight container
License:        LGPLv2+
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description nspawn
systemd-nspawn may be used to run a command or OS in a light-weight namespace
container. In many ways it is similar to chroot, but more powerful since it
fully virtualizes the file system hierarchy, as well as the process tree, the
various IPC subsystems and the host and domain name.

%package networkd
Summary:        System daemon that manages network configurations
Requires:       %{name}%{?_isa} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):  /usr/bin/getent
Requires(post): systemd
Requires(preun):systemd
Requires(postun):systemd

%description networkd
systemd-networkd is a system service that manages networks. It detects
and configures network devices as they appear, as well as creating virtual
network devices.

%package timesyncd
Summary:        Network Time Synchronization
License:        LGPLv2+
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires(post): systemd
Requires(preun):systemd
Requires(postun):systemd
Requires(pre):  /usr/bin/getent

%description timesyncd
systemd-timesyncd is a system service that may be used to synchronize
the local system clock with a remote Network Time Protocol (NTP) server.
It also saves the local time to disk every time the clock has been
synchronized and uses this to possibly advance the system realtime clock
on subsequent reboots to ensure it (roughly) monotonically advances even
if the system lacks a battery-buffered RTC chip.

%package pam
Summary:        systemd PAM module
Requires:       %{name} = %{version}-%{release}

%description pam
Systemd PAM module registers the session with systemd-logind.

%package coredump
Summary:        Systemd tools for coredump management
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
%systemd_requires
Provides:       systemd:%{_bindir}/coredumpctl

%description coredump
Systemd tools to store and manage coredumps.

This package contains systemd-coredump, coredumpctl.

%package portable
Summary:        Systemd tools for portable services
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
%systemd_requires

%description portable
Systemd tools to manage portable services. The feature is still
considered experimental so the package might change  or vanish.
Use at own risk.

More information can be found online:

http://0pointer.net/blog/walkthrough-for-portable-services.html
https://systemd.io/PORTABLE_SERVICES

%package userdbd
Summary:        Systemd tools for userdbd services
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
%systemd_requires

%description userdbd
systemd-userdbd is a system service that multiplexes user/group lookups to 
all local services that provide JSON user/group record definitions to the system.
Most of systemd-userdbd's functionality is accessible through the userdbctl(1) command.

%package pstore
Summary:        Systemd tools for pstore services
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
%systemd_requires

%description pstore
systemd-pstore.service is a system service that archives the contents 
of the Linux persistent storage filesystem, pstore, to other storage, 
thus preserving the existing information contained in the pstore, 
and clearing pstore storage for future error events.

%package_help

%prep
%autosetup -n %{name}-%{version} -p1 -Sgit

%build

CONFIGURE_OPTS=(
        -Dsysvinit-path=/etc/rc.d/init.d
        -Drc-local=/etc/rc.d/rc.local
        -Ddev-kvm-mode=0666
        -Dkmod=true
        -Dxkbcommon=true
        -Dblkid=true
        %ifarch riscv64
        -Dseccomp=false
        %else
        -Dseccomp=true
        %endif
        -Dima=true
        -Dselinux=true
        -Dapparmor=false
        -Dpolkit=true
        -Dxz=true
        -Dzlib=true
        -Dbzip2=true
        -Dlz4=true
        -Dpam=true
        -Dacl=true
        -Dsmack=true
        -Dgcrypt=true
        -Daudit=true
        -Delfutils=true
        -Dlibcryptsetup=true
        -Delfutils=true
        -Dqrencode=true
        -Dgnutls=true
        -Dmicrohttpd=true
        -Dlibidn2=true
        -Dlibiptc=true
        -Dlibcurl=true
        -Defi=true
%if 0%{?have_gnu_efi}
        -Dgnu-efi=true
%endif
        -Dtpm=true
        -Dhwdb=true
        -Dsysusers=true
        -Ddefault-kill-user-processes=false
        -Dtests=true
        -Dinstall-tests=false
        -Dtty-gid=5
        -Dusers-gid=100
        -Dnobody-user=nobody
        -Dnobody-group=nobody
        -Dsplit-usr=false
        -Dsplit-bin=true
        -Db_lto=true
        -Db_ndebug=false
        -Dman=true
        -Dversion-tag=v%{version}-%{release}
        -Ddefault-hierarchy=legacy
        -Ddefault-dnssec=no
        # https://bugzilla.redhat.com/show_bug.cgi?id=1867830
        -Ddefault-mdns=no
        -Ddefault-llmnr=resolve
        -Doomd=true
        -Dhtml=false
)

%meson "${CONFIGURE_OPTS[@]}"
%meson_build

%install
%meson_install

# udev links
mkdir -p %{buildroot}/%{_sbindir}
ln -sf ../bin/udevadm %{buildroot}%{_sbindir}/udevadm

# Compatiblity and documentation files
touch %{buildroot}/etc/crypttab
chmod 600 %{buildroot}/etc/crypttab

# /etc/initab
install -Dm0644 -t %{buildroot}/etc/ %{SOURCE5}

# /etc/sysctl.conf compat
install -Dm0644 %{SOURCE6} %{buildroot}/etc/sysctl.conf
ln -s ../sysctl.conf %{buildroot}/etc/sysctl.d/99-sysctl.conf

# Make sure these directories are properly owned
mkdir -p %{buildroot}%{system_unit_dir}/basic.target.wants
mkdir -p %{buildroot}%{system_unit_dir}/default.target.wants
mkdir -p %{buildroot}%{system_unit_dir}/dbus.target.wants
mkdir -p %{buildroot}%{system_unit_dir}/syslog.target.wants
mkdir -p %{buildroot}%{_localstatedir}/run
mkdir -p %{buildroot}%{_localstatedir}/log
touch %{buildroot}%{_localstatedir}/run/utmp
touch %{buildroot}%{_localstatedir}/log/{w,b}tmp

# Make sure the user generators dir exists too
mkdir -p %{buildroot}%{pkgdir}/system-generators
mkdir -p %{buildroot}%{pkgdir}/user-generators

# Create new-style configuration files so that we can ghost-own them
touch %{buildroot}%{_sysconfdir}/hostname
touch %{buildroot}%{_sysconfdir}/vconsole.conf
touch %{buildroot}%{_sysconfdir}/locale.conf
touch %{buildroot}%{_sysconfdir}/machine-id
touch %{buildroot}%{_sysconfdir}/machine-info
touch %{buildroot}%{_sysconfdir}/localtime
mkdir -p %{buildroot}%{_sysconfdir}/X11/xorg.conf.d
touch %{buildroot}%{_sysconfdir}/X11/xorg.conf.d/00-keyboard.conf

# Make sure the shutdown/sleep drop-in dirs exist
mkdir -p %{buildroot}%{pkgdir}/system-shutdown/
mkdir -p %{buildroot}%{pkgdir}/system-sleep/

# Make sure directories in /var exist
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/coredump
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/catalog
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/backlight
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/rfkill
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/linger
mkdir -p %{buildroot}%{_localstatedir}/lib/private
mkdir -p %{buildroot}%{_localstatedir}/log/private
mkdir -p %{buildroot}%{_localstatedir}/cache/private
mkdir -p %{buildroot}%{_localstatedir}/lib/private/systemd/journal-upload
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/timesync
ln -s ../private/systemd/journal-upload %{buildroot}%{_localstatedir}/lib/systemd/journal-upload
mkdir -p %{buildroot}%{_localstatedir}/log/journal
touch %{buildroot}%{_localstatedir}/lib/systemd/catalog/database
touch %{buildroot}%{_sysconfdir}/udev/hwdb.bin
touch %{buildroot}%{_localstatedir}/lib/systemd/random-seed
touch %{buildroot}%{_localstatedir}/lib/systemd/timesync/clock
touch %{buildroot}%{_localstatedir}/lib/private/systemd/journal-upload/state

# Install yum protection fragment
install -Dm0644 %{SOURCE4} %{buildroot}/etc/dnf/protected.d/systemd.conf

install -Dm0644 -t %{buildroot}/usr/lib/firewalld/services/ %{SOURCE7} %{SOURCE8}

# Restore systemd-user pam config from before "removal of Fedora-specific bits"
install -Dm0644 -t %{buildroot}/etc/pam.d/ %{SOURCE12}

# https://bugzilla.redhat.com/show_bug.cgi?id=1378974
install -Dm0644 -t %{buildroot}%{system_unit_dir}/systemd-udev-trigger.service.d/ %{SOURCE10}

# A temporary work-around for https://bugzilla.redhat.com/show_bug.cgi?id=1663040
mkdir -p %{buildroot}%{system_unit_dir}/systemd-hostnamed.service.d/
cat >%{buildroot}%{system_unit_dir}/systemd-hostnamed.service.d/disable-privatedevices.conf <<EOF
[Service]
PrivateDevices=no
EOF

install -Dm0755 -t %{buildroot}%{_prefix}/lib/kernel/install.d/ %{SOURCE11}

install -D -t %{buildroot}%{_systemddir}/ %{SOURCE3}

#sed -i 's|#!/usr/bin/env python3|#!%{__python3}|' %{buildroot}%{_systemddir}/tests/run-unit-tests.py

%find_lang %{name}

# Install rc.local
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/
install -m 0644 %{SOURCE13} %{buildroot}%{_sysconfdir}/rc.d/rc.local
ln -s rc.d/rc.local %{buildroot}%{_sysconfdir}/rc.local

install -m 0644 %{SOURCE100} %{buildroot}/%{_udevrulesdir}/40-openEuler.rules
install -m 0644 %{SOURCE101} %{buildroot}/%{_udevrulesdir}/55-persistent-net-generator.rules
install -m 0644 %{SOURCE102} %{buildroot}/%{_udevrulesdir}/56-net-sriov-names.rules
install -m 0644 %{SOURCE103} %{buildroot}/%{_udevrulesdir}/61-openeuler-persistent-storage.rules
install -m 0755 %{SOURCE104} %{buildroot}/usr/lib/udev
install -m 0755 %{SOURCE105} %{buildroot}/usr/lib/udev
install -m 0755 %{SOURCE106} %{buildroot}/usr/lib/udev
install -m 0755 %{SOURCE107} %{buildroot}/usr/lib/udev

# remove rpath info
for file in $(find %{buildroot}/ -executable -type f -exec file {} ';' | grep "\<ELF\>" | awk -F ':' '{print $1}')
do
        if [ ! -u "$file" ]; then
                if [ -w "$file" ]; then
                        chrpath -d $file
                fi
        fi
done
# add rpath path /usr/lib/systemd in ld.so.conf.d
mkdir -p %{buildroot}%{_sysconfdir}/ld.so.conf.d
echo "/usr/lib/systemd" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/%{name}-%{_arch}.conf

%check
%ninja_test -C %{_vpath_builddir}

#############################################################################################
#  -*- Mode: rpm-spec; indent-tabs-mode: nil -*- */
#  SPDX-License-Identifier: LGPL-2.1+
#
#  This file is part of systemd.
#
#  Copyright 2015 Zbigniew Jędrzejewski-Szmek
#  Copyright 2018 Neal Gompa
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

# The contents of this are an example to be copied into systemd.spec.
#
# Minimum rpm version supported: 4.13.0

%transfiletriggerin -P 900900 -- %{_systemddir}/system /etc/systemd/system
# This script will run after any package is initially installed or
# upgraded. We care about the case where a package is initially
# installed, because other cases are covered by the *un scriptlets,
# so sometimes we will reload needlessly.
if test -d /run/systemd/system; then
  %{_bindir}/systemctl daemon-reload
fi

%transfiletriggerun -- %{_systemddir}/system /etc/systemd/system
# On removal, we need to run daemon-reload after any units have been
# removed. %transfiletriggerpostun would be ideal, but it does not get
# executed for some reason.
# On upgrade, we need to run daemon-reload after any new unit files
# have been installed, but before %postun scripts in packages get
# executed. %transfiletriggerun gets the right list of files
# but it is invoked too early (before changes happen).
# %filetriggerpostun happens at the right time, but it fires for
# every package.
# To execute the reload at the right time, we create a state
# file in %transfiletriggerun and execute the daemon-reload in
# the first %filetriggerpostun.

if test -d "/run/systemd/system"; then
    mkdir -p "%{_localstatedir}/lib/rpm-state/systemd"
    touch "%{_localstatedir}/lib/rpm-state/systemd/needs-reload"
fi

%filetriggerpostun -P 1000100 -- %{_systemddir}/system /etc/systemd/system
if test -f "%{_localstatedir}/lib/rpm-state/systemd/needs-reload"; then
    rm -rf "%{_localstatedir}/lib/rpm-state/systemd"
    %{_bindir}/systemctl daemon-reload
fi

%transfiletriggerin -P 100700 -- /usr/lib/sysusers.d
# This script will process files installed in /usr/lib/sysusers.d to create
# specified users automatically. The priority is set such that it
# will run before the tmpfiles file trigger.
if test -d /run/systemd/system; then
  %{_bindir}/systemd-sysusers || :
fi

%transfiletriggerin -P 100500 -- /usr/lib/tmpfiles.d
# This script will process files installed in /usr/lib/tmpfiles.d to create
# tmpfiles automatically. The priority is set such that it will run
# after the sysusers file trigger, but before any other triggers.
if test -d /run/systemd/system; then
  %{_bindir}/systemd-tmpfiles --create || :
fi

%transfiletriggerin udev -- /usr/lib/udev/hwdb.d
# This script will automatically invoke hwdb update if files have been
# installed or updated in /usr/lib/udev/hwdb.d.
if test -d /run/systemd/system; then
  %{_bindir}/systemd-hwdb update || :
fi

%transfiletriggerin -- %{_systemddir}/catalog
# This script will automatically invoke journal catalog update if files
# have been installed or updated in %{_systemddir}/catalog.
if test -d /run/systemd/system; then
  %{_bindir}/journalctl --update-catalog || :
fi

%transfiletriggerin udev -- /usr/lib/udev/rules.d
# This script will automatically update udev with new rules if files
# have been installed or updated in /usr/lib/udev/rules.d.
if test -e /run/udev/control; then
  %{_bindir}/udevadm control --reload || :
fi

%transfiletriggerin -- /usr/lib/sysctl.d
# This script will automatically apply sysctl rules if files have been
# installed or updated in /usr/lib/sysctl.d.
if test -d /run/systemd/system; then
  %{_systemddir}/systemd-sysctl || :
fi

%transfiletriggerin -- /usr/lib/binfmt.d
# This script will automatically apply binfmt rules if files have been
# installed or updated in /usr/lib/binfmt.d.
if test -d /run/systemd/system; then
  # systemd-binfmt might fail if binfmt_misc kernel module is not loaded
  # during install
  %{_systemddir}/systemd-binfmt || :
fi

%pre
getent group cdrom &>/dev/null || groupadd -r -g 11 cdrom &>/dev/null || :
getent group utmp &>/dev/null || groupadd -r -g 22 utmp &>/dev/null || :
getent group tape &>/dev/null || groupadd -r -g 33 tape &>/dev/null || :
getent group dialout &>/dev/null || groupadd -r -g 18 dialout &>/dev/null || :
getent group input &>/dev/null || groupadd -r input &>/dev/null || :
getent group kvm &>/dev/null || groupadd -r -g 36 kvm &>/dev/null || :
getent group render &>/dev/null || groupadd -r render &>/dev/null || :
getent group systemd-journal &>/dev/null || groupadd -r -g 190 systemd-journal 2>&1 || :

%pre coredump
getent group systemd-coredump &>/dev/null || groupadd -r systemd-coredump 2>&1 || :
getent passwd systemd-coredump &>/dev/null || useradd -r -l -g systemd-coredump -d / -s /sbin/nologin -c "systemd Core Dumper" systemd-coredump &>/dev/null || :

%pre networkd
getent group systemd-network &>/dev/null || groupadd -r -g 192 systemd-network 2>&1 || :
getent passwd systemd-network &>/dev/null || useradd -r -u 192 -l -g systemd-network -d / -s /sbin/nologin -c "systemd Network Management" systemd-network &>/dev/null || :

%pre resolved
getent group systemd-resolve &>/dev/null || groupadd -r -g 193 systemd-resolve 2>&1 || :
getent passwd systemd-resolve &>/dev/null || useradd -r -u 193 -l -g systemd-resolve -d / -s /sbin/nologin -c "systemd Resolver" systemd-resolve &>/dev/null || :

%post
/sbin/ldconfig
systemd-machine-id-setup &>/dev/null || :
systemctl daemon-reexec &>/dev/null || :
journalctl --update-catalog &>/dev/null || :
systemd-tmpfiles --create &>/dev/null || :


# Make sure new journal files will be owned by the "systemd-journal" group
machine_id=$(cat /etc/machine-id 2>/dev/null)
chgrp systemd-journal /{run,var}/log/journal/{,${machine_id}} &>/dev/null || :
chmod g+s /{run,var}/log/journal/{,${machine_id}} &>/dev/null || :

# Apply ACL to the journal directory
setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/ &>/dev/null || :

# We reset the enablement of all services upon initial installation
# https://bugzilla.redhat.com/show_bug.cgi?id=1118740#c23
# This will fix up enablement of any preset services that got installed
# before systemd due to rpm ordering problems:
# https://bugzilla.redhat.com/show_bug.cgi?id=1647172
if [ $1 -eq 1 ] ; then
        echo "DefaultTasksMax=80%" >> /etc/systemd/system.conf
        systemctl preset-all &>/dev/null || :
fi

%postun
/sbin/ldconfig

%post libs
%{?ldconfig}

function mod_nss() {
    if [ -f "$1" ] ; then
        # sed-fu to add myhostname to hosts line
        grep -E -q '^hosts:.* myhostname' "$1" ||
        sed -i.bak -e '
                /^hosts:/ !b
                /\<myhostname\>/ b
                s/[[:blank:]]*$/ myhostname/
                ' "$1" &>/dev/null || :

        # Add nss-systemd to passwd and group
        grep -E -q '^(passwd|group):.* systemd' "$1" ||
        sed -i.bak -r -e '
                s/^(passwd|group):(.*)/\1: \2 systemd/
                ' "$1" &>/dev/null || :
    fi
}

FILE="$(readlink /etc/nsswitch.conf || echo /etc/nsswitch.conf)"
if [ "$FILE" = "/etc/authselect/nsswitch.conf" ] && authselect check &>/dev/null; then
        mod_nss "/etc/authselect/user-nsswitch.conf"
        authselect apply-changes &> /dev/null || :
else
        mod_nss "$FILE"
        # also apply the same changes to user-nsswitch.conf to affect
        # possible future authselect configuration
        mod_nss "/etc/authselect/user-nsswitch.conf"
fi

# check if nobody or nfsnobody is defined
export SYSTEMD_NSS_BYPASS_SYNTHETIC=1
if getent passwd nfsnobody &>/dev/null; then
   test -f /etc/systemd/dont-synthesize-nobody || {
       echo 'Detected system with nfsnobody defined, creating /etc/systemd/dont-synthesize-nobody'
       mkdir -p /etc/systemd || :
       : >/etc/systemd/dont-synthesize-nobody || :
   }
elif getent passwd nobody 2>/dev/null | grep -v 'nobody:[x*]:65534:65534:.*:/:/sbin/nologin' &>/dev/null; then
   test -f /etc/systemd/dont-synthesize-nobody || {
       echo 'Detected system with incompatible nobody defined, creating /etc/systemd/dont-synthesize-nobody'
       mkdir -p /etc/systemd || :
       : >/etc/systemd/dont-synthesize-nobody || :
   }
fi

%{?ldconfig:%postun -p %ldconfig}

%global udev_services systemd-udev{d,-settle,-trigger}.service systemd-udevd-{control,kernel}.socket systemd-timesyncd.service

%preun
if [ $1 -eq 0 ] ; then
        systemctl disable --quiet \
                remote-fs.target \
                getty@.service \
                serial-getty@.service \
                console-getty.service \
                debug-shell.service \
                >/dev/null || :
fi


%preun resolved
if [ $1 -eq 0 ] ; then
        systemctl disable --quiet \
                systemd-resolved.service \
                >/dev/null || :
fi

%preun networkd
if [ $1 -eq 0 ] ; then
        systemctl disable --quiet \
                systemd-networkd.service \
                systemd-networkd-wait-online.service \
                >/dev/null || :
fi

%pre timesyncd
getent group systemd-timesync &>/dev/null || groupadd -r systemd-timesync 2>&1 || :
getent passwd systemd-timesync &>/dev/null || useradd -r -l -g systemd-timesync -d / -s /sbin/nologin -c "systemd Time Synchronization" systemd-timesync &>/dev/null || :

%post timesyncd
# Move old stuff around in /var/lib
mv %{_localstatedir}/lib/random-seed %{_localstatedir}/lib/systemd/random-seed &>/dev/null
if [ -L %{_localstatedir}/lib/systemd/timesync ]; then
    rm %{_localstatedir}/lib/systemd/timesync
    mv %{_localstatedir}/lib/private/systemd/timesync %{_localstatedir}/lib/systemd/timesync
fi
if [ -f %{_localstatedir}/lib/systemd/clock ] ; then
    mkdir -p %{_localstatedir}/lib/systemd/timesync
    mv %{_localstatedir}/lib/systemd/clock %{_localstatedir}/lib/systemd/timesync/.
fi
# devided from post and preun stage of udev that included in macro udev_services
%systemd_post systemd-timesyncd.service

%post udev
# Move old stuff around in /var/lib
mv %{_localstatedir}/lib/backlight %{_localstatedir}/lib/systemd/backlight &>/dev/null

udevadm hwdb --update &>/dev/null
%systemd_post %udev_services
%{_systemddir}/systemd-random-seed save 2>&1

# Replace obsolete keymaps
# https://bugzilla.redhat.com/show_bug.cgi?id=1151958
grep -q -E '^KEYMAP="?fi-latin[19]"?' /etc/vconsole.conf 2>/dev/null &&
    sed -i.rpm.bak -r 's/^KEYMAP="?fi-latin[19]"?/KEYMAP="fi"/' /etc/vconsole.conf || :

if [ -f "/usr/lib/udev/rules.d/50-udev-default.rules" ]; then
     sed -i 's/KERNEL=="kvm", GROUP="kvm", MODE="0666"/KERNEL=="kvm", GROUP="kvm", MODE="0660"/g' /usr/lib/udev/rules.d/50-udev-default.rules
fi
%{_bindir}/systemctl daemon-reload &>/dev/null || :

%preun timesyncd
%systemd_preun systemd-timesyncd.service

%preun udev
%systemd_preun %udev_services

%postun udev
# Only restart systemd-udev, to run the upgraded dameon.
# Others are either oneshot services, or sockets, and restarting them causes issues (#1378974)
%systemd_postun_with_restart systemd-udevd.service

%pre journal-remote
getent group systemd-journal-remote &>/dev/null || groupadd -r systemd-journal-remote 2>&1 || :
getent passwd systemd-journal-remote &>/dev/null || useradd -r -l -g systemd-journal-remote -d %{_localstatedir}/log/journal/remote -s /sbin/nologin -c "Journal Remote" systemd-journal-remote &>/dev/null || :

%post journal-remote
%systemd_post systemd-journal-gatewayd.socket systemd-journal-gatewayd.service
%systemd_post systemd-journal-remote.socket systemd-journal-remote.service
%systemd_post systemd-journal-upload.service
%firewalld_reload

%preun journal-remote
%systemd_preun systemd-journal-gatewayd.socket systemd-journal-gatewayd.service
%systemd_preun systemd-journal-remote.socket systemd-journal-remote.service
%systemd_preun systemd-journal-upload.service
if [ $1 -eq 1 ] ; then
    if [ -f %{_localstatedir}/lib/systemd/journal-upload/state -a ! -L %{_localstatedir}/lib/systemd/journal-upload ] ; then
        mkdir -p %{_localstatedir}/lib/private/systemd/journal-upload
        mv %{_localstatedir}/lib/systemd/journal-upload/state %{_localstatedir}/lib/private/systemd/journal-upload/.
        rmdir %{_localstatedir}/lib/systemd/journal-upload || :
    fi
fi

%postun journal-remote
%systemd_postun_with_restart systemd-journal-gatewayd.service
%systemd_postun_with_restart systemd-journal-remote.service
%systemd_postun_with_restart systemd-journal-upload.service
%firewalld_reload

%preun portable
%systemd_preun systemd-portabled.service

%preun userdbd
%systemd_preun systemd-userdbd.service systemd-userdbd.socket

%preun pstore
%systemd_preun systemd-pstore.service

%files -f %{name}.lang
%doc %{_pkgdocdir}
%exclude %{_pkgdocdir}/LICENSE.*
%license LICENSE.GPL2 LICENSE.LGPL2.1
%ghost %dir %attr(0755,-,-) /etc/systemd/system/basic.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/bluetooth.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/default.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/getty.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/graphical.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/local-fs.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/machines.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/multi-user.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/network-online.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/printer.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/remote-fs.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/sockets.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/sysinit.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/system-update.target.wants
%ghost %dir %attr(0755,-,-) /etc/systemd/system/timers.target.wants
%ghost %dir %attr(0755,-,-) /var/lib/rpm-state/systemd

%ghost %dir /var/log/journal
%ghost %attr(0664,root,utmp) /var/log/wtmp
/var/log/README
%ghost %attr(0600,root,utmp) /var/log/btmp
%ghost %attr(0700,root,root) %dir /var/log/private
%ghost %attr(0664,root,utmp) /var/run/utmp
%ghost %attr(0700,root,root) %dir /var/cache/private
%ghost %attr(0700,root,root) %dir /var/lib/private
%dir /var/lib/systemd
%dir /var/lib/systemd/catalog
%ghost %dir /var/lib/systemd/linger
%ghost /var/lib/systemd/catalog/database
%ghost %dir /var/lib/private/systemd
/usr/sbin/reboot
/usr/sbin/halt
/usr/sbin/telinit
/usr/sbin/init
/usr/sbin/runlevel
/usr/sbin/poweroff
/usr/sbin/shutdown
%dir /usr/share/systemd
%dir /usr/share/factory
%dir /usr/share/factory/etc
/usr/share/factory/etc/issue
/usr/share/factory/etc/nsswitch.conf
%dir /usr/share/factory/etc/pam.d
/usr/share/factory/etc/pam.d/other
/usr/share/factory/etc/pam.d/system-auth
/usr/share/systemd/language-fallback-map
/usr/share/systemd/kbd-model-map
/usr/share/bash-completion/completions/localectl
/usr/share/bash-completion/completions/systemd-path
/usr/share/bash-completion/completions/portablectl
/usr/share/bash-completion/completions/systemd-run
/usr/share/bash-completion/completions/systemd-cat
/usr/share/bash-completion/completions/coredumpctl
/usr/share/bash-completion/completions/systemd-delta
/usr/share/bash-completion/completions/systemd-cgls
/usr/share/bash-completion/completions/systemd-detect-virt
/usr/share/bash-completion/completions/hostnamectl
/usr/share/bash-completion/completions/systemd-cgtop
/usr/share/bash-completion/completions/systemctl
/usr/share/bash-completion/completions/journalctl
/usr/share/bash-completion/completions/systemd-analyze
/usr/share/bash-completion/completions/loginctl
/usr/share/bash-completion/completions/timedatectl
/usr/share/bash-completion/completions/busctl
/usr/share/zsh/site-functions/_loginctl
/usr/share/zsh/site-functions/_systemd-inhibit
/usr/share/zsh/site-functions/_journalctl
/usr/share/zsh/site-functions/_systemd-delta
/usr/share/zsh/site-functions/_systemd-tmpfiles
/usr/share/zsh/site-functions/_systemctl
/usr/share/zsh/site-functions/_systemd-run
/usr/share/zsh/site-functions/_sd_outputmodes
/usr/share/zsh/site-functions/_sd_unit_files
/usr/share/zsh/site-functions/_sd_machines
/usr/share/zsh/site-functions/_coredumpctl
/usr/share/zsh/site-functions/_timedatectl
/usr/share/zsh/site-functions/_busctl
/usr/share/zsh/site-functions/_systemd
/usr/share/zsh/site-functions/_systemd-analyze
/usr/share/zsh/site-functions/_hostnamectl
/usr/share/zsh/site-functions/_sd_hosts_or_user_at_host
/usr/share/zsh/site-functions/_localectl
/usr/share/dbus-1/system-services/org.freedesktop.portable1.service
/usr/share/dbus-1/system-services/org.freedesktop.login1.service
/usr/share/dbus-1/system-services/org.freedesktop.locale1.service
/usr/share/dbus-1/system-services/org.freedesktop.hostname1.service
/usr/share/dbus-1/system-services/org.freedesktop.timedate1.service
/usr/share/dbus-1/system.d/org.freedesktop.timedate1.conf
/usr/share/dbus-1/system.d/org.freedesktop.hostname1.conf
/usr/share/dbus-1/system.d/org.freedesktop.login1.conf
/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf
/usr/share/dbus-1/system.d/org.freedesktop.locale1.conf
/usr/share/dbus-1/system.d/org.freedesktop.portable1.conf
/usr/share/pkgconfig/systemd.pc
/usr/share/pkgconfig/udev.pc
/usr/share/polkit-1/actions/org.freedesktop.hostname1.policy
/usr/share/polkit-1/actions/org.freedesktop.portable1.policy
/usr/share/polkit-1/actions/org.freedesktop.timedate1.policy
/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy
/usr/share/polkit-1/actions/org.freedesktop.login1.policy
/usr/share/polkit-1/actions/org.freedesktop.locale1.policy
/usr/bin/systemd-machine-id-setup
/usr/bin/localectl
/usr/bin/systemd-path
/usr/bin/systemd-run
/usr/bin/systemd-firstboot
/usr/bin/systemd-escape
/usr/bin/systemd-tmpfiles
/usr/bin/systemd-cat
/usr/bin/systemd-inhibit
/usr/bin/systemd-ask-password
/usr/bin/systemd-notify
/usr/bin/systemd-delta
/usr/bin/systemd-cgls
/usr/bin/systemd-stdio-bridge
/usr/bin/systemd-detect-virt
/usr/bin/systemd-socket-activate
/usr/bin/hostnamectl
/usr/bin/systemd-mount
/usr/bin/systemd-umount
/usr/bin/systemd-cgtop
/usr/bin/systemd-id128
/usr/bin/systemctl
/usr/bin/journalctl
/usr/bin/systemd-analyze
/usr/bin/systemd-dissect
/usr/bin/loginctl
/usr/bin/timedatectl
/usr/bin/systemd-sysusers
/usr/bin/systemd-tty-ask-password-agent
/usr/bin/busctl
%dir /usr/lib/environment.d
%dir /usr/lib/binfmt.d
%dir /usr/lib/tmpfiles.d
%dir /usr/lib/sysctl.d
%dir /usr/lib/systemd
%dir /usr/lib/sysusers.d
/usr/lib/pam.d/systemd-user
/usr/lib/sysusers.d/systemd.conf
/usr/lib/sysusers.d/basic.conf
/usr/lib/systemd/system/hwclock-save.service
/usr/lib/systemd/system/initrd-usr-fs.target
/usr/lib/systemd/system/sysinit.target.wants/hwclock-save.service
%{_systemddir}/systemd-update-done
%{_systemddir}/systemd-update-utmp
%{_systemddir}/systemd-initctl
%{_systemddir}/purge-nobody-user
%dir %{_systemddir}/system-shutdown
%dir %{_systemddir}/catalog
%dir %{_systemddir}/network
%{_systemddir}/systemd-cgroups-agent
%{_systemddir}/systemd-sulogin-shell
%{_systemddir}/systemd-boot-check-no-failures
%{_systemddir}/systemd-user-sessions
%{_systemddir}/systemd-sysctl
%{_systemddir}/systemd-socket-proxyd
%{_systemddir}/systemd-ac-power
%{_systemddir}/systemd-hostnamed
%{_systemddir}/systemd-bless-boot
%{_systemddir}/systemd-localed
%dir %{_systemddir}/user
%{_systemddir}/systemd-volatile-root
%{_systemddir}/systemd-journald
%{_systemddir}/systemd-user-runtime-dir
%{_systemddir}/systemd-logind
%dir %{_systemddir}/system-preset
%dir %{_systemddir}/user-environment-generators
%{_systemddir}/systemd-shutdown
%{_systemddir}/libsystemd-shared*.so
%{_systemddir}/systemd-reply-password
%dir %{_systemddir}/system-generators
%dir %{_systemddir}/system
%{_systemddir}/systemd-export
%{_systemddir}/systemd-fsck
%{_systemddir}/systemd-timedated
%dir %{_systemddir}/user-generators
%{_systemddir}/systemd
%dir %{_systemddir}/user-preset
%{_systemddir}/systemd-veritysetup
%{_systemddir}/systemd-network-generator
%{_systemddir}/systemd-binfmt
%{_systemddir}/user-preset/90-systemd.preset
%{_unitdir}/systemd-networkd.socket
%{_unitdir}/systemd-binfmt.service
%{_unitdir}/systemd-machine-id-commit.service
%dir %{_unitdir}/basic.target.wants
%{_unitdir}/ctrl-alt-del.target
%{_unitdir}/systemd-tmpfiles-setup.service
%{_unitdir}/rpcbind.target
%{_unitdir}/systemd-update-done.service
%{_unitdir}/dev-hugepages.mount
%{_unitdir}/systemd-firstboot.service
%dir %{_unitdir}/sockets.target.wants
%dir %{_unitdir}/dbus.target.wants
%{_unitdir}/network.target
%{_unitdir}/system-update-pre.target
%{_unitdir}/shutdown.target
%{_unitdir}/proc-sys-fs-binfmt_misc.automount
%{_unitdir}/syslog.socket
%{_unitdir}/systemd-localed.service
%{_unitdir}/systemd-ask-password-console.service
%{_unitdir}/exit.target
%{_unitdir}/systemd-ask-password-console.path
%{_unitdir}/systemd-logind.service
%{_unitdir}/graphical.target
%{_unitdir}/systemd-initctl.service
%{_unitdir}/multi-user.target
%{_unitdir}/swap.target
%{_unitdir}/sys-kernel-debug.mount
%{_unitdir}/systemd-tmpfiles-clean.service
%{_unitdir}/basic.target
%{_unitdir}/remote-fs-pre.target
%{_unitdir}/systemd-journald-audit.socket
%{_unitdir}/getty@.service
%{_unitdir}/sigpwr.target
%dir %{_unitdir}/runlevel3.target.wants
%{_unitdir}/reboot.target
%{_unitdir}/systemd-boot-system-token.service
%{_unitdir}/systemd-user-sessions.service
%{_unitdir}/systemd-journald-dev-log.socket
%{_unitdir}/systemd-journald.socket
%{_unitdir}/time-set.target
%{_unitdir}/getty.target
%{_unitdir}/systemd-kexec.service
%{_unitdir}/remote-fs.target
%{_unitdir}/systemd-ask-password-wall.service
%{_unitdir}/poweroff.target
%{_unitdir}/runlevel2.target
%dir %{_unitdir}/runlevel5.target.wants
%{_unitdir}/initrd-fs.target
%{_unitdir}/runlevel6.target
%{_unitdir}/systemd-journal-flush.service
%{_unitdir}/initrd-cleanup.service
%{_unitdir}/systemd-timedated.service
%{_unitdir}/user-runtime-dir@.service
%{_unitdir}/nss-lookup.target
%{_unitdir}/tmp.mount
%dir %{_unitdir}/systemd-hostnamed.service.d
%{_unitdir}/timers.target
%{_unitdir}/systemd-fsck@.service
%{_unitdir}/printer.target
%{_unitdir}/systemd-reboot.service
%{_unitdir}/systemd-volatile-root.service
%dir %{_unitdir}/multi-user.target.wants
%{_unitdir}/sound.target
%{_unitdir}/kexec.target
%{_unitdir}/initrd-root-fs.target
%{_unitdir}/systemd-update-utmp.service
%dir %{_unitdir}/rescue.target.wants
%{_unitdir}/bluetooth.target
%{_unitdir}/systemd-ask-password-wall.path
%{_unitdir}/emergency.service
%{_unitdir}/network-pre.target
%{_unitdir}/rescue.service
%{_unitdir}/systemd-bless-boot.service
%{_unitdir}/sys-kernel-config.mount
%{_unitdir}/systemd-journald.service
%dir %{_unitdir}/runlevel2.target.wants
%dir %{_unitdir}/syslog.target.wants
%{_unitdir}/console-getty.service
%dir %{_unitdir}/timers.target.wants
%{_unitdir}/systemd-sysusers.service
%dir %{_unitdir}/runlevel4.target.wants
%dir %{_unitdir}/graphical.target.wants
%{_unitdir}/systemd-fsck-root.service
%{_unitdir}/dbus-org.freedesktop.login1.service
%{_unitdir}/systemd-update-utmp-runlevel.service
%{_unitdir}/network-online.target
%{_unitdir}/systemd-initctl.socket
%{_unitdir}/time-sync.target
%{_unitdir}/runlevel5.target
%{_unitdir}/paths.target
%dir %{_unitdir}/runlevel1.target.wants
%{_unitdir}/systemd-exit.service
%{_unitdir}/rescue.target
%{_unitdir}/umount.target
%{_unitdir}/initrd-switch-root.service
%{_unitdir}/initrd.target
%{_unitdir}/ldconfig.service
%{_unitdir}/initrd-root-device.target
%{_unitdir}/default.target
%{_unitdir}/boot-complete.target
%dir %{_unitdir}/sysinit.target.wants
%{_unitdir}/systemd-tmpfiles-clean.timer
%{_unitdir}/user@.service
%{_unitdir}/final.target
%{_unitdir}/sys-fs-fuse-connections.mount
%{_unitdir}/getty-pre.target
%{_unitdir}/runlevel4.target
%{_unitdir}/serial-getty@.service
%{_unitdir}/sysinit.target
%{_unitdir}/rc-local.service
%{_unitdir}/debug-shell.service
%{_unitdir}/dev-mqueue.mount
%{_unitdir}/emergency.target
%{_unitdir}/dbus-org.freedesktop.timedate1.service
%{_unitdir}/runlevel1.target
%dir %{_unitdir}/remote-fs.target.wants
%{_unitdir}/dbus-org.freedesktop.hostname1.service
%{_unitdir}/runlevel0.target
%{_unitdir}/user.slice
%{_unitdir}/systemd-journal-catalog-update.service
%{_unitdir}/local-fs-pre.target
%{_unitdir}/systemd-halt.service
%{_unitdir}/container-getty@.service
%{_unitdir}/slices.target
%{_unitdir}/systemd-network-generator.service
%{_unitdir}/autovt@.service
%dir %{_unitdir}/user-.slice.d
%{_unitdir}/systemd-boot-check-no-failures.service
%{_unitdir}/halt.target
%{_unitdir}/system-update-cleanup.service
%dir %{_unitdir}/local-fs.target.wants
%{_unitdir}/proc-sys-fs-binfmt_misc.mount
%{_unitdir}/dbus-org.freedesktop.locale1.service
%{_unitdir}/initrd-switch-root.target
%{_unitdir}/initrd-parse-etc.service
%{_unitdir}/nss-user-lookup.target
%{_unitdir}/sockets.target
%dir %{_unitdir}/default.target.wants
%{_unitdir}/systemd-poweroff.service
%{_unitdir}/systemd-sysctl.service
%{_unitdir}/runlevel3.target
%{_unitdir}/local-fs.target
%{_unitdir}/smartcard.target
%{_unitdir}/systemd-hostnamed.service
%{_unitdir}/system-update.target
%{_unitdir}/local-fs.target.wants/tmp.mount
%{_unitdir}/user-.slice.d/10-defaults.conf
%{_unitdir}/sysinit.target.wants/systemd-binfmt.service
%{_unitdir}/sysinit.target.wants/systemd-machine-id-commit.service
%{_unitdir}/sysinit.target.wants/systemd-tmpfiles-setup.service
%{_unitdir}/sysinit.target.wants/systemd-update-done.service
%{_unitdir}/sysinit.target.wants/dev-hugepages.mount
%{_unitdir}/sysinit.target.wants/systemd-firstboot.service
%{_unitdir}/sysinit.target.wants/proc-sys-fs-binfmt_misc.automount
%{_unitdir}/sysinit.target.wants/systemd-ask-password-console.path
%{_unitdir}/sysinit.target.wants/sys-kernel-debug.mount
%{_unitdir}/sysinit.target.wants/systemd-boot-system-token.service
%{_unitdir}/sysinit.target.wants/systemd-journal-flush.service
%{_unitdir}/sysinit.target.wants/systemd-update-utmp.service
%{_unitdir}/sysinit.target.wants/sys-kernel-config.mount
%{_unitdir}/sysinit.target.wants/systemd-journald.service
%{_unitdir}/sysinit.target.wants/systemd-sysusers.service
%{_unitdir}/sysinit.target.wants/ldconfig.service
%{_unitdir}/sysinit.target.wants/sys-fs-fuse-connections.mount
%{_unitdir}/sysinit.target.wants/dev-mqueue.mount
%{_unitdir}/sysinit.target.wants/systemd-journal-catalog-update.service
%{_unitdir}/sysinit.target.wants/systemd-sysctl.service
%{_unitdir}/graphical.target.wants/systemd-update-utmp-runlevel.service
%{_unitdir}/timers.target.wants/systemd-tmpfiles-clean.timer
%{_unitdir}/rescue.target.wants/systemd-update-utmp-runlevel.service
%{_unitdir}/multi-user.target.wants/systemd-logind.service
%{_unitdir}/multi-user.target.wants/systemd-user-sessions.service
%{_unitdir}/multi-user.target.wants/getty.target
%{_unitdir}/multi-user.target.wants/systemd-ask-password-wall.path
%{_unitdir}/multi-user.target.wants/systemd-update-utmp-runlevel.service
%{_unitdir}/systemd-hostnamed.service.d/disable-privatedevices.conf
%{_unitdir}/sockets.target.wants/systemd-journald-dev-log.socket
%{_unitdir}/sockets.target.wants/systemd-journald.socket
%{_unitdir}/sockets.target.wants/systemd-initctl.socket
%{_unitdir}/blockdev@.target
%{_unitdir}/sys-kernel-tracing.mount
%{_unitdir}/sysinit.target.wants/sys-kernel-tracing.mount
%{_unitdir}/system-systemd\x2dcryptsetup.slice
%{_unitdir}/systemd-journald-varlink@.socket
%{_unitdir}/systemd-journald@.service
%{_unitdir}/systemd-journald@.socket
%{_unitdir}/usb-gadget.target
%{_unitdir}/modprobe@.service
%{_systemddir}/system-generators/systemd-fstab-generator
%{_systemddir}/system-generators/systemd-sysv-generator
%{_systemddir}/system-generators/systemd-rc-local-generator
%{_systemddir}/system-generators/systemd-bless-boot-generator
%{_systemddir}/system-generators/systemd-debug-generator
%{_systemddir}/system-generators/systemd-veritysetup-generator
%{_systemddir}/system-generators/systemd-run-generator
%{_systemddir}/system-generators/systemd-system-update-generator
%{_systemddir}/system-generators/systemd-getty-generator
%{_systemddir}/user-environment-generators/30-systemd-environment-d-generator
%{_systemddir}/system-preset/90-systemd.preset
%{_userunitdir}/systemd-tmpfiles-setup.service
%{_userunitdir}/graphical-session.target
%{_userunitdir}/shutdown.target
%{_userunitdir}/exit.target
%{_userunitdir}/systemd-tmpfiles-clean.service
%{_userunitdir}/basic.target
%{_userunitdir}/timers.target
%{_userunitdir}/printer.target
%{_userunitdir}/sound.target
%{_userunitdir}/bluetooth.target
%{_userunitdir}/graphical-session-pre.target
%{_userunitdir}/paths.target
%{_userunitdir}/systemd-exit.service
%{_userunitdir}/default.target
%{_userunitdir}/systemd-tmpfiles-clean.timer
%{_userunitdir}/sockets.target
%{_userunitdir}/smartcard.target
%{_systemddir}/network/80-wifi-adhoc.network
%{_systemddir}/network/80-wifi-ap.network.example
%{_systemddir}/network/80-wifi-station.network.example
%{_systemddir}/catalog/systemd.fr.catalog
%{_systemddir}/catalog/systemd.be.catalog
%{_systemddir}/catalog/systemd.bg.catalog
%{_systemddir}/catalog/systemd.de.catalog
%{_systemddir}/catalog/systemd.pt_BR.catalog
%{_systemddir}/catalog/systemd.it.catalog
%{_systemddir}/catalog/systemd.be@latin.catalog
%{_systemddir}/catalog/systemd.pl.catalog
%{_systemddir}/catalog/systemd.zh_CN.catalog
%{_systemddir}/catalog/systemd.zh_TW.catalog
%{_systemddir}/catalog/systemd.ru.catalog
%{_systemddir}/catalog/systemd.catalog
%{_systemddir}/systemd-xdg-autostart-condition
%{_systemddir}/user-generators/systemd-xdg-autostart-generator
%{_systemddir}/user/xdg-desktop-autostart.target
/usr/lib/sysctl.d/50-default.conf
/usr/lib/sysctl.d/50-pid-max.conf
/usr/lib/tmpfiles.d/systemd-tmp.conf
/usr/lib/tmpfiles.d/systemd-nologin.conf
/usr/lib/tmpfiles.d/systemd.conf
/usr/lib/tmpfiles.d/journal-nocow.conf
/usr/lib/tmpfiles.d/x11.conf
/usr/lib/tmpfiles.d/tmp.conf
/usr/lib/tmpfiles.d/home.conf
/usr/lib/tmpfiles.d/etc.conf
/usr/lib/tmpfiles.d/legacy.conf
/usr/lib/tmpfiles.d/static-nodes-permissions.conf
/usr/lib/tmpfiles.d/var.conf
/usr/lib/environment.d/99-environment.conf
%ghost %config(noreplace) /etc/localtime
%dir /etc/rc.d
%dir /etc/binfmt.d
%dir /etc/tmpfiles.d
%dir /etc/sysctl.d
%ghost %config(noreplace) /etc/locale.conf
%config(noreplace) /etc/sysctl.conf
%ghost %config(noreplace) /etc/crypttab
%dir /etc/systemd
/etc/inittab
%ghost %config(noreplace) /etc/machine-info
%ghost %config(noreplace) /etc/machine-id
%ghost %config(noreplace) /etc/hostname
%config(noreplace) /etc/systemd/user.conf
%dir /etc/systemd/user
%config(noreplace) /etc/systemd/logind.conf
%config(noreplace) /etc/systemd/journald.conf
%dir /etc/systemd/system
%config(noreplace) /etc/systemd/system.conf
%ghost %config(noreplace) /etc/X11/xorg.conf.d/00-keyboard.conf
%config(noreplace) /etc/X11/xinit/xinitrc.d/50-systemd-user.sh
%config(noreplace) /etc/pam.d/systemd-user
%config(noreplace) /etc/sysctl.d/99-sysctl.conf
%config(noreplace) /etc/dnf/protected.d/systemd.conf
%dir /etc/rc.d/init.d
%config(noreplace) /etc/rc.d/rc.local
%config(noreplace) /etc/rc.local
%config(noreplace) /etc/rc.d/init.d/README
%dir /etc/xdg/systemd
%config(noreplace) /etc/xdg/systemd/user
%{_sysconfdir}/ld.so.conf.d/%{name}-%{_arch}.conf

/usr/lib/rpm/macros.d/macros.systemd

/usr/bin/systemd-cryptenroll
/usr/bin/systemd-sysext
/usr/lib/modprobe.d/README
/usr/lib/sysctl.d/README
/usr/lib/systemd/system/first-boot-complete.target
/usr/lib/systemd/system/initrd-root-device.target.wants/remote-cryptsetup.target
/usr/lib/systemd/system/initrd-root-device.target.wants/remote-veritysetup.target
/usr/lib/systemd/system/remote-veritysetup.target
/usr/lib/systemd/system/sysinit.target.wants/veritysetup.target
/usr/lib/systemd/system/systemd-sysext.service
/usr/lib/systemd/system/veritysetup-pre.target
/usr/lib/systemd/system/veritysetup.target
/usr/lib/systemd/user/app.slice
/usr/lib/systemd/user/background.slice
/usr/lib/systemd/user/session.slice
/usr/lib/sysusers.d/README
/usr/lib/tmpfiles.d/README
%ifnarch riscv64
/usr/lib/udev/dmi_memory_id
%endif
/usr/lib/udev/hwdb.d/20-dmi-id.hwdb
/usr/lib/udev/hwdb.d/60-autosuspend-fingerprint-reader.hwdb
/usr/lib/udev/hwdb.d/README
/usr/lib/udev/hwdb.d/60-seat.hwdb
/usr/lib/udev/hwdb.d/80-ieee1394-unit-function.hwdb
/usr/lib/udev/rules.d/81-net-dhcp.rules
%ifnarch riscv64
/usr/lib/udev/rules.d/70-memory.rules
%endif
/usr/lib/udev/rules.d/README
/usr/share/bash-completion/completions/systemd-id128
/usr/share/zsh/site-functions/_systemd-path

%files libs
%{_libdir}/libnss_systemd.so.2
%{_libdir}/libnss_myhostname.so.2
%{_libdir}/libsystemd.so.*
%{_libdir}/libudev.so.*

%files devel
/usr/share/man/man3/*
%dir /usr/include/systemd
/usr/include/libudev.h
/usr/include/systemd/sd-event.h
/usr/include/systemd/_sd-common.h
/usr/include/systemd/sd-bus-vtable.h
/usr/include/systemd/sd-daemon.h
/usr/include/systemd/sd-hwdb.h
/usr/include/systemd/sd-device.h
/usr/include/systemd/sd-messages.h
/usr/include/systemd/sd-journal.h
/usr/include/systemd/sd-bus-protocol.h
/usr/include/systemd/sd-id128.h
/usr/include/systemd/sd-bus.h
/usr/include/systemd/sd-login.h
/usr/include/systemd/sd-path.h
%{_libdir}/libudev.so
%{_libdir}/libsystemd.so
%{_libdir}/pkgconfig/libsystemd.pc
%{_libdir}/pkgconfig/libudev.pc

%files udev
%ghost %dir /var/lib/systemd/backlight
%ghost %dir /var/lib/systemd/rfkill
%ghost /var/lib/systemd/random-seed
/usr/sbin/udevadm
/usr/share/bash-completion/completions/udevadm
/usr/share/bash-completion/completions/bootctl
/usr/share/bash-completion/completions/kernel-install
/usr/share/zsh/site-functions/_bootctl
/usr/share/zsh/site-functions/_udevadm
/usr/share/zsh/site-functions/_kernel-install
/usr/bin/systemd-hwdb
/usr/bin/udevadm
/usr/bin/bootctl
/usr/bin/kernel-install
%dir /usr/lib/modprobe.d
%dir /usr/lib/udev
%dir /usr/lib/kernel
%dir /usr/lib/modules-load.d
%{_systemddir}/systemd-growfs
%{_systemddir}/systemd-modules-load
%dir %{_systemddir}/system-sleep
%{_systemddir}/systemd-makefs
%{_systemddir}/systemd-remount-fs
%{_systemddir}/systemd-backlight
%{_systemddir}/systemd-hibernate-resume
%{_systemddir}/systemd-random-seed
%{_systemddir}/systemd-sleep
%{_systemddir}/systemd-cryptsetup
%{_systemddir}/systemd-udevd
%{_systemddir}/systemd-quotacheck
%{_systemddir}/systemd-rfkill
%{_systemddir}/systemd-vconsole-setup
%{_unitdir}/systemd-udevd.service
%{_unitdir}/initrd-udevadm-cleanup-db.service
%{_unitdir}/systemd-rfkill.socket
%{_unitdir}/systemd-suspend.service
%{_unitdir}/suspend-then-hibernate.target
%{_unitdir}/systemd-modules-load.service
%{_unitdir}/systemd-tmpfiles-setup-dev.service
%{_unitdir}/systemd-vconsole-setup.service
%{_unitdir}/systemd-hibernate.service
%{_unitdir}/systemd-backlight@.service
%dir %{_unitdir}/systemd-udev-trigger.service.d
%{_unitdir}/systemd-random-seed.service
%{_unitdir}/systemd-quotacheck.service
%{_unitdir}/systemd-udevd-control.socket
%{_unitdir}/hibernate.target
%{_unitdir}/systemd-remount-fs.service
%{_unitdir}/suspend.target
%{_unitdir}/systemd-hybrid-sleep.service
%{_unitdir}/systemd-rfkill.service
%{_unitdir}/systemd-suspend-then-hibernate.service
%{_unitdir}/cryptsetup-pre.target
%{_unitdir}/hybrid-sleep.target
%{_unitdir}/quotaon.service
%{_unitdir}/systemd-hwdb-update.service
%{_unitdir}/systemd-hibernate-resume@.service
%{_unitdir}/systemd-udev-settle.service
%{_unitdir}/sleep.target
%{_unitdir}/kmod-static-nodes.service
%{_unitdir}/systemd-udevd-kernel.socket
%{_unitdir}/remote-cryptsetup.target
%{_unitdir}/cryptsetup.target
%{_unitdir}/systemd-udev-trigger.service
%{_unitdir}/sysinit.target.wants/systemd-udevd.service
%{_unitdir}/sysinit.target.wants/systemd-modules-load.service
%{_unitdir}/sysinit.target.wants/systemd-tmpfiles-setup-dev.service
%{_unitdir}/sysinit.target.wants/systemd-random-seed.service
%{_unitdir}/sysinit.target.wants/systemd-hwdb-update.service
%{_unitdir}/sysinit.target.wants/kmod-static-nodes.service
%{_unitdir}/sysinit.target.wants/cryptsetup.target
%{_unitdir}/sysinit.target.wants/systemd-udev-trigger.service
%{_unitdir}/systemd-udev-trigger.service.d/systemd-udev-trigger-no-reload.conf
%{_unitdir}/sockets.target.wants/systemd-udevd-control.socket
%{_unitdir}/sockets.target.wants/systemd-udevd-kernel.socket
%{_systemddir}/system-generators/systemd-cryptsetup-generator
%{_systemddir}/system-generators/systemd-hibernate-resume-generator
%{_systemddir}/system-generators/systemd-gpt-auto-generator
%if 0%{?have_gnu_efi}
%dir %{_systemddir}/boot
%dir %{_systemddir}/boot/efi
%{_systemddir}/boot/efi/systemd-boot%{efi_arch}.efi
%{_systemddir}/boot/efi/linux%{efi_arch}.efi.stub
%{_systemddir}/boot/efi/linux%{efi_arch}.elf.stub
%endif
%{_systemddir}/network/99-default.link
%dir /usr/lib/kernel/install.d
/usr/lib/kernel/install.d/20-grubby.install
/usr/lib/kernel/install.d/00-entry-directory.install
/usr/lib/kernel/install.d/90-loaderentry.install
/usr/lib/kernel/install.d/50-depmod.install
/usr/lib/udev/v4l_id
%dir /usr/lib/udev/rules.d
/usr/lib/udev/ata_id
/usr/lib/udev/cdrom_id
/usr/lib/udev/mtd_probe
/usr/lib/udev/scsi_id
/usr/lib/udev/fido_id
%dir /usr/lib/udev/hwdb.d
%{_udevhwdbdir}/20-bluetooth-vendor-product.hwdb
%{_udevhwdbdir}/70-touchpad.hwdb
%{_udevhwdbdir}/60-evdev.hwdb
%{_udevhwdbdir}/20-net-ifname.hwdb
%{_udevhwdbdir}/20-acpi-vendor.hwdb
%{_udevhwdbdir}/20-usb-classes.hwdb
%{_udevhwdbdir}/20-sdio-vendor-model.hwdb
%{_udevhwdbdir}/60-keyboard.hwdb
%{_udevhwdbdir}/20-pci-vendor-model.hwdb
%{_udevhwdbdir}/20-pci-classes.hwdb
%{_udevhwdbdir}/20-OUI.hwdb
%{_udevhwdbdir}/20-sdio-classes.hwdb
%{_udevhwdbdir}/20-usb-vendor-model.hwdb
%{_udevhwdbdir}/70-pointingstick.hwdb
%{_udevhwdbdir}/20-vmbus-class.hwdb
%{_udevhwdbdir}/70-joystick.hwdb
%{_udevhwdbdir}/60-sensor.hwdb
%{_udevhwdbdir}/70-mouse.hwdb
%{_udevhwdbdir}/60-input-id.hwdb
%{_udevhwdbdir}/60-autosuspend-chromiumos.hwdb
%{_udevhwdbdir}/60-autosuspend.hwdb
%{_udevrulesdir}/60-autosuspend.rules
%{_udevrulesdir}/40-openEuler.rules
%{_udevrulesdir}/40-elevator.rules
%{_udevrulesdir}/73-idrac.rules
%{_udevrulesdir}/60-block.rules
%{_udevrulesdir}/60-input-id.rules
%{_udevrulesdir}/71-seat.rules
%{_udevrulesdir}/73-seat-late.rules
%{_udevrulesdir}/80-drivers.rules
%{_udevrulesdir}/60-cdrom_id.rules
%{_udevrulesdir}/64-btrfs.rules
%{_udevrulesdir}/60-drm.rules
%{_udevrulesdir}/70-mouse.rules
%{_udevrulesdir}/70-touchpad.rules
%{_udevrulesdir}/60-persistent-alsa.rules
%{_udevrulesdir}/75-net-description.rules
%{_udevrulesdir}/60-persistent-v4l.rules
%{_udevrulesdir}/70-joystick.rules
%{_udevrulesdir}/70-power-switch.rules
%{_udevrulesdir}/60-persistent-storage.rules
%{_udevrulesdir}/80-net-setup-link.rules
%{_udevrulesdir}/60-evdev.rules
%{_udevrulesdir}/60-sensor.rules
%{_udevrulesdir}/60-serial.rules
%{_udevrulesdir}/90-vconsole.rules
%{_udevrulesdir}/78-sound-card.rules
%{_udevrulesdir}/70-uaccess.rules
%{_udevrulesdir}/60-persistent-input.rules
%{_udevrulesdir}/75-probe_mtd.rules
%{_udevrulesdir}/99-systemd.rules
%{_udevrulesdir}/60-persistent-storage-tape.rules
%{_udevrulesdir}/50-udev-default.rules
%{_udevrulesdir}/60-fido-id.rules
/usr/lib/modprobe.d/systemd.conf
%ghost %config(noreplace) /etc/vconsole.conf
%dir /etc/udev
%dir /etc/kernel
%dir /etc/modules-load.d
%config(noreplace) /etc/systemd/sleep.conf
%dir /etc/kernel/install.d
%ghost /etc/udev/hwdb.bin
%dir /etc/udev/rules.d
%config(noreplace) /etc/udev/udev.conf
%dir /etc/udev/hwdb.d

%files container
/usr/share/bash-completion/completions/machinectl
/usr/share/zsh/site-functions/_machinectl
/usr/share/dbus-1/system-services/org.freedesktop.import1.service
/usr/share/dbus-1/system-services/org.freedesktop.machine1.service
/usr/share/dbus-1/services/org.freedesktop.systemd1.service
/usr/share/dbus-1/system-services/org.freedesktop.systemd1.service
/usr/share/dbus-1/system.d/org.freedesktop.import1.conf
/usr/share/dbus-1/system.d/org.freedesktop.machine1.conf
/usr/share/polkit-1/actions/org.freedesktop.import1.policy
/usr/share/polkit-1/actions/org.freedesktop.machine1.policy
%{_libdir}/libnss_mymachines.so.2
/usr/bin/machinectl
%{_systemddir}/systemd-import
%{_systemddir}/systemd-machined
%{_systemddir}/systemd-importd
%{_systemddir}/systemd-import-fs
%{_systemddir}/systemd-pull
%{_systemddir}/import-pubring.gpg
%{_unitdir}/systemd-machined.service
%{_unitdir}/dbus-org.freedesktop.import1.service
%{_unitdir}/var-lib-machines.mount
%{_unitdir}/systemd-importd.service
%{_unitdir}/dbus-org.freedesktop.machine1.service
%{_unitdir}/machine.slice
%{_unitdir}/machines.target
%dir %{_unitdir}/machines.target.wants
%{_unitdir}/machines.target.wants/var-lib-machines.mount
%{_unitdir}/remote-fs.target.wants/var-lib-machines.mount
%{_systemddir}/network/80-vm-vt.network

%files journal-remote
%ghost %dir /var/log/journal/remote
%ghost /var/lib/systemd/journal-upload
%ghost %dir /var/lib/private/systemd/journal-upload
%ghost /var/lib/private/systemd/journal-upload/state
%dir /usr/share/systemd/gatewayd
/usr/share/systemd/gatewayd/browse.html
/usr/lib/sysusers.d/systemd-remote.conf
%{_systemddir}/systemd-journal-upload
%{_systemddir}/systemd-journal-gatewayd
%{_systemddir}/systemd-journal-remote
%{_unitdir}/systemd-journal-upload.service
%{_unitdir}/systemd-journal-gatewayd.service
%{_unitdir}/systemd-journal-gatewayd.socket
%{_unitdir}/systemd-journal-remote.socket
%{_unitdir}/systemd-journal-remote.service
/usr/lib/firewalld/services/systemd-journal-remote.xml
/usr/lib/firewalld/services/systemd-journal-gatewayd.xml
%config(noreplace) /etc/systemd/journal-remote.conf
%config(noreplace) /etc/systemd/journal-upload.conf

%files udev-compat
%{_udevrulesdir}/55-persistent-net-generator.rules
%{_udevrulesdir}/56-net-sriov-names.rules
%{_udevrulesdir}/61-openeuler-persistent-storage.rules
/usr/lib/udev/rule_generator.functions
/usr/lib/udev/write_net_rules
/usr/lib/udev/net-set-sriov-names
/usr/lib/udev/detect_virt

%files oomd
/etc/systemd/oomd.conf
/usr/bin/oomctl
/usr/lib/systemd/system/systemd-oomd.service
/usr/lib/systemd/system/dbus-org.freedesktop.oom1.service
/usr/lib/systemd/systemd-oomd
/usr/share/dbus-1/system-services/org.freedesktop.oom1.service
/usr/share/dbus-1/system.d/org.freedesktop.oom1.conf

%files help
/usr/share/man/*/*
%exclude /usr/share/man/man3/*

%files resolved
/usr/sbin/resolvconf
/usr/bin/resolvectl
/usr/share/bash-completion/completions/resolvectl
/usr/share/zsh/site-functions/_resolvectl
/usr/share/bash-completion/completions/systemd-resolve
/usr/share/dbus-1/system-services/org.freedesktop.resolve1.service
/usr/share/dbus-1/system.d/org.freedesktop.resolve1.conf
/usr/share/polkit-1/actions/org.freedesktop.resolve1.policy
/usr/bin/systemd-resolve
%{_systemddir}/resolv.conf
%{_systemddir}/systemd-resolved
%config(noreplace) /etc/systemd/resolved.conf
%{_libdir}/libnss_resolve.so.2
%{_unitdir}/systemd-resolved.service

%files nspawn
/usr/share/bash-completion/completions/systemd-nspawn
/usr/share/zsh/site-functions/_systemd-nspawn
/usr/bin/systemd-nspawn
%{_unitdir}/systemd-nspawn@.service
/usr/lib/tmpfiles.d/systemd-nspawn.conf

%files networkd
/usr/share/bash-completion/completions/networkctl
/usr/share/zsh/site-functions/_networkctl
/usr/share/dbus-1/system-services/org.freedesktop.network1.service
/usr/share/dbus-1/system.d/org.freedesktop.network1.conf
/usr/share/polkit-1/actions/org.freedesktop.network1.policy
/usr/share/polkit-1/rules.d/systemd-networkd.rules
/usr/bin/networkctl
%{_systemddir}/systemd-networkd-wait-online
%{_systemddir}/systemd-networkd
%{_unitdir}/systemd-networkd.socket
%{_unitdir}/systemd-networkd-wait-online.service
%{_unitdir}/systemd-networkd.service
%{_systemddir}/network/80-container-host0.network
%dir /etc/systemd/network
%config(noreplace) /etc/systemd/networkd.conf
%{_systemddir}/network/80-container-vz.network
%{_systemddir}/network/80-container-ve.network

%files timesyncd
%dir %{_systemddir}/ntp-units.d
%{_systemddir}/systemd-time-wait-sync
%{_unitdir}/systemd-time-wait-sync.service
%ghost %dir /var/lib/systemd/timesync
%ghost /var/lib/systemd/timesync/clock
/usr/share/dbus-1/system-services/org.freedesktop.timesync1.service
/usr/share/dbus-1/system.d/org.freedesktop.timesync1.conf
%{_systemddir}/systemd-timesyncd
%{_unitdir}/systemd-timesyncd.service
%{_systemddir}/ntp-units.d/80-systemd-timesync.list
%config(noreplace) /etc/systemd/timesyncd.conf

%files pam
%{_libdir}/security/pam_systemd.so

%files coredump
%defattr(-,root,root)
%{_bindir}/coredumpctl
%{_prefix}/lib/systemd/systemd-coredump
%{_unitdir}/systemd-coredump*
%{_unitdir}/sockets.target.wants/systemd-coredump.socket
%{_sysctldir}/50-coredump.conf
%config(noreplace) %{_sysconfdir}/systemd/coredump.conf
%dir %{_localstatedir}/lib/systemd/coredump

%files portable
%defattr(-,root,root)
%{_bindir}/portablectl
%{_prefix}/lib/systemd/systemd-portabled
%{_prefix}/lib/systemd/portable
%{_unitdir}/systemd-portabled.service
%{_unitdir}/dbus-org.freedesktop.portable1.service
%{_tmpfilesdir}/portables.conf

%files pstore
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/systemd/pstore.conf
%{_prefix}/lib/systemd/systemd-pstore
%{_unitdir}/systemd-pstore.service
%{_tmpfilesdir}/systemd-pstore.conf

%files userdbd
%defattr(-,root,root)
%{_bindir}/userdbctl
%{_prefix}/lib/systemd/systemd-userwork
%{_prefix}/lib/systemd/systemd-userdbd
%{_unitdir}/systemd-userdbd.service
%{_unitdir}/systemd-userdbd.socket

%changelog
* Fri Dec 31 2021 lvxiaoqian <xiaoqian@nj.iscas.ac.cn> - 249-3
- increase test timeout for riscv
  update configure flag for riscv
  there is no dmi_memory_id and 70-memory.rules created for riscv, these two files are created for x86, x86_64, aarch64, arm, ia64, mips

+* Tue Dec 27 2021 yangmingtai <yangmingtai@huawei.com> - 249-2
+- delete useless Provides and Obsoletes

* Wed Dec 8 2021 yangmingtai <yangmingtai@huawei.com> - 249-1
- systemd update to v249

* Thu Sep 16 2021 ExtinctFire <shenyining_00@126.com> - 248-13
- core: fix free undefined pointer when strdup failed in the first loop

* Mon Sep 6 2021 yangmingtai <yangmingtai@huawei.com> - 248-12
- move postun to correct position

* Sat Sep 4 2021 yangmingtai <yangmingtai@huawei.com> - 248-11
- systemd delete rpath

* Mon Aug 30 2021 yangmingtai <yangmingtai@huawei.com> - 248-10
- enable some patches and delete unused patches

* Thu Aug 26 2021 xujing <xujing99@huawei.com> - 248-9
- enable some patches to fix bugs

* Mon Aug 16 2021 yangmingtai <yangmingtai@huawei.com> - 248-8
- udev: exec daemon-reload after installation

* Thu Jun 03 2021 yangmingtai <yangmingtai@huawei.com> - 248-7
- fix CVE-2021-33910

* Thu Jul 22 2021 shenyangyang <shenyangyang4@huawei.com> - 248-6
- change requires to openssl-libs as post scripts systemctl requires libssl.so.1.1

* Mon May 31 2021 hexiaowen<hexiaowen@huawei.com> - 248-5
- fix typo

* Wed May 19 2021 fangxiuning <fangxiuning@huawei.com> - 248-4
- journald: enforce longer line length limit during "setup" phase of stream protocol

* Fri Apr 30 2021 hexiaowen <hexiaowen@huawei.com> - 248-3
- delete unused rebase-patch

* Fri Apr 30 2021 hexiaowen <hexiaowen@huawei.com> - 248-2
- delete unused patches

* Fri Apr 30 2021 hexiaowen <hexiaowen@huawei.com> - 248-1
- Rebase to version 248

* Wed Mar 31 2021 fangxiuning <fangxiuning@huawei.com> - 246-15
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix userdata double free

* Wed Mar 3 2021 shenyangyang <shenyangyang4@huawei.com> - 246-14
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix Failed to migrate controller cgroups from *: Permission denied

* Sat Feb 27 2021 shenyangyang <shenyangyang4@huawei.com> - 246-13
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:xdg autostart Lower most info messages to debug level

* Sat Feb 27 2021 gaoyi <ymuemc@163.com> - 246-12
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:just configure DefaultTasksMax when install

* Tue Jan 26 2021 extinctfire <shenyining_00@126.com> - 246-11
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix login timeout 2 minutes

* Fri Dec 18 2020 overweight <hexiaowen@huawei.com> - 246-10
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix 40-openEuler.rules for memory offline

* Wed Dec 16 2020 shenyangyang <shenyangyang4@huawei.com> - 246-9
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:do not create /var/log/journal on initial installation

* Wed Nov 25 2020 shenyangyang <shenyangyang4@huawei.com> - 246-8
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:don't enable systemd-journald-audit.socket by default

* Thu Sep 17 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-7
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:delete unneed patches and rebase to bded6f

* Fri Sep 11 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-6
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:delete unneed patches

* Wed Sep 9 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-5
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:set default tasks max to 85%

* Wed Sep 9 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-4
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix error handling on readv

* Mon Aug 01 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-3
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:Update to real release 246

* Tue Jul 7 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-2
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix buffer overrun when urlifying.

* Fri Jun 12 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-1
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:Update to release 246

* Thu May 28 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-23
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add requirement of systemd to libs

* Mon May 11 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-22
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:solve the build failure caused by the upgrade of libseccomp

* Mon Apr 27 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-21
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:resolve memleak of pid1 and add some patches

* Thu Apr 9 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-20
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:delete redundant info in spec

* Wed Mar 25 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-19
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add patch of CVE-2020-1714-5

* Fri Mar 13 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-18
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix two vf visual machines have the same mac address

* Tue Mar 10 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-17
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix CVE-2020-1712 and close journal files that were deleted by journald
       before we've setup inotify watch and bump pim_max to 80%

* Thu Mar 5 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-16
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add 1603-udev-add-actions-while-rename-netif-failed.patch

* Sat Feb 29 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-15
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:update rtc with system clock when shutdown

* Mon Feb 17 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-14
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:enable tests

* Mon Feb 3 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-13
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:modify kvm authority 0660 and fix dbus daemon restart need 90s after killed

* Tue Jan 21 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-12
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add systemd-libs

* Sun Jan 19 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-11
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix resolv.conf has symlink default

* Fri Jan 17 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-10
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix capsh drop but ping success and udev ignore error caused by device disconnection

* Wed Jan 15 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-9
- Type:NA
- ID:NA
- SUG:NA
- DESC:delete unneeded obsoletes

* Wed Jan 08 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-8
- Type:NA
- ID:NA
- SUG:NA
- DESC:delete unneeded patchs

* Tue Dec 31 2019 openEuler Buildteam <buildteam@openeuler.org> - 243-7
- Type:NA
- ID:NA
- SUG:NA
- DESC:delete unneeded source

* Mon Dec 23 2019 openEuler Buildteam <buildteam@openeuler.org> - 243-6
- Type:NA
- ID:NA
- SUG:NA
- DESC:modify name of persistent-storage.rules

* Fri Dec 20 2019 jiangchuangang<jiangchuangang@huawei.com> - 243-5
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:change time log level

* Fri Nov 22 2019 shenyangyang<shenyangyang4@huawei.com> - 243-4
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:add efi_arch to solve build problem of x86

* Sat Sep 28 2019 guoxiaoqi<guoxiaoqi2@huawei.com> - 243-3
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:modify default-hierarchy

* Tue Sep 24 2019 shenyangyang<shenyangyang4@huawei.com> - 243-2
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:revise requires

* Thu Sep 12 2019 hexiaowen <hexiaowen@huawei.com> - 243-1
- Update to release 243

* Tue Sep 10 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h43
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:revert fix two vf visual machines have the same mac address

* Wed Sep 04 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h42
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix two vf visual machines have the same mac address

* Sat Aug 31 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h41
- Type:NA
- ID:NA
- SUG:NA
- DESC:timeout waiting for scaning on device 8:3

* Mon Aug 26 2019 shenyangyang<shenyangyang4@huawei.com> - 239-3.h40
- Type:NA
- ID:NA
- SUG:NA
- DESC:remove sensetive info

* Wed Aug 21 2019 yangbin<robin.yb@huawei.com> - 239-3.h39
- Type:NA
- ID:NA
- SUG:NA
- DESC:merge from branch next to openeuler

* Mon Aug 19 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h38
- Type:NA
- ID:NA
- SUG:NA
- DESC:merge from branch next to openeuler

* Thu Jul 25 2019 yangbin<robin.yb@huawei.com> - 239-3.h37
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:change CPUSetMemMigrate type to bool

* Tue Jul 23 2019 yangbin<robin.yb@huawei.com> - 239-3.h36
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add systemd cgroup config for cpuset and freezon

* Thu Jul 18 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h35
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: change support URL shown in the catalog entries

* Tue Jul 09 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h34
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: add systemd dependency requires openssl-libs

* Tue Jul 09 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h33
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: login: use parse_uid() when unmounting user runtime directory

* Tue Jul 9 2019 fangxiuning<fangxiuning@huawei.com> - 239-3.h32
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix timedatectl set-timezone,  UTC time wrong

* Wed Jun 19 2019 cangyi<cangyi@huawei.com> - 239-3.h31
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix memleak on invalid message

* Tue Jun 18 2019 cangyi<cangyi@huawei.com> - 239-3.h30
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: revert fix memleak on invalid message

* Mon Jun 17 2019 wenjun<wenjun8@huawei.com> - 239-3.h29
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:revert h26

* Mon Jun 17 2019 cangyi<cangyi@huawei.com> - 239-3.h28
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix memleak on invalid message

* Wed Jun 12 2019 cangyi<cangyi@huawei.com> - 239-3.h27
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix warnings

* Tue Jun 11 2019 wenjun<wenjun8@huawei.com> - 239-3.h26
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix race between daemon-reload and other commands,remove useless patch

* Mon Jun 10 2019 gaoyi<gaoyi15@huawei.com> - 239-3.h25
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:repair the test test-journal-syslog
	https://github.com/systemd/systemd/commit/8595102d3ddde6d25c282f965573a6de34ab4421

* Tue Jun 04 2019 gaoyi<gaoyi15@huawei.com> - 239-3.h24
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:backport CVE-2019-3844 CVE-2019-3843

* Mon Jun 3 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h23
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix CVE

* Wed May 22 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h22
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix button_open sd_event_source leak

* Mon May 20 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h21
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix some bugfix

* Fri May 17 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h20
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix some bugfix

* Thu May 16 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h19
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix some bugfix

* Mon May 13 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h17
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix some bugfix

* Mon May 13 2019 liuzhiqiang<liuzhiqiang26@huawei.com> - 239-3.h16
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:remove 86-network.rules and its ifup-hotplug script

* Sun May 12 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h15
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:Set-DynamicUser-no-for-networkd-resolved-timesyncd

* Wed May 8 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h14
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:Set-DynamicUser-no-for-networkd-resolved-timesyncd

* Wed May 8 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h13
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:rename patches

* Thu Apr 4 2019 luochunsheng<luochunsheng@huawei.com> - 239-3.h11
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:remove sensitive information

* Wed Mar 27 2019 wangjia<wangjia55@huawei.com> - 239-3.h10
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: rollback patch 1610-add-new-rules-for-lower-priority-events-to-preempt.patch,
        this patch caused mount failed

* Fri Mar 22 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h9
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: Open source fragment reference rectification

* Thu Mar 21 2019 wangxiao<wangxiao65@huawei.com> - 239-3.h8
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: systemctl-fix-assert-for-failed-mktime-conversion.patch
        network-link-Fix-logic-error-in-matching-devices-by-.patch
        bus-socket-Fix-line_begins-to-accept-word-matching-f.patch
        networkd-fix-overflow-check.patch
        resolve-fix-memleak.patch
        syslog-fix-segfault-in-syslog_parse_priority.patch
        journald-free-the-allocated-memory-before-returning-.patch
        resolvectl-free-the-block-of-memory-hashed-points-to.patch
        util-do-not-use-stack-frame-for-parsing-arbitrary-in.patch
        dynamic-user-fix-potential-segfault.patch
        journald-fixed-assertion-failure-when-system-journal.patch
        core-socket-fix-memleak-in-the-error-paths-in-usbffs.patch
        systemd-do-not-pass-.wants-fragment-path-to-manager_.patch
        verbs-reset-optind-10116.patch
        network-fix-memleak-about-routing-policy.patch
        network-fix-memleak-around-Network.dhcp_vendor_class.patch
        sd-dhcp-lease-fix-memleaks.patch
        meson-use-the-host-architecture-compiler-linker-for-.patch
        dhcp6-fix-an-off-by-one-error-in-dhcp6_option_parse_.patch
        bus-message-use-structured-initialization-to-avoid-u.patch
        bus-message-do-not-crash-on-message-with-a-string-of.patch
        bus-message-fix-skipping-of-array-fields-in-gvariant.patch
        basic-hexdecoct-check-for-overflow.patch
        journal-upload-add-asserts-that-snprintf-does-not-re.patch
        bus-unit-util-fix-parsing-of-IPAddress-Allow-Deny.patch
        terminal-util-extra-safety-checks-when-parsing-COLUM.patch
        core-handle-OOM-during-deserialization-always-the-sa.patch
        systemd-nspawn-do-not-crash-on-var-log-journal-creat.patch
        core-don-t-create-Requires-for-workdir-if-missing-ok.patch
        chown-recursive-let-s-rework-the-recursive-logic-to-.patch
        network-fix-segfault-in-manager_free.patch
        network-fix-possible-memleak-caused-by-multiple-sett.patch
        network-fix-memleak-in-config_parse_hwaddr.patch
        network-fix-memleak-abot-Address.label.patch
        tmpfiles-fix-minor-memory-leak-on-error-path.patch
        udevd-explicitly-set-default-value-of-global-variabl.patch
        udev-handle-sd_is_socket-failure.patch
        basic-remove-an-assertion-from-cunescape_one.patch
        debug-generator-fix-minor-memory-leak.patch
        journald-check-whether-sscanf-has-changed-the-value-.patch
        coredumpctl-fix-leak-of-bus-connection.patch
        vconsole-Don-t-skip-udev-call-for-dummy-device.patch
        mount-don-t-propagate-errors-from-mount_setup_unit-f.patch
        sd-device-fix-segfault-when-error-occurs-in-device_n.patch
        boot-efi-use-a-wildcard-section-copy-for-final-EFI-g.patch
        basic-hexdecoct-be-more-careful-in-overflow-check.patch        

* Fri Mar 15 2019 wangjia<wangjia55@huawei.com> - 239-3.h7
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: modify RemoveIPC to false by default value

* Wed Mar 13 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h6
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: add rc.local

* Fri Mar 8 2019 hexiaowen<hexiaowen@huawei.com> - 239-3.h5
- Type:bugfix
- ID:NA
- SUG:restart
- DESC: disable-initialize_clock

* Sat Feb 09 2019 xuchunmei<xuchunmei@huawei.com> - 239-3.h4
- Type:bugfix
- ID:NA
- SUG:restart
- DESC:do not create /var/log/journal on initial installation

* Sat Feb 02 2019 Yi Cang<cangyi@huawei.com> - 239-3.h3
- Type:enhance
- ID:NA
- SUG:restart
- DESC:sync patch

* Tue Jan 29 2019 Yining Shen<shenyining@huawei.com> - 239-3.h2
- Type:enhance
- ID:NA
- SUG:restart
- DESC:sync patch
       journald-fix-allocate-failed-journal-file.patch
       1602-activation-service-must-be-restarted-when-reactivated.patch
       1509-fix-journal-file-descriptors-leak-problems.patch
       2016-set-forwardtowall-no-to-avoid-emerg-log-shown-on-she.patch
       1612-serialize-pids-for-scope-when-not-started.patch
       1615-do-not-finish-job-during-daemon-reload-in-unit_notify.patch
       1617-bus-cookie-must-wrap-around-to-1.patch
       1619-delay-to-restart-when-a-service-can-not-be-auto-restarted.patch
       1620-nop_job-of-a-unit-must-also-be-coldpluged-after-deserization.patch
       1605-systemd-core-fix-problem-of-dbus-service-can-not-be-started.patch
       1611-systemd-core-fix-problem-on-forking-service.patch
       uvp-bugfix-call-malloc_trim-to-return-memory-to-OS-immediately.patch
       uvp-bugfix-also-stop-machine-when-unit-in-active-but-leader-exited.patch

* Mon Dec 10 2018 Zhipeng Xie<xiezhipeng1@huawei.com> - 239-3.h1
- Type:bugfix
- ID:NA
- SUG:restart
- DESC:fix obs build fail

* Mon Dec 10 2018 hexiaowen <hexiaowen@huawei.com> - 239-1
- Package init

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

Name:           systemd
Url:            https://www.freedesktop.org/wiki/Software/systemd
Version:        243
Release:        44
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

Source100:	udev-40-openEuler.rules
Source101:	udev-55-persistent-net-generator.rules
Source102:	udev-56-net-sriov-names.rules
Source103:	udev-61-openeuler-persistent-storage.rules
Source104:	net-set-sriov-names
Source105:	rule_generator.functions
Source106:	write_net_rules
Source107:	detect_virt

Patch0002:      0002-0001-udev-ignore-error-caused-by-device-disconnection.patch
Patch0003:      0003-0001-core-dont-check-error-parameter-of-get_name_owner_handler.patch
Patch0004:      0004-0001-core-dont-check-potentially-NULL-error.patch
Patch0005:      0005-0001-core-shorten-code-a-bit.patch
Patch0006:      0006-0001-core-no-need-to-eat-up-error.patch
Patch0007:      0007-0001-core-create-or-remove-unit-bus-name-slots-always-together.patch
Patch0008:      0008-0001-core-drop-initial-ListNames-bus-call-from-PID1.patch
Patch0009:      0009-1605-update-rtc-with-system-clock-when-shutdown.patch
Patch0010:      0010-1603-udev-add-actions-while-rename-netif-failed.patch
Patch0011:      0011-CVE-2020-1712-1.patch
Patch0012:      0012-CVE-2020-1712-2.patch
Patch0013:      0013-CVE-2020-1712-3.patch
Patch0014:      0014-CVE-2020-1712-4.patch
Patch0015:      0015-CVE-2020-1712-5.patch
Patch0016:      0016-sd-journal-close-journal-files-that-were-deleted-by-.patch
Patch0017:      0017-pid1-bump-DefaultTasksMax-to-80-of-the-kernel-pid.ma.patch
Patch0018:      0018-fix-two-VF-virtual-machines-have-same-mac-address.patch
Patch0019:      0019-logind-set-RemoveIPC-to-false-by-default.patch
Patch0020:      0020-rules-add-rule-for-naming-Dell-iDRAC-USB-Virtual-NIC.patch
Patch0021:      0021-unit-don-t-add-Requires-for-tmp.mount.patch
Patch0022:      0022-Revert-sysctl.d-switch-net.ipv4.conf.all.rp_filter-f.patch
Patch0023:      0023-rules-add-elevator-kernel-command-line-parameter.patch
Patch0024:      0024-rules-add-the-rule-that-adds-elevator-kernel-command.patch
Patch0025:      0025-units-add-Install-section-to-tmp.mount.patch
Patch0026:      0026-Make-systemd-udevd.service-start-after-systemd-remou.patch
Patch0027:      0027-udev-virsh-shutdown-vm.patch
Patch0028:      0028-fix-fd-leak-in-no-memory-condition.patch
Patch0029:      0029-dbus-execute-avoid-extra-strdup.patch
Patch0030:      0030-Avoid-tmp-being-mounted-as-tmpfs-without-the-user-s-.patch
Patch0031:      0031-sd-bus-properly-initialize-containers.patch
Patch0032:      0032-Revert-core-one-step-back-again-for-nspawn-we-actual.patch
Patch0033:      0033-journal-don-t-enable-systemd-journald-audit.socket-b.patch

# The patch of 0026~0029 resolve the pid1 memory leaks
Patch0034:      0034-revert-pid1-drop-unit-caches-only-based-on-mtime.patch
Patch0035:      0035-revert-analyze-add-unit-files-to-dump-the-unit-fragm.patch
Patch0036:      0036-revert-pid1-use-a-cache-for-all-unit-aliases.patch
Patch0037:      0037-revert-shared-unit-file-add-a-function-to-validate-u.patch

Patch0038:      0038-systemd-Fix-busctl-crash-on-aarch64-when-setting-out.patch
Patch0039:      0039-seccomp-more-comprehensive-protection-against-libsec.patch
Patch0040:      0040-network-fix-double-free-in-macsec_receive_channel_fr.patch
Patch0041:      0041-network-L2TP-fix-crash.patch

Patch0042:      0042-systemctl-fix-memleak-caused-by-wrong-cleanup-func.patch
Patch0043:      0043-analyze-fix-minor-memleak.patch
Patch0044:      0044-network-add-one-more-section-validty-check.patch
Patch0045:      0045-network-use-fix-invalid-free-function.patch
Patch0046:      0046-network-fix-memleak.patch
Patch0047:      0047-network-Add-support-to-advertie-ipv6-route.patch
Patch0048:      0048-network-fix-invalid-cleanup-function.patch
Patch0049:      0049-network-fix-memleak-in-route_prefix_free.patch
Patch0050:      0050-sd-radv-fix-memleak.patch
Patch0051:      0051-sd-bus-invalidate-connection-when-Hello-fails.patch
Patch0052:      0052-shared-bus-util-Don-t-replace-exsting-strv.patch
Patch0053:      0053-systemctl-Add-with-dependencies-flag.patch
Patch0054:      0054-man-Document-systemctl-with-dependencies-switch.patch
Patch0055:      0055-core-expose-swap-priority-value-via-dbus-only-if-it-.patch
Patch0056:      0056-tree-wide-we-forgot-to-destroy-some-bus-errors.patch
Patch0057:      0057-sd-bus-fix-introspection-bug-in-signal-parameter-nam.patch
Patch0058:      0058-core-sync-SeccompParseFlags-between-dbus-execute-and.patch
Patch0059:      0059-core-swap-priority-can-be-negative.patch
Patch0060:      0060-core-no-need-to-initialize-swap-structure-fields-if-.patch
Patch0061:      0061-core-initialize-priority_set-when-parsing-swap-unit-.patch
Patch0062:      0062-core-use-unit-based-logging-instead-of-generic-loggi.patch
Patch0063:      0063-core-set-error-value-correctly.patch
Patch0064:      0064-core-fix-re-realization-of-cgroup-siblings.patch
Patch0065:      0065-basic-string-table-avoid-crash-when-table-is-sparse.patch
Patch0066:      0066-journal-fix-buffer-overrun-when-urlifying.patch

Patch0071:      0071-backport-CVE-2018-21029-resolved-check-for-IP-in-certificate-when-using-DoT-.patch
Patch0072:      0072-backport-CVE-2018-21029-resolved-fix-connection-failures-with-TLS-1.3-and-Gn.patch
Patch0073:      0073-backport-CVE-2018-21029-resolved-require-at-least-version-3.6.0-of-GnuTLS-fo.patch
Patch0074:      0074-backport-CVE-2018-21029-Be-more-specific-in-resolved.conf-man-page-with-rega.patch
Patch0075:      0075-backport-CVE-2018-21029-Implement-SNI-when-using-DNS-over-TLS.patch
Patch0076:      0076-backport-CVE-2018-21029-resolve-error-handling-improvements.patch
Patch0077:      0077-backport-CVE-2018-21029-systemd-resolved-use-hostname-for-certificate-valida.patch
Patch0078:      0078-backport-varlink-make-userdata-pointer-inheritance-from-varli.patch
Patch0079:      0079-backport-udev-net_id-parse-_SUN-ACPI-index-as-a-signed-intege.patch
Patch0080:      0080-backport-udev-net_id-don-t-generate-slot-based-names-if-multi.patch
Patch0081:      0081-journal-refresh-cached-credentials-of-stdout-streams.patch 
Patch0082:      0082-journald-rework-end-of-line-marker-handling-to-use-a.patch 
Patch0083:      0083-journald-rework-pid-change-handling.patch 
Patch0084:      0084-journald-enforce-longer-line-length-limit-during-set.patch 
Patch0085:      backport-execute-Fix-migration-from-DynamicUser-yes-to-no.patch
Patch0086:      0086-fix-CVE-2021-33910.patch
Patch0087:      backport-units-restore-RemainAfterExit-yes-in-systemd-vconsol.patch
Patch0088:      backport-udevd-don-t-kill-worker-in-manager_kill_workers-when.patch
Patch0089:      backport-stat-util-add-stat_inode_unmodified-helper-that-chec.patch
Patch0090:      backport-basic-stat-util-make-mtime-check-stricter-and-use-en.patch
Patch0091:      backport-udev-make-algorithm-that-selects-highest-priority-de.patch

#openEuler
Patch9002:      1509-fix-journal-file-descriptors-leak-problems.patch
Patch9003:      1602-activation-service-must-be-restarted-when-reactivated.patch
Patch9004:      1605-systemd-core-fix-problem-of-dbus-service-can-not-be-started.patch
#Patch9004:  1612-serialize-pids-for-scope-when-not-started.patch
#Patch9005:  1615-do-not-finish-job-during-daemon-reload-in-unit_notify.patch
Patch9007:      1619-delay-to-restart-when-a-service-can-not-be-auto-restarted.patch
Patch9008:      1620-nop_job-of-a-unit-must-also-be-coldpluged-after-deserization.patch
#Patch9006:  core-bugfix-call-malloc_trim-to-return-memory-to-OS-immediately.patch
#Patch9009:  systemd-core-Close-and-free-dbus-when-bus-authentica.patch
Patch9009:      systemd-change-time-log-level.patch
Patch9010:      fix-capsh-drop-but-ping-success.patch
Patch9011:      0998-resolved-create-etc-resolv.conf-symlink-at-runtime.patch
Patch9012:      set-kernel-core_pipe_limit-to-16.patch

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
BuildRequires:  gnu-efi gnu-efi-devel
BuildRequires:  valgrind-devel, util-linux

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

Provides:       %{name}-pam = %{version}-%{release}
Provides:       %{name}-rpm-config = %{version}-%{release}
Obsoletes:      %{name}-pam <= %{version}-%{release}
Obsoletes:      %{name}-rpm-config <= %{version}-%{release}

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
        -Dseccomp=true
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
        -Dgnu-efi=true
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

getent group systemd-coredump &>/dev/null || groupadd -r systemd-coredump 2>&1 || :
getent passwd systemd-coredump &>/dev/null || useradd -r -l -g systemd-coredump -d / -s /sbin/nologin -c "systemd Core Dumper" systemd-coredump &>/dev/null || :

getent group systemd-network &>/dev/null || groupadd -r -g 192 systemd-network 2>&1 || :
getent passwd systemd-network &>/dev/null || useradd -r -u 192 -l -g systemd-network -d / -s /sbin/nologin -c "systemd Network Management" systemd-network &>/dev/null || :

getent group systemd-resolve &>/dev/null || groupadd -r -g 193 systemd-resolve 2>&1 || :
getent passwd systemd-resolve &>/dev/null || useradd -r -u 193 -l -g systemd-resolve -d / -s /sbin/nologin -c "systemd Resolver" systemd-resolve &>/dev/null || :

%post
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
        systemctl preset-all &>/dev/null || :
fi

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
                systemd-networkd.service \
                systemd-networkd-wait-online.service \
                systemd-resolved.service \
                >/dev/null || :
fi

%pre udev
getent group systemd-timesync &>/dev/null || groupadd -r systemd-timesync 2>&1 || :
getent passwd systemd-timesync &>/dev/null || useradd -r -l -g systemd-timesync -d / -s /sbin/nologin -c "systemd Time Synchronization" systemd-timesync &>/dev/null || :

%post udev
# Move old stuff around in /var/lib
mv %{_localstatedir}/lib/random-seed %{_localstatedir}/lib/systemd/random-seed &>/dev/null
mv %{_localstatedir}/lib/backlight %{_localstatedir}/lib/systemd/backlight &>/dev/null
if [ -L %{_localstatedir}/lib/systemd/timesync ]; then
    rm %{_localstatedir}/lib/systemd/timesync
    mv %{_localstatedir}/lib/private/systemd/timesync %{_localstatedir}/lib/systemd/timesync
fi
if [ -f %{_localstatedir}/lib/systemd/clock ] ; then
    mkdir -p %{_localstatedir}/lib/systemd/timesync
    mv %{_localstatedir}/lib/systemd/clock %{_localstatedir}/lib/systemd/timesync/.
fi

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
%ghost %dir /var/lib/systemd/coredump
%ghost %dir /var/lib/systemd/linger
%ghost /var/lib/systemd/catalog/database
%ghost %dir /var/lib/private/systemd
/usr/sbin/reboot
/usr/sbin/halt
/usr/sbin/telinit
/usr/sbin/resolvconf
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
/usr/share/bash-completion/completions/resolvectl
/usr/share/bash-completion/completions/coredumpctl
/usr/share/bash-completion/completions/systemd-delta
/usr/share/bash-completion/completions/systemd-cgls
/usr/share/bash-completion/completions/systemd-resolve
/usr/share/bash-completion/completions/networkctl
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
/usr/share/zsh/site-functions/_resolvectl
/usr/share/zsh/site-functions/_systemctl
/usr/share/zsh/site-functions/_systemd-run
/usr/share/zsh/site-functions/_sd_outputmodes
/usr/share/zsh/site-functions/_sd_unit_files
/usr/share/zsh/site-functions/_sd_machines
/usr/share/zsh/site-functions/_coredumpctl
/usr/share/zsh/site-functions/_networkctl
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
/usr/share/dbus-1/system-services/org.freedesktop.resolve1.service
/usr/share/dbus-1/system-services/org.freedesktop.hostname1.service
/usr/share/dbus-1/system-services/org.freedesktop.network1.service
/usr/share/dbus-1/system-services/org.freedesktop.timedate1.service
/usr/share/dbus-1/system.d/org.freedesktop.resolve1.conf
/usr/share/dbus-1/system.d/org.freedesktop.timedate1.conf
/usr/share/dbus-1/system.d/org.freedesktop.hostname1.conf
/usr/share/dbus-1/system.d/org.freedesktop.login1.conf
/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf
/usr/share/dbus-1/system.d/org.freedesktop.locale1.conf
/usr/share/dbus-1/system.d/org.freedesktop.portable1.conf
/usr/share/dbus-1/system.d/org.freedesktop.network1.conf
/usr/share/pkgconfig/systemd.pc
/usr/share/pkgconfig/udev.pc
/usr/share/polkit-1/actions/org.freedesktop.hostname1.policy
/usr/share/polkit-1/actions/org.freedesktop.portable1.policy
/usr/share/polkit-1/actions/org.freedesktop.timedate1.policy
/usr/share/polkit-1/actions/org.freedesktop.resolve1.policy
/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy
/usr/share/polkit-1/actions/org.freedesktop.login1.policy
/usr/share/polkit-1/actions/org.freedesktop.network1.policy
/usr/share/polkit-1/actions/org.freedesktop.locale1.policy
/usr/share/polkit-1/rules.d/systemd-networkd.rules
/usr/bin/systemd-machine-id-setup
/usr/bin/localectl
/usr/bin/systemd-path
/usr/bin/portablectl
/usr/bin/systemd-run
/usr/bin/systemd-firstboot
/usr/bin/systemd-escape
/usr/bin/systemd-tmpfiles
/usr/bin/systemd-cat
/usr/bin/systemd-inhibit
/usr/bin/systemd-ask-password
/usr/bin/resolvectl
/usr/bin/systemd-notify
/usr/bin/coredumpctl
/usr/bin/systemd-delta
/usr/bin/systemd-cgls
/usr/bin/systemd-resolve
/usr/bin/networkctl
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
/usr/lib/sysusers.d/systemd.conf
/usr/lib/sysusers.d/basic.conf
/usr/lib/systemd/system/hwclock-save.service
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
%dir %{_systemddir}/ntp-units.d
%{_systemddir}/systemd-user-sessions
%{_systemddir}/systemd-sysctl
%{_systemddir}/systemd-networkd-wait-online
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
%{_systemddir}/systemd-networkd
%dir %{_systemddir}/system-preset
%dir %{_systemddir}/user-environment-generators
%{_systemddir}/systemd-shutdown
%{_systemddir}/systemd-portabled
%{_systemddir}/libsystemd-shared-243.so
%{_systemddir}/systemd-reply-password
%dir %{_systemddir}/system-generators
%dir %{_systemddir}/system
%{_systemddir}/systemd-export
%{_systemddir}/systemd-fsck
%{_systemddir}/systemd-timedated
%dir %{_systemddir}/user-generators
%dir %{_systemddir}/portable
%{_systemddir}/systemd
%dir %{_systemddir}/user-preset
%{_systemddir}/systemd-coredump
%{_systemddir}/resolv.conf
%{_systemddir}/systemd-dissect
%{_systemddir}/systemd-veritysetup
%{_systemddir}/systemd-network-generator
%{_systemddir}/systemd-time-wait-sync
%{_systemddir}/systemd-pstore
%{_systemddir}/systemd-resolved
%{_systemddir}/systemd-binfmt
%{_systemddir}/user-preset/90-systemd.preset
%dir %{_systemddir}/portable/profile
%dir %{_systemddir}/portable/profile/strict
%dir %{_systemddir}/portable/profile/nonetwork
%dir %{_systemddir}/portable/profile/trusted
%dir %{_systemddir}/portable/profile/default
%{_systemddir}/portable/profile/default/service.conf
%{_systemddir}/portable/profile/trusted/service.conf
%{_systemddir}/portable/profile/nonetwork/service.conf
%{_systemddir}/portable/profile/strict/service.conf
%{_unitdir}/systemd-networkd.socket
%{_unitdir}/systemd-binfmt.service
%{_unitdir}/systemd-machine-id-commit.service
%dir %{_unitdir}/basic.target.wants
%{_unitdir}/systemd-coredump.socket
%{_unitdir}/ctrl-alt-del.target
%{_unitdir}/systemd-tmpfiles-setup.service
%{_unitdir}/systemd-time-wait-sync.service
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
%{_unitdir}/systemd-pstore.service
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
%{_unitdir}/systemd-networkd-wait-online.service
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
%{_unitdir}/systemd-coredump@.service
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
%{_unitdir}/dbus-org.freedesktop.portable1.service
%{_unitdir}/rc-local.service
%{_unitdir}/debug-shell.service
%{_unitdir}/dev-mqueue.mount
%{_unitdir}/emergency.target
%{_unitdir}/systemd-portabled.service
%{_unitdir}/dbus-org.freedesktop.timedate1.service
%{_unitdir}/runlevel1.target
%dir %{_unitdir}/remote-fs.target.wants
%{_unitdir}/dbus-org.freedesktop.hostname1.service
%{_unitdir}/systemd-networkd.service
%{_unitdir}/runlevel0.target
%{_unitdir}/user.slice
%{_unitdir}/systemd-journal-catalog-update.service
%{_unitdir}/local-fs-pre.target
%{_unitdir}/systemd-halt.service
%{_unitdir}/systemd-resolved.service
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
%{_unitdir}/sockets.target.wants/systemd-coredump.socket
%{_unitdir}/sockets.target.wants/systemd-journald-audit.socket
%{_unitdir}/sockets.target.wants/systemd-journald-dev-log.socket
%{_unitdir}/sockets.target.wants/systemd-journald.socket
%{_unitdir}/sockets.target.wants/systemd-initctl.socket
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
%{_systemddir}/network/80-container-host0.network
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
/usr/lib/sysctl.d/50-coredump.conf
/usr/lib/sysctl.d/50-default.conf
/usr/lib/sysctl.d/50-pid-max.conf
/usr/lib/tmpfiles.d/systemd-tmp.conf
/usr/lib/tmpfiles.d/systemd-nologin.conf
/usr/lib/tmpfiles.d/systemd.conf
/usr/lib/tmpfiles.d/journal-nocow.conf
/usr/lib/tmpfiles.d/portables.conf
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
%dir /etc/systemd/network
%config(noreplace) /etc/systemd/user.conf
%config(noreplace) /etc/systemd/coredump.conf
%dir /etc/systemd/user
%config(noreplace) /etc/systemd/logind.conf
%config(noreplace) /etc/systemd/networkd.conf
%config(noreplace) /etc/systemd/resolved.conf
%config(noreplace) /etc/systemd/journald.conf
%config(noreplace) /etc/systemd/pstore.conf
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

/usr/lib64/security/pam_systemd.so
/usr/lib/rpm/macros.d/macros.systemd

%files libs
/usr/lib64/libnss_systemd.so.2
/usr/lib64/libnss_resolve.so.2
/usr/lib64/libnss_myhostname.so.2
/usr/lib64/libsystemd.so.0
/usr/lib64/libsystemd.so.0.27.0
/usr/lib64/libudev.so.1
/usr/lib64/libudev.so.1.6.15

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
/usr/lib64/libudev.so
/usr/lib64/libsystemd.so
/usr/lib64/pkgconfig/libsystemd.pc
/usr/lib64/pkgconfig/libudev.pc

%files udev
%ghost %dir /var/lib/systemd/backlight
%ghost %dir /var/lib/systemd/timesync
%ghost %dir /var/lib/systemd/rfkill
%ghost /var/lib/systemd/random-seed
%ghost /var/lib/systemd/timesync/clock
/usr/sbin/udevadm
/usr/share/bash-completion/completions/udevadm
/usr/share/bash-completion/completions/bootctl
/usr/share/bash-completion/completions/kernel-install
/usr/share/zsh/site-functions/_bootctl
/usr/share/zsh/site-functions/_udevadm
/usr/share/zsh/site-functions/_kernel-install
/usr/share/dbus-1/system-services/org.freedesktop.timesync1.service
/usr/share/dbus-1/system.d/org.freedesktop.timesync1.conf
/usr/bin/systemd-hwdb
/usr/bin/udevadm
/usr/bin/bootctl
/usr/bin/kernel-install
%dir /usr/lib/modprobe.d
%dir /usr/lib/udev
%dir /usr/lib/kernel
%dir /usr/lib/modules-load.d
%dir %{_systemddir}/boot
%{_systemddir}/systemd-timesyncd
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
%{_unitdir}/systemd-timesyncd.service
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
%{_systemddir}/ntp-units.d/80-systemd-timesync.list
%dir %{_systemddir}/boot/efi
%{_systemddir}/boot/efi/systemd-boot%{efi_arch}.efi
%{_systemddir}/boot/efi/linux%{efi_arch}.efi.stub
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
/usr/lib/modprobe.d/systemd.conf
%ghost %config(noreplace) /etc/vconsole.conf
%dir /etc/udev
%dir /etc/kernel
%dir /etc/modules-load.d
%config(noreplace) /etc/systemd/timesyncd.conf
%config(noreplace) /etc/systemd/sleep.conf
%dir /etc/kernel/install.d
%ghost /etc/udev/hwdb.bin
%dir /etc/udev/rules.d
%config(noreplace) /etc/udev/udev.conf
%dir /etc/udev/hwdb.d

%files container
/usr/share/bash-completion/completions/machinectl
/usr/share/bash-completion/completions/systemd-nspawn
/usr/share/zsh/site-functions/_machinectl
/usr/share/zsh/site-functions/_systemd-nspawn
/usr/share/dbus-1/system-services/org.freedesktop.import1.service
/usr/share/dbus-1/system-services/org.freedesktop.machine1.service
/usr/share/dbus-1/system.d/org.freedesktop.import1.conf
/usr/share/dbus-1/system.d/org.freedesktop.machine1.conf
/usr/share/polkit-1/actions/org.freedesktop.import1.policy
/usr/share/polkit-1/actions/org.freedesktop.machine1.policy
/usr/lib64/libnss_mymachines.so.2
/usr/bin/machinectl
/usr/bin/systemd-nspawn
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
%{_unitdir}/systemd-nspawn@.service
%{_unitdir}/machines.target.wants/var-lib-machines.mount
%{_unitdir}/remote-fs.target.wants/var-lib-machines.mount
%{_systemddir}/network/80-container-vz.network
%{_systemddir}/network/80-container-ve.network
/usr/lib/tmpfiles.d/systemd-nspawn.conf

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

%files help
/usr/share/man/*/*
%exclude /usr/share/man/man3/*

%changelog
* Tue Aug 10 2021 yangmingtai <yangmingtai@huawei.com> - 243-44
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:udevd: exec daemon-reload after installation

* Tue Aug 03 2021 yangmingtai <yangmingtai@huawei.com> - 243-43
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:udevd: fix broken symbolic links when same link for different devices

* Fri Jul 30 2021 jiazhenyuan <jiazhenyuan@uniontech.com> - 243-42
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:set kernel.core_pipe_limit=16

* Tue Jul 27 2021 fangxiuning <fangxiuning@huawei.com> - 243-41
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:udevd: don't kill worker in manager_kill_worker when it's running

* Mon Jul 26 2021 extinctfire <shenyining_00@126.com> - 243-40
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:restore RemainAfterExit=yes in systemd-vconsole-setup.service

* Wed Jul 21 2021 yangmingtai <yangmingtai@huawei.com> - 243-39
- Type:cve
- ID:CVE-2021-33910
- SUG:NA
- DESC: fix CVE-2021-33910

* Thu Jun 03 2021 ExtinctFire <shenyining_00@126.com> - 243-38
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix migration from DynamicUser=yes to no.

* Tue Jun 01 2021 fangxiuning <fangxiuning@huawei.com> - 243-37
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: journald: enforce longer line length limit during "setup" phase of stream protocol

* Mon May 31 2021 overweight <hexiaowen@huawei.com> - 243-36
- fix patches name and patches num

* Thu May 27 2021 shenyangyang <shenyangyang4@huawei.com> - 243-35
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:change requires to openssl-libs as post scripts systemctl requires libssl.so.1.1

* Mon May 10 2021 shenyangyang <shenyangyang4@huawei.com> - 243-34
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:backport from upstream to solve the problem when devices claim the same slot

* Fri Apr 02 2021 fangxiuning <fangxiuning@huawei.com> - 243-33
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix userdate double free

* Fri Jan 29 2021 overweight <hexiaowen@huawei.com> - 243-32
- Type:cve
- ID:CVE-2018-21029
- SUG:NA
- DESC:fix cve-2018-21029

* Fri Dec 18 2020 overweight <hexiaowen@huawei.com> - 243-31
- Type:bugfix
- ID:NA
- SUG:NA
- DESC: fix 40-openEuler.rules for memory offline

* Wed Dec 16 2020 shenyangyang <shenyangyang4@huawei.com> - 243-30
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:do not create /var/log/journal on initial installation

* Mon Dec 14 2020 shenyangyang <shenyangyang4@huawei.com> - 243-29
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:revert don't enable systemd-journald-audit.socket by default
       that may cause reboot problem if update systemd with out dracut -f
       from LTS-20.03

* Wed Nov 25 2020 shenyangyang <shenyangyang4@huawei.com> - 243-28
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:don't enable systemd-journald-audit.socket by default

* Mon Nov 23 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-27
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:add elevator= kernel command line parameter and don't enable bfq
       by default

* Tue Jul 7 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-26
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix buffer overrun when urlifying

* Thu Jun 18 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-25
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:dbus commissioning enhancement

* Thu May 28 2020 openEuler Buildteam <buildteam@openeuler.org> - 243-24
- Type:enhancement
- ID:NA
- SUG:NA
- DESC:fix double free in macsec_receive_channel_free() and 
       fix crash in network L2TP

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
- DESC:add 0010-1603-udev-add-actions-while-rename-netif-failed.patch

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

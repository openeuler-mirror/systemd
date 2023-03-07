%global vendor %{?_vendor:%{_vendor}}%{!?_vendor:openEuler}
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
Release:        48
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

Source100:      udev-40-generic.rules
Source101:      udev-55-persistent-net-generator.rules
Source102:      udev-56-net-sriov-names.rules
Source104:      net-set-sriov-names
Source105:      rule_generator.functions
Source106:      write_net_rules
Source107:      detect_virt

Patch6000:      backport-hostnamed-correct-variable-with-errno-in-fallback_ch.patch
Patch6001:      backport-docs-improve-wording-when-mentioning-the-acronym-ESP.patch
Patch6002:      backport-systemctl-show-error-when-help-for-unknown-unit-is-r.patch
Patch6003:      backport-shared-format-table-allocate-buffer-of-sufficient-si.patch
Patch6004:      backport-fix-CVE-2021-33910.patch
Patch6005:      backport-sd-bus-fix-missing-initializer-in-SD_BUS_VTABLE_END-.patch
Patch6006:      backport-pid1-propagate-the-original-command-line-when-reexec.patch
Patch6007:      backport-coredump-stacktrace.c-avoid-crash-on-binaries-withou.patch
Patch6008:      backport-machined-varlink-fix-double-free.patch
Patch6009:      backport-malloc-uses-getrandom-now.patch
Patch6010:      backport-discover-image-mount-as-read-only-when-extracting-me.patch
Patch6011:      backport-networkd-Include-linux-netdevice.h-header.patch
Patch6012:      backport-seccomp-drop-getrandom-from-system-service.patch
Patch6013:      backport-seccomp-move-sched_getaffinity-from-system-service-t.patch
Patch6014:      backport-systemctl-allow-set-property-to-be-called-with-a-glo.patch
Patch6015:      backport-Use-correct-fcntl.h-include.patch
Patch6016:      backport-Use-correct-poll.h-include.patch
Patch6017:      backport-veritysetup-print-help-for-help-h-help.patch
Patch6018:      backport-network-use-address_equal-route_equal-to-compare-add.patch
Patch6019:      backport-mkosi-openSUSE-update-bootable-no-dependencies.patch
Patch6020:      backport-mkosi-Fix-openSUSE-Jinja2-package-name.patch
Patch6021:      backport-sd-netlink-always-append-new-bridge-FDB-entries.patch
Patch6022:      backport-core-cgroup-fix-error-handling-of-cg_remove_xattr.patch
Patch6023:      backport-core-wrap-cgroup-path-with-empty_to_root-in-log-mess.patch
Patch6024:      backport-network-add-comments.patch
Patch6025:      backport-network-ignore-errors-on-setting-bridge-config.patch
Patch6026:      backport-network-ignore-errors-on-unsetting-master-ifindex.patch
Patch6027:      backport-network-also-check-addresses-when-determine-a-gatewa.patch
Patch6028:      backport-network-check-the-received-interface-name-is-actuall.patch
Patch6029:      backport-network-configure-address-with-requested-lifetime.patch
Patch6030:      backport-network-use-monotonic-instead-of-boot-time-to-handle.patch
Patch6031:      backport-udev-when-setting-up-lo-do-not-return-an-error.patch
Patch6032:      backport-network-fix-configuring-of-CAN-devices.patch
Patch6033:      backport-network-fix-logic-for-checking-gateway-address-is-re.patch
Patch6034:      backport-Fix-the-Failed-to-open-random-seed-.-message.patch
Patch6035:      backport-resolved-Don-t-omit-AD-bit-in-reply-if-DO-is-set-in-.patch
Patch6036:      backport-sd-dhcp6-client-fix-copy-and-paste-mistake.patch
Patch6037:      backport-sd-dhcp6-client-cirtainly-adjust-T1-and-T2.patch
Patch6038:      backport-Get-rid-of-dangling-setutxent.patch
Patch6039:      backport-sd-dhcp-server-fix-possible-double-free-or-use-after.patch
Patch6040:      backport-hostname-fix-off-by-one-issue-in-gethostname.patch
Patch6041:      backport-systemd-analyze-parse-ip_filters_custom_egress-corre.patch
Patch6042:      backport-cgroup-do-catchup-for-unit-cgroup-inotify-watch-file.patch
Patch6043:      backport-core-Make-sure-cgroup_oom_queue-is-flushed-on-manage.patch
Patch6044:      backport-sd-boot-Fix-possible-null-pointer-dereference.patch
Patch6045:      backport-resolved-retry-on-SERVFAIL-before-downgrading-featur.patch
Patch6046:      backport-Don-t-open-var-journals-in-volatile-mode-when-runtim.patch
Patch6047:      backport-network-allow-users-to-forbid-passthru-MACVLAN-from-.patch
Patch6048:      backport-unit-coldplug-both-job-and-nop_job-if-possible.patch
Patch6049:      backport-network-do-not-assume-the-highest-priority-when-Prio.patch
Patch6050:      backport-fstab-generator-Respect-nofail-when-ordering.patch
Patch6051:      backport-discover-image-pass-the-right-fd-to-fd_getcrtime.patch
Patch6052:      backport-src-boot-efi-linux-fix-linux_exec-prototype.patch
Patch6053:      backport-timesync-fix-wrong-type-for-receiving-timestamp-in-n.patch
Patch6054:      backport-import-turn-off-weird-protocols-in-curl.patch
Patch6055:      backport-network-fix-wrong-flag-manage_foreign_routes-manage_.patch
Patch6056:      backport-icmp6-drop-unnecessary-assertion.patch
Patch6057:      backport-socket-util-introduce-CMSG_SPACE_TIMEVAL-TIMESPEC-ma.patch
Patch6058:      backport-timesync-check-cmsg-length.patch
Patch6059:      backport-journal-network-timesync-fix-segfault-on-32bit-timev.patch
Patch6060:      backport-tpm-util-fix-TPM-parameter-handling.patch
Patch6061:      backport-basic-linux-Sync-if_arp.h-with-Linux-5.14.patch
Patch6062:      backport-Drop-bundled-copy-of-linux-if_arp.h.patch
Patch6063:      backport-explicitly-close-FIDO2-devices.patch
Patch6064:      backport-core-respect-install_sysconfdir_samples-in-meson-fil.patch
Patch6065:      backport-login-respect-install_sysconfdir_samples-in-meson-fi.patch
Patch6066:      backport-core-Remove-circular-include.patch
Patch6067:      backport-path-util-make-find_executable-work-without-proc-mou.patch
Patch6068:      backport-Fix-another-crash-due-to-missing-NHDR.patch
Patch6069:      backport-hwdb-remove-double-empty-line-in-help-text.patch
Patch6070:      backport-run-mount-systemctl-don-t-fork-off-PolicyKit-ask-pw-.patch
Patch6071:      backport-homed-make-sure-to-use-right-asssesors-for-GID-acces.patch
Patch6072:      backport-homed-fix-log-message-referring-to-fsck-when-we-actu.patch
Patch6073:      backport-homed-add-missing-SYNTHETIC_ERRNO.patch
Patch6074:      backport-homed-remove-misplaced-assert.patch
Patch6075:      backport-network-print-Ethernet-Link-Layer-DHCP-client-ID-wit.patch
Patch6076:      backport-udev-fix-potential-memleak.patch
Patch6077:      backport-nspawn-fix-type-to-pass-to-connect.patch
Patch6078:      backport-home-secret-argument-of-handle_generic_user_record_e.patch
Patch6079:      backport-docs-portablectl-is-in-bin.patch
Patch6080:      backport-core-fix-free-undefined-pointer-when-strdup-failed-i.patch
Patch6081:      backport-sd-event-take-ref-on-event-loop-object-before-dispat.patch
Patch6082:      backport-nss-systemd-pack-pw_passwd-result-into-supplied-buff.patch
Patch6083:      backport-nss-systemd-ensure-returned-strings-point-into-provi.patch
Patch6084:      backport-core-Parse-log-environment-settings-again-after-appl.patch
Patch6085:      backport-network-fix-handling-of-network-interface-renaming.patch
Patch6086:      backport-virt-Improve-detection-of-EC2-metal-instances.patch
Patch6087:      backport-Fix-error-building-repart-with-no-libcryptsetup-2073.patch
Patch6088:      backport-sd-journal-Don-t-compare-hashes-from-different-journ.patch
Patch6089:      backport-test-use-a-less-restrictive-portable-profile-when-ru.patch
Patch6090:      backport-Respect-install_sysconfdir.patch
Patch6091:      backport-journalctl-never-fail-at-flushing-when-the-flushed-f.patch
Patch6092:      backport-sd-journal-Ignore-data-threshold-if-set-to-zero-in-s.patch
Patch6093:      backport-watchdog-pass-right-error-code-to-log-function-so-th.patch
Patch6094:      backport-fileio-lower-maximum-virtual-file-buffer-size-by-one.patch
Patch6095:      backport-fileio-set-O_NOCTTY-when-reading-virtual-files.patch
Patch6096:      backport-fileio-start-with-4k-buffer-for-procfs.patch
Patch6097:      backport-fileio-fix-truncated-read-handling-in-read_virtual_f.patch
Patch6098:      backport-test-fileio-test-read_virtual_file-with-more-files-f.patch
Patch6099:      backport-bootctl-Fix-update-not-adding-EFI-entry-if-Boot-IDs-.patch
Patch6100:      backport-network-disable-event-sources-before-unref-them.patch
Patch6101:      backport-libsystemd-network-disable-event-sources-before-unre.patch
Patch6102:      backport-resolved-suppress-writing-DNS-server-info-into-etc-r.patch
Patch6103:      backport-resolvconf-compat-make-u-operation-a-NOP.patch
Patch6104:      backport-basic-unit-file-don-t-filter-out-names-starting-with.patch
Patch6105:      backport-core-mount-add-implicit-unit-dependencies-even-if-wh.patch
Patch6106:      backport-seccomp-Always-install-filters-for-native-architectu.patch
Patch6107:      backport-test-Check-that-native-architecture-is-always-filter.patch
Patch6108:      backport-mount-util-fix-fd_is_mount_point-when-both-the-paren.patch
Patch6109:      backport-sleep-don-t-skip-resume-device-with-low-priority-ava.patch
Patch6110:      backport-repart-use-right-error-variable.patch
Patch6111:      backport-basic-env-util-correctly-parse-extended-vars-after-n.patch
Patch6112:      backport-user-record-disable-two-pbkdf-fields-that-don-t-appl.patch
Patch6113:      backport-core-fix-SIGABRT-on-empty-exec-command-argv.patch
Patch6114:      backport-core-service-also-check-path-in-exec-commands.patch
Patch6115:      backport-coredump-Don-t-log-an-error-if-D-Bus-isn-t-running.patch
Patch6116:      backport-ether-addr-util-make-hw_addr_to_string-return-valid-.patch
Patch6117:      backport-localed-use-PROJECT_FILE-rather-than-__FILE__-for-lo.patch
Patch6118:      backport-coredumpctl-stop-truncating-information-about-coredu.patch
Patch6119:      backport-sd-dhcp6-client-ignore-IAs-whose-IAID-do-not-match-c.patch
Patch6120:      backport-sd-boot-Unify-error-handling.patch
Patch6121:      backport-sd-boot-Rework-console-input-handling.patch
Patch6122:      backport-coredump-fix-filename-in-journal-when-not-compressed.patch
Patch6123:      backport-virt-Support-detection-for-ARM64-Hyper-V-guests.patch
Patch6124:      backport-homework-fix-incorrect-error-variable-use.patch
Patch6125:      backport-sd-device-monitor-update-log-message-to-clarify-the-.patch
Patch6126:      backport-homework-don-t-bother-with-BLKRRPART-on-images-that-.patch
Patch6127:      backport-userdb-fix-type-to-pass-to-connect.patch
Patch6128:      backport-homed-shutdown-call-valgrind-magic-after-LOOP_GET_ST.patch
Patch6129:      backport-utmp-remove-dev-from-line.patch
Patch6130:      backport-network-route-fix-possible-overflow-in-conversion-us.patch
Patch6131:      backport-varlink-disconnect-varlink-link-in-one-more-case.patch
Patch6132:      backport-udev-do-not-try-to-rename-interface-if-it-is-already.patch
Patch6133:      backport-stat-util-specify-O_DIRECTORY-when-reopening-dir-in-.patch
Patch6134:      backport-json-do-something-remotely-reasonable-when-we-see-Na.patch
Patch6135:      backport-change-indicator-used-for-later-versions-of-VirtualB.patch
Patch6136:      backport-hwdb-Allow-console-users-access-to-media-nodes.patch
Patch6137:      backport-test-do-not-use-alloca-in-function-call.patch
Patch6138:      backport-systemctl-pretty-print-ExtensionImages-property.patch
Patch6139:      backport-systemctl-small-fixes-for-MountImages-pretty-printin.patch
Patch6140:      backport-core-normalize-r-variable-handling-in-unit_attach_pi.patch
Patch6141:      backport-scope-refuse-activation-of-scopes-if-no-PIDs-to-add-.patch
Patch6142:      backport-homework-repart-turn-on-cryptsetup-logging-before-we.patch
Patch6143:      backport-systemctl-only-fall-back-to-local-cgroup-display-if-.patch
Patch6144:      backport-execute-respect-selinux_context_ignore.patch
Patch6145:      backport-core-ignore-failure-on-setting-smack-process-label-w.patch
Patch6146:      backport-process-util-wait-for-processes-we-killed-even-if-ki.patch
Patch6147:      backport-scope-count-successful-cgroup-additions-when-delegat.patch
Patch6148:      backport-creds-util-switch-to-OpenSSL-3.0-APIs.patch
Patch6149:      backport-openssl-util-use-EVP-API-to-get-RSA-bits.patch
Patch6150:      backport-ci-fix-indentation.patch
Patch6151:      backport-ci-cancel-previous-jobs-on-ref-update.patch
Patch6152:      backport-ci-take-CIFuzz-s-matrix-into-consideration.patch
Patch6153:      backport-ci-run-the-unit_tests-and-mkosi-jobs-on-stable-branc.patch
Patch6154:      backport-test-oomd-util-skip-tests-if-cgroup-memory-controlle.patch
Patch6155:      backport-ci-pin-the-debian-systemd-repo-to-a-specific-revisio.patch
Patch6156:      backport-basic-mountpoint-util-detect-erofs-as-a-read-only-FS.patch
Patch6157:      backport-user-record-fix-display-of-access-mode.patch
Patch6158:      backport-logind-downgrade-message-about-run-utmp-missing-to-L.patch
Patch6159:      backport-tree-wide-use-sd_event_source_disable_unref-where-we.patch
Patch6160:      backport-sd-event-don-t-destroy-inotify-data-structures-from-.patch
Patch6161:      backport-Change-gendered-terms-to-be-gender-neutral-21325.patch
Patch6162:      backport-binfmt-fix-exit-value.patch
Patch6163:      backport-unit_is_bound_by_inactive-fix-return-pointer-check.patch
Patch6164:      backport-umask-util-add-helper-that-resets-umask-until-end-of.patch
Patch6165:      backport-namespace-rebreak-a-few-comments.patch
Patch6166:      backport-namespace-make-whole-namespace_setup-work-regardless.patch
Patch6167:      backport-namespace-make-tmp-dir-handling-code-independent-of-.patch
Patch6168:      backport-tests-add-test-case-for-UMask-BindPaths-combination.patch
Patch6169:      backport-sd-dhcp6-client-constify-one-argument.patch
Patch6170:      backport-sd-dhcp6-client-modernize-dhcp6_option_parse.patch
Patch6171:      backport-test-add-tests-for-reading-unaligned-data.patch
Patch6172:      backport-sd-dhcp6-client-fix-buffer-size-calculation-in-dhcp6.patch
Patch6173:      backport-sd-dhcp6-client-constify-several-arguments.patch
Patch6174:      backport-sd-dhcp6-client-make-dhcp6_lease_free-accepts-NULL.patch
Patch6175:      backport-sd-dhcp6-client-do-not-merge-NTP-and-SNTP-options.patch
Patch6176:      backport-dhcp-fix-assertion-failure.patch
Patch6177:      backport-network-address-read-flags-from-message-header-when-.patch
Patch6178:      backport-seccomp-move-mprotect-to-default.patch
Patch6179:      backport-journal-Skip-over-corrupt-entry-items-in-enumerate_d.patch
Patch6180:      backport-journal-Use-separate-variable-for-Data-object-in-sd_.patch
Patch6181:      backport-journal-Skip-corrupt-Data-objects-in-sd_journal_get_.patch
Patch6182:      backport-analyze-fix-printing-config-when-there-is-no-main-co.patch
Patch6183:      backport-resolved-fix-ResolveService-hostname-handling.patch
Patch6184:      backport-resolved-properly-signal-transient-errors-back-to-NS.patch
Patch6185:      backport-resolved-make-sure-we-don-t-hit-an-assert-when-deali.patch
Patch6186:      backport-resolved-clean-up-manager_write_resolv_conf-a-bit.patch
Patch6187:      backport-virt-Fix-the-detection-for-Hyper-V-VMs.patch
Patch6188:      backport-homework-fix-a-bad-error-propagation.patch
Patch6189:      backport-journal-Remove-entry-seqnum-revert-logic.patch
Patch6190:      backport-mmap-cache-LIST_REMOVE-after-w-unused_prev.patch
Patch6191:      backport-journal-Deduplicate-entry-items-before-they-are-stor.patch
Patch6192:      backport-test-journal-flush-allow-testing-against-specific-fi.patch
Patch6193:      backport-test-journal-flush-do-not-croak-on-corrupted-input-f.patch
Patch6194:      backport-fix-ConditionDirectoryNotEmpty-when-it-comes-to-a-No.patch
Patch6195:      backport-fix-ConditionPathIsReadWrite-when-path-does-not-exis.patch
Patch6196:      backport-sd-dhcp6-client-fix-error-handling.patch
Patch6197:      backport-core-bpf-firewall-make-bpf_firewall_supported-always.patch
Patch6198:      backport-cgroup-don-t-emit-BPF-firewall-warning-when-manager-.patch
Patch6199:      backport-cryptenroll-fix-wrong-error-messages.patch
Patch6200:      backport-Bump-the-max-number-of-inodes-for-dev-to-128k.patch
Patch6201:      backport-fix-DirectoryNotEmpty-when-it-comes-to-a-Non-directo.patch
Patch6202:      backport-core-use-correct-level-for-CPU-time-log-message.patch
Patch6203:      backport-core-cgroup-set-bfq.weight-first-and-fixes-blkio.wei.patch
Patch6204:      backport-core-cgroup-use-helper-macro-for-bfq-conversion.patch
Patch6205:      backport-resolve-remove-server-large-level.patch
Patch6206:      backport-mkosi-Build-Fedora-35-images.patch
Patch6207:      backport-home-fix-heap-use-after-free.patch
Patch6208:      backport-journactl-show-info-about-journal-range-only-at-debu.patch
Patch6209:      backport-fstab-generator-do-not-remount-sys-when-running-in-a.patch
Patch6210:      backport-journal-remote-use-MHD_HTTP_CONTENT_TOO_LARGE-as-MHD.patch
Patch6211:      backport-repart-use-real-disk-start-end-for-bar-production.patch
Patch6212:      backport-machined-set-TTYPath-for-container-shell.patch
Patch6213:      backport-sd-journal-free-incomplete-match-on-failure.patch
Patch6214:      backport-sd-journal-fix-segfault-when-match_new-fails.patch
Patch6215:      backport-random-util-use-ssize_t-for-getrandom-return-value.patch
Patch6216:      backport-dbus-wait-for-jobs-add-extra_args-to-bus_wait_for_jo.patch
Patch6217:      backport-systemd-run-ensure-error-logs-suggest-to-use-user-wh.patch
Patch6218:      backport-sysusers-use-filename-if-proc-is-not-mounted.patch
Patch6219:      backport-nss-systemd-fix-required-buffer-size-calculation.patch
Patch6220:      backport-nss-systemd-fix-alignment-of-gr_mem.patch
Patch6221:      backport-nss-myhostname-do-not-apply-non-zero-offset-to-null-.patch
Patch6222:      backport-syscalls-update-syscall-definitions.patch
Patch6223:      backport-missing-syscall-add-__NR_openat2.patch
Patch6224:      backport-basic-log-allow-errno-values-higher-than-255.patch
Patch6225:      backport-backlight-ignore-error-if-the-backlight-device-is-al.patch
Patch6226:      backport-logind-do-not-propagate-error-in-delayed-action.patch
Patch6227:      backport-test-watchdog-mark-as-unsafe.patch
Patch6228:      backport-fstab-generator-skip-root-directory-handling-when-nf.patch
Patch6229:      backport-seccomp-move-arch_prctl-to-default.patch
Patch6230:      backport-boot-timestamps-Discard-firmware-init-time-when-runn.patch
Patch6231:      backport-CVE-2021-3997-rm-rf-refactor-rm_rf_children-split-out-body-of-dire.patch
Patch6232:      backport-CVE-2021-3997-rm-rf-optionally-fsync-after-removing-directory-tree.patch
Patch6233:      backport-CVE-2021-3997-tmpfiles-st-may-have-been-used-uninitialized.patch
Patch6234:      backport-CVE-2021-3997-shared-rm_rf-refactor-rm_rf_children_inner-to-shorte.patch
Patch6235:      backport-CVE-2021-3997-shared-rm_rf-refactor-rm_rf-to-shorten-code-a-bit.patch
Patch6236:      backport-CVE-2021-3997-shared-rm-rf-loop-over-nested-directories-instead-of.patch
Patch6237:      backport-nss-drop-dummy-setup_logging-helpers.patch
Patch6238:      backport-nss-only-read-logging-config-from-environment-variab.patch
Patch6239:      backport-fix-test-string-util-failed-when-locale-is-not-utf8.patch
Patch6240:      backport-policy-files-adjust-landing-page-link.patch
Patch6241:      backport-xdg-autostart-service-Ignore-missing-desktop-sepcifi.patch
Patch6242:      backport-journal-Skip-data-objects-with-invalid-offsets.patch
Patch6243:      backport-namespace-allow-ProcSubset-pid-with-some-ProtectKern.patch
Patch6244:      backport-sysext-use-LO_FLAGS_PARTSCAN-when-opening-image.patch
Patch6245:      backport-dissect-image-validate-extension-release-even-if-the.patch
Patch6246:      backport-core-refuse-to-mount-ExtensionImages-if-the-base-lay.patch
Patch6247:      backport-resolve-fix-assertion-triggered-when-r-0.patch
Patch6248:      backport-oomd-fix-race-with-path-unavailability-when-killing-.patch
Patch6249:      backport-oomd-handle-situations-when-no-cgroups-are-killed.patch
Patch6250:      backport-udevadm-cleanup_dir-use-dot_or_dot_dot.patch
Patch6251:      backport-udevadm-cleanup-db-don-t-delete-information-for-kept.patch
Patch6252:      backport-core-namespace-allow-using-ProtectSubset-pid-and-Pro.patch
Patch6253:      backport-core-namespace-s-normalize_mounts-drop_unused_mounts.patch
Patch6254:      backport-logind.conf-Fix-name-of-option-RuntimeDirectoryInode.patch
Patch6255:      backport-sd-dhcp-server-refuse-too-large-packet-to-send.patch
Patch6256:      backport-basic-mac_-selinux-smack-_apply_fd-does-not-work-whe.patch
Patch6257:      backport-sd-dhcp-lease-fix-an-infinite-loop-found-by-the-fuzz.patch
Patch6258:      backport-sd-dhcp-lease-fix-a-memory-leak-in-dhcp_lease_parse_.patch
Patch6259:      backport-core-don-t-fail-on-EEXIST-when-creating-mount-point.patch
Patch6260:      backport-bus-util-retrieve-bus-error-from-message.patch
Patch6261:      backport-core-unit-use-bus_error_message-at-one-more-place.patch
Patch6262:      backport-login-use-bus_error_message-at-one-more-place.patch
Patch6263:      backport-pid1-pass-PAM_DATA_SILENT-to-pam_end-in-child.patch
Patch6264:      backport-execute-use-_cleanup_-logic-where-appropriate.patch
Patch6265:      backport-execute-line-break-comments-a-bit-less-aggressively.patch
Patch6266:      backport-execute-document-that-the-env-param-is-input-and-out.patch
Patch6267:      backport-sd-dhcp-lease-fix-memleak.patch
Patch6269:      backport-util-another-set-of-CVE-2021-4034-assert-s.patch
Patch6270:      backport-resolve-fix-potential-memleak-and-use-after-free.patch
Patch6271:      backport-resolve-fix-possible-memleak.patch
Patch6272:      backport-resolve-use-_cleanup_-attribute-for-freeing-DnsQuery.patch
Patch6273:      backport-network-bridge-fix-endian-of-vlan-protocol.patch
Patch6274:      backport-basic-escape-add-helper-for-quoting-command-lines.patch
Patch6275:      backport-core-use-the-new-quoting-helper.patch
Patch6276:      backport-sd-bus-print-quoted-commandline-when-in-bus_socket_e.patch
Patch6277:      backport-sd-bus-print-debugging-information-if-bus_container_.patch
Patch6278:      backport-sd-bus-allow-numerical-uids-in-M-user-.host.patch
Patch6279:      backport-packit-remove-unsupported-Dcryptolib-openssl-option.patch
Patch6280:      backport-sd-device-silence-gcc-warning-with-newest-gcc.patch
Patch6281:      backport-packit-build-on-and-use-Fedora-35-spec-file.patch
Patch6282:      backport-ci-use-the-system-llvm-11-package-on-Focal.patch
Patch6283:      backport-resolve-refuse-AF_UNSPEC-when-resolving-address.patch
Patch6284:      backport-resolve-add-reference-of-the-original-bus-message-to.patch
Patch6285:      backport-ci-replace-apt-key-with-signed-by.patch
Patch6286:      backport-ci-fix-clang-13-installation.patch
Patch6287:      backport-tree-wide-mark-set-but-not-used-variables-as-unused-.patch
Patch6288:      backport-sd-dhcp-server-rename-server_send_nak-server_send_na.patch
Patch6289:      backport-packit-drop-unnumbered-patches-as-well.patch
Patch6290:      backport-dns-domain-re-introduce-dns_name_is_empty.patch
Patch6291:      backport-resolve-synthesize-empty-name.patch
Patch6292:      backport-resolve-synthesize-null-address-IPv4-broadcast-addre.patch
Patch6293:      backport-resolve-drop-never-matched-condition.patch
Patch6294:      backport-resolve-make-dns_scope_good_domain-take-DnsQuery.patch
Patch6295:      backport-resolve-synthesize-empty-domain-only-when-A-and-or-A.patch
Patch6296:      backport-pid1-watch-bus-name-always-when-we-have-it.patch
Patch6297:      backport-pid1-lookup-owning-PID-of-BusName-name-of-services-a.patch
Patch6298:      backport-docs-SYSTEMD_NSS_BYPASS_BUS-is-not-honoured-anymore-.patch
Patch6299:      backport-pid1-set-SYSTEMD_NSS_DYNAMIC_BYPASS-1-env-var-for-db.patch
Patch6300:      backport-systemctl-make-timestamp-affect-the-show-verb-as-wel.patch
Patch6301:      backport-core-really-skip-automatic-restart-when-a-JOB_STOP-j.patch
Patch6302:      backport-test-oomd-util-style-fixlets.patch
Patch6303:      backport-test-oomd-util-fix-conditional-jump-on-uninitialised.patch
Patch6304:      backport-test-fix-file-descriptor-leak-in-test-catalog.patch
Patch6305:      backport-test-fix-file-descriptor-leak-in-test-oomd-util.patch
Patch6306:      backport-test-fix-file-descriptor-leak-in-test-fs-util.patch
Patch6307:      backport-test-fix-file-descriptor-leak-in-test-tmpfiles.c.patch
Patch6308:      backport-test-fix-file-descriptor-leak-in-test-psi-util.patch
Patch6309:      backport-clang-format-we-actually-typically-use-16ch-continua.patch
Patch6310:      backport-test-journal-send-close-fd-opend-by-syslog.patch
Patch6311:      backport-journal-send-close-fd-on-exit-when-running-with-valg.patch
Patch6312:      backport-udev-builtin-input_id-don-t-label-absolute-mice-as-p.patch
Patch6313:      backport-mkosi-Remove-Arch-nspawn-workaround.patch
Patch6314:      backport-core-check-size-before-mmap.patch
Patch6315:      backport-devnode-acl-use-_cleanup_-to-free-acl_t.patch
Patch6316:      backport-dissect-image-add-extension-specific-validation-flag.patch
Patch6317:      backport-portabled-error-out-if-there-are-no-units-only-after.patch
Patch6318:      backport-portabled-validate-SYSEXT_LEVEL-when-attaching.patch
Patch6319:      backport-portabled-refactor-extraction-validation-into-a-comm.patch
Patch6320:      backport-portable-move-profile-search-helper-to-path-lookup.patch
Patch6321:      backport-portable-add-flag-to-return-extension-releases-in-Ge.patch
Patch6322:      backport-portablectl-reorder-if-branches-to-match-previous-co.patch
Patch6323:      backport-portable-inline-one-variable-declaration.patch
Patch6324:      backport-portable-add-return-parameter-to-GetImageMetadataWit.patch
Patch6325:      backport-wait-online-rename-Manager-elements.patch
Patch6326:      backport-journald-make-sure-SIGTERM-handling-doesn-t-get-star.patch
Patch6327:      backport-journal-file-if-we-are-going-down-don-t-use-event-lo.patch
Patch6328:      backport-kernel-install-also-remove-modules.builtin.alias.bin.patch
Patch6329:      backport-Bump-the-max-number-of-inodes-for-dev-to-a-million.patch
Patch6330:      backport-Bump-the-max-number-of-inodes-for-tmp-to-a-million-t.patch
Patch6331:      backport-unit-escape.patch
Patch6332:      backport-udev-rename-type-name-e.g.-struct-worker-Worker.patch
Patch6333:      backport-udev-run-the-main-process-workers-and-spawned-comman.patch
Patch6334:      backport-Add-meson-option-to-disable-urlify.patch
Patch6335:      backport-Revert-sysctl.d-switch-net.ipv4.conf.all.rp_filter-f.patch
Patch6336:      backport-login-drop-non-default-value-for-RuntimeDirectoryIno.patch
Patch6337:      backport-login-make-RuntimeDirectoryInodesMax-support-K-G-M-s.patch
Patch6338:      backport-virt-detect-OpenStack-Nova-instance.patch
Patch6339:      backport-Avoid-tmp-being-mounted-as-tmpfs-without-the-user-s-.patch
Patch6340:      backport-revert-delete-initrd-usr-fs-target.patch
Patch6341:      backport-journal-Only-move-to-objects-when-necessary.patch
Patch6342:      backport-sd-device-introduce-device_has_devlink.patch
Patch6343:      backport-udev-node-split-out-permission-handling-from-udev_no.patch
Patch6344:      backport-udev-node-stack-directory-must-exist-when-adding-dev.patch
Patch6345:      backport-udev-node-save-information-about-device-node-and-pri.patch
Patch6346:      backport-udev-node-always-update-timestamp-of-stack-directory.patch
Patch6347:      backport-udev-node-assume-no-new-claim-to-a-symlink-if-run-ud.patch
Patch6348:      backport-udev-node-always-atomically-create-symlink-to-device.patch
Patch6349:      backport-udev-node-check-stack-directory-change-even-if-devli.patch
Patch6350:      backport-udev-node-shorten-code-a-bit-and-update-log-message.patch
Patch6351:      backport-udev-node-add-random-delay-on-conflict-in-updating-d.patch
Patch6352:      backport-udev-node-drop-redundant-trial-of-devlink-creation.patch
Patch6353:      backport-udev-node-simplify-the-example-of-race.patch
Patch6354:      backport-udev-node-do-not-ignore-unexpected-errors-on-removin.patch
Patch6355:      backport-calendarspec-fix-possibly-skips-next-elapse.patch
Patch6356:      backport-macro-account-for-negative-values-in-DECIMAL_STR_WID.patch
Patch6357:      backport-core-command-argument-can-be-longer-than-PATH_MAX.patch
Patch6358:      backport-hwdb-fix-parsing-options.patch
Patch6359:      backport-sd-bus-fix-buffer-overflow.patch
Patch6360:      backport-temporarily-disable-test-seccomp.patch
Patch6362:      backport-meson.build-change-operator-combining-bools-from-to-.patch
Patch6363:      backport-core-replace-slice-dependencies-as-they-get-added.patch
Patch6364:      backport-scsi_id-retry-inquiry-ioctl-if-host_byte-is-DID_TRAN.patch
Patch6365:      backport-revert-units-add-ProtectClock-yes.patch
Patch6366:      backport-fix-CVE-2022-3821.patch
Patch6367:      backport-CVE-2022-4415-test-Create-convenience-macros-to-declare-tests.patch
Patch6368:      backport-CVE-2022-4415-test-Slightly-rework-DEFINE_TEST_MAIN-macros.patch
Patch6369:      backport-CVE-2022-4415-test-Add-TEST_RET-macro.patch
Patch6370:      backport-CVE-2022-4415-test-Add-sd_booted-condition-test-to-TEST-macro.patch
Patch6371:      backport-CVE-2022-4415-basic-add-STRERROR-wrapper-for-strerror_r.patch
Patch6372:      backport-CVE-2022-4415-tree-wide-define-and-use-STRERROR_OR_EOF.patch
Patch6373:      backport-coredump-Fix-format-string-type-mismatch.patch
Patch6374:      backport-coredump-drop-an-unused-variable.patch
Patch6375:      backport-CVE-2022-4415-coredump-adjust-whitespace.patch
Patch6376:      backport-CVE-2022-4415-dont-allow-user-access-coredumps-with-changed-uid.patch
Patch6377:      backport-dns-domain-make-each-label-nul-terminated.patch
Patch6378:      backport-resolve-fix-heap-buffer-overflow-reported-by-ASAN-wi.patch
Patch6379:      backport-sd-bus-do-not-pass-NULL-when-received-message-with-i.patch
Patch6380:      backport-growfs-don-t-actually-resize-on-dry-run.patch
Patch6381:      backport-stat-util-replace-is_dir-is_dir_fd-by-single-is_dir_.patch
Patch6382:      backport-tmpfiles-check-the-directory-we-were-supposed-to-cre.patch
Patch6383:      backport-coredump-Connect-stdout-stderr-to-dev-null-before-do.patch
Patch6384:      backport-cgroups-agent-connect-stdin-stdout-stderr-to-dev-nul.patch
Patch6385:      backport-unit-file-avoid-null-in-debugging-logs.patch
Patch6386:      backport-resolve-mdns_packet_extract_matching_rrs-may-return-.patch
Patch6387:      backport-dhcp-fix-potential-buffer-overflow.patch
Patch6388:      backport-sd-device-monitor-actually-refuse-to-send-invalid-de.patch
Patch6389:      backport-sysusers-add-fsync-for-passwd-24324.patch
Patch6390:      backport-condition-fix-device-tree-firmware-path.patch
Patch6391:      backport-log-don-t-attempt-to-duplicate-closed-fd.patch
Patch6392:      backport-mount-util-fix-error-code.patch
Patch6393:      backport-analyze-add-forgotten-return-statement.patch
Patch6394:      backport-shared-condition-avoid-nss-lookup-in-PID1.patch
Patch6395:      backport-logind-fix-getting-property-OnExternalPower-via-D-Bu.patch
Patch6396:      backport-udev-support-by-path-devlink-for-multipath-nvme-bloc.patch

Patch9001:      update-rtc-with-system-clock-when-shutdown.patch
Patch9002:      udev-add-actions-while-rename-netif-failed.patch
Patch9003:      fix-two-VF-virtual-machines-have-same-mac-address.patch
Patch9004:      logind-set-RemoveIPC-to-false-by-default.patch
Patch9005:      rules-add-rule-for-naming-Dell-iDRAC-USB-Virtual-NIC.patch
Patch9006:      unit-don-t-add-Requires-for-tmp.mount.patch
Patch9007:      rules-add-elevator-kernel-command-line-parameter.patch
Patch9008:      rules-add-the-rule-that-adds-elevator-kernel-command.patch
Patch9009:      units-add-Install-section-to-tmp.mount.patch
Patch9010:      Make-systemd-udevd.service-start-after-systemd-remou.patch
Patch9011:      udev-virsh-shutdown-vm.patch
Patch9012:      sd-bus-properly-initialize-containers.patch
Patch9013:      Revert-core-one-step-back-again-for-nspawn-we-actual.patch
Patch9014:      journal-don-t-enable-systemd-journald-audit.socket-b.patch
Patch9015:      systemd-change-time-log-level.patch
Patch9016:      fix-capsh-drop-but-ping-success.patch
Patch9017:      resolved-create-etc-resolv.conf-symlink-at-runtime.patch
Patch9018:      pid1-bump-DefaultTasksMax-to-80-of-the-kernel-pid.ma.patch
Patch9019:      fix-journal-file-descriptors-leak-problems.patch
Patch9020:      activation-service-must-be-restarted-when-reactivated.patch
Patch9021:      systemd-core-fix-problem-of-dbus-service-can-not-be-started.patch
Patch9022:      delay-to-restart-when-a-service-can-not-be-auto-restarted.patch
Patch9023:      disable-initialize_clock.patch
Patch9024:      systemd-solve-that-rsyslog-reads-journal-s-object-of.patch
Patch9025:      check-whether-command_prev-is-null-before-assigning-.patch
Patch9027:      core-skip-change-device-to-dead-in-manager_catchup-d.patch
Patch9028:      revert-rpm-restart-services-in-posttrans.patch
Patch9029:      Don-t-set-AlternativeNamesPolicy-by-default.patch
Patch9030:      change-NTP-server-to-x.pool.ntp.org.patch
Patch9031:      keep-weight-consistent-with-the-set-value.patch
Patch9032:      Systemd-Add-sw64-architecture.patch
%ifarch loongarch64
Patch9033:	0029-Add-support-for-the-LoongArch-architecture.patch
Patch9034:	0030-Add-LoongArch-dmi-virt-detection-and-testcase.patch
Patch9035:	add-loongarch-for-missing_syscall_def.patch
%endif
Patch9036:      core-update-arg_default_rlimit-in-bump_rlimit.patch
Patch9037:      set-forwardtowall-no-to-avoid-emerg-log-shown-on-she.patch
Patch9038:      core-cgroup-support-cpuset.patch
Patch9039:      core-cgroup-support-freezer.patch
Patch9040:      core-cgroup-support-memorysw.patch
Patch9041:      systemd-core-Add-new-rules-for-lower-priority-events.patch
Patch9042:      bugfix-also-stop-machine-when-a-machine-un.patch
Patch9043:      print-the-process-status-to-console-when-shutdown.patch
Patch9044:      Retry-to-handle-the-uevent-when-worker-is-terminated.patch
Patch9045:      treat-hyphen-as-valid-hostname-char.patch
Patch9046:      process-util-log-more-information-when-runnin.patch
Patch9047:      fuser-print-umount-message-to-reboot-umount-msg.patch
Patch9048:      shutdown-reboot-when-recieve-crash-signal.patch
Patch9049:      core-add-OptionalLog-to-allow-users-change-log-level.patch
Patch9050:      core-cgroup-support-default-slice-for-all-uni.patch
Patch9051:      core-add-invalidate-cgroup-config.patch
Patch9052:      let-the-child-of-one-unit-don-t-affect-each-other.patch
Patch9053:      support-disable-cgroup-controllers-we-don-t-want.patch
Patch9054:      fix-mount-failed-while-daemon-reexec.patch
Patch9055:      bugfix-for-cgroup-Swap-cgroup-v1-deletion-and-migration.patch
Patch9056:      delete-journal-files-except-system.journal-when-jour.patch

BuildRequires:  gcc, gcc-c++
BuildRequires:  libcap-devel, libmount-devel, pam-devel, libselinux-devel
BuildRequires:  audit-libs-devel, dbus-devel, libacl-devel
BuildRequires:  gobject-introspection-devel, libblkid-devel, xz-devel, xz
BuildRequires:  lz4-devel, lz4, bzip2-devel, libidn2-devel
BuildRequires:  kmod-devel, libgcrypt-devel, libgpg-error-devel
BuildRequires:  gnutls-devel, libxkbcommon-devel
BuildRequires:  iptables-devel, docbook-style-xsl, pkgconfig, libxslt, gperf
BuildRequires:  gawk, tree, hostname, git, meson >= 0.43, gettext, dbus >= 1.9.18
BuildRequires:  python3-devel, python3-lxml, firewalld-filesystem, libseccomp-devel
BuildRequires:  python3-jinja2

%ifarch %{valgrind_arches}
%ifnarch loongarch64
BuildRequires:  valgrind-devel
%endif
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

This package contains machinectl, systemd-machined.

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

%package_help

%prep
%autosetup -n %{name}-%{version} -p1 -Sgit
%ifnarch sw_64
%patch9032 -R -p1
%endif

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
        -Dsmack=false
        -Dgcrypt=true
        -Daudit=true
        -Delfutils=false
        -Dlibcryptsetup=false
        -Dqrencode=false
        -Dgnutls=true
        -Dmicrohttpd=false
        -Dlibidn2=true
        -Dlibidn=false
        -Dlibiptc=false
        -Dlibcurl=false
        -Defi=true
        -Dtpm=false
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
        -Ddefault-dnssec=allow-downgrade
        # https://bugzilla.redhat.com/show_bug.cgi?id=1867830
        -Ddefault-mdns=yes
        -Ddefault-llmnr=yes
        -Dhtml=false
        -Dlibfido2=false
        -Dopenssl=false
        -Dpwquality=false
        -Dtpm2=false
        -Dzstd=false
        -Dbpf-framework=false
        -Drepart=false
        -Dcompat-mutable-uid-boundaries=false
        -Dvalgrind=false
        -Dfexecve=false
        -Dstandalone-binaries=false
        -Dstatic-libsystemd=false
        -Dstatic-libudev=false
        -Dfirstboot=false
        -Dsysext=false
        -Dhomed=false
        -Dgnu-efi=false
        -Dquotacheck=false
        -Dxdg-autostart=false
        -Dimportd=false
        -Dbacklight=false
        -Drfkill=false
        -Dpstore=false
        -Dportabled=false
        -Doomd=false
        -Duserdb=false
        -Dtime-epoch=0
        -Dmode=release
        -Durlify=false
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
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/linger
mkdir -p %{buildroot}%{_localstatedir}/lib/private
mkdir -p %{buildroot}%{_localstatedir}/log/private
mkdir -p %{buildroot}%{_localstatedir}/cache/private
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/timesync
mkdir -p %{buildroot}%{_localstatedir}/log/journal
touch %{buildroot}%{_localstatedir}/lib/systemd/catalog/database
touch %{buildroot}%{_sysconfdir}/udev/hwdb.bin
touch %{buildroot}%{_localstatedir}/lib/systemd/random-seed
touch %{buildroot}%{_localstatedir}/lib/systemd/timesync/clock

# Install yum protection fragment
install -Dm0644 %{SOURCE4} %{buildroot}/etc/dnf/protected.d/systemd.conf

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

install -m 0644 %{SOURCE100} %{buildroot}/%{_udevrulesdir}/40-%{vendor}.rules

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
%ifnarch loongarch64
%ninja_test -C %{_vpath_builddir}
%endif

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

%global udev_services systemd-udev{d,-settle,-trigger}.service systemd-udevd-{control,kernel}.socket

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

%files -f %{name}.lang
%doc %{_pkgdocdir}
%exclude %{_pkgdocdir}/LICENSE.*
%exclude %{_systemddir}/systemd-bless-boot
%exclude %{_unitdir}/systemd-bless-boot.service
%exclude %{_systemddir}/system-generators/systemd-bless-boot-generator
%exclude %{_unitdir}/systemd-boot-system-token.service
%exclude %{_unitdir}/sysinit.target.wants/systemd-boot-system-token.service
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
/usr/share/dbus-1/system-services/org.freedesktop.login1.service
/usr/share/dbus-1/system-services/org.freedesktop.locale1.service
/usr/share/dbus-1/system-services/org.freedesktop.hostname1.service
/usr/share/dbus-1/system-services/org.freedesktop.timedate1.service
/usr/share/dbus-1/system.d/org.freedesktop.timedate1.conf
/usr/share/dbus-1/system.d/org.freedesktop.hostname1.conf
/usr/share/dbus-1/system.d/org.freedesktop.login1.conf
/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf
/usr/share/dbus-1/system.d/org.freedesktop.locale1.conf
/usr/share/pkgconfig/systemd.pc
/usr/share/pkgconfig/udev.pc
/usr/share/polkit-1/actions/org.freedesktop.hostname1.policy
/usr/share/polkit-1/actions/org.freedesktop.timedate1.policy
/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy
/usr/share/polkit-1/actions/org.freedesktop.login1.policy
/usr/share/polkit-1/actions/org.freedesktop.locale1.policy
/usr/bin/systemd-machine-id-setup
/usr/bin/localectl
/usr/bin/systemd-path
/usr/bin/systemd-run
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
/usr/bin/coredumpctl
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
%{_systemddir}/systemd-user-sessions
%{_systemddir}/systemd-sysctl
%{_systemddir}/systemd-socket-proxyd
%{_systemddir}/systemd-ac-power
%{_systemddir}/systemd-hostnamed
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
%{_systemddir}/systemd-fsck
%{_systemddir}/systemd-timedated
%dir %{_systemddir}/user-generators
%{_systemddir}/systemd
%dir %{_systemddir}/user-preset
%{_systemddir}/systemd-coredump
%{_systemddir}/systemd-network-generator
%{_systemddir}/systemd-binfmt
%{_systemddir}/user-preset/90-systemd.preset
%{_unitdir}/systemd-binfmt.service
%{_unitdir}/systemd-machine-id-commit.service
%dir %{_unitdir}/basic.target.wants
%{_unitdir}/systemd-coredump.socket
%{_unitdir}/systemd-coredump@.service
%{_unitdir}/ctrl-alt-del.target
%{_unitdir}/systemd-tmpfiles-setup.service
%{_unitdir}/rpcbind.target
%{_unitdir}/systemd-update-done.service
%{_unitdir}/dev-hugepages.mount
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
%{_unitdir}/sysinit.target.wants/proc-sys-fs-binfmt_misc.automount
%{_unitdir}/sysinit.target.wants/systemd-ask-password-console.path
%{_unitdir}/sysinit.target.wants/sys-kernel-debug.mount
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
%{_unitdir}/sockets.target.wants/systemd-journald-dev-log.socket
%{_unitdir}/sockets.target.wants/systemd-journald.socket
%{_unitdir}/sockets.target.wants/systemd-initctl.socket
%{_unitdir}/sockets.target.wants/systemd-coredump.socket
%{_unitdir}/blockdev@.target
%{_unitdir}/sys-kernel-tracing.mount
%{_unitdir}/sysinit.target.wants/sys-kernel-tracing.mount
%{_unitdir}/systemd-journald-varlink@.socket
%{_unitdir}/systemd-journald@.service
%{_unitdir}/systemd-journald@.socket
%{_unitdir}/modprobe@.service
%{_systemddir}/system-generators/systemd-fstab-generator
%{_systemddir}/system-generators/systemd-sysv-generator
%{_systemddir}/system-generators/systemd-rc-local-generator
%{_systemddir}/system-generators/systemd-debug-generator
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
/usr/lib/sysctl.d/50-default.conf
/usr/lib/sysctl.d/50-pid-max.conf
/usr/lib/sysctl.d/50-coredump.conf
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
%config(noreplace) /etc/systemd/coredump.conf
%dir /etc/systemd/system
%config(noreplace) /etc/systemd/system.conf
%ghost %config(noreplace) /etc/X11/xorg.conf.d/00-keyboard.conf
%config(noreplace) /etc/X11/xinit/xinitrc.d/50-systemd-user.sh
%config(noreplace) /etc/pam.d/systemd-user
/usr/lib/pam.d/systemd-user
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
/usr/lib/modprobe.d/README
/usr/lib/sysctl.d/README
/usr/lib/systemd/system/first-boot-complete.target
/usr/lib/systemd/user/app.slice
/usr/lib/systemd/user/background.slice
/usr/lib/systemd/user/session.slice
/usr/lib/sysusers.d/README
/usr/lib/tmpfiles.d/README
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
%exclude /usr/share/bash-completion/completions/kernel-install
%exclude /usr/share/zsh/site-functions/_kernel-install
%exclude /usr/bin/kernel-install
%exclude /usr/lib/kernel/install.d/00-entry-directory.install
%exclude /usr/lib/kernel/install.d/90-loaderentry.install
%exclude /usr/lib/kernel/install.d/50-depmod.install
%exclude /usr/lib/kernel/install.d/20-grubby.install
%exclude %dir /etc/kernel/install.d
%exclude %dir /etc/kernel
%exclude %dir /usr/lib/kernel
%exclude %dir /usr/lib/kernel/install.d
%exclude /usr/bin/bootctl
%exclude /usr/share/zsh/site-functions/_bootctl
%exclude /usr/share/bash-completion/completions/bootctl
%exclude %{_unitdir}/usb-gadget.target
%ghost /var/lib/systemd/random-seed
/etc/modules-load.d
/usr/sbin/udevadm
/usr/share/bash-completion/completions/udevadm
/usr/share/zsh/site-functions/_udevadm
/usr/bin/systemd-hwdb
/usr/bin/udevadm
%dir /usr/lib/modprobe.d
%dir /usr/lib/udev
%dir /usr/lib/modules-load.d
%{_systemddir}/systemd-growfs
%{_systemddir}/systemd-modules-load
%dir %{_systemddir}/system-sleep
%{_systemddir}/systemd-makefs
%{_systemddir}/systemd-remount-fs
%{_systemddir}/systemd-hibernate-resume
%{_systemddir}/systemd-random-seed
%{_systemddir}/systemd-sleep
%{_systemddir}/systemd-udevd
%{_systemddir}/systemd-vconsole-setup
%{_unitdir}/systemd-udevd.service
%{_unitdir}/initrd-udevadm-cleanup-db.service
%{_unitdir}/systemd-suspend.service
%{_unitdir}/suspend-then-hibernate.target
%{_unitdir}/systemd-modules-load.service
%{_unitdir}/systemd-tmpfiles-setup-dev.service
%{_unitdir}/systemd-vconsole-setup.service
%{_unitdir}/systemd-hibernate.service
%dir %{_unitdir}/systemd-udev-trigger.service.d
%{_unitdir}/systemd-random-seed.service
%{_unitdir}/systemd-udevd-control.socket
%{_unitdir}/hibernate.target
%{_unitdir}/systemd-remount-fs.service
%{_unitdir}/suspend.target
%{_unitdir}/systemd-hybrid-sleep.service
%{_unitdir}/systemd-suspend-then-hibernate.service
%{_unitdir}/hybrid-sleep.target
%{_unitdir}/systemd-hwdb-update.service
%{_unitdir}/systemd-hibernate-resume@.service
%{_unitdir}/systemd-udev-settle.service
%{_unitdir}/sleep.target
%{_unitdir}/kmod-static-nodes.service
%{_unitdir}/systemd-udevd-kernel.socket
%{_unitdir}/systemd-udev-trigger.service
%{_unitdir}/sysinit.target.wants/systemd-udevd.service
%{_unitdir}/sysinit.target.wants/systemd-modules-load.service
%{_unitdir}/sysinit.target.wants/systemd-tmpfiles-setup-dev.service
%{_unitdir}/sysinit.target.wants/systemd-random-seed.service
%{_unitdir}/sysinit.target.wants/systemd-hwdb-update.service
%{_unitdir}/sysinit.target.wants/kmod-static-nodes.service
%{_unitdir}/sysinit.target.wants/systemd-udev-trigger.service
%{_unitdir}/systemd-udev-trigger.service.d/systemd-udev-trigger-no-reload.conf
%{_unitdir}/sockets.target.wants/systemd-udevd-control.socket
%{_unitdir}/sockets.target.wants/systemd-udevd-kernel.socket
%{_systemddir}/system-generators/systemd-hibernate-resume-generator
%{_systemddir}/system-generators/systemd-gpt-auto-generator
%{_systemddir}/network/99-default.link
/usr/lib/udev/v4l_id
/usr/lib/udev/ata_id
/usr/lib/udev/cdrom_id
/usr/lib/udev/mtd_probe
/usr/lib/udev/scsi_id
/usr/lib/udev/fido_id
%ifnarch sw_64 riscv64
/usr/lib/udev/dmi_memory_id
%endif

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
%{_udevhwdbdir}/20-dmi-id.hwdb
%{_udevhwdbdir}/60-autosuspend-fingerprint-reader.hwdb
%{_udevhwdbdir}/60-seat.hwdb
%{_udevhwdbdir}/80-ieee1394-unit-function.hwdb
%{_udevhwdbdir}/README

%dir /usr/lib/udev/rules.d
%{_udevrulesdir}/60-autosuspend.rules
%{_udevrulesdir}/40-%{vendor}.rules
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
%{_udevrulesdir}/81-net-dhcp.rules
%ifnarch sw_64 riscv64
%{_udevrulesdir}/70-memory.rules
%endif
%{_udevrulesdir}/README

/usr/lib/modprobe.d/systemd.conf
%ghost %config(noreplace) /etc/vconsole.conf
%dir /etc/udev
%dir /etc/kernel
%config(noreplace) /etc/systemd/sleep.conf
%ghost /etc/udev/hwdb.bin
%dir /etc/udev/rules.d
%config(noreplace) /etc/udev/udev.conf
%dir /etc/udev/hwdb.d

%files container
/usr/share/bash-completion/completions/machinectl
/usr/share/zsh/site-functions/_machinectl
/usr/share/dbus-1/system-services/org.freedesktop.machine1.service
/usr/share/dbus-1/services/org.freedesktop.systemd1.service
/usr/share/dbus-1/system-services/org.freedesktop.systemd1.service
/usr/share/dbus-1/system.d/org.freedesktop.machine1.conf
/usr/share/polkit-1/actions/org.freedesktop.machine1.policy
%{_libdir}/libnss_mymachines.so.2
/usr/bin/machinectl
%{_systemddir}/systemd-machined
%{_unitdir}/systemd-machined.service
%{_unitdir}/var-lib-machines.mount
%{_unitdir}/dbus-org.freedesktop.machine1.service
%{_unitdir}/machine.slice
%{_unitdir}/machines.target
%dir %{_unitdir}/machines.target.wants
%{_unitdir}/machines.target.wants/var-lib-machines.mount
%{_unitdir}/remote-fs.target.wants/var-lib-machines.mount
%{_systemddir}/network/80-vm-vt.network

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
%{_systemddir}/network/80-wifi-adhoc.network
%{_systemddir}/network/80-wifi-ap.network.example
%{_systemddir}/network/80-wifi-station.network.example

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

%changelog
* Tue Mar 7 2023 wangyuhang <wangyuhang27@huawei.com> -249-48
- fix symlinks to NVMe drives are missing in /dev/disk/by-path

* Tue Feb 28 2023 misaka00251 <liuxin@iscas.ac.cn> -249-47
- Exclude riscv64 unsupported files for now, might add them back later

* Thu Jan 19 2023 yangmingtai <yangmingtai@huawei.com> -249-46
- delete unused patch files

* Fri Jan 13 2023 yangmingtai <yangmingtai@huawei.com> -249-45
- backport patches from upstream and add patchs to enhance compatibility
  and features

* Wed Dec 28 2022 huyubiao<huyubiao@huawei.com> - 249-44
- fix CVE-2022-4415

* Mon Dec 12 2022 huajingyun<huajingyun@loongson.cn> - 249-43
- Add loongarch for missing_syscall_def.h

* Wed Nov 23 2022 yangmingtai <yangmingtai@huawei.com> -249-42
- 1.change /etc/systemd/journald.conf ForwardToWall to no
  2.change DefaultLimitMEMLOCK to 64M
  3.replace openEuler to vendor
  4.delete useless file udev-61-openeuler-persistent-storage.rules

* Tue Nov 15 2022 huajingyun<huajingyun@loongson.cn> - 249-41
- Add loongarch64 architecture

* Mon Nov 7 2022 yangmingtai <yangmingtai@huawei.com> -249-40
- fix CVE-2022-3821

* Thu Oct 27 2022 wuzx<wuzx1226@qq.com> - 249-39
- Add sw64 architecture

* Mon Oct 10 2022 wangyuhang <wangyuhang27@huawei.com> -249-38
- backport: sync systemd-stable-249 patches from systemd community

* Thu Sep 29 2022 yangmingtai <yangmingtai@huawei.com> -249-37
- 1.change default ntp server
  2.correct the default value of RuntimeDirectoryInodesMax

* Fri Sep 16 2022 yangmingtai <yangmingtai@huawei.com> -249-36
- revert:delete the initrd-usr-fs.target

* Wed Sep 14 2022 xujing <xujing125@huawei.com> -249-35
- revert add ProtectClock=yes

* Fri Sep 2 2022 Wenchao Hao <haowenchao@huawei.com> -249-34
- scsi_id: retry inquiry ioctl if host_byte is DID_TRANSPORT_DISRUPTED

* Thu Sep 1 2022 hongjinghao<hongjinghao@huawei.com> - 249-33
- 1. Don't set AlternativeNamesPolicy by default
  2. fix systemd-journald coredump

* Tue Aug 02 2022 zhukeqian<zhukeqian1@huawei.com> -249-32
- core: replace slice dependencies as they get added

* Wed Jun 22 2022 zhangyao<zhangyao108@huawei.com> -249-31
- fix don't preset systemd-timesyncd when install systemd-udev

* Tue Jun 21 2022 zhangyao<zhangyao108@huawei.com> -249-30
- fix Avoid /tmp being mounted as tmpfs without the user's will

* Tue Jun 21 2022 wangyuhang<wangyuhang27@huawei.com> -249-29
- fix build fail on meson-0.6
  1. delete invalid meson build option
  2. meson.build: change operator combining bools from + to and

* Fri Jun 17 2022 wangyuhang<wangyuhang27@huawei.com> -249-28
- revert rpm: restart services in %posttrans
  fix spelling errors in systemd.spec, fdev -> udev

* Wed Jun 01 2022 licunlong<licunlong1@huawei.com> -249-27
- move udev{rules, hwdb, program} to systemd-udev.

* Mon Apr 18 2022 xujing <xujing99@huawei.com> - 249-26
- rename patches name and use patch from upstream

* Tue Apr 12 2022 xujing <xujing99@huawei.com> - 249-25
- core: skip change device to dead in manager_catchup during booting

* Tue Apr 12 2022 xujing <xujing99@huawei.com> - 249-24
- print the real reason for link update

* Tue Apr 12 2022 xujing <xujing99@huawei.com> - 249-23
- check whether command_prev is null before assigning value

* Mon Apr 11 2022 xujing <xujing99@huawei.com> - 249-22
- solve that rsyslog reads journal's object of size 0

* Mon Apr 11 2022 xujing <xujing99@huawei.com> - 249-21
- disable initialize_clock

* Fri Apr 8 2022 xujing <xujing99@huawei.com> - 249-20
- fix name of option: RuntimeDirectoryInodes

* Fri Apr 8 2022 wangyuhang <wangyuhang27@huawei.com> - 249-19
- set dnssec to be allow-downgrade by default
  set mdns to be yes by default
  set llmnr to be yes by default

* Sat Apr 2 2022 xujing <xujing99@huawei.com> - 249-18
- set urlify to be disabled by default

* Thu Mar 31 2022 xujing <xujing99@huawei.com> - 249-17
- set DEFAULT_TASKS_MAX to 80% and set mode to release

* Wed Mar 23 2022 xujing <xujing99@huawei.com> - 249-16
- systemd-journald: Fix journal file descriptors leak problems.
  systemd: Activation service must be restarted when it is already started and re-actived by dbus
  systemd-core: fix problem of dbus service can not be started
  systemd-core: Delay to restart when a service can not be auto-restarted when there is one STOP_JOB for the service
  core: fix SIGABRT on empty exec command argv
  journalctl: never fail at flushing when the flushed flag is set
  timesync: fix wrong type for receiving timestamp in nanoseconds
  udev: fix potential memleak

* Fri Mar 18 2022 yangmingtai <yangmingtai@huawei.com> - 249-15
- fix systemctl reload systemd-udevd failed

* Thu Mar 17 2022 xujing <xujing99@huawei.com> - 249-14
- pid1 bump DefaultTasksMax to 80% of the kernel pid.max value

* Thu Mar 17 2022 xujing <xujing99@huawei.com> - 249-13
- allow more inodes in /dev an /tmp

* Fri Mar 11 2022 yangmingtai <yangmingtai@huawei.com> - 249-12
- disable some features

* Thu Mar 10 2022 xujing <xujing99@huawei.com> - 249-11
- core: use empty_to_root for cgroup path in log messages

* Tue Mar 1 2022 yangmingtai <yangmingtai@huawei.com> - 249-10
- revert :core map io.bfq.weight to 1..1000

* Tue Mar 1 2022 duyiwei <duyiwei@kylinos.cn> - 249-9
- change %systemd_requires to %{?systemd_requires}

* Tue Feb 22 2022 xujing <xujing99@huawei.com> - 249-8
- temporarily disable test-seccomp and ensure some features disabled

* Tue Feb 15 2022 yangmingtai <yangmingtai@huawei.com> - 249-7
- disable rename function of net interface

* Tue Feb 15 2022 yangmingtai <yangmingtai@huawei.com> - 249-6
- nop_job of a unit must also be coldpluged after deserization

* Tue Feb 15 2022 yangmingtai <yangmingtai@huawei.com> - 249-5
- fix CVE-2021-3997 and CVE-2021-33910

* Tue Feb 8 2022 yangmingtai <yangmingtai@huawei.com> - 249-4
- fix ConditionDirectoryNotEmpty,ConditionPathIsReadWrite and DirectoryNotEmpty

* Tue Feb 8 2022 yangmingtai <yangmingtai@huawei.com> - 249-3
- do not make systemd-cpredump sub packages

* Mon Dec 27 2021 yangmingtai <yangmingtai@huawei.com> - 249-2
- delete useless Provides and Obsoletes

* Wed Dec 8 2021 yangmingtai <yangmingtai@huawei.com> - 249-1
- systemd update to v249

* Tue Dec 28 2021 licunlong <licunlong1@huawei.com> - 248-15
- fix typo: disable not denable.

* Wed Dec 01 2021 licunlong <licunlong1@huawei.com> - 248-14
- disable systemd-{timesyncd, networkd, resolved} by default

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

* Thu Jul 22 2021 yangmingtai <yangmingtai@huawei.com> - 248-7
- fix CVE-2021-33910

* Thu Jun 03 2021 shenyangyang <shenyangyang4@huawei.com> - 248-6
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

* Sat Aug 01 2020 openEuler Buildteam <buildteam@openeuler.org> - 246-3
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

Name:           lh-dmverity-builder
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-dmverity - Level-by-Level SHA-256 Merkle Hash Tree Hierarchy
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dmverity-builder
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Memory-safe pure-Rust (#![forbid(unsafe_code)]) Linux dm-verity SHA-256 Merkle tree builder, 512-byte v1 superblock serializer, inclusion proof verifier, and 10-rule immutable rootfs posture auditor.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-dmverity ]; then
    install -m 0755 bin/lh-dmverity %{buildroot}%{_bindir}/lh-dmverity
elif [ -f lh-dmverity ]; then
    install -m 0755 lh-dmverity %{buildroot}%{_bindir}/lh-dmverity
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-dmverity-builder.

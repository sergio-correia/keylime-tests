#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

rlJournalStart

    rlPhaseStartTest "Enable repo and install rust keylime RPMs"
        rpm -q keylime-agent-rust && rlRun "yum -y remove keylime-agent-rust"
        # backup previous config file
        [ -f /etc/keylime/agent.conf ] && rlRun "mv /etc/keylime/agent.conf /etc/keylime/agent.conf.backup$$"
        rlRun 'cat > /etc/yum.repos.d/copr-rust-keylime-master.repo <<_EOF
[copr-rust-keylime-master]
name=Copr repo for keylime-rust-keylime-master owned by packit
baseurl=https://download.copr.fedorainfracloud.org/results/packit/keylime-rust-keylime-master/fedora-\$releasever-\$basearch/
type=rpm-md
skip_if_unavailable=True
gpgcheck=1
gpgkey=https://download.copr.fedorainfracloud.org/results/packit/keylime-rust-keylime-master/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
priority=1
_EOF'
        if rlIsRHELLike; then
            rlRun "sed -i 's|keylime-rust-keylime-master/fedora|keylime-rust-keylime-master/centos-stream|' /etc/yum.repos.d/copr-rust-keylime-master.repo"
        fi
        rlRun "yum -y install keylime-agent-rust"
        rlAssertRpm keylime-agent-rust
        rlAssertExists /etc/keylime/agent.conf
        # prepare directory for drop-in adjustments
        rlRun "mkdir -p /etc/systemd/system/keylime_agent.service.d"
        rlRun "mkdir -p /etc/keylime/agent.conf.d"
    rlPhaseEnd

    rlPhaseStartTest "Test installed binaries"
        rlRun "keylime_agent --help" 0,1
    rlPhaseEnd

rlJournalEnd

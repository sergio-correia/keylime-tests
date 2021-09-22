#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

rlJournalStart

    rlPhaseStartSetup "Install TPM emulator"
        # configure Sergio's copr repo providing necessary dependencies
        rlRun 'cat > /etc/yum.repos.d/keylime.repo <<_EOF
[copr:copr.devel.redhat.com:scorreia:keylime]
name=Copr repo for keylime owned by scorreia
baseurl=http://coprbe.devel.redhat.com/results/scorreia/keylime/rhel-9.dev-\$basearch/
type=rpm-md
skip_if_unavailable=True
gpgcheck=0
gpgkey=http://coprbe.devel.redhat.com/results/scorreia/keylime/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
_EOF'
        rlRun "yum -y install ibmswtpm2 cfssl"
        # update to fixed tpm2-tss
        rlRun "rpm -Fvh http://download.eng.bos.redhat.com/brewroot/vol/rhel-9/packages/tpm2-tss/3.0.3/6.el9/x86_64/tpm2-tss-3.0.3-6.el9.x86_64.rpm"
    rlPhaseEnd

    rlPhaseStartSetup "Start TPM emulator"
        export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
        rlLogInfo "exported TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI"
        rlServiceStart ibm-tpm-emulator
    rlPhaseEnd

    rlPhaseStartTest "Test TPM emulator"
        rlRun -s "tpm2_pcrread"
        rlAssertGrep "0 : 0x0000000000000000000000000000000000000000" $rlRun_LOG
        rlServiceStop ibm-tpm-emulator
    rlPhaseEnd

rlJournalEnd

#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/keylime/Multihost/basic-attestation
#   Description: tests basic keylime attestation scenario using multiple hosts
#   Author: Karel Srot <ksrot@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2021 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
#. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

# The following roles are expected to be assigned during test scheduling
# VERIFIER
# REGISTRAT
# AGENT
# assigned hostnames should be available in environment variables
# of the respective name


# updates /etc/keylime.conf
# params: SECTION_NAME KEY NEW_VALUE SED_FLAGS
function limeUpdateConf() {
  sed -i "/^\[$1\]/,/^\[/ s@^$2 *=.*@$2 = $3@$4" /etc/keylime.conf
}


function get_IP() {
    if echo $1 | egrep -q '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        echo $1
    else
        host $1 | sed -n -e 's/.*has address //p' | head -n 1
    fi
}


Verifier() {
    rlPhaseStartSetup "Verifier setup"
        # generate TLS certificates for all
        rlRun "x509KeyGen ca" 0 "Preparing RSA CA certificate"
        rlRun "x509KeyGen verifier" 0 "Preparing RSA verifier certificate"
        rlRun "x509KeyGen registrar" 0 "Preparing RSA registrar certificate"
        rlRun "x509KeyGen agent" 0 "Preparing RSA agent certificate"
        rlRun "x509KeyGen tenant" 0 "Preparing RSA agent certificate"
        rlRun "x509SelfSign ca" 0 "Selfsigning CA certificate"
        rlRun "x509CertSign --CA ca --DN 'CN = $VERIFIER' verifier" 0 "Signing verifier certificate with our CA certificate"
        rlRun "x509CertSign --CA ca --DN 'CN = $REGISTRAR' registrar" 0 "Signing registrar certificate with our CA certificate"
        rlRun "x509CertSign --CA ca --DN 'CN = $AGENT' agent" 0 "Signing agent certificate with our CA certificate"
        rlRun "x509CertSign --CA ca --DN 'CN = $TENANT' tenant" 0 "Signing tenant certificate with our CA certificate"
        # expose certificates for clients
        rlRun "mkdir certs"
        rlRun "cp $(x509Cert ca) certs/cacert.pem"
        rlRun "cp $(x509Cert verifier) certs/verifier-cert.pem"
        rlRun "cp $(x509Key verifier) certs/verifier-key.pem"
        rlRun "cp $(x509Cert registrar) certs/registrar-cert.pem"
        rlRun "cp $(x509Key registrar) certs/registrar-key.pem"
        rlRun "cp $(x509Cert agent) certs/agent-cert.pem"
        rlRun "cp $(x509Key agent) certs/agent-key.pem"
        rlRun "cp $(x509Cert agent) certs/tenant-cert.pem"
        rlRun "cp $(x509Key agent) certs/tenant-key.pem"
        rlRun "pushd certs"
        rlRun "python3 -m http.server 8000 &"
        HTTP_PID=$!
        rlRun "popd"

        # Verifier setup goes here
        rlRun "limeUpdateConf cloud_verifier cloudverifier_ip ${VERIFIER_IP}"
        rlRun "limeUpdateConf cloud_verifier registrar_ip = ${REGISTRAR_IP}"
        # configure certificates
        CERTDIR=/var/lib/keylime/certs
        rlRun "mkdir $CERTDIR && cp certs/cacert.pem certs/verifier*.pem $CERTDIR"
        rlRun "limeUpdateConf cloud_verifier tls_dir $CERTDIR"
        rlRun "limeUpdateConf cloud_verifier ca_cert cacert.pem"
        rlRun "limeUpdateConf cloud_verifier my_cert verifier-cert.pem"
        rlRun "limeUpdateConf cloud_verifier private_key verifier-key.pem"
        rlRun "limeUpdateConf cloud_verifier private_key_pw ''"

        # start keylime_verifier
        limeStartVerifier
        rlRun "limeWaitForVerifier"
        rlRun "rhts-sync-set -s VERIFIER_SETUP_DONE"
        rlRun "rhts-sync-block -s AGENT_ALL_TESTS_DONE $AGENT" 0 "Waiting for the Agent to finish the test"
    rlPhaseEnd

    rlPhaseStartTest "Verifier test"
        rlAssertGrep "WARNING - File not found in allowlist: .*/keylime-bad-script.sh" $(limeVerifierLogfile) -E
        AGENT_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        rlAssertGrep "WARNING - Agent $AGENT_ID failed, stopping polling" $(limeVerifierLogfile)
    rlPhaseEnd

    rlPhaseStartCleanup "Verifier cleanup"
        rlRun "kill $HTTP_PID"
        limeStopVerifier
        rlFileSubmit $(limeVerifierLogfile)
    rlPhaseEnd
}


Registrar() {
    rlPhaseStartSetup "Registrar setup"
        # Registrar setup goes here
        rlRun "rhts-sync-block -s VERIFIER_SETUP_DONE $VERIFIER" 0 "Waiting for the Verifier to start"

        # download certificates from the verifier
        CERTDIR=/var/lib/keylime/certs
        rlRun "mkdir $CERTDIR"
        for F in cacert.pem registrar-cert.pem registrar-key.pem; do
            rlRun "wget -O $CERTDIR/$F 'http://$VERIFIER:8000/$F'"
        done
        # configure certificates
        rlRun "limeUpdateConf registrar tls_dir $CERTDIR"
        rlRun "limeUpdateConf registrar ca_cert cacert.pem"
        rlRun "limeUpdateConf registrar my_cert registrar-cert.pem"
        rlRun "limeUpdateConf registrar private_key registrar-key.pem"
        rlRun "limeUpdateConf registrar private_key_pw ''"
        # configure registrar
        rlRun "limeUpdateConf registrar registrar_ip = ${REGISTRAR_IP}"

        limeStartRegistrar
        rlRun "limeWaitForRegistrar"

        rlRun "rhts-sync-set -s REGISTRAR_SETUP_DONE"
        rlRun "rhts-sync-block -s AGENT_ALL_TESTS_DONE $AGENT" 0 "Waiting for the Agent to finish the test"
    rlPhaseEnd

    rlPhaseStartCleanup "Registrar cleanup"
        limeStopRegistrar
        rlFileSubmit $(limeRegistrarLogfile)
    rlPhaseEnd
}


Agent() {
    rlPhaseStartSetup "Agent and tenant setup"
        # Agent and tenant setup goes here
        rlRun "rhts-sync-block -s REGISTRAR_SETUP_DONE $REGISTRAR" 0 "Waiting for the Registrar finish to start"

        # agent setup
        #rlRun "limeUpdateConf cloud_agent cloudverifier_ip ${VERIFIER_IP}"
        rlRun "limeUpdateConf cloud_agent registrar_ip = ${REGISTRAR_IP}"

        # tenant setup
        # download certificates from the verifier
        CERTDIR=/var/lib/keylime/certs
        rlRun "mkdir $CERTDIR"
        for F in cacert.pem tenant-cert.pem tenant-key.pem; do
            rlRun "wget -O $CERTDIR/$F 'http://$VERIFIER:8000/$F'"
        done
        # configure tenant certificates
        rlRun "limeUpdateConf tenant tls_dir $CERTDIR"
        rlRun "limeUpdateConf tenant ca_cert cacert.pem"
        rlRun "limeUpdateConf tenant my_cert tenant-cert.pem"
        rlRun "limeUpdateConf tenant private_key tenant-key.pem"
        rlRun "limeUpdateConf tenant private_key_pw ''"
        # configure tenant
        rlRun "limeUpdateConf tenant cloudverifier_ip ${VERIFIER_IP}"
        rlRun "limeUpdateConf tenant registrar_ip = ${REGISTRAR_IP}"
        rlRun "limeUpdateConf tenant require_ek_cert False"

        # if IBM TPM emulator is present
        if limeTPMEmulated; then
            # start tpm emulator
            rlServiceStart ibm-tpm-emulator
            rlRun "limeWaitForTPMEmulator"
            # make sure tpm2-abrmd is running
            rlServiceStart tpm2-abrmd
            sleep 5
            # start ima emulator
            export TPM2TOOLS_TCTI=tabrmd:bus_name=com.intel.tss2.Tabrmd
            limeInstallIMAConfig
            limeStartIMAEmulator
        else
            rlServiceStart tpm2-abrmd
        fi
        sleep 5

        limeStartAgent
        sleep 5
        # create allowlist and excludelist
        limeCreateTestLists
    rlPhaseEnd

    rlPhaseStartTest "Agent test: Add keylime tenant"
        AGENT_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        rlRun "keylime_tenant -v ${VERIFIER_IP} -t ${AGENT_IP} -u ${AGENT_ID} -f excludelist.txt --allowlist allowlist.txt --exclude excludelist.txt -c add"
        sleep 5
        rlRun -s "keylime_tenant -c cvlist"
        rlAssertGrep "{'agent_id': '${AGENT_ID}'}" $rlRun_LOG
        rlRun -s "keylime_tenant -c status -u ${AGENT_ID}"
        rlAssertGrep '"operational_state": "Get Quote"' $rlRun_LOG
    rlPhaseEnd

    rlPhaseStartTest "Agent test: Fail keylime tenant"
        TESTDIR=`limeCreateTestDir`
        limeExtendNextExcludelist $TESTDIR
        rlRun "echo -e '#!/bin/bash\necho boom' > $TESTDIR/keylime-bad-script.sh && chmod a+x $TESTDIR/keylime-bad-script.sh"
        rlRun "$TESTDIR/keylime-bad-script.sh"
        sleep 5
        rlRun -s "keylime_tenant -c status -u $AGENT_ID"
        rlAssertGrep '"operational_state": "(Failed|Invalid Quote)"' $rlRun_LOG -E
    rlPhaseEnd

    rlPhaseStartCleanup "Agent cleanup"
        rlRun "rhts-sync-set -s AGENT_ALL_TESTS_DONE"
        limeStopAgent
        rlFileSubmit $(limeAgentLogfile)
        if limeTPMEmulated; then
            limeStopIMAEmulator
            rlFileSubmit $(limeIMAEmulatorLogfile)
            rlServiceRestore ibm-tpm-emulator
        fi
        rlServiceRestore tpm2-abrmd
    rlPhaseEnd
}


####################
# Common script part
####################

# assigne custom roles using SERVERS and CLIENTS variables
export VERIFIER=$( echo "$SERVERS $CLIENTS" | cut -d ' ' -f 1)
export REGISTRAR=$( echo "$SERVERS $CLIENTS" | cut -d ' ' -f 2)
export AGENT=$( echo "$SERVERS $CLIENTS" | cut -d ' ' -f 3)

rlJournalStart
    rlPhaseStartSetup
        [ -n "$VERIFIER" ] && export VERIFIER_IP=$( get_IP $VERIFIER )
        [ -n "$REGISTRAR" ] && export REGISTRAR_IP=$( get_IP $REGISTRAR )
        [ -n "$AGENT" ] && export AGENT_IP=$( get_IP $AGENT )
        rlLog "VERIFIER: $VERIFIER ${VERIFIER_IP}"
        rlLog "REGISTRAR: $REGISTRAR ${REGISTRAR_IP}"
        rlLog "AGENT: $AGENT ${AGENT_IP}"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"

        ###############
        # common setup
        ###############

        # import keylime library
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import keylime-tests/test-helpers library"
        rlRun 'rlImport "openssl/certgen"' || rlDie "cannot import openssl/certgen library"
        # backup files
        limeBackupConfig
    rlPhaseEnd

    if echo $VERIFIER | grep -q $HOSTNAME ; then
        Verifier
    elif echo $REGISTRAR | grep -q $HOSTNAME ; then
        Registrar
    elif echo $AGENT | grep -q $HOSTNAME ; then
        Agent
    else
        rlReport "Unknown role" "FAIL"
    fi

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

        #################
        # common cleanup
        #################
        limeClearData
        limeRestoreConfig
    rlPhaseEnd

rlJournalPrintText
rlJournalEnd

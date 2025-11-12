#!/bin/bash
. /usr/share/beakerlib/beakerlib.sh || exit 1

AGENT_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

rlJournalStart
    rlPhaseStartSetup "Setup push authentication environment"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import keylime-tests/test-helpers library"
        rlAssertRpm keylime

        # Backup original configuration
        limeBackupConfig

        # Set the verifier to run in PUSH mode
        rlRun "limeUpdateConf verifier mode 'push'"
        rlRun "limeUpdateConf verifier challenge_lifetime 1800"
        rlRun "limeUpdateConf verifier session_lifetime 180"

        # Enable authentication
        rlRun "limeUpdateConf agent enable_authentication true"
        rlRun "limeUpdateConf agent tls_accept_invalid_certs true"
        rlRun "limeUpdateConf agent tls_accept_invalid_hostnames true"
        rlRun "limeUpdateConf verifier extend_token_on_attestation true"

        # Disable EK certificate verification on the tenant
        rlRun "limeUpdateConf tenant require_ek_cert False"

        # Configure TPM emulator if needed
        if limeTPMEmulated; then
            rlRun "limeStartTPMEmulator"
            rlRun "limeWaitForTPMEmulator"
            rlRun "limeCondStartAbrmd"
            rlRun "limeInstallIMAConfig"
            rlRun "limeStartIMAEmulator"
        fi

        # Start keylime services with push support
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlRun "limeStartRegistrar"
        rlRun "limeWaitForRegistrar"
    rlPhaseEnd

    rlPhaseStartTest "Test authentication fails for unenrolled agent"
        rlLog "Testing that unenrolled agents cannot authenticate"

        # Start push-attestation agent WITHOUT enrolling it first
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Wait a bit for agent to attempt authentication
        rlRun "sleep 5"

        # Agent should NOT have a Bearer token since it's not enrolled
        if grep -q "authorization: \"Bearer" "$(limePushAgentLogfile)"; then
            rlFail "Unenrolled agent should not receive authentication token"
        else
            rlPass "Unenrolled agent correctly denied authentication token"
        fi

        # Verify agent log shows authentication failed
        # Per spec, verifier issues challenges even for unenrolled agents,
        # but authentication fails during proof submission (PATCH)
        rlRun "grep -q 'Authentication failed with evaluation: fail' $(limePushAgentLogfile)" \
            0 "Agent log shows authentication failed for unenrolled agent"

        # Stop agent for enrollment
        rlRun "limeStopPushAgent"
    rlPhaseEnd

    rlPhaseStartTest "Enroll agent and test initial authentication"
        rlLog "Enrolling agent and testing that it authenticates and receives token"

        # Create a simple policy that allows everything (for authentication testing)
        # We don't need actual files for authentication testing, just a valid policy

        TESTDIR=$(limeCreateTestDir)
        # Create a dummy file so limeCreateTestPolicy doesn't fail
        rlRun "touch ${TESTDIR}/dummy.txt"
        rlRun "limeCreateTestPolicy ${TESTDIR}/*"

        # Enroll the agent
        rlRun "keylime_tenant -v 127.0.0.1 -u $AGENT_ID --runtime-policy policy.json -c add"

        # Verify agent appears in verifier's agent list
        rlRun -s "keylime_tenant -c cvlist"
        rlAssertGrep "$AGENT_ID" "$rlRun_LOG"

        # Start push-attestation agent (now enrolled)
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Wait for agent to authenticate and get token
        rlRun "rlWaitForCmd 'grep -q \"authorization: \\\"Bearer\" \$(limePushAgentLogfile)' -m 30 -d 1" \
            0 "Agent authenticated and received token"

        # Capture the token
        AGENT_LOG=$(limePushAgentLogfile)
        INITIAL_TOKEN=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Initial authentication token: $INITIAL_TOKEN"

        # Verify token is not empty
        if [ -n "$INITIAL_TOKEN" ]; then
            rlPass "Agent received valid authentication token"
        else
            rlFail "Agent did not receive authentication token"
        fi

        # Verify verifier log shows authentication succeeded
        rlRun "grep -q 'Authentication token validated for agent.*${AGENT_ID}' \$(limeVerifierLogfile)" \
            0 "Verifier log shows successful authentication"
    rlPhaseEnd

    rlPhaseStartTest "Test token extension on successful attestations"
        rlLog "Testing that successful attestations extend token lifetime (no re-authentication needed)"

        # Stop services to reconfigure
        rlRun "limeStopPushAgent"
        rlRun "limeStopVerifier"

        # Set moderate session lifetime (60 seconds) and attestation interval (5 seconds)
        # Use 60 seconds to allow time for verifier restart without token expiring
        # With frequent attestations, the token should be extended each time
        rlRun "limeUpdateConf verifier session_lifetime 60"
        rlRun "limeUpdateConf agent attestation_interval_seconds 5"
        rlRun "limeUpdateConf verifier extend_token_on_attestation true"

        # Restart services
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Wait for agent to authenticate and start using token
        rlRun "rlWaitForCmd 'grep -q \"authorization: \\\"Bearer\" \$(limePushAgentLogfile)' -m 30 -d 1" \
            0 "Waiting for agent to use authentication token"

        # Wait a bit to let agent do some attestations with the new token
        rlRun "sleep 5"

        # NOW capture the token (after agent has settled into steady state)
        AGENT_LOG=$(limePushAgentLogfile)
        INITIAL_TOKEN=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Initial token: $INITIAL_TOKEN"

        # Mark the log position for checking re-authentication later
        LOG_MARK=$(wc -l < "$AGENT_LOG")

        # Restart ONLY the verifier (not the agent) to test token persistence
        rlLog "Restarting verifier to test if token persists from database..."
        rlRun "limeStopVerifier"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Wait for token to be used after restart (should persist from database)
        # With token extension enabled, attestations should keep extending the token
        # so NO re-authentication should occur even after verifier restart
        rlLog "Waiting for attestations to resume after verifier restart..."
        rlRun "sleep 15"

        # Verify NO re-authentication happened (no 401 received)
        if tail -n +$LOG_MARK "$(limePushAgentLogfile)" | grep -q "Received 401"; then
            rlFail "Token expired and re-authentication occurred - optimization not working"
        else
            rlPass "No re-authentication occurred - token was extended by successful attestations"
        fi

        # Get the current token being used
        AGENT_LOG=$(limePushAgentLogfile)
        CURRENT_TOKEN=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Current token: $CURRENT_TOKEN"

        # Verify token is still the same (not replaced)
        if [ "$INITIAL_TOKEN" = "$CURRENT_TOKEN" ] && [ -n "$INITIAL_TOKEN" ]; then
            rlPass "Token remained the same ('$INITIAL_TOKEN') - successfully extended without re-authentication"
        else
            rlFail "Token changed from '$INITIAL_TOKEN' to '$CURRENT_TOKEN' - unexpected re-authentication"
        fi

        # Verify we see token extension messages in verifier log
        rlRun "grep -q 'Extended auth token for agent.*${AGENT_ID}' \$(limeVerifierLogfile)" \
            0 "Verifier log shows token extensions"

        # Restore config
        rlRun "limeStopPushAgent"
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_lifetime 180"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"
    rlPhaseEnd

    rlPhaseStartTest "Test automatic token re-authentication"
        rlLog "Testing that agent automatically re-authenticates when token expires"

        # Stop services to reconfigure
        rlRun "limeStopPushAgent"
        rlRun "limeStopVerifier"

        # Set very short session lifetime (15 seconds) and attestation interval (5 seconds)
        # Disable token extension so the token actually expires
        rlRun "limeUpdateConf verifier session_lifetime 15"
        rlRun "limeUpdateConf verifier extend_token_on_attestation False"
        rlRun "limeUpdateConf agent attestation_interval_seconds 5"

        # Restart services
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Wait for agent to be using its authentication token
        rlRun "rlWaitForCmd 'grep -q \"authorization: \\\"Bearer\" \$(limePushAgentLogfile)' -m 30 -d 1" \
            0 "Waiting for agent to use authentication token"

        # Capture the current token being used
        AGENT_LOG=$(limePushAgentLogfile)
        INITIAL_TOKEN=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Initial token: $INITIAL_TOKEN"

        # Mark the log position for checking re-authentication later
        LOG_MARK=$(wc -l < "$AGENT_LOG")

        # Wait for token to expire (15 seconds + some buffer)
        rlRun "sleep 18"

        # Verify re-authentication happened
        rlRun "rlWaitForCmd 'tail -n +$LOG_MARK \$(limePushAgentLogfile) | grep -q \"Received 401\"' -m 30 -d 1" \
            0 "Token expiration detected (401 from verifier) and re-authentication triggered"

        # Get the new token being used after re-authentication
        AGENT_LOG=$(limePushAgentLogfile)
        NEW_TOKEN=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "New token after re-auth: $NEW_TOKEN"

        # Verify token changed
        if [ "$INITIAL_TOKEN" != "$NEW_TOKEN" ] && [ -n "$INITIAL_TOKEN" ] && [ -n "$NEW_TOKEN" ]; then
            rlPass "Authentication token changed from '$INITIAL_TOKEN' to '$NEW_TOKEN' - re-authentication successful"
        else
            rlFail "Authentication token did not change or was not captured (initial: '$INITIAL_TOKEN', new: '$NEW_TOKEN')"
        fi

        # Restore config (keep agent running to preserve token for next test)
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_lifetime 180"
        rlRun "limeUpdateConf verifier extend_token_on_attestation True"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Wait for agent to re-authenticate with new verifier
        rlRun "sleep 5"
    rlPhaseEnd

    rlPhaseStartTest "Test token persistence across verifier restarts"
        rlLog "Testing that authentication tokens persist in database and survive verifier restarts"

        # Restart agent to get a fresh token with proper lifetime (not expired from previous test)
        rlRun "limeStopPushAgent"
        rlRun "limeStartPushAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Wait for agent to authenticate and get a fresh token
        rlRun "rlWaitForCmd 'grep -q \"authorization: \\\"Bearer\" \$(limePushAgentLogfile)' -m 30 -d 1" \
            0 "Waiting for agent to authenticate"

        # Wait a bit more to ensure token is stable
        rlRun "sleep 5"

        # Capture the token from the running agent
        AGENT_LOG=$(limePushAgentLogfile)
        TOKEN_BEFORE=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Token before restart: $TOKEN_BEFORE"

        # Verify agent can attest successfully with this token
        VERIFIER_LOG_MARK=$(wc -l < "$(limeVerifierLogfile)")
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -qE \"Attestation [0-9]+ for agent .${AGENT_ID}. successfully passed verification\"' -m 30 -d 1" \
            0 "Agent can attest successfully before restart"

        # Mark log position before restart
        VERIFIER_LOG_MARK=$(wc -l < "$(limeVerifierLogfile)")

        # Restart ONLY the verifier (NOT the agent!) - this clears shared memory but NOT database
        rlRun "limeStopVerifier"
        rlLog "Verifier stopped - shared memory cleared, but database persists"

        # Set reasonable token lifetime and enable token extension
        rlRun "limeUpdateConf verifier session_lifetime 300"  # 5 minutes
        rlRun "limeUpdateConf verifier extend_token_on_attestation true"

        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlLog "Verifier restarted - testing if token still works"

        # Wait a bit for agent to attempt attestation with the existing token
        rlRun "sleep 10"

        # Verify that agent continues to attest successfully WITHOUT re-authentication
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -qE \"Attestation [0-9]+ for agent .${AGENT_ID}. successfully passed verification\"' -m 30 -d 1" \
            0 "Agent can attest successfully after restart using persisted token"

        # Verify token extension message appears (token was restored from DB and extended)
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -q \"Extended auth token for agent.*${AGENT_ID}\"' -m 30 -d 1" \
            0 "Verifier extended token from database after restart"

        # Verify no re-authentication occurred (token should be the same)
        AGENT_LOG=$(limePushAgentLogfile)
        TOKEN_AFTER=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Token after restart: $TOKEN_AFTER"

        if [ "$TOKEN_BEFORE" = "$TOKEN_AFTER" ] && [ -n "$TOKEN_BEFORE" ]; then
            rlPass "Token persisted across verifier restart (token: $TOKEN_BEFORE) - no re-authentication needed"
        else
            rlFail "Token changed from '$TOKEN_BEFORE' to '$TOKEN_AFTER' - database persistence failed"
        fi

        # Restore config (keep agent running)
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_lifetime 180"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Agent keeps running with same session for any subsequent tests
    rlPhaseEnd

    rlPhaseStartTest "Validate authentication protocol responses per spec"
        rlLog "Testing that authentication protocol responses match specification format"

        # Test POST /sessions response format
        rlLog "Testing POST /sessions response format"
        SESSION_RESPONSE=$(curl -s -k -X POST https://localhost:8881/v3.0/sessions \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")

        # Validate POST response has required fields per spec
        echo "$SESSION_RESPONSE" | jq -e '.data.type == "session"' >/dev/null
        rlAssert0 "POST /sessions response has correct type" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.id' >/dev/null
        rlAssert0 "POST /sessions response has session id" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.agent_id' >/dev/null
        rlAssert0 "POST /sessions response has agent_id" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.authentication_requested[0].authentication_type == "tpm_pop"' >/dev/null
        rlAssert0 "POST /sessions response has authentication_requested with tpm_pop" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.authentication_requested[0].chosen_parameters.challenge' >/dev/null
        rlAssert0 "POST /sessions response has challenge" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.created_at' >/dev/null
        rlAssert0 "POST /sessions response has created_at" $?

        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.challenges_expire_at' >/dev/null
        rlAssert0 "POST /sessions response has challenges_expire_at" $?

        # Verify POST response does NOT have token (only on PATCH success)
        echo "$SESSION_RESPONSE" | jq -e '.data.attributes.token' >/dev/null 2>&1 && \
            rlFail "POST /sessions response should not have token" || \
            rlPass "POST /sessions response does not have token"

        # Test PATCH /sessions failure response format
        rlLog "Testing PATCH /sessions failure response format"
        # Create a session first
        FAIL_SESSION_RESPONSE=$(curl -s -k -X POST https://localhost:8881/v3.0/sessions \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")

        FAIL_SESSION_ID=$(echo "$FAIL_SESSION_RESPONSE" | jq -r '.data.id')
        rlLog "Created session ID for failure test: $FAIL_SESSION_ID"

        # Submit invalid proof of possession (empty signatures)
        FAIL_PATCH_RESPONSE=$(curl -s -k -X PATCH "https://localhost:8881/v3.0/sessions/${FAIL_SESSION_ID}" \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"id\":\"${FAIL_SESSION_ID}\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_provided\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\",\"data\":{\"message\":\"\",\"signature\":\"\"}}]}}}")

        # Validate failure response has required fields per spec
        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.evaluation == "fail"' >/dev/null
        rlAssert0 "PATCH /sessions failure response has evaluation=fail" $?

        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.authentication[0].authentication_type == "tpm_pop"' >/dev/null
        rlAssert0 "PATCH /sessions failure response has authentication array" $?

        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.created_at' >/dev/null
        rlAssert0 "PATCH /sessions failure response has created_at" $?

        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.challenges_expire_at' >/dev/null
        rlAssert0 "PATCH /sessions failure response has challenges_expire_at" $?

        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.response_received_at' >/dev/null
        rlAssert0 "PATCH /sessions failure response has response_received_at" $?

        # Verify failure response does NOT have token or token_expires_at
        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.token' >/dev/null 2>&1 && \
            rlFail "PATCH /sessions failure response should not have token" || \
            rlPass "PATCH /sessions failure response does not have token"

        echo "$FAIL_PATCH_RESPONSE" | jq -e '.data.attributes.token_expires_at' >/dev/null 2>&1 && \
            rlFail "PATCH /sessions failure response should not have token_expires_at" || \
            rlPass "PATCH /sessions failure response does not have token_expires_at"

        # Test that 401 responses are returned for expired tokens
        rlLog "Testing that 401 responses are returned for expired tokens"
        rlRun "limeUpdateConf verifier session_lifetime 5"
        rlRun "limeStopVerifier"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Wait for token to expire and agent to get 401
        rlRun "sleep 10"

        # Verify 401 was received
        rlRun "grep -q 'Received 401' \$(limePushAgentLogfile)" \
            0 "Agent received 401 response for expired token"

        # Restore config (keep agent running to preserve token for next test)
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_lifetime 180"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Wait for agent to re-authenticate with new verifier
        rlRun "sleep 5"
    rlPhaseEnd

    rlPhaseStartTest "Test authentication token remains valid on failed attestations"
        rlLog "Testing that authentication tokens persist through verifier restarts and attestation failures in push mode"

        # Agent is still running from previous phase - capture current token
        AGENT_LOG=$(limePushAgentLogfile)
        TOKEN_INITIAL=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Initial token (from previous phase): $TOKEN_INITIAL"

        # Stop ONLY verifier to reconfigure (agent keeps running)
        rlRun "limeStopVerifier"

        # Configure for this test
        rlRun "limeUpdateConf verifier session_lifetime 60"  # 1 minute token
        rlRun "limeUpdateConf verifier extend_token_on_attestation true"
        rlRun "limeUpdateConf agent attestation_interval_seconds 5"

        # Restart ONLY verifier (agent still running with same token)
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Wait for agent to use its existing token after verifier restart
        rlRun "sleep 10"

        # Verify token survived verifier restart (should be same token from database)
        TOKEN_AFTER_VERIFIER_RESTART=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Token after verifier restart: $TOKEN_AFTER_VERIFIER_RESTART"

        if [ "$TOKEN_INITIAL" = "$TOKEN_AFTER_VERIFIER_RESTART" ] && [ -n "$TOKEN_INITIAL" ]; then
            rlPass "Token survived verifier restart (database persistence working)"
        else
            rlFail "Token changed from '$TOKEN_INITIAL' to '$TOKEN_AFTER_VERIFIER_RESTART' after verifier restart - database persistence failed"
        fi

        # Now capture token before attestation failure testing
        TOKEN_BEFORE=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Token before attestation failure: $TOKEN_BEFORE"

        # Wait for successful attestation first
        VERIFIER_LOG=$(limeVerifierLogfile)
        VERIFIER_LOG_MARK=$(wc -l < "$VERIFIER_LOG")
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -qE \"Attestation [0-9]+ for agent .${AGENT_ID}. successfully passed verification\"' -m 30 -d 1" \
            0 "Agent can attest successfully before we break it"

        # Now cause an attestation failure by adding a file not in the allowlist
        rlLog "Creating a file not in allowlist to cause attestation failures"

        # Get a new test directory for the bad script
        BAD_TESTDIR=$(limeCreateTestDir)

        # Create a new file NOT in the allowlist
        rlRun "echo -e '#!/bin/bash\necho boom' > ${BAD_TESTDIR}/bad-script.sh && chmod a+x ${BAD_TESTDIR}/bad-script.sh"

        # Run it so IMA logs it (which will cause next attestation to fail)
        rlRun "${BAD_TESTDIR}/bad-script.sh"

        # Mark log position before failure
        VERIFIER_LOG_MARK=$(wc -l < "$VERIFIER_LOG")
        AGENT_LOG_MARK=$(wc -l < "$AGENT_LOG")

        # Wait for attestation to fail
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -qE \"Attestation [0-9]+ for agent .${AGENT_ID}. failed verification\"' -m 30 -d 1" \
            0 "Attestation failure detected"

        # CRITICAL: Verify token was NOT invalidated (should still see Bearer token in subsequent requests)
        rlRun "sleep 10"  # Wait for a few more attestation attempts

        # Check that agent is still using the SAME token (not re-authenticating)
        AGENT_LOG=$(limePushAgentLogfile)
        TOKEN_AFTER=$(grep "authorization: \"Bearer" "$AGENT_LOG" | tail -1 | sed -n 's/.*Bearer \([^"]*\).*/\1/p')
        rlLog "Token after attestation failure: $TOKEN_AFTER"

        if [ "$TOKEN_BEFORE" = "$TOKEN_AFTER" ] && [ -n "$TOKEN_BEFORE" ]; then
            rlPass "Token remained valid after failed attestation (token: $TOKEN_BEFORE)"
        else
            rlFail "Token changed from '$TOKEN_BEFORE' to '$TOKEN_AFTER' - session was incorrectly invalidated"
        fi

        # Verify agent did NOT get 401 (which would indicate session was deleted)
        if tail -n +$AGENT_LOG_MARK "$AGENT_LOG" | grep -q "Received 401"; then
            rlFail "Agent received 401 - authentication session was incorrectly deleted on attestation failure"
        else
            rlPass "Agent did not receive 401 - authentication session was preserved"
        fi

        # Verify token was NOT extended (should only extend on successful attestations)
        if tail -n +$VERIFIER_LOG_MARK "$VERIFIER_LOG" | grep -q "Extended auth token for agent.*${AGENT_ID}"; then
            rlFail "Token was extended on failed attestation - should only extend on success"
        else
            rlPass "Token was not extended on failed attestation (correct behavior)"
        fi

        # Verify agent can still submit attestations (accept_attestations should remain true in push mode)
        VERIFIER_LOG_MARK=$(wc -l < "$VERIFIER_LOG")
        rlRun "sleep 10"  # Wait for more attestation attempts
        if tail -n +$VERIFIER_LOG_MARK "$VERIFIER_LOG" | grep -qE "Attestation [0-9]+ for agent .${AGENT_ID}. failed verification"; then
            rlPass "Agent continued to submit attestations after failure (push mode allows retry)"
        else
            rlFail "Agent stopped submitting attestations - accept_attestations may have been set to False"
        fi

        # Restore working policy
        # First exclude the bad test directory from verification
        limeExtendNextExcludelist $BAD_TESTDIR
        TESTDIR=$(limeCreateTestDir)
        rlRun "touch ${TESTDIR}/dummy.txt"
        rlRun "limeCreateTestPolicy ${TESTDIR}/*"
        rlRun "keylime_tenant -v 127.0.0.1 -u $AGENT_ID --runtime-policy policy.json -c update"

        # Verify agent recovers and attestations pass again
        VERIFIER_LOG_MARK=$(wc -l < "$VERIFIER_LOG")
        rlRun "rlWaitForCmd 'tail -n +$VERIFIER_LOG_MARK \$(limeVerifierLogfile) | grep -qE \"Attestation [0-9]+ for agent .${AGENT_ID}. successfully passed verification\"' -m 30 -d 1" \
            0 "Agent recovered - attestations passing again"

        # Restore config (keep agent running)
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_lifetime 180"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Agent keeps running with same session for any subsequent tests
    rlPhaseEnd

    rlPhaseStartTest "Test authentication rate limiting"
        rlLog "Testing that rate limiting prevents authentication DoS attacks"

        # Stop verifier to configure aggressive rate limits for testing
        rlRun "limeStopVerifier"

        # Configure low rate limits to trigger quickly in tests
        # Agent-based: 3 requests per 10 seconds
        # IP-based: 5 requests per 10 seconds
        rlRun "limeUpdateConf verifier session_create_rate_limit_per_agent 3"
        rlRun "limeUpdateConf verifier session_create_rate_limit_window_agent 10"
        rlRun "limeUpdateConf verifier session_create_rate_limit_per_ip 5"
        rlRun "limeUpdateConf verifier session_create_rate_limit_window_ip 10"

        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"

        # Test agent-based rate limiting
        rlLog "Testing agent-based rate limiting (max 3 requests per 10 seconds)"

        # Make 3 requests - should all succeed
        for i in 1 2 3; do
            RESPONSE=$(curl -s -k -w "\n%{http_code}" -X POST https://localhost:8881/v3.0/sessions \
                -H "Content-Type: application/vnd.api+json" \
                -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")
            HTTP_CODE=$(echo "$RESPONSE" | tail -1)
            if [ "$HTTP_CODE" = "200" ]; then
                rlPass "Request $i: Got 200 OK (within rate limit)"
            else
                rlFail "Request $i: Got $HTTP_CODE instead of 200 (should be within rate limit)"
            fi
        done

        # 4th request should be rate limited
        RESPONSE=$(curl -s -k -i -X POST https://localhost:8881/v3.0/sessions \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")
        HTTP_CODE=$(echo "$RESPONSE" | head -1 | grep -oP 'HTTP/[\d.]+ \K\d+')

        if [ "$HTTP_CODE" = "429" ]; then
            rlPass "Request 4: Got 429 Too Many Requests (rate limit working)"

            # Verify Retry-After header is present
            RETRY_AFTER=$(echo "$RESPONSE" | grep -i "^Retry-After:" | awk '{print $2}' | tr -d '\r')
            if [ -n "$RETRY_AFTER" ]; then
                rlPass "Response includes Retry-After header: $RETRY_AFTER seconds"
            else
                rlFail "Response missing Retry-After header"
            fi
        else
            rlFail "Request 4: Got $HTTP_CODE instead of 429 (rate limiting not working)"
        fi

        # Test IP-based rate limiting with different agent IDs from same IP
        rlLog "Testing IP-based rate limiting (max 5 requests per 10 seconds from same IP)"

        # Wait for agent rate limit to reset
        rlRun "sleep 11"

        # Make requests for different agents from same IP (localhost)
        # We already made 3 requests above (now expired), so make 5 more - all should succeed
        for i in 1 2 3 4 5; do
            TEST_AGENT_ID="test-agent-$(printf '%04d' $i)"
            RESPONSE=$(curl -s -k -w "\n%{http_code}" -X POST https://localhost:8881/v3.0/sessions \
                -H "Content-Type: application/vnd.api+json" \
                -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${TEST_AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")
            HTTP_CODE=$(echo "$RESPONSE" | tail -1)
            if [ "$HTTP_CODE" = "200" ]; then
                rlPass "IP limit test request $i (agent $TEST_AGENT_ID): Got 200 OK"
            else
                rlFail "IP limit test request $i (agent $TEST_AGENT_ID): Got $HTTP_CODE instead of 200"
            fi
        done

        # 6th request from same IP should be rate limited
        RESPONSE=$(curl -s -k -w "\n%{http_code}" -X POST https://localhost:8881/v3.0/sessions \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"test-agent-0006\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)

        if [ "$HTTP_CODE" = "429" ]; then
            rlPass "IP limit test request 6: Got 429 Too Many Requests (IP-based rate limiting working)"
        else
            rlFail "IP limit test request 6: Got $HTTP_CODE instead of 429 (IP rate limiting not working)"
        fi

        # Verify rate limit resets after block expires
        # The rate limiter uses exponential backoff, so we need to wait for the Retry-After time
        # First block is 60 seconds (60 * 2^0), not the window time (10 seconds)
        rlLog "Waiting for rate limit block to expire (60 seconds from exponential backoff)"
        rlRun "sleep 61"

        RESPONSE=$(curl -s -k -w "\n%{http_code}" -X POST https://localhost:8881/v3.0/sessions \
            -H "Content-Type: application/vnd.api+json" \
            -d "{\"data\":{\"type\":\"session\",\"attributes\":{\"agent_id\":\"${AGENT_ID}\",\"authentication_supported\":[{\"authentication_class\":\"pop\",\"authentication_type\":\"tpm_pop\"}]}}}")
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)

        if [ "$HTTP_CODE" = "200" ]; then
            rlPass "Rate limit reset after block expired - request succeeded"
        else
            rlFail "Rate limit did not reset - got $HTTP_CODE instead of 200"
        fi

        # Restore original rate limit config
        rlRun "limeStopVerifier"
        rlRun "limeUpdateConf verifier session_create_rate_limit_per_agent 15"
        rlRun "limeUpdateConf verifier session_create_rate_limit_window_agent 60"
        rlRun "limeUpdateConf verifier session_create_rate_limit_per_ip 50"
        rlRun "limeUpdateConf verifier session_create_rate_limit_window_ip 60"
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
    rlPhaseEnd

    rlPhaseStartCleanup "Cleanup push authentication test"
        # Stop push agent
        rlRun "limeStopPushAgent"

        # Stop keylime services
        rlRun "limeStopRegistrar"
        rlRun "limeStopVerifier"

        # Stop TPM emulator if used
        if limeTPMEmulated; then
            rlRun "limeStopIMAEmulator"
            rlRun "limeStopTPMEmulator"
            rlRun "limeCondStopAbrmd"
        fi

        limeSubmitCommonLogs
        limeClearData
        limeRestoreConfig
        limeExtendNextExcludelist $TESTDIR
    rlPhaseEnd
rlJournalEnd

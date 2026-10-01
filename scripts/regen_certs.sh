#!/bin/bash
# Regenerates the ISO 15118-2 PKI (V2GRootCA -> CPOSubCA1 -> CPOSubCA2 -> SECC leaf,
# plus the OEM/MO/contract chain) inside the SECC container, then syncs the freshly
# generated chain into EVCC (and, if present, Evil_SECC/Evil_EVCC -- see "Split HLC
# proxy" in the README) so every container trusts the same chain.
#
# Why this exists: the iso15118 project's create_certs.sh hardcodes short validity
# windows (VALIDITY_SECC_LEAF_CERT=60 days), so the certs baked into the docker image
# at build time expire ~2 months later. TLS/PnC runs then fail with:
#   ssl.SSLCertVerificationError: certificate has expired
# Re-run this any time evcc_run_full.sh (PnC/TLS mode) starts failing that way.
#
# Every container must share the SAME regenerated chain -- CA keys are random per
# run of create_certs.sh, so regenerating independently on each side breaks trust.
# Evil_SECC terminates TLS with the real EVCC using this same SECC identity, and
# Evil_EVCC terminates TLS with the real SECC trusting this same root CA, so both
# need it too, exactly like EVCC does today.
#
# Usage: ./regen_certs.sh
set -euo pipefail

PKI_REL="iso15118/iso15118/shared/pki/iso15118_2"

echo "--- Regenerating certs inside SECC ---"
docker exec SECC bash -c "cd /usr/src/app/iso15118/iso15118/shared/pki && ./create_certs.sh -v iso-2"

echo "--- Syncing regenerated chain from SECC to EVCC ---"
TMP="$(mktemp -d)"
docker cp "SECC:/usr/src/app/${PKI_REL}/." "$TMP/"
docker cp "$TMP/." "EVCC:/usr/src/app/${PKI_REL}/"
rm -rf "$TMP"

# Evil_SECC/Evil_EVCC only exist when the "split" compose profile has been
# started at least once (see README "Split proxy") -- sync to them too
# if they're there, but don't fail the whole script if they're not.
for TARGET in Evil_SECC Evil_EVCC; do
    if docker inspect "$TARGET" >/dev/null 2>&1; then
        echo "--- Syncing regenerated chain from SECC to $TARGET ---"
        TMP="$(mktemp -d)"
        docker cp "SECC:/usr/src/app/${PKI_REL}/." "$TMP/"
        docker cp "$TMP/." "${TARGET}:/usr/src/app/${PKI_REL}/"
        rm -rf "$TMP"
    fi
done

echo "--- Done. New certs are valid from today for the validity periods set at the"
echo "    top of create_certs.sh (SECC leaf: 60 days by default)."

#!/usr/bin/env bash
# saml-sp scenario:
#   1. fetch our IDP metadata from a tenant subdomain
#   2. assert it's well-formed SAML metadata with a signing cert
#   3. save metadata.xml + print SAMLtest.id upload steps

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

CURL=/usr/bin/curl
SLUG=${CHALK_TENANT_SLUG:-verify21778806025}
APEX=${CHALK_APEX:-localhost:8080}
URL="http://${SLUG}.${APEX}/idp/saml/metadata"

echo "==> fetching IDP metadata from $URL"
if ! "$CURL" -fsS -o metadata.xml -w "    HTTP %{http_code}, %{size_download} bytes\n" "$URL"; then
    echo
    echo "FAIL — could not fetch metadata. Is tenant '$SLUG' active?"
    echo "Override with: CHALK_TENANT_SLUG=<slug> $0"
    exit 1
fi

echo "==> validating metadata structure"
python3 <<'PY' || { echo; echo "FAIL — metadata.xml is malformed"; exit 1; }
import sys
import xml.etree.ElementTree as ET

NS = {
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}

tree = ET.parse('metadata.xml')
root = tree.getroot()

if root.tag != f"{{{NS['md']}}}EntityDescriptor":
    print(f"  ✗ root is not <EntityDescriptor>: {root.tag}")
    sys.exit(1)

entity_id = root.attrib.get('entityID', '')
print(f"  ✓ entityID: {entity_id}")

idp_descriptor = root.find('md:IDPSSODescriptor', NS)
if idp_descriptor is None:
    print("  ✗ no <IDPSSODescriptor>")
    sys.exit(1)
print("  ✓ <IDPSSODescriptor> present")

cert = root.find('.//ds:X509Certificate', NS)
if cert is None or not (cert.text and cert.text.strip()):
    print("  ✗ no <X509Certificate>")
    sys.exit(1)
print(f"  ✓ <X509Certificate> present ({len(cert.text.strip())} chars)")

sso = root.find('.//md:SingleSignOnService', NS)
if sso is None:
    print("  ✗ no <SingleSignOnService>")
    sys.exit(1)
print(f"  ✓ <SingleSignOnService> at {sso.attrib.get('Location', '?')}")
PY

echo
echo "==> metadata saved to metadata.xml"
echo
echo "Next: complete the manual SAMLtest steps from the README."
echo "  1. open https://samltest.id/upload.php and upload metadata.xml"
echo "  2. open https://samltest.id/start-idp-test/"
echo "  3. enter entity ID: $(grep -oE 'entityID="[^"]+"' metadata.xml | head -1 | sed -E 's/entityID="([^"]+)"/\1/')"
echo "  4. click Login, complete the flow, confirm SAMLtest shows green"
echo
echo "PASS — metadata is well-formed; manual SAMLtest verification next"

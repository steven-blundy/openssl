// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"testing"
)

const signedKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC9y8Iq0DUnrtau73ybZbc57fMI8UC1XGQg8uBXV3w733URiz6n
alriviWy18bvQxlJelBdoOsoCI32l1hhIITq5xiqjKQHSfN3gGWirU5hIIEELPJP
FPdAOD7dS96VorSL5EJqQX/OELkWgkTQzzox4jB9Y9591ez79ha2rokirwIBAwKB
gH6H1sc1eMUfOcn0/bzueiaeogX2KyOS7WtMlY+PqCfqTguyKcTxkex+w8yP2fTX
ZjD8NZPAnMVbCU8PkEDAWJt0Drr+1rkwsiNaQGYPEPX9PvM+tegk7Vc/HRVPU7im
M6Z16rASD36gr6M2z8venDa/6o7Zn6XIRlddvgoOHwJrAkEA4mVrVmwxbI+dkthz
tOXKR6DlK6q2fgwmf8MjkXpyHXHfl0kmYyf2VBa85IGlxVrBoS7VhTceaTn975En
+nmz3wJBANadJrf1wBRYpOYsleHPJd0BsiM2vF+HFtnQGcNmjov1MpwZO8NAmcua
5MuLeTv1HiEh0Zg35sBJevnof57g6zECQQCW7keO8sudtRO3OvfN7obaa0Nycc7+
ssRVLMJg/EwToT+6MMRCGqQ4DyiYVm6DkdZrdI5Yz2mbe/6fthqm+80/AkEAjxNv
JU6ADZBt7shj699uk1Z2wiR9lQS55oq715m0XU4hvWYn14Bmh7yYh7JQ0qNpa2vh
ECVEgDD8ppr/v0CcywJBAMYSeTR7Boc4m4xdVM/plmcfo6iv8x/+f0oyOH4DU+3N
rRXG4ly2LivDQoySJwfmEEqygkHMZd7PybCYFGZI2pI=
-----END RSA PRIVATE KEY-----`
const signedCert = `-----BEGIN CERTIFICATE-----
MIIB1zCCAUACAQEwDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCVVMxFDASBgNV
BAoMC1Rlc3QgSW50IENBMRUwEwYDVQQDDAxpbnRlcm1lZGlhdGUwHhcNMTgxMDE2
MTM0NzA2WhcNMTgxMDE3MTM0NzA2WjAwMQ0wCwYDVQQKDARUZXN0MRIwEAYDVQQD
DAlsb2NhbGhvc3QxCzAJBgNVBAYTAlVTMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB
hwKBgQC9y8Iq0DUnrtau73ybZbc57fMI8UC1XGQg8uBXV3w733URiz6nalriviWy
18bvQxlJelBdoOsoCI32l1hhIITq5xiqjKQHSfN3gGWirU5hIIEELPJPFPdAOD7d
S96VorSL5EJqQX/OELkWgkTQzzox4jB9Y9591ez79ha2rokirwIBAzANBgkqhkiG
9w0BAQsFAAOBgQBISH3ZfExSPyd460dTtMqeFkW+cqVTjB8LD47k1n6RMyfGAAZS
/CORFVVSNO0XBDHz0Xb3EdHJ4tLoKS9ldI6DS5caTnKlRQOkskAzwJDs9NXqyyku
6uSUKTW74bgOrWNX6GFxOYPqqJW0OduNb23qzWI12pZ/jUwfVNonE87xmg==
-----END CERTIFICATE-----`
const signedCertIntCA = `-----BEGIN CERTIFICATE-----
MIICMTCCAZoCAQEwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCVVMxFTATBgNV
BAoMDFRlc3QgUm9vdCBDQTENMAsGA1UEAwwEcm9vdDAeFw0xODEwMTYxMzQ3MDZa
Fw0xODEwMTcxMzQ3MDZaMDoxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtUZXN0IElu
dCBDQTEVMBMGA1UEAwwMaW50ZXJtZWRpYXRlMIGdMA0GCSqGSIb3DQEBAQUAA4GL
ADCBhwKBgQC1lhS3CXYog1qlhDxqza5sOL6giCajD4bfQ5d9sb5saKlr4UCbyV1Y
8o4fFt/yMYbwnzHVJviyqGuRYaXkwz1QEFUkPr8lSRQl/e/GHFbgJN6Y4YQROIJ3
RAvRBJsY4QhWuDJirvi2a/0UbuekK4O/O6gTILFP35F0AnooK6cjewIBA6NVMFMw
DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSeIH/6PPkoVL7M05GPhp5U+FRzbzAR
BglghkgBhvhCAQEEBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOBgQAUyQyLG7NfYeli7AAZeZjRcq+Rq9EMMoAT8jK295fZk9fwfPnW4NmVI88n
5NUYfWI6NJkaciglT4AwjTFVuqFgszN6Gs3zikB6Gk319PaL6Lmw15I8mcwFgQWf
F0oXCfyy1Rfr9tMohwvKzdFo3d7SJqv0JuzAIsjJRorHgDw3pA==
-----END CERTIFICATE-----`
const signedCertRootCA = `-----BEGIN CERTIFICATE-----
MIICKjCCAZMCAQEwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCVVMxFTATBgNV
BAoMDFRlc3QgUm9vdCBDQTENMAsGA1UEAwwEcm9vdDAeFw0xODEwMTYxMzQ3MDZa
Fw0xODEwMTcxMzQ3MDZaMDMxCzAJBgNVBAYTAlVTMRUwEwYDVQQKDAxUZXN0IFJv
b3QgQ0ExDTALBgNVBAMMBHJvb3QwgZ0wDQYJKoZIhvcNAQEBBQADgYsAMIGHAoGB
AMOhxBH+1bXofJ6vARuJw2ZO4ezdHaDhYCczA2iZQJT69JUa0BuBuo8vbtnsrvTg
rKH1nbMTOwFLZ4K4dZzorB00yAA6AzyTQa3CijEaQZGIqeT3DNK6aXYz1kNnKu8q
W0YJl0HEohnYzkHDa0vEBVc7T71tuEpxP9rNJmLZBsajAgEDo1UwUzAOBgNVHQ8B
Af8EBAMCAQYwHQYDVR0OBBYEFIoEGWhtOwpLchb3xZyozLACqmDTMBEGCWCGSAGG
+EIBAQQEAwICBDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAFMJ
YEKyonQFKY///0yNSK8yaLg4RRcdhLOVIWbKN5w/sD6QPSOpVcX1gamlBa28/LL1
D/p2BhLZ5AkUTQ3gV1OuTluRUuOI/MwGcXIbP/cApgI4QQlLuTMIYH2ZLpY28LlS
lizL7MBDo9q00rFlccJbMkevO24OuNN3fTIl5C/6
-----END CERTIFICATE-----`

func TestMarshalPKCS12(t *testing.T) {
	key, cert, err := loadSelfSignedTestCert()
	if err != nil {
		t.Fatal(err)
	}

	pkcs12, err := MarshalPKCS12("test", "testing", key, cert, nil)

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}
	if pkcs12 == nil {
		t.Fatal("Not Marshaled")
	}

	parsed_key, parsed_cert, parsed_chain, err := LoadCertificateFromPKCS12(pkcs12, "test")

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}

	if parsed_key == nil {
		t.Error("Key not unmarshaled")
	}

	assertCertificateMatch(t, cert, parsed_cert)

	if parsed_chain != nil {
		t.Error("Chain not expected")
	}
}

func TestMarshalPKCS12_NoKey(t *testing.T) {
	_, cert, intermediate, root, err := loadSignedTestCert()
	if err != nil {
		t.Fatal(err)
	}

	pkcs12, err := MarshalPKCS12("test", "testing", nil, cert, []*Certificate{intermediate, root})

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}
	if pkcs12 == nil {
		t.Fatal("Not Marshaled")
	}

	parsed_key, parsed_cert, parsed_ca, err := LoadCertificateFromPKCS12(pkcs12, "test")

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}

	if parsed_key != nil {
		t.Error("Key not expected")
	}

	if parsed_cert != nil {
		t.Error("Cert not expected")
	}

	if parsed_ca == nil {
		t.Error("Chain not unmarshaled")
	}

	// When a PKCS #12 does not include a private key, all certs end up in the CA chain
	assertChainContents(t, []*Certificate{cert, intermediate, root}, parsed_ca)
}

func TestMarshalPKCS12_NoCertificate(t *testing.T) {
	key, _, err := loadSelfSignedTestCert()
	if err != nil {
		t.Fatal(err)
	}

	pkcs12, err := MarshalPKCS12("test", "testing", key, nil, nil)

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}
	if pkcs12 == nil {
		t.Fatal("Not Marshaled")
	}

	parsed_key, parsed_cert, parsed_ca, err := LoadCertificateFromPKCS12(pkcs12, "test")

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}

	if parsed_key == nil {
		t.Error("Key not unmarshaled")
	}

	if parsed_cert != nil {
		t.Error("Cert not expected")
	}

	if parsed_ca != nil {
		t.Error("Chain not expected")
	}
}

func TestMarshalPKCS12_WithChain(t *testing.T) {
	key, cert, intermediate, root, err := loadSignedTestCert()
	if err != nil {
		t.Fatal(err)
	}

	pkcs12, err := MarshalPKCS12("test", "testing", key, cert, []*Certificate{intermediate, root})

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}
	if pkcs12 == nil {
		t.Fatal("Not Marshaled")
	}

	parsed_key, parsed_cert, parsed_ca, err := LoadCertificateFromPKCS12(pkcs12, "test")

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}

	if parsed_key == nil {
		t.Error("Key not unmarshaled")
	}

	assertCertificateMatch(t, cert, parsed_cert)
	assertChainContents(t, []*Certificate{intermediate, root}, parsed_ca)
}

func TestMarshalPKCS12_ChainOnly(t *testing.T) {
	_, _, intermediate, root, err := loadSignedTestCert()
	if err != nil {
		t.Fatal(err)
	}

	pkcs12, err := MarshalPKCS12("test", "testing", nil, nil, []*Certificate{intermediate, root})

	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}
	if pkcs12 == nil {
		t.Fatal("Not Marshaled")
	}

	parsed_key, parsed_cert, parsed_ca, err := LoadCertificateFromPKCS12(pkcs12, "test")
	if err != nil {
		t.Fatalf("Error returned:%v", err)
	}

	if parsed_key != nil {
		t.Error("Key not expected")
	}

	if parsed_cert != nil {
		t.Error("Cert not expected")
	}

	assertChainContents(t, []*Certificate{intermediate, root}, parsed_ca)
}

func loadSelfSignedTestCert() (PrivateKey, *Certificate, error) {
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, nil, err
	}

	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func loadSignedTestCert() (PrivateKey, *Certificate, *Certificate, *Certificate, error) {
	key, err := LoadPrivateKeyFromPEM([]byte(signedKey))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, err := LoadCertificateFromPEM([]byte(signedCert))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	intermediate, err := LoadCertificateFromPEM([]byte(signedCertIntCA))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	root, err := LoadCertificateFromPEM([]byte(signedCertRootCA))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return key, cert, intermediate, root, nil
}

func assertCertificateMatch(t *testing.T, expected *Certificate, actual *Certificate) {
	t.Helper()

	if actual == nil {
		t.Error("Cert not unmarshaled")
	} else if actual.GetSerialNumberHex() != expected.GetSerialNumberHex() {
		t.Errorf("Cert serial numbers don't match:expected=%s actual=%s", expected.GetSerialNumberHex(), actual.GetSerialNumberHex())
	}
}

func assertChainContents(t *testing.T, expected []*Certificate, actual []*Certificate) {
	t.Helper()

	if actual == nil {
		t.Error("Chain not unmarshaled")
		return
	}

	if len(actual) != len(expected) {
		t.Errorf("Chain length incorrect:expected=%d actual=%d", len(expected), len(actual))
	}

	for i := 0; i < len(actual) && i < len(expected); i++ {
		assertCertificateMatch(t, expected[i], actual[i])
	}
}

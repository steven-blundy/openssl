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

// #include <openssl/pkcs12.h>
// #include "shim.h"
import "C"
import (
	"errors"
	"io/ioutil"
	"runtime"
	"unsafe"
)

// KeyType is a non-standard MS extension
type KeyType int

const (
	KEY_TYPE_undef KeyType = 0
	KEY_EX         KeyType = 0x10
	KEY_SIG        KeyType = 0x80
)

// LoadCertificateFromPKCS12 loads an X509 certificate from a PKCS#12-encoded byte set.
func LoadCertificateFromPKCS12(pkcs12 []byte, password string) (PrivateKey, *Certificate, []*Certificate, error) {
	if len(pkcs12) == 0 {
		return nil, nil, nil, errors.New("empty PKCS #12 block")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var pw *C.char
	if len(password) > 0 {
		pw = C.CString(password)
		defer C.free(unsafe.Pointer(pw))
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pkcs12[0]), C.int(len(pkcs12)))
	if bio == nil {
		return nil, nil, nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	p12 := C.d2i_PKCS12_bio(bio, nil)
	if p12 == nil {
		return nil, nil, nil, errors.New("failed reading PKCS#12 data into bio")
	}
	defer C.PKCS12_free(p12)

	var key *C.EVP_PKEY
	var x *C.X509
	var stack *C.struct_stack_st_X509

	rc := int(C.PKCS12_parse(p12, pw, &key, &x, &stack))
	if rc != 1 {
		return nil, nil, nil, errorFromErrorQueue()
	}

	var cert *Certificate
	if x != nil {
		cert = &Certificate{x: x}
		runtime.SetFinalizer(cert, func(x *Certificate) {
			C.X509_free(x.x)
		})
	}

	var pkey PrivateKey
	if key != nil {
		pkey = &pKey{key: key}
		runtime.SetFinalizer(pkey, func(p *pKey) {
			C.X_EVP_PKEY_free(p.key)
		})
	}

	ca := asStackOfX509(stack).toChain()
	return pkey, cert, ca, nil
}

// MarshalPKCS12 converts the PrivateKey, X509 certificate, and signing chain to PEM-encoded format. Uses suggested
// defaults for rarely used parameters.
func MarshalPKCS12(password, friendlyName string, pk PrivateKey, c *Certificate, chain []*Certificate) (
	pkcs12 []byte, err error) {
	return MarshalPKCS12Ex(password, friendlyName, pk, c, chain, NID_undef, NID_undef, 0, 0, KEY_TYPE_undef)
}

// MarshalPKCS12Ex converts the PrivateKey, X509 certificate, and signing chain to PEM-encoded format
func MarshalPKCS12Ex(password, friendly_name string, pk PrivateKey, cert *Certificate, ca []*Certificate,
	nid_key, nid_cert NID, iter, mac_iter int, keytype KeyType) (pkcs12 []byte, err error) {
	var pw *C.char
	if len(password) > 0 {
		pw = C.CString(password)
		defer C.free(unsafe.Pointer(pw))
	}

	var name *C.char
	if len(friendly_name) > 0 {
		name = C.CString(friendly_name)
		defer C.free(unsafe.Pointer(name))
	}

	var key *C.EVP_PKEY
	if pk != nil {
		key = pk.evpPKey()
	}

	var x *C.X509
	if cert != nil {
		x = cert.x
	}

	var stack *C.struct_stack_st_X509
	if ca != nil {
		sk := newStack()
		defer sk.free()

		for _, element := range ca {
			if sk.push(element.x) == 0 {
				return nil, errors.New("failed to prepare stack")
			}
		}

		stack = sk.asPtr()
	}

	p12 := C.PKCS12_create(pw, name, key, x, stack, C.int(nid_key), C.int(nid_cert), C.int(iter),
		C.int(mac_iter), C.int(keytype))
	if p12 == nil {
		return nil, errors.New("failed to encode in PKCS#12 structure")
	}
	defer C.PKCS12_free(p12)

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PKCS12_bio(bio, p12)) != 1 {
		return nil, errors.New("failed writing certificate")
	}
	return ioutil.ReadAll(asAnyBio(bio))
}

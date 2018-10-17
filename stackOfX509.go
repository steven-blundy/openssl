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

// #include "shim.h"
import "C"
import "runtime"

type stackOfX509 C.struct_stack_st_X509

func asStackOfX509(ptr *C.struct_stack_st_X509) *stackOfX509 {
	return (*stackOfX509)(ptr)
}

func newStack() *stackOfX509 {
	ptr := C.X_sk_X509_new_null()
	return asStackOfX509(ptr)
}

func (sk *stackOfX509) free() {
	C.X_sk_X509_free(sk.asPtr())
}

func (sk *stackOfX509) num() int {
	return int(C.X_sk_X509_num(sk.asPtr()))
}

func (sk *stackOfX509) value(i int) *C.X509 {
	return C.X_sk_X509_value(sk.asPtr(), C.int(i))
}

func (sk *stackOfX509) push(x *C.X509) int {
	return int(C.X_sk_X509_push(sk.asPtr(), x))
}

func (sk *stackOfX509) asPtr() *C.struct_stack_st_X509 {
	return (*C.struct_stack_st_X509)(sk)
}

func (sk *stackOfX509) toChain() []*Certificate {
	if sk == nil {
		return nil
	}

	sk_num := sk.num()
	rv := make([]*Certificate, 0, sk_num)
	for i := 0; i < sk_num; i++ {
		x := sk.value(i)
		if 1 != C.X_X509_add_ref(x) {
			return nil
		}
		cert := &Certificate{x: x}
		runtime.SetFinalizer(cert, func(cert *Certificate) {
			C.X509_free(cert.x)
		})
		rv = append(rv, cert)
	}

	return rv
}

// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"fmt"
)

// ErrorKind identifies a kind of error.
type ErrorKind string

// These constants are used to identify a specific ErrorKind.
const (
	ErrJoinSession = ErrorKind("ErrJoinSession")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// Error identifies an address-related error.
//
// It has full support for errors.Is and errors.As, so the caller can ascertain
// the specific reason for the error by checking the underlying error.
type Error struct {
	Err         error
	Description string
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	return e.Description
}

// Unwrap returns the underlying wrapped error.
func (e Error) Unwrap() error {
	return e.Err
}

// makeError creates an Error given a set of arguments.
func makeError(kind ErrorKind, desc string) Error {
	return Error{Err: kind, Description: desc}
}

func errorf(kind ErrorKind, format string, args ...interface{}) Error {
	descr := fmt.Sprintf(format, args...)
	return Error{Err: kind, Description: descr}
}

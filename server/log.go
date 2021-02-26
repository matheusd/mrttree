// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"github.com/decred/slog"
)

var (
	svrLog = slog.Disabled
)

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger slog.Logger) {
	svrLog = logger
}

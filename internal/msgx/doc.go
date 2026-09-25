// Package msgx calls xnu's private batched socket calls, sendmsg_x and recvmsg_x, through libSystem.
//
// The calls are not public API, so the package never links them: it looks them up with dlsym on first use.
// The package is darwin-only, and on iOS Available is always false, so App Store builds keep to public API.
package msgx

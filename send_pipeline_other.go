//go:build !darwin && !send_pipeline

package nebula

import "github.com/slackhq/nebula/overlay/tio"

// sendPipelinePlatform is false off darwin: the pipelined send path (interface_pipeline.go) is darwin only for now,
// and listenIn writes its own batches everywhere else. Being a constant, it removes the branch at compile time.
// Build with -tags send_pipeline to run the pipeline, and its tests, on another platform.
const sendPipelinePlatform = false

// listenInPipelined is a plain function rather than a method so this unreachable stub leaves no trace in the binary.
func listenInPipelined(*Interface, tio.Queue, int) {}

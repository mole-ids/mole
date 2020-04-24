package merr

import "errors"

const (
	LoggerInitConfigMsg     = "getting logger config"
	LoggerBuildZapFieldsMsg = "while compiling logger options"
)

var (
	LoggerInitConfigErr     = errors.New(LoggerInitConfigMsg)
	LoggerBuildZapFieldsErr = errors.New(LoggerBuildZapFieldsMsg)
)

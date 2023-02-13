package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// log.New: returns `*zap.SugaredLogger`
// panic: put to panic level else info
func New(panic bool) *zap.SugaredLogger {
	atom := zap.NewAtomicLevel()
	atom.SetLevel(zap.InfoLevel)

	if panic {
		atom.SetLevel(zap.PanicLevel)
	}

	zLog := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom,
	))

	return zLog.Sugar()
}

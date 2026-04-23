package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

func init() {
	zerolog.ErrorFieldName = "err"
	zerolog.DurationFieldUnit = time.Nanosecond
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.DefaultContextLogger = NewLogger(false, zerolog.InfoLevel, "")
}

func NewLogger(pretty bool, logLevel zerolog.Level, version string) *zerolog.Logger {
	var output io.Writer = os.Stderr
	if pretty {
		output = zerolog.ConsoleWriter{Out: os.Stderr}
	}

	logger := zerolog.New(output).
		With().
		Timestamp().
		Str("version", version).
		Logger().
		Level(logLevel).
		Hook(TracingHook{})

	return &logger
}

type ContextKey string

const SpanIDKey ContextKey = "span-id"

type TracingHook struct{}

func (h TracingHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	ctx := e.GetCtx()
	if spanID, ok := ctx.Value(SpanIDKey).(string); ok && spanID != "" {
		e.Str("span-id", spanID)
	}
}

package op_test

import (
	"testing"

	"github.com/keng42/go/op"
	"github.com/stretchr/testify/require"
)

func TestIf(t *testing.T) {
	require.Equal(t, 1, op.If(true, 1, 0))
	require.Equal(t, "not ok", op.If(false, "ok", "not ok"))
}

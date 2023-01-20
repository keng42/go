// Package op stands for operator
package op

// If stands for ternary operator
func If[T any](con bool, trueVal, falseVal T) T {
	if con {
		return trueVal
	}
	return falseVal
}

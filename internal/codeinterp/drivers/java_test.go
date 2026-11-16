package drivers

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// The driver's behaviour is tested against a real JDK in
// internal/codeinterp/proc (java_test.go, langs_test.go).
func TestJavaDriver(t *testing.T) {
	want := append(append([]string{"/bin/prog"}, javaArgs...), "/d/java_driver.java")
	checkDriver(t, codeinterp.LangJava, []string{"java"}, "java_driver.java", want, `executionEngine("local")`)
	checkDriverRefuses(t, codeinterp.LangJava)
}

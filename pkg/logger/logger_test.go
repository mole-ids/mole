package logger

import "testing"

func TestLogger(t *testing.T) {
	err := New()

	if err != nil {
		t.Errorf("Expection no error, but found %s", err.Error())
	}

	if Log == nil {
		t.Error("Logger was not initialized successfully")
	}

	if Result == nil {
		t.Error("Result logger was not initialized successfully")
	}
}

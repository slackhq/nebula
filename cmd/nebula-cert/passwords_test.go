package main

type StubPasswordReader struct {
	password []byte
	err      error
}

func (pr *StubPasswordReader) ReadPassword() ([]byte, error) {
	return pr.password, pr.err
}

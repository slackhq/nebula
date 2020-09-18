package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/skip2/go-qrcode"
)

type qrFlags struct {
	set     *flag.FlagSet
	inFile  *string
	outFile *string
	bitSize *int
}

func newQRFlags() *qrFlags {
	qf := qrFlags{set: flag.NewFlagSet("qr", flag.ContinueOnError)}
	qf.set.Usage = func() {}
	qf.inFile = qf.set.String("in", "", "Required: path of the file to turn into a QR code")
	qf.outFile = qf.set.String("out", "", "Optional: path to write the qr code to, if empty the in path will be used and the extension changed to png")
	qf.bitSize = qf.set.Int("bit-size", 5, "Optional: size for each data pixel")
	return &qf
}

func qr(args []string, out io.Writer, errOut io.Writer) error {
	qf := newQRFlags()
	err := qf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("in", qf.inFile); err != nil {
		return err
	}

	if *qf.outFile == "" {
		inFile := *qf.inFile
		ext := path.Ext(inFile)
		*qf.outFile = inFile[0:len(inFile)-len(ext)] + ".png"
	}

	raw, err := ioutil.ReadFile(*qf.inFile)
	if err != nil {
		return fmt.Errorf("error while reading in file: %s", err)
	}

	enc, err := qrcode.Encode(string(raw), qrcode.Medium, -*qf.bitSize)
	if err != nil {
		return fmt.Errorf("error while encoding as a qr code: %s", err)
	}

	err = ioutil.WriteFile(*qf.outFile, enc, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out file: %s", err)
	}

	return nil
}

func qrSummary() string {
	return "qr <flags>: convert a file into a qr code image"
}

func qrHelp(out io.Writer) {
	qf := newQRFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + qrSummary() + "\n"))
	qf.set.SetOutput(out)
	qf.set.PrintDefaults()
}

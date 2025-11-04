package heartbleed

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

// write data to network conn.
func write(conn net.Conn, data []byte, timeout time.Duration) error {
	err := conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

// // read data from network conn.
// func read(conn net.Conn, timeout time.Duration) ([]byte, error) {
// 	var bytes []byte
// 	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
// 	buff := bufio.NewReader(conn)
// 	for {
// 		b, err := buff.ReadByte()
// 		bytes = append(bytes, b)
// 		if err != nil {
// 			return bytes, err
// 		}
// 		if buff.Buffered() == 0 {
// 			break
// 		}
// 	}
// 	return bytes, nil
// }

const (
	notApplicable = "n/a"
	notVulnerable = "no"
	vulnerable    = "yes"
	testFailed    = "error"
)

type Heartbleed struct {
	Vulnerable       string `json:"vulnerable"`
	ExtensionEnabled bool   `json:"extension"`
}

// Heartbleed test.
func (h *Heartbleed) Check(host string, port string, tlsVers int) error {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", host+":"+port)
	if err != nil {
		h.Vulnerable = testFailed

		return err
	}
	defer conn.Close()

	/*
		only test up to tlsv1.2 because not possible
		with tlsv1.3
	*/
	if tlsVers > tls.VersionTLS12 {
		tlsVers = tls.VersionTLS12
	}

	err = starttls.StartTLS(ctx, conn, port)
	if err != nil {
		h.Vulnerable = testFailed

		return err
	}

	// Send clientHello
	clientHello := makeClientHello(tlsVers)

	err = write(conn, clientHello, 2)
	if err != nil {
		h.Vulnerable = testFailed

		return err
	}

	connbuf := bufio.NewReader(conn)

	hBEnabled, err := checkExtension(connbuf)
	if err != nil {
		switch err.Error() {
		// some applications reset the tcp connection
		// when probing for heartbleed
		case "EOF":
		default:
			h.Vulnerable = testFailed

			return err
		}
	}

	if hBEnabled {
		h.ExtensionEnabled = true

		payload := makePayload(tlsVers)

		err = write(conn, payload, 2)
		if err != nil {
			h.Vulnerable = testFailed

			return err
		}

		h.Vulnerable = heartbeatListen(connbuf)

		return nil
	}

	h.Vulnerable = notApplicable

	return nil
}

// checks if handshake was successful and if the
// heartbeat extension is enabled.
func checkExtension(buff *bufio.Reader) (bool, error) {
	var data []byte

	var err error

	hBEnabled := false

	for {
		b, err := buff.ReadByte()
		if err != nil {
			return hBEnabled, err
		}

		data = append(data, b)

		// is heartbeat extension enabled?
		if strings.HasSuffix(fmt.Sprintf("%X", data), "000F000101") {
			hBEnabled = true
		}

		// is serverHello finished
		if strings.HasSuffix(fmt.Sprintf("%X", data), "0E000000") {
			break
		}
	}

	return hBEnabled, err
}

// Reads from buffer and checks the size of the response
// to determine if heartbleed was exploited.
func heartbeatListen(buff *bufio.Reader) string {
	// listen for reply
	// ReadBytes has to be ran one to process started, but
	// it will block if there isn't any data to read
	var data []byte

	go func() {
		buff.ReadByte()
	}()

	time.Sleep(1 * time.Second)

	i := 0

	for {
		buffLeft := buff.Buffered()

		// fmt.Printf("iter: %d left: %d\n", i, buffLeft)
		if buffLeft == 0 && i <= 3 {
			i++
			continue
		}

		if buffLeft == 0 && i > 3 {
			break
		}

		b, err := buff.ReadByte()
		data = append(data, b)

		if err != nil {
			// logger.Debugf("event_id=heartbleed_error msg=%v", err)
			break
		}

		if len(data) >= 1600 {
			// logger.Debugf("event_id=heartbleed_check status=%s", vulnerable)
			return vulnerable
		}

		i++
	}

	return notVulnerable
}

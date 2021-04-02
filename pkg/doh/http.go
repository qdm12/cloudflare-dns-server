package doh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/qdm12/dns/pkg/dot"
)

var (
	ErrHTTPStatus = errors.New("bad HTTP status")
)

func newDoTClient(settings dot.ResolverSettings) *http.Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{
		Resolver: dot.NewResolver(settings),
	}
	httpTransport.DialContext = dialer.DialContext
	const timeout = 5 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
}

func dohHTTPRequest(ctx context.Context, client *http.Client, bufferPool *sync.Pool,
	url *url.URL, wire []byte) (respWire []byte, err error) { //nolint:interfacer
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)

	_, err = buffer.Write(wire)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), buffer)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/dns-udpwireformat")

	response, err := client.Do(request)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrHTTPStatus, response.Status)
	}

	respWire, err = io.ReadAll(response.Body) // TODO copy to buffer
	if err != nil {
		return nil, err
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	return respWire, nil
}

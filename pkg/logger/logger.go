package logger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/file"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/utils/conversion"
	pdhttpUtils "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"

	"github.com/projectdiscovery/proxify/pkg/types"
)

const (
	dataWithNewLine      = "%s\n"
	dataWithoutNewLine   = "%s"
	LoggerConfigFilename = "export-config.yaml"
)

// ErrLoggerClosed is returned by LogRequest/LogResponse when they are called
// after Close has begun: the async queue is (or is about to be) closed, so the
// transaction is rejected rather than lost or sent on a closed channel.
var ErrLoggerClosed = errors.New("logger is closed")

type OptionsLogger struct {
	Verbosity    types.Verbosity
	OutputFolder string // when output is written to multiple files
	OutputFile   string // when output is written to single file
	OutputFormat string // jsonl or yaml
	DumpRequest  bool   // dump request to file
	DumpResponse bool   // dump response to file
	MaxSize      int    // max size of the output
	Elastic      *elastic.Options
	Kafka        *kafka.Options
}

type Store interface {
	Save(data types.HTTPTransaction) error
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan types.HTTPTransaction
	Store      []Store
	sWriter    OutputFileWriter // sWriter is the structured writer

	// mu excludes producers only across the send/closed decision (RLock) and
	// the close transition (Lock). It is never held while draining.
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once      // closes asyncqueue and sWriter exactly once
	wg        sync.WaitGroup // tracks the AsyncWrite worker so Close can drain
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan types.HTTPTransaction, 1000),
	}
	if options.Elastic.Addr != "" {
		store, err := elastic.New(options.Elastic)
		if err != nil {
			gologger.Warning().Msgf("Error while creating elastic logger: %s", err)
		} else {
			logger.Store = append(logger.Store, store)
		}
	}
	if options.Kafka.Addr != "" {
		kfoptions := kafka.Options{
			Addr:  options.Kafka.Addr,
			Topic: options.Kafka.Topic,
		}
		store, err := kafka.New(&kfoptions)
		if err != nil {
			gologger.Warning().Msgf("Error while creating kafka logger: %s", err)
		} else {
			logger.Store = append(logger.Store, store)

		}
	}
	store, err := file.New(&file.Options{
		OutputFolder: options.OutputFolder,
	})
	if err != nil {
		gologger.Warning().Msgf("Error while creating file logger: %s", err)
	} else {
		logger.Store = append(logger.Store, store)
	}

	// setup structured writer
	if options.OutputFormat != "" {
		sWriter, err := NewOutputFileWriter(options.OutputFormat, options.OutputFile)
		if err != nil {
			gologger.Warning().Msgf("Error while creating structured writer: %s", err)
		} else {
			logger.sWriter = sWriter
		}
	}

	logger.wg.Add(1)
	go logger.AsyncWrite()
	return logger
}

// enqueue snapshots have already been taken by the caller; it hands the
// transaction to the async writer while holding the producer lock only across
// the closed check and the channel send, so Close can never close the queue
// out from under an in-flight send.
func (l *Logger) enqueue(t types.HTTPTransaction) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return ErrLoggerClosed
	}
	l.asyncqueue <- t
	return nil
}

// LogRequest and user data
func (l *Logger) LogRequest(req *http.Request, userdata types.UserData) error {
	if req == nil {
		return nil
	}

	// Snapshot while this goroutine still has exclusive access: the async
	// writer must never touch the live request the proxy is about to forward.
	return l.enqueue(types.HTTPTransaction{
		Userdata: userdata,
		Request:  snapshotRequest(req),
	})
}

// LogResponse and user data
func (l *Logger) LogResponse(resp *http.Response, userdata types.UserData) error {
	if resp == nil {
		return nil
	}
	// Snapshot while this goroutine still has exclusive access: the async
	// writer must never touch the live response the proxy is still writing
	// to the client, nor fields callers mutate after logging (resp.Close).
	snapshot := snapshotResponse(resp)
	return l.enqueue(types.HTTPTransaction{
		Userdata: userdata,
		Response: snapshot,
		Request:  snapshot.Request,
	})
}

// responseSnapshotPrefix is how much of a response body is buffered into a
// snapshot: the ResponseChain in AsyncWrite caps body reads at 4096 bytes,
// +1 so oversized bodies still trip its too-large error path.
const responseSnapshotPrefix = 4096 + 1

// errReader replays a read error to whichever side owns the tail of a
// snapshotted body, so a mid-body failure is not silently converted to EOF.
type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

// compositeBody pairs a replacement body reader with the closer of the
// original body it wraps, so closing the live body still releases the
// underlying connection.
type compositeBody struct {
	io.Reader
	io.Closer
}

// snapshotRequest returns a copy of req that the async writer can consume
// without touching state the serving goroutines still own. The body is read
// synchronously here, while the caller has exclusive access, and the live
// request and the copy get independent readers over the same bytes.
func snapshotRequest(req *http.Request) *http.Request {
	clone := req.Clone(context.Background())
	// Never share the rewind func across the ownership boundary.
	clone.GetBody = nil
	if req.Body == nil || req.Body == http.NoBody {
		return clone
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	live := io.Reader(bytes.NewReader(body))
	snap := io.Reader(bytes.NewReader(body))
	if err != nil {
		live = io.MultiReader(live, &errReader{err: err})
		snap = io.MultiReader(snap, &errReader{err: err})
	}
	req.Body = io.NopCloser(live)
	clone.Body = io.NopCloser(snap)
	return clone
}

// snapshotResponse returns a copy of resp safe for the async writer. Only the
// first responseSnapshotPrefix bytes of the body are buffered (all AsyncWrite
// ever reads is the 4096-capped ResponseChain); the live response replays the
// buffered prefix and then keeps streaming from the original body.
func snapshotResponse(resp *http.Response) *http.Response {
	clone := new(http.Response)
	*clone = *resp
	// Invariant: fields still aliased after this shallow copy (TransferEncoding,
	// TLS, Request.Response) must never be written after LogResponse enqueues
	// the snapshot; only Close, Header, Trailer, Body, and Request are known to
	// be touched post-log, and those are deep-copied below.
	clone.Header = resp.Header.Clone()
	clone.Trailer = resp.Trailer.Clone()
	if resp.Request != nil {
		clone.Request = snapshotRequest(resp.Request)
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		return clone
	}
	orig := resp.Body
	var prefix bytes.Buffer
	_, err := io.CopyN(&prefix, orig, responseSnapshotPrefix)
	switch {
	case err == nil:
		// More body remains: the client resumes streaming after the prefix.
		resp.Body = &compositeBody{
			Reader: io.MultiReader(bytes.NewReader(prefix.Bytes()), orig),
			Closer: orig,
		}
	case errors.Is(err, io.EOF):
		resp.Body = &compositeBody{
			Reader: bytes.NewReader(prefix.Bytes()),
			Closer: orig,
		}
	default:
		resp.Body = &compositeBody{
			Reader: io.MultiReader(bytes.NewReader(prefix.Bytes()), &errReader{err: err}),
			Closer: orig,
		}
	}
	clone.Body = io.NopCloser(bytes.NewReader(prefix.Bytes()))
	return clone
}

// AsyncWrite data
func (l *Logger) AsyncWrite() {
	defer l.wg.Done()
	for httpData := range l.asyncqueue {
		if httpData.Request == nil {
			// we can't do anything without request
			continue
		}
		// we have better options to handle this
		// i.e Buffer reuse and normalizing request/response body (removing encoding etc)
		reqDump, err := httputil.DumpRequest(httpData.Request, true)
		if err != nil {
			gologger.Warning().Msgf("Error while dumping request: %s", err)
		}

		// debug log request if true
		l.debugLogRequest(reqDump, httpData.Request)

		var respChain *pdhttpUtils.ResponseChain
		if httpData.Response != nil {
			respChainx := pdhttpUtils.NewResponseChain(httpData.Response, 4096)
			if err := respChainx.Fill(); err == nil {
				respChain = respChainx
			} else {
				gologger.Warning().Msgf("responseChain: Error while dumping response: %s", err)
			}
		}
		// debug log response if true
		if respChain != nil {
			if err := l.debugLogResponse(respChain); err != nil {
				gologger.Warning().Msgf("Error while logging response: %s", err)
			}
		}

		// first write to structured writer
		if l.sWriter != nil {
			func() {
				// if matchers were given only store those that match
				if httpData.Userdata.Match != nil {
					if !*httpData.Userdata.Match {
						return
					}
				}

				sData := &types.HTTPRequestResponseLog{
					Timestamp: time.Now().Format(time.RFC3339),
					URL:       httpData.Request.URL.String(),
				}
				defer func() {
					if sData.Response != nil {
						// write to structured writer with whatever data we have
						err := l.sWriter.Write(sData)
						if err != nil {
							gologger.Warning().Msgf("Error while logging: %s", err)
						}
					}
				}()
				sRequest, err := types.NewHttpRequestData(httpData.Request)
				if err != nil {
					gologger.Warning().Msgf("Error while creating request: %s", err)
					return
				}
				sData.Request = sRequest
				if respChain != nil {
					sResponse, err := types.NewHttpResponseData(respChain)
					if err != nil {
						gologger.Warning().Msgf("Error while creating response: %s", err)
					}
					sData.Response = sResponse
				}
			}()
		}

		// write to other writers
		if len(l.Store) > 0 {
			// write request first
			outputData := httpData
			// outputData.Data = reqDump
			outputData.RawData = reqDump
			outputData.Userdata.HasResponse = false
			l.storeWriter(outputData)

			// write response if available
			if respChain != nil {
				// outputData.Data = respChain.FullResponse().Bytes()
				outputData.RawData = respChain.FullResponse().Bytes()
				outputData.Userdata.HasResponse = true
				l.storeWriter(outputData)
			}
		}
	}
}

// Close stops the logger, drains every accepted transaction, then closes the
// structured writer. It is safe to call concurrently and repeatedly: sync.Once
// runs the shutdown once and every caller blocks until that single drain
// completes. Producers must be stopped by the owner (P16) before or during
// Close; any that race Close observe ErrLoggerClosed rather than a lost write.
func (l *Logger) Close() {
	l.closeOnce.Do(func() {
		// Exclude producers just long enough to flip closed and close the
		// queue. Taking the write lock waits for every in-flight enqueue to
		// finish its send, so close never races a channel send; afterward any
		// producer sees closed and returns ErrLoggerClosed.
		l.mu.Lock()
		l.closed = true
		close(l.asyncqueue)
		l.mu.Unlock()

		// Drain outside the producer lock: wait for AsyncWrite to process
		// every queued transaction so nothing accepted before Close is lost.
		l.wg.Wait()

		// The writer is closed only after the drain so AsyncWrite never writes
		// to a closed writer.
		if l.sWriter != nil {
			if err := l.sWriter.Close(); err != nil {
				gologger.Warning().Msgf("Error while closing structured writer: %s", err)
			}
		}
	})
}

// debugLogRequest logs the request to the console if debugging is enabled
func (l *Logger) debugLogRequest(reqdump []byte, req *http.Request) {
	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := req.Header.Get("Content-Type")
		b, _ := io.ReadAll(req.Body)
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(string(b)) {
			reqdump, _ = httputil.DumpRequest(req, false)
		}
		gologger.Silent().Msgf("%s", string(reqdump))
	}
}

// debugLogResponse logs the response to the console if debugging is enabled
func (l *Logger) debugLogResponse(respChain *pdhttpUtils.ResponseChain) error {
	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := respChain.Response().Header.Get("Content-Type")
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(conversion.String(respChain.Body().Bytes())) {
			gologger.Silent().Msgf("%s", respChain.Headers().String())
		} else {
			gologger.Silent().Msgf("%s", respChain.FullResponse().String())
		}
	}
	return nil
}

// storeWriter writes the data to the store (file, kafka, elastic)
// this can be refactored to make it more readable and scalable
// with improved interface and probably use of structure http data
// instead of raw bytes
func (l *Logger) storeWriter(outputdata types.HTTPTransaction) {
	if !l.options.DumpRequest && !l.options.DumpResponse {
		outputdata.PartSuffix = ""
	} else if l.options.DumpRequest && !outputdata.Userdata.HasResponse {
		outputdata.PartSuffix = ".request"
	} else if l.options.DumpResponse && outputdata.Userdata.HasResponse {
		outputdata.PartSuffix = ".response"
	} else {
		return
	}
	outputdata.Name = fmt.Sprintf("%s%s-%s", outputdata.Userdata.Host, outputdata.PartSuffix, outputdata.Userdata.ID)
	if outputdata.Userdata.HasResponse && (!l.options.DumpRequest && !l.options.DumpResponse) {
		if outputdata.Userdata.Match != nil && *outputdata.Userdata.Match {
			outputdata.Name = outputdata.Name + ".match"
		}
	}
	outputdata.Format = dataWithoutNewLine
	if !strings.HasSuffix(string(outputdata.Data), "\n") {
		outputdata.Format = dataWithNewLine
	}

	outputdata.DataString = fmt.Sprintf(outputdata.Format, outputdata.Data)
	if outputdata.Userdata.HasResponse {
		outputdata.Format = "\n" + outputdata.Format
	}
	outputdata.RawData = []byte(fmt.Sprintf(outputdata.Format, outputdata.RawData))

	if l.options.MaxSize > 0 {
		outputdata.DataString = stringsutil.Truncate(outputdata.DataString, l.options.MaxSize)
		outputdata.RawData = []byte(stringsutil.Truncate(string(outputdata.RawData), l.options.MaxSize))
	}
	for _, store := range l.Store {
		err := store.Save(outputdata)
		if err != nil {
			gologger.Warning().Msgf("Error while logging: %s", err)
		}
	}
}

func isASCIICheckRequired(contentType string) bool {
	return stringsutil.ContainsAny(contentType, "application/octet-stream", "application/x-www-form-urlencoded")
}

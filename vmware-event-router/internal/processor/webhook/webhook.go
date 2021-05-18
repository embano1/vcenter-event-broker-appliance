package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/pkg/errors"
	"go.uber.org/ratelimit"
	"go.uber.org/zap"

	config "github.com/vmware-samples/vcenter-event-broker-appliance/vmware-event-router/internal/config/v1alpha1"
	"github.com/vmware-samples/vcenter-event-broker-appliance/vmware-event-router/internal/logger"
	"github.com/vmware-samples/vcenter-event-broker-appliance/vmware-event-router/internal/metrics"
	"github.com/vmware-samples/vcenter-event-broker-appliance/vmware-event-router/internal/processor"
)

const (
	defaultTimeout         = time.Second * 10
	defaultRateLimitSecond = 10
)

// assert we implement Processor interface
var _ processor.Processor = (*Processor)(nil)

type Processor struct {
	client http.Client
	// TODO: inject via custom roundtripper to avoid code dup
	remote  *url.URL
	headers map[string]string
	limit   ratelimit.Limiter

	logger.Logger
	sync.RWMutex
	typeFilter    map[string]struct{}
	subjectFilter map[string]struct{}
	stats         metrics.EventStats
}

func NewProcessor(ctx context.Context, cfg *config.ProcessorConfigWebhook, ms metrics.Receiver, log logger.Logger, opts ...Option) (*Processor, error) {
	if cfg == nil {
		return nil, errors.New("no Webhook configuration found")
	}

	whLog := log
	if zapSugared, ok := log.(*zap.SugaredLogger); ok {
		proc := strings.ToUpper(string(config.ProcessorWebhook))
		whLog = zapSugared.Named(fmt.Sprintf("[%s]", proc))
	}

	limit := cfg.RPS
	if limit == 0 {
		whLog.Warn("rate limit not defined (using default): %d", defaultRateLimitSecond)
		limit = defaultRateLimitSecond
	}

	client := http.Client{
		Timeout: defaultTimeout,
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, errors.Wrap(err, "parse URL")
	}

	whProcessor := Processor{
		client:        client,
		remote:        u,
		Logger:        whLog,
		limit:         ratelimit.New(int(limit)),
		typeFilter:    map[string]struct{}{},
		subjectFilter: map[string]struct{}{},
		stats: metrics.EventStats{
			Provider:    string(config.ProcessorWebhook),
			Type:        config.EventProcessor,
			Address:     cfg.URL,
			Started:     time.Now().UTC(),
			Invocations: make(map[string]*metrics.InvocationDetails),
		},
	}

	for _, f := range cfg.Filters {
		if t := f.Type; t != "" {
			whLog.Debugf("adding %q to cloud event type filter", t)
			whProcessor.typeFilter[t] = struct{}{}
		}

		if s := f.Subject; s != "" {
			whLog.Debugf("adding %q to cloud event subject filter", s)
			whProcessor.subjectFilter[s] = struct{}{}
		}
	}

	// apply options
	for _, opt := range opts {
		opt(&whProcessor)
	}

	go whProcessor.PushMetrics(ctx, ms)

	return &whProcessor, nil
}

func (p *Processor) Process(ctx context.Context, ce cloudevents.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	p.Logger.(*zap.SugaredLogger).With("eventID", ce.ID())

	p.Debugw("processing event", "event", ce)

	// 	check if event needs to be processed
	doProcess := func() bool {
		if len(p.typeFilter)+len(p.subjectFilter) == 0 {
			// no filter
			return true
		}

		if _, ok := p.typeFilter[ce.Type()]; ok {
			return true
		}

		if _, ok := p.subjectFilter[ce.Subject()]; ok {
			return true
		}
		return false
	}

	if !doProcess() {
		p.Debugw("ignoring event", "subject", ce.Subject(), "type", ce.Type())
		return nil
	}

	// create request

	msg, err := createSlackMessage(ce)
	if err != nil {
		return processor.NewError(config.ProcessorWebhook, errors.Wrap(err, "create slack message"))
	}

	buf := bytes.NewBuffer(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.remote.String(), buf)
	if err != nil {
		return processor.NewError(config.ProcessorWebhook, errors.Wrap(err, "create request"))
	}

	if len(p.headers) != 0 {
		p.Debug("applying custom headers")
		for k, v := range p.headers {
			req.Header.Add(k, v)
		}
	}

	p.Debug("acquiring rate limit token")
	_ = p.limit.Take()

	p.Debug("sending request")
	resp, err := p.client.Do(req)

	p.Lock()
	defer p.Unlock()
	subject := ce.Subject()
	// initialize invocation stats
	if _, ok := p.stats.Invocations[subject]; !ok {
		p.stats.Invocations[subject] = &metrics.InvocationDetails{}
	}
	if err != nil {
		p.stats.Invocations[subject].Failure()
		return processor.NewError(config.ProcessorWebhook, errors.Wrapf(err, "send event %s", ce.ID()))
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	p.Info("successfully sent event")
	p.stats.Invocations[subject].Success()
	return nil
}

func (p *Processor) PushMetrics(ctx context.Context, ms metrics.Receiver) {
	ticker := time.NewTicker(metrics.PushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.RLock()
			ms.Receive(&p.stats)
			p.RUnlock()
		}
	}
}

func (p *Processor) Shutdown(ctx context.Context) error {
	p.Logger.Infof("attempting graceful shutdown") // noop for now
	return nil
}

// hack!!!
func createSlackMessage(ce cloudevents.Event) ([]byte, error) {
	template := `
{
	"blocks": [
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "New ` + "`" + `CloudEvent` + "`" + ` :alert:  !!!\n\n*Type:* %s\n*Source:* %s\n*Subject:* %s"
			},
			"accessory": {
				"type": "image",
				"image_url": "https://cloudevents.io/img/logos/cloudevents-icon-color.png",
				"alt_text": "CE"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "` + "```" + `%s` + "```" + `"
			}
		}
	]
}
`

	b, err := json.Marshal(ce.String())
	if err != nil {
		return nil, errors.Wrap(err, "marshal cloud event")
	}

	cleaned := strings.TrimPrefix(string(b), `"`)
	cleaned = strings.TrimSuffix(cleaned, `"`)

	m := fmt.Sprintf(template, ce.Type(), ce.Source(), ce.Subject(), cleaned)
	return []byte(m), nil
}

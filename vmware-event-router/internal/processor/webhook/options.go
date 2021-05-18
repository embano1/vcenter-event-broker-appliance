package webhook

// Option configures the Webhook processor
// TODO: change signature to return errors
type Option func(processor *Processor)

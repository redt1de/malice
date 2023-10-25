package callz

type CallerCFG struct {
	Resolver int
	Hasher   func(string) string
	Opts     map[string]interface{}
}

type CallerOpt func(*CallerCFG)

func WithResolver(resolver int) CallerOpt {
	return func(h *CallerCFG) {
		h.Resolver = resolver
	}
}

func WithHasher(hasher func(string) string) CallerOpt {
	return func(h *CallerCFG) {
		h.Hasher = hasher
	}
}

func WithConfig(c *CallerCFG) CallerOpt {
	return func(h *CallerCFG) {
		h.Hasher = c.Hasher
		h.Resolver = c.Resolver
	}
}

package ntd

import "github.com/redt1de/malice/pkg/callz"

const (
	RESOLVER_MEM    = 0
	RESOLVER_DISK   = 1
	RESOLVER_EXCEPT = 2
)

func OptResolverMem() callz.CallerOpt {
	return func(h *callz.CallerCFG) {
		h.Resolver = RESOLVER_MEM
	}
}

func OptResolverDisk() callz.CallerOpt {
	return func(h *callz.CallerCFG) {
		h.Resolver = RESOLVER_DISK
	}
}
func OptResolverExcept() callz.CallerOpt {
	return func(h *callz.CallerCFG) {
		h.Resolver = RESOLVER_EXCEPT
	}
}

func OptHasher(hasher func(string) string) callz.CallerOpt {
	return func(h *callz.CallerCFG) {
		h.Hasher = hasher
	}
}

func OptConfig(c *callz.CallerCFG) callz.CallerOpt {
	return func(h *callz.CallerCFG) {
		h.Hasher = c.Hasher
		h.Resolver = c.Resolver
	}
}

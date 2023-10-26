package ntd

func getTrampoline(exportAddr uintptr) uintptr

// GetTRampolines returns the address of a clean syscall;ret gadget. Intentionally searches in syscall stubs != to the syscall we are calling, like SysWhispers3
func (n *NtDll) GetTrampoline(notfunc string) uintptr {
	ex, e := n.Pe.Exports()
	if e != nil {
		return 0
	}
	for _, exp := range ex {
		if exp.Name != notfunc && n.cfg.Hasher(exp.Name) != notfunc { // avoid the syscall we're using
			// tramp := getTrampoline(n.Start + uintptr(exp.VirtualAddress))
			tramp := n.FindGadget(GADGET_SYSCALL_RET)
			if tramp != 0 {
				return tramp
			}
		}
	}
	return 0
}

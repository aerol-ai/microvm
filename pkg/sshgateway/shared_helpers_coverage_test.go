package sshgateway

func sshUint32s(vals ...uint32) []byte {
	out := make([]byte, 0, 4*len(vals))
	for _, v := range vals {
		out = append(out, encodeUint32(v)...)
	}
	return out
}

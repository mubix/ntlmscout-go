package der

// OID values used when wrapping NTLMSSP in SPNEGO/GSSAPI.
var (
	oidSPNEGO  = []int{1, 3, 6, 1, 5, 5, 2}
	oidNTLMSSP = []int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

// SPNEGONegTokenInit wraps a raw NTLMSSP token in a GSSAPI/SPNEGO
// NegTokenInit, as consumed by SMB, LDAP (GSS-SPNEGO SASL) and RDP/CredSSP.
func SPNEGONegTokenInit(ntlmToken []byte) []byte {
	mechTypes := TLV(0xA0, TLV(0x30, OID(oidNTLMSSP)))
	mechToken := TLV(0xA2, TLV(0x04, ntlmToken))
	negTokenInit := TLV(0xA0, TLV(0x30, concat(mechTypes, mechToken)))
	inner := concat(OID(oidSPNEGO), negTokenInit)
	return TLV(0x60, inner) // [APPLICATION 0]
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

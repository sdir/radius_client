package session

type Context struct {
	UserName   string
	PassWord   string
	NasAddr    string
	NasPort    string
	NasPasswd  string
	VlanID     uint32
	ClientAddr string
	ClientMac  string
}

// func (c *Context) initTLS() {
// 	if c.tlsCache == nil {
// 		var err error
// 		c.tlsCache, err = eaptls.New()
// 		if err != nil {
// 			log.Println(err)
// 		}
// 	}
// }

// func (c *Context) SetTLSRaw(data []byte) {
// 	c.initTLS()
// 	if c.tlsCache.HandShakeCnt > 0 {
// 		log.Printf("tls raw write %d", len(data))
// 		c.tlsCache.WriteServerRaw(data)
// 		c.tlsCache.HandShakeCnt++
// 	}
// }

// func (c *Context) GetTLSRaw() []byte {
// 	if c.tlsCache.HandShakeCnt == 0 || c.tlsCache.HandShakeCnt > 3 {
// 		log.Printf("tls raw read")
// 		c.tlsCache.HandShakeCnt++
// 		return c.tlsCache.ReadServerRaw()
// 	}
// 	return []byte{}
// }

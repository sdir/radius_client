package session

import (
	"encoding/hex"
	"log"
	"net"

	"github.com/sdir/eapol_test/eap"
	"github.com/sdir/eapol_test/radius"
	tlsCache "github.com/sdir/eapol_test/tls"
)

type Session struct {
	ServerIP net.UDPAddr
	context  *Context
	tlsCache *tlsCache.TLSCache
}

func New(addr string, context *Context) *Session {
	tlsCache, err := tlsCache.New()
	if err != nil {
		log.Panicln(err)
	}
	session := &Session{
		ServerIP: net.UDPAddr{
			IP:   net.ParseIP(addr),
			Port: 1812,
		},
		context:  context,
		tlsCache: tlsCache,
	}
	return session
}

func (s *Session) InitRadius() *radius.Packet {
	packet := radius.New()

	packet.SetUserName(s.context.UserName)
	packet.NASIPAddress_Add(s.context.NasAddr)
	packet.NASPortID_Add(s.context.NasPort, s.context.VlanID)
	packet.CallingStationID_Add(s.context.ClientMac)
	packet.ServiceType_Add(radius.ServiceType_Value_FramedUser)
	packet.NASPortType_Add(radius.NASPortType_Value_Ethernet)
	packet.FramedIPAddress_Add(s.context.ClientAddr)
	packet.FramedMTU_Add(1400)

	eapPacket := eap.NewEapIdentity()
	eapPacket.SetIdentity(s.context.UserName)
	eapPacket.SetCode(eap.EAPResponse)

	if ok, eapMsg := eapPacket.Encode(); ok {
		packet.EAPMessage_Set(eapMsg)
	}

	packet.MessageAuthenticator_Set(s.context.NasPasswd)

	return packet
}

func (s *Session) reply(data []byte) []byte {
	req, err := radius.Parse(data)
	if err != nil {
		log.Println(err)
		return []byte{}
	}
	reqEapData, err := req.EAPMessage_Get()
	if err != nil {
		log.Println(err)
		return []byte{}
	}
	reqEapPacket := eap.Decode(reqEapData, nil)

	log.Printf("Identifier:%d eap:%d \n", req.Identifier, reqEapPacket.GetId())

	switch reqEapPacket.GetCode() {
	case eap.EAPRequest:
		switch reqEapPacket.GetType() {
		case eap.Peap:
			packet := radius.NewReply(req)

			packet.SetUserName(s.context.UserName)
			packet.NASIPAddress_Add(s.context.NasAddr)
			packet.NASPortID_Add(s.context.NasPort, s.context.VlanID)
			packet.CallingStationID_Add(s.context.ClientMac)
			packet.ServiceType_Add(radius.ServiceType_Value_FramedUser)
			packet.NASPortType_Add(radius.NASPortType_Value_Ethernet)
			packet.FramedIPAddress_Add(s.context.ClientAddr)
			packet.FramedMTU_Add(1400)

			reqPeapPacket := reqEapPacket.(*eap.EapPeap)

			peapPacket := eap.NewEapPeap()
			peapPacket.SetCode(eap.EAPResponse)
			peapPacket.SetId(reqPeapPacket.GetId())

			if reqPeapPacket.GetStartFlag() {
				peapPacket.SetTLSPayload(s.tlsCache.Read())
			}

			if s.tlsCache.HandStaus != tlsCache.HandOK {
				tlsLen := reqPeapPacket.GetTLSTotalLength()
				tlsData := reqPeapPacket.GetTLSPayload()
				peapPacket.SetTLSPayload(s.tlsCache.HandShake(tlsData, tlsLen))
			} else {
				reqTLSData := s.tlsCache.Decode(reqPeapPacket.GetTLSPayload())
				reqTLSPacket := eap.Decode(reqTLSData, reqEapPacket)
				switch reqTLSPacket.GetType() {
				case eap.Identity:
					log.Println("Identity")
					peapPacket.SetTLSPayload(s.tlsCache.Encode(eap.PeapIdentity(s.context.UserName)))
				case eap.MsChapv2:
					msPacket := reqTLSPacket.(*eap.EapMSCHAPv2)
					log.Printf("MsChapv2 %s", msPacket.GetName())
					log.Printf("MsChapv2 %d", msPacket.GetOpCode())
					switch msPacket.GetOpCode() {
					case eap.MsChapV2Challenge:
						msReqPacket := eap.NewEapMsChapV2()
						msReqPacket.SetCode(eap.EAPResponse)
						msReqPacket.SetId(msPacket.GetId())
						msReqPacket.SetOpCode(eap.MsChapV2Response)

						peerChallenge := eap.RandPeerChallenge()
						authenticatorChallenge := msPacket.GetAuthChallenge()

						log.Println("\npeer: \n" + hex.Dump(peerChallenge))
						log.Println("\nauth: \n" + hex.Dump(authenticatorChallenge))

						ntResponse := eap.GenerateNTResponse(s.context.UserName, s.context.PassWord,
							authenticatorChallenge, peerChallenge)
						// authResponse := eap.GenerateAuthenticatorResponse(s.context.UserName, s.context.PassWord,
						// 	ntResponse, authenticatorChallenge, peerChallenge)

						log.Println("\nnt: \n" + hex.Dump(ntResponse))
						// log.Println("\nresponse: \n" + hex.Dump(authResponse))

						var response []byte
						response = append(response, peerChallenge...)
						response = append(response, 0, 0, 0, 0, 0, 0, 0, 0)
						response = append(response, ntResponse...)
						response = append(response, 0)
						msReqPacket.SetValue(response)
						msReqPacket.SetName(s.context.UserName)
						if ok, data := msReqPacket.Encode(); ok {
							log.Println(len(data))
							peapPacket.SetTLSPayload(s.tlsCache.Encode(data[4:]))
						}
					case eap.MsChapV2Success:
						log.Println("mschap success")
						log.Printf("MsChapv2 %s", msPacket.GetMessage())

						msReqPacket := eap.NewEapMsChapV2()
						msReqPacket.SetCode(eap.EAPResponse)
						msReqPacket.SetId(msPacket.GetId())
						msReqPacket.SetOpCode(eap.MsChapV2Success)
						if ok, data := msReqPacket.Encode(); ok {
							log.Println(len(data))
							peapPacket.SetTLSPayload(s.tlsCache.Encode(data[4:]))
						}
					case eap.MsChapV2Failure:
						log.Println("mschap failure")
					}
				case eap.TLV:
					tlvPacket := reqTLSPacket.(*eap.EapTLVResult)
					log.Printf("TLV %d", tlvPacket.GetResult())
					tlsReqPacket := eap.NewEapTLVResult()
					tlsReqPacket.SetCode(eap.EAPResponse)
					tlsReqPacket.SetResult(eap.TLVResOk)
					if ok, data := tlsReqPacket.Encode(); ok {
						log.Println(len(data))
						peapPacket.SetTLSPayload(s.tlsCache.Encode(data))
					}
				default:
					log.Printf("code:%d", reqTLSPacket.GetType())
					// case eap.TLV:
				}
			}

			if ok, eapMsg := peapPacket.Encode(); ok {
				packet.EAPMessage_Set(eapMsg)
			}
			packet.MessageAuthenticator_Set(s.context.NasPasswd)

			data, err := packet.MarshalBinary()
			if err == nil {
				return data
			} else {
				log.Println(err)
			}

		default:
			log.Printf("Not find eap type %d", reqEapPacket.GetType())
		}
	case eap.EAPSuccess:
	case eap.EAPFailure:
	}
	return []byte{}
}

func (s *Session) Run() {
	c, err := net.DialUDP("udp", nil, &s.ServerIP)
	if err != nil {
		log.Printf("Run error: %s", err)
		return
	}
	defer c.Close()

	p := s.InitRadius()
	data, err := p.MarshalBinary()
	if err != nil {
		log.Println(err)
		return
	}

	c.Write(data)

	for {
		data := make([]byte, 2048)
		n, _, err := c.ReadFromUDP(data)
		if err != nil {
			log.Printf("Read server error: %s", err)
			return
		}

		if n > 0 {
			rdata := s.reply(data[0:n])
			if len(rdata) == 0 {
				break
			}
			c.Write(rdata)
		}

	}
}

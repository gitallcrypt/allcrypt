/* A line protocol over wireguard-go's own handshake, cookie and
 * transport code, for scripts/check_wireguard.py. Copied into
 * wireguard-go's device package (it uses unexported names) and built
 * as a test binary:
 *
 *     cp witness_test.go /opt/wgwitness/wireguard-go/device/
 *     cd /opt/wgwitness/wireguard-go && go test -c -o /opt/wgwitness/wgwitness ./device
 *     /opt/wgwitness/wgwitness -test.run TestWitness
 *
 * One command a line, hex arguments, one answer a line: "ok ...", or
 * "fail ..." for a refusal.
 *
 *   key PRIV                    device with this key; answers its public key
 *   peer PUB PSK                add a peer
 *   init                        an initiation to the peer, MACs added
 *   consume_init MSG            check MAC1 and consume an initiation
 *   respond                     a response, MACs added; the session begins
 *   consume_response MSG        check MAC1, consume, begin the session
 *   seal COUNTER PLAINTEXT      a transport message, padded as send.go pads
 *   open MSG                    a transport message's plaintext, padding kept
 *   cookie_reply MSG SRC        the reply a loaded responder sends
 *   consume_cookie MSG          the initiator takes a cookie reply
 *   check_mac2 MSG SRC          whether a message's MAC2 is good
 */

package device

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestWitness(t *testing.T) {
	if os.Getenv("WGWITNESS") == "" {
		t.Skip("run by scripts/check_wireguard.py")
	}
	var dev *Device
	var peer *Peer
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	say := func(format string, args ...any) {
		fmt.Fprintf(out, format+"\n", args...)
		out.Flush()
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			say("fail hex")
		}
		return b
	}
	current := func() *Keypair {
		peer.keypairs.RLock()
		defer peer.keypairs.RUnlock()
		if next := peer.keypairs.next.Load(); next != nil {
			return next
		}
		return peer.keypairs.current
	}
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "key":
			var sk NoisePrivateKey
			copy(sk[:], unhex(f[1]))
			if dev != nil {
				dev.Close()
			}
			tun := tuntest.NewChannelTUN()
			dev = NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
			dev.SetPrivateKey(sk)
			pk := dev.staticIdentity.privateKey.publicKey()
			say("ok %x", pk[:])
		case "peer":
			var pk NoisePublicKey
			copy(pk[:], unhex(f[1]))
			p, err := dev.NewPeer(pk)
			if err != nil {
				say("fail %v", err)
				continue
			}
			copy(p.handshake.presharedKey[:], unhex(f[2]))
			p.Start()
			peer = p
			say("ok")
		case "init":
			msg, err := dev.CreateMessageInitiation(peer)
			if err != nil {
				say("fail %v", err)
				continue
			}
			b := make([]byte, MessageInitiationSize)
			msg.marshal(b)
			peer.cookieGenerator.AddMacs(b)
			say("ok %x", b)
		case "consume_init":
			b := unhex(f[1])
			if !dev.cookieChecker.CheckMAC1(b) {
				say("fail mac1")
				continue
			}
			var msg MessageInitiation
			if msg.unmarshal(b) != nil {
				say("fail length")
				continue
			}
			p := dev.ConsumeMessageInitiation(&msg)
			if p == nil {
				say("fail consume")
				continue
			}
			peer = p
			say("ok %x", p.handshake.remoteStatic[:])
		case "respond":
			msg, err := dev.CreateMessageResponse(peer)
			if err != nil {
				say("fail %v", err)
				continue
			}
			b := make([]byte, MessageResponseSize)
			msg.marshal(b)
			peer.cookieGenerator.AddMacs(b)
			if err := peer.BeginSymmetricSession(); err != nil {
				say("fail %v", err)
				continue
			}
			say("ok %x", b)
		case "consume_response":
			b := unhex(f[1])
			if !dev.cookieChecker.CheckMAC1(b) {
				say("fail mac1")
				continue
			}
			var msg MessageResponse
			if msg.unmarshal(b) != nil {
				say("fail length")
				continue
			}
			if dev.ConsumeMessageResponse(&msg) == nil {
				say("fail consume")
				continue
			}
			if err := peer.BeginSymmetricSession(); err != nil {
				say("fail %v", err)
				continue
			}
			say("ok")
		case "seal":
			counter, _ := strconv.ParseUint(f[1], 10, 64)
			var plain []byte
			if len(f) > 2 {
				plain = unhex(f[2])
			}
			padded := make([]byte, len(plain)+calculatePaddingSize(len(plain), 1420))
			copy(padded, plain)
			kp := current()
			b := make([]byte, MessageTransportHeaderSize)
			binary.LittleEndian.PutUint32(b, MessageTransportType)
			binary.LittleEndian.PutUint32(b[4:], kp.remoteIndex)
			binary.LittleEndian.PutUint64(b[8:], counter)
			var nonce [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(nonce[4:], counter)
			b = kp.send.Seal(b, nonce[:], padded, nil)
			say("ok %x", b)
		case "open":
			b := unhex(f[1])
			kp := current()
			if len(b) < MessageTransportSize ||
				binary.LittleEndian.Uint32(b[4:]) != kp.localIndex {
				say("fail index")
				continue
			}
			counter := binary.LittleEndian.Uint64(b[8:])
			var nonce [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(nonce[4:], counter)
			plain, err := kp.receive.Open(nil, nonce[:], b[16:], nil)
			if err != nil {
				say("fail open")
				continue
			}
			say("ok %x", plain)
		case "cookie_reply":
			b := unhex(f[1])
			recv := binary.LittleEndian.Uint32(b[4:])
			reply, err := dev.cookieChecker.CreateReply(b, recv, unhex(f[2]))
			if err != nil {
				say("fail %v", err)
				continue
			}
			r := make([]byte, MessageCookieReplySize)
			reply.marshal(r)
			say("ok %x", r)
		case "consume_cookie":
			var msg MessageCookieReply
			if msg.unmarshal(unhex(f[1])) != nil || !peer.cookieGenerator.ConsumeReply(&msg) {
				say("fail cookie")
				continue
			}
			say("ok")
		case "check_mac2":
			say("ok %v", dev.cookieChecker.CheckMAC2(unhex(f[1]), unhex(f[2])))
		default:
			say("fail unknown %s", f[0])
		}
	}
}

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"net"
	"os"
	"strings"

	//"crypto/rand"
	//"flag"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"

	//"os"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"

	//"github.com/libp2p/go-libp2p-core/peerstore"

	"github.com/multiformats/go-multiaddr"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	geth_log "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
)

type GethLogger struct {
	logrus.FieldLogger
}

var (
	h              host.Host
	udpV5          *discover.UDPv5
	identifyPeerID string
	ids            *identify.IDService
)

type AttnetsENREntry []byte

func NewAttnetsENREntry(input_bytes string) AttnetsENREntry {

	result, err := hex.DecodeString(input_bytes)

	if err != nil {
		fmt.Println(err)
	}

	return result
}

func (aee AttnetsENREntry) ENRKey() string {
	return "attnets"
}

type Eth2ENREntry []byte

func NewEth2DataEntry(input_bytes string) Eth2ENREntry {
	result, err := hex.DecodeString(input_bytes)

	if err != nil {
		fmt.Println(err)
	}

	return result
}

func (eee Eth2ENREntry) ENRKey() string {
	return "eth2"
}

func main() {

	//reader := bufio.NewReader(os.Stdin)
	fmt.Println("Hola")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sourcePort := flag.Int("sp", 0, "Source port number")
	privKeyString := flag.String("d", "", "privKeyString")
	//identifyPeerID := flag.String("p", "", "identify peer id")
	help := flag.Bool("help", false, "Display help")
	//debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")

	flag.Parse()

	if *help {
		fmt.Printf("This program demonstrates a simple p2p chat application using libp2p\n\n")
		fmt.Println("Usage: Run './chat -sp <SOURCE_PORT>' where <SOURCE_PORT> can be any port number.")
		fmt.Println("Now run './chat -d <MULTIADDR>' where <MULTIADDR> is multiaddress of previous listener host.")

		os.Exit(0)
	}

	// If debug is enabled, use a constant random source to generate the peer ID. Only useful for debugging,
	// off by default. Otherwise, it uses rand.Reader.
	/*var r io.Reader
	if *debug {
		// Use the port number as the randomness source.
		// This will always generate the same host ID on multiple executions, if the same port number is used.
		// Never do this in production code.
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}*/
	var err error
	//prvKey := generate_privKey()
	//generate_privKey()
	prvKey, err := ParsePrivateKey(*privKeyString)

	localNode := createLocalNode(prvKey)
	//fmt.Println(localNode)

	h, err = makeHost(ctx, *sourcePort, prvKey)
	if err != nil {
		log.Println(err)
		return
	}
	local_multiaddress := h.Addrs()[0].String() + "/p2p/" + h.ID().String()
	mAddr, err := ma.NewMultiaddr(h.Addrs()[0].String())
	err = h.Network().Listen(mAddr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Listening at: ", local_multiaddress)

	/*h.SetStreamHandler("/echo/1.0.0", func(s network.Stream) {
		fmt.Println("listener received new stream")
		fmt.Println(s)

	})*/

	bundle := &network.NotifyBundle{}

	bundle.ListenF = StandardListenF
	bundle.ListenCloseF = StandardListenCloseF
	bundle.ConnectedF = StandardConnectF
	bundle.DisconnectedF = StandardDisconnectF
	bundle.OpenedStreamF = StandardOpenedStreamF
	bundle.ClosedStreamF = StandardClosedF

	h.Network().Notify(bundle)

	//if identifyPeerID != nil {
	/*ids, err = identify.NewIDService(h)
	if err != nil {
		fmt.Println(err)
		fmt.Println(ids)
	}
	fmt.Println("Created IDS")*/
	//var a string = (string)(*identifyPeerID)

	//h2p, err := peer.IDFromString(a)

	/*if err != nil {
		fmt.Println("ID error", err)
	}*/
	/*forgetMe, _ := ma.NewMultiaddr("/ip4/192.168.0.127/tcp/9001/")
	h.Peerstore().AddAddr(h2p, forgetMe, peerstore.RecentlyConnectedAddrTTL)

	h1t2c := h.Network().ConnsToPeer(h2p)

	ids.IdentifyConn(h1t2c[0])*/
	//fmt.Println(h2p)
	//fmt.Println(*identifyPeerID)
	//}

	//localNode.Set(enr.WithEntry("eth2", "0xb5303f2a"))
	localNode.Set(NewAttnetsENREntry("ffffffffffffffff"))
	localNode.Set(NewEth2DataEntry("b5303f2a"))
	//fmt.Printf("%+v\n", localNode)

	//fmt.Println(localNode.ID())

	dv5_client, err := start_dv5(uint16(*sourcePort), prvKey, localNode)
	fmt.Println("PING")

	dv5_client.Ping(enode.MustParse("enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg"))
	random_nodes := dv5_client.RandomNodes()

	for random_nodes.Next() {
		fmt.Printf("n: %s\n", random_nodes.Node().ID().String())
	}

	//fmt.Printf("%+v\n", random_nodes)

	//iter := dv5_client.RandomNodes()

	//fmt.Printf("Random%+v\n", iter)

	/*// Let's get the actual TCP port from our listen multiaddr, in case we're using 0 (default; random available port).
	var port string
	for _, la := range h.Network().ListenAddresses() {
		if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
			port = p
			break
		}
	}

	if port == "" {
		log.Println("was not able to find actual local port")
		return
	}

	log.Printf("Run './chat -d /ip4/127.0.0.1/tcp/%v/p2p/%s' on another console.\n", port, h.ID().Pretty())
	log.Println("You can replace 127.0.0.1 with public IP as well.")
	log.Println("Waiting for incoming connection")
	log.Println()*/
	select {}

}

func makeHost(ctx context.Context, port int, prvKey *crypto.Secp256k1PrivateKey) (host.Host, error) {
	// Creates a new RSA key pair for this host.

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	return libp2p.New(
		ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
		libp2p.UserAgent("BSC_testing_crawler"),
	)
}

/*func handleStream(s network.Stream) {
	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	go writeData(rw)

	// stream 's' will stay open until you close it (or the other side closes it).
}*/

func createLocalNode(privKey *crypto.Secp256k1PrivateKey) *enode.LocalNode {
	localNodeDB, err := enode.OpenDB("") // memory-DB

	if err != nil {
		fmt.Println(err)
	}

	localNode := enode.NewLocalNode(localNodeDB, (*ecdsa.PrivateKey)(privKey))

	//fmt.Println(localNode.Node())

	return localNode

}

func generate_privKey() *crypto.Secp256k1PrivateKey {

	key, err := ecdsa.GenerateKey(gcrypto.S256(), rand.Reader)

	if err != nil {
		fmt.Errorf("failed to generate key: %v", err)
	}

	secpKey := (*crypto.Secp256k1PrivateKey)(key)

	keyBytes, err := secpKey.Raw()

	if err != nil {
		fmt.Errorf("failed to serialize key: %v", err)
	}
	fmt.Println("key", hex.EncodeToString(keyBytes))

	return secpKey
}

func start_dv5(listenPort uint16, prvKey *crypto.Secp256k1PrivateKey, localNode *enode.LocalNode) (discover.UDPv5, error) {

	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: int(listenPort),
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println("Connection: ", conn.LocalAddr().String())

	//gethLogWrap := GethLogger{FieldLogger: logrus.New()}
	gethLogger := geth_log.New()
	gethLogger.SetHandler(geth_log.FuncHandler(func(r *geth_log.Record) error {

		fmt.Printf("%+v\n", r)
		fmt.Println()

		return nil
	}))

	cfg := discover.Config{
		PrivateKey:   (*ecdsa.PrivateKey)(prvKey),
		NetRestrict:  nil,
		Bootnodes:    create_bootNodeList(),
		Unhandled:    nil, // Not used in dv5
		Log:          gethLogger,
		ValidSchemes: enode.ValidSchemes,
	}

	fmt.Println("dv5 starting to listen: ")
	fmt.Println()
	udpV5, err = discover.ListenV5(conn, localNode, cfg)
	if err != nil {
		fmt.Println(err)
		return *udpV5, err
	}

	//found_node := udpV5.Lookup

	//fmt.Println("localNode:", udpV5.LocalNode().ID())

	return *udpV5, nil
}

func create_bootNodeList() []*enode.Node {
	var bootNodeList []*enode.Node

	bootNodeList = append(bootNodeList, enode.MustParse("enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg"))
	bootNodeList = append(bootNodeList, enode.MustParse("enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA"))

	//fmt.Printf("%v\n", bootNodeList)

	return bootNodeList
}

func StandardListenF(net network.Network, addr ma.Multiaddr) {
	fmt.Println("Listen")
}

func StandardListenCloseF(net network.Network, addr ma.Multiaddr) {
	fmt.Println("Close listen")
}

func StandardConnectF(net network.Network, conn network.Conn) {
	fmt.Println("Connection")
	fmt.Printf("%+v\n", conn)

	fmt.Println("PEers in PeerStore")
	fmt.Printf("%+v\n", h.Network().Peerstore().Peers())

	//fmt.Println("Creating IDS")
	//ids, err := identify.NewIDService(h)
	//defer ids.Close()
	//fmt.Println("dsgfs")
	/*if err != nil {
		fmt.Println(err)
		fmt.Println(ids)
	}*/

	/*h2p := h.Network().Peerstore().Peers()[1]
	h1t2c := h.Network().ConnsToPeer(h2p)
	fmt.Println(h2p)

	fmt.Println(h1t2c)
	ids.IdentifyConn(h1t2c[0])
	fmt.Println("Identified")
	newPeer := h.Network().Peerstore().Peers()[1]
	fmt.Println(newPeer)

	fmt.Println(h.Peerstore().Get(newPeer, "ProtocolVersion"))*/

}

func StandardDisconnectF(net network.Network, conn network.Conn) {
	fmt.Println("Disconnect")
}

func StandardOpenedStreamF(net network.Network, str network.Stream) {
	fmt.Println("Open Stream")
}

func StandardClosedF(net network.Network, str network.Stream) {
	fmt.Println("Close")
}

func ParsePrivateKey(v string) (*crypto.Secp256k1PrivateKey, error) {
	if strings.HasPrefix(v, "0x") {
		v = v[2:]
	}
	privKeyBytes, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, expected hex string: %v", err)
	}
	var priv crypto.PrivKey
	priv, err = crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, invalid private key (Secp256k1): %v", err)
	}
	key := (priv).(*crypto.Secp256k1PrivateKey)
	key.Curve = gcrypto.S256()              // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1
	if !key.Curve.IsOnCurve(key.X, key.Y) { // TODO: should we be checking this?
		return nil, fmt.Errorf("invalid private key, not on curve")
	}
	return key, nil
}

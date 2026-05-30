package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := negotiateAuth(conn); err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	if err := handleConnect(conn); err != nil {
		log.Printf("connect handling failed: %v", err)
		return
	}
}

func negotiateAuth(conn net.Conn) error {
	// Read greeting
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read greeting header: %w", err)
	}

	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %x", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	reqUser := os.Getenv("PROXY_USER")
	reqPass := os.Getenv("PROXY_PASS")

	requiresAuth := reqUser != ""

	supportedMethod := byte(0xFF) // No acceptable methods
	for _, m := range methods {
		if requiresAuth && m == 0x02 {
			supportedMethod = 0x02
			break
		}
		if !requiresAuth && m == 0x00 {
			supportedMethod = 0x00
			break
		}
	}

	// Send method selection
	if _, err := conn.Write([]byte{0x05, supportedMethod}); err != nil {
		return fmt.Errorf("failed to write method selection: %w", err)
	}

	if supportedMethod == 0xFF {
		return fmt.Errorf("no acceptable authentication methods")
	}

	if supportedMethod == 0x02 {
		return authenticateUserPass(conn, reqUser, reqPass)
	}

	return nil
}

func authenticateUserPass(conn net.Conn, expectedUser, expectedPass string) error {
	header := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read auth header: %w", err)
	}

	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %x", header[0])
	}

	uLen := int(header[1])
	uName := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uName); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}

	pLen := int(pLenBuf[0])
	pWord := make([]byte, pLen)
	if _, err := io.ReadFull(conn, pWord); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	status := byte(0x01) // Failure by default
	if string(uName) == expectedUser && string(pWord) == expectedPass {
		status = 0x00 // Success
	}

	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return fmt.Errorf("failed to write auth response: %w", err)
	}

	if status != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func handleConnect(conn net.Conn) error {
	header := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read connect header: %w", err)
	}

	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version in request: %x", header[0])
	}

	if header[1] != 0x01 { // CMD != CONNECT
		sendReply(conn, 0x07) // Command not supported
		return fmt.Errorf("unsupported command: %x", header[1])
	}

	atyp := header[3]
	var targetAddr string

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return fmt.Errorf("failed to read IPv4: %w", err)
		}
		targetAddr = net.IP(ip).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		targetAddr = string(domain)
	case 0x04: // IPv6 (not supported per requirements)
		sendReply(conn, 0x08) // Address type not supported
		return fmt.Errorf("IPv6 not supported")
	default:
		sendReply(conn, 0x08)
		return fmt.Errorf("unknown address type: %x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	target := fmt.Sprintf("%s:%d", targetAddr, port)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		sendReply(conn, 0x04) // Host unreachable / General failure
		return fmt.Errorf("failed to dial target %s: %w", target, err)
	}
	defer targetConn.Close()

	if err := sendReply(conn, 0x00); err != nil {
		return fmt.Errorf("failed to send connect reply: %w", err)
	}

	relay(conn, targetConn)
	return nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

func relay(clientConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

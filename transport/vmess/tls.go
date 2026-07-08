package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/tlsmirror"

	"github.com/metacubex/tls"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	FingerPrint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	NextProtos        []string
	ECH               *ech.Config
	Reality           *tlsC.RealityConfig
	TLSMirror         *tlsmirror.Config
	TLSMirrorDialer   tlsmirror.EnrollmentDialer
}

func (cfg *TLSConfig) ToStdConfig() (*tls.Config, error) {
	return ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
		},
		Fingerprint: cfg.FingerPrint,
		Certificate: cfg.Certificate,
		PrivateKey:  cfg.PrivateKey,
	})
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	if cfg.TLSMirror != nil {
		return tlsmirror.Dial(ctx, conn, tlsmirror.ClientConfig{
			Config:             *cfg.TLSMirror,
			ServerName:         cfg.Host,
			SkipCertVerify:     cfg.SkipCertVerify,
			ALPN:               cfg.NextProtos,
			Fingerprint:        cfg.FingerPrint,
			Certificate:        cfg.Certificate,
			PrivateKey:         cfg.PrivateKey,
			ClientFingerprint:  cfg.ClientFingerprint,
			ForwardAddressHint: cfg.Host,
			ECH:                cfg.ECH,
			EnrollmentDialer:   cfg.TLSMirrorDialer,
		})
	}

	tlsConfig, err := cfg.ToStdConfig()
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConfig := tlsC.UConfig(tlsConfig)
		err = cfg.ECH.ClientHandleUTLS(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	err = cfg.ECH.ClientHandle(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}

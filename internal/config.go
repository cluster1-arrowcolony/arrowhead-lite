package internal

import (
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/gateway"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/relay"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Health   HealthConfig   `mapstructure:"health"`
	Gateway  GatewayConfig  `mapstructure:"gateway"`
	Relay    RelayConfig    `mapstructure:"relay"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	TLS          TLSConfig     `mapstructure:"tls"`
	CORS         CORSConfig    `mapstructure:"cors"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type CORSConfig struct {
	AllowOrigins []string `mapstructure:"allow_origins"`
	AllowMethods []string `mapstructure:"allow_methods"`
	AllowHeaders []string `mapstructure:"allow_headers"`
}

type DatabaseConfig struct {
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
}

type AuthConfig struct {
	JWTSecret      string        `mapstructure:"jwt_secret"`
	TokenDuration  time.Duration `mapstructure:"token_duration"`
	PrivateKeyFile string        `mapstructure:"private_key_file"`
	PublicKeyFile  string        `mapstructure:"public_key_file"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

type HealthConfig struct {
	CheckInterval   time.Duration `mapstructure:"check_interval"`
	InactiveTimeout time.Duration `mapstructure:"inactive_timeout"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

type GatewayConfig struct {
	Enabled         bool             `mapstructure:"enabled"`
	CloudID         string           `mapstructure:"cloud_id"`
	CertificateFile string           `mapstructure:"certificate_file"`
	PrivateKeyFile  string           `mapstructure:"private_key_file"`
	TrustAnchors    []TrustAnchorCfg `mapstructure:"trust_anchors"`
	TrustStore      string           `mapstructure:"trust_store"`
}

type TrustAnchorCfg struct {
	CloudID         string `mapstructure:"cloud_id"`
	CertificateFile string `mapstructure:"certificate_file"`
}

type RelayConfig struct {
	Enabled     bool                    `mapstructure:"enabled"`
	Connections []RelayConnectionConfig `mapstructure:"connections"`
}

type RelayConnectionConfig struct {
	Name       string `mapstructure:"name"`
	BrokerType string `mapstructure:"broker_type"`
	BrokerURL  string `mapstructure:"broker_url"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	TLSEnabled bool   `mapstructure:"tls_enabled"`
	CertPath   string `mapstructure:"cert_path"`
	KeyPath    string `mapstructure:"key_path"`
	CACertPath string `mapstructure:"ca_cert_path"`
	MaxRetries int    `mapstructure:"max_retries"`
}

// GetGateway returns the gateway configuration compatible with gateway package
func (c *Config) GetGateway() *gateway.GatewayConfig {
	// Convert trust anchors
	trustAnchors := make([]gateway.TrustAnchorCfg, len(c.Gateway.TrustAnchors))
	for i, ta := range c.Gateway.TrustAnchors {
		trustAnchors[i] = gateway.TrustAnchorCfg{
			CloudID:     ta.CloudID,
			Certificate: ta.CertificateFile,
		}
	}

	return &gateway.GatewayConfig{
		Enabled:         c.Gateway.Enabled,
		CloudID:         c.Gateway.CloudID,
		CertificateFile: c.Gateway.CertificateFile,
		PrivateKeyFile:  c.Gateway.PrivateKeyFile,
		TrustStore:      c.Gateway.TrustStore,
		TrustAnchors:    trustAnchors,
	}
}

// GetRelay returns the relay configuration compatible with relay package
func (c *Config) GetRelay() relay.RelayConfig {
	// Convert connections
	connections := make([]relay.RelayConnectionConfig, len(c.Relay.Connections))
	for i, conn := range c.Relay.Connections {
		connections[i] = relay.RelayConnectionConfig{
			Name:       conn.Name,
			BrokerType: conn.BrokerType,
			BrokerURL:  conn.BrokerURL,
			Username:   conn.Username,
			Password:   conn.Password,
			TLSEnabled: conn.TLSEnabled,
			CertPath:   conn.CertPath,
			KeyPath:    conn.KeyPath,
			CACertPath: conn.CACertPath,
			MaxRetries: conn.MaxRetries,
		}
	}

	return relay.RelayConfig{
		Enabled:     c.Relay.Enabled,
		Connections: connections,
	}
}

func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
	}

	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8443)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.tls.enabled", false)
	viper.SetDefault("server.cors.allow_origins", []string{"*"})
	viper.SetDefault("server.cors.allow_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("server.cors.allow_headers", []string{"*"})

	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.path", "./arrowhead.db")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.username", "arrowhead")
	viper.SetDefault("database.password", "arrowhead")
	viper.SetDefault("database.name", "arrowhead")

	viper.SetDefault("auth.jwt_secret", "arrowhead-lite-secret")
	viper.SetDefault("auth.token_duration", "24h")

	viper.SetDefault("logging.level", "warn")
	viper.SetDefault("logging.format", "text")

	viper.SetDefault("health.check_interval", "1m")
	viper.SetDefault("health.inactive_timeout", "5m")
	viper.SetDefault("health.cleanup_interval", "10m")

	viper.SetDefault("gateway.enabled", false)
	viper.SetDefault("gateway.cloud_id", "local-cloud")

	viper.SetDefault("relay.enabled", false)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("ARROWHEAD")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

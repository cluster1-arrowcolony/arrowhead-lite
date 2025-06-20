package internal

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Health   HealthConfig   `mapstructure:"health"`
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
	Enabled        bool   `mapstructure:"enabled"`
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
	TruststoreFile string `mapstructure:"truststore_file"`
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
